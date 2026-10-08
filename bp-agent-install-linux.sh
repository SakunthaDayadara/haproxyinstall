#!/usr/bin/env bash
# =============================================================================
#
#    ##    ##  ######  #### ##    ##  ######      ###
#    ###   ## ##    ##  ##  ###   ## ##    ##    ## ##
#    ####  ## ##        ##  ####  ## ##         ##   ##
#    ## ## ## ##        ##  ## ## ## ##   #### ##     ##
#    ##  #### ##        ##  ##  #### ##    ##  #########
#    ##   ### ##    ##  ##  ##   ### ##    ##  ##     ##
#    ##    ##  ######  #### ##    ##  ######   ##     ##
#
#    NCINGA INTERNAL  -  Bindplane air-gapped deployment tooling
#
# =============================================================================
#  bp-agent-install-linux.sh  -  offline Bindplane agent install for Linux log sources
# -----------------------------------------------------------------------------
#  Copyright (c) 2026 NCINGA. All rights reserved.
#
#  NCINGA INTERNAL - PROPRIETARY AND CONFIDENTIAL. This script, including its
#  design, logic, messages and accompanying documentation, is the intellectual
#  property of NCINGA. It is provided solely for use by NCINGA personnel and
#  NCINGA-authorised implementation partners on NCINGA engagements. Copying,
#  distributing, modifying, sublicensing or disclosing it, in whole or in part,
#  for any other purpose requires the prior written permission of NCINGA.
#
#  Provided "AS IS", without warranty of any kind, express or implied. NCINGA
#  accepts no liability for loss or damage arising from its use. Test it in a
#  non-production environment first and follow the change-management process of
#  the environment it is run in.
#
#  Third-party software: it installs and configures software that NCINGA does
#  not own - the Bindplane / OpenTelemetry collector (observIQ, Apache License
#  2.0) - subject to its own licence. Product names are trademarks of their
#  respective owners; no affiliation or endorsement is implied.
# =============================================================================
#  Runbook Stage 8 (Linux log sources) without internet access. The offline
#  counterpart of the vendor's install_unix.sh: the package comes from the
#  gateway of this host's segment - the LIVE gateway's mirror, or the DMZ
#  gateway's repository - built by bp-live-setup.sh / bp-dmz-setup.sh:
#
#    http://<gateway>:8080/   packages/  SHA256SUMS  VERSION-INFO
#    ws://<gateway>:3001/v1/opamp       the OpAMP relay the agent connects to
#
#  What it does, step by step (each step is recorded; a re-run resumes):
#    preflight  host, OS (Ubuntu/Debian .deb or RHEL family .rpm), architecture
#    gateway    repository reachable, chosen version present, ports 3001/4317
#    download   the package (resumable), the publisher's checksums and key
#    verify     SHA256SUMS + publisher checksum + package signature (pinned key)
#    install    dpkg / rpm, upgrade or switch between collector families
#    configure  manager.yaml (v1) or supervisor.yaml (v2): endpoint, secret
#               key, labels - the agent identity is kept on re-install
#    start      enable and start the service, crash-loop detection
#    connect    stable OpAMP session to the gateway, console confirmation
#
#  The collector: any version staged on the gateway, of either family:
#    v1  observiq-otel-collector    /opt/observiq-otel-collector   manager.yaml
#    v2  bindplane-otel-collector   /opt/bindplane-otel-collector  supervisor.yaml
#
#  Interactive by default (asks for every value, offers detected defaults);
#  explainable (each failure says what happened, the likely cause and the fix,
#  then offers retry / diagnostics / skip / quit); resumable (Ctrl+C and SSH
#  drops are safe). The secret key is never saved by this script - it lives
#  only in the collector's own configuration file (mode 0600).
#
#  Usage:  curl -fsSO http://<gateway>:8080/scripts/bp-agent-install-linux.sh
#          sudo bash bp-agent-install-linux.sh            (then follow the prompts)
#          sudo bash bp-agent-install-linux.sh --help     (all options)
# =============================================================================

SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="bp-agent-install-linux"

set -uo pipefail
umask 022
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

# ----------------------------------------------------------------------------
# Paths (override with env: BP_STATE_DIR, BP_LOG_DIR, BP_CACHE_DIR)
# ----------------------------------------------------------------------------
STATE_DIR=${BP_STATE_DIR:-/var/lib/bp-agent-install}
LOG_DIR=${BP_LOG_DIR:-/var/log/bp-agent-install}
CACHE_DIR=${BP_CACHE_DIR:-/var/cache/bp-agent-install}
CONF_FILE="$STATE_DIR/agent.conf"
STATE_FILE="$STATE_DIR/progress"
LOCK_FILE="/run/bp-agent-install.lock"
EVIDENCE_DIR="$LOG_DIR/evidence"

# Collector families - use_family() points the COLLECTOR_* variables at one of them
V1_PKG="observiq-otel-collector";  V1_HOME=${BP_COLLECTOR_HOME:-/opt/observiq-otel-collector}
V2_PKG="bindplane-otel-collector"; V2_HOME=${BP_V2_HOME:-/opt/bindplane-otel-collector}
MANAGER_YAML="$V1_HOME/manager.yaml"
SUP_YAML="$V2_HOME/supervisor.yaml"
COLLECTOR_FAMILY=v1; COLLECTOR_PKG=$V1_PKG; COLLECTOR_SVC=$V1_PKG; COLLECTOR_HOME=$V1_HOME
COLLECTOR_CONF=$MANAGER_YAML; COLLECTOR_LOG="$V1_HOME/log/collector.log"
COLLECTOR_BIN="$V1_HOME/observiq-otel-collector"; COLLECTOR_PROC="observiq"
BENIGN_LOG_RE='Capabilities is deprecated|Using legacy service\.telemetry\.resource'
# sha256 of the supervisor.yaml the v2 package ships (no endpoint/key) - as in the vendor's installer
DEFAULT_SUPERVISOR_CFG_HASH="ac4e6001f1b19d371bba6a2797ba0a55d7ca73151ba6908040598ca275c0efca"
# The publisher's package-signing key (primary key fingerprint). The key itself comes from the gateway
# (packages/<package>-<tag>-gpg-keys.tar.gz); it is accepted only if it is this key. When the publisher
# rotates its key, pass the new fingerprint with --signing-key FPR after checking it independently.
PUBLISHER_FPR="7A0E3514903C1907DFED7DF16D1F39C113D127C8"

REPO_PORT_DEFAULT=8080
OPAMP_PORT_DEFAULT=3001
OTLP_PORT=4317

# Steps in execution order --------------------------------------------------------
STEPS=(preflight gateway download verify install configure start connect)
declare -A STEP_TITLE=(
  [preflight]="Pre-flight checks on this host"
  [gateway]="Gateway repository and ports"
  [download]="Download the collector package from the gateway"
  [verify]="Verify checksums and the publisher signature"
  [install]="Install the collector package"
  [configure]="Write the collector configuration"
  [start]="Enable and start the collector service"
  [connect]="Verify the agent is connected through the gateway"
)
declare -A STEP_REF=(
  [preflight]="Stage 8, pre-flight" [gateway]="§8.1" [download]="§8.2" [verify]="§8.2"
  [install]="§8.2, §8.3" [configure]="§8.4" [start]="§8.4" [connect]="§8.9"
)

# Saved answers ($CONF_FILE, root-only). The secret key is deliberately NOT one of them.
CONF_KEYS=(GATEWAY REPO_PORT OPAMP_ENDPOINT BP_VERSION AGENT_LABELS AGENT_NAME PAUSE_BETWEEN_STEPS)
init_defaults() {
  GATEWAY="" REPO_PORT="" OPAMP_ENDPOINT="" BP_VERSION="" AGENT_LABELS="" AGENT_NAME="" PAUSE_BETWEEN_STEPS="no"
}
# a changed answer sends these steps round again
declare -A DEPENDS=(
  [GATEWAY]="gateway download verify connect"
  [REPO_PORT]="gateway download verify"
  [OPAMP_ENDPOINT]="gateway configure start connect"
  [BP_VERSION]="gateway download verify install configure start connect"
  [AGENT_LABELS]="configure start connect"
  [AGENT_NAME]="configure start connect"
)

# Runtime globals -------------------------------------------------------------------
ACTION="install"; ACTION_ARG=""; FROM_STEP=""; ONLY_STEP=""
ASSUME_YES=0; RECONFIGURE=0; FORCE_PAUSE=0; USE_COLOR=1; FORCE_ALL=0; ADHOC=0
NO_GPG_CHECK=0; REINSTALL=0; OTHER_ACTION=""; OTHER_SECRET=""
ARG_GATEWAY=""; ARG_REPO_PORT=""; ARG_ENDPOINT=""; ARG_VERSION=""; ARG_LABELS=""; ARG_ZONE=""; ARG_NAME=""
ARG_PKG_TYPE=""; SECRET_FILE=""
CURRENT_STEP=""; DL_PID=""; CONFIG_CHANGED=0
FAIL_WHAT=""; FAIL_WHY=""; FAIL_FIX=""; LAST_OUT=""
RUN_TS=$(date +%Y%m%d-%H%M%S)
LOG_FILE=""; RUN_TMP=""; TTY=""; TTY_OUT=0
ENV_SECRET=${BP_SECRET:-}; BP_SECRET=""; SECRET_SOURCE=""
OS_ID=""; OS_LIKE=""; OS_PRETTY=""; OS_LABEL=""; ARCH=""; PKG_TYPE=""
REPO_SUMS=""; REPO_INFO=""; REPO_VERSIONS=""; REPO_CODE=""; DL_RC=0; DL_CODE=""; DL_ERR=""
SIG_RESULT=""
SELF=$0; [[ -f $SELF ]] || SELF="bp-agent-install-linux.sh"

# =============================================================================
#  Output, logging and prompts   (shared with the NCINGA gateway scripts)
# =============================================================================
# NCINGA banner and IP notice - printed at the start of every run
print_brand() {
  local title=$1
  printf '%s\n' "$C_BLU"
  cat <<'NCINGA_ART'
   ##    ##  ######  #### ##    ##  ######      ###
   ###   ## ##    ##  ##  ###   ## ##    ##    ## ##
   ####  ## ##        ##  ####  ## ##         ##   ##
   ## ## ## ##        ##  ## ## ## ##   #### ##     ##
   ##  #### ##        ##  ##  #### ##    ##  #########
   ##   ### ##    ##  ##  ##   ### ##    ##  ##     ##
   ##    ##  ######  #### ##    ##  ######   ##     ##
NCINGA_ART
  printf '%s\n' "$C_OFF"
  printf '   %sNCINGA internal implementation tool%s - Bindplane air-gapped deployment\n' "$C_BLD" "$C_OFF"
  printf '   %s\n' "$title"
  printf '   %s(c) 2026 NCINGA. All rights reserved. Proprietary and confidential: for use on NCINGA\n' "$C_DIM"
  printf '   engagements by authorised personnel only. Provided as is, without warranty (see the header).%s\n' "$C_OFF"
  log "NCINGA $SCRIPT_NAME v$SCRIPT_VERSION - $title"
}
setup_colors() {
  if (( USE_COLOR )) && [[ -t 1 ]]; then
    C_RED=$'\e[31m' C_GRN=$'\e[32m' C_YLW=$'\e[33m' C_BLU=$'\e[36m'
    C_BLD=$'\e[1m' C_DIM=$'\e[2m' C_OFF=$'\e[0m'
  else
    C_RED="" C_GRN="" C_YLW="" C_BLU="" C_BLD="" C_DIM="" C_OFF=""
  fi
  [[ -t 1 ]] && TTY_OUT=1
}
sed_escape() { printf '%s' "$1" | sed -e 's/[]\/$*.^[]/\\&/g'; }
# Never let the secret key reach a log or evidence file.
redact_stream() {
  if [[ -n ${BP_SECRET:-} ]]; then sed -e "s/$(sed_escape "$BP_SECRET")/***REDACTED***/g"; else cat; fi
}
log() {
  [[ -n $LOG_FILE ]] || return 0
  printf '%s %s\n' "$(date '+%F %T')" "$*" | redact_stream >>"$LOG_FILE"
}
log_file() { [[ -n $LOG_FILE && -f $1 ]] && redact_stream <"$1" >>"$LOG_FILE"; return 0; }
info() { printf '%s[INFO]%s %s\n' "$C_BLU" "$C_OFF" "$*"; log "INFO $*"; }
ok()   { printf '%s[ OK ]%s %s\n' "$C_GRN" "$C_OFF" "$*"; log "OK   $*"; }
warn() { printf '%s[WARN]%s %s\n' "$C_YLW" "$C_OFF" "$*"; log "WARN $*"; }
err()  { printf '%s[FAIL]%s %s\n' "$C_RED" "$C_OFF" "$*"; log "FAIL $*"; }
hint() { printf '       %s-> %s%s\n' "$C_DIM" "$*" "$C_OFF"; log "HINT $*"; }
say()  { printf '%s\n' "$*"; log "     $*"; }
hr()   { printf '%s\n' "------------------------------------------------------------------------------"; }
banner_line() { printf '\n%s%s%s\n' "$C_BLD" "$*" "$C_OFF"; log "==== $*"; }
# Print the last N lines of a file, indented (for failed commands).
show_tail() {
  local f=$1 n=${2:-20}
  [[ -s $f ]] || return 0
  printf '%s      | last %s lines of output:%s\n' "$C_DIM" "$n" "$C_OFF"
  tail -n "$n" "$f" | redact_stream | sed -e 's/^/      | /'
}
# Record a failure explanation. Usage: fail "what" "why" "fix"; return 1
fail() { FAIL_WHAT=${1-}; FAIL_WHY=${2-}; FAIL_FIX=${3-}; return 1; }
print_block() { # label text  (text may contain \n)
  local label=$1 text=$2 first=1 line
  [[ -n $text ]] || return 0
  while IFS= read -r line; do
    if (( first )); then printf '  %-14s %s\n' "$label" "$line"; first=0
    else printf '  %-14s %s\n' "" "$line"; fi
  done < <(printf '%b\n' "$text")
}
print_failure() {
  local step=$1
  echo
  printf '%s' "$C_RED"; hr; printf '  STEP FAILED: %s  (runbook %s)\n' "${STEP_TITLE[$step]:-$step}" "${STEP_REF[$step]:-}"; hr; printf '%s' "$C_OFF"
  print_block "What happened" "${FAIL_WHAT:-The step returned an error (see output above).}"
  print_block "Likely cause"  "${FAIL_WHY:-}"
  print_block "How to fix"    "${FAIL_FIX:-}"
  print_block "Full log"      "$LOG_FILE"
  hr
  log "STEP FAILED $step | what: $FAIL_WHAT | why: $FAIL_WHY | fix: $FAIL_FIX"
}
trim() { local s=$1; s=${s#"${s%%[![:space:]]*}"}; s=${s%"${s##*[![:space:]]}"}; printf '%s' "$s"; }
mask() { local s=$1; (( ${#s} > 10 )) && printf '%s****%s' "${s:0:4}" "${s: -4}" || printf '****'; }
human() { awk -v b="${1:-0}" 'BEGIN{split("B KB MB GB TB",u," ");i=1;while(b>=1024&&i<5){b/=1024;i++};printf (i==1?"%d %s":"%.1f %s"),b,u[i]}'; }
sha256() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }
contains_word() { [[ " $1 " == *" $2 "* ]]; }
ask() {
  local __var=$1 prompt=$2 def=${3-} validator=${4-} optional=${5:-0} ans msg
  while :; do
    if (( ASSUME_YES )) || [[ -z $TTY ]]; then
      if [[ -z $def && $optional != 1 && -z $TTY ]]; then
        err "A value is required for: $prompt"
        hint "No terminal is available to ask. Run the script interactively (not through a pipe)."
        return 1
      fi
      ans=$def
      printf '  %s: %s %s(default)%s\n' "$prompt" "${ans:-<none>}" "$C_DIM" "$C_OFF"
    else
      if [[ -n $def ]]; then printf '  %s [%s]: ' "$prompt" "$def" >"$TTY"
      else printf '  %s: ' "$prompt" >"$TTY"; fi
      if ! IFS= read -r ans <"$TTY"; then echo >"$TTY"; return 1; fi
      ans=$(trim "$ans")
      [[ -z $ans ]] && ans=$def
      if [[ $optional == 1 && ( ${ans,,} == none || $ans == - ) ]]; then ans=""; fi
    fi
    if [[ -n $validator ]] && ! msg=$("$validator" "$ans"); then
      warn "  ${msg:-'$ans' is not valid here.}"
      if (( ASSUME_YES )) || [[ -z $TTY ]]; then return 1; fi
      continue
    fi
    printf -v "$__var" '%s' "$ans"
    log "ANSWER $prompt = $ans"
    return 0
  done
}
# ask_yn "question" default(y|n)  -> 0 = yes
ask_yn() {
  local prompt=$1 def=${2:-n} ans
  if (( ASSUME_YES )) || [[ -z $TTY ]]; then
    printf '  %s %s(%s, default)%s\n' "$prompt" "$C_DIM" "$def" "$C_OFF"
    log "ANSWER $prompt = $def (default)"
    [[ $def == y ]]; return
  fi
  while :; do
    printf '  %s [%s]: ' "$prompt" "$([[ $def == y ]] && echo Y/n || echo y/N)" >"$TTY"
    IFS= read -r ans <"$TTY" || return 1
    ans=$(trim "${ans:-$def}")
    case ${ans,,} in
      y|yes) log "ANSWER $prompt = yes"; return 0 ;;
      n|no)  log "ANSWER $prompt = no";  return 1 ;;
    esac
    printf '  Please answer y or n.\n' >"$TTY"
  done
}
# single-key menu: choose "prompt" "rdsq" [default] -> echoes chosen letter
choose() {
  local prompt=$1 allowed=$2 def=${3:-} c
  while :; do
    printf '%s' "$prompt" >"$TTY"
    IFS= read -r c <"$TTY" || { echo q; return; }
    c=$(trim "${c,,}"); c=${c:0:1}; c=${c:-$def}
    [[ -n $c && $allowed == *"$c"* ]] && { log "MENU $c"; echo "$c"; return; }
  done
}
ask_secret() {
  local __var=$1 prompt=$2 a b
  if [[ -z $TTY ]]; then err "Cannot prompt for the secret key without a terminal."; return 1; fi
  while :; do
    printf '  %s: ' "$prompt" >"$TTY"; IFS= read -rs a <"$TTY"; echo >"$TTY"
    a=$(trim "$a")
    [[ -n $a ]] || { warn "  The secret key cannot be empty (an empty key fails exactly like a wrong one)."; continue; }
    printf '  Re-enter to confirm: ' >"$TTY"; IFS= read -rs b <"$TTY"; echo >"$TTY"
    [[ $a == "$(trim "$b")" ]] || { warn "  The two entries did not match - try again."; continue; }
    printf -v "$__var" '%s' "$a"
    log "ANSWER secret key entered (length ${#a})"
    return 0
  done
}

# --- validators: print a message and return 1 when invalid ---------------------
# --- validators: print a message and return 1 when invalid ---------------------
is_ipv4() {
  local ip=$1 o
  [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
}
v_version(){ [[ $1 =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.]+)?$ ]] || { echo "'$1' is not a release tag. Use the form v1.108.1"; return 1; }; }
v_labels() { [[ $1 =~ ^[A-Za-z0-9_.-]+=[A-Za-z0-9_.-]+(,[A-Za-z0-9_.-]+=[A-Za-z0-9_.-]+)*$ ]] || { echo "Use key=value pairs separated by commas, e.g. site=primary,segment=prod-live,role=gateway"; return 1; }; }
v_agent_name() { [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$ ]] || { echo "Letters, digits, '.', '_' or '-' only (max 63)."; return 1; }; }
v_host() {
  local h=${1%:*}
  [[ $1 == *:* ]] && { [[ ${1##*:} =~ ^[0-9]{1,5}$ ]] || { echo "The port after ':' must be a number, e.g. 10.20.30.40:8080"; return 1; }; }
  is_ipv4 "$h" && return 0
  [[ $h =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]] \
    || { echo "Enter the gateway's IPv4 address (e.g. 10.20.30.40) or host name."; return 1; }
}
v_endpoint() {
  [[ $1 =~ ^wss?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[^[:space:]\"]*)?$ ]] \
    || { echo "Use the form ws://<gateway>:$OPAMP_PORT_DEFAULT/v1/opamp"; return 1; }
}
v_label_value() {
  [[ $1 =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "Letters, digits, '.', '_' or '-' only (no spaces, commas or '=')."; return 1; }
}
v_step() { contains_word "${STEPS[*]}" "$1" || { echo "Unknown step '$1'. Steps: ${STEPS[*]}"; return 1; }; }

# =============================================================================
#  Config and progress state
# =============================================================================
save_config() {
  local tmp k
  tmp=$(mktemp "$STATE_DIR/.conf.XXXXXX") || return 1
  {
    echo "# $SCRIPT_NAME answers - written $(date -Is). Root-only (0600)."
    echo "# The Bindplane secret key is NOT stored here (it is only in the collector's config file)."
    for k in "${CONF_KEYS[@]}"; do printf '%s=%q\n' "$k" "${!k-}"; done
  } >"$tmp"
  chmod 600 "$tmp" && mv -f "$tmp" "$CONF_FILE"
}
load_config() {
  [[ -f $CONF_FILE ]] || return 1
  local owner perm
  owner=$(stat -c %u "$CONF_FILE"); perm=$(stat -c %a "$CONF_FILE")
  if [[ $owner != 0 || $perm != 600 ]]; then
    err "Refusing to read $CONF_FILE: it must be owned by root with mode 600 (found uid=$owner mode=$perm)."
    hint "Fix with: chown root:root $CONF_FILE && chmod 600 $CONF_FILE"
    exit 1
  fi
  # shellcheck disable=SC1090
  source "$CONF_FILE"
}
state_get() { [[ -f $STATE_FILE ]] && awk -F'|' -v s="$1" '$1==s{st=$2} END{print st}' "$STATE_FILE"; return 0; }
state_set() {
  (( ADHOC )) && return 0
  local tmp
  tmp=$(mktemp "$STATE_DIR/.progress.XXXXXX") || return 1
  { [[ -f $STATE_FILE ]] && grep -v "^$1|" "$STATE_FILE"; printf '%s|%s|%s\n' "$1" "$2" "$(date -Is)"; } >"$tmp"
  chmod 600 "$tmp"; mv -f "$tmp" "$STATE_FILE"
  log "STATE $1=$2"
}
step_index() { local i; for i in "${!STEPS[@]}"; do [[ ${STEPS[$i]} == "$1" ]] && { echo $((i+1)); return; }; done; echo 0; }

# =============================================================================
#  Command runners
# =============================================================================
# run "description" cmd [args...]  - output goes to the log; tail shown on failure
run() {
  local desc=$1 rc; shift
  LAST_OUT="$RUN_TMP/last.out"
  printf '    %s ... ' "$desc"
  log "CMD  $*"
  "$@" >"$LAST_OUT" 2>&1 9>&-; rc=$?
  log_file "$LAST_OUT"
  if (( rc == 0 )); then printf '%sok%s\n' "$C_GRN" "$C_OFF"
  else printf '%sFAILED (exit %d)%s\n' "$C_RED" "$rc" "$C_OFF"; show_tail "$LAST_OUT" 20; fi
  return $rc
}
# run_stream "description" cmd [args...] - like run, but streams output live
run_stream() {
  local desc=$1 rc; shift
  LAST_OUT="$RUN_TMP/last.out"
  info "$desc"
  log "CMD  $*"
  "$@" 2>&1 9>&- | tee "$LAST_OUT" | sed -u -e 's/^/      | /'
  rc=${PIPESTATUS[0]}
  log_file "$LAST_OUT"
  if (( rc == 0 )); then ok "$desc - done"; else err "$desc - FAILED (exit $rc)"; fi
  return $rc
}
# curl for endpoints on this host: never through a proxy
lcurl() { curl --noproxy '*' "$@"; }

# =============================================================================
#  Platform and collector detection
# =============================================================================
# shellcheck disable=SC2034  # COLLECTOR_* are read here and by the scripts built from this one
use_family() {
  COLLECTOR_FAMILY=$1
  if [[ $1 == v2 ]]; then
    COLLECTOR_PKG=$V2_PKG; COLLECTOR_SVC=$V2_PKG; COLLECTOR_HOME=$V2_HOME; COLLECTOR_CONF=$SUP_YAML
    COLLECTOR_LOG="$V2_HOME/supervisor.log"; COLLECTOR_BIN="$V2_HOME/bindplane-otel-collector"; COLLECTOR_PROC="opampsupervisor"
  else
    COLLECTOR_PKG=$V1_PKG; COLLECTOR_SVC=$V1_PKG; COLLECTOR_HOME=$V1_HOME; COLLECTOR_CONF=$MANAGER_YAML
    COLLECTOR_LOG="$V1_HOME/log/collector.log"; COLLECTOR_BIN="$V1_HOME/observiq-otel-collector"; COLLECTOR_PROC="observiq"
  fi
}
family_of_version() { [[ $1 =~ ^v?([2-9]|[1-9][0-9]+)\. ]] && echo v2 || echo v1; }
product_of_family() { [[ $1 == v2 ]] && echo "$V2_PKG" || echo "$V1_PKG"; }
family_label() { [[ $1 == v2 ]] && echo "v2 ($V2_PKG, supervisor.yaml)" || echo "v1 ($V1_PKG, manager.yaml)"; }
is_prerelease() { [[ $1 == *-* ]]; }
# sort_tags - newest last; a pre-release sorts before its release (v2.0.1-beta.6 < v2.0.1)
sort_tags() { sed 's/-/~/' | sort -V | sed 's/~/-/'; }
order_tags() { # LIST -> v1 tags newest first, then v2 tags newest first
  local fam t
  for fam in v1 v2; do for t in $1; do [[ $(family_of_version "$t") == "$fam" ]] && echo "$t"; done | sort_tags | tac; done | awk '!seen[$0]++' | paste -sd' '
}
installed_family() { # the collector family installed on this host: v1, v2, both or none
  local a b; a=$(pkg_version "$V1_PKG"); b=$(pkg_version "$V2_PKG")
  if [[ -n $a && -n $b ]]; then echo both; elif [[ -n $b ]]; then echo v2; elif [[ -n $a ]]; then echo v1; else echo none; fi
}
# yaml_get KEY - endpoint | secret_key | agent_id | labels | agent_name of the active collector family
yaml_get() {
  local f=$COLLECTOR_CONF
  if [[ $COLLECTOR_FAMILY == v2 ]]; then
    case $1 in
      agent_id)   sed -n 's/^instance_id:[[:space:]]*//p' "$V2_HOME/supervisor_storage/persistent_state.yaml" 2>/dev/null | head -n1; return 0 ;;
      agent_name) hostname -s; return 0 ;;
    esac
    [[ -r $f ]] || return 0
    case $1 in
      endpoint)   sed -nE 's/^[[:space:]]+endpoint:[[:space:]]*"?([^"[:space:]]+)"?.*/\1/p' "$f" | head -n1 ;;
      secret_key) sed -nE 's/^[[:space:]]*Authorization:[[:space:]]*"?Secret-Key[[:space:]]+([^"[:space:]]+)"?.*/\1/p' "$f" | head -n1 ;;
      labels)     sed -nE 's/^[[:space:]]+service\.labels:[[:space:]]*"?([^"]*)"?.*/\1/p' "$f" | head -n1 ;;
    esac
    return 0
  fi
  [[ -r $f ]] || return 0
  sed -nE "s/^$1:[[:space:]]*//p" "$f" | head -n1 | sed -E "s/[[:space:]]+#.*$//; s/^[\"']//; s/[\"'][[:space:]]*$//"
}
collector_version() {
  local v=""
  v=$(pkg_version "$COLLECTOR_PKG")
  if [[ -z $v && $COLLECTOR_FAMILY == v1 && -x $COLLECTOR_BIN ]]; then
    v=$("$COLLECTOR_BIN" --version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
  fi
  printf '%s' "$v"
}
other_family() { [[ $1 == v2 ]] && echo v1 || echo v2; }
# owner of the collector home, e.g. bdot:bdot (v1.108+ and v2)
collector_owner() { stat -c '%U:%G' "$COLLECTOR_HOME" 2>/dev/null || echo root:root; }
collector_log_errors() { # last N problem lines since line $1 of the active family's log (default: last 200 lines)
  [[ -r $COLLECTOR_LOG ]] || return 0
  local from=${1:-0} n=${2:-5}
  if (( from > 0 )); then tail -n +"$((from+1))" "$COLLECTOR_LOG"; else tail -n 200 "$COLLECTOR_LOG"; fi 2>/dev/null \
    | grep -iE '"level":"error"|error|refused|denied|unauthor|forbidden|bad handshake|status=[45][0-9][0-9]' | grep -vE "$BENIGN_LOG_RE" \
    | sed -E 's/"resource":\{[^}]*\},?//; s/"stacktrace":"[^"]*"//; s/"caller":"[^"]*",?//; s/,\}$/}/' | tail -n "$n" | cut -c1-230
}
http_code_in_log() { # FROM -> the last 4xx/5xx status the collector logged (v1 "status=403", v2 "status=403 Forbidden")
  [[ -r $COLLECTOR_LOG ]] || return 0
  local from=${1:-0}; (( from < 0 )) && from=0
  tail -n +"$((from+1))" "$COLLECTOR_LOG" 2>/dev/null | grep -oE 'status[ =:"]*[45][0-9]{2}' | grep -oE '[45][0-9]{2}' | tail -n1
}
# own_name_versions - "package_version_..." file names -> versions whose name matches their family
# (a v2 release saved under the v1 name, i.e. a renamed download, is ignored)
own_name_versions() {
  local f p v
  while read -r f; do
    p=${f%%_v*}; v=${f#*_}; v=${v%%_linux_*}
    [[ $p == "$(product_of_family "$(family_of_version "$v")")" ]] && echo "$v"
  done | awk '!seen[$0]++' | paste -sd' '
}

os_field() { ( . /etc/os-release 2>/dev/null; eval "printf '%s' \"\${$1:-}\"" ); }

# detect_platform -> OS_* ARCH PKG_TYPE (deb|rpm|"") OS_LABEL (the os= label value)
detect_platform() {
  local m words
  OS_ID=$(os_field ID); OS_LIKE=$(os_field ID_LIKE); OS_PRETTY=$(os_field PRETTY_NAME)
  [[ -n $OS_PRETTY ]] || OS_PRETTY="$(uname -s) $(uname -r)"
  m=$(uname -m)
  case $m in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) ARCH="unsupported($m)" ;; esac
  words=" $OS_ID $OS_LIKE "
  if [[ -n $ARG_PKG_TYPE ]]; then PKG_TYPE=$ARG_PKG_TYPE
  elif [[ $words =~ [[:space:]](debian|ubuntu)[[:space:]] ]] && command -v dpkg >/dev/null; then PKG_TYPE=deb
  elif [[ $words =~ [[:space:]](rhel|fedora|centos|rocky|almalinux|ol|amzn|suse|sles|opensuse)[[:space:]] ]] && command -v rpm >/dev/null; then PKG_TYPE=rpm
  elif command -v dpkg >/dev/null && ! command -v rpm >/dev/null; then PKG_TYPE=deb
  elif command -v rpm >/dev/null; then PKG_TYPE=rpm
  else PKG_TYPE=""; fi
  case $OS_ID in
    ubuntu|debian) OS_LABEL=$OS_ID ;;
    rhel|centos|rocky|almalinux|ol|fedora) OS_LABEL=rhel ;;
    sles|sled|opensuse*) OS_LABEL=suse ;;
    amzn) OS_LABEL=amazon ;;
    *) OS_LABEL=$(tr -cd 'A-Za-z0-9_.-' <<<"${OS_ID:-linux}") ;;
  esac
}
rpm_arch() { [[ $1 == arm64 ]] && echo aarch64 || echo x86_64; }

# pkg_version PACKAGE -> installed version as a release tag (2.0.1~beta.6 -> v2.0.1-beta.6), or empty
pkg_version() {
  local v
  if [[ $PKG_TYPE == rpm ]]; then
    v=$(rpm -q --qf '%{VERSION}\n' "$1" 2>/dev/null | head -n1) || return 0
  else
    v=$(dpkg-query -W -f='${Status}|${Version}' "$1" 2>/dev/null)
    [[ $v == *"ok installed|"* ]] || return 0
    v=${v##*|}
  fi
  [[ -n $v ]] && printf 'v%s' "${v//\~/-}"
  return 0
}
# the family to work with: that of the chosen version, else the one installed here (v1 when none)
set_family() {
  if [[ -n ${BP_VERSION:-} ]]; then use_family "$(family_of_version "$BP_VERSION")"
  else case $(installed_family) in v2) use_family v2 ;; *) use_family v1 ;; esac; fi
}
installed_summary() {
  case $(installed_family) in
    none) echo "none" ;;
    both) echo "v1 $(pkg_version "$V1_PKG") + v2 $(pkg_version "$V2_PKG")" ;;
    v2)   echo "v2 $(pkg_version "$V2_PKG") ($V2_PKG)" ;;
    *)    echo "v1 $(pkg_version "$V1_PKG") ($V1_PKG)" ;;
  esac
}
# file name of a version's package in the repository, for this host
pkg_rel() { printf 'packages/%s_%s_linux_%s.%s' "$(product_of_family "$(family_of_version "$1")")" "$1" "$ARCH" "$PKG_TYPE"; }
pkg_file() { printf '%s/%s' "$CACHE_DIR" "$(basename "$(pkg_rel "$1")")"; }
# the version string the package carries (dpkg/rpm form): v2.0.1-beta.6 -> 2.0.1~beta.6
pkg_native_version() { local v=${1#v}; printf '%s' "${v/-/\~}"; }
label_get() { tr ',' '\n' <<<"${AGENT_LABELS:-}" | sed -n "s/^$1=//p" | head -n1; }

# =============================================================================
#  The gateway: repository (http://GATEWAY:REPO_PORT/) and relay (OPAMP_ENDPOINT)
# =============================================================================
repo_url() { printf 'http://%s:%s/%s' "$GATEWAY" "$REPO_PORT" "${1#/}"; }
# repo_fetch PATH OUTFILE -> curl exit code; REPO_CODE = HTTP status
repo_fetch() {
  local rc
  REPO_CODE=$(lcurl -sS --connect-timeout 10 --max-time 60 -o "$2" -w '%{http_code}' "$(repo_url "$1")" 2>"$RUN_TMP/repo.err"); rc=$?
  log "GET $(repo_url "$1") -> rc=$rc http=$REPO_CODE"
  if (( rc == 0 )) && [[ $REPO_CODE != 200 ]]; then rc=22; fi
  return "$rc"
}
opamp_host() { local h=${OPAMP_ENDPOINT#*://}; h=${h%%/*}; printf '%s' "${h%%:*}"; }
opamp_port() { local h=${OPAMP_ENDPOINT#*://}; h=${h%%/*}; [[ $h == *:* ]] && printf '%s' "${h##*:}" || { [[ $OPAMP_ENDPOINT == wss:* ]] && echo 443 || echo 80; }; }
resolve_ip() { is_ipv4 "$1" && { echo "$1"; return 0; }; getent ahostsv4 "$1" 2>/dev/null | awk 'NR==1{print $1}'; }
info_field() { [[ -f $REPO_INFO ]] && sed -n "s/^$1=//p" "$REPO_INFO" | head -n1; return 0; }

# load_repo_index - fetch SHA256SUMS (the authoritative list of what the gateway serves) and VERSION-INFO;
#   REPO_VERSIONS = versions with a package for this OS type and architecture (v1 newest first, then v2)
load_repo_index() {
  local rc
  REPO_SUMS="$RUN_TMP/repo.SHA256SUMS"; REPO_INFO="$RUN_TMP/repo.VERSION-INFO"; REPO_VERSIONS=""
  repo_fetch SHA256SUMS "$REPO_SUMS"; rc=$?
  if (( rc != 0 )); then rm -f "$REPO_SUMS"; return "$rc"; fi
  grep -qE '^[0-9a-f]{64}[[:space:]]+' "$REPO_SUMS" || { REPO_CODE="not-a-sums-file"; rm -f "$REPO_SUMS"; return 22; }
  repo_fetch VERSION-INFO "$REPO_INFO" || : >"$REPO_INFO"
  REPO_VERSIONS=$(order_tags "$(awk '{print $2}' "$REPO_SUMS" \
     | grep -oE "^packages/($V1_PKG|$V2_PKG)_v[0-9][^_/]*_linux_${ARCH}\.${PKG_TYPE}$" | sed 's#^packages/##' | own_name_versions)")
  return 0
}
repo_has() { [[ -n $REPO_SUMS && -f $REPO_SUMS ]] && awk -v n="$1" '$2==n{f=1} END{exit !f}' "$REPO_SUMS"; }
repo_sum() { awk -v n="$1" '$2==n {print $1; exit}' "$REPO_SUMS" 2>/dev/null; }

# tcp_state HOST PORT -> open | refused | timeout | unreachable | error
tcp_state() {
  local out rc
  out=$(timeout 6 bash -c "exec 3<>/dev/tcp/$1/$2" 2>&1 9>&-); rc=$?
  if (( rc == 0 )); then echo open
  elif (( rc == 124 )); then echo timeout
  elif [[ $out == *refused* ]]; then echo refused
  elif [[ $out == *"No route"* || $out == *nreachable* ]]; then echo unreachable
  elif [[ $out == *"Name or service"* || $out == *"not known"* ]]; then echo noname
  else echo error; fi
}
route_src() { ip -o route get "$1" 2>/dev/null | grep -oE 'src [0-9.]+' | awk '{print $2}'; }

# explain_tcp HOST PORT STATE PURPOSE -> result line + hints; returns 1 unless open
explain_tcp() {
  local h=$1 p=$2 st=$3 what=$4 src
  src=$(route_src "$(resolve_ip "$h")")
  case $st in
    open) ok "TCP $h:$p reachable ($what)"; return 0 ;;
    timeout) err "TCP $h:$p timed out ($what)"
             hint "A firewall silently drops ${src:-this host} -> $h tcp/$p: the rule for this log source is missing or not installed yet. Raise it with the network team (runbook Stage 7/8 firewall rules)." ;;
    refused) err "TCP $h:$p refused ($what)"
             hint "The gateway answered but nothing listens on port $p: the service there is stopped. On the gateway: bp-live-setup.sh --diagnose (LIVE) or bp-dmz-setup.sh --diagnose (DMZ)." ;;
    unreachable) err "TCP $h:$p unreachable ($what)"
             hint "No route from this host to $h: wrong address, or a routing problem (ip route get $h)." ;;
    noname) err "$h does not resolve ($what)"
             hint "Name resolution is not available on most isolated segments - use the gateway's IP address." ;;
    *) err "TCP $h:$p could not be tested ($what)"; hint "Try: timeout 5 bash -c '</dev/tcp/$h/$p' && echo open" ;;
  esac
  return 1
}

# explain_repo_failure RC WHAT -> FAIL_* for a failed request to the gateway repository
explain_repo_failure() {
  local rc=$1 what=$2 url st
  url=$(repo_url "$what")
  case $rc in
    7)  st=$(tcp_state "$GATEWAY" "$REPO_PORT")
        if [[ $st == refused ]]; then
          fail "The gateway $GATEWAY refused the connection on port $REPO_PORT." "nginx (the repository) is not running on the gateway, or listens on another port." \
               "On the gateway: systemctl status nginx ; ss -lntp | grep :$REPO_PORT\nIf the repository uses another port, re-run with --reconfigure and enter <gateway>:<port>."
        else
          fail "Could not connect to the gateway repository $GATEWAY:$REPO_PORT ($st)." "The firewall rule from this host to the gateway on tcp/$REPO_PORT is missing, or the address is wrong." \
               "Test: timeout 5 bash -c '</dev/tcp/$GATEWAY/$REPO_PORT' && echo open\nThe address is the gateway of THIS segment (LIVE log sources: the LIVE gateway). Change it with --reconfigure."
        fi ;;
    6)  fail "$GATEWAY does not resolve." "There is no DNS for that name on this segment." "Use the gateway's IP address: re-run with --reconfigure." ;;
    28) fail "The request to $GATEWAY:$REPO_PORT timed out." "A firewall silently drops this host -> $GATEWAY tcp/$REPO_PORT, or the gateway is overloaded." \
             "Test: curl -sv --noproxy '*' --max-time 10 $(repo_url /VERSION-INFO)\nRaise the missing rule with the network team, then retry." ;;
    18|56|52|92) fail "The connection to the gateway was cut during the transfer (curl exit $rc)." "An inline device reset the connection, or the gateway restarted." "Choose [r] - downloads resume where they stopped." ;;
    23) fail "Could not write the download to $CACHE_DIR." "The filesystem is full or read-only." "df -h $CACHE_DIR" ;;
    22) case $REPO_CODE in
          404) if [[ $what == SHA256SUMS ]]; then
                 fail "$GATEWAY:$REPO_PORT answers, but has no SHA256SUMS (HTTP 404) - it is not the gateway repository." \
                      "A wrong port (the repository is on :$REPO_PORT_DEFAULT; :$OPAMP_PORT_DEFAULT is the OpAMP relay), or another web server." \
                      "Re-run with --reconfigure and enter the repository address (<gateway> or <gateway>:<port>)."
                 return
               fi
               fail "The gateway has no $what (HTTP 404)." \
                    "The gateway's repository does not hold this file: the version is not staged there, or the LIVE mirror is not in sync with the DMZ repository." \
                    "On the DMZ host: bp-dmz-update-repo.sh --status (stage the version if missing)\nOn the LIVE gateway: bp-live-setup.sh --sync-mirror\nThen retry." ;;
          403) fail "The gateway refused $what (HTTP 403)." "File permissions in the repository on the gateway (nginx cannot read it)." "On the gateway: chmod -R a+rX /srv/bindplane" ;;
          not-a-sums-file) fail "$url did not return a SHA256SUMS file." "This address/port is not the NCINGA Bindplane repository (another web service answered)." "Check the gateway address and port (--reconfigure)." ;;
          000|"") fail "No HTTP answer from $url." "See the curl error: $(tail -n1 "$RUN_TMP/repo.err" 2>/dev/null)" "curl -sv --noproxy '*' $url" ;;
          *)   fail "The gateway answered HTTP $REPO_CODE for $what." "Unexpected response from the repository web server." "curl -sv --noproxy '*' $url ; on the gateway: tail /var/log/nginx/bindplane-repo.error.log" ;;
        esac ;;
    *)  fail "The request to $url failed (curl exit $rc)." "$(tail -n1 "$RUN_TMP/repo.err" 2>/dev/null)" "curl -sv --noproxy '*' $url" ;;
  esac
}

# download REL DEST -> resumable download from the gateway; DL_RC DL_CODE DL_ERR
download() {
  local rel=$1 dest=$2 attempt size total="" url errf="$RUN_TMP/dl.err" codef="$RUN_TMP/dl.code"
  url=$(repo_url "$rel")
  total=$(lcurl -sSI --connect-timeout 10 --max-time 20 "$url" 2>/dev/null | tr -d '\r' | awk 'tolower($1)=="content-length:"{print $2}' | tail -n1)
  for attempt in 1 2; do
    : >"$errf"; : >"$codef"
    lcurl -f -sS --connect-timeout 15 --retry 3 --retry-delay 3 --speed-limit 1024 --speed-time 60 \
         -C - -o "$dest" -w '%{http_code}' "$url" >"$codef" 2>"$errf" 9>&- &
    DL_PID=$!
    while kill -0 "$DL_PID" 2>/dev/null; do
      if (( TTY_OUT )); then
        size=$(stat -c %s "$dest" 2>/dev/null || echo 0)
        if [[ $total =~ ^[0-9]+$ ]] && (( total > 0 )); then
          printf '\r      downloading %s ... %s of %s (%d%%)   ' "$(basename "$rel")" "$(human "$size")" "$(human "$total")" $(( size * 100 / total ))
        else printf '\r      downloading %s ... %s   ' "$(basename "$rel")" "$(human "$size")"; fi
      fi
      sleep 1
    done
    wait "$DL_PID"; DL_RC=$?; DL_PID=""
    (( TTY_OUT )) && printf '\r\e[K'
    DL_CODE=$(cat "$codef" 2>/dev/null); DL_ERR=$(grep . "$errf" 2>/dev/null | tail -n 1)
    log "DOWNLOAD $url -> rc=$DL_RC http=$DL_CODE err=$DL_ERR"
    # 33/36 or HTTP 416: the partial file cannot be resumed (it changed on the gateway) -> start again
    if (( attempt == 1 )) && { (( DL_RC == 33 || DL_RC == 36 )) || [[ $DL_CODE == 416 ]]; }; then rm -f "$dest"; continue; fi
    break
  done
  REPO_CODE=$DL_CODE
  return "$DL_RC"
}

# =============================================================================
#  Checks shared by pre-flight and --diagnose (print their own result lines)
# =============================================================================
c_ok()   { ok "$@"; }
c_warn() { warn "$@"; CHK_WARNS=$((CHK_WARNS+1)); }
c_fail() { err "$@"; CHK_FAILS=$((CHK_FAILS+1)); }
check_time() {
  local sync
  sync=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
  case $sync in
    yes) c_ok "System clock is NTP-synchronised" ;;
    no)  c_warn "System clock is NOT NTP-synchronised - TLS and OpAMP both fail on clock skew"; hint "timedatectl status ; check chrony/systemd-timesyncd" ;;
    *)   c_warn "Could not read clock sync state (timedatectl)" ;;
  esac
}
CHK_FAILS=0; CHK_WARNS=0

check_platform() {
  if [[ -n $PKG_TYPE ]]; then c_ok "OS: $OS_PRETTY - packages: .$PKG_TYPE ($( [[ $PKG_TYPE == deb ]] && echo dpkg || echo rpm ))"
  else c_fail "OS: $OS_PRETTY - neither dpkg nor rpm is available"; hint "Only Debian/Ubuntu (.deb) and RHEL-family/SUSE (.rpm) hosts are supported. Force a type with --package-type deb|rpm."; fi
  case $ARCH in
    amd64|arm64) c_ok "Architecture: $ARCH" ;;
    *) c_fail "Architecture $ARCH is not staged on the gateways (amd64 and arm64 only)"
       hint "The collector exists for other architectures, but the DMZ repository stages amd64 (and arm64 when enabled)." ;;
  esac
  if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null; then c_ok "systemd is the init system"
  else c_fail "systemd is not running on this host"; hint "The collector packages install systemd units; SysV-init / non-systemd hosts are not supported by this installer."; fi
}
check_tools() {
  local c miss=""
  for c in curl sha256sum tar gzip ss ip awk sed grep stat df timeout; do command -v "$c" >/dev/null || miss+=" $c"; done
  if [[ $PKG_TYPE == deb ]]; then for c in dpkg dpkg-deb dpkg-query; do command -v "$c" >/dev/null || miss+=" $c"; done
  elif [[ $PKG_TYPE == rpm ]]; then command -v rpm >/dev/null || miss+=" rpm"; fi
  if [[ -n $miss ]]; then c_fail "Required commands missing:$miss"; hint "Install them from the internal OS repository (they are part of a standard server install)."
  else c_ok "Required tools present"; fi
  if (( ! NO_GPG_CHECK )); then
    if [[ $PKG_TYPE == deb ]]; then
      command -v gpg >/dev/null || { c_warn "gpg is not installed - the package signature cannot be checked"; hint "apt-get install gnupg (from the internal repository), or accept checksum-only verification when asked."; }
      command -v ar >/dev/null || command -v python3 >/dev/null || { c_warn "Neither 'ar' (binutils) nor python3 is installed - the .deb signature cannot be read"; hint "apt-get install binutils, or accept checksum-only verification when asked."; }
    fi
  fi
}
check_space() { # PATH MIN_MB LABEL
  local path=$1 min=$2 label=$3 avail fs
  while [[ ! -e $path ]]; do path=$(dirname "$path"); done
  avail=$(( $(df -Pk "$path" | awk 'NR==2{print $4}') * 1024 ))
  fs=$(df -P "$path" | awk 'NR==2{print $6}')
  if (( avail < min * 1024 * 1024 )); then c_fail "Only $(human $avail) free for $label (filesystem $fs) - need ~${min} MB"; hint "Free space on $fs, or point $( [[ $label == *cache* ]] && echo 'BP_CACHE_DIR' || echo 'the filesystem') elsewhere."; return 1
  else c_ok "$(human $avail) free for $label (filesystem $fs)"; fi
}
check_noexec() {
  local p=/opt opts
  [[ -d $p ]] || p=/
  opts=$(findmnt -no OPTIONS -T "$p" 2>/dev/null)
  if [[ ,$opts, == *,noexec,* ]]; then c_fail "$p is mounted noexec - the collector binary in /opt cannot run"; hint "Remount /opt without noexec, or ask the platform team for an exception for /opt/*-otel-collector."
  else c_ok "/opt allows executables"; fi
}
check_selinux() {
  command -v getenforce >/dev/null || return 0
  local m; m=$(getenforce 2>/dev/null)
  case $m in
    Enforcing) c_ok "SELinux is enforcing (the collector runs as an unconfined service; log files it reads must be readable)" ;;
    "") ;;
    *) c_ok "SELinux: $m" ;;
  esac
}
check_existing() {
  local f v st ep
  for f in v1 v2; do
    v=$(pkg_version "$(product_of_family "$f")")
    [[ -n $v ]] || continue
    st=$(systemctl is-active "$(product_of_family "$f")" 2>/dev/null)
    ep=$( use_family "$f"; yaml_get endpoint )
    c_ok "Installed: $(family_label "$f") $v (service: ${st:-unknown}${ep:+, endpoint $ep})"
    [[ -d $( use_family "$f"; echo "$COLLECTOR_HOME" ) ]] || c_warn "$(product_of_family "$f") is registered as installed but $( use_family "$f"; echo "$COLLECTOR_HOME" ) is missing - it will be reinstalled"
  done
  if [[ $PKG_TYPE == deb ]]; then
    for f in "$V1_PKG" "$V2_PKG"; do
      dpkg-query -W -f='${Status}' "$f" 2>/dev/null | grep -qE 'half-configured|unpacked|half-installed|triggers-' \
        && c_warn "$f is half-installed from an earlier attempt - the install step reinstalls it"
    done
  fi
  [[ $(installed_family) == none ]] && c_ok "No collector installed yet"
  return 0
}
check_proxy_env() {
  if env | grep -qiE '^(https?|all)_proxy=' || grep -qsiE '^(https?|all)_proxy=' /etc/environment; then
    c_ok "A proxy is configured in the environment - this script bypasses it for the gateway (curl --noproxy)"
  fi
  return 0
}

# =============================================================================
#  Secret key: never saved by this script; it ends up only in the collector config (0600)
# =============================================================================
ensure_secret() {
  [[ -n $BP_SECRET ]] && return 0
  local existing other cf
  cf=$(basename "$COLLECTOR_CONF")
  existing=$(yaml_get secret_key)
  other=${OTHER_SECRET:-$( use_family "$(other_family "$COLLECTOR_FAMILY")"; yaml_get secret_key )}
  if [[ -n $SECRET_FILE ]]; then
    [[ -r $SECRET_FILE ]] || { fail "Cannot read the secret key file $SECRET_FILE." "" "Check the path and its permissions (it must be readable by root)."; return 1; }
    BP_SECRET=$(trim "$(head -n1 "$SECRET_FILE")"); SECRET_SOURCE="file $SECRET_FILE"
    [[ -n $BP_SECRET ]] || { fail "$SECRET_FILE is empty." "" "Put the secret key on the first line."; return 1; }
    info "Using the secret key from $SECRET_FILE ($(mask "$BP_SECRET"))"
  elif [[ -n $ENV_SECRET ]]; then
    BP_SECRET=$ENV_SECRET; SECRET_SOURCE="environment"
    info "Using the secret key from the BP_SECRET environment variable ($(mask "$BP_SECRET"))"
  elif [[ -n $existing ]] && { (( ! RECONFIGURE )) || ask_yn "Keep the secret key already in $cf ($(mask "$existing"))?" y; }; then
    BP_SECRET=$existing; SECRET_SOURCE=$cf
    info "Using the secret key already in $COLLECTOR_CONF ($(mask "$BP_SECRET")) - to replace it run with --reconfigure"
  elif [[ -z $existing && -n $other ]] && ask_yn "Use the secret key of the $(other_family "$COLLECTOR_FAMILY") collector on this host ($(mask "$other"))?" y; then
    BP_SECRET=$other; SECRET_SOURCE="$(other_family "$COLLECTOR_FAMILY") collector config"
  else
    say "  The agent needs the Bindplane secret key (Bindplane console -> Agents -> Install Agents)."
    say "  It is written only to $COLLECTOR_CONF (mode 0600) - this script does not keep a copy."
    ask_secret BP_SECRET "Bindplane secret key" || { fail "No secret key was provided." "It is required in $cf." \
      "Run interactively, or for an unattended run pass it in the environment (BP_SECRET=...) or a root-only file (--secret-file PATH)."; return 1; }
    SECRET_SOURCE="prompt"
  fi
  log "secret key source: $SECRET_SOURCE"
  [[ $BP_SECRET =~ ^[0-9A-HJKMNP-TV-Z]{26}$ ]] || warn "The key is not a 26-character ULID - double-check it (an invalid key fails exactly like a wrong one)."
  return 0
}

# =============================================================================
#  Package signature (the publisher's key, pinned by fingerprint)
# =============================================================================
# ar_members DEB / ar_cat DEB MEMBER... - read a .deb (an 'ar' archive) with ar, or python3 when
# binutils is not installed (minimal servers)
ar_members() {
  if command -v ar >/dev/null; then ar t "$1"; return; fi
  python3 -I - "$1" <<'PY'
import sys
f = open(sys.argv[1], 'rb')
if f.read(8) != b'!<arch>\n': sys.exit(2)
while True:
    h = f.read(60)
    if len(h) < 60: break
    size = int(h[48:58]); print(h[:16].decode().strip().rstrip('/'))
    f.seek(size + (size % 2), 1)
PY
}
ar_cat() {
  local deb=$1; shift
  if command -v ar >/dev/null; then ar p "$deb" "$@"; return; fi
  python3 -I - "$deb" "$@" <<'PY'
import sys
want = sys.argv[2:]; out = sys.stdout.buffer; found = {}
f = open(sys.argv[1], 'rb')
if f.read(8) != b'!<arch>\n': sys.exit(2)
while True:
    h = f.read(60)
    if len(h) < 60: break
    name = h[:16].decode().strip().rstrip('/'); size = int(h[48:58])
    found[name] = (f.tell(), size); f.seek(size + (size % 2), 1)
for w in want:
    if w not in found: sys.exit(3)
    pos, size = found[w]; f.seek(pos)
    while size > 0:
        b = f.read(min(size, 1 << 20)); out.write(b); size -= len(b)
PY
}

# unpack_keys TARBALL DIR -> 0 if it holds the publisher's key
unpack_keys() {
  mkdir -p "$2" && tar -xzf "$1" -C "$2" 2>/dev/null && [[ -s $2/bdot-public-gpg-key.asc ]]
}
# key_fingerprints ASC -> primary key fingerprints in the file (needs gpg)
key_fingerprints() {
  local g; g=$(mktemp -d "$RUN_TMP/gpg.XXXXXX"); chmod 700 "$g"
  gpg --homedir "$g" --batch --with-colons --show-keys "$1" 2>/dev/null | awk -F: '$1=="pub"{p=1;next} $1=="fpr"&&p{print $10;p=0}'
  rm -rf "$g"
}

# verify_deb_sig DEB KEYDIR -> SIG_RESULT (good|expired|revoked|bad|nokey|error), FAIL_* on failure
verify_deb_sig() {
  local deb=$1 kd=$2 g members m status prim
  local -a parts=()
  g=$(mktemp -d "$RUN_TMP/gnupg.XXXXXX"); chmod 700 "$g"
  gpg --homedir "$g" --batch --import "$kd/bdot-public-gpg-key.asc" >"$RUN_TMP/gpg.import" 2>&1 \
    || { SIG_RESULT=error; fail "gpg could not import the publisher's key." "$(tail -n1 "$RUN_TMP/gpg.import")" "gpg --version ; check $kd/bdot-public-gpg-key.asc"; return 1; }
  for m in "$kd"/deb-revocations/*; do [[ -f $m ]] && gpg --homedir "$g" --batch --import "$m" >>"$RUN_TMP/gpg.import" 2>&1; done
  members=$(ar_members "$deb") || { SIG_RESULT=error; fail "$(basename "$deb") could not be read as a .deb archive." "The file is damaged." "Delete it and download again: choose [r] after: rm -f $deb"; return 1; }
  grep -qx _gpgorigin <<<"$members" || { SIG_RESULT=unsigned; fail "$(basename "$deb") carries no signature (_gpgorigin)." "Not a package as published - it was rebuilt or modified." "Re-stage this version on the DMZ host (bp-dmz-update-repo.sh), sync the mirror, then choose [r]."; return 1; }
  while read -r m; do [[ -n $m && $m != _gpgorigin ]] && parts+=("$m"); done <<<"$members"
  ar_cat "$deb" _gpgorigin >"$g/sig" || { SIG_RESULT=error; fail "Could not extract the signature from $(basename "$deb")." "" "Install binutils (ar) or python3, then choose [r]."; return 1; }
  ar_cat "$deb" "${parts[@]}" | gpg --homedir "$g" --batch --status-fd 3 --verify "$g/sig" - 3>"$g/status" >"$g/human" 2>&1
  status=$(cat "$g/status"); log_file "$g/human"
  prim=$(awk '$2=="VALIDSIG"{print $NF}' <<<"$status" | tail -n1)
  rm -rf "$g"
  if grep -q 'REVKEYSIG\|KEYREVOKED' <<<"$status"; then SIG_RESULT=revoked
    fail "The package is signed with a REVOKED key." "The publisher revoked the signing key - packages signed with it must not be trusted." "Do not install this file. Stage a current release on the DMZ host (bp-dmz-update-repo.sh), sync the mirror and pick it with --reconfigure."; return 1
  elif grep -q 'BADSIG' <<<"$status"; then SIG_RESULT=bad
    fail "The package signature is INVALID (BADSIG)." "The package content was changed after it was signed: corruption or tampering." "Do not install it. Re-stage the version on the DMZ host, sync the mirror, delete the cached copy (rm -f $deb) and choose [r]. Report it if it repeats."; return 1
  elif grep -q 'NO_PUBKEY\|ERRSIG' <<<"$status"; then SIG_RESULT=nokey
    fail "The package is signed with a key that is not the publisher's key in the repository." "A package from another source, or the publisher rotated its key." "Check the release on the publisher's site; if the key was rotated, stage that release's gpg-keys on the DMZ host."; return 1
  elif grep -q 'EXPKEYSIG\|KEYEXPIRED' <<<"$status"; then SIG_RESULT=expired
    fail "The package signature is valid, but the signing key has EXPIRED." "The publisher's installer rejects expired keys too: the release is older than the key's validity, or the clock on this host is wrong ($(date -u +%F))." "Check the clock (timedatectl); otherwise pick a newer release staged on the gateway (--reconfigure)."; return 1
  elif grep -q 'GOODSIG' <<<"$status" && [[ -n $prim ]]; then
    if [[ ${prim^^} != "${PUBLISHER_FPR^^}" ]]; then SIG_RESULT=wrongkey
      fail "The package is validly signed, but by key $prim - not the pinned publisher key $PUBLISHER_FPR." "The key file on the gateway is not the publisher's key, or the publisher rotated it." "Verify the new fingerprint independently (publisher documentation), then re-run with --signing-key <fingerprint>."; return 1
    fi
    SIG_RESULT=good; return 0
  fi
  SIG_RESULT=error
  fail "gpg could not verify the package signature." "$(grep -m1 -E 'gpg:' "$RUN_TMP/gpg.import" 2>/dev/null)" "See the log $LOG_FILE (gpg output)."
  return 1
}

short_keyid() { local k=${PUBLISHER_FPR: -8}; printf '%s' "${k,,}"; }   # rpm's gpg-pubkey-<id>
# verify_rpm_sig RPM KEYDIR -> SIG_RESULT; uses a private rpm database (the system one is not touched)
verify_rpm_sig() {
  local f=$1 kd=$2 db out keyid fprs
  db=$(mktemp -d "$RUN_TMP/rpmdb.XXXXXX")
  rpm --dbpath "$db" --initdb >/dev/null 2>&1
  if command -v gpg >/dev/null; then
    fprs=$(key_fingerprints "$kd/bdot-public-gpg-key.asc")
    grep -qix "$PUBLISHER_FPR" <<<"$fprs" || { SIG_RESULT=wrongkey; fail "The key file on the gateway is not the pinned publisher key ($PUBLISHER_FPR)." "It holds: ${fprs:-no readable key}" "Verify the publisher's current fingerprint independently; if it was rotated, re-run with --signing-key <fingerprint>."; return 1; }
  fi
  rpm --dbpath "$db" --import "$kd/bdot-public-gpg-key.asc" >"$RUN_TMP/rpm.import" 2>&1 \
    || { SIG_RESULT=error; fail "rpm could not import the publisher's key." "$(tail -n1 "$RUN_TMP/rpm.import")" "rpm --version"; return 1; }
  keyid=$(rpm --dbpath "$db" -q gpg-pubkey --qf '%{VERSION}\n' 2>/dev/null | head -n1)
  [[ ${keyid,,} == "$(short_keyid)" ]] \
    || { SIG_RESULT=wrongkey; fail "The key file on the gateway is not the pinned publisher key (key id ${keyid:-?}, expected ${PUBLISHER_FPR: -8})." "" "Verify the publisher's current key; re-run with --signing-key <fingerprint> if it was rotated."; return 1; }
  out=$(rpm --dbpath "$db" --checksig -v "$f" 2>&1); log "rpm --checksig: $out"
  rm -rf "$db"
  if grep -qi 'BAD' <<<"$out"; then SIG_RESULT=bad
    fail "The package signature is INVALID." "The package content was changed after it was signed: corruption or tampering." "Do not install it. Delete the cached copy (rm -f $f), re-stage the version on the DMZ host and choose [r]."; return 1
  elif grep -qi 'EXPIRED' <<<"$out"; then SIG_RESULT=expired
    fail "The package is signed with an EXPIRED key." "The publisher's installer rejects it too; or the clock here is wrong ($(date -u +%F))." "Check the clock; otherwise pick a newer release (--reconfigure)."; return 1
  elif grep -qE 'NOKEY|NOTFOUND|MISSING' <<<"$out"; then SIG_RESULT=nokey
    fail "The package is not signed with the publisher's key." "Signature by an unknown key: $(grep -m1 -oiE 'key ID [0-9a-f]+' <<<"$out")" "Check where the package came from; re-stage the release on the DMZ host."; return 1
  elif grep -qiE 'signature.*OK|pgp.*OK' <<<"$out"; then SIG_RESULT=good; return 0
  fi
  SIG_RESULT=unsigned
  fail "rpm found no signature on the package." "$(tail -n1 <<<"$out")" "Re-stage the release on the DMZ host, then choose [r]."
  return 1
}
# The system rpm database needs the key only when this host enforces signatures (%_pkgverify_level)
ensure_rpm_key() {
  local kd=$1 lvl
  lvl=$(rpm --eval '%{?_pkgverify_level}' 2>/dev/null)
  [[ $lvl == signature || $lvl == all ]] || return 0
  rpm -q "gpg-pubkey-$(short_keyid)" >/dev/null 2>&1 && return 0
  run "Importing the publisher's key into the rpm database (this host enforces signatures: _pkgverify_level=$lvl)" rpm --import "$kd/bdot-public-gpg-key.asc"
}

# =============================================================================
#  Installing / removing packages
# =============================================================================
explain_pkg_failure() { # OUTPUT_FILE
  local f=$1
  if grep -qiE 'No space left' "$f"; then
    fail "The package manager ran out of disk space." "The filesystem holding /opt or /var is full." "df -h /opt /var ; free space, then choose [r]."
  elif grep -qiE 'dependency problems|Failed dependencies|depends on' "$f"; then
    fail "The package needs other packages that are not installed." "$(grep -m2 -iE 'depends on|needed by' "$f" | tr '\n' ' ')" "Install them from the internal OS repository, then choose [r]."
  elif grep -qiE 'trying to overwrite|conflicts with file' "$f"; then
    fail "A file of the collector package belongs to another package already." "$(grep -m1 -iE 'trying to overwrite|conflicts with file' "$f")" "Remove the conflicting package (or a manual install in /opt), then choose [r]."
  elif grep -qiE 'pre-installation script|%pre\(|preinst' "$f"; then
    fail "The package's pre-install script failed." "It creates the runtime user 'bdot'; user creation may be blocked by policy (central identity, read-only /etc/passwd)." \
         "Create the user/group 'bdot' beforehand and run with BDOT_SKIP_RUNTIME_USER_CREATION=true, or see the output above."
  elif grep -qiE 'post-installation script|%post\(|postinst' "$f"; then
    fail "The package's post-install script failed." "See the output above (usually systemd or file permissions)." "journalctl -xe ; then choose [r] (the package is reinstalled)."
  elif grep -qiE 'signature|NOKEY|digest' "$f"; then
    fail "rpm rejected the package signature." "This host enforces package signatures and does not trust the publisher's key yet." "The installer imports the key when it verifies it; choose [r]. Manually: rpm --import <bdot-public-gpg-key.asc>"
  else
    fail "The package manager failed." "See the output above." "$( [[ $PKG_TYPE == deb ]] && echo "dpkg -l '*otel-collector*' ; dpkg --audit" || echo "rpm -qa '*otel-collector*'" )"
  fi
}
# pkg_install FILE [downgrade] - dpkg -i / rpm -U, waiting for a package-manager lock held by another process
pkg_install() {
  local f=$1 mode=${2:-} i
  local -a cmd
  if [[ $PKG_TYPE == deb ]]; then cmd=(dpkg --force-confold -i "$f")
  else cmd=(rpm -U -v "$f"); [[ $mode == downgrade ]] && cmd=(rpm -U -v --oldpackage "$f"); [[ $mode == reinstall ]] && cmd=(rpm -U -v --replacepkgs "$f"); fi
  for i in $(seq 1 30); do
    run_stream "${cmd[*]}" "${cmd[@]}" && return 0
    if grep -qiE 'lock.*(locked|held)|Unable to acquire|frontend lock|waiting for transaction lock|cannot get (exclusive|shared) lock' "$LAST_OUT"; then
      warn "The package manager is locked by another process (unattended upgrades, yum/dnf) - waiting 10s ($i/30)"; sleep 10; continue
    fi
    break
  done
  explain_pkg_failure "$LAST_OUT"
  return 1
}
pkg_remove() { # PACKAGE
  if [[ $PKG_TYPE == deb ]]; then run_stream "Removing $1 (dpkg --purge)" dpkg --purge "$1"
  else run_stream "Removing $1 (rpm -e)" rpm -e "$1"; fi
}

# what to do with a collector of the other family (two collectors = two agents in the console)
handle_other_family() {
  local f=$1 v=$2 svc a
  svc=$(product_of_family "$f")
  if ! systemctl is-active --quiet "$svc" && [[ $(systemctl is-enabled "$svc" 2>/dev/null) != enabled ]] && [[ $OTHER_ACTION != remove ]]; then
    ok "The $(family_label "$f") collector $v is stopped and disabled - its package stays for rollback"
    return 0
  fi
  warn "The $(family_label "$f") collector $v is installed here; this host is being set up with $(family_label "$COLLECTOR_FAMILY") $BP_VERSION."
  say  "  Two collectors on one host are two agents in the console, each with its own configuration."
  OTHER_SECRET=$( use_family "$f"; yaml_get secret_key )
  a=$OTHER_ACTION
  if [[ -z $a ]]; then
    if (( ASSUME_YES )) || [[ -z $TTY ]]; then
      fail "The $f collector is installed and no choice was given for it." "Unattended runs never change the other collector on their own." \
           "Re-run interactively, or add --other-collector stop (stop + disable, package kept), remove (uninstall) or keep"
      return 1
    fi
    a=$(choose "  [s] stop + disable it (package kept for rollback)   [r] remove it   [k] keep both   [q] quit: " srkq s)
    case $a in s) a=stop ;; r) a=remove ;; k) a=keep ;; *) fail "Stopped at your request." "" "Re-run when you have decided what to do with the $f collector."; return 1 ;; esac
  fi
  case $a in
    stop)   run "Stopping and disabling $svc" systemctl disable --now "$svc" || return 1
            ok "The $f collector is stopped and disabled (package and config kept - back: systemctl enable --now $svc)" ;;
    remove) systemctl disable --now "$svc" >/dev/null 2>&1
            pkg_remove "$svc" || { explain_pkg_failure "$LAST_OUT"; return 1; }
            ok "The $f collector is removed - its agent shows as disconnected in the console (delete it there)" ;;
    keep)   warn "Keeping the $f collector running next to the new one at your request" ;;
  esac
  return 0
}

# =============================================================================
#  Collector configuration
# =============================================================================
# write_manager_yaml (v1) / write_supervisor_yaml (v2) -> CONFIG_CHANGED=0|1
write_manager_yaml() {
  local aid owner tmp
  CONFIG_CHANGED=1
  aid=$(yaml_get agent_id)
  if [[ -f $MANAGER_YAML && $(yaml_get endpoint) == "$OPAMP_ENDPOINT" && $(yaml_get secret_key) == "$BP_SECRET" \
        && $(yaml_get labels) == "$AGENT_LABELS" && $(yaml_get agent_name) == "$AGENT_NAME" ]]; then
    CONFIG_CHANGED=0; ok "manager.yaml already has the right endpoint, key, labels and name"; return 0
  fi
  [[ -f $MANAGER_YAML ]] && backup_config
  owner=$(collector_owner)
  tmp=$(mktemp "$V1_HOME/.manager.XXXXXX") || { fail "Cannot write in $V1_HOME." "Disk full or read-only filesystem." "df -h $V1_HOME"; return 1; }
  chmod 600 "$tmp"
  {
    echo "endpoint: $OPAMP_ENDPOINT"
    echo "secret_key: $BP_SECRET"
    [[ -n $aid ]] && echo "agent_id: $aid"
    echo "labels: \"$AGENT_LABELS\""
    echo "agent_name: $AGENT_NAME"
  } >"$tmp"
  chown "$owner" "$tmp" 2>/dev/null || warn "Could not chown manager.yaml to $owner - leaving it root-owned"
  mv -f "$tmp" "$MANAGER_YAML"
  ok "Wrote $MANAGER_YAML (endpoint $OPAMP_ENDPOINT, owner $owner, mode 0600)"
  if [[ -n $aid ]]; then info "Kept the existing agent_id $aid - the console keeps this host as the same agent"
  else info "No agent_id yet - the collector generates one when it starts"; fi
}
render_supervisor_yaml() { # the layout the vendor's v2 installer writes
  cat <<EOF
server:
  endpoint: "${OPAMP_ENDPOINT}"
  headers:
    Authorization: "Secret-Key ${BP_SECRET}"
    User-Agent: "bindplane-otel-collector/${BP_VERSION#v}"
  tls:
    insecure: true
    insecure_skip_verify: true
capabilities:
  accepts_remote_config: true
  reports_remote_config: true
  reports_available_components: true
agent:
  executable: "$V2_HOME/bindplane-otel-collector"
  config_apply_timeout: 30s
  bootstrap_timeout: 5s
  args: ["--feature-gates", "service.AllowNoPipelines"]
  description:
    non_identifying_attributes:
      service.labels: "${AGENT_LABELS}"
storage:
  directory: "$V2_HOME/supervisor_storage"
telemetry:
  logs:
    level: 0
    output_paths: ["$V2_HOME/supervisor.log"]
EOF
}
write_supervisor_yaml() {
  local new="$RUN_TMP/supervisor.yaml" owner tmp old_ep old_lb old_key id
  CONFIG_CHANGED=1
  ( umask 077; render_supervisor_yaml >"$new" )
  if [[ -f $SUP_YAML ]] && cmp -s "$new" "$SUP_YAML"; then rm -f "$new"; CONFIG_CHANGED=0; ok "supervisor.yaml already has the right endpoint, key and labels"; return 0; fi
  if [[ -f $SUP_YAML ]]; then
    if [[ $(sha256 "$SUP_YAML") == "$DEFAULT_SUPERVISOR_CFG_HASH" ]]; then
      info "Replacing the package's default supervisor.yaml (it has no endpoint or key)"
    else
      old_ep=$(yaml_get endpoint); old_lb=$(yaml_get labels); old_key=$(yaml_get secret_key)
      backup_config
      [[ $old_ep != "$OPAMP_ENDPOINT" ]] && say "      endpoint: ${old_ep:-<none>}  ->  $OPAMP_ENDPOINT"
      [[ $old_lb != "$AGENT_LABELS" ]] && say "      labels:   ${old_lb:-<none>}  ->  $AGENT_LABELS"
      [[ -n $old_key && $old_key != "$BP_SECRET" ]] && say "      secret key: replaced ($(mask "$old_key") -> $(mask "$BP_SECRET"))"
    fi
  fi
  owner=$(collector_owner)
  tmp=$(mktemp "$V2_HOME/.supervisor.XXXXXX") || { rm -f "$new"; fail "Cannot write in $V2_HOME." "Disk full or read-only filesystem." "df -h $V2_HOME"; return 1; }
  chmod 600 "$tmp"; cat "$new" >"$tmp"; rm -f "$new"
  chown "$owner" "$tmp" 2>/dev/null || warn "Could not chown supervisor.yaml to $owner - leaving it root-owned (the service runs as root)"
  mv -f "$tmp" "$SUP_YAML"
  ok "Wrote $SUP_YAML (endpoint $OPAMP_ENDPOINT, owner $owner, mode 0600)"
  if command -v python3 >/dev/null && python3 -c 'import yaml' 2>/dev/null; then
    python3 -I -c 'import sys,yaml; yaml.safe_load(open(sys.argv[1]))' "$SUP_YAML" 2>"$RUN_TMP/yaml.err" \
      || { fail "supervisor.yaml is not valid YAML: $(tail -n1 "$RUN_TMP/yaml.err")" "A character in the labels or key broke the file." "Check the labels and the key: $SELF --reconfigure"; return 1; }
  fi
  id=$(yaml_get agent_id)
  [[ -n $id ]] && info "The agent identity ($id, supervisor_storage/) is kept - the console keeps this host as the same agent"
  return 0
}
# the previous config is kept for reference - with the secret key removed (it stays only in the live file)
backup_config() {
  local b; b="$STATE_DIR/$(basename "$COLLECTOR_CONF").bak-$RUN_TS"
  ( umask 077; redacted_config >"$b" )
  info "Previous $(basename "$COLLECTOR_CONF") saved as $b (secret key redacted)"
}
redacted_config() { # the active collector config without the secret
  [[ -r $COLLECTOR_CONF ]] || { echo "(no $COLLECTOR_CONF)"; return 0; }
  sed -E 's/^(secret_key:).*/\1 ***REDACTED***/; s/(Secret-Key )[^"]*/\1***REDACTED***/' "$COLLECTOR_CONF"
}

# =============================================================================
#  STEPS  (each returns 0 = done, 1 = failed, 3 = skipped on purpose)
# =============================================================================
ensure_index() { # the gateway's SHA256SUMS for this run (fetched once)
  [[ -n $REPO_SUMS && -s $REPO_SUMS ]] && return 0
  local rc; load_repo_index; rc=$?
  (( rc == 0 )) || { explain_repo_failure "$rc" SHA256SUMS; return 1; }
}
keys_name() { printf '%s-%s-gpg-keys.tar.gz' "$(product_of_family "$(family_of_version "$1")")" "$1"; }
pubsums_name() { printf '%s-%s-SHA256SUMS' "$(product_of_family "$(family_of_version "$1")")" "$1"; }

step_preflight() {
  local f="$EVIDENCE_DIR/preflight-$RUN_TS.txt"
  CHK_FAILS=0; CHK_WARNS=0
  info "Recording the host baseline to $f"
  {
    echo "# pre-flight $(date -Is) on $(hostname) - $SCRIPT_NAME v$SCRIPT_VERSION"
    echo "## OS"; cat /etc/os-release 2>/dev/null; uname -a
    echo "## interfaces and routing"; ip -br addr 2>&1; ip route 2>&1
    echo "## time"; timedatectl status 2>&1
    echo "## disk"; df -h /opt /var 2>&1
    echo "## collectors"; installed_summary
  } >"$f" 2>&1
  check_platform
  check_tools
  check_time
  check_space /opt 700 "the collector (/opt)"
  check_space "$CACHE_DIR" 300 "the download cache ($CACHE_DIR)"
  check_noexec
  check_selinux
  check_existing
  check_proxy_env
  if (( CHK_FAILS > 0 )); then
    fail "$CHK_FAILS pre-flight check(s) failed, $CHK_WARNS warning(s)." "See the [FAIL] lines and hints above." \
         "Fix the failing items, then choose [r] to re-check. Choose [s] only if you knowingly accept a failure."
    return 1
  fi
  if (( CHK_WARNS > 0 )); then
    warn "$CHK_WARNS warning(s) above."
    ask_yn "Continue despite the warnings?" y || { fail "Stopped at your request after pre-flight warnings." "" "Resolve the warnings, then re-run."; return 1; }
  fi
  ok "Pre-flight passed"
}

step_gateway() {
  local st rc oh op remote mine
  st=$(tcp_state "$GATEWAY" "$REPO_PORT")
  explain_tcp "$GATEWAY" "$REPO_PORT" "$st" "gateway repository" \
    || { fail "The gateway repository $GATEWAY:$REPO_PORT is not reachable ($st)." "See the hint above." "Fix the path and choose [r]. Wrong address? Re-run with --reconfigure."; return 1; }
  REPO_SUMS=""; load_repo_index; rc=$?
  (( rc == 0 )) || { explain_repo_failure "$rc" SHA256SUMS; return 1; }
  if [[ -s $REPO_INFO ]]; then
    ok "Repository: $(wc -l <"$REPO_SUMS") files; default $(info_field current_collector_version), current v1 $(info_field current_v1), current v2 $(info_field current_v2) (updated $(info_field updated))"
  else
    warn "The gateway serves no VERSION-INFO - is this the NCINGA Bindplane repository? ($(wc -l <"$REPO_SUMS") files in SHA256SUMS)"
  fi
  if [[ -z $REPO_VERSIONS ]]; then
    fail "The gateway has no collector package for this host (.$PKG_TYPE, $ARCH)." \
         "Staged there: $(info_field staged_versions). RPM and ARM64 packages are staged only when enabled on the DMZ host." \
         "On the DMZ host: bp-dmz-setup.sh --reconfigure (stage RPM / ARM64), then bp-dmz-setup.sh --only collector_artefacts\nOn the LIVE gateway afterwards: bp-live-setup.sh --sync-mirror ; then choose [r] here."
    return 1
  fi
  ok "Versions for this host (.$PKG_TYPE, $ARCH): $REPO_VERSIONS"
  if ! contains_word "$REPO_VERSIONS" "$BP_VERSION"; then
    fail "$BP_VERSION is not on the gateway for this host ($(basename "$(pkg_rel "$BP_VERSION")"))." \
         "It was removed from the repository, the LIVE mirror is not synced yet, or it is not staged for .$PKG_TYPE/$ARCH." \
         "Pick one of: $REPO_VERSIONS  ->  $SELF --reconfigure\nOr stage it on the DMZ host (bp-dmz-update-repo.sh) and sync the LIVE mirror (bp-live-setup.sh --sync-mirror)."
    return 1
  fi
  ok "$(pkg_rel "$BP_VERSION") is on the gateway ($(family_label "$COLLECTOR_FAMILY"))"
  if repo_has "packages/$(keys_name "$BP_VERSION")"; then ok "The publisher's signing key for $BP_VERSION is on the gateway"
  else warn "No publisher signing key for $BP_VERSION on the gateway - the verify step cannot check the signature"
       hint "On the DMZ host: bp-dmz-setup.sh --only collector_artefacts (stages gpg-keys for every version), then sync the LIVE mirror."; fi
  oh=$(opamp_host); op=$(opamp_port)
  st=$(tcp_state "$oh" "$op")
  if ! explain_tcp "$oh" "$op" "$st" "OpAMP relay - how the agent is managed"; then
    warn "The agent cannot connect until tcp/$op to $oh is open; the package can still be installed now."
    ask_yn "Continue with the installation?" y || { fail "Stopped: the OpAMP relay $oh:$op is not reachable ($st)." "See the hint above." "Have the rule installed, then choose [r]."; return 1; }
  fi
  st=$(tcp_state "$oh" "$OTLP_PORT")
  if [[ $st == open ]]; then ok "TCP $oh:$OTLP_PORT reachable (OTLP - where this agent's telemetry is sent once configured)"
  else warn "TCP $oh:$OTLP_PORT $st (OTLP) - management works without it, but telemetry from this agent will not flow until it is open (Stage 11)"; fi
  if repo_has scripts/bp-agent-install-linux.sh && repo_fetch scripts/bp-agent-install-linux.sh "$RUN_TMP/remote-installer.sh"; then
    remote=$(sed -n 's/^SCRIPT_VERSION="\([0-9.]*\)".*/\1/p' "$RUN_TMP/remote-installer.sh" | head -n1); mine=$SCRIPT_VERSION
    if [[ -n $remote && $remote != "$mine" && $(printf '%s\n%s\n' "$mine" "$remote" | sort -V | tail -n1) == "$remote" ]]; then
      warn "The gateway has a newer version of this installer ($remote; this is $mine)"
      hint "curl -fsSO $(repo_url scripts/bp-agent-install-linux.sh) and run that one (it resumes from the same progress)"
    fi
  fi
  return 0
}

step_download() {
  local rel f want extra rel2 rc
  ensure_index || return 1
  rel=$(pkg_rel "$BP_VERSION"); f=$(pkg_file "$BP_VERSION")
  want=$(repo_sum "$rel")
  [[ -n $want ]] || { fail "$rel is not listed in the gateway's SHA256SUMS." "The version is not on the gateway for this host." "$SELF --only gateway (lists what is available)"; return 1; }
  install -d -m 700 "$CACHE_DIR"
  if [[ -f $f && $(sha256 "$f") == "$want" ]]; then
    ok "$(basename "$f") already downloaded ($(human "$(stat -c %s "$f")")) and matches SHA256SUMS"
  else
    rm -f "$f"
    [[ -s $f.part ]] && info "Resuming the partial download ($(human "$(stat -c %s "$f.part")") so far)"
    info "Downloading $(repo_url "$rel")"
    if ! download "$rel" "$f.part"; then
      explain_repo_failure "$DL_RC" "$rel"; [[ -n $DL_ERR ]] && hint "curl said: $DL_ERR"
      [[ -s $f.part ]] && FAIL_FIX+="\nThe partial file is kept: [r] resumes it."
      return 1
    fi
    mv -f "$f.part" "$f"
    ok "Downloaded $(basename "$f") ($(human "$(stat -c %s "$f")"))"
  fi
  for extra in "$(pubsums_name "$BP_VERSION")" "$(keys_name "$BP_VERSION")"; do
    rel2="packages/$extra"
    repo_has "$rel2" || { log "$rel2 is not on the gateway"; continue; }
    [[ -f $CACHE_DIR/$extra && $(sha256 "$CACHE_DIR/$extra") == "$(repo_sum "$rel2")" ]] && continue
    repo_fetch "$rel2" "$CACHE_DIR/$extra"; rc=$?
    (( rc == 0 )) || { rm -f "$CACHE_DIR/$extra"; explain_repo_failure "$rc" "$rel2"; return 1; }
    ok "Downloaded $extra"
  done
  return 0
}

# accept_unverified REASON -> 0 when the operator accepts checksum-only verification
accept_unverified() {
  warn "$1"
  say "  The package matches the gateway's checksums, but its publisher signature cannot be checked."
  say "  Without the signature, a package replaced on the gateway (together with its checksum) is not detected."
  if (( ASSUME_YES )) || [[ -z $TTY ]]; then return 1; fi
  ask_yn "Install with checksum verification only (NOT recommended)?" n
}

step_verify() {
  local rel f want got asset pubsums pw meta name arch ver keys kd result_file="$STATE_DIR/verify.result" attempt
  ensure_index || return 1
  rel=$(pkg_rel "$BP_VERSION"); f=$(pkg_file "$BP_VERSION"); asset=$(basename "$rel")
  want=$(repo_sum "$rel")
  for attempt in 1 2; do
    [[ -f $f ]] || { info "$asset is not in the download cache - downloading it"; step_download || return 1; }
    got=$(sha256 "$f")
    [[ $got == "$want" ]] && break
    rm -f "$f"
    (( attempt == 1 )) && { warn "$asset does not match the gateway's SHA256SUMS (corrupt or changed during the transfer) - downloading it again"; continue; }
    fail "$asset still does not match the gateway's SHA256SUMS after a fresh download." \
         "The file on the gateway differs from its SHA256SUMS: the repository is inconsistent (a partial mirror sync, or a manual change)." \
         "On the gateway: cd /srv/bindplane && sha256sum -c --quiet SHA256SUMS ; on the LIVE gateway: bp-live-setup.sh --sync-mirror"
    return 1
  done
  ok "$asset matches the gateway's SHA256SUMS ($got)"
  pubsums="$CACHE_DIR/$(pubsums_name "$BP_VERSION")"
  if [[ -s $pubsums ]]; then
    pw=$(awk -v n="$asset" '$2==n || $2==("*" n) {print $1; exit}' "$pubsums")
    if [[ -n $pw && $pw != "$got" ]]; then
      rm -f "$f"
      fail "$asset differs from the PUBLISHER's checksum ($(basename "$pubsums"))." \
           "The repository holds a file that is not the published release - it was modified or replaced." \
           "Do not install it. Re-stage the version on the DMZ host (bp-dmz-update-repo.sh --prune then add it again) and report the incident."
      return 1
    fi
    [[ -n $pw ]] && ok "$asset matches the publisher's SHA256SUMS" || info "$asset is not listed in the publisher's SHA256SUMS"
  else
    info "The publisher's SHA256SUMS for $BP_VERSION is not on the gateway - skipped"
  fi
  if [[ $PKG_TYPE == deb ]]; then
    name=$(dpkg-deb -f "$f" Package 2>/dev/null); arch=$(dpkg-deb -f "$f" Architecture 2>/dev/null); ver=$(dpkg-deb -f "$f" Version 2>/dev/null)
    meta=$arch
  else
    meta=$(rpm -qp --qf '%{NAME}|%{ARCH}|%{VERSION}' "$f" 2>/dev/null); IFS='|' read -r name arch ver <<<"$meta"
  fi
  [[ $name == "$COLLECTOR_PKG" ]] || { fail "$asset contains the package '${name:-unreadable}', not $COLLECTOR_PKG." "A renamed or wrong file in the repository." "Re-stage it on the DMZ host with bp-dmz-update-repo.sh."; return 1; }
  [[ $arch == "$ARCH" || $arch == "$(rpm_arch "$ARCH")" ]] || { fail "$asset is built for '$arch', this host is $ARCH." "A wrongly named file in the repository." "Re-stage it on the DMZ host."; return 1; }
  [[ $ver == "$(pkg_native_version "$BP_VERSION")" ]] || { fail "$asset contains version $ver, not $BP_VERSION." "A renamed file in the repository." "Re-stage it on the DMZ host."; return 1; }
  ok "Package metadata: $name $ver ($arch)"

  SIG_RESULT=""
  keys="$CACHE_DIR/$(keys_name "$BP_VERSION")"; kd="$RUN_TMP/keys"
  if (( NO_GPG_CHECK )); then
    warn "Signature check skipped (--no-gpg-check) - only the checksums were verified"; SIG_RESULT=skipped
  elif [[ ! -s $keys ]]; then
    if accept_unverified "The gateway has no publisher signing key for $BP_VERSION ($(keys_name "$BP_VERSION"))."; then SIG_RESULT=accepted-unverified
    else
      fail "The package signature could not be checked: no signing key for $BP_VERSION on the gateway." \
           "The repository was staged before the NCINGA tooling kept the publisher's gpg-keys.tar.gz (or the mirror is not synced)." \
           "On the DMZ host: bp-dmz-setup.sh --only collector_artefacts && bp-dmz-setup.sh --only checksums\nOn the LIVE gateway: bp-live-setup.sh --sync-mirror ; then choose [r] here.\nTo accept checksum-only verification knowingly: re-run with --no-gpg-check"
      return 1
    fi
  elif ! { rm -rf "$kd"; unpack_keys "$keys" "$kd"; }; then
    fail "$(basename "$keys") from the gateway is not a valid key archive." "A damaged file in the repository." "Re-stage it on the DMZ host (bp-dmz-setup.sh --only collector_artefacts), then choose [r]."
    return 1
  elif [[ $PKG_TYPE == deb ]] && ! command -v gpg >/dev/null; then
    if accept_unverified "gpg is not installed on this host."; then SIG_RESULT=accepted-unverified
    else fail "The .deb signature cannot be checked without gpg." "gnupg is not installed." "apt-get install gnupg (internal repository), then choose [r] - or re-run with --no-gpg-check"; return 1; fi
  elif [[ $PKG_TYPE == deb ]] && ! command -v ar >/dev/null && ! command -v python3 >/dev/null; then
    if accept_unverified "Neither ar (binutils) nor python3 is installed - the .deb signature cannot be read."; then SIG_RESULT=accepted-unverified
    else fail "The .deb signature cannot be read." "binutils (ar) and python3 are both missing." "apt-get install binutils, then choose [r] - or re-run with --no-gpg-check"; return 1; fi
  else
    if [[ $PKG_TYPE == deb ]]; then verify_deb_sig "$f" "$kd"; else verify_rpm_sig "$f" "$kd"; fi
    if [[ $SIG_RESULT == good ]]; then
      ok "Signature valid - signed by the publisher's key $PUBLISHER_FPR (BDOT)"
    elif [[ $SIG_RESULT == expired ]] && accept_unverified "$FAIL_WHAT"; then
      SIG_RESULT=accepted-expired; FAIL_WHAT="" FAIL_WHY="" FAIL_FIX=""
    else
      return 1
    fi
  fi
  { echo "version=$BP_VERSION"; echo "file=$asset"; echo "sha256=$got"; echo "publisher_sums=${pw:+match}"; echo "signature=$SIG_RESULT"; echo "checked=$(date -Is)"; } >"$result_file"
  chmod 600 "$result_file"
  return 0
}

step_install() {
  local f inst ofam ov mode="" newer
  f=$(pkg_file "$BP_VERSION")
  [[ -f $f ]] || { fail "$(basename "$f") is not in the download cache." "The download step did not complete, or the cache was cleaned." "$SELF --from download"; return 1; }
  if [[ $(sed -n 's/^version=//p' "$STATE_DIR/verify.result" 2>/dev/null) != "$BP_VERSION" ]] || [[ $(sed -n 's/^sha256=//p' "$STATE_DIR/verify.result" 2>/dev/null) != "$(sha256 "$f")" ]]; then
    if [[ $(state_get verify) == skipped ]]; then warn "The verify step was skipped - installing a package whose checksums and signature were not checked"
    else fail "$(basename "$f") has not been verified (or changed since)." "The verify step must pass first." "$SELF --from verify"; return 1; fi
  fi
  ofam=$(other_family "$COLLECTOR_FAMILY"); ov=$(pkg_version "$(product_of_family "$ofam")")
  if [[ -n $ov ]]; then handle_other_family "$ofam" "$ov" || return 1; fi
  inst=$(pkg_version "$COLLECTOR_PKG")
  if [[ $PKG_TYPE == deb ]] && dpkg-query -W -f='${Status}' "$COLLECTOR_PKG" 2>/dev/null | grep -qE 'half-configured|unpacked|half-installed|triggers-'; then
    # the vendor's post-install script deletes its staging area on the first attempt, so
    # 'dpkg --configure' cannot finish it - unpacking the package again can
    warn "$COLLECTOR_PKG is half-installed from an earlier attempt - reinstalling it"; mode=reinstall
  fi
  if [[ -n $inst && ! -d $COLLECTOR_HOME ]]; then
    warn "$COLLECTOR_PKG $inst is registered as installed, but $COLLECTOR_HOME is missing - reinstalling"
    if [[ $PKG_TYPE == deb ]]; then dpkg --purge "$COLLECTOR_PKG" >/dev/null 2>&1; inst=""; else mode=reinstall; fi
  fi
  if [[ $inst == "$BP_VERSION" && -z $mode ]]; then
    if (( REINSTALL )); then mode=reinstall; info "Reinstalling $inst (--reinstall)"
    else ok "$COLLECTOR_PKG $inst is already installed"; return 0; fi
  fi
  if [[ -n $inst && $inst != "$BP_VERSION" ]]; then
    newer=$(printf '%s\n%s\n' "$inst" "$BP_VERSION" | sort_tags | tail -n1)
    if [[ $newer == "$inst" ]]; then
      warn "This is a DOWNGRADE: $inst -> $BP_VERSION"
      ask_yn "Downgrade the collector to $BP_VERSION?" y || { fail "Downgrade declined." "" "Pick another version with --reconfigure."; return 1; }
      mode=downgrade
    else
      info "Upgrading $COLLECTOR_PKG $inst -> $BP_VERSION (configuration and agent identity are kept)"
    fi
  fi
  if [[ $PKG_TYPE == rpm && -s $CACHE_DIR/$(keys_name "$BP_VERSION") ]]; then
    rm -rf "$RUN_TMP/keys.inst"; unpack_keys "$CACHE_DIR/$(keys_name "$BP_VERSION")" "$RUN_TMP/keys.inst" && ensure_rpm_key "$RUN_TMP/keys.inst"
  fi
  info "Installing from the local file - NOT with install_unix.sh, which needs the internet"
  pkg_install "$f" "$mode" || return 1
  systemctl daemon-reload >/dev/null 2>&1
  systemctl cat "$COLLECTOR_SVC" >/dev/null 2>&1 || { fail "The package installed but $COLLECTOR_SVC.service is missing." "The package scripts failed part-way." "Choose [r] to install it again, or: $( [[ $PKG_TYPE == deb ]] && echo "dpkg -l $COLLECTOR_PKG" || echo "rpm -q $COLLECTOR_PKG" )"; return 1; }
  ok "Installed $COLLECTOR_PKG $(collector_version) - runtime owner of $COLLECTOR_HOME: $(collector_owner)"
  # the packages swap the binary but do not restart a running service: the start step does
  touch "$STATE_DIR/restart-needed"
  return 0
}

step_configure() {
  CONFIG_CHANGED=1
  ensure_secret || return 1
  [[ -d $COLLECTOR_HOME ]] || { fail "$COLLECTOR_HOME does not exist." "The $COLLECTOR_PKG package is not installed." "$SELF --from install"; return 1; }
  if [[ $COLLECTOR_FAMILY == v2 ]]; then write_supervisor_yaml || return 1; else write_manager_yaml || return 1; fi
  (( CONFIG_CHANGED )) && touch "$STATE_DIR/restart-needed"
  hint "Labels \"$AGENT_LABELS\" decide which configuration the console assigns to this agent (Stage 11)."
  return 0
}

# explain_collector_start FILE (journal + log lines)
explain_collector_start() {
  local f=$1
  if grep -qiE 'status=203/EXEC|exec format error|Permission denied.*(otel-collector|opampsupervisor)' "$f" && ! grep -qiE '\.yaml' <<<"$(grep -iE 'Permission denied' "$f")"; then
    fail "systemd could not execute the collector binary." "/opt is mounted noexec, the binary is for another architecture, or a security agent blocks it." "findmnt -T /opt ; file $COLLECTOR_BIN ; journalctl -u $COLLECTOR_SVC -n 30"
  elif grep -qiE 'permission denied' "$f"; then
    fail "The collector cannot read or write a file it needs (permission denied)." "$(grep -m1 -iE 'permission denied' "$f" | cut -c1-200)" \
         "Its files must belong to the runtime user ($(collector_owner)): chown -R $(collector_owner) $COLLECTOR_HOME ; then choose [r]"
  elif grep -qiE 'yaml:|unmarshal|cannot parse|failed to (load|read) config|invalid config' "$f"; then
    fail "The collector rejected its configuration file." "$(grep -m1 -iE 'yaml:|unmarshal|cannot parse|config' "$f" | cut -c1-200)" "Re-write it: $SELF --only configure (check the labels) ; tail -n 30 $COLLECTOR_LOG"
  elif grep -qiE 'avc: *denied|SELinux' "$f"; then
    fail "SELinux blocked the collector." "$(grep -m1 -iE 'avc' "$f" | cut -c1-200)" "ausearch -m avc -ts recent ; restorecon -Rv $COLLECTOR_HOME"
  elif grep -qiE 'address already in use|bind:' "$f"; then
    fail "The collector could not bind a port that is already in use." "$(grep -m1 -iE 'address already in use|bind:' "$f" | cut -c1-200)" "ss -lntp ; a second collector (the other family?) may be running: systemctl status $V1_PKG $V2_PKG"
  else
    fail "The collector service does not stay running." "See the journal and log lines above." "journalctl -u $COLLECTOR_SVC -n 50 --no-pager ; tail -n 50 $COLLECTOR_LOG"
  fi
}

step_start() {
  local i nr0 nr1 since f="$RUN_TMP/start.out" before=0
  [[ -f $COLLECTOR_CONF ]] || { fail "$COLLECTOR_CONF is missing." "The configure step has not run." "$SELF --from configure"; return 1; }
  run "Reloading systemd units" systemctl daemon-reload
  run "Enabling $COLLECTOR_SVC at boot" systemctl enable "$COLLECTOR_SVC" || { fail "systemctl enable failed." "See the output above." "systemctl status $COLLECTOR_SVC"; return 1; }
  [[ -r $COLLECTOR_LOG ]] && before=$(wc -l <"$COLLECTOR_LOG")
  since=$(date '+%Y-%m-%d %H:%M:%S')
  if [[ -f $STATE_DIR/restart-needed || -n ${FORCED[start]-} ]] || ! systemctl is-active --quiet "$COLLECTOR_SVC"; then
    echo "$COLLECTOR_LOG $before" >"$STATE_DIR/log-mark"
    run "Restarting $COLLECTOR_SVC" systemctl restart "$COLLECTOR_SVC" || {
      journalctl -u "$COLLECTOR_SVC" --since "$since" --no-pager >"$f" 2>&1; show_tail "$f" 15; explain_collector_start "$f"; return 1; }
  else
    ok "$COLLECTOR_SVC is already running with the current configuration"
  fi
  nr0=$(systemctl show -p NRestarts --value "$COLLECTOR_SVC" 2>/dev/null)
  info "Watching the service for 10s (a bad configuration makes it exit and restart) ..."
  for i in $(seq 1 10); do sleep 1; systemctl is-active --quiet "$COLLECTOR_SVC" || break; done
  nr1=$(systemctl show -p NRestarts --value "$COLLECTOR_SVC" 2>/dev/null)
  if ! systemctl is-active --quiet "$COLLECTOR_SVC" || [[ -n $nr0 && -n $nr1 && $nr1 != "$nr0" ]]; then
    { journalctl -u "$COLLECTOR_SVC" --since "$since" --no-pager 2>&1; [[ -r $COLLECTOR_LOG ]] && tail -n +"$((before+1))" "$COLLECTOR_LOG" | tail -n 20; } >"$f"
    err "$COLLECTOR_SVC is not stable ($(systemctl is-active "$COLLECTOR_SVC" 2>/dev/null)$( [[ -n $nr1 ]] && echo ", restarts: $nr0 -> $nr1"))"
    show_tail "$f" 15; explain_collector_start "$f"; return 1
  fi
  rm -f "$STATE_DIR/restart-needed"
  i=$(systemctl show -p MainPID --value "$COLLECTOR_SVC" 2>/dev/null)
  ok "$COLLECTOR_SVC is active and stable$( [[ $i =~ ^[1-9][0-9]*$ ]] && echo " (pid $i)")"
}

# log_mark -> line of the collector log where the last (re)start by this script began (0 = whole log)
log_mark() {
  local f n cur
  read -r f n <"$STATE_DIR/log-mark" 2>/dev/null || { echo 0; return; }
  cur=$(wc -l <"$COLLECTOR_LOG" 2>/dev/null || echo 0)
  if [[ $f == "$COLLECTOR_LOG" && $n =~ ^[0-9]+$ ]] && (( n <= cur )); then echo "$n"; else echo 0; fi
}
collector_conn() { # local address of the active collector's established OpAMP session
  local ip; ip=$(resolve_ip "$(opamp_host)")
  [[ -n $ip ]] || return 0
  ss -Htnp state established dst "$ip:$(opamp_port)" 2>/dev/null | grep -iE "$COLLECTOR_PROC" | awk '{print $3}' | head -n1
}

step_connect() {
  local i v aid c1="" c2="" errs before=0 console=0 name cf oh op code st ev
  cf=$(basename "$COLLECTOR_CONF"); oh=$(opamp_host); op=$(opamp_port)
  name=$( [[ $COLLECTOR_FAMILY == v2 ]] && hostname -s || echo "$AGENT_NAME" )
  systemctl is-active --quiet "$COLLECTOR_SVC" || { fail "The collector service is not running." "It stopped after the start step." "$SELF --from start ; journalctl -u $COLLECTOR_SVC -n 50"; return 1; }
  v=$(collector_version); [[ $v == "$BP_VERSION" ]] && ok "Collector $v is running - $(family_label "$COLLECTOR_FAMILY")" || warn "Collector reports '${v:-?}' (chosen version $BP_VERSION)"
  before=$(log_mark)
  for i in $(seq 1 30); do aid=$(yaml_get agent_id); [[ -n $aid ]] && break; sleep 1; done
  [[ -n $aid ]] && ok "Agent identity $aid" || warn "No agent identity recorded yet"
  info "Waiting up to 60s for the OpAMP session to $oh:$op ..."
  for i in $(seq 1 60); do c1=$(collector_conn); [[ -n $c1 ]] && break; sleep 1; done
  [[ -n $c1 ]] && { info "Session from $c1 - checking it holds for 15s ..."; sleep 15; c2=$(collector_conn); }
  errs=$(collector_log_errors "$before" 6)
  if [[ -n $errs ]]; then
    log "collector log errors since the start: $errs"
    [[ -n $c1 && $c1 == "$c2" ]] || { warn "Collector log errors since it was started:"; printf '%s\n' "$errs" | redact_stream | sed 's/^/         /'; }
  fi
  if [[ -n $c1 && $c1 == "$c2" ]]; then
    ok "Stable OpAMP session to $oh:$op from $c1 (a rejected key would have dropped it)"
    say "  Check the Bindplane console now: Agents -> $name (identity ${aid:-?}, labels $AGENT_LABELS)."
    ask_yn "Is $name shown as Connected?" y && console=1
  fi
  ev="$EVIDENCE_DIR/agent-$(hostname -s)-$RUN_TS.txt"
  {
    echo "# Agent install evidence - $(hostname -s) - $(date -Is) - $SCRIPT_NAME v$SCRIPT_VERSION"
    echo "os=$OS_PRETTY arch=$ARCH package_type=$PKG_TYPE"
    echo "collector=$COLLECTOR_PKG version=$v family=$COLLECTOR_FAMILY identity=${aid:-} name=$name"
    echo "gateway_repo=$(repo_url /) opamp=$OPAMP_ENDPOINT labels=$AGENT_LABELS"
    echo "session=${c1:-none} stable=$([[ -n $c1 && $c1 == "$c2" ]] && echo yes || echo no) console_connected=$console"
    echo "## verification"; cat "$STATE_DIR/verify.result" 2>/dev/null
    echo "## service"; systemctl status "$COLLECTOR_SVC" --no-pager 2>&1 | head -n 12
    echo "## sessions"; ss -tnp state established 2>/dev/null | grep -E ":($op|$OTLP_PORT) "
    echo "## $cf (secret redacted)"; redacted_config
  } 2>&1 | redact_stream >"$ev"
  chmod 600 "$ev"
  if (( console )); then
    ok "PASS: the agent is managed from Bindplane through the gateway (evidence: $ev)"
    prune_cache
    return 0
  fi
  code=$(http_code_in_log "$before")
  if [[ ( -z $c1 || $c1 != "$c2" ) && -n $code ]]; then
    case $code in
      401|403) fail "The gateway refused the agent's session with HTTP $code (collector log)." \
                    "The secret key in $cf was rejected by Bindplane - a wrong key, or a key of another Bindplane organisation." \
                    "Copy the key again from the console (Agents -> Install Agents), then: $SELF --reconfigure (answer 'n' to keeping the key)" ;;
      404)     fail "The session was answered with HTTP 404." "The endpoint path is wrong (it must end in /v1/opamp), or the relay forwards to the wrong place." "Check: grep -n endpoint $COLLECTOR_CONF ; fix with --reconfigure" ;;
      502|503) fail "The session was answered with HTTP $code by the gateway." "The relay chain behind the gateway is down (LIVE hop 2 -> DMZ hop 1 -> Bindplane)." "On the gateway: bp-live-setup.sh --diagnose (or bp-dmz-setup.sh --diagnose); then: $SELF --only connect" ;;
      *)       fail "The session was answered with HTTP $code." "See the collector log lines above." "$SELF --diagnose" ;;
    esac
  elif [[ -z $c1 ]]; then
    st=$(tcp_state "$oh" "$op")
    if [[ $st != open ]]; then explain_tcp "$oh" "$op" "$st" "OpAMP relay"
      fail "The agent cannot open a connection to $oh:$op ($st)." "See the hint above." "Fix that (firewall rule, or the relay service on the gateway), then: $SELF --only connect"
    else
      fail "The agent did not hold an OpAMP session to $oh:$op within 60s." \
           "The port is reachable, so either the session is rejected at once (wrong secret key - the agent backs off), or the agent uses another endpoint." \
           "grep -n endpoint $COLLECTOR_CONF ; tail -n 50 $COLLECTOR_LOG ; then $SELF --only connect"
    fi
  elif [[ $c1 != "$c2" ]]; then
    fail "The OpAMP session keeps reconnecting (local port $c1 -> ${c2:-none})." \
         "The session is closed after it is established - typically a wrong secret key, or an inline device between this host and the gateway." \
         "Compare the key with the console; replace it with $SELF --reconfigure. On the gateway: journalctl -u haproxy -n 30"
  else
    fail "The session is up but the console does not show $name as Connected." \
         "Authentication was rejected (wrong key or organisation), or the console was not refreshed." \
         "Refresh the console and re-check the key; then: $SELF --only connect"
  fi
  return 1
}
# remove cached packages of other versions (each is ~100 MB) once the chosen one runs
prune_cache() {
  local f keep n=0
  keep=$(basename "$(pkg_file "$BP_VERSION")")
  for f in "$CACHE_DIR"/*-otel-collector_v*; do
    [[ -f $f ]] || continue
    [[ $(basename "$f") == "$keep" ]] && continue
    rm -f "$f" && n=$((n+1))
  done
  (( n )) && info "Removed $n cached package(s) of other versions from $CACHE_DIR"
  return 0
}

# =============================================================================
#  Answers
# =============================================================================
# pick_version - choose the collector version from what the gateway has for this host
pick_version() {
  local list def inst1 inst2 dflt cur1 cur2 fam t n=0 flags reply defn=""
  local -a idx=()
  list=$REPO_VERSIONS
  if [[ -n $ARG_VERSION ]]; then
    reply=$ARG_VERSION; [[ $reply == v* ]] || reply="v$reply"
    v_version "$reply" >/dev/null || { warn "  $(v_version "$reply")"; return 1; }
    if [[ -n $list ]] && ! contains_word "$list" "$reply"; then warn "  $reply is not on the gateway for this host. Available: $list"; return 1; fi
    BP_VERSION=$reply; set_family; info "  Collector version: $BP_VERSION - $(family_label "$COLLECTOR_FAMILY")"; return 0
  fi
  if [[ -z $list ]]; then
    warn "  The gateway's versions could not be listed - enter the release tag"
    ask BP_VERSION "Collector version (release tag, e.g. v1.109.0 or v2.0.1-beta.6)" "${BP_VERSION:-}" v_version || return 1
    [[ $BP_VERSION == v* ]] || BP_VERSION="v$BP_VERSION"; set_family; return 0
  fi
  inst1=$(pkg_version "$V1_PKG"); inst2=$(pkg_version "$V2_PKG")
  dflt=$(info_field current_collector_version); cur1=$(info_field current_v1); cur2=$(info_field current_v2)
  def=${BP_VERSION:-}; contains_word "$list" "$def" || def=""
  for t in $inst1 $inst2 $dflt; do [[ -z $def ]] && contains_word "$list" "$t" && def=$t; done
  [[ -z $def ]] && def=${list%% *}
  say "  Collector versions on the gateway for this host (.$PKG_TYPE, $ARCH):"
  for fam in v1 v2; do
    contains_word "$(for t in $list; do family_of_version "$t"; done | paste -sd' ')" "$fam" || continue
    if [[ $fam == v1 ]]; then printf '     %sv1  observiq-otel-collector%s  - manager.yaml; the stable line the runbook describes\n' "$C_BLD" "$C_OFF"
    else printf '     %sv2  bindplane-otel-collector%s - OpAMP supervisor + supervisor.yaml\n' "$C_BLD" "$C_OFF"; fi
    for t in $list; do
      [[ $(family_of_version "$t") == "$fam" ]] || continue
      n=$((n+1)); idx[n]=$t; [[ $t == "$def" ]] && defn=$n
      flags=""; is_prerelease "$t" && flags+=" pre-release"
      [[ $t == "$dflt" ]] && flags+=" (gateway default)"; [[ $t == "$cur1" || $t == "$cur2" ]] && flags+=" (current $fam)"
      [[ $t == "$inst1" || $t == "$inst2" ]] && flags+=" (installed here)"
      printf '        %2d) %-16s%s\n' "$n" "$t" "$flags"
    done
  done
  while :; do
    ask reply "Collector version to install (number or tag)" "${defn:-1}" || return 1
    [[ $reply =~ ^[0-9]+$ && -n ${idx[reply]-} ]] && reply=${idx[reply]}
    [[ $reply == v* ]] || reply="v$reply"
    if contains_word "$list" "$reply"; then BP_VERSION=$reply; break; fi
    warn "  $reply is not on the gateway for this host - choose a number from the list"
    { (( ASSUME_YES )) || [[ -z $TTY ]]; } && return 1
  done
  set_family
  info "  $BP_VERSION: $(family_label "$COLLECTOR_FAMILY")$(is_prerelease "$BP_VERSION" && echo ' - PRE-RELEASE: production use needs the customer'"'"'s approval')"
  t=$(pkg_version "$(product_of_family "$(other_family "$COLLECTOR_FAMILY")")")
  [[ -n $t ]] && warn "  This host runs the $(other_family "$COLLECTOR_FAMILY") collector $t - the install step asks what to do with it (stop, remove or keep)"
  return 0
}

# compose_labels - site / segment / zone asked one by one, os and role filled in, then the whole string
compose_labels() {
  local site seg zone lbl extras origin oip tier def_site def_seg
  if [[ -n $ARG_LABELS ]]; then
    v_labels "$ARG_LABELS" >/dev/null || { warn "  --labels: $(v_labels "$ARG_LABELS")"; return 1; }
    AGENT_LABELS=$ARG_LABELS; info "  Labels: $AGENT_LABELS"; return 0
  fi
  origin=$(info_field origin_host); oip=$(grep -oE '\(([0-9.]+)\)' <<<"$origin" | tr -d '()')
  def_site=$(label_get site)
  [[ -z $def_site ]] && { [[ ${origin%% *} == *dr* ]] && def_site=dr || def_site=primary; }
  def_seg=$(label_get segment)
  if [[ -z $def_seg ]]; then
    [[ -n $oip && $oip == "$GATEWAY" ]] && tier=dmz || tier=live
    [[ $def_site == dr ]] && def_seg="dr-$tier" || def_seg="prod-$tier"
  fi
  say "  Labels decide which configuration the console assigns to this agent (Stage 11) - they are not cosmetic."
  ask site "Site (primary or dr)" "$def_site" v_label_value || return 1
  ask seg "Network segment of this host" "$def_seg" v_label_value || return 1
  if [[ -z ${ARG_ZONE:-$(label_get zone)} ]] && { (( ASSUME_YES )) || [[ -z $TTY ]]; }; then
    err "  The zone label has no default - unattended runs need --zone NAME (or the full --labels \"...\")"; return 1
  fi
  ask zone "Zone / application group of this host (e.g. web, app, db, ad)" "${ARG_ZONE:-$(label_get zone)}" v_label_value || return 1
  lbl="site=$site,segment=$seg,zone=$zone,os=$OS_LABEL,role=source"
  extras=$(tr ',' '\n' <<<"${AGENT_LABELS:-}" | grep -vE '^(site|segment|zone|os|role)=' | grep . | paste -sd,)
  [[ -n $extras ]] && lbl+=",$extras"
  ask AGENT_LABELS "Labels (Enter to accept; edit to add more key=value pairs)" "$lbl" v_labels || return 1
}

apply_args() { # command-line values override the saved answers
  if [[ -n $ARG_GATEWAY ]]; then GATEWAY=${ARG_GATEWAY%%:*}; [[ $ARG_GATEWAY == *:* ]] && REPO_PORT=${ARG_GATEWAY##*:}; fi
  [[ -n $ARG_REPO_PORT ]] && REPO_PORT=$ARG_REPO_PORT
  [[ -n $ARG_ENDPOINT ]] && OPAMP_ENDPOINT=$ARG_ENDPOINT
  [[ -n $ARG_VERSION ]] && { BP_VERSION=$ARG_VERSION; [[ $BP_VERSION == v* ]] || BP_VERSION="v$BP_VERSION"; }
  [[ -n $ARG_LABELS ]] && AGENT_LABELS=$ARG_LABELS
  [[ -n $ARG_NAME ]] && AGENT_NAME=$ARG_NAME
  [[ -n $REPO_PORT ]] || REPO_PORT=$REPO_PORT_DEFAULT
  return 0
}

gather_config() {
  local def reply rc f ep h old_gw=$GATEWAY
  banner_line "Answers for this log source ($(hostname -s))"
  def=${GATEWAY:-}
  if [[ -z $def ]]; then # an installed collector already knows its gateway
    for f in v1 v2; do ep=$( use_family "$f"; yaml_get endpoint ); [[ -n $ep ]] || continue
      h=${ep#*://}; h=${h%%/*}; def=${h%%:*}; break; done
  fi
  [[ -n $def && -n $REPO_PORT && $REPO_PORT != "$REPO_PORT_DEFAULT" ]] && def="$def:$REPO_PORT"
  say "  The gateway of this host's segment: the LIVE gateway for LIVE log sources, the DMZ gateway for DMZ ones."
  while :; do
    ask reply "Gateway address (IP; add :port if the repository is not on :$REPO_PORT_DEFAULT)" "$def" v_host || return 1
    GATEWAY=${reply%%:*}
    if [[ $reply == *:* ]]; then REPO_PORT=${reply##*:}; else REPO_PORT=$REPO_PORT_DEFAULT; fi
    info "  Checking the repository at $(repo_url /) ..."
    REPO_SUMS=""; load_repo_index; rc=$?
    if (( rc == 0 )); then ok "  Repository found - versions for this host: ${REPO_VERSIONS:-none}"; break; fi
    explain_repo_failure "$rc" SHA256SUMS
    print_block "Problem" "$FAIL_WHAT"; print_block "Likely cause" "$FAIL_WHY"; print_block "How to fix" "$FAIL_FIX"
    FAIL_WHAT="" FAIL_WHY="" FAIL_FIX=""
    if (( ASSUME_YES )) || [[ -z $TTY ]]; then return 1; fi
    ask_yn "Keep $GATEWAY anyway (the version list cannot be shown; the gateway step checks again)?" n && break
    def=$reply
  done
  def=${OPAMP_ENDPOINT:-}
  if [[ -z $def ]] || { [[ -n $old_gw && $old_gw != "$GATEWAY" ]] && [[ $def == *"://$old_gw:"* || $def == *"://$old_gw/"* ]]; }; then
    def="ws://$GATEWAY:$OPAMP_PORT_DEFAULT/v1/opamp"
  fi
  ask OPAMP_ENDPOINT "OpAMP endpoint the agent connects to (the gateway's relay)" "$def" v_endpoint || return 1
  pick_version || return 1
  compose_labels || return 1
  def=${AGENT_NAME:-$( use_family v1; yaml_get agent_name )}; def=${def:-$(hostname -s)}
  if [[ $COLLECTOR_FAMILY == v1 ]]; then
    ask AGENT_NAME "Agent name shown in the console" "$def" v_agent_name || return 1
  else
    AGENT_NAME=$(hostname -s)
    info "  Agent name: $AGENT_NAME (a v2 agent is named after the host)"
  fi
  return 0
}
config_complete() {
  local k
  for k in GATEWAY REPO_PORT OPAMP_ENDPOINT BP_VERSION AGENT_LABELS AGENT_NAME; do [[ -n ${!k-} ]] || return 1; done
  return 0
}
show_config() {
  printf '  %-22s %s\n' "Gateway repository" "$( [[ -n $GATEWAY ]] && repo_url / || echo '?')" \
    "OpAMP endpoint" "${OPAMP_ENDPOINT:-?}" \
    "Collector version" "${BP_VERSION:-?}$( [[ -n $BP_VERSION ]] && echo " - $(family_label "$(family_of_version "$BP_VERSION")")")$(is_prerelease "${BP_VERSION:-}" && echo '  PRE-RELEASE')" \
    "Labels" "${AGENT_LABELS:-?}" \
    "Agent name" "${AGENT_NAME:-?}" \
    "This host" "$OS_PRETTY, $ARCH, .$PKG_TYPE packages" \
    "Collector here now" "$(installed_summary)"
}
confirm_config() {
  banner_line "Summary"
  show_config
  echo
  ask_yn "Proceed with these answers?" y
}

# =============================================================================
#  Diagnostics (read-only)
# =============================================================================
section() { printf '\n%s--- %s ---%s\n' "$C_BLD" "$*" "$C_OFF"; log "---- $*"; }
run_diagnostics() {
  local f v st en nr oh op rc errs code sess
  CHK_FAILS=0; CHK_WARNS=0
  banner_line "Diagnostics (read-only) - $(hostname -s), $(date '+%F %T')"
  section "This host"
  check_platform; check_time; check_space /opt 700 "the collector (/opt)"; check_noexec; check_selinux; check_proxy_env
  section "Gateway"
  if [[ -n ${GATEWAY:-} ]]; then
    st=$(tcp_state "$GATEWAY" "$REPO_PORT"); explain_tcp "$GATEWAY" "$REPO_PORT" "$st" "repository" || CHK_FAILS=$((CHK_FAILS+1))
    if [[ $st == open ]]; then
      REPO_SUMS=""; load_repo_index; rc=$?
      if (( rc == 0 )); then c_ok "Repository: $(wc -l <"$REPO_SUMS") files; versions for this host: ${REPO_VERSIONS:-none}; default $(info_field current_collector_version)"
        [[ -n ${BP_VERSION:-} ]] && { contains_word "$REPO_VERSIONS" "$BP_VERSION" && c_ok "$BP_VERSION is on the gateway" || c_warn "$BP_VERSION is no longer on the gateway"; }
      else explain_repo_failure "$rc" SHA256SUMS; c_fail "$FAIL_WHAT"; hint "$(printf '%b' "$FAIL_FIX" | head -n1)"; FAIL_WHAT="" FAIL_WHY="" FAIL_FIX=""; fi
    fi
    if [[ -n ${OPAMP_ENDPOINT:-} ]]; then
      oh=$(opamp_host); op=$(opamp_port)
      st=$(tcp_state "$oh" "$op"); explain_tcp "$oh" "$op" "$st" "OpAMP relay" || CHK_FAILS=$((CHK_FAILS+1))
      st=$(tcp_state "$oh" "$OTLP_PORT"); [[ $st == open ]] && c_ok "TCP $oh:$OTLP_PORT reachable (OTLP)" || c_warn "TCP $oh:$OTLP_PORT $st (OTLP - telemetry)"
    fi
  else
    c_warn "No gateway saved yet - run the installer first (or pass --gateway IP to --diagnose)"
  fi
  section "Collector"
  if [[ $(installed_family) == none ]]; then c_warn "No collector package is installed"; fi
  for f in v1 v2; do
    v=$(pkg_version "$(product_of_family "$f")"); [[ -n $v ]] || continue
    use_family "$f"
    st=$(systemctl is-active "$COLLECTOR_SVC" 2>/dev/null); en=$(systemctl is-enabled "$COLLECTOR_SVC" 2>/dev/null)
    nr=$(systemctl show -p NRestarts --value "$COLLECTOR_SVC" 2>/dev/null)
    [[ $st == active ]] && c_ok "$(family_label "$f") $v: $st, $en${nr:+, restarts $nr}" || c_warn "$(family_label "$f") $v: ${st:-unknown}, ${en:-unknown}${nr:+, restarts $nr}"
    if [[ -f $COLLECTOR_CONF ]]; then
      c_ok "$(basename "$COLLECTOR_CONF"): owner $(stat -c '%U:%G' "$COLLECTOR_CONF"), mode $(stat -c %a "$COLLECTOR_CONF"), endpoint $(yaml_get endpoint), key $( [[ -n $(yaml_get secret_key) ]] && mask "$(yaml_get secret_key)" || echo MISSING)"
      say "         labels: $(yaml_get labels)   identity: $(yaml_get agent_id)"
      [[ $(stat -c %a "$COLLECTOR_CONF") == 600 ]] || c_warn "$(basename "$COLLECTOR_CONF") should be mode 0600 (it holds the secret key)"
      [[ -n ${OPAMP_ENDPOINT:-} && $(yaml_get endpoint) != "$OPAMP_ENDPOINT" ]] && c_warn "Its endpoint differs from the saved answer ($OPAMP_ENDPOINT) - $SELF --only configure"
    else c_warn "$COLLECTOR_CONF is missing - the agent has no endpoint/key ($SELF --only configure)"; fi
    sess=""; [[ -n ${OPAMP_ENDPOINT:-} ]] && sess=$(collector_conn)
    [[ -n $sess ]] && c_ok "OpAMP session established from $sess" || { [[ $st == active ]] && c_warn "No established OpAMP session to $(opamp_host 2>/dev/null):$(opamp_port 2>/dev/null)"; }
    code=$(http_code_in_log "$(log_mark)")
    [[ $code == 401 || $code == 403 ]] && c_warn "The log shows HTTP $code on the OpAMP upgrade: the secret key is rejected"
    errs=$(collector_log_errors "$(log_mark)" 5)
    [[ -n $errs ]] && { say "         log errors since the last start ($COLLECTOR_LOG):"; printf '%s\n' "$errs" | redact_stream | sed 's/^/           /'; }
  done
  set_family
  section "Result"
  if (( CHK_FAILS )); then err "$CHK_FAILS problem(s), $CHK_WARNS warning(s) - see the hints above"
  elif (( CHK_WARNS )); then warn "No failures, $CHK_WARNS warning(s)"
  else ok "No problems found"; fi
  say "  Logs: this script $LOG_DIR ; collector $COLLECTOR_LOG ; journalctl -u $COLLECTOR_SVC"
  return 0
}

# =============================================================================
#  Operations
# =============================================================================
status_word() {
  case $1 in
    done) printf '%sdone%s' "$C_GRN" "$C_OFF" ;; skipped) printf '%sSKIPPED%s' "$C_YLW" "$C_OFF" ;;
    failed) printf '%sFAILED%s' "$C_RED" "$C_OFF" ;; running|interrupted) printf '%sINTERRUPTED%s' "$C_YLW" "$C_OFF" ;;
    *) printf 'pending' ;;
  esac
}
show_progress() {
  local s i=0
  for s in "${STEPS[@]}"; do
    i=$((i+1))
    printf '   %2d. %-52s %s\n' "$i" "${STEP_TITLE[$s]}" "$(status_word "$(state_get "$s")")"
  done
}
snapshot_config() { local k; for k in "${CONF_KEYS[@]}"; do OLD_CONF[$k]=${!k-}; done; }
invalidate_changed() {
  local k s changed=""
  for k in "${!DEPENDS[@]}"; do
    [[ ${OLD_CONF[$k]-} == "${!k-}" ]] && continue
    changed+=" $k"
    for s in ${DEPENDS[$k]}; do [[ $(state_get "$s") == "done" || $(state_get "$s") == skipped ]] && state_set "$s" pending; done
  done
  [[ -n $changed ]] && info "Changed:$changed - dependent steps will run again."
  return 0
}
declare -A OLD_CONF=()
declare -A FORCED=()
run_steps() {
  local step st i total=${#STEPS[@]} rc c last=${*: -1}
  for step in "$@"; do
    i=$(step_index "$step"); st=$(state_get "$step")
    if [[ $st == "done" ]] && (( ! FORCE_ALL )) && [[ -z ${FORCED[$step]-} ]]; then
      printf '%s  [%2d/%d] %-52s done - skipping%s\n' "$C_DIM" "$i" "$total" "${STEP_TITLE[$step]}" "$C_OFF"
      continue
    fi
    while :; do
      printf '\n%s=== [%2d/%d] %s   (runbook %s) ===%s\n' "$C_BLD" "$i" "$total" "${STEP_TITLE[$step]}" "${STEP_REF[$step]}" "$C_OFF"
      log "==== STEP $step (${STEP_TITLE[$step]})"
      CURRENT_STEP=$step; FAIL_WHAT=""; FAIL_WHY=""; FAIL_FIX=""
      state_set "$step" running
      cd "$STATE_DIR" 2>/dev/null || cd /
      if [[ $step == *:* ]]; then "step_${step%%:*}" "${step#*:}"; else "step_$step"; fi; rc=$?
      cd "$STATE_DIR" 2>/dev/null || cd /
      if (( rc == 0 )); then state_set "$step" "done"; CURRENT_STEP=""; break; fi
      if (( rc == 3 )); then state_set "$step" skipped; CURRENT_STEP=""; break; fi
      state_set "$step" failed
      print_failure "$step"
      if (( ASSUME_YES )) || [[ -z $TTY ]]; then c=q
      else
        while :; do
          c=$(choose "  What next?  [r] retry this step   [d] diagnostics   [s] skip this step   [q] quit, resume later: " rdsq)
          [[ $c == d ]] || break
          run_diagnostics; print_failure "$step"
        done
      fi
      case $c in
        r) info "Retrying: ${STEP_TITLE[$step]}" ;;
        s) warn "Skipping '${STEP_TITLE[$step]}' at your request - later steps may fail because of it."
           state_set "$step" skipped; CURRENT_STEP=""; break ;;
        q) CURRENT_STEP=""; echo
           if (( ADHOC )); then info "Stopped. Nothing in the build progress was changed - fix the cause and run the same command again."
           else info "Stopped. Progress is saved - fix the cause, then re-run this script to resume at: ${STEP_TITLE[$step]}"; fi
           info "Log: $LOG_FILE"
           exit 1 ;;
      esac
    done
    if [[ $step != "$last" && ( $PAUSE_BETWEEN_STEPS == yes || $FORCE_PAUSE == 1 ) ]] && [[ -n $TTY ]] && (( ! ASSUME_YES )); then
      c=$(choose "  [Enter] continue to the next step   [q] pause here (resume later by re-running): " cq c)
      [[ $c == q ]] && { info "Paused after '${STEP_TITLE[$step]}'. Re-run the script to continue."; exit 0; }
    fi
  done
}
all_steps_settled() {
  local s st
  for s in "${STEPS[@]}"; do st=$(state_get "$s"); [[ $st == "done" || $st == skipped ]] || return 1; done
  return 0
}

needs_secret() { # the configure step is pending or forced (and will run)
  if [[ -n ${FORCED[configure]-} || $(state_get configure) != "done" ]]; then
    [[ -z $ONLY_STEP || $ONLY_STEP == configure ]] && return 0
  fi
  return 1
}

final_summary() {
  local name
  name=$( [[ $COLLECTOR_FAMILY == v2 ]] && hostname -s || echo "$AGENT_NAME" )
  banner_line "Result"
  show_progress
  echo
  say "  Agent          : $name - $COLLECTOR_PKG $(collector_version) ($COLLECTOR_FAMILY)"
  say "  Gateway        : repository $(repo_url /)   OpAMP $OPAMP_ENDPOINT"
  say "  Labels         : $AGENT_LABELS"
  say "  Config / log   : $COLLECTOR_CONF (0600)  |  $COLLECTOR_LOG"
  say "  Service        : systemctl status $COLLECTOR_SVC"
  say "  This run's log : $LOG_FILE"
  say "  Later          : $SELF --diagnose | --upgrade [tag] | --reconfigure | --uninstall"
}

action_install() {
  local had=0 list=() s found=0 old_key
  init_defaults
  load_config && had=1
  apply_args
  set_family
  snapshot_config
  if (( ! had || RECONFIGURE )) || ! config_complete; then
    (( had )) && (( ! RECONFIGURE )) && info "Some answers are missing - asking for them now."
    gather_config || { err "The answers were not completed - nothing was changed."; exit 1; }
    confirm_config || { info "Stopped before making changes."; exit 0; }
    save_config; ok "Answers saved to $CONF_FILE (root-only; the secret key is not stored there)"
  else
    banner_line "Using saved answers ($CONF_FILE)"
    show_config
    say "  (run with --reconfigure to change any of them)"
    if [[ -n $TTY ]] && (( ! ASSUME_YES )) && ! ask_yn "Continue with these values?" y; then
      gather_config && confirm_config || { info "Stopped before making changes."; exit 0; }
      save_config; ok "Answers saved"
    fi
  fi
  (( had )) && invalidate_changed
  set_family
  if [[ -n $ONLY_STEP ]]; then list=("$ONLY_STEP"); FORCED[$ONLY_STEP]=1
  elif [[ -n $FROM_STEP ]]; then
    for s in "${STEPS[@]}"; do [[ $s == "$FROM_STEP" ]] && found=1; (( found )) && { list+=("$s"); FORCED[$s]=1; }; done
  else list=("${STEPS[@]}"); fi
  if (( REINSTALL )); then for s in download verify install configure start connect; do [[ $(state_get "$s") == "done" ]] && state_set "$s" pending; done; fi
  banner_line "Progress"
  show_progress
  if [[ -z $ONLY_STEP && -z $FROM_STEP ]] && all_steps_settled && (( ! RECONFIGURE )); then
    echo; ok "Every step is already complete - the agent is installed and connected."
    hint "Health check: $SELF --diagnose | upgrade: $SELF --upgrade | change answers: $SELF --reconfigure"
    return 0
  fi
  if (( RECONFIGURE )) || needs_secret; then
    old_key=$(yaml_get secret_key)
    ensure_secret || { print_block "Problem" "$FAIL_WHAT"; print_block "How to fix" "$FAIL_FIX"; exit 1; }
    if [[ -n $old_key && $BP_SECRET != "$old_key" ]]; then
      for s in configure start connect; do [[ $(state_get "$s") == "done" ]] && state_set "$s" pending; done
      info "The secret key changed - the configure, start and connect steps run again"
    fi
  fi
  run_steps "${list[@]}"
  final_summary
}

# newest version of a family on the gateway (stable preferred)
newest_of() {
  local fam=$1 c t
  c=$(for t in $REPO_VERSIONS; do [[ $(family_of_version "$t") == "$fam" ]] && echo "$t"; done)
  { grep -v -- - <<<"$c" | sort_tags | tail -n1; sort_tags <<<"$c" | tail -n1; } | grep . | head -n1
}
action_upgrade() {
  local target inst rc s fam
  init_defaults
  load_config || { err "This host has no saved answers yet - run the installer without --upgrade first."; exit 1; }
  apply_args; set_family
  inst=$(pkg_version "$COLLECTOR_PKG")
  banner_line "Offline upgrade from the gateway $(repo_url /)"
  REPO_SUMS=""; load_repo_index; rc=$?
  (( rc == 0 )) || { explain_repo_failure "$rc" SHA256SUMS; print_block "Problem" "$FAIL_WHAT"; print_block "How to fix" "$FAIL_FIX"; exit 1; }
  target=${ACTION_ARG:-}
  [[ -n $target && $target != v* ]] && target="v$target"
  if [[ -z $target ]]; then
    fam=$(family_of_version "${inst:-$BP_VERSION}")
    target=$(newest_of "$fam")
    info "Newest $fam version on the gateway for this host: ${target:-none} (installed: ${inst:-none})"
  fi
  [[ -n $target ]] || { err "The gateway has no version for this host (.$PKG_TYPE, $ARCH): ${REPO_VERSIONS:-none}"; exit 1; }
  contains_word "$REPO_VERSIONS" "$target" || { err "$target is not on the gateway for this host. Available: $REPO_VERSIONS"; exit 1; }
  if [[ $target == "$inst" ]]; then ok "$COLLECTOR_PKG $inst is already the version requested - nothing to do"; hint "Other versions on the gateway: $REPO_VERSIONS"; exit 0; fi
  if [[ $(family_of_version "$target") != "$COLLECTOR_FAMILY" ]]; then
    warn "$target is a $(family_label "$(family_of_version "$target")") release - this SWITCHES the collector family on this host."
    say  "  The new collector gets its own configuration (same endpoint, key and labels) and appears as a new agent."
    if (( ASSUME_YES )) && [[ -z $OTHER_ACTION ]]; then err "Unattended family switch needs --other-collector stop|remove|keep"; exit 1; fi
  fi
  ask_yn "Change $COLLECTOR_PKG ${inst:-<none>} -> $target?" y || { info "Nothing changed."; exit 0; }
  BP_VERSION=$target; save_config
  for s in gateway download verify install configure start connect; do state_set "$s" pending; done
  set_family
  ensure_secret || { print_block "Problem" "$FAIL_WHAT"; print_block "How to fix" "$FAIL_FIX"; exit 1; }
  run_steps "${STEPS[@]}"
  final_summary
}

action_uninstall() {
  local f v home any=0
  init_defaults; load_config
  banner_line "Uninstall the Bindplane collector from $(hostname -s)"
  for f in v1 v2; do
    v=$(pkg_version "$(product_of_family "$f")"); [[ -n $v ]] || continue
    any=1
    ask_yn "Remove $(family_label "$f") $v?" y || continue
    use_family "$f"; home=$COLLECTOR_HOME
    systemctl disable --now "$COLLECTOR_SVC" >/dev/null 2>&1
    pkg_remove "$COLLECTOR_PKG" || { explain_pkg_failure "$LAST_OUT"; print_block "Problem" "$FAIL_WHAT"; print_block "How to fix" "$FAIL_FIX"; exit 1; }
    ok "$COLLECTOR_PKG removed"
    if [[ -d $home && $home == /?*/?* ]]; then
      if ask_yn "Also delete $home (its config with the secret key, the agent identity, any queued telemetry)?" y; then
        rm -rf -- "$home" && ok "Deleted $home"
      else warn "Kept $home - it still holds the secret key in $(basename "$COLLECTOR_CONF")"; fi
    fi
  done
  (( any )) || ok "No collector package is installed on this host"
  rm -f "$STATE_FILE" "$STATE_DIR/restart-needed" "$STATE_DIR/verify.result" "$STATE_DIR/log-mark"
  ok "Progress cleared ($STATE_FILE)"
  if [[ -d $CACHE_DIR ]] && ask_yn "Delete the downloaded packages in $CACHE_DIR?" y; then rm -rf -- "${CACHE_DIR:?}"/* && ok "Cache emptied"; fi
  if [[ -f $CONF_FILE ]] && ask_yn "Forget the saved answers too ($CONF_FILE)?" n; then
    rm -f "$CONF_FILE" "$STATE_DIR"/*.bak-* && ok "Answers and configuration backups removed"
  fi
  (( any )) && hint "The agent now shows as disconnected in the console - delete it there (Agents)."
  return 0
}

action_status() {
  init_defaults
  load_config || info "No saved answers yet ($CONF_FILE)"
  apply_args; set_family
  banner_line "Saved answers"; show_config
  banner_line "Progress"; show_progress
  banner_line "Collector service"
  if [[ $(installed_family) == none ]]; then say "  not installed"
  else
    systemctl --no-pager --lines=0 status "$COLLECTOR_SVC" 2>/dev/null | head -n 5 | sed 's/^/  /'
    [[ -n ${OPAMP_ENDPOINT:-} ]] && { local c; c=$(collector_conn); say "  OpAMP session: ${c:-none} -> $(opamp_host):$(opamp_port)"; }
    [[ -f $STATE_DIR/verify.result ]] && say "  Last verification: $(tr '\n' ' ' <"$STATE_DIR/verify.result")"
  fi
}
action_diagnose() {
  init_defaults; load_config; apply_args; set_family
  run_diagnostics
}
action_list() { local s i=0; for s in "${STEPS[@]}"; do i=$((i+1)); printf '  %2d. %-10s %s\n' "$i" "$s" "${STEP_TITLE[$s]}"; done; }
action_reset() { rm -f "$STATE_FILE" "$STATE_DIR/restart-needed"; ok "Step progress forgotten (answers kept in $CONF_FILE)"; }

# =============================================================================
#  Entry point
# =============================================================================
usage() {
  cat <<EOF
$SCRIPT_NAME v$SCRIPT_VERSION - NCINGA internal: offline Bindplane agent install for Linux log sources (Stage 8)

Usage: sudo bash $SELF [options]

Install (default): asks for the gateway, lists the collector versions it holds for this host,
asks for the secret key and labels, then downloads, verifies, installs, configures, starts and
checks the agent. Re-running resumes at the first unfinished step; completed steps are skipped.

Answers (also usable for unattended runs with -y):
  --gateway IP[:PORT]       the gateway of this segment (repository on :$REPO_PORT_DEFAULT unless PORT is given)
  --endpoint URL            OpAMP endpoint (default ws://<gateway>:$OPAMP_PORT_DEFAULT/v1/opamp)
  --collector-version TAG   e.g. v1.109.0 or v2.0.1-beta.6 (default: the gateway's default)
  --labels "k=v,..."        all labels, e.g. site=primary,segment=prod-live,zone=web,os=$OS_LABEL,role=source
  --zone NAME               only the zone label (site and segment are derived from the gateway)
  --agent-name NAME         v1 agent name (default: the short host name)
  --secret-file PATH        read the secret key from a root-only file (or set BP_SECRET in the environment)
  --other-collector stop|remove|keep   what to do with a collector of the other family (v1/v2)

Run control:
  --reconfigure             ask every question again (previous answers are the defaults)
  --from STEP | --only STEP re-run from / just one step      --list-steps   the step names
  --reinstall               install the same version again (repairs a damaged installation)
  --pause                   pause between steps
  -y, --yes                 no questions: saved/default answers; stop at the first failure

Verification:
  --no-gpg-check            accept checksum-only verification (no publisher signature check)
  --signing-key FPR         trust this publisher key fingerprint instead of the built-in one
                            (only after the publisher rotated its key and you verified the new one)

Operations:
  --status                  answers, progress, service and session
  --diagnose                read-only health check (gateway, ports, service, config, log errors)
  --upgrade [TAG]           offline upgrade from the gateway (default: newest of the installed family)
  --uninstall               remove the collector (asks before deleting its configuration)
  --reset                   forget step progress (answers are kept)
  --package-type deb|rpm    override the package type detection
  --no-color | -h, --help | --version

Files: answers $CONF_FILE | progress $STATE_FILE | downloads $CACHE_DIR | logs $LOG_DIR
The secret key is never stored by this script - only in the collector's config (mode 0600).

(c) 2026 NCINGA. All rights reserved. NCINGA internal - proprietary and confidential; see the header.
EOF
}

parse_args() {
  local need
  while (( $# )); do
    need=0
    case $1 in
      --gateway)        need=1; ARG_GATEWAY=${2:-} ;;           --gateway=*)  ARG_GATEWAY=${1#*=} ;;
      --repo-port)      need=1; ARG_REPO_PORT=${2:-} ;;
      --endpoint)       need=1; ARG_ENDPOINT=${2:-} ;;          --endpoint=*) ARG_ENDPOINT=${1#*=} ;;
      --collector-version|--agent-version) need=1; ARG_VERSION=${2:-} ;;
      --collector-version=*|--agent-version=*) ARG_VERSION=${1#*=} ;;
      --labels)         need=1; ARG_LABELS=${2:-} ;;            --labels=*)   ARG_LABELS=${1#*=} ;;
      --zone)           need=1; ARG_ZONE=${2:-} ;;              --zone=*)     ARG_ZONE=${1#*=} ;;
      --agent-name)     need=1; ARG_NAME=${2:-} ;;
      --secret-file)    need=1; SECRET_FILE=${2:-} ;;
      --other-collector) need=1; OTHER_ACTION=${2:-} ;;         --other-collector=*) OTHER_ACTION=${1#*=} ;;
      --package-type)   need=1; ARG_PKG_TYPE=${2:-} ;;
      --signing-key)    need=1; PUBLISHER_FPR=$(tr -d ' ' <<<"${2:-}" | tr 'a-f' 'A-F') ;;
      --no-gpg-check)   NO_GPG_CHECK=1 ;;
      --reinstall)      REINSTALL=1 ;;
      --from)           need=1; FROM_STEP=${2:-} ;;             --from=*)     FROM_STEP=${1#*=} ;;
      --only)           need=1; ONLY_STEP=${2:-} ;;             --only=*)     ONLY_STEP=${1#*=} ;;
      --reconfigure)    RECONFIGURE=1 ;;
      --pause)          FORCE_PAUSE=1 ;;
      -y|--yes)         ASSUME_YES=1 ;;
      --status)         ACTION=status ;;
      --diagnose|--diag) ACTION=diagnose ;;
      --upgrade)        ACTION=upgrade; if [[ -n ${2:-} && ${2:0:1} != - ]]; then ACTION_ARG=$2; shift; fi ;;
      --upgrade=*)      ACTION=upgrade; ACTION_ARG=${1#*=} ;;
      --uninstall)      ACTION=uninstall ;;
      --list-steps)     ACTION=list ;;
      --reset)          ACTION=reset ;;
      --no-color)       USE_COLOR=0 ;;
      -h|--help)        ACTION=help ;;
      --version)        echo "$SCRIPT_NAME $SCRIPT_VERSION"; exit 0 ;;
      *) echo "Unknown option: $1   (see --help)" >&2; exit 2 ;;
    esac
    if (( need )); then
      [[ -n ${2:-} ]] || { echo "Option $1 needs a value (see --help)" >&2; exit 2; }
      shift
    fi
    shift
  done
  local m
  for m in "$FROM_STEP" "$ONLY_STEP"; do [[ -z $m ]] || v_step "$m" >/dev/null || { v_step "$m" >&2; exit 2; }; done
  [[ -z $OTHER_ACTION || $OTHER_ACTION =~ ^(stop|remove|keep)$ ]] || { echo "--other-collector takes stop, remove or keep" >&2; exit 2; }
  [[ -z $ARG_PKG_TYPE || $ARG_PKG_TYPE =~ ^(deb|rpm)$ ]] || { echo "--package-type takes deb or rpm" >&2; exit 2; }
  [[ -z $ARG_GATEWAY ]] || v_host "$ARG_GATEWAY" >/dev/null || { echo "--gateway: $(v_host "$ARG_GATEWAY")" >&2; exit 2; }
  [[ -z $ARG_ENDPOINT ]] || v_endpoint "$ARG_ENDPOINT" >/dev/null || { echo "--endpoint: $(v_endpoint "$ARG_ENDPOINT")" >&2; exit 2; }
  [[ -z $ARG_REPO_PORT || $ARG_REPO_PORT =~ ^[0-9]{1,5}$ ]] || { echo "--repo-port takes a port number" >&2; exit 2; }
  [[ $PUBLISHER_FPR =~ ^[0-9A-F]{40}$ ]] || { echo "--signing-key takes a 40-hex-digit fingerprint" >&2; exit 2; }
  [[ -z $SECRET_FILE || -r $SECRET_FILE ]] || { echo "--secret-file: cannot read $SECRET_FILE" >&2; exit 2; }
}

on_signal() {
  local sig=$1
  trap '' INT TERM HUP
  [[ -n $TTY ]] && stty echo <"$TTY" 2>/dev/null
  [[ -n $DL_PID ]] && kill "$DL_PID" 2>/dev/null
  echo
  warn "Received SIG$sig - stopping safely."
  [[ -n $CURRENT_STEP ]] && state_set "$CURRENT_STEP" interrupted
  info "Progress is saved (a partial download is resumed). Re-run the script to continue${CURRENT_STEP:+ at: ${STEP_TITLE[$CURRENT_STEP]}}."
  [[ -n $LOG_FILE ]] && info "Log: $LOG_FILE"
  exit 130
}
on_exit() {
  [[ -n $DL_PID ]] && kill "$DL_PID" 2>/dev/null
  [[ -n $RUN_TMP && -d $RUN_TMP ]] && rm -rf "$RUN_TMP"
}

main() {
  local c miss=""
  parse_args "$@"
  setup_colors
  detect_platform
  [[ $ACTION == help ]] && { print_brand "$SCRIPT_NAME v$SCRIPT_VERSION - offline agent install (Linux)"; usage; exit 0; }
  (( EUID == 0 )) || { echo "This script must run as root:  sudo bash $SELF $*" >&2; exit 1; }
  for c in awk sed grep flock sha256sum stat df mktemp timeout curl tar systemctl; do command -v "$c" >/dev/null || miss+=" $c"; done
  if [[ -n $miss ]]; then
    echo "Missing required commands:$miss" >&2
    echo "Install them from the internal OS repository - they are part of a standard server installation." >&2
    exit 1
  fi
  install -d -m 700 "$STATE_DIR" "$LOG_DIR" "$EVIDENCE_DIR" || { echo "Cannot create $STATE_DIR / $LOG_DIR" >&2; exit 1; }
  LOG_FILE="$LOG_DIR/run-$RUN_TS-$ACTION.log"; : >"$LOG_FILE"; chmod 600 "$LOG_FILE"
  RUN_TMP=$(mktemp -d "/tmp/$SCRIPT_NAME.XXXXXX") || exit 1
  if [[ -c /dev/tty ]] && ( : </dev/tty ) 2>/dev/null; then TTY=/dev/tty; fi

  exec 9>>"$LOCK_FILE"
  if ! flock -n 9; then
    echo "Another $SCRIPT_NAME run is in progress (PID $(head -n1 "$LOCK_FILE" 2>/dev/null || echo '?'), lock $LOCK_FILE)." >&2
    exit 1
  fi
  printf '%s\n' "$$" >"$LOCK_FILE"
  trap 'on_signal INT' INT; trap 'on_signal TERM' TERM; trap 'on_signal HUP' HUP; trap on_exit EXIT

  print_brand "$SCRIPT_NAME v$SCRIPT_VERSION - offline agent install for Linux log sources (Stage 8)"
  set_family
  say "  Host: $(hostname -s)   OS: $OS_PRETTY ($ARCH, .${PKG_TYPE:-?})   Collector here: $(installed_summary)"
  say "  Action: $ACTION   Log: $LOG_FILE"
  log "args: $* (tty output: $TTY_OUT)"
  [[ $SELF == bp-agent-install-linux.sh && ! -f $0 ]] && warn "This script runs from a pipe: save it to a file first, so a failed run can be resumed (curl -fsSO http://<gateway>:$REPO_PORT_DEFAULT/scripts/bp-agent-install-linux.sh)"
  if [[ $ACTION == install && -n ${SSH_CONNECTION:-} && -z ${TMUX:-}${STY:-} ]]; then
    say "  Tip: over SSH, a dropped session is safe - re-run the script and it resumes."
  fi
  case $ACTION in
    install)   action_install ;;
    upgrade)   action_upgrade ;;
    uninstall) action_uninstall ;;
    status)    action_status ;;
    diagnose)  action_diagnose ;;
    list)      action_list ;;
    reset)     action_reset ;;
  esac
}

main "$@"

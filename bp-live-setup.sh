#!/usr/bin/env bash
# =============================================================================
#  bp-live-setup.sh  -  CBSL Bindplane: LIVE gateway build (Ubuntu, no internet)
# =============================================================================
#  Implements the LIVE-side stages of "CBSL Bindplane Deployment - Production
#  Command Runbook v1.0" on bp-gw-live-01 (or bp-gw-drlive-01 for DR):
#
#    Stage 5 ....... software with no repository: path check to the DMZ
#                    gateway (§5.1), apt pointed ONLY at the DMZ repository
#                    (§5.2, signed or unsigned §5.4), nginx/haproxy/wget (§5.5)
#    Stage 6 ....... mirror of the DMZ repository + bp-mirror-sync (§6.1),
#                    nginx serving it to the LIVE segment on LIVE_GW_IP:8080
#                    (§6.2), HAProxy hop 2 on LIVE_GW_IP:3001 (§6.3), the
#                    collector installed from the mirror with a hand-written
#                    manager.yaml (§6.4) and verified (§6.5)
#    Stage 12.1 .... socket census + evidence pack + log-source hand-off
#
#  Prerequisite: the DMZ side (bp-dmz-setup.sh) is complete and its gates
#  §4.2/§4.4 passed. This host needs Fortigate rules to the DMZ gateway on
#  tcp/8080 (packages), tcp/3001 (OpAMP) and later tcp/4317 (OTLP).
#
#  Design goals: interactive (asks for every value, offers detected defaults),
#  resumable (re-run resumes at the first unfinished step; Ctrl+C / SSH drop
#  are safe), explainable (each failure states what happened, the likely cause
#  and the fix; then retry / diagnostics / skip / quit), idempotent.
#
#  Usage:  sudo bash bp-live-setup.sh            (then follow the prompts)
#          sudo bash bp-live-setup.sh --help     (all options)
# =============================================================================

SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="bp-live-setup"

set -uo pipefail
umask 022
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

# ----------------------------------------------------------------------------
# Fixed paths and ports (runbook values). Paths can be overridden via env.
# ----------------------------------------------------------------------------
STATE_DIR=${BP_STATE_DIR:-/var/lib/bp-live-setup}
LOG_DIR=${BP_LOG_DIR:-/var/log/bp-live-setup}
REPO_ROOT=${BP_REPO_ROOT:-/srv/bindplane}
CONF_FILE="$STATE_DIR/setup.conf"
STATE_FILE="$STATE_DIR/progress"
UFW_RECORD="$STATE_DIR/ufw-rules.added"
LOCK_FILE="/run/$SCRIPT_NAME.lock"
EVIDENCE_DIR="$LOG_DIR/evidence"
NEXT_STEPS_FILE="$LOG_DIR/NEXT-STEPS-LOG-SOURCES.txt"

APT_LIST="/etc/apt/sources.list.d/bindplane-local.list"
APT_KEYRING_DEFAULT="/etc/apt/keyrings/bindplane-repo.gpg"
MIRROR_SYNC="/usr/local/bin/bp-mirror-sync"
MIRROR_LOG="/var/log/bp-mirror-sync.log"
SYNC_SERVICE="/etc/systemd/system/bp-mirror-sync.service"
SYNC_TIMER="/etc/systemd/system/bp-mirror-sync.timer"

COLLECTOR_HOME=${BP_COLLECTOR_HOME:-/opt/observiq-otel-collector}
COLLECTOR_SVC="observiq-otel-collector"
COLLECTOR_PKG="observiq-otel-collector"
MANAGER_YAML="$COLLECTOR_HOME/manager.yaml"
COLLECTOR_LOG="$COLLECTOR_HOME/log/collector.log"
COLLECTOR_BIN="$COLLECTOR_HOME/observiq-otel-collector"
# known harmless error-level line the collector prints at every start
BENIGN_LOG_RE='Capabilities is deprecated'

HAPROXY_CFG="/etc/haproxy/haproxy.cfg"
HAPROXY_DROPIN_DIR="/etc/systemd/system/haproxy.service.d"
HAPROXY_DROPIN="$HAPROXY_DROPIN_DIR/limits.conf"
NGINX_SITE="/etc/nginx/sites-available/bindplane-repo"
NGINX_LINK="/etc/nginx/sites-enabled/bindplane-repo"
NGINX_ACCESS_LOG="/var/log/nginx/bindplane-repo.access.log"
NGINX_ERROR_LOG="/var/log/nginx/bindplane-repo.error.log"

OPAMP_PORT=3001
OTLP_PORT=4317
REPO_PORT=8080
STATS_PORT=8404
STATS_URL="http://127.0.0.1:${STATS_PORT}/stats;csv"

# Build steps in execution order ------------------------------------------------
STEPS=(preflight dmz_path apt_source os_packages mirror nginx haproxy_config
       haproxy_limits host_firewall haproxy_start probe_chain collector_install
       collector_config collector_verify evidence)
declare -A STEP_TITLE=(
  [preflight]="Pre-flight checks"
  [dmz_path]="Path to the DMZ gateway (repository and relay)"
  [apt_source]="Point apt at the DMZ repository only"
  [os_packages]="Install nginx, HAProxy and wget from the DMZ repository"
  [mirror]="Mirror the DMZ repository into $REPO_ROOT"
  [nginx]="Serve the mirror to the LIVE segment on :$REPO_PORT"
  [haproxy_config]="HAProxy hop 2 configuration"
  [haproxy_limits]="HAProxy file-descriptor limits"
  [host_firewall]="Host firewall (ufw)"
  [haproxy_start]="Start HAProxy and check the path to hop 1"
  [probe_chain]="Validate the chain: probe through both hops"
  [collector_install]="Install the collector from the mirror"
  [collector_config]="Write manager.yaml and start the collector"
  [collector_verify]="Verify the LIVE collector is connected"
  [evidence]="Socket census, evidence pack, log-source hand-off"
)
declare -A STEP_REF=(
  [preflight]="Pre-flight, isolated hosts"  [dmz_path]="§5.1"
  [apt_source]="§5.2, §5.4"                 [os_packages]="§5.2, §5.5"
  [mirror]="§6.1"                           [nginx]="§6.2"
  [haproxy_config]="§6.3, §3.1"             [haproxy_limits]="§6.3, §3.5"
  [host_firewall]="§5.6 (Ubuntu equivalent)" [haproxy_start]="§6.3"
  [probe_chain]="§6.3"                      [collector_install]="§6.4"
  [collector_config]="§6.4"                 [collector_verify]="§6.5"
  [evidence]="§12.1, §12.4, Stage 8"
)

# Saved answers (persisted in $CONF_FILE). The secret key is deliberately NOT
# saved here: it lives only in manager.yaml (0600), and is asked for when needed.
CONF_KEYS=(SITE LIVE_GW_IP DMZ_GW_IP BP_VERSION PKG_SOURCE REPO_SIGNED REPO_KEYRING
           AGENT_NAME AGENT_LABELS FW_SOURCES FW_PORTS HAPROXY_MAXCONN MIRROR_TIMER
           PAUSE_BETWEEN_STEPS PROXY_DEBUG)

init_defaults() {
  SITE="" LIVE_GW_IP="" DMZ_GW_IP="" BP_VERSION="" PKG_SOURCE="" REPO_SIGNED=""
  REPO_KEYRING="" AGENT_NAME="" AGENT_LABELS="" FW_SOURCES="" FW_PORTS=""
  HAPROXY_MAXCONN="" MIRROR_TIMER="" PAUSE_BETWEEN_STEPS="" PROXY_DEBUG="no"
}

# Runtime globals -------------------------------------------------------------------
ACTION="build"; ACTION_ARG=""; FROM_STEP=""; ONLY_STEP=""
ASSUME_YES=0; RECONFIGURE=0; FORCE_PAUSE=0; USE_COLOR=1; FORCE_ALL=0; ADHOC=0
CURRENT_STEP=""; POLICY_RC_CREATED=0; REPLACE_CONFIRMED=0
FAIL_WHAT=""; FAIL_WHY=""; FAIL_FIX=""; LAST_OUT=""
RUN_TS=$(date +%Y%m%d-%H%M%S)
LOG_FILE=""; RUN_TMP=""; TTY=""; TTY_OUT=0
ENV_SECRET=${BP_SECRET:-}; BP_SECRET=""; SECRET_SOURCE=""
DMZ_INFO=""; DMZ_VERSIONS=""; DMZ_V2_VERSIONS=""
APT_OPTS=()

# =============================================================================
#  Output, logging and prompts   (shared with bp-dmz-setup.sh)
# =============================================================================
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
# ask_yn_var VAR "question" fallback-default(yes|no) ; stores yes/no
ask_yn_var() {
  local __var=$1 prompt=$2 fallback=$3 cur def
  cur=${!__var-}; cur=${cur:-$fallback}
  [[ $cur == yes ]] && def=y || def=n
  if ask_yn "$prompt" "$def"; then printf -v "$__var" yes; else printf -v "$__var" no; fi
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

# --- validators: print a message and return 1 when invalid ---------------------
# --- validators: print a message and return 1 when invalid ---------------------
is_ipv4() {
  local ip=$1 o
  [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
}
local_ipv4s() { ip -o -4 addr show 2>/dev/null | awk '{split($4,a,"/"); print a[1]}'; }
is_local_ip() { local_ipv4s | grep -qxF "$1"; }
iface_of_ip() { ip -o -4 addr show 2>/dev/null | awk -v ip="$1" '{split($4,a,"/"); if (a[1]==ip) {print $2; exit}}'; }
default_iface() { ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'; }
v_site()   { [[ $1 == primary || $1 == dr ]] || { echo "Enter 'primary' or 'dr'."; return 1; }; }
v_version(){ [[ $1 =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.]+)?$ ]] || { echo "'$1' is not a release tag. Use the form v1.108.1"; return 1; }; }
v_ipv4()   { is_ipv4 "$1" || { echo "'$1' is not a valid IPv4 address."; return 1; }; }
v_local_ip(){
  is_ipv4 "$1" || { echo "'$1' is not a valid IPv4 address."; return 1; }
  is_local_ip "$1" || { echo "$1 is not assigned to any interface on this host (HAProxy/nginx could not bind to it). Local addresses: $(local_ipv4s | tr '\n' ' ')"; return 1; }
}
v_remote_ip(){
  is_ipv4 "$1" || { echo "'$1' is not a valid IPv4 address."; return 1; }
  is_local_ip "$1" && { echo "$1 belongs to THIS host - enter the LIVE gateway's address."; return 1; }
  return 0
}
v_sources(){
  local s
  [[ -n $1 ]] || { echo "Enter at least one IP or CIDR."; return 1; }
  for s in $1; do
    if [[ $s == */* ]]; then
      is_ipv4 "${s%/*}" && [[ ${s#*/} =~ ^[0-9]{1,2}$ ]] && (( ${s#*/} <= 32 )) || { echo "'$s' is not a valid IPv4 CIDR."; return 1; }
      if [[ ${s#*/} == 0 ]]; then echo "'$s' would allow the whole internet - use specific sources."; return 1; fi
    else is_ipv4 "$s" || { echo "'$s' is not a valid IPv4 address."; return 1; }; fi
  done
  return 0
}
v_ports()  { local p; [[ -n $1 ]] || { echo "Enter at least one port."; return 1; }; for p in $1; do [[ $p =~ ^[0-9]+$ ]] && (( p>0 && p<65536 )) || { echo "'$p' is not a TCP port."; return 1; }; done; return 0; }
v_maxconn(){ [[ $1 =~ ^[0-9]+$ ]] && (( $1 >= 100 && $1 <= 1000000 )) || { echo "Enter a number between 100 and 1000000."; return 1; }; }
v_step()   { contains_word "${STEPS[*]}" "$1" || { echo "Unknown step '$1'. Steps: ${STEPS[*]}"; return 1; }; }
v_labels() { [[ $1 =~ ^[A-Za-z0-9_.-]+=[A-Za-z0-9_.-]+(,[A-Za-z0-9_.-]+=[A-Za-z0-9_.-]+)*$ ]] || { echo "Use key=value pairs separated by commas, e.g. site=primary,segment=prod-live,role=gateway"; return 1; }; }
v_agent_name() { [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$ ]] || { echo "Letters, digits, '.', '_' or '-' only (max 63)."; return 1; }; }
v_pkg_source() { [[ $1 == dmz || $1 == system ]] || { echo "Enter 'dmz' or 'system'."; return 1; }; }
v_keyring() {
  [[ -n $1 ]] || { echo "Enter the path of the repository keyring."; return 1; }
  [[ -s $1 ]] || { echo "$1 does not exist yet. Copy bindplane-repo-keyring.gpg from the DMZ host (/var/lib/bp-dmz-setup/) here through your configuration-management channel (§5.4), then answer again."; return 1; }
}

# =============================================================================
#  Config and progress state   (shared)
# =============================================================================
save_config() {
  local tmp k
  tmp=$(mktemp "$STATE_DIR/.conf.XXXXXX") || return 1
  {
    echo "# $SCRIPT_NAME configuration - written $(date -Is)"
    echo "# Contains the Bindplane secret key: keep owned by root, mode 0600."
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
#  Command runners   (shared)
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
# --- policy-rc.d: stop packages auto-starting services on wildcard addresses -----
block_service_autostart() {
  if [[ ! -e /usr/sbin/policy-rc.d ]]; then
    printf '#!/bin/sh\n# temporary file created by %s - safe to delete\nexit 101\n' "$SCRIPT_NAME" >/usr/sbin/policy-rc.d
    chmod 755 /usr/sbin/policy-rc.d; POLICY_RC_CREATED=1
  fi
}
unblock_service_autostart() {
  if (( POLICY_RC_CREATED )) || grep -qs "created by $SCRIPT_NAME" /usr/sbin/policy-rc.d; then
    rm -f /usr/sbin/policy-rc.d; POLICY_RC_CREATED=0
  fi
}

# --- apt restricted to the DMZ repository (§5.2) --------------------------------
# Only $APT_LIST is consulted, so apt never reaches for the unreachable Ubuntu
# mirrors (that is what hangs on an isolated host). Any proxy configured for apt
# is bypassed for the DMZ address.
apt_set_opts() {
  APT_OPTS=(-q -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold
            -o Acquire::Retries=2 -o Acquire::http::Timeout=30)
  if [[ ${PKG_SOURCE:-dmz} == dmz ]]; then
    APT_OPTS+=(-o "Dir::Etc::sourcelist=$APT_LIST" -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0
               -o "Acquire::http::Proxy::$DMZ_GW_IP=DIRECT")
  fi
}
apt_get() {
  local desc=$1; shift
  apt_set_opts
  run_stream "$desc" apt-get "${APT_OPTS[@]}" "$@" && return 0
  explain_apt_failure "$LAST_OUT"
  return 1
}

explain_apt_failure() {
  local f=$1 dmz="${DMZ_GW_IP:-the DMZ gateway}"
  if grep -qE 'NO_PUBKEY|signatures couldn.t be verified|is not signed' "$f"; then
    fail "apt rejected the DMZ repository signature." \
         "The keyring $REPO_KEYRING does not hold the key that signed the DMZ repository (or the repository was re-signed with a new key)." \
         "Copy /var/lib/bp-dmz-setup/bindplane-repo-keyring.gpg from the DMZ host to $REPO_KEYRING again (configuration-management channel, §5.4), then retry."
  elif grep -qE 'is not valid yet|Release file .* is expired' "$f"; then
    fail "apt says the repository Release file is not valid yet / expired." \
         "This host's clock disagrees with the DMZ host's clock (the Release file is dated by the DMZ host)." \
         "Fix time sync on both hosts: timedatectl status ; chronyc tracking. Then retry."
  elif grep -qE 'does not have a Release file' "$f" && [[ ${REPO_SIGNED:-no} == yes ]]; then
    fail "The DMZ repository is not signed, but this host was told to expect a signed repository." \
         "REPO_SIGNED=yes, yet $dmz serves no InRelease/Release.gpg." "Re-run with --reconfigure and answer 'no' to the signed-repository question, or sign the repository on the DMZ host."
  elif grep -qE "Could not connect to $dmz|Connection timed out|Unable to connect|Connection failed|No route to host" "$f"; then
    fail "apt could not reach the DMZ repository on $dmz:$REPO_PORT." \
         "The Fortigate rule this host -> $dmz tcp/$REPO_PORT is missing, or nginx on the DMZ host is down (§5.1)." \
         "Test: curl -s --max-time 5 http://$dmz:$REPO_PORT/ | head ; on the DMZ host: bp-dmz-setup.sh --diagnose"
  elif grep -qE '(post|pre)-(installation|removal) script subprocess returned error' "$f"; then
    fail "A package's own install script failed: $(grep -m1 -oE '(processing package|installing) [^ ]+' "$f" | head -n1)." \
         "The lines just before 'returned error exit status' name the cause: $(grep -B3 -m1 'script subprocess returned error' "$f" | grep -vE 'dpkg: error|returned error' | tail -n2 | tr '\n' ' ')" \
         "Fix that cause, then choose [r]: the half-installed package is configured again (dpkg --configure)."
  elif grep -qE 'Could not get lock|Unable to acquire the dpkg frontend lock|is another process using it' "$f"; then
    fail "Another apt/dpkg process held the package lock for more than 5 minutes." \
         "unattended-upgrades (which cannot reach the mirrors on this host and may hang) or another admin session." \
         "See what is running: ps -ef | grep -E 'apt|dpkg' | grep -v grep\nWait or stop it (systemctl stop unattended-upgrades apt-daily.service), then choose [r]."
  elif grep -q 'dpkg was interrupted' "$f"; then
    fail "dpkg reports an earlier interrupted installation." "A previous package installation was killed part-way." "Run: dpkg --configure -a   then choose [r] to retry."
  elif grep -qE 'Unable to locate package|has no installation candidate|no installation candidate' "$f"; then
    fail "The DMZ repository does not offer one of the requested packages." \
         "The package lists are stale (apt_source not run since the DMZ repository changed), or the DMZ repository was built without it." \
         "Run: $0 --only apt_source ; check http://$dmz:$REPO_PORT/apt/Packages for the package."
  elif grep -qE 'unmet dependencies|but it is not going to be installed|but .* is to be installed|held broken packages' "$f"; then
    fail "apt could not satisfy the dependencies from the DMZ repository." \
         "The DMZ repository was built on a different Ubuntu release than this host, or a dependency was not staged (§2.3)." \
         "Compare: curl -s http://$dmz:$REPO_PORT/VERSION-INFO  with  . /etc/os-release; echo \$VERSION_ID\nRebuild the DMZ repository on a host of the same release, or add the package with --reconfigure on the DMZ side (extra packages)."
  elif grep -qE 'Hash Sum mismatch|File has unexpected size' "$f"; then
    fail "apt downloaded a file whose checksum did not match the index." \
         "The DMZ repository was being rebuilt while this host was reading it." "Wait until the DMZ run finishes, then choose [r]: apt-get update runs again."
  elif grep -qE 'No space left on device' "$f"; then
    fail "The disk is full." "Not enough free space for the package cache." "df -h /var ; apt-get clean"
  else
    fail "apt-get failed." "First error: $(grep -m1 -E '^(E|Err):' "$f" || echo 'see the output above')" "Fix the reported problem, then choose [r] to retry."
  fi
}

# =============================================================================
#  Detection helpers
# =============================================================================
yaml_get() { # top-level key from manager.yaml
  [[ -r $MANAGER_YAML ]] || return 0
  sed -nE "s/^$1:[[:space:]]*//p" "$MANAGER_YAML" | head -n1 | sed -E "s/[[:space:]]+#.*$//; s/^[\"']//; s/[\"'][[:space:]]*$//"
}
collector_version() {
  local v=""
  [[ -x $COLLECTOR_BIN ]] && v=$("$COLLECTOR_BIN" --version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
  if [[ -z $v ]]; then
    v=$(dpkg-query -W -f='${Version}' "$COLLECTOR_SVC" 2>/dev/null | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+')
    [[ -n $v ]] && v="v$v"
  fi
  printf '%s' "$v"
}
collector_unit_env() { systemctl show "$COLLECTOR_SVC" -p Environment --value 2>/dev/null; }
os_field() { ( . /etc/os-release 2>/dev/null; eval "printf '%s' \"\${$1:-}\"" ); }

collector_installed_version() { # v1.2.3 from dpkg, or empty
  local v; v=$(dpkg-query -W -f='${Status}|${Version}' "$COLLECTOR_PKG" 2>/dev/null)
  [[ $v == *"ok installed|"* ]] && printf 'v%s' "${v##*|}"
}
# owner of the collector home, e.g. bdot:bdot (v1.108+) or observiq-otel-collector:... (older)
collector_owner() { stat -c '%U:%G' "$COLLECTOR_HOME" 2>/dev/null || echo root:root; }
collector_log_errors() { # last N error lines since line $1 (default: last 200 lines)
  [[ -r $COLLECTOR_LOG ]] || return 0
  local from=${1:-0} n=${2:-5}
  if (( from > 0 )); then tail -n +"$((from+1))" "$COLLECTOR_LOG"; else tail -n 200 "$COLLECTOR_LOG"; fi 2>/dev/null \
    | grep -iE '"level":"error"|error|refused|denied|unauthor|forbidden|bad handshake' | grep -vE "$BENIGN_LOG_RE" \
    | sed -E 's/"resource":\{[^}]*\},?//; s/"stacktrace":"[^"]*"//' | tail -n "$n" | cut -c1-230
}
local_release() { printf 'ubuntu-%s-%s-%s' "$(os_field VERSION_ID)" "$(os_field VERSION_CODENAME)" "$(dpkg --print-architecture)"; }

# --- the DMZ gateway ---------------------------------------------------------------
dmz_url() { printf 'http://%s:%s%s' "$DMZ_GW_IP" "$REPO_PORT" "${1:-/}"; }
dmz_get() { lcurl -fsS --max-time 15 "$(dmz_url "$1")" 2>/dev/null; }
dmz_code() { lcurl -s -o /dev/null -w '%{http_code}' --max-time 15 "$(dmz_url "$1")" 2>/dev/null; }
info_field() { sed -n "s/^$1=//p" <<<"$DMZ_INFO" | head -n1; }
fetch_dmz_info() {
  local idx
  DMZ_INFO=$(dmz_get /VERSION-INFO); idx=$(dmz_get /packages/)
  # v1.x observiq-otel-collector: what this script installs. v2.x bindplane-otel-collector: listed, never installed.
  DMZ_VERSIONS=$(grep -oE "observiq-otel-collector_v[0-9][^\"<>_/]*_linux_$(dpkg --print-architecture)\.deb" <<<"$idx" \
                 | sed -E 's/^observiq-otel-collector_//; s/_linux_.*$//' | sort -uV | paste -sd' ')
  DMZ_V2_VERSIONS=$(grep -oE "bindplane-otel-collector_v[0-9][^\"<>_/]*_linux_$(dpkg --print-architecture)\.deb" <<<"$idx" \
                 | sed -E 's/^bindplane-otel-collector_//; s/_linux_.*$//' | sort -uV | paste -sd' ')
}
# v_live_version VERSION - a v1.x release tag (the v2 package is a different product layout)
v_live_version() {
  local x=$1
  v_version "$x" || return 1
  [[ $x == v* ]] || x="v$x"
  if [[ $x =~ ^v([2-9]|[1-9][0-9]+)\. ]] || contains_word "${DMZ_V2_VERSIONS:-}" "$x" || [[ -f $REPO_ROOT/packages/bindplane-otel-collector_${x}_linux_$(dpkg --print-architecture).deb ]]; then
    echo "$x is the v2 package 'bindplane-otel-collector' (OpAMP supervisor, supervisor.yaml, /opt/bindplane-otel-collector)."
    echo "  This script installs and configures the v1 observiq-otel-collector (manager.yaml, runbook §6.4/§6.5); installing"
    echo "  v2 next to it would run two collectors. Moving to v2 is a separate migration. v1 versions available: ${DMZ_VERSIONS:-$(mirror_versions)}"
    return 1
  fi
  return 0
}
dmz_newest_version() { tr ' ' '\n' <<<"$DMZ_VERSIONS" | grep . | sort -V | tail -n1; }
mirror_versions() {
  find "$REPO_ROOT/packages" -maxdepth 1 -name "observiq-otel-collector_v*_linux_$(dpkg --print-architecture).deb" -printf '%f\n' 2>/dev/null \
    | sed -E 's/^observiq-otel-collector_//; s/_linux_.*$//' | sort -V | paste -sd' '
}

# tcp_state HOST PORT -> open | refused | timeout | unreachable | error
tcp_state() {
  local out rc
  out=$(timeout 6 bash -c "exec 3<>/dev/tcp/$1/$2" 2>&1 9>&-); rc=$?
  if (( rc == 0 )); then echo open
  elif (( rc == 124 )); then echo timeout
  elif [[ $out == *refused* ]]; then echo refused
  elif [[ $out == *"No route"* || $out == *nreachable* ]]; then echo unreachable
  else echo error; fi
}
route_src() { ip -o route get "$1" 2>/dev/null | grep -oE 'src [0-9.]+' | awk '{print $2}'; }
route_dev() { ip -o route get "$1" 2>/dev/null | grep -oE 'dev [^ ]+' | awk '{print $2}'; }

# explain_tcp HOST PORT STATE PURPOSE -> prints a [FAIL] line + hints; returns 1 unless open
explain_tcp() {
  local h=$1 p=$2 st=$3 what=$4 src
  src=$(route_src "$h")
  case $st in
    open) ok "TCP $h:$p reachable ($what)"; return 0 ;;
    timeout) err "TCP $h:$p timed out ($what)"
             hint "The Fortigate is silently dropping ${src:-this host} -> $h tcp/$p: the rule is missing or not yet installed. Raise it with the network team." ;;
    refused) err "TCP $h:$p refused ($what)"
             hint "The DMZ host answered but nothing listens on $h:$p: the service there is stopped or bound to another address. On the DMZ host: bp-dmz-setup.sh --diagnose" ;;
    unreachable) err "TCP $h:$p unreachable ($what)"
             hint "No route from this host to $h: wrong address, or a routing problem (ip route get $h)." ;;
    *) err "TCP $h:$p could not be tested ($what)"; hint "Try: timeout 5 bash -c '</dev/tcp/$h/$p' && echo open" ;;
  esac
  return 1
}

# =============================================================================
#  Checks shared by pre-flight and --diagnose (print their own result lines)
# =============================================================================
c_ok()   { ok "$@"; }
c_warn() { warn "$@"; CHK_WARNS=$((CHK_WARNS+1)); }
c_fail() { err "$@"; CHK_FAILS=$((CHK_FAILS+1)); }
check_os() {
  local id ver code
  id=$(. /etc/os-release 2>/dev/null; echo "${ID:-unknown}")
  ver=$(. /etc/os-release 2>/dev/null; echo "${VERSION_ID:-?}")
  code=$(. /etc/os-release 2>/dev/null; echo "${VERSION_CODENAME:-?}")
  if [[ $id == ubuntu ]]; then
    case $ver in 20.04|22.04|24.04) c_ok "OS: Ubuntu $ver ($code)";;
      *) c_warn "OS: Ubuntu $ver - this script was written for 20.04/22.04/24.04 LTS";; esac
  else
    c_warn "OS: $id $ver - this script targets Ubuntu; commands may differ"
  fi
}
check_time() {
  local sync
  sync=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
  case $sync in
    yes) c_ok "System clock is NTP-synchronised" ;;
    no)  c_warn "System clock is NOT NTP-synchronised - TLS and OpAMP both fail on clock skew"; hint "timedatectl status ; check chrony/systemd-timesyncd" ;;
    *)   c_warn "Could not read clock sync state (timedatectl)" ;;
  esac
}
# check_port_free PORT OWNER  - free, or already used only by OWNER (re-run)
check_port_free() {
  local port=$1 owner=$2 lines procs
  lines=$(ss -H -lntp "sport = :$port" 2>/dev/null)
  if [[ -z $lines ]]; then c_ok "TCP $port is free"; return 0; fi
  procs=$(grep -oE 'users:\(\("[^"]+"' <<<"$lines" | cut -d'"' -f2 | sort -u | tr '\n' ' ')
  if [[ $(trim "$procs") == "$owner" ]]; then c_ok "TCP $port is in use by $owner (from a previous run)"; return 0; fi
  c_fail "TCP $port is already in use by: ${procs:-unknown process}"
  hint "$(awk '{print $4}' <<<"$lines" | tr '\n' ' ') - stop that service or move it; the runbook ports are fixed."
  return 1
}
check_ip_forward() {
  if [[ $(sysctl -n net.ipv4.ip_forward 2>/dev/null) == 1 ]]; then
    c_warn "net.ipv4.ip_forward=1 - a gateway proxy host should not route packets between segments"
    hint "If nothing else needs it: sysctl -w net.ipv4.ip_forward=0 (and persist in /etc/sysctl.d)"
  else c_ok "IP forwarding is disabled"; fi
}
CHK_FAILS=0; CHK_WARNS=0

# check_bind_free IP PORT OWNER - only a listener on IP:PORT or a wildcard conflicts
check_bind_free() {
  local ip=$1 port=$2 owner=$3 lines procs
  lines=$(ss -H -lntp "sport = :$port" 2>/dev/null | awk -v a="$ip:$port" -v p=":$port" '$4==a || $4=="0.0.0.0"p || $4=="*"p || $4=="[::]"p')
  if [[ -z $lines ]]; then c_ok "$ip:$port is free"; return 0; fi
  procs=$(grep -oE 'users:\(\("[^"]+"' <<<"$lines" | cut -d'"' -f2 | sort -u | tr '\n' ' ')
  if [[ $(trim "$procs") == "$owner" ]]; then c_ok "$ip:$port is in use by $owner (from a previous run)"; return 0; fi
  c_fail "$ip:$port is already in use by: ${procs:-unknown process} ($(awk '{print $4}' <<<"$lines" | tr '\n' ' '))"
  hint "Stop or move that service - the runbook ports are fixed."
  return 1
}

check_space() { # PATH MIN_GB LABEL
  local path=$1 min=$2 label=$3 avail fs
  while [[ ! -e $path ]]; do path=$(dirname "$path"); done
  avail=$(( $(df -Pk "$path" | awk 'NR==2{print $4}') * 1024 ))
  fs=$(df -P "$path" | awk 'NR==2{print $6}')
  if (( avail < min * 1024 * 1024 * 1024 / 4 )); then c_fail "Only $(human $avail) free for $label (filesystem $fs) - need ~${min} GB"; return 1
  elif (( avail < min * 1024 * 1024 * 1024 )); then c_warn "$(human $avail) free for $label (filesystem $fs) - ~${min} GB recommended"
  else c_ok "$(human $avail) free for $label (filesystem $fs)"; fi
}

check_collector_live() {
  local v ep aid st
  v=$(collector_installed_version)
  if [[ -z $v ]]; then c_ok "No collector installed yet (it is installed from the mirror in step collector_install)"; return 0; fi
  st=$(systemctl is-active "$COLLECTOR_SVC" 2>/dev/null)
  ep=$(yaml_get endpoint); aid=$(yaml_get agent_id)
  c_ok "Collector $v installed (service: ${st:-unknown}, runtime owner $(collector_owner))"
  if [[ -n $ep ]]; then
    if [[ -n $DMZ_GW_IP && $ep != "ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp" ]]; then c_warn "manager.yaml endpoint is $ep - it will be set to ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp"
    else c_ok "manager.yaml endpoint: $ep"; fi
  fi
  [[ -n $aid ]] && c_ok "Existing agent_id $aid will be kept (no duplicate agent in the console)"
  return 0
}

# =============================================================================
#  HAProxy / nginx helpers
# =============================================================================
# Hop 2 (§6.3): rewrites nothing, terminates nothing; the backend is an IP
# literal so there is no resolvers section on a segment with no DNS.
render_haproxy_cfg() {
  local user_lines="" debug_lines=""
  if id haproxy >/dev/null 2>&1; then
    user_lines=$'    # drop root after binding (hardening; not in the lab config)\n    user  haproxy\n    group haproxy'
  fi
  if [[ ${PROXY_DEBUG:-no} == yes ]]; then
    debug_lines=$'    # TEMPORARY troubleshooting capture - remove before handover (--proxy-debug off)\n    capture request header Host len 64\n    capture request header Upgrade len 16\n    capture request header Authorization len 12'
  fi
  cat <<EOF
# -----------------------------------------------------------------------------
# Managed by $SCRIPT_NAME v$SCRIPT_VERSION - runbook §6.3 (OpAMP relay hop 2)
# Generated $(date -Is) on $(hostname -s)
# Hop 2 rewrites nothing: the Host rewrite happens once, at hop 1 on the DMZ host.
# NOTE: HAProxy has no backslash line continuation - keep each 'server' on ONE line.
# -----------------------------------------------------------------------------
global
    log stdout format raw local0 info
    maxconn ${HAPROXY_MAXCONN}
${user_lines}

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    option  http-keep-alive
    timeout connect 10s
    timeout client  60s
    timeout server  60s
    timeout tunnel  24h
    timeout client-fin 30s

frontend opamp_in
    bind ${LIVE_GW_IP}:${OPAMP_PORT}
    option forwardfor
${debug_lines}
    default_backend hop1_dmz

backend hop1_dmz
    server dmz ${DMZ_GW_IP}:${OPAMP_PORT} check

frontend stats_in
    bind 127.0.0.1:${STATS_PORT}
    stats enable
    stats uri /stats
    stats refresh 10s
EOF
}

render_nginx_site() {
  cat <<EOF
# Managed by $SCRIPT_NAME v$SCRIPT_VERSION - runbook §6.2 (mirror served to the LIVE segment)
# Bound to the LIVE-facing address only: this host also faces the Fortigate, and a
# repository listening there is an ingress path no firewall rule describes.
server {
    listen ${LIVE_GW_IP}:${REPO_PORT};
    server_name _;
    root ${REPO_ROOT};
    autoindex on;
    autoindex_exact_size off;
    server_tokens off;
    access_log ${NGINX_ACCESS_LOG};
    error_log  ${NGINX_ERROR_LOG};

    location / {
        limit_except GET HEAD { deny all; }
        try_files \$uri \$uri/ =404;
    }
    # text/plain so PowerShell's Invoke-WebRequest returns these as strings (§9.2 checksum check)
    location ~ ^/(SHA256SUMS|VERSION-INFO|README\.txt)\$ {
        limit_except GET HEAD { deny all; }
        default_type text/plain;
        try_files \$uri =404;
    }
    location ~ (\.part|\.tmp)\$ { return 404; }
    location ~ /\. { deny all; }
}
EOF
}

# stats_csv -> raw CSV from the local stats frontend
stats_csv() { lcurl -s --max-time 5 "$STATS_URL" 2>/dev/null; }
# stats_field PXNAME SVNAME FIELD   (field looked up by header name)
stats_field() {
  stats_csv | awk -F, -v px="$1" -v sv="$2" -v f="$3" '
    NR==1 { sub(/^# */,""); for (i=1;i<=NF;i++) idx[$i]=i; next }
    $1==px && $2==sv && (f in idx) { print $(idx[f]); exit }'
}
tunnel_census() {
  stats_csv | awk -F, 'NR==1 { sub(/^# */,""); for (i=1;i<=NF;i++) idx[$i]=i; next }
    $1!~"^#" && $1!="stats_in" { printf "      %-16s %-9s status=%-12s scur=%-5s smax=%-5s check=%s %s\n", $1,$2,$(idx["status"]),$(idx["scur"]),$(idx["smax"]),$(idx["check_status"]),$(idx["last_chk"]) }'
}
describe_term_flags() { # HAProxy termination state (first two characters)
  local f=$1 a=${1:0:1} b=${1:1:1} wa wb
  [[ $f == ---* ]] && { echo "normal termination - no proxy-side error"; return; }
  case $a in
    C) wa="client aborted";; S) wa="server aborted/refused or connection failed";; P) wa="proxy blocked/denied";;
    R) wa="resource exhausted (maxconn/memory)";; I) wa="internal error";; D) wa="server was marked DOWN";;
    L) wa="answered locally";; K) wa="killed by admin";; c) wa="client-side timeout";; s) wa="server-side timeout";;
    -) wa="no error";; *) wa="'$a'";;
  esac
  case $b in
    R) wb="while waiting for the request";; Q) wb="while queued";; C) wb="while connecting to the server";;
    H) wb="while waiting for response headers";; D) wb="during data transfer";; L) wb="during the last data";;
    T) wb="while tarpitted";; -) wb="";; *) wb="";;
  esac
  echo "$wa ${wb}"
}
# haproxy_log_since "YYYY-MM-DD HH:MM:SS" -> last opamp_in log line
haproxy_log_since() {
  local since_epoch line ts epoch found=""
  since_epoch=$(date -d "$1" +%s 2>/dev/null || echo 0)
  while IFS= read -r line; do
    # only accept lines whose own timestamp [dd/Mon/yyyy:HH:MM:SS.mmm] is not older than "since"
    if [[ $line =~ \[([0-9]{2})/([A-Za-z]{3})/([0-9]{4}):([0-9:]{8}) ]]; then
      ts="${BASH_REMATCH[1]} ${BASH_REMATCH[2]} ${BASH_REMATCH[3]} ${BASH_REMATCH[4]}"
      epoch=$(date -d "$ts" +%s 2>/dev/null || echo 0)
      (( epoch + 1 >= since_epoch )) && found=$line
    fi
  done < <(journalctl -u haproxy --since "$1" --no-pager -o cat 2>/dev/null | grep ' opamp_in ' | tail -n 20)
  printf '%s' "$found"
}
# probe_opamp URL OUTFILE  -> PROBE_RC PROBE_STATUS PROBE_VIA (§4.1)
probe_opamp() {
  local url=$1 out=$2 hfile="$RUN_TMP/probe.headers"
  # the secret goes in a 0600 header file, never on the command line (ps would show it)
  ( umask 077; printf '%s\n' 'Connection: Upgrade' 'Upgrade: websocket' 'Sec-WebSocket-Version: 13' \
      'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' "Authorization: Secret-Key ${BP_SECRET}" >"$hfile" )
  lcurl -i -sS --max-time 30 --http1.1 -H @"$hfile" "$url" >"$out" 2>&1; PROBE_RC=$?
  rm -f "$hfile"
  PROBE_STATUS=$(grep -aE '^HTTP/[0-9.]+ [0-9]{3}' "$out" | tail -n1 | awk '{print $2}')
  PROBE_VIA=$(grep -aiE '^via:' "$out" | head -n1 | tr -d '\r')
  return 0
}
# verify_listener PORT IP PROCESS - bound to IP only, never a wildcard
verify_listener() {
  local port=$1 ip=$2 proc=$3 lines i
  for i in 1 2 3 4 5 6; do lines=$(ss -H -lntp "sport = :$port" 2>/dev/null); [[ -n $lines ]] && break; sleep 1; done
  if [[ -z $lines ]]; then
    fail "Nothing is listening on TCP $port." "$proc did not start, or failed to bind." "systemctl status $proc --no-pager ; journalctl -u $proc -n 30 --no-pager"; return 1
  fi
  log "ss: $lines"
  if grep -qE "[[:space:]](\*|0\.0\.0\.0|\[::\]|\[::ffff:0\.0\.0\.0\]):${port}[[:space:]]" <<<" $lines "; then
    fail "TCP $port is bound to ALL interfaces." \
         "A wildcard bind exposes the service on the internet-facing interface (runbook §2.7 / §3.7)." \
         "Find the extra listener: grep -rnE 'listen|bind' /etc/nginx/sites-enabled /etc/nginx/conf.d $HAPROXY_CFG"; return 1
  fi
  if ! grep -qF " $ip:$port " <<<" $(awk '{print $4}' <<<"$lines" | tr '\n' ' ') "; then
    fail "TCP $port is not bound to $ip." "Listeners found: $(awk '{print $4}' <<<"$lines" | tr '\n' ' ')" "Check the configuration of $proc."; return 1
  fi
  grep -q "\"$proc" <<<"$lines" || warn "TCP $port is owned by an unexpected process: $(grep -oE 'users:\(\("[^"]+"' <<<"$lines" | cut -d'"' -f2 | sort -u | tr '\n' ' ')"
  ok "Listening on $ip:$port only (not on the internet-facing interface)"
}
apparmor_denials() { # recent AppArmor denials for haproxy/nginx
  { journalctl -k --since "-30min" --no-pager 2>/dev/null || dmesg 2>/dev/null; } | grep -i 'apparmor="DENIED"' | grep -iE 'haproxy|nginx' | tail -n 5
}

describe_check_status() { # hop 2 backend = plain TCP check to hop 1
  local s=${1#\*}; s=$(trim "$s"); s=${s%%[[:space:]]*}
  case $s in
    L4OK|L6OK|L7OK) echo "healthy" ;;
    L4TOUT) echo "TCP connect to hop 1 ($DMZ_GW_IP:$OPAMP_PORT) timed out: the Fortigate is silently dropping this host -> DMZ tcp/$OPAMP_PORT (rule missing)." ;;
    L4CON)  echo "connection to hop 1 refused/unreachable: HAProxy on the DMZ host is stopped or not bound to $DMZ_GW_IP, or a firewall is rejecting." ;;
    SOCKERR) echo "local socket error: check file-descriptor limits and journalctl -u haproxy." ;;
    "") echo "no check result yet" ;;
    *) echo "check status '$1'" ;;
  esac
}

explain_haproxy_log_line() {
  local line=$1
  [[ -n $line ]] || { warn "No HAProxy log line found for this request (journalctl -u haproxy -n 20)"; return 1; }
  say "      HAProxy log: $(cut -c1-200 <<<"$line")"
  if [[ $line =~ opamp_in[[:space:]]+([^[:space:]]+)/([^[:space:]]+)[[:space:]]+([-0-9]+/[-0-9]+/[-0-9]+/[-0-9]+/[-0-9]+)[[:space:]]+([0-9]+)[[:space:]]+[0-9]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+([^[:space:]]{4}) ]]; then
    local be=${BASH_REMATCH[1]} sv=${BASH_REMATCH[2]} tm=${BASH_REMATCH[3]} st=${BASH_REMATCH[4]} fl=${BASH_REMATCH[5]}
    say "        backend/server : $be/$sv $( [[ $sv == '<NOSRV>' ]] && echo '<- HAProxy never chose a server (hop 1 marked DOWN)')"
    say "        timers Tq/Tw/Tc/Tr/Tt (ms): $tm $( [[ $tm =~ ^[-0-9]+/[-0-9]+/[0-9]+/[0-9]+/ ]] && echo '<- a real round trip through hop 1 happened')"
    say "        status : $st     termination flags: $fl ($(describe_term_flags "$fl"))"
  fi
  return 0
}

# classify_probe WHERE -> 0 pass, 1 fail (fills FAIL_*)
classify_probe() {
  local where=$1 cs st
  if [[ $PROBE_STATUS == 403 && ${PROBE_VIA,,} == *google* ]]; then
    ok "PASS ($where): 403 with '$PROBE_VIA' - the request crossed the relay chain and reached Bindplane Cloud"
    return 0
  fi
  if [[ $PROBE_STATUS == 101 ]]; then ok "PASS ($where): 101 Switching Protocols - the path works end to end"; return 0; fi
  case $PROBE_STATUS in
    404) fail "Probe via $where returned 404." "Host header or SNI wrong at hop 1, or the path is not /v1/opamp. Hop 2 rewrites nothing, so this is hop 1's configuration." \
              "On the DMZ host: grep -nE 'set-header|sni' /etc/haproxy/haproxy.cfg ; bp-dmz-setup.sh --diagnose" ;;
    503) st=$(stats_field hop1_dmz dmz status); cs=$(stats_field hop1_dmz dmz check_status)
         if [[ $where == *"$LIVE_GW_IP"* && $st != UP* ]]; then
           fail "Probe via $where returned 503 - hop 2 has no healthy hop 1." "Hop 2 backend check: ${cs:-unknown} - $(describe_check_status "$cs")" \
                "Check the Fortigate rule this host -> $DMZ_GW_IP tcp/$OPAMP_PORT and HAProxy on the DMZ host (bp-dmz-setup.sh --diagnose there)."
         else
           fail "Probe via $where returned 503 - hop 1 (DMZ) cannot reach Bindplane Cloud." "The 503 comes from hop 1: DNS, the Checkpoint rule or certificate verification on the DMZ host." \
                "On the DMZ host: bp-dmz-setup.sh --diagnose"
         fi ;;
    403) fail "Probe via $where returned 403 WITHOUT 'Via: 1.1 google'." "Something other than Bindplane's front end answered (an inspection device or block page)." "Inspect the response headers in the evidence file; check the DMZ side with bp-dmz-setup.sh --diagnose." ;;
    "")  case $PROBE_RC in
           7)  fail "Connection refused on $where." "Nothing listens there (HAProxy stopped or bound elsewhere)." "ss -lntp | grep :$OPAMP_PORT ; systemctl status haproxy" ;;
           28) fail "The probe via $where hung, then timed out." "A firewall is dropping silently rather than rejecting." "Raise with the network team (rule to $DMZ_GW_IP tcp/$OPAMP_PORT)." ;;
           52) fail "HAProxy closed the connection without a response ($where)." "Protocol problem further up the chain." "journalctl -u haproxy -n 30 --no-pager here and on the DMZ host" ;;
           *)  fail "The probe via $where failed (curl exit $PROBE_RC)." "See the output above." "journalctl -u haproxy -n 30 --no-pager" ;;
         esac ;;
    *) fail "Probe via $where returned HTTP $PROBE_STATUS." "Unexpected response from the relay chain." "Read the response headers above and the HAProxy log line; run --diagnose." ;;
  esac
  return 1
}

explain_service_start() { # SERVICE LOGFILE
  local svc=$1 f=$2
  if grep -qE 'Cannot assign requested address' "$f"; then
    fail "$svc could not bind to $LIVE_GW_IP." "That address is not (or no longer) assigned to this host." "ip -br addr ; re-run with --reconfigure to choose the correct address."
  elif grep -qE 'Address already in use' "$f"; then
    fail "$svc could not bind: the port is already in use." "Another process is listening on the same port." "ss -lntp | grep -E ':($OPAMP_PORT|$REPO_PORT|$STATS_PORT) '"
  elif grep -qE 'Cannot raise FD limit|Too many open files|setrlimit' "$f"; then
    fail "$svc could not get enough file descriptors ($(grep -m1 -oE 'limit is [0-9]+' "$f" || echo 'limit too low'))." \
         "HAProxy needs about 2 x maxconn descriptors (maxconn ${HAPROXY_MAXCONN:-?} -> ~$(( ${HAPROXY_MAXCONN:-0} * 2 + 20 ))), but the service limit is lower." \
         "Make sure the drop-in is active: systemctl daemon-reload && systemctl show haproxy -p LimitNOFILE\nOr lower maxconn: re-run with --reconfigure."
  elif [[ -n $(apparmor_denials) ]]; then
    fail "$svc was blocked by AppArmor." "$(apparmor_denials | tail -n 2)" "Review the profile: aa-status ; adjust it (aa-complain <profile> to test) rather than disabling AppArmor."
  elif grep -qE 'unable to load|cannot open|No such file' "$f"; then
    fail "$svc could not read a file it needs." "$(grep -m1 -E 'unable to load|cannot open|No such file' "$f")" "Check the path named above exists and is readable."
  else
    fail "$svc failed to start." "See the journal lines above." "systemctl status $svc --no-pager ; journalctl -u $svc -n 50 --no-pager"
  fi
}
service_restart_checked() { # SERVICE  -> restart and confirm active
  local svc=$1 f="$RUN_TMP/journal.$1"
  run "Restarting $svc" systemctl restart "$svc"
  sleep 2
  if ! systemctl is-active --quiet "$svc"; then
    journalctl -u "$svc" -n 30 --no-pager >"$f" 2>&1; log_file "$f"
    err "$svc is not running after restart. Journal:"; show_tail "$f" 15
    explain_service_start "$svc" "$f"; return 1
  fi
  ok "$svc is active"
}
ufw_active() { command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; }

# =============================================================================
#  Secret key: never saved by this script; it ends up only in manager.yaml (0600)
# =============================================================================
ensure_secret() {
  [[ -n $BP_SECRET ]] && return 0
  local existing; existing=$(yaml_get secret_key)
  if [[ -n $ENV_SECRET ]]; then
    BP_SECRET=$ENV_SECRET; SECRET_SOURCE="environment"
    info "Using the secret key from the BP_SECRET environment variable ($(mask "$BP_SECRET"))"
  elif [[ -n $existing ]] && { (( ! RECONFIGURE )) || ask_yn "Keep the secret key already in manager.yaml ($(mask "$existing"))?" y; }; then
    BP_SECRET=$existing; SECRET_SOURCE="manager.yaml"
    info "Using the secret key already in $MANAGER_YAML ($(mask "$BP_SECRET")) - to replace it run with --reconfigure"
  else
    say "  The collector needs the Bindplane secret key (console -> Agents -> Install Agents)."
    say "  It is written only to $MANAGER_YAML (mode 0600) - this script does not keep a copy."
    ask_secret BP_SECRET "Bindplane secret key" || { fail "No secret key was provided." "It is required for manager.yaml." "Re-run interactively, or set BP_SECRET in the environment for an unattended run."; return 1; }
    SECRET_SOURCE="prompt"
  fi
  log "secret key source: $SECRET_SOURCE"
  [[ $BP_SECRET =~ ^[0-9A-HJKMNP-TV-Z]{26}$ ]] || warn "The key is not a 26-character ULID - double-check it (an invalid key fails exactly like a wrong one)."
  return 0
}

# =============================================================================
#  BUILD STEPS  (each returns 0 = done, 1 = failed, 3 = skipped on purpose)
# =============================================================================
step_preflight() {
  local f="$EVIDENCE_DIR/preflight-$RUN_TS.txt" dev src others
  CHK_FAILS=0; CHK_WARNS=0
  info "Recording the host baseline to $f"
  {
    echo "# pre-flight $(date -Is) on $(hostname)"
    echo "## identity and OS"; hostnamectl 2>&1 || hostname; grep -E '^(NAME|VERSION_ID)=' /etc/os-release
    echo "## interfaces and routing"; ip -br addr; ip route show default; ip route get "$DMZ_GW_IP" 2>&1
    echo "## time"; timedatectl status 2>&1
    echo "## disk"; df -h /var /opt /srv 2>&1
    echo "## name resolution"; resolvectl status 2>/dev/null || cat /etc/resolv.conf
  } >"$f" 2>&1
  check_os
  if is_local_ip "$LIVE_GW_IP"; then c_ok "LIVE_GW_IP $LIVE_GW_IP is on interface $(iface_of_ip "$LIVE_GW_IP")"
  else c_fail "LIVE_GW_IP $LIVE_GW_IP is not assigned to this host"; hint "Re-run with --reconfigure to choose the correct address."; fi
  dev=$(route_dev "$DMZ_GW_IP"); src=$(route_src "$DMZ_GW_IP")
  if [[ -n $dev ]]; then c_ok "Route to the DMZ gateway $DMZ_GW_IP: via $dev, source address ${src:-?} (the Fortigate rules must permit this source)"
  else c_fail "No route to the DMZ gateway $DMZ_GW_IP"; hint "ip route get $DMZ_GW_IP"; fi
  check_time
  check_bind_free "$LIVE_GW_IP" "$OPAMP_PORT" haproxy
  check_bind_free "$LIVE_GW_IP" "$REPO_PORT" nginx
  check_bind_free 127.0.0.1 "$STATS_PORT" haproxy
  check_space "$REPO_ROOT" 2 "the mirror ($REPO_ROOT)"
  check_space "$COLLECTOR_HOME" 5 "the collector's persistent queue ($COLLECTOR_HOME/storage)"
  check_ip_forward
  check_collector_live
  if env | grep -qiE '^(https?|all)_proxy=' || grep -qsiE '^(https?|all)_proxy=' /etc/environment; then
    c_warn "A proxy is configured in the environment - this script bypasses it for the DMZ address (curl --noproxy, wget --no-proxy, apt DIRECT)"
  fi
  others=$(grep -rhsE '^[[:space:]]*(deb|URIs:)' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | grep -vF "$DMZ_GW_IP" | wc -l)
  (( others > 0 )) && info "$others other apt source line(s) are configured; they are unreachable from here and are ignored by this script (unattended-upgrades on this host will fail - expected)"
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

step_dmz_path() {
  local st8 st3 st4 code idx bad=0 built mine
  info "Testing the Fortigate path from $(route_src "$DMZ_GW_IP") to the DMZ gateway $DMZ_GW_IP (§5.1 - if this fails, nothing else in Stage 5 works)"
  st8=$(tcp_state "$DMZ_GW_IP" "$REPO_PORT"); explain_tcp "$DMZ_GW_IP" "$REPO_PORT" "$st8" "package repository" || bad=1
  st3=$(tcp_state "$DMZ_GW_IP" "$OPAMP_PORT"); explain_tcp "$DMZ_GW_IP" "$OPAMP_PORT" "$st3" "OpAMP relay hop 1" || bad=1
  st4=$(tcp_state "$DMZ_GW_IP" "$OTLP_PORT")
  case $st4 in
    open) ok "TCP $DMZ_GW_IP:$OTLP_PORT reachable (OTLP - used once the Stage 11 configuration is pushed)" ;;
    refused) info "TCP $DMZ_GW_IP:$OTLP_PORT refused - normal until the DMZ gateway configuration (Stage 11) opens the Bindplane Gateway source; the Fortigate path itself is open" ;;
    *) warn "TCP $DMZ_GW_IP:$OTLP_PORT $st4 - telemetry to the DMZ gateway (Stage 11) will need the Fortigate rule this host -> $DMZ_GW_IP tcp/$OTLP_PORT" ;;
  esac
  if (( bad )); then
    fail "The DMZ gateway is not reachable on the required ports." \
         "timeout = the Fortigate drops the traffic (rule missing); refused = the DMZ service is down or bound elsewhere; unreachable = routing/address." \
         "Rules needed: $(route_src "$DMZ_GW_IP") -> $DMZ_GW_IP tcp/$REPO_PORT and tcp/$OPAMP_PORT (tcp/$OTLP_PORT for Stage 11).\nOn the DMZ host: bp-dmz-setup.sh --status (gates §4.2/§4.4 must have passed)."
    return 1
  fi
  code=$(dmz_code /)
  [[ $code == 200 ]] || { fail "The DMZ repository index returned HTTP ${code:-nothing}." "Port $REPO_PORT answers but nginx on the DMZ host is not serving /srv/bindplane." "On the DMZ host: bp-dmz-setup.sh --only nginx"; return 1; }
  idx=$(dmz_get / | grep -oE 'href="[^"]+/"' | sed -E 's/href="//; s/"//' | tr '\n' ' ')
  ok "Repository index answers 200: $idx"
  [[ $(dmz_code /SHA256SUMS) == 200 ]] || { fail "The DMZ repository has no SHA256SUMS." "Stage 2.4 was not completed on the DMZ host." "On the DMZ host: bp-dmz-setup.sh --only checksums"; return 1; }
  ok "SHA256SUMS present ($(dmz_get /SHA256SUMS | wc -l) files)"
  fetch_dmz_info
  if [[ -n $DMZ_INFO ]]; then
    ok "DMZ repository: current collector $(info_field current_collector_version), staged ${DMZ_VERSIONS:-?}"
    built=$(info_field apt_repo_built_for); mine=$(local_release)
    if [[ $PKG_SOURCE == dmz ]]; then
      if [[ $built == ubuntu-* && $built != "$mine" ]]; then
        fail "The DMZ apt repository was built for $built, but this host is $mine." \
             "Packages from another Ubuntu release will not satisfy this host's dependencies (§2.3: build on the same major release)." \
             "Build the repository on a DMZ-side host of the same release, or use CBSL's internal mirror (--reconfigure, package source 'system')."
        return 1
      elif [[ $built != ubuntu-* ]]; then
        fail "The DMZ host did not build an apt repository ($built)." "nginx/HAProxy for this host must then come from CBSL's internal Ubuntu mirror." \
             "Re-run with --reconfigure and choose package source 'system', or build the apt repository on the DMZ host."
        return 1
      fi
      ok "apt repository built for $built - matches this host"
    fi
  else
    warn "No VERSION-INFO on the DMZ repository (built without bp-dmz-setup.sh?) - Ubuntu release compatibility cannot be checked automatically"
    [[ $PKG_SOURCE == dmz && $(dmz_code /apt/Packages) != 200 ]] && { fail "The DMZ repository has no apt/Packages index." "The OS-package repository (§2.3) was not built." "Build it on the DMZ host, or use package source 'system' (--reconfigure)."; return 1; }
  fi
  if [[ -n $BP_VERSION && " $DMZ_VERSIONS " != *" $BP_VERSION "* && -n $DMZ_VERSIONS ]]; then
    fail "Collector $BP_VERSION is not staged on the DMZ repository (available: $DMZ_VERSIONS)." "BP_VERSION must be a version the DMZ host has downloaded." \
         "Re-run with --reconfigure and pick one of: $DMZ_VERSIONS - or stage it on the DMZ host: bp-dmz-update-repo.sh --versions $BP_VERSION"
    return 1
  fi
  ok "Path to the DMZ gateway is good"
}

step_apt_source() {
  local line out
  if [[ $PKG_SOURCE == system ]]; then
    info "Package source: the system's own apt sources (CBSL internal mirror) - no DMZ repository entry is written"
    apt_get "Refreshing package lists (apt-get update)" update || return 1
    return 0
  fi
  if [[ $REPO_SIGNED == yes ]]; then
    [[ -s $REPO_KEYRING ]] || { fail "Keyring $REPO_KEYRING is missing." "The signed repository needs the DMZ host's public key here (§5.4)." "Copy /var/lib/bp-dmz-setup/bindplane-repo-keyring.gpg from the DMZ host to $REPO_KEYRING via configuration management, then retry."; return 1; }
    # apt accepts an ASCII-armoured key only when the file name ends in .asc
    if [[ $REPO_KEYRING != *.asc ]] && head -c 40 "$REPO_KEYRING" | grep -q 'BEGIN PGP'; then
      command -v gpg >/dev/null || { fail "$REPO_KEYRING is ASCII-armoured but not named *.asc, and gpg is not installed to convert it." "" "Rename it to bindplane-repo.asc (and --reconfigure), or provide the binary keyring bindplane-repo-keyring.gpg."; return 1; }
      gpg --dearmor <"$REPO_KEYRING" >"$REPO_KEYRING.tmp" && mv -f "$REPO_KEYRING.tmp" "$REPO_KEYRING" \
        || { fail "Could not convert the armoured key $REPO_KEYRING." "" "Provide the binary keyring bindplane-repo-keyring.gpg from the DMZ host."; return 1; }
      info "Converted the ASCII-armoured key in $REPO_KEYRING to the binary format apt expects"
    fi
    chmod 644 "$REPO_KEYRING"
    line="deb [signed-by=$REPO_KEYRING] http://$DMZ_GW_IP:$REPO_PORT/apt ./"
  else
    line="deb [trusted=yes] http://$DMZ_GW_IP:$REPO_PORT/apt ./"
    info "Unsigned repository: [trusted=yes] is acceptable on an internal host reached over a single permitted rule (§5.2); see §5.4 if CBSL requires signing"
  fi
  if [[ -f $APT_LIST ]] && ! grep -qxF "$line" "$APT_LIST"; then cp -p "$APT_LIST" "$STATE_DIR/bindplane-local.list.bak-$RUN_TS"; info "Previous $APT_LIST saved in $STATE_DIR"; fi
  printf '# Managed by %s - runbook §5.2: the DMZ repository is the ONLY source for this host\n%s\n' "$SCRIPT_NAME" "$line" >"$APT_LIST"
  chmod 644 "$APT_LIST"
  ok "Wrote $APT_LIST: $line"
  apt_get "Refreshing the DMZ repository index (apt-get update, this source only)" update || return 1
  if grep -qE "^(Err|E|W):.*$DMZ_GW_IP" "$LAST_OUT"; then explain_apt_failure "$LAST_OUT"; return 1; fi
  apt_set_opts
  out=$(apt-cache "${APT_OPTS[@]}" policy nginx haproxy wget 2>&1)
  log "$out"
  if grep -q 'Candidate: (none)' <<<"$out"; then
    fail "The DMZ repository index does not offer nginx, haproxy and wget." "$(grep -B1 'Candidate: (none)' <<<"$out" | head -n1)" "Check http://$DMZ_GW_IP:$REPO_PORT/apt/Packages ; rebuild with bp-dmz-setup.sh --only os_repo on the DMZ host"
    return 1
  fi
  ok "apt sees nginx $(apt-cache "${APT_OPTS[@]}" policy nginx | awk '/Candidate:/{print $2}'), haproxy $(apt-cache "${APT_OPTS[@]}" policy haproxy | awk '/Candidate:/{print $2}') from the DMZ repository"
}

step_os_packages() {
  local -a want=(nginx haproxy wget) absent=() upgrades=()
  local p rc plan
  for p in "${want[@]}"; do dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'ok installed' || absent+=("$p"); done
  if (( ${#absent[@]} )); then
    apt_set_opts
    plan=$(apt-get "${APT_OPTS[@]}" -s install --no-install-recommends --no-upgrade "${absent[@]}" 2>&1); rc=$?
    log "$plan"
    if (( rc != 0 )); then printf '%s\n' "$plan" >"$RUN_TMP/plan.out"; explain_apt_failure "$RUN_TMP/plan.out"; show_tail "$RUN_TMP/plan.out" 12; return 1; fi
    mapfile -t upgrades < <(grep -E '^Inst [^ ]+ \[' <<<"$plan" | awk '{print $2" "$3" -> "$4}' | tr -d '[]()')
    info "To install: $(grep -cE '^Inst ' <<<"$plan") package(s) for ${absent[*]}"
    if (( ${#upgrades[@]} )); then
      warn "This also UPGRADES ${#upgrades[@]} package(s) already on this host (their newer versions are dependencies):"
      printf '         %s\n' "${upgrades[@]:0:15}"
      ask_yn "Proceed with these upgrades (change control)?" y || { fail "Stopped before upgrading existing packages." "" "Review the list above with your change board, then retry."; return 1; }
    fi
    block_service_autostart
    apt_get "Installing ${absent[*]} from the DMZ repository (services kept from auto-starting on *:80)" install -y --no-install-recommends --no-upgrade "${absent[@]}"; rc=$?
    unblock_service_autostart
    (( rc == 0 )) || return 1
  else
    ok "nginx, haproxy and wget are already installed"
  fi
  ok "$(nginx -v 2>&1)"
  ok "$(haproxy -v 2>/dev/null | head -n1)"
  ok "$(wget --version 2>/dev/null | head -n1)"
}

write_mirror_sync() {
  cat >"$MIRROR_SYNC" <<'EOF'
#!/usr/bin/env bash
# bp-mirror-sync - pull the DMZ package origin into the local mirror and verify it
# (runbook §6.1 / §13.3). Generated by bp-live-setup - re-run it to change the origin.
# Exit codes: 0 ok | 3 disk | 4 network (Fortigate rule / DMZ nginx) | 8 HTTP error on a file | 20 checksum | 75 already running
set -uo pipefail
ORIGIN="@ORIGIN@"
ROOT="@ROOT@"
LOG="@LOG@"
sync_once() {
  echo "$(date -Is) sync from $ORIGIN into $ROOT"
  mkdir -p "$ROOT" || return 3
  wget -r -np -nH -N -nv -R 'index.html*' -e robots=off --no-proxy --tries=3 --timeout=30 --waitretry=5 -P "$ROOT" "$ORIGIN"
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "$(date -Is) ERROR: wget exit $rc (4 = network: Fortigate rule to the DMZ host or its nginx; 8 = a file returned an HTTP error; 3 = disk)"
    return "$rc"
  fi
  if ! ( cd "$ROOT" && sha256sum -c --quiet SHA256SUMS ); then
    echo "$(date -Is) ERROR: checksum verification failed - truncated transfer, or the origin changed mid-copy. Run bp-mirror-sync again (df -h $ROOT)."
    return 20
  fi
  chmod -R a+rX "$ROOT"
  echo "$(date -Is) OK: $(wc -l < "$ROOT/SHA256SUMS") files verified; $(grep -s '^current_collector_version=' "$ROOT/VERSION-INFO" || echo 'no VERSION-INFO')"
}
exec 9>/run/bp-mirror-sync.lock
flock -n 9 || { echo "bp-mirror-sync: another sync is already running" >&2; exit 75; }
sync_once 2>&1 | tee -a "$LOG"
exit "${PIPESTATUS[0]}"
EOF
  sed -i -e "s|@ORIGIN@|$(dmz_url /)|" -e "s|@ROOT@|$REPO_ROOT|" -e "s|@LOG@|$MIRROR_LOG|" "$MIRROR_SYNC"
  chmod 755 "$MIRROR_SYNC"
}

configure_sync_timer() {
  if [[ $MIRROR_TIMER == yes ]]; then
    printf '[Unit]\nDescription=Bindplane mirror sync from the DMZ origin (bp-live-setup)\nAfter=network-online.target\n[Service]\nType=oneshot\nExecStart=%s\n' "$MIRROR_SYNC" >"$SYNC_SERVICE"
    printf '[Unit]\nDescription=Daily Bindplane mirror sync (bp-live-setup)\n[Timer]\nOnCalendar=*-*-* 02:30:00\nRandomizedDelaySec=30m\nPersistent=true\n[Install]\nWantedBy=timers.target\n' >"$SYNC_TIMER"
    systemctl daemon-reload && run "Enabling the daily bp-mirror-sync timer" systemctl enable --now bp-mirror-sync.timer \
      || warn "Could not enable the timer - run: systemctl enable --now bp-mirror-sync.timer"
  elif [[ -f $SYNC_TIMER ]]; then
    systemctl disable --now bp-mirror-sync.timer >/dev/null 2>&1; rm -f "$SYNC_TIMER" "$SYNC_SERVICE"; systemctl daemon-reload
    info "Daily sync timer removed (manual syncs only)"
  fi
}

step_mirror() {
  local rc bad notfound
  install -d -m 755 "$REPO_ROOT" || { fail "Cannot create $REPO_ROOT." "Read-only or full filesystem." "findmnt -T $REPO_ROOT ; df -h $REPO_ROOT"; return 1; }
  write_mirror_sync
  info "Mirroring $(dmz_url /) into $REPO_ROOT - only new or changed files are transferred (wget -N)"
  run_stream "Mirror sync (bp-mirror-sync)" "$MIRROR_SYNC"; rc=$?
  if (( rc != 0 )); then
    notfound=$(grep -B1 -E 'ERROR [0-9]{3}' "$LAST_OUT" | grep -oE 'https?://[^ ]+' | sed 's/:$//' | sed "s#^$(dmz_url /)##" | head -n 5 | tr '\n' ' ')
    case $rc in
      4)  fail "The mirror sync could not talk to the DMZ repository (wget exit 4)." "Network failure: the Fortigate rule this host -> $DMZ_GW_IP tcp/$REPO_PORT, or nginx on the DMZ host." "curl -s --max-time 5 $(dmz_url /) | head ; then choose [r] - completed files are not fetched again." ;;
      8)  fail "Some files in the DMZ index could not be downloaded (wget exit 8): ${notfound:-see output}" \
               "The DMZ index links to names nginx cannot serve (e.g. '%3a' in .deb names from a hand-built repository), or a file was removed during the sync." \
               "On the DMZ host: bp-dmz-setup.sh --only os_repo (renames such files), then choose [r]." ;;
      3)  fail "The mirror sync could not write files (wget exit 3)." "Disk full or $REPO_ROOT not writable." "df -h $REPO_ROOT" ;;
      20) bad=$(cd "$REPO_ROOT" && sha256sum -c --quiet SHA256SUMS 2>&1 | head -n 5)
          # is the ORIGIN itself inconsistent? hash the failing file straight from the DMZ host
          local f want remote_sum origin_bad=""
          while IFS= read -r f; do
            want=$(awk -v n="$f" '$2==n {print $1; exit}' "$REPO_ROOT/SHA256SUMS")
            remote_sum=$(lcurl -fsS --max-time 120 "$(dmz_url "/$f")" 2>/dev/null | sha256sum | awk '{print $1}')
            [[ -n $want && $remote_sum != "$want" ]] && origin_bad+="$f "
          done < <(sed -n 's/: FAILED.*$//p' <<<"$bad" | head -n 3)
          if [[ -n $origin_bad ]]; then
            fail "The DMZ repository's own SHA256SUMS does not match its files: $origin_bad" \
                 "The file was changed on the DMZ host after the checksums were computed - this is not a transfer problem.\n$bad" \
                 "On the DMZ host: bp-dmz-setup.sh --only checksums   then here: choose [r]."
          else
            fail "Checksum verification of the mirror failed (§6.1: every line must read OK)." \
                 "Truncated transfer, or the DMZ repository changed while it was being copied.\n$bad" \
                 "Choose [r] to sync again; check free space (df -h $REPO_ROOT)."
          fi ;;
      75) fail "Another bp-mirror-sync is already running." "A scheduled or manual sync holds /run/bp-mirror-sync.lock." "Wait for it (tail -f $MIRROR_LOG), then choose [r]." ;;
      *)  fail "The mirror sync failed (exit $rc)." "See the output above." "Run $MIRROR_SYNC by hand to see the full error." ;;
    esac
    return 1
  fi
  ok "Mirror verified: $(wc -l <"$REPO_ROOT/SHA256SUMS") files, $(du -sh "$REPO_ROOT" | cut -f1); collector versions: $(mirror_versions)"
  compgen -G "$REPO_ROOT/packages/bindplane-otel-collector_v*" >/dev/null && \
    info "Also mirrored: v2 'bindplane-otel-collector' packages ($(find "$REPO_ROOT/packages" -maxdepth 1 -name 'bindplane-otel-collector_v*_linux_amd64.deb' -printf '%f\n' | sed -E 's/^bindplane-otel-collector_//; s/_linux_.*//' | sort -V | paste -sd' ')) - served to log sources, not installed here"
  ok "Repeatable sync installed: $MIRROR_SYNC  (log: $MIRROR_LOG)"
  configure_sync_timer
}

step_nginx() {
  local others code
  dpkg -s nginx >/dev/null 2>&1 || { fail "nginx is not installed." "The os_packages step did not complete." "$0 --only os_packages"; return 1; }
  others=$(find /etc/nginx/sites-enabled -mindepth 1 -maxdepth 1 ! -name default ! -name bindplane-repo -printf '%f ' 2>/dev/null)
  [[ -n $others ]] && warn "Other nginx sites are enabled here and will keep running: $others(make sure none listens on a wildcard address)"
  if [[ -e /etc/nginx/sites-enabled/default || -L /etc/nginx/sites-enabled/default ]]; then
    rm -f /etc/nginx/sites-enabled/default; info "Disabled the default site (it listens on *:80); it remains in sites-available"
  fi
  render_nginx_site >"$RUN_TMP/nginx.site"
  install -m 644 -o root -g root "$RUN_TMP/nginx.site" "$NGINX_SITE"
  ln -sf "$NGINX_SITE" "$NGINX_LINK"
  if ! run "Validating the nginx configuration (nginx -t)" nginx -t; then
    explain_service_start nginx "$LAST_OUT"
    [[ $FAIL_WHAT == "nginx failed to start." ]] && fail "nginx -t rejected the configuration." "$(grep -m1 -E 'emerg|error' "$LAST_OUT")" "Edit $NGINX_SITE or the file named above, then retry."
    return 1
  fi
  run "Enabling nginx at boot" systemctl enable nginx
  if systemctl is-active --quiet nginx; then
    run "Reloading nginx" systemctl reload nginx || { service_restart_checked nginx || return 1; }
  else
    service_restart_checked nginx || return 1
  fi
  verify_listener "$REPO_PORT" "$LIVE_GW_IP" nginx || return 1
  code=$(lcurl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://$LIVE_GW_IP:$REPO_PORT/")
  [[ $code == 200 ]] || { fail "The mirror index returned HTTP ${code:-no response}." "nginx is running but cannot serve $REPO_ROOT." "tail $NGINX_ERROR_LOG ; ls -ld $REPO_ROOT"; return 1; }
  lcurl -s --max-time 10 "http://$LIVE_GW_IP:$REPO_PORT/SHA256SUMS" -o "$RUN_TMP/sums.http"
  cmp -s "$RUN_TMP/sums.http" "$REPO_ROOT/SHA256SUMS" \
    || { fail "SHA256SUMS served over HTTP differs from the file on disk." "Wrong root directory or a caching layer." "grep root $NGINX_SITE"; return 1; }
  ok "Mirror served on http://$LIVE_GW_IP:$REPO_PORT/ ($(wc -l <"$REPO_ROOT/SHA256SUMS") files) - log sources install from here (Stage 8)"
}

step_haproxy_config() {
  local new="$RUN_TMP/haproxy.cfg.new" first
  command -v haproxy >/dev/null || { fail "haproxy is not installed." "The os_packages step did not complete." "$0 --only os_packages"; return 1; }
  is_local_ip "$LIVE_GW_IP" || { fail "$LIVE_GW_IP is not assigned to this host." "The address changed since configuration." "Re-run with --reconfigure."; return 1; }
  if [[ -f $HAPROXY_CFG ]] && ! grep -q "Managed by $SCRIPT_NAME" "$HAPROXY_CFG" && grep -qE '^[[:space:]]*(frontend|listen)[[:space:]]' "$HAPROXY_CFG"; then
    warn "HAProxy on this host already has a custom configuration: $(grep -E '^[[:space:]]*(frontend|listen)[[:space:]]' "$HAPROXY_CFG" | awk '{print $1" "$2}' | tr '\n' ' ')"
    hint "This step replaces $HAPROXY_CFG entirely (a backup is kept). Other services relying on it would stop working."
    if ! ask_yn "Replace the existing HAProxy configuration?" n; then
      render_haproxy_cfg >"$STATE_DIR/haproxy.cfg.hop2-candidate"
      fail "Existing HAProxy configuration left untouched." "This host's HAProxy already serves other frontends." \
           "The runbook expects a dedicated gateway. Move the other frontends, or merge $STATE_DIR/haproxy.cfg.hop2-candidate\ninto the existing file by hand, then choose [s] for this step."
      return 1
    fi
  fi
  render_haproxy_cfg >"$new"
  if ! run "Validating the new configuration before installing it (haproxy -c)" haproxy -c -f "$new"; then
    first=$(grep -m1 -F '[ALERT]' "$LAST_OUT")
    fail "haproxy -c rejected the generated configuration." "First alert: ${first:-see output}\nOnly the FIRST alert is real - later ones are the parser losing its place (§3.1)." \
         "The live configuration was NOT changed. The candidate file is $STATE_DIR/haproxy.cfg.rejected."
    cp -f "$new" "$STATE_DIR/haproxy.cfg.rejected" 2>/dev/null
    return 1
  fi
  if [[ -f $HAPROXY_CFG && ! -f $HAPROXY_CFG.orig ]]; then cp -p "$HAPROXY_CFG" "$HAPROXY_CFG.orig"; info "Saved the package default as $HAPROXY_CFG.orig"; fi
  if [[ -f $HAPROXY_CFG ]] && ! grep -q "Managed by $SCRIPT_NAME" "$HAPROXY_CFG" && ! cmp -s "$HAPROXY_CFG" "$HAPROXY_CFG.orig"; then
    cp -p "$HAPROXY_CFG" "$HAPROXY_CFG.bak-$RUN_TS"; info "Backed up the existing configuration to $HAPROXY_CFG.bak-$RUN_TS"
  fi
  install -m 644 -o root -g root "$new" "$HAPROXY_CFG"
  run "Re-validating the installed configuration" haproxy -c -f "$HAPROXY_CFG" || { fail "Installed configuration failed validation." "" "Restore with: cp $HAPROXY_CFG.orig $HAPROXY_CFG"; return 1; }
  ok "timeout tunnel 24h set here too (the shortest value in the chain wins - a correct hop 1 does not rescue hop 2)"
  ok "Hop 2 installed: $LIVE_GW_IP:$OPAMP_PORT -> hop 1 $DMZ_GW_IP:$OPAMP_PORT (no Host rewrite, no resolvers)"
}

step_haproxy_limits() {
  install -d -m 755 "$HAPROXY_DROPIN_DIR"
  printf '# Managed by %s - runbook §6.3 / §3.5\n[Service]\nLimitNOFILE=65535\n' "$SCRIPT_NAME" >"$HAPROXY_DROPIN"
  chmod 644 "$HAPROXY_DROPIN"
  run "Reloading systemd units (daemon-reload)" systemctl daemon-reload || { fail "systemctl daemon-reload failed." "" "journalctl -n 20"; return 1; }
  ok "LimitNOFILE=65535 set for haproxy (maxconn $HAPROXY_MAXCONN: keep it >= 2x the projected agent count)"
}

step_host_firewall() {
  local src port label osrc oport odst keep="$RUN_TMP/ufw.keep"
  if ufw_active && [[ -z $FW_SOURCES || $FW_SOURCES == none ]]; then
    fail "ufw is active, but no log-source subnets are configured." "ufw was inactive when the questions were asked, so no sources were recorded." \
         "Re-run with --reconfigure and enter the LIVE log-source subnets (they need tcp/${FW_PORTS// /,} to $LIVE_GW_IP)."
    return 1
  fi
  if ufw_active; then
    info "ufw is active - allowing the LIVE log sources to reach $LIVE_GW_IP (outbound to the DMZ host is allowed by ufw's default policy)"
    touch "$UFW_RECORD"; chmod 600 "$UFW_RECORD"; : >"$keep"
    while read -r osrc oport odst; do
      [[ -n $osrc ]] || continue; odst=${odst:-$LIVE_GW_IP}
      if [[ $odst == "$LIVE_GW_IP" ]] && contains_word "$FW_SOURCES" "$osrc" && contains_word "$FW_PORTS" "$oport"; then echo "$osrc $oport $odst" >>"$keep"
      else run "remove old rule $osrc -> $odst tcp/$oport" ufw delete allow proto tcp from "$osrc" to "$odst" port "$oport" || warn "Could not remove it - check: ufw status numbered"; fi
    done <"$UFW_RECORD"
    cp -f "$keep" "$UFW_RECORD"
    for src in $FW_SOURCES; do
      for port in $FW_PORTS; do
        case $port in "$OPAMP_PORT") label="bindplane opamp hop2";; "$REPO_PORT") label="bindplane package mirror";; "$OTLP_PORT") label="bindplane otlp";; *) label="bindplane";; esac
        run "allow $src -> $LIVE_GW_IP tcp/$port" ufw allow proto tcp from "$src" to "$LIVE_GW_IP" port "$port" comment "$label" \
          || { fail "ufw refused the rule for $src tcp/$port." "See the ufw output above." "ufw status verbose"; return 1; }
        grep -qxF "$src $port $LIVE_GW_IP" "$UFW_RECORD" || echo "$src $port $LIVE_GW_IP" >>"$UFW_RECORD"
      done
    done
    if ufw status verbose 2>/dev/null | grep -qE 'Default:.*deny \(outgoing\)|reject \(outgoing\)'; then
      warn "ufw denies outgoing traffic by default - also allow out to $DMZ_GW_IP tcp/$REPO_PORT,$OPAMP_PORT,$OTLP_PORT"
    fi
    ufw status numbered >"$EVIDENCE_DIR/ufw-status-$RUN_TS.txt" 2>&1
  else
    info "ufw is not active - no host-firewall changes made"
    if iptables -S INPUT 2>/dev/null | grep -q '^-P INPUT DROP' || nft list ruleset 2>/dev/null | grep -qE 'hook input .*policy drop'; then
      warn "The INPUT policy is DROP but ufw is not managing it: allow tcp/${FW_PORTS// /,} from the LIVE log sources to $LIVE_GW_IP in your firewall tooling"
    fi
  fi
  info "Perimeter rules still needed (network team):"
  say  "        Fortigate : $(route_src "$DMZ_GW_IP") -> $DMZ_GW_IP  tcp/$OPAMP_PORT (OpAMP), tcp/$REPO_PORT (packages), tcp/$OTLP_PORT (OTLP)"
  say  "        LIVE log sources -> $LIVE_GW_IP tcp/$OPAMP_PORT, tcp/$OTLP_PORT, tcp/$REPO_PORT (if they cross a segment firewall)"
  return 0
}

step_haproxy_start() {
  local i st cs lim
  run "Enabling haproxy at boot" systemctl enable haproxy
  service_restart_checked haproxy || return 1
  verify_listener "$OPAMP_PORT" "$LIVE_GW_IP" haproxy || return 1
  stats_csv | grep -q '^hop1_dmz,' && ok "Stats endpoint http://127.0.0.1:$STATS_PORT/stats is answering" \
    || { fail "The stats endpoint does not answer." "The stats_in frontend did not bind 127.0.0.1:$STATS_PORT." "ss -lntp | grep $STATS_PORT ; journalctl -u haproxy -n 20"; return 1; }
  lim=$(systemctl show haproxy -p LimitNOFILE --value 2>/dev/null)
  [[ $lim == 65535 ]] && ok "haproxy runs with LimitNOFILE=65535" || warn "haproxy LimitNOFILE is '${lim:-?}' (expected 65535) - run: systemctl daemon-reload && systemctl restart haproxy"
  info "Waiting for the health check of hop 1 ($DMZ_GW_IP:$OPAMP_PORT) ..."
  for i in $(seq 1 30); do
    st=$(stats_field hop1_dmz dmz status); cs=$(stats_field hop1_dmz dmz check_status)
    [[ $st == UP* ]] && break
    [[ $st == DOWN* && $i -ge 8 ]] && break
    sleep 1
  done
  if [[ $st == UP* ]]; then ok "Backend hop1_dmz/dmz is UP (check: ${cs:-?})"; return 0; fi
  fail "Backend hop1_dmz/dmz is ${st:-unknown} (check: ${cs:-none})." \
       "$(describe_check_status "$cs")\nHAProxy answers 503 to every log source while hop 1 is down." \
       "Re-test: $0 --only dmz_path ; on the DMZ host: bp-dmz-setup.sh --diagnose\nLast check detail: $(stats_field hop1_dmz dmz last_chk)"
  return 1
}

step_probe_chain() {
  local out="$EVIDENCE_DIR/probe-chain-$RUN_TS.txt" out1="$EVIDENCE_DIR/probe-hop1-from-live-$RUN_TS.txt" since line
  ensure_secret || return 1
  since=$(date '+%Y-%m-%d %H:%M:%S'); sleep 1
  info "Probing ws://$LIVE_GW_IP:$OPAMP_PORT/v1/opamp - through hop 2 and hop 1 to Bindplane Cloud (§6.3)"
  probe_opamp "http://$LIVE_GW_IP:$OPAMP_PORT/v1/opamp" "$out"
  head -n 12 "$out" | awk '{sub(/\r$/,""); print "      | " $0}'
  sleep 2
  line=$(haproxy_log_since "$since"); explain_haproxy_log_line "$line"
  [[ -n $line ]] && printf '\n# hop-2 HAProxy log line\n%s\n' "$line" >>"$out"
  if classify_probe "hop 2 ($LIVE_GW_IP)"; then
    hint "A 403 carrying 'Via: 1.1 google' from a host two segments from the internet is the result the design turns on (§6.3)."
    hint "The DMZ host logged the same request: journalctl -u haproxy -n 5 --no-pager (run there)."
    return 0
  fi
  local w=$FAIL_WHAT y=$FAIL_WHY x=$FAIL_FIX
  info "Localising the fault (troubleshooting flowchart): the same probe straight to hop 1 from this host"
  probe_opamp "http://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp" "$out1"
  if classify_probe "hop 1 ($DMZ_GW_IP) directly" >/dev/null; then
    fail "$w" "Hop 1 answers correctly when probed directly from this host, so the fault is in HOP 2 on this host (bind, backend or timeout).\n$y" \
         "grep -nE 'bind|server|timeout' $HAPROXY_CFG ; journalctl -u haproxy -n 30 --no-pager"
  else
    fail "$w" "The direct probe to hop 1 fails too ($PROBE_STATUS${PROBE_STATUS:+ }curl exit $PROBE_RC), so the fault is at or beyond hop 1: the Fortigate rule, or the DMZ side.\n$y" \
         "$x\nOn the DMZ host: bp-dmz-setup.sh --diagnose"
  fi
  return 1
}

step_collector_install() {
  local arch deb rel want got inst
  arch=$(dpkg --print-architecture)
  deb="$REPO_ROOT/packages/observiq-otel-collector_${BP_VERSION}_linux_${arch}.deb"
  rel="packages/observiq-otel-collector_${BP_VERSION}_linux_${arch}.deb"
  if ! want=$(v_live_version "$BP_VERSION"); then
    fail "Collector version $BP_VERSION cannot be installed by this script." "$want" "Choose a v1.x version with: $0 --reconfigure"
    return 1
  fi
  if [[ ! -f $deb ]]; then
    fail "$rel is not in the mirror." "Mirrored versions: $(mirror_versions)" "Pick one of them with --reconfigure, or stage $BP_VERSION on the DMZ host (bp-dmz-update-repo.sh --versions $BP_VERSION) and run: $0 --only mirror"
    return 1
  fi
  want=$(awk -v n="$rel" '$2==n {print $1; exit}' "$REPO_ROOT/SHA256SUMS"); got=$(sha256 "$deb")
  [[ -n $want && $want == "$got" ]] || { fail "$rel does not match SHA256SUMS." "Corrupt or partial mirror copy." "$0 --only mirror"; return 1; }
  ok "$rel verified against SHA256SUMS"
  if dpkg-query -W -f='${Status}' "$COLLECTOR_PKG" 2>/dev/null | grep -qE 'half-configured|unpacked|half-installed|triggers-'; then
    # the vendor's post-install script deletes its staging area on the first attempt, so
    # 'dpkg --configure' cannot finish it - unpacking the package again can
    warn "$COLLECTOR_PKG is half-installed from an earlier attempt - reinstalling it (its scripts cannot simply be re-run)"
    REPLACE_CONFIRMED=1
  fi
  inst=$(collector_installed_version)
  if [[ $inst == "$BP_VERSION" ]]; then ok "Collector $inst is already installed"; return 0; fi
  if [[ -n $inst ]] && (( ! REPLACE_CONFIRMED )); then
    warn "Collector $inst is installed; the estate version is $BP_VERSION"
    ask_yn "Replace $inst with $BP_VERSION from the mirror?" y || { warn "Keeping $inst"; return 0; }
  fi
  info "Installing the package directly with dpkg - NOT with install_unix.sh, which hangs offline on isolated hosts (§6.4)"
  dpkg_install "$deb" || return 1
  systemctl cat "$COLLECTOR_SVC" >/dev/null 2>&1 || { fail "The package installed but $COLLECTOR_SVC.service is missing." "The package scripts failed part-way." "dpkg -l $COLLECTOR_PKG ; apt-get install --reinstall $deb"; return 1; }
  ok "Collector $(collector_version) installed; runtime owner of $COLLECTOR_HOME: $(collector_owner)"
  [[ $(collector_owner) != observiq-otel-collector:* ]] && hint "Note: v1.108+ uses the 'bdot' user, not 'observiq-otel-collector' as written in runbook §6.4/§8.4 - this script uses the actual owner."
  # the package swaps the binary but does not restart a running service - the old code keeps running until restarted
  if [[ -n $inst && -f $MANAGER_YAML ]] && systemctl is-active --quiet "$COLLECTOR_SVC"; then
    service_restart_checked "$COLLECTOR_SVC" || return 1
    info "Restarted so the new binary is the one running (the package does not restart it)"
  fi
  return 0
}

step_collector_config() {
  local endpoint="ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp" aid owner tmp changed=1
  ensure_secret || return 1
  [[ -d $COLLECTOR_HOME ]] || { fail "$COLLECTOR_HOME does not exist." "The collector is not installed." "$0 --only collector_install"; return 1; }
  aid=$(yaml_get agent_id)
  if [[ -f $MANAGER_YAML && $(yaml_get endpoint) == "$endpoint" && $(yaml_get secret_key) == "$BP_SECRET" \
        && $(yaml_get labels) == "$AGENT_LABELS" && $(yaml_get agent_name) == "$AGENT_NAME" ]]; then
    changed=0; ok "manager.yaml already has the right endpoint, key, labels and name"
  else
    [[ -f $MANAGER_YAML ]] && { cp -p "$MANAGER_YAML" "$STATE_DIR/manager.yaml.bak-$RUN_TS"; info "Previous manager.yaml saved as $STATE_DIR/manager.yaml.bak-$RUN_TS"; }
    owner=$(collector_owner)
    tmp=$(mktemp "$COLLECTOR_HOME/.manager.XXXXXX") || { fail "Cannot write in $COLLECTOR_HOME." "" "df -h $COLLECTOR_HOME"; return 1; }
    {
      echo "endpoint: $endpoint"
      echo "secret_key: $BP_SECRET"
      [[ -n $aid ]] && echo "agent_id: $aid"
      echo "labels: \"$AGENT_LABELS\""
      echo "agent_name: $AGENT_NAME"
    } >"$tmp"
    chmod 600 "$tmp"; chown "$owner" "$tmp" 2>/dev/null || warn "Could not chown manager.yaml to $owner - leaving it root-owned (root can still read it)"
    mv -f "$tmp" "$MANAGER_YAML"
    ok "Wrote $MANAGER_YAML (endpoint $endpoint, owner $owner, mode 0600)"
    if [[ -n $aid ]]; then info "Kept the existing agent_id $aid - the console keeps this host as the same agent"
    else info "No agent_id written - the collector generates one when it starts (§6.4)"; fi
    hint "labels \"$AGENT_LABELS\" are how configurations get assigned in bulk later (§6.4) - not cosmetic."
  fi
  run "Enabling the collector at boot" systemctl enable "$COLLECTOR_SVC"
  if (( changed )) || ! systemctl is-active --quiet "$COLLECTOR_SVC"; then
    service_restart_checked "$COLLECTOR_SVC" || return 1
  fi
}

# dpkg -i with a wait for the dpkg lock (unattended-upgrades may hold it)
dpkg_install() {
  local i
  for i in $(seq 1 30); do
    run_stream "dpkg -i ${1#"$REPO_ROOT"/}" dpkg -i "$1" && return 0
    if grep -qE 'lock.*(locked|held)|Unable to acquire|frontend lock' "$LAST_OUT"; then
      warn "The dpkg lock is held by another process - waiting 10s ($i/30)"; sleep 10; continue
    fi
    break
  done
  explain_apt_failure "$LAST_OUT"
  return 1
}

collector_conn() { # local address of an established collector session to hop 1
  ss -Htnp state established dst "$DMZ_GW_IP:$OPAMP_PORT" 2>/dev/null | grep -i 'observiq' | awk '{print $3}' | head -n1
}

step_collector_verify() {
  local i v aid c1="" c2="" errs before=0 console=0
  [[ -r $COLLECTOR_LOG ]] && before=$(wc -l <"$COLLECTOR_LOG")
  for i in $(seq 1 15); do systemctl is-active --quiet "$COLLECTOR_SVC" && break; sleep 1; done
  systemctl is-active --quiet "$COLLECTOR_SVC" || { journalctl -u "$COLLECTOR_SVC" -n 20 --no-pager >"$RUN_TMP/col.j" 2>&1; show_tail "$RUN_TMP/col.j" 12
    fail "The collector service is not running." "It exits at start - see the journal above and $COLLECTOR_LOG." "journalctl -u $COLLECTOR_SVC -n 50 --no-pager ; tail -n 50 $COLLECTOR_LOG"; return 1; }
  ok "Collector service is active"
  v=$(collector_version); [[ $v == "$BP_VERSION" ]] && ok "Collector version $v" || warn "Collector reports '${v:-?}' (estate version $BP_VERSION)"
  for i in $(seq 1 30); do aid=$(yaml_get agent_id); [[ -n $aid ]] && break; sleep 1; done
  [[ -n $aid ]] && ok "agent_id $aid present in manager.yaml" || warn "No agent_id in manager.yaml yet"
  info "Waiting up to 60s for the OpAMP session to hop 1 ($DMZ_GW_IP:$OPAMP_PORT) ..."
  for i in $(seq 1 60); do c1=$(collector_conn); [[ -n $c1 ]] && break; sleep 1; done
  if [[ -n $c1 ]]; then
    sleep 15; c2=$(collector_conn)
  fi
  errs=$(collector_log_errors "$before" 6)
  [[ -n $errs ]] && { warn "Collector log errors since the start:"; printf '%s\n' "$errs" | redact_stream | sed 's/^/         /'; }
  if [[ -n $c1 && $c1 == "$c2" ]]; then
    ok "Stable OpAMP session to hop 1 from $c1 (held for 15s+ - a rejected session would have dropped)"
    say "  Check the Bindplane console now: Agents -> $AGENT_NAME (agent_id ${aid:-?})."
    ask_yn "Is $AGENT_NAME shown as Connected?" y && console=1
  fi
  { echo "# §6.5 $(date -Is)"; ss -tnp state established dst "$DMZ_GW_IP:$OPAMP_PORT" 2>&1; echo "agent_id=$aid version=$v console_connected=$console"; } >"$EVIDENCE_DIR/collector-verify-$RUN_TS.txt"
  if (( console )); then
    ok "PASS: the LIVE collector is managed from Bindplane Cloud through the relay (§6.5 gate)"
    hint "Confirm the tunnel on the DMZ host: curl -s '$STATS_URL' | awk -F, '\$1==\"bindplane_cloud\"{print \$1,\$2,\"scur=\"\$5}'"
    return 0
  fi
  local code=""; code=$(grep -oE 'status=[0-9]{3}' <<<"$errs" | tail -n1 | cut -d= -f2)
  if [[ -z $c1 || $c1 != "$c2" ]] && [[ -n $code ]]; then
    case $code in
      401|403) fail "The upgrade to WebSocket was refused with HTTP $code (collector log: 'Server responded with status=$code')." \
                    "A real collector getting $code means the secret key in manager.yaml was rejected (wrong key, or a key from another Bindplane tenant). The 403 the synthetic probe gets is expected; a collector's is not." \
                    "Copy the key again from the console (Agents -> Install Agents), then: $0 --reconfigure (answer 'n' to keeping the key) and --only collector_config" ;;
      404)     fail "The upgrade was answered with HTTP 404." "Host header or SNI at hop 1 does not name the cloud host, or the path is not /v1/opamp." "On the DMZ host: grep -nE 'set-header|sni' /etc/haproxy/haproxy.cfg" ;;
      502|503) fail "The upgrade was answered with HTTP $code by the relay chain." "Hop 2 has no healthy hop 1 ($(stats_field hop1_dmz dmz check_status)), or hop 1 cannot reach Bindplane Cloud." "$0 --diagnose here; bp-dmz-setup.sh --diagnose on the DMZ host" ;;
      *)       fail "The upgrade was answered with HTTP $code." "See the collector log lines above." "$0 --diagnose" ;;
    esac
  elif [[ -z $c1 ]]; then
    local st; st=$(tcp_state "$DMZ_GW_IP" "$OPAMP_PORT")
    if [[ $st != open ]]; then explain_tcp "$DMZ_GW_IP" "$OPAMP_PORT" "$st" "OpAMP relay hop 1"
      fail "The collector cannot open a connection to hop 1 ($st)." "See the hint above." "Fix the path, then: $0 --only collector_verify"
    else
      fail "The collector did not hold an OpAMP session to $DMZ_GW_IP:$OPAMP_PORT within 60s." \
           "Hop 1 is reachable, so either the session is rejected at once (wrong secret key - the upgrade is refused and the collector backs off), or the collector is not using this endpoint." \
           "grep endpoint $MANAGER_YAML ; tail -n 50 $COLLECTOR_LOG ; journalctl -u $COLLECTOR_SVC -n 30"
    fi
  elif [[ $c1 != "$c2" ]]; then
    fail "The OpAMP session keeps reconnecting (local port changed $c1 -> ${c2:-none})." \
         "Hop 1 or Bindplane Cloud closes the session after the upgrade - typically a wrong secret_key, or an inline device at the DMZ edge." \
         "Compare the key with the console; to replace it: $0 --reconfigure (answer 'n' to keeping the key), then --only collector_config.\nOn the DMZ host: journalctl -u haproxy -n 30 (termination flags)."
  else
    fail "The session is up but the console does not show $AGENT_NAME as Connected." \
         "Authentication was rejected (wrong secret key / tenant), or the console was not refreshed." \
         "Re-check the console, the secret key and the labels, then: $0 --only collector_verify"
  fi
  return 1
}

write_next_steps() {
  local seg site_label arch
  seg=$([[ $SITE == dr ]] && echo dr-live || echo prod-live); site_label=$([[ $SITE == dr ]] && echo dr || echo primary)
  arch=$(dpkg --print-architecture)
  cat >"$NEXT_STEPS_FILE" <<EOF
# =============================================================================
# Hand-off for the ${seg^^} log sources - runbook Stages 8, 9, 11, 13
# Generated by $SCRIPT_NAME on $(hostname -s) at $(date -Is)
# Gateway for this segment: $LIVE_GW_IP  (repository :$REPO_PORT, OpAMP :$OPAMP_PORT, OTLP :$OTLP_PORT)
# =============================================================================

## Stage 8 - Linux (Ubuntu) log source: manual install (8.2 + 8.4)
export BP_VERSION='$BP_VERSION'
export GW_IP='$LIVE_GW_IP'
export BP_SECRET='<paste from the console - never stored in this file>'
sudo mkdir -p /opt/bp-install && cd /opt/bp-install
sudo curl -fL -O "http://\${GW_IP}:$REPO_PORT/packages/observiq-otel-collector_\${BP_VERSION}_linux_amd64.deb"
sudo curl -fL -O "http://\${GW_IP}:$REPO_PORT/SHA256SUMS"
# verify THIS file (SHA256SUMS lists it as packages/...; the runbook's --ignore-missing form verifies nothing)
grep " packages/observiq-otel-collector_\${BP_VERSION}_linux_amd64.deb\$" SHA256SUMS | sed 's# packages/# #' | sha256sum -c -
sudo dpkg -i "observiq-otel-collector_\${BP_VERSION}_linux_amd64.deb"      # never install_unix.sh offline
sudo tee /opt/observiq-otel-collector/manager.yaml >/dev/null <<EOT
endpoint: ws://\${GW_IP}:$OPAMP_PORT/v1/opamp
secret_key: \${BP_SECRET}
labels: "site=$site_label,segment=$seg,zone=<zone>,os=ubuntu,role=source"
agent_name: \$(hostname -s)
EOT
# v1.108+ runs as user 'bdot' (runbook 8.4 says observiq-otel-collector) - use the real owner:
sudo chown "\$(stat -c %U:%G /opt/observiq-otel-collector)" /opt/observiq-otel-collector/manager.yaml
sudo chmod 600 /opt/observiq-otel-collector/manager.yaml
sudo systemctl enable --now observiq-otel-collector
ss -tnp | grep -E ':($OPAMP_PORT|$OTLP_PORT)'      # 8.9: one established connection to $OPAMP_PORT

## Stage 8 - RHEL log source (8.3)
sudo curl -fL -O "http://\${GW_IP}:$REPO_PORT/packages/observiq-otel-collector_\${BP_VERSION}_linux_amd64.rpm"
sudo rpm -U "observiq-otel-collector_\${BP_VERSION}_linux_amd64.rpm"     # then the same manager.yaml, os=rhel

## Stage 8.8 - Ansible: set  bp_gateway: "$LIVE_GW_IP"  and change  owner/group: observiq-otel-collector
##             to the runtime user of the installed version (bdot for v1.108+).

## Stage 9 - Windows log source (9.2 / 9.3), elevated PowerShell. Write the gateway as \${Gateway} (or escape
##   the colon: \$Gateway\`:$REPO_PORT) - "\$Gateway:$REPO_PORT" is parsed as a scoped variable and comes out empty.
#   \$Gateway = '$LIVE_GW_IP'
#   New-Item -ItemType Directory -Force -Path C:\\bp-install | Out-Null
#   Invoke-WebRequest -Uri "http://\${Gateway}:$REPO_PORT/windows/observiq-otel-collector.msi" -OutFile 'C:\\bp-install\\observiq-otel-collector.msi' -UseBasicParsing
#   (Invoke-WebRequest -Uri "http://\${Gateway}:$REPO_PORT/SHA256SUMS" -UseBasicParsing).Content -split "\`n" | Select-String 'windows/observiq-otel-collector.msi\$'
#   (Get-FileHash 'C:\\bp-install\\observiq-otel-collector.msi' -Algorithm SHA256).Hash      # must match the line above
#   Start-Process msiexec.exe -Wait -ArgumentList '/i','C:\\bp-install\\observiq-otel-collector.msi','/qn','/norestart'
#   manager.yaml (9.3): endpoint: ws://\${Gateway}:$OPAMP_PORT/v1/opamp ; labels "site=$site_label,segment=$seg,zone=enterprise,os=windows,role=source"

## Stage 11 - this gateway's configuration (cbsl-${seg}-gateway, labels segment=$seg,role=gateway):
##   source Bindplane Gateway on $LIVE_GW_IP:$OTLP_PORT -> destination Bindplane Gateway $DMZ_GW_IP:$OTLP_PORT, gRPC, compression on.
##   Put volume-reducing processors HERE, not on the DMZ gateway (11.5).

## Stage 13.1 - disable automatic upgrades for every agent labelled segment=$seg: an OpAMP upgrade
##   hands the agent a URL it cannot reach from this segment. Upgrade offline instead:
##   DMZ: bp-dmz-update-repo.sh (asks for the versions) then here: bp-live-setup.sh --upgrade-collector vX.Y.Z

## Stage 13.7 - mirror ownership: run $MIRROR_SYNC after every DMZ-side change$( [[ $MIRROR_TIMER == yes ]] && echo " (a daily timer is enabled)" ).
EOF
  chmod 644 "$NEXT_STEPS_FILE"
}

step_evidence() {
  local d="$EVIDENCE_DIR/pack-$RUN_TS" tarball inbound outbound
  mkdir -p "$d"
  inbound=$(ss -Htn state established "( sport = :$OPAMP_PORT )" 2>/dev/null | grep -cF "$LIVE_GW_IP:$OPAMP_PORT")
  outbound=$(ss -Htn state established dst "$DMZ_GW_IP:$OPAMP_PORT" 2>/dev/null | wc -l)
  banner_line "Socket census (§12.1)"
  ss -H -lntp 2>/dev/null | grep -E ":($OPAMP_PORT|$OTLP_PORT|5514|$REPO_PORT|$STATS_PORT) " \
    | awk -v ip="$LIVE_GW_IP" '$4 ~ "^(" ip "|127\\.0\\.0\\.1|0\\.0\\.0\\.0|\\*|\\[::\\]):" {printf "      listen %-24s %s\n", $4, $6}'
  say "      established inbound from agents to $LIVE_GW_IP:$OPAMP_PORT : $inbound"
  say "      established outbound to hop 1 $DMZ_GW_IP:$OPAMP_PORT        : $outbound"
  tunnel_census
  (( outbound > 0 )) && ok "Outbound sessions to the DMZ gateway exist" || warn "No outbound session to the DMZ gateway - destination misconfigured or Fortigate rule missing (§12.1)"
  {
    echo "# Evidence pack - $(hostname -s) - $(date -Is) - $SCRIPT_NAME v$SCRIPT_VERSION"
    echo "## versions"; haproxy -v 2>&1 | head -n1; nginx -v 2>&1; echo "collector $(collector_version)"
    echo "## listeners"; ss -lntp 2>/dev/null | grep -E ":($OPAMP_PORT|$OTLP_PORT|5514|$REPO_PORT|$STATS_PORT) "
    echo "## socket census"; echo "inbound=$inbound outbound=$outbound"; tunnel_census
    echo "## haproxy -c"; haproxy -c -f "$HAPROXY_CFG" 2>&1
    echo "## apt source"; cat "$APT_LIST" 2>/dev/null
    echo "## mirror"; cat "$REPO_ROOT/VERSION-INFO" 2>/dev/null; tail -n 3 "$MIRROR_LOG" 2>/dev/null
    echo "## step progress"; cat "$STATE_FILE" 2>/dev/null
    echo "## host firewall"; ufw status verbose 2>&1 || true
    echo "## ip_forward"; sysctl net.ipv4.ip_forward 2>&1
  } >"$d/summary.txt" 2>&1
  cp -f "$HAPROXY_CFG" "$d/haproxy.cfg" 2>/dev/null
  cp -f "$NGINX_SITE" "$d/nginx-bindplane-repo.conf" 2>/dev/null
  [[ -r $MANAGER_YAML ]] && sed -E 's/^(secret_key:).*/\1 ***REDACTED***/' "$MANAGER_YAML" >"$d/manager.yaml.redacted"
  write_next_steps; cp -f "$NEXT_STEPS_FILE" "$d/"
  if [[ -n $BP_SECRET ]] && grep -rqF "$BP_SECRET" "$EVIDENCE_DIR" 2>/dev/null; then
    grep -rlF "$BP_SECRET" "$EVIDENCE_DIR" | while read -r f; do sed -i "s/$(sed_escape "$BP_SECRET")/***REDACTED***/g" "$f"; done
  fi
  tarball="$LOG_DIR/bp-live-evidence-$(hostname -s)-$RUN_TS.tar.gz"
  ( cd "$EVIDENCE_DIR" && tar -czf "$tarball" . ) 2>/dev/null; chmod 600 "$tarball" 2>/dev/null
  ok "Evidence pack: $tarball"
  ok "Log-source hand-off notes (Stage 8/9/11/13): $NEXT_STEPS_FILE"
}

# =============================================================================
#  Diagnostics (--diagnose, and [d] in the failure menu) - read-only
#  Works outward from this host, following the runbook's troubleshooting flowchart.
# =============================================================================
section() { printf '\n%s--- %s ---%s\n' "$C_BLD" "$*" "$C_OFF"; log "---- $*"; }

run_diagnostics() {
  local svc a e st cs first code sums remote local_sums inbound outbound c1 aid
  CHK_FAILS=0; CHK_WARNS=0
  banner_line "Diagnostics (read-only) - working outward from this host"

  section "1. Services"
  for svc in "$COLLECTOR_SVC" nginx haproxy; do
    if systemctl cat "$svc" >/dev/null 2>&1; then
      a=$(systemctl is-active "$svc" 2>/dev/null); e=$(systemctl is-enabled "$svc" 2>/dev/null)
      if [[ $a == active ]]; then c_ok "$svc: active, ${e:-?} at boot"; [[ $e == enabled ]] || c_warn "$svc is not enabled at boot"
      else c_fail "$svc: $a"; hint "journalctl -u $svc -n 30 --no-pager"; fi
    else c_warn "$svc is not installed"; fi
  done
  [[ -f $SYNC_TIMER ]] && { systemctl is-active --quiet bp-mirror-sync.timer && c_ok "bp-mirror-sync.timer active" || c_warn "bp-mirror-sync.timer not active"; }

  section "2. Listeners (bound to $LIVE_GW_IP only - never the Fortigate-facing interface)"
  ss -H -lntp 2>/dev/null | grep -E ":($OPAMP_PORT|$OTLP_PORT|5514|$REPO_PORT|$STATS_PORT)[[:space:]]" \
    | awk -v ip="${LIVE_GW_IP:-x}" '$4 ~ "^(" ip "|127\\.0\\.0\\.1|0\\.0\\.0\\.0|\\*|\\[::\\]):" {printf "      %-24s %s\n", $4, $6}'
  if [[ -n $LIVE_GW_IP ]]; then
    if verify_listener "$OPAMP_PORT" "$LIVE_GW_IP" haproxy >/dev/null; then c_ok "HAProxy hop 2 bound to $LIVE_GW_IP:$OPAMP_PORT only"; else c_fail "$FAIL_WHAT"; hint "$FAIL_FIX"; fi
    if verify_listener "$REPO_PORT" "$LIVE_GW_IP" nginx >/dev/null; then c_ok "Mirror bound to $LIVE_GW_IP:$REPO_PORT only"; else c_fail "$FAIL_WHAT"; hint "$FAIL_FIX"; fi
  else c_warn "LIVE_GW_IP unknown (no saved configuration) - listener checks skipped"; fi
  ss -H -lnt "sport = :$OTLP_PORT" 2>/dev/null | grep -q . && c_ok "Collector listens on :$OTLP_PORT (Stage 11 configuration arrived)" \
    || say "      :$OTLP_PORT not listening yet - normal until the cbsl-live-gateway configuration is rolled out (Stage 11)"

  section "3. Configuration files"
  if [[ -f $HAPROXY_CFG ]] && command -v haproxy >/dev/null; then
    if haproxy -c -f "$HAPROXY_CFG" >"$RUN_TMP/hc.out" 2>&1; then c_ok "haproxy -c: configuration is valid"
    else first=$(grep -m1 -F '[ALERT]' "$RUN_TMP/hc.out"); c_fail "haproxy -c: ${first:-invalid}"; hint "Only the first alert is real (§3.1)."; fi
    grep -qE '^[[:space:]]*timeout[[:space:]]+tunnel' "$HAPROXY_CFG" && c_ok "timeout tunnel is set" \
      || c_fail "timeout tunnel is missing - agents connect then drop every ~50s (it must be set at BOTH hops)"
    grep -qE 'set-header[[:space:]]+Host' "$HAPROXY_CFG" && c_warn "Hop 2 rewrites the Host header - keep the rewrite at hop 1 only (§6.3)"
    grep -qE '\\[[:space:]]*$' "$HAPROXY_CFG" && c_fail "A line ends in '\\' - HAProxy has no line continuation (§3.1)"
    grep -q 'capture request header Authorization' "$HAPROXY_CFG" && c_warn "Temporary header capture is ON - turn it off before handover: $0 --proxy-debug off"
  else c_warn "$HAPROXY_CFG not present"; fi
  command -v nginx >/dev/null && { nginx -t >"$RUN_TMP/nt.out" 2>&1 && c_ok "nginx -t: configuration is valid" || c_fail "nginx -t: $(grep -m1 -E 'emerg|error' "$RUN_TMP/nt.out")"; }

  section "4. Hop 2 tunnel census"
  if stats_csv | grep -q '^hop1_dmz,'; then
    tunnel_census
    st=$(stats_field hop1_dmz dmz status); cs=$(stats_field hop1_dmz dmz check_status)
    [[ $st == UP* ]] && c_ok "Hop 1 backend is $st ($cs)" || { c_fail "Hop 1 backend is ${st:-?} ($cs)"; hint "$(describe_check_status "$cs")"; }
    say "      agents connected through hop 2 right now: $(stats_field opamp_in FRONTEND scur)"
  else c_warn "HAProxy stats not reachable on 127.0.0.1:$STATS_PORT"; fi

  section "5. Path to the DMZ gateway ($DMZ_GW_IP, source $(route_src "$DMZ_GW_IP"))"
  if [[ -n $DMZ_GW_IP ]]; then
    explain_tcp "$DMZ_GW_IP" "$REPO_PORT" "$(tcp_state "$DMZ_GW_IP" "$REPO_PORT")" "package repository" || CHK_FAILS=$((CHK_FAILS+1))
    explain_tcp "$DMZ_GW_IP" "$OPAMP_PORT" "$(tcp_state "$DMZ_GW_IP" "$OPAMP_PORT")" "OpAMP hop 1" || CHK_FAILS=$((CHK_FAILS+1))
    st=$(tcp_state "$DMZ_GW_IP" "$OTLP_PORT")
    case $st in open) c_ok "TCP $DMZ_GW_IP:$OTLP_PORT reachable (OTLP)";; refused) say "      $DMZ_GW_IP:$OTLP_PORT refused - normal until the DMZ gateway configuration is pushed (Stage 11)";; *) c_warn "TCP $DMZ_GW_IP:$OTLP_PORT $st - Stage 11 telemetry needs this rule";; esac
  fi

  section "6. Probe chain (flowchart: this hop, then the hop above)"
  if [[ -n $LIVE_GW_IP ]] && systemctl is-active --quiet haproxy; then
    probe_opamp "http://$LIVE_GW_IP:$OPAMP_PORT/v1/opamp" "$RUN_TMP/diag.p2"
    if classify_probe "hop 2 ($LIVE_GW_IP)" >/dev/null; then c_ok "Probe via hop 2: $PROBE_STATUS $PROBE_VIA - path is fine; if an agent is not Connected check its manager.yaml, clock and agent_id"
    else
      c_fail "Probe via hop 2: $FAIL_WHAT"
      probe_opamp "http://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp" "$RUN_TMP/diag.p1"
      if classify_probe "hop 1" >/dev/null; then hint "The same probe straight to hop 1 PASSES -> this hop's config: bind, backend, timeout"
      else hint "The same probe to hop 1 fails too ($PROBE_STATUS) -> Fortigate rule or the DMZ side is down (run bp-dmz-setup.sh --diagnose there)"; fi
    fi
  else c_warn "Probe skipped (haproxy not running or LIVE_GW_IP unknown)"; fi

  section "7. Package mirror"
  if [[ -f $REPO_ROOT/SHA256SUMS ]]; then
    sums=$(cd "$REPO_ROOT" && sha256sum -c --quiet SHA256SUMS 2>&1 | head -n 5)
    [[ -z $sums ]] && c_ok "All $(wc -l <"$REPO_ROOT/SHA256SUMS") mirrored files match SHA256SUMS" || { c_fail "Mirror checksum problems:"; printf '%s\n' "$sums" | sed 's/^/         /'; hint "Run: $MIRROR_SYNC"; }
    if [[ -n $DMZ_GW_IP ]]; then
      remote=$(dmz_get /SHA256SUMS | sha256sum | awk '{print $1}'); local_sums=$(sha256 "$REPO_ROOT/SHA256SUMS")
      if [[ $remote == "$(printf '' | sha256sum | awk '{print $1}')" ]]; then c_warn "Could not read the DMZ SHA256SUMS to compare freshness"
      elif [[ $remote == "$local_sums" ]]; then c_ok "Mirror is identical to the DMZ origin"
      else c_warn "Mirror differs from the DMZ origin (new content upstream) - run: $MIRROR_SYNC"; fi
    fi
    say "      mirrored collector versions: $(mirror_versions)"
    [[ -s $MIRROR_LOG ]] && say "      last sync: $(tail -n1 "$MIRROR_LOG" | cut -c1-150)"
  else c_warn "No mirror yet ($REPO_ROOT/SHA256SUMS missing)"; fi
  if [[ -n $LIVE_GW_IP ]]; then
    code=$(lcurl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$LIVE_GW_IP:$REPO_PORT/")
    [[ $code == 200 ]] && c_ok "Mirror index http://$LIVE_GW_IP:$REPO_PORT/ answers 200" || c_fail "Mirror index answers ${code:-nothing}"
  fi
  if [[ -s $NGINX_ACCESS_LOG ]]; then
    say "      log sources that fetched from the mirror recently:"
    tail -n 2000 "$NGINX_ACCESS_LOG" | awk '{print $1}' | sort | uniq -c | sort -rn | head -n 5 | sed 's/^/        /'
  fi

  section "8. apt source"
  if [[ ${PKG_SOURCE:-dmz} == dmz ]]; then
    [[ -f $APT_LIST ]] && c_ok "$APT_LIST: $(grep -v '^#' "$APT_LIST")" || c_warn "$APT_LIST missing"
    [[ ${REPO_SIGNED:-no} == yes ]] && { [[ -s $REPO_KEYRING ]] && c_ok "Keyring $REPO_KEYRING present" || c_fail "Keyring $REPO_KEYRING missing"; }
  else say "      package source: system apt sources (CBSL internal mirror)"; fi

  section "9. LIVE collector"
  if [[ -n $(collector_installed_version) ]]; then
    st=$(systemctl is-active "$COLLECTOR_SVC" 2>/dev/null)
    [[ $st == active ]] && c_ok "Collector $(collector_version) active" || c_fail "Collector is $st"
    say "      endpoint: $(yaml_get endpoint)   agent_name: $(yaml_get agent_name)   labels: $(yaml_get labels)"
    aid=$(yaml_get agent_id); [[ -n $aid ]] && c_ok "agent_id $aid" || c_warn "No agent_id yet"
    c1=$(collector_conn)
    [[ -n $c1 ]] && c_ok "OpAMP session established from $c1 to $DMZ_GW_IP:$OPAMP_PORT" || c_fail "No established OpAMP session to $DMZ_GW_IP:$OPAMP_PORT"
    e=$(collector_log_errors 0 3)
    [[ -n $e ]] && { c_warn "Recent collector log errors:"; printf '%s\n' "$e" | redact_stream | sed 's/^/         /'; }
  else c_warn "Collector not installed"; fi

  section "10. Gateway hygiene"
  check_time
  check_ip_forward
  check_space "$REPO_ROOT" 2 "the mirror"
  check_space "$COLLECTOR_HOME" 5 "the collector queue"
  if ufw_active; then c_ok "ufw active; bindplane rules:"; ufw status 2>/dev/null | grep -i bindplane | sed 's/^/        /'; else say "      ufw not active"; fi
  [[ -n $(apparmor_denials) ]] && { c_warn "Recent AppArmor denials for haproxy/nginx:"; apparmor_denials | sed 's/^/        /'; }
  systemctl cat haproxy >/dev/null 2>&1 && { [[ $(systemctl show haproxy -p LimitNOFILE --value 2>/dev/null) == 65535 ]] && c_ok "haproxy LimitNOFILE=65535" || c_warn "haproxy LimitNOFILE is not 65535"; }

  section "11. Socket census (§12.1) and recent HAProxy log"
  inbound=$(ss -Htn state established "( sport = :$OPAMP_PORT )" 2>/dev/null | grep -cF "${LIVE_GW_IP:-x}:$OPAMP_PORT")
  outbound=$(ss -Htn state established dst "${DMZ_GW_IP:-0.0.0.0}:$OPAMP_PORT" 2>/dev/null | wc -l)
  say "      inbound sessions from agents: $inbound   outbound sessions to hop 1: $outbound"
  (( inbound > 0 && outbound == 0 )) && c_fail "Inbound sessions but none outbound - the hop 1 destination is misconfigured or the Fortigate rule is missing (§12.1)"
  journalctl -u haproxy -n 300 --no-pager -o cat 2>/dev/null | grep -E ' opamp_in |\[ALERT\]|hop1_dmz' | tail -n 6 | cut -c1-200 | sed 's/^/      /'

  echo
  if (( CHK_FAILS )); then err "Diagnostics: $CHK_FAILS failure(s), $CHK_WARNS warning(s) - fix the first failure first; most failures are a segment away from where they appear."
  else ok "Diagnostics: no failures, $CHK_WARNS warning(s)"
    hint "Escalate to Bindplane if sessions drop with no event at either proxy or the Fortigate (include both HAProxy configs and collector.log, and say it is a two-hop plain proxy chain)."
  fi
  return 0
}

action_diagnose() {
  init_defaults; load_config || true
  [[ -z $LIVE_GW_IP && -f $HAPROXY_CFG ]] && LIVE_GW_IP=$(sed -nE "s/^[[:space:]]*bind[[:space:]]+([0-9.]+):$OPAMP_PORT.*/\1/p" "$HAPROXY_CFG" | head -n1)
  [[ -z $DMZ_GW_IP && -f $HAPROXY_CFG ]] && DMZ_GW_IP=$(sed -nE "s/^[[:space:]]*server[[:space:]]+dmz[[:space:]]+([0-9.]+):.*/\1/p" "$HAPROXY_CFG" | head -n1)
  BP_SECRET=$(yaml_get secret_key)   # the probe result does not depend on it (Cloud Armor answers 403 regardless)
  run_diagnostics
  cp -f "$LOG_FILE" "$EVIDENCE_DIR/diagnose-$RUN_TS.txt" 2>/dev/null
  info "Report saved: $EVIDENCE_DIR/diagnose-$RUN_TS.txt"
}

# =============================================================================
#  Other actions
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

show_gates() {
  local p v
  p=$(state_get probe_chain); v=$(state_get collector_verify)
  if [[ $p == "done" && $v == "done" ]]; then ok "Gate §6.5 PASSED - a collector with no internet access is managed through both hops. Stage 8 (log sources) may start."
  else
    [[ $p == "done" ]] || warn "Gate §6.3 (probe through both hops: 403 + Via: 1.1 google) not yet passed"
    [[ $v == "done" ]] || warn "Gate §6.5 (LIVE collector Connected in the console) not yet passed"
  fi
}

show_config() {
  printf '  %-30s %s\n' \
    "Site" "$SITE" \
    "LIVE gateway IP (bind)" "$LIVE_GW_IP${LIVE_GW_IP:+ on $(iface_of_ip "$LIVE_GW_IP")}" \
    "DMZ gateway IP (hop 1)" "$DMZ_GW_IP${DMZ_GW_IP:+ (reached via $(route_dev "$DMZ_GW_IP"), source $(route_src "$DMZ_GW_IP"))}" \
    "Collector version" "$BP_VERSION" \
    "OS package source" "$([[ $PKG_SOURCE == dmz ]] && echo "DMZ repository http://$DMZ_GW_IP:$REPO_PORT/apt" || echo 'system apt sources (internal mirror)')" \
    "Repository signed" "${REPO_SIGNED:-no}$([[ $REPO_SIGNED == yes ]] && echo " (keyring $REPO_KEYRING)")" \
    "Agent name / labels" "$AGENT_NAME / $AGENT_LABELS" \
    "Secret key" "asked when needed (from manager.yaml if present); not saved by this script" \
    "Host-firewall sources/ports" "${FW_SOURCES:-?} -> tcp ${FW_PORTS:-?} $(ufw_active && echo '(ufw active)' || echo '(ufw inactive: not applied)')" \
    "HAProxy maxconn" "$HAPROXY_MAXCONN" \
    "Daily mirror sync timer" "${MIRROR_TIMER:-no}" \
    "Pause between steps" "${PAUSE_BETWEEN_STEPS:-no}"
}

action_status() {
  init_defaults
  if load_config; then banner_line "Saved configuration ($CONF_FILE)"; show_config; else warn "No saved configuration yet"; fi
  banner_line "Step progress"; show_progress
  echo; show_gates
}

action_list() {
  local s i=0
  for s in "${STEPS[@]}"; do i=$((i+1)); printf '  %2d  %-18s %-52s runbook %s\n' "$i" "$s" "${STEP_TITLE[$s]}" "${STEP_REF[$s]}"; done
}

action_reset() {
  ask_yn "Forget step progress (answers in $CONF_FILE are kept)?" n || { info "Nothing changed"; return 0; }
  rm -f "$STATE_FILE"; ok "Progress cleared - the next run starts from step 1"
}

action_proxy_debug() {
  local new="$RUN_TMP/haproxy.cfg.new"
  init_defaults; load_config || { err "No saved configuration - run the build first."; exit 1; }
  case ${ACTION_ARG,,} in on) PROXY_DEBUG=yes ;; off) PROXY_DEBUG=no ;; *) err "Use: --proxy-debug on|off"; exit 2 ;; esac
  render_haproxy_cfg >"$new"
  run "Validating" haproxy -c -f "$new" || { err "Validation failed - nothing changed"; exit 1; }
  install -m 644 "$new" "$HAPROXY_CFG"
  run "Reloading haproxy" systemctl reload haproxy || service_restart_checked haproxy || exit 1
  save_config
  if [[ $PROXY_DEBUG == yes ]]; then
    warn "Header capture is ON: Host, Upgrade and the first 12 characters of Authorization now appear in journalctl -u haproxy."
    hint "Remove it before handover: $0 --proxy-debug off"
  else ok "Header capture is OFF"; fi
}

action_sync_mirror() {
  init_defaults; load_config || { err "No saved configuration - run the build first."; exit 1; }
  ADHOC=1; FORCE_ALL=1
  run_steps mirror
  ok "Mirror is in sync with $(dmz_url /)"
}

action_upgrade_collector() {
  local newv=${ACTION_ARG:-} old msg aid0 aid1 arch deb inst i
  init_defaults; load_config || { err "No saved configuration - run the full build first."; exit 1; }
  arch=$(dpkg --print-architecture); inst=$(collector_installed_version)
  banner_line "Offline collector upgrade on the LIVE gateway (runbook §13.2 / §13.3)"
  say "  Order: DMZ gateways first, then LIVE gateways, then log sources in batches (§13.2)."
  ADHOC=1; FORCE_ALL=1
  run_steps mirror
  ADHOC=0
  if [[ -z $newv ]]; then newv=$(tr ' ' '\n' <<<"$(mirror_versions)" | grep . | sort -V | tail -n1); info "Newest version in the mirror: $newv"; fi
  [[ -n $newv ]] || { err "No v1 collector version is in the mirror (mirrored: none)."; exit 1; }
  msg=$(v_live_version "$newv") || { err "$msg"; exit 2; }
  [[ $newv == v* ]] || newv="v$newv"
  [[ $newv == "$inst" ]] && { ok "Collector $inst is already installed - nothing to do"; return 0; }
  deb="$REPO_ROOT/packages/observiq-otel-collector_${newv}_linux_${arch}.deb"
  [[ -f $deb ]] || { err "$newv is not in the mirror (mirrored: $(mirror_versions)). Stage it on the DMZ host first: bp-dmz-update-repo.sh --versions $newv, then: sudo bp-mirror-sync"; exit 1; }
  ask_yn "Upgrade the collector ${inst:-<none>} -> $newv now?" y || { info "Nothing changed"; return 0; }
  aid0=$(yaml_get agent_id); old=$BP_VERSION
  BP_VERSION=$newv; REPLACE_CONFIRMED=1
  FORCE_ALL=1; ADHOC=1
  run_steps collector_install
  ADHOC=0
  sleep 5
  [[ $(collector_version) == "$newv" ]] && ok "Collector now reports $newv" || warn "Collector reports '$(collector_version)' (expected $newv)"
  systemctl is-active --quiet "$COLLECTOR_SVC" && ok "Collector is running" || err "Collector is not running after the upgrade - escalate to Bindplane if an upgrade leaves it stopped (§13.3)"
  aid1=$(yaml_get agent_id)
  if [[ $aid0 == "$aid1" ]]; then ok "agent_id unchanged ($aid1) - the console still sees the same agent"
  else err "agent_id CHANGED ($aid0 -> $aid1): the host re-registered as a new agent - escalate to Bindplane (§13.3)"; fi
  for i in $(seq 1 60); do [[ -n $(collector_conn) ]] && break; sleep 1; done
  [[ -n $(collector_conn) ]] && ok "OpAMP session to hop 1 re-established" || warn "No OpAMP session after 60s - check: $0 --diagnose"
  save_config
  hint "Rollback (§13.4): dpkg -i $REPO_ROOT/packages/observiq-otel-collector_${inst:-$old}_linux_${arch}.deb   (keep the previous version in the mirror)"
}

action_rollback() {
  local src port dst others
  init_defaults; load_config || true
  banner_line "Rollback - back out the changes made by this script"
  say "  This will:"
  say "    - restore $HAPROXY_CFG from $HAPROXY_CFG.orig, then stop and disable haproxy"
  say "    - remove the nginx site 'bindplane-repo' (and stop nginx if no other site is enabled)"
  say "    - remove $HAPROXY_DROPIN, the ufw rules this script added, the bp-mirror-sync timer"
  say "    - clear step progress (your answers are kept)"
  say "  You will be asked separately about the collector, the apt source and the mirror content."
  ask_yn "Proceed with the rollback?" n || { info "Nothing changed"; return 0; }
  if [[ -f $HAPROXY_CFG.orig ]]; then cp -p "$HAPROXY_CFG" "$HAPROXY_CFG.rolledback-$RUN_TS" 2>/dev/null; cp -p "$HAPROXY_CFG.orig" "$HAPROXY_CFG"; ok "haproxy.cfg restored (previous copy: $HAPROXY_CFG.rolledback-$RUN_TS)"; fi
  systemctl cat haproxy >/dev/null 2>&1 && systemctl disable --now haproxy >/dev/null 2>&1 && ok "haproxy stopped and disabled"
  rm -f "$HAPROXY_DROPIN"; rmdir "$HAPROXY_DROPIN_DIR" 2>/dev/null; systemctl daemon-reload 2>/dev/null; ok "LimitNOFILE drop-in removed"
  if [[ -e $NGINX_LINK || -e $NGINX_SITE ]]; then
    rm -f "$NGINX_LINK" "$NGINX_SITE"; ok "nginx site bindplane-repo removed"
    others=$(find /etc/nginx/sites-enabled -mindepth 1 -maxdepth 1 2>/dev/null | head -n1)
    if [[ -z $others ]]; then systemctl disable --now nginx >/dev/null 2>&1 && ok "nginx stopped and disabled (no other sites)"
    else systemctl reload nginx >/dev/null 2>&1 && ok "nginx reloaded (other sites remain)"; fi
  fi
  if [[ -s $UFW_RECORD ]] && command -v ufw >/dev/null; then
    while read -r src port dst; do
      [[ -n $src ]] || continue; dst=${dst:-$LIVE_GW_IP}
      ufw delete allow proto tcp from "$src" to "$dst" port "$port" >/dev/null 2>&1 && ok "ufw rule removed: $src -> $dst tcp/$port" || warn "Could not remove ufw rule $src -> $dst tcp/$port"
    done <"$UFW_RECORD"
    rm -f "$UFW_RECORD"
  fi
  if [[ -f $SYNC_TIMER || -f $MIRROR_SYNC ]]; then
    systemctl disable --now bp-mirror-sync.timer >/dev/null 2>&1; rm -f "$SYNC_TIMER" "$SYNC_SERVICE" "$MIRROR_SYNC"; systemctl daemon-reload 2>/dev/null
    ok "bp-mirror-sync and its timer removed"
  fi
  if [[ -n $(collector_installed_version) ]] && ask_yn "Also STOP and REMOVE the collector package (manager.yaml is kept)?" n; then
    [[ -f $MANAGER_YAML ]] && cp -p "$MANAGER_YAML" "$STATE_DIR/manager.yaml.rolledback-$RUN_TS"
    run "Removing $COLLECTOR_PKG" apt-get -q -o DPkg::Lock::Timeout=300 -y remove "$COLLECTOR_PKG" && ok "Collector removed (manager.yaml copy: $STATE_DIR/manager.yaml.rolledback-$RUN_TS)"
  fi
  if [[ -f $APT_LIST ]] && ask_yn "Also remove the apt source $APT_LIST?" n; then rm -f "$APT_LIST"; ok "apt source removed"; fi
  if [[ -d $REPO_ROOT/packages ]] && ask_yn "Also DELETE the mirror content in $REPO_ROOT?" n; then
    rm -rf --one-file-system "${REPO_ROOT:?}"/{packages,scripts,windows,apt,rpm} "$REPO_ROOT"/{SHA256SUMS,VERSION-INFO,README.txt}; ok "Mirror content deleted"
  fi
  rm -f "$STATE_FILE"; ok "Step progress cleared"
  hint "nginx/haproxy packages are left installed. To remove them: apt-get purge haproxy nginx nginx-common"
}

# =============================================================================
#  Configuration dialogue
# =============================================================================
choose_live_ip() {
  local dmzdev rows=() r i=0 ifc ip def="" sel msg note
  dmzdev=$(route_dev "$DMZ_GW_IP")
  mapfile -t rows < <(ip -o -4 addr show scope global 2>/dev/null | awk '{print $2" "$4}')
  (( ${#rows[@]} )) || { err "No global IPv4 address found on this host."; return 1; }
  say "  IPv4 addresses on this host:"
  for r in "${rows[@]}"; do
    i=$((i+1)); ifc=${r%% *}; ip=${r#* }; ip=${ip%/*}; note=""
    [[ $ifc == "$dmzdev" ]] && note="<- route to the DMZ gateway (Fortigate-facing)"
    printf '     %d) %-14s %-20s %s\n' "$i" "$ifc" "${r#* }" "$note"
    [[ -z $def && $ifc != "$dmzdev" ]] && def=$ip
  done
  [[ -n $LIVE_GW_IP ]] && def=$LIVE_GW_IP
  [[ -z $def ]] && { def=${rows[0]#* }; def=${def%/*}; }
  while :; do
    ask sel "LIVE-facing address the log sources will use (HAProxy :$OPAMP_PORT, mirror :$REPO_PORT) - number or IP" "$def" || return 1
    if [[ $sel =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#rows[@]} )); then sel=${rows[$((sel-1))]#* }; sel=${sel%/*}; fi
    if ! msg=$(v_local_ip "$sel"); then warn "  $msg"; { (( ASSUME_YES )) || [[ -z $TTY ]]; } && return 1; continue; fi
    if [[ $(iface_of_ip "$sel") == "$dmzdev" && ${#rows[@]} -gt 1 ]]; then
      warn "  $sel is on the interface that faces the Fortigate/DMZ ($dmzdev). §6.2: bind to the LIVE-facing interface only."
      ask_yn "Use $sel anyway?" n || continue
    fi
    LIVE_GW_IP=$sel; return 0
  done
}

gather_config() {
  local st def_v def_labels def_name seg site_label
  banner_line "Configuration"
  say "  Press Enter to accept the value in [brackets]."
  ask SITE "Site of this LIVE gateway (primary/dr)" "${SITE:-primary}" v_site || return 1
  ask DMZ_GW_IP "DMZ gateway address ($([[ $SITE == dr ]] && echo bp-gw-drdmz-01 || echo bp-gw-dmz-01): the address its repository and relay listen on)" "$DMZ_GW_IP" v_remote_ip || return 1
  st=$(tcp_state "$DMZ_GW_IP" "$REPO_PORT")
  if [[ $st == open ]]; then
    fetch_dmz_info
    ok "  DMZ repository reachable: current collector $(info_field current_collector_version || true), staged: ${DMZ_VERSIONS:-?}, apt built for $(info_field apt_repo_built_for), signed: $(info_field apt_repo_signed)"
  else
    warn "  DMZ repository $DMZ_GW_IP:$REPO_PORT is $st right now - continuing; the dmz_path step will check again"
  fi
  choose_live_ip || return 1
  def_v=${BP_VERSION:-$(info_field current_collector_version)}
  if [[ -n $def_v ]] && ! v_live_version "$def_v" >/dev/null; then
    warn "  The DMZ repository's current version $def_v is the v2 package (bindplane-otel-collector) - offering the newest v1 instead"
    def_v=""
  fi
  def_v=${def_v:-$(dmz_newest_version)}; def_v=${def_v:-$(collector_installed_version)}
  [[ -n ${DMZ_V2_VERSIONS:-} ]] && info "  Also staged on the DMZ (v2 package, not installed by this script): $DMZ_V2_VERSIONS"
  ask BP_VERSION "Collector version to install (v1.x, must be staged on the DMZ repository)" "$def_v" v_live_version || return 1
  [[ $BP_VERSION == v* ]] || BP_VERSION="v$BP_VERSION"
  if [[ -n $DMZ_VERSIONS && " $DMZ_VERSIONS " != *" $BP_VERSION "* ]]; then warn "  $BP_VERSION is not staged on the DMZ repository (staged: $DMZ_VERSIONS)"; fi
  if [[ -z $PKG_SOURCE ]]; then
    if [[ -z $DMZ_INFO || $(info_field apt_repo_built_for) == ubuntu-* ]]; then PKG_SOURCE=dmz; else PKG_SOURCE=system; fi
  fi
  say "  Where should nginx/HAProxy/wget come from? 'dmz' = the DMZ repository (§5.2); 'system' = this host's own apt"
  say "  sources, e.g. CBSL's internal Ubuntu mirror reachable from PROD-LIVE (runbook 'Preferred alternative')."
  ask PKG_SOURCE "OS package source (dmz/system)" "$PKG_SOURCE" v_pkg_source || return 1
  if [[ $PKG_SOURCE == dmz ]]; then
    [[ -z $REPO_SIGNED && $(info_field apt_repo_signed) == yes ]] && REPO_SIGNED=yes
    ask_yn_var REPO_SIGNED "Is the DMZ repository GPG-signed (§5.4)?" no
    if [[ $REPO_SIGNED == yes ]]; then
      ask REPO_KEYRING "Path of the repository keyring on this host (distributed via config management)" "${REPO_KEYRING:-$APT_KEYRING_DEFAULT}" v_keyring || return 1
    fi
  else REPO_SIGNED=no; fi
  seg=$([[ $SITE == dr ]] && echo dr-live || echo prod-live); site_label=$([[ $SITE == dr ]] && echo dr || echo primary)
  def_name=${AGENT_NAME:-$(yaml_get agent_name)}
  if [[ -z $def_name ]]; then
    if [[ $(hostname -s) == bp-gw-* ]]; then def_name=$(hostname -s); else def_name=$([[ $SITE == dr ]] && echo bp-gw-drlive-01 || echo bp-gw-live-01); fi
  fi
  # switching site? swap the runbook default name
  [[ $SITE == dr && $def_name == bp-gw-live-01 ]] && def_name=bp-gw-drlive-01
  [[ $SITE == primary && $def_name == bp-gw-drlive-01 ]] && def_name=bp-gw-live-01
  ask AGENT_NAME "Agent name shown in the console" "$def_name" v_agent_name || return 1
  def_labels=${AGENT_LABELS:-"site=$site_label,segment=$seg,role=gateway"}
  [[ -n $AGENT_LABELS && $AGENT_LABELS != *"segment=$seg"* ]] && def_labels="site=$site_label,segment=$seg,role=gateway"
  ask AGENT_LABELS "Agent labels (§8.5 scheme - configurations are assigned by these)" "$def_labels" v_labels || return 1
  if ufw_active; then
    say "  ufw is active here: rules will allow only these sources to reach $LIVE_GW_IP."
    [[ $FW_SOURCES == none ]] && FW_SOURCES=""
    ask FW_SOURCES "Allowed sources (IPs/CIDRs of the LIVE log-source subnets)" "$FW_SOURCES" v_sources || return 1
    ask FW_PORTS "TCP ports to allow from them" "${FW_PORTS:-$OPAMP_PORT $REPO_PORT $OTLP_PORT}" v_ports || return 1
  else
    FW_SOURCES=${FW_SOURCES:-none}; FW_PORTS=${FW_PORTS:-"$OPAMP_PORT $REPO_PORT $OTLP_PORT"}
  fi
  ask HAPROXY_MAXCONN "HAProxy maxconn (>= 2x projected agents in this segment; 20000 supports ~10,000)" "${HAPROXY_MAXCONN:-20000}" v_maxconn || return 1
  ask_yn_var MIRROR_TIMER "Schedule a daily mirror sync from the DMZ (systemd timer)? Manual: $MIRROR_SYNC" no
  ask_yn_var PAUSE_BETWEEN_STEPS "Pause for confirmation between steps?" no
  return 0
}

config_complete() {
  local k
  for k in SITE LIVE_GW_IP DMZ_GW_IP BP_VERSION PKG_SOURCE REPO_SIGNED AGENT_NAME AGENT_LABELS FW_SOURCES FW_PORTS HAPROXY_MAXCONN MIRROR_TIMER PAUSE_BETWEEN_STEPS; do
    [[ -n ${!k-} ]] || return 1
  done
  [[ $REPO_SIGNED != yes || -n $REPO_KEYRING ]]
}

confirm_config() {
  local c
  while :; do
    banner_line "Please review"
    show_config
    if (( ASSUME_YES )) || [[ -z $TTY ]]; then return 0; fi
    c=$(choose "  Proceed with these values? [y]es / [e]dit / [q]uit: " yeq y)
    case $c in y) return 0 ;; e) gather_config || return 1 ;; q) return 1 ;; esac
  done
}

# Steps whose result depends on a changed answer are re-run automatically.
declare -A DEPENDS=(
  [SITE]="evidence"
  [LIVE_GW_IP]="preflight nginx haproxy_config host_firewall haproxy_start probe_chain evidence"
  [DMZ_GW_IP]="preflight dmz_path apt_source mirror haproxy_config haproxy_start probe_chain collector_config collector_verify evidence"
  [BP_VERSION]="dmz_path collector_install collector_verify evidence"
  [PKG_SOURCE]="dmz_path apt_source os_packages" [REPO_SIGNED]="apt_source os_packages" [REPO_KEYRING]="apt_source os_packages"
  [AGENT_NAME]="collector_config collector_verify evidence" [AGENT_LABELS]="collector_config collector_verify evidence"
  [FW_SOURCES]="host_firewall" [FW_PORTS]="host_firewall"
  [HAPROXY_MAXCONN]="haproxy_config haproxy_start probe_chain"
  [MIRROR_TIMER]="mirror"
)
declare -A OLD_CONF=()
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

# =============================================================================
#  Step runner
# =============================================================================
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

needs_secret() { # true if a pending/forced step will need the secret key
  local s
  for s in probe_chain collector_config; do
    if [[ -n ${FORCED[$s]-} || $(state_get "$s") != "done" ]]; then
      if [[ -z $ONLY_STEP || $ONLY_STEP == "$s" ]]; then return 0; fi
    fi
  done
  return 1
}

final_summary() {
  banner_line "Result"
  show_progress
  echo
  show_gates
  echo
  say "  Mirror          : http://$LIVE_GW_IP:$REPO_PORT/   ($REPO_ROOT; refresh with $MIRROR_SYNC)"
  say "  OpAMP relay     : ws://$LIVE_GW_IP:$OPAMP_PORT/v1/opamp  ->  hop 1 ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp"
  say "  This collector  : $AGENT_NAME  ->  ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp"
  say "  HAProxy stats   : curl -s '$STATS_URL'   (loopback only)"
  say "  Hand-off notes  : $NEXT_STEPS_FILE"
  say "  This run's log  : $LOG_FILE"
  say "  Health check    : $0 --diagnose"
}

action_build() {
  local had=0 list=() s found=0
  init_defaults
  load_config && had=1
  snapshot_config
  if (( ! had || RECONFIGURE )) || ! config_complete; then
    (( had )) && (( ! RECONFIGURE )) && info "Some answers are missing - asking for them now."
    gather_config || { err "Configuration was not completed - nothing changed."; exit 1; }
    confirm_config || { info "Stopped before making changes."; exit 0; }
    save_config; ok "Answers saved to $CONF_FILE (root-only, mode 0600; the secret key is not stored there)"
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

  if [[ -n $ONLY_STEP ]]; then list=("$ONLY_STEP"); FORCED[$ONLY_STEP]=1
  elif [[ -n $FROM_STEP ]]; then
    for s in "${STEPS[@]}"; do [[ $s == "$FROM_STEP" ]] && found=1; (( found )) && { list+=("$s"); FORCED[$s]=1; }; done
  else list=("${STEPS[@]}"); fi

  banner_line "Progress"
  show_progress
  if [[ -z $ONLY_STEP && -z $FROM_STEP ]] && all_steps_settled; then
    echo; ok "Every step is already complete."
    hint "Health check: $0 --diagnose   |   re-run one step: $0 --only STEP   |   from a step: $0 --from STEP"
    show_gates; return 0
  fi
  if needs_secret; then ensure_secret || { print_block "Problem" "$FAIL_WHAT"; exit 1; }; fi
  run_steps "${list[@]}"
  final_summary
}

# =============================================================================
#  Entry point
# =============================================================================
usage() {
  cat <<EOF
$SCRIPT_NAME v$SCRIPT_VERSION - CBSL Bindplane LIVE gateway build (runbook v1.0, Stages 5-6) for Ubuntu

Usage: sudo bash $0 [options]

Build (default): asks for the values it needs, then runs every pending step.
Re-running resumes at the first unfinished step; completed steps are skipped.
  --reconfigure          ask all questions again (previous answers are the defaults)
  --from STEP            re-run STEP and every step after it
  --only STEP            re-run just STEP (e.g. --only probe_chain)
  --pause                pause for confirmation between steps
  -y, --yes              accept saved/default answers; quit on the first failure
                         (set BP_SECRET in the environment if no manager.yaml exists yet)

Operations:
  --status               saved answers, step progress and gate status
  --list-steps           list step names
  --diagnose             read-only health check (troubleshooting flowchart, socket census §12.1)
  --sync-mirror          pull new/changed files from the DMZ repository and verify them
  --upgrade-collector [VER]  offline upgrade from the mirror (§13.3; default: newest mirrored)
  --proxy-debug on|off   temporary HAProxy header capture (remove before handover)
  --rollback             back out this script's changes (asks about collector, apt source, mirror)
  --reset                forget step progress (answers are kept)
  --no-color             plain output
  -h, --help             this help

Files: answers $CONF_FILE (0600) | progress $STATE_FILE | logs $LOG_DIR
Steps: ${STEPS[*]}
EOF
}

parse_args() {
  local need
  while (( $# )); do
    need=0
    case $1 in
      --from)          need=1; FROM_STEP=${2:-} ;;
      --from=*)        FROM_STEP=${1#*=} ;;
      --only)          need=1; ONLY_STEP=${2:-} ;;
      --only=*)        ONLY_STEP=${1#*=} ;;
      --reconfigure)   RECONFIGURE=1 ;;
      --pause)         FORCE_PAUSE=1 ;;
      -y|--yes)        ASSUME_YES=1 ;;
      --status)        ACTION=status ;;
      --list-steps)    ACTION=list ;;
      --diagnose|--diag) ACTION=diagnose ;;
      --sync-mirror)   ACTION=sync ;;
      --upgrade-collector) ACTION=upgrade; if [[ -n ${2:-} && ${2:0:1} != - ]]; then ACTION_ARG=$2; shift; fi ;;
      --upgrade-collector=*) ACTION=upgrade; ACTION_ARG=${1#*=} ;;
      --proxy-debug)   need=1; ACTION=proxydebug; ACTION_ARG=${2:-} ;;
      --rollback)      ACTION=rollback ;;
      --reset)         ACTION=reset ;;
      --no-color)      USE_COLOR=0 ;;
      -h|--help)       ACTION=help ;;
      --version)       echo "$SCRIPT_NAME $SCRIPT_VERSION"; exit 0 ;;
      *) echo "Unknown option: $1   (see --help)" >&2; exit 2 ;;
    esac
    if (( need )); then
      [[ -n ${2:-} && ${2:0:1} != - ]] || { echo "Option $1 needs a value (see --help)" >&2; exit 2; }
      shift
    fi
    shift
  done
  local m
  for m in "$FROM_STEP" "$ONLY_STEP"; do
    [[ -z $m ]] || v_step "$m" >/dev/null || { v_step "$m" >&2; exit 2; }
  done
}

on_signal() {
  local sig=$1
  trap '' INT TERM HUP
  [[ -n $TTY ]] && stty echo <"$TTY" 2>/dev/null
  echo
  warn "Received SIG$sig - stopping safely."
  unblock_service_autostart
  [[ -n $CURRENT_STEP ]] && state_set "$CURRENT_STEP" interrupted
  info "Progress is saved. Re-run the script to resume${CURRENT_STEP:+ at: ${STEP_TITLE[$CURRENT_STEP]}}."
  [[ -n $LOG_FILE ]] && info "Log: $LOG_FILE"
  exit 130
}

on_exit() {
  unblock_service_autostart
  [[ -n $RUN_TMP && -d $RUN_TMP ]] && rm -rf "$RUN_TMP"
}

main() {
  local c miss=""
  parse_args "$@"
  setup_colors
  [[ $ACTION == help ]] && { usage; exit 0; }
  (( EUID == 0 )) || { echo "This script must run as root:  sudo bash $0 $*" >&2; exit 1; }
  for c in systemctl journalctl ss ip awk sed grep flock sha256sum stat df mktemp timeout curl dpkg-query apt-get; do command -v "$c" >/dev/null || miss+=" $c"; done
  if [[ -n $miss ]]; then
    echo "Missing required commands:$miss" >&2
    [[ $miss == *curl* ]] && echo "curl ships with Ubuntu Server; install it from the DMZ repository, e.g.: apt-get -o Dir::Etc::sourcelist=<list with the DMZ repo> -o Dir::Etc::sourceparts=- install curl" >&2
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
  unblock_service_autostart

  banner_line "CBSL Bindplane - LIVE gateway build   ($SCRIPT_NAME v$SCRIPT_VERSION, runbook v1.0 Stages 5-6)"
  say "  Host: $(hostname -s)   Action: $ACTION   Log: $LOG_FILE"
  log "args: $*"
  if [[ $ACTION == build && -n ${SSH_CONNECTION:-} && -z ${TMUX:-}${STY:-} ]]; then
    say "  Tip: over SSH, run inside tmux or screen. If the session drops, re-run the script - it resumes."
  fi

  case $ACTION in
    build)      action_build ;;
    status)     action_status ;;
    list)       action_list ;;
    diagnose)   action_diagnose ;;
    sync)       action_sync_mirror ;;
    upgrade)    action_upgrade_collector ;;
    proxydebug) action_proxy_debug ;;
    rollback)   action_rollback ;;
    reset)      action_reset ;;
  esac
}

main "$@"

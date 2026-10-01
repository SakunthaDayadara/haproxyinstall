#!/usr/bin/env bash
# =============================================================================
#  bp-dmz-setup.sh  -  CUSTOMER Bindplane: DMZ gateway build (Ubuntu)
# =============================================================================
#  Implements the DMZ-side stages of "CUSTOMER Bindplane Deployment - Production
#  Command Runbook v1.0" on bp-gw-dmz-01 (or bp-gw-drdmz-01 for DR):
#
#    Pre-flight ........ host baseline + Stage 1 gate checks (§1.3 / §1.4)
#    Stage 2 ........... offline package origin for the isolated segments:
#                        collector artefacts, local apt repository, checksums,
#                        nginx file server bound to the DMZ_GW_IP:8080 only
#    Stage 3 ........... HAProxy OpAMP relay hop 1 on DMZ_GW_IP:3001
#    Stage 4 ........... validation: synthetic probe (§4.1-4.3) and the
#                        definitive "real collector through the hop" test (§4.4)
#
#  Stage 1 (the DMZ collector itself) must already be installed and Connected;
#  this script only verifies it.
#
#  Design goals
#    * interactive: asks for every value it needs, offers detected defaults
#    * resumable:   progress is saved after every step; re-running resumes at
#                   the first unfinished step. Ctrl+C / SSH drop is safe.
#    * explainable: every failure prints what happened, the likely cause and
#                   how to fix it, and offers retry / diagnostics / skip / quit
#    * idempotent:  every step can be re-run safely
#
#  Usage:  sudo bash bp-dmz-setup.sh            (then follow the prompts)
#          sudo bash bp-dmz-setup.sh --help     (all options)
# =============================================================================

SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="bp-dmz-setup"

set -uo pipefail
umask 022
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

# ----------------------------------------------------------------------------
# Fixed paths and ports (runbook values). Paths can be overridden via env.
# ----------------------------------------------------------------------------
STATE_DIR=${BP_STATE_DIR:-/var/lib/bp-dmz-setup}
LOG_DIR=${BP_LOG_DIR:-/var/log/bp-dmz-setup}
REPO_ROOT=${BP_REPO_ROOT:-/srv/bindplane}
CONF_FILE="$STATE_DIR/setup.conf"
STATE_FILE="$STATE_DIR/progress"
MANIFEST="$STATE_DIR/artefacts.manifest"
UFW_RECORD="$STATE_DIR/ufw-rules.added"
HOP_MARKER="$STATE_DIR/hop-test.in-progress"
GNUPG_DIR="$STATE_DIR/gnupg"
LOCK_FILE="/run/$SCRIPT_NAME.lock"
EVIDENCE_DIR="$LOG_DIR/evidence"
NEXT_STEPS_FILE="$LOG_DIR/NEXT-STEPS-LIVE-GATEWAY.txt"

COLLECTOR_HOME=${BP_COLLECTOR_HOME:-/opt/observiq-otel-collector}
COLLECTOR_SVC="observiq-otel-collector"
MANAGER_YAML="$COLLECTOR_HOME/manager.yaml"
COLLECTOR_LOG="$COLLECTOR_HOME/log/collector.log"
COLLECTOR_BIN="$COLLECTOR_HOME/observiq-otel-collector"

HAPROXY_CFG="/etc/haproxy/haproxy.cfg"
HAPROXY_DROPIN_DIR="/etc/systemd/system/haproxy.service.d"
HAPROXY_DROPIN="$HAPROXY_DROPIN_DIR/limits.conf"
NGINX_SITE="/etc/nginx/sites-available/bindplane-repo"
NGINX_LINK="/etc/nginx/sites-enabled/bindplane-repo"
NGINX_ACCESS_LOG="/var/log/nginx/bindplane-repo.access.log"
NGINX_ERROR_LOG="/var/log/nginx/bindplane-repo.error.log"

CA_BASE="/etc/ssl/certs"                       # Ubuntu row of the §3.3 table
CA_FILE="/etc/ssl/certs/ca-certificates.crt"

OPAMP_PORT=3001
OTLP_PORT=4317
REPO_PORT=8080
STATS_PORT=8404
STATS_URL="http://127.0.0.1:${STATS_PORT}/stats;csv"

GH_REPO="observIQ/bindplane-otel-collector"
GH_API="https://api.github.com/repos/$GH_REPO"
GH_DL="https://github.com/$GH_REPO/releases/download"
BDOT_CDN="https://bdot.bindplane.com"

# Build steps in execution order ------------------------------------------------
STEPS=(preflight base_packages repo_layout collector_artefacts os_repo checksums
       nginx haproxy_install haproxy_config haproxy_limits host_firewall
       haproxy_start probe_hop1 collector_via_hop1 evidence)
declare -A STEP_TITLE=(
  [preflight]="Pre-flight checks and Stage 1 baseline"
  [base_packages]="Base packages"
  [repo_layout]="Repository layout under $REPO_ROOT"
  [collector_artefacts]="Download collector artefacts (Linux/ARM/Windows)"
  [os_repo]="Local apt repository (nginx, haproxy, wget + deps)"
  [checksums]="Repository checksums (SHA256SUMS)"
  [nginx]="Serve the repository with nginx on :$REPO_PORT"
  [haproxy_install]="Install HAProxy"
  [haproxy_config]="HAProxy hop 1 configuration"
  [haproxy_limits]="HAProxy file-descriptor limits"
  [host_firewall]="Host firewall (ufw)"
  [haproxy_start]="Start HAProxy and check the cloud backend"
  [probe_hop1]="Validate hop 1: synthetic OpAMP probe"
  [collector_via_hop1]="Validate hop 1: real collector through the hop"
  [evidence]="Evidence pack and LIVE-gateway hand-off notes"
)
declare -A STEP_REF=(
  [preflight]="Pre-flight, §1.3, §1.4"   [base_packages]="§1.1, §2.3"
  [repo_layout]="§2.1"                   [collector_artefacts]="§2.2"
  [os_repo]="§2.3, §5.4"                 [checksums]="§2.4"
  [nginx]="§2.5, §2.7"                   [haproxy_install]="§3.2"
  [haproxy_config]="§3.1, §3.3, §3.4"    [haproxy_limits]="§3.5"
  [host_firewall]="§3.6 (Ubuntu equivalent)" [haproxy_start]="§3.7"
  [probe_hop1]="§4.1, §4.2, §4.3"        [collector_via_hop1]="§4.4"
  [evidence]="§12.4"
)

# Saved answers (persisted in $CONF_FILE) -----------------------------------------
CONF_KEYS=(SITE BP_CLOUD_HOST BP_SECRET BP_VERSION DMZ_GW_IP LIVE_GW_IP
           FW_SOURCES FW_PORTS HAPROXY_MAXCONN STAGE_RPM STAGE_ARM64
           STAGE_WINDOWS BUILD_APT_REPO EXTRA_APT_PKGS SIGN_APT_REPO DL_PROXY
           PAUSE_BETWEEN_STEPS PROXY_DEBUG)

init_defaults() {
  SITE="" BP_CLOUD_HOST="" BP_SECRET="" BP_VERSION="" DMZ_GW_IP="" LIVE_GW_IP=""
  FW_SOURCES="" FW_PORTS="" HAPROXY_MAXCONN="" STAGE_RPM="" STAGE_ARM64=""
  STAGE_WINDOWS="" BUILD_APT_REPO="" EXTRA_APT_PKGS="" SIGN_APT_REPO=""
  DL_PROXY="" PAUSE_BETWEEN_STEPS="" PROXY_DEBUG="no"
}

# Runtime globals -------------------------------------------------------------------
ACTION="build"; ACTION_ARG=""; FROM_STEP=""; ONLY_STEP=""
ASSUME_YES=0; RECONFIGURE=0; FORCE_PAUSE=0; USE_COLOR=1; FORCE_ALL=0
CURRENT_STEP=""; HOP_TEST_ACTIVE=0; DL_PID=""; POLICY_RC_CREATED=0
FAIL_WHAT=""; FAIL_WHY=""; FAIL_FIX=""; LAST_OUT=""
RUN_TS=$(date +%Y%m%d-%H%M%S)
LOG_FILE=""; RUN_TMP=""; TTY=""; TTY_OUT=0
DET_CLOUD_HOST=""; DET_SECRET=""; DET_VERSION=""; DET_PROXY=""
UPSTREAM_SUMS=""; REL_ASSETS=""; REL_ASSETS_KNOWN=0
CURL_PROXY_OPTS=(); APT_PROXY_OPTS=()

# =============================================================================
#  Output, logging and prompts
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

# --- prompts (always read from the terminal, never from a pipe) ------------------
# ask VAR "prompt" "default" [validator] [optional]
#   optional=1 lets the user type "none" (or "-") to clear the value.
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
v_host()   { [[ $1 =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]] || { echo "'$1' is not a valid DNS host name (no scheme, no path), e.g. app.bindplane.com"; return 1; }; }
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
v_proxy()  { [[ -z $1 || $1 =~ ^https?://[^[:space:]]+$ ]] || { echo "Use the form http://proxy.example:8080 (or 'none')."; return 1; }; }
v_pkgs()   { [[ -z $1 || $1 =~ ^[a-z0-9][a-z0-9+.-]*([[:space:]]+[a-z0-9][a-z0-9+.-]*)*$ ]] || { echo "Space-separated Ubuntu package names only."; return 1; }; }
v_step()   { contains_word "${STEPS[*]}" "$1" || { echo "Unknown step '$1'. Steps: ${STEPS[*]}"; return 1; }; }

# =============================================================================
#  Config and progress state
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
ADHOC=0   # --fetch-version: steps run outside the build's progress tracking
state_set() {
  (( ADHOC )) && return 0
  local tmp
  tmp=$(mktemp "$STATE_DIR/.progress.XXXXXX") || return 1
  { [[ -f $STATE_FILE ]] && grep -v "^$1|" "$STATE_FILE"; printf '%s|%s|%s\n' "$1" "$2" "$(date -Is)"; } >"$tmp"
  chmod 600 "$tmp"; mv -f "$tmp" "$STATE_FILE"
  log "STATE $1=$2"
}
step_index() { local i; for i in "${!STEPS[@]}"; do [[ ${STEPS[$i]} == "$1" ]] && { echo $((i+1)); return; }; done; echo 0; }

manifest_get() { [[ -f $MANIFEST ]] && awk -F'|' -v r="$1" '$1==r{v=$2"|"$3} END{print v}' "$MANIFEST"; return 0; }
manifest_set() {
  local tmp; tmp=$(mktemp "$STATE_DIR/.manifest.XXXXXX")
  { [[ -f $MANIFEST ]] && awk -F'|' -v r="$1" '$1!=r' "$MANIFEST"; printf '%s|%s|%s\n' "$1" "$2" "$3"; } >"$tmp"
  chmod 600 "$tmp"; mv -f "$tmp" "$MANIFEST"
}
manifest_del() {
  [[ -f $MANIFEST ]] || return 0
  local tmp; tmp=$(mktemp "$STATE_DIR/.manifest.XXXXXX")
  awk -F'|' -v r="$1" '$1!=r' "$MANIFEST" >"$tmp"; chmod 600 "$tmp"; mv -f "$tmp" "$MANIFEST"
}

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

set_proxy_opts() {
  CURL_PROXY_OPTS=(); APT_PROXY_OPTS=()
  if [[ -n ${DL_PROXY:-} ]]; then
    CURL_PROXY_OPTS=(--proxy "$DL_PROXY")
    APT_PROXY_OPTS=(-o "Acquire::http::Proxy=$DL_PROXY" -o "Acquire::https::Proxy=$DL_PROXY")
  fi
}

# apt-get wrapper with lock wait, proxy and failure explanation
apt_get() {
  local desc=$1; shift
  run_stream "$desc" apt-get -q -o DPkg::Lock::Timeout=300 \
      -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
      "${APT_PROXY_OPTS[@]}" "$@" && return 0
  explain_apt_failure "$LAST_OUT"
  return 1
}

explain_apt_failure() {
  local f=$1
  if grep -qE 'Temporary failure resolving|Could not resolve' "$f"; then
    fail "apt could not resolve the Ubuntu mirror host names." \
         "DNS on this host cannot resolve external names, or the Checkpoint blocks DNS." \
         "Check: resolvectl status; getent hosts archive.ubuntu.com\nIf egress must go through a forward proxy, re-run with --reconfigure and set it."
  elif grep -qE 'Could not connect|Connection timed out|Unable to connect|Connection failed|Network is unreachable|407' "$f"; then
    fail "apt could not connect to the Ubuntu mirrors." \
         "The Checkpoint does not permit HTTP/HTTPS from this host to the Ubuntu mirrors, or a forward proxy is required (407 = proxy wants credentials)." \
         "Ask the network team to permit archive.ubuntu.com / security.ubuntu.com (or CUSTOMER's internal mirror),\nor re-run with --reconfigure and set the outbound proxy (http://user:pass@host:port if it needs auth)."
  elif grep -qE '^(Err|E):.* (40[0-9]|50[0-9]) [A-Z]' "$f" || grep -qE '^  +(40[0-9]|50[0-9]) +[A-Z][a-z]' "$f"; then
    fail "The mirror or proxy refused apt's requests: $(grep -m1 -oE '(40[0-9]|50[0-9]) +[A-Za-z ]+' "$f" | head -n1 | sed -E 's/ +/ /g; s/ $//')." \
         "403/405: the forward proxy does not allow apt's plain-HTTP requests, or URL filtering blocks the mirror. 407: the proxy wants credentials. 5xx: mirror/proxy fault.\nThe 'no longer signed' lines that follow are a consequence, not a separate problem." \
         "If this host does not need a proxy for the Ubuntu mirrors: re-run with --reconfigure and set the proxy to 'none'.\nOtherwise ask for the mirrors to be allowed through the proxy, or use CUSTOMER's internal mirror."
  elif grep -qE 'Could not get lock|Unable to acquire the dpkg frontend lock|is another process using it' "$f"; then
    fail "Another apt/dpkg process held the package lock for more than 5 minutes." \
         "unattended-upgrades or another admin session is installing packages." \
         "See what is running: ps -ef | grep -E 'apt|dpkg' | grep -v grep\nWait for it to finish, then choose [r] to retry."
  elif grep -q 'dpkg was interrupted' "$f"; then
    fail "dpkg reports an earlier interrupted installation." "A previous package installation was killed part-way." "Run: dpkg --configure -a   then choose [r] to retry."
  elif grep -qE 'Unable to locate package|has no installation candidate|no installation candidate' "$f"; then
    fail "apt cannot find one of the requested packages." \
         "The package lists are stale or empty (apt-get update failed earlier), or the 'main'/'universe' components are not enabled." \
         "Run: apt-get update   and read any W:/E: lines; check /etc/apt/sources.list(.d)."
  elif grep -qE 'Hash Sum mismatch|File has unexpected size' "$f"; then
    fail "apt downloaded a file whose checksum did not match." \
         "A mirror was mid-sync, or a TLS/HTTP-inspecting proxy altered the content." "Wait a few minutes and retry; if it persists, check content inspection on the proxy."
  elif grep -qE 'NO_PUBKEY|is not signed|EXPKEYSIG' "$f"; then
    fail "apt rejected a repository signature." "A configured repository's signing key is missing or expired." "Fix or disable the offending repository listed above, then retry."
  elif grep -qE 'No space left on device' "$f"; then
    fail "The disk is full." "Not enough free space for the package cache or $REPO_ROOT." "Check: df -h /var /srv ; apt-get clean"
  elif grep -qE 'unmet dependencies|held broken packages' "$f"; then
    fail "apt could not resolve package dependencies." "Held packages or a partial upgrade on this host." "Run: apt-get -f install ; apt-mark showhold"
  else
    fail "apt-get failed." "First error: $(grep -m1 '^E:' "$f" || echo 'see the output above')" "Fix the reported problem, then choose [r] to retry."
  fi
}

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

# --- downloads ----------------------------------------------------------------
# download URL DEST LABEL  -> sets DL_RC DL_CODE DL_ERR ; resumes partial files
download() {
  local url=$1 dest=$2 label=$3 attempt size
  local errf="$RUN_TMP/dl.err" codef="$RUN_TMP/dl.code"
  for attempt in 1 2; do
    : >"$errf"; : >"$codef"
    curl -fL -sS --connect-timeout 20 --retry 3 --retry-delay 5 --speed-limit 1024 --speed-time 60 \
         "${CURL_PROXY_OPTS[@]}" -C - -o "$dest" -w '%{http_code}' "$url" >"$codef" 2>"$errf" 9>&- &
    DL_PID=$!
    while kill -0 "$DL_PID" 2>/dev/null; do
      if (( TTY_OUT )); then
        size=$(stat -c %s "$dest" 2>/dev/null || echo 0)
        printf '\r      downloading %s ... %s     ' "$label" "$(human "$size")"
      fi
      sleep 1
    done
    wait "$DL_PID"; DL_RC=$?; DL_PID=""
    (( TTY_OUT )) && printf '\r\e[K'
    DL_CODE=$(cat "$codef" 2>/dev/null); DL_ERR=$(tail -n 3 "$errf" 2>/dev/null)
    log "DOWNLOAD $url -> rc=$DL_RC http=$DL_CODE err=$DL_ERR"
    # 33/36 or HTTP 416 = resume not possible -> start again from zero
    if (( attempt == 1 )) && { (( DL_RC == 33 || DL_RC == 36 )) || [[ $DL_CODE == 416 ]]; }; then
      rm -f "$dest"; continue
    fi
    break
  done
  return "$DL_RC"
}

# explain_curl RC HTTP_CODE URL  -> fills FAIL_* (always returns 1)
explain_curl() {
  local rc=$1 code=${2:-} url=$3 host
  host=${url#*://}; host=${host%%/*}
  case $rc in
    5)  fail "Could not resolve the proxy host ($DL_PROXY)." "The configured outbound proxy name does not resolve." "Re-run with --reconfigure and correct the proxy, or set it to 'none'." ;;
    6)  fail "Could not resolve $host." "DNS on this host cannot resolve external names." "Check: getent hosts $host ; resolvectl status\nOr configure an outbound proxy with --reconfigure." ;;
    7)  fail "Could not connect to $host (connection refused or blocked)." \
             "The Checkpoint does not permit HTTPS from this host to $host, or a forward proxy is mandatory." \
             "Downloads need HTTPS to: github.com, objects.githubusercontent.com (release downloads redirect there),\napi.github.com and bdot.bindplane.com. Ask the network team, or set a proxy with --reconfigure." ;;
    28) fail "The download from $host timed out." \
             "A firewall is silently dropping the traffic, or the link is slower than 1 KB/s for 60s." \
             "Try: curl -sSI https://$host  ; raise with the network team. Partial files are kept and resumed on retry." ;;
    35|58|59|60|77|83|90|91)
        fail "TLS to $host failed (curl exit $rc)." \
             "TLS inspection is active on this destination and the inspection CA is not trusted by this host (runbook §1.4)." \
             "Check the issuer: echo | openssl s_client -connect $host:443 -servername $host 2>/dev/null | openssl x509 -noout -issuer\nEither request an inspection bypass, or install the CA: cp ca.crt /usr/local/share/ca-certificates/ && update-ca-certificates" ;;
    18|56|92|16)
        fail "The connection to $host was cut mid-transfer (curl exit $rc)." "An IPS/proxy reset the connection, or the link dropped." "Choose [r] to retry - the partial file is resumed." ;;
    23) fail "Could not write the downloaded file." "Disk full or $REPO_ROOT not writable." "Check: df -h $REPO_ROOT" ;;
    22) case $code in
          404) fail "HTTP 404 from $host: the file does not exist." "Version $BP_VERSION does not match a published release tag, or the asset name changed." \
                    "Check the release page: https://github.com/$GH_REPO/releases/tag/$BP_VERSION\n$( [[ $ACTION == build ]] && echo 'Re-run with --reconfigure to change the version.' || echo 'Use the exact tag, e.g. v1.108.1.')" ;;
          403) fail "HTTP 403 from $host." "A proxy/URL-category filter blocks GitHub downloads, or GitHub rate-limited this address." "Try again later, or ask for github.com and objects.githubusercontent.com to be permitted." ;;
          407) fail "HTTP 407: the proxy requires authentication." "The forward proxy wants credentials." "Re-run with --reconfigure and set the proxy as http://user:password@host:port" ;;
          5*)  fail "HTTP $code from $host." "Upstream (GitHub/CDN) server error." "Wait a few minutes and choose [r] to retry." ;;
          *)   fail "HTTP error $code from $host." "See the curl error above." "Check the URL manually: curl -sSIL '$url'" ;;
        esac ;;
    *)  fail "Download from $host failed (curl exit $rc: ${DL_ERR:-no detail})." "See 'man curl' EXIT CODES for $rc." "Test manually: curl -sSIL '$url'" ;;
  esac
}

# validate_kind FILE KIND -> prints a reason and returns 1 when the file is wrong
validate_kind() {
  local f=$1 kind=$2 magic head
  [[ -s $f ]] || { echo "file is empty"; return 1; }
  magic=$(od -An -tx1 -N8 "$f" | tr -d ' \n')
  head=$(head -c 200 "$f" | tr -d '\0' | tr '\n' ' ')
  if [[ ${head,,} == *"<html"* || ${head,,} == *"<!doctype"* ]]; then
    echo "got an HTML page instead of the file (a proxy block page or captive portal?): ${head:0:120}"; return 1
  fi
  case $kind in
    deb-amd64|deb-arm64)
      local pkg arch
      pkg=$(dpkg-deb -f "$f" Package 2>/dev/null) || { echo "not a valid Debian package"; return 1; }
      arch=$(dpkg-deb -f "$f" Architecture 2>/dev/null)
      [[ $pkg == observiq-otel-collector ]] || { echo "package name is '$pkg', expected observiq-otel-collector"; return 1; }
      [[ $arch == "${kind#deb-}" ]] || { echo "architecture is '$arch', expected ${kind#deb-}"; return 1; } ;;
    rpm)  [[ $magic == edabeedb* ]] || { echo "not an RPM package (magic $magic)"; return 1; } ;;
    msi)  [[ $magic == d0cf11e0a1b11ae1 ]] || { echo "not a Windows MSI (magic $magic)"; return 1; } ;;
    sh)   [[ $(head -c 2 "$f") == '#!' ]] || { echo "not a shell script"; return 1; } ;;
    ps1)  : ;;
    sums) grep -qE '^[0-9a-f]{64}[[:space:]]+' "$f" || { echo "not a SHA256SUMS file"; return 1; } ;;
  esac
  return 0
}

# =============================================================================
#  Detection helpers
# =============================================================================
yaml_get() { # top-level key from manager.yaml
  [[ -r $MANAGER_YAML ]] || return 0
  sed -nE "s/^$1:[[:space:]]*//p" "$MANAGER_YAML" | head -n1 | sed -E "s/[[:space:]]+#.*$//; s/^[\"']//; s/[\"'][[:space:]]*$//"
}
endpoint_host() { local h=${1#*://}; h=${h%%/*}; h=${h%%:*}; printf '%s' "$h"; }

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

detect_defaults() {
  local ep
  ep=$(yaml_get endpoint)
  if [[ -n $ep && $ep == wss://* ]]; then DET_CLOUD_HOST=$(endpoint_host "$ep"); fi
  DET_SECRET=$(yaml_get secret_key)
  DET_VERSION=$(collector_version)
  DET_PROXY=${https_proxy:-${HTTPS_PROXY:-}}
  if [[ -z $DET_PROXY ]]; then
    DET_PROXY=$(collector_unit_env | tr ' ' '\n' | sed -nE 's/^(HTTPS_PROXY|https_proxy)=//p' | head -n1)
  fi
  if [[ -z $DET_PROXY ]] && command -v apt-config >/dev/null; then
    DET_PROXY=$(apt-config dump 2>/dev/null | sed -nE 's/^Acquire::https?::Proxy "(https?:[^"]+)";/\1/p' | head -n1)
  fi
}

# =============================================================================
#  Checks shared by pre-flight and --diagnose (print their own result lines)
# =============================================================================
CHK_FAILS=0; CHK_WARNS=0
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

check_collector() {
  local st v ep sk aid errs
  if [[ ! -d $COLLECTOR_HOME ]] || ! systemctl cat "$COLLECTOR_SVC" >/dev/null 2>&1; then
    c_fail "Collector not installed ($COLLECTOR_HOME or $COLLECTOR_SVC.service missing)"
    hint "Stage 1 (§1.2) must be completed on this host first."
    return 1
  fi
  st=$(systemctl is-active "$COLLECTOR_SVC" 2>/dev/null)
  if [[ $st == active ]]; then c_ok "Collector service $COLLECTOR_SVC is active"
  else c_fail "Collector service is '$st'"; hint "journalctl -u $COLLECTOR_SVC -n 50 --no-pager ; tail -n 50 $COLLECTOR_LOG"; fi
  v=$(collector_version); [[ -n $v ]] && c_ok "Collector version: $v" || c_warn "Could not read the collector version"
  if [[ ! -r $MANAGER_YAML ]]; then c_fail "$MANAGER_YAML is missing"; return 1; fi
  ep=$(yaml_get endpoint); sk=$(yaml_get secret_key); aid=$(yaml_get agent_id)
  [[ -n $ep ]] && c_ok "manager.yaml endpoint: $ep" || c_fail "manager.yaml has no endpoint"
  [[ -n $sk ]] && c_ok "manager.yaml secret_key present ($(mask "$sk"))" || c_fail "manager.yaml has no secret_key"
  if [[ -n $aid ]]; then c_ok "manager.yaml agent_id: $aid"
  else c_warn "manager.yaml has no agent_id - the collector has never connected successfully"; hint "§1.3: the console must list this host as Connected before you continue."; fi
  if [[ $ep == ws://*:$OPAMP_PORT/* ]]; then
    c_warn "The collector points at a relay ($ep), not directly at the cloud"
    hint "Left over from a §4.4 test? The direct copy is $MANAGER_YAML.direct"
  fi
  if [[ -r $COLLECTOR_LOG ]]; then
    errs=$(tail -n 200 "$COLLECTOR_LOG" | grep -iE 'error|refused|denied|timeout|unauthor' | tail -n 3)
    if [[ -n $errs ]]; then c_warn "Recent errors in $COLLECTOR_LOG (last 3 shown):"; printf '%s\n' "$errs" | redact_stream | cut -c1-220 | sed 's/^/         /'
    else c_ok "No recent errors in collector.log"; fi
  fi
  if collector_unit_env | grep -qiE 'https?_proxy='; then
    c_warn "The collector service uses a forward proxy (HTTPS_PROXY in its unit)"
    hint "HAProxy hop 1 connects DIRECTLY to the cloud on 443. If direct egress is not permitted, the hop will fail (probe 503, check status L4TOUT/L4CON)."
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

check_dns() {
  local host=$1 addrs
  addrs=$(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')
  if [[ -n $addrs ]]; then c_ok "DNS: $host -> $addrs"; return 0; fi
  c_fail "DNS: cannot resolve $host"
  hint "HAProxy resolves the cloud host via /etc/resolv.conf. Check: getent hosts $host ; resolvectl status"
  return 1
}

# Direct TLS test (no proxy) - exactly the path HAProxy hop 1 will use.
check_tls() {
  local host=$1 outf="$RUN_TMP/tls.out" rc issuer vrc
  timeout 20 openssl s_client -connect "$host:443" -servername "$host" -verify_hostname "$host" \
      -CAfile "$CA_FILE" </dev/null >"$outf" 2>&1; rc=$?
  log_file "$outf"
  issuer=$(openssl x509 -noout -issuer <"$outf" 2>/dev/null | sed 's/^issuer= *//')
  vrc=$(grep -m1 'Verify return code' "$outf" | sed 's/^ *//')
  if [[ $vrc == *"Verify return code: 0 (ok)"* ]]; then
    c_ok "TLS: direct connection to $host:443 verifies (issuer: ${issuer:-?})"; return 0
  fi
  if (( rc == 124 )) || grep -qiE 'connect:errno|Connection refused|timed out|No route to host|Network is unreachable|BIO_connect|getaddrinfo' "$outf"; then
    c_fail "TLS: cannot open a direct TCP connection to $host:443"
    hint "HAProxy hop 1 connects directly (no forward proxy). The Checkpoint must permit this host -> $host:443."
    hint "If CUSTOMER mandates a forward proxy for this host, hop 1 cannot work as designed - raise it before continuing."
    return 1
  fi
  c_fail "TLS: certificate verification failed for $host ($vrc)"
  if [[ $vrc == *"hostname mismatch"* ]]; then
    hint "The certificate presented does not cover $host: the name resolves to the wrong server, or an inline device presents its own certificate."
  fi
  hint "Issuer seen: ${issuer:-unknown}. An internal-CA issuer means TLS inspection is active (§1.4)."
  hint "HAProxy uses 'verify required' and will return 503 until this passes. Request an inspection bypass,"
  hint "or trust the CA: cp ca.crt /usr/local/share/ca-certificates/ && update-ca-certificates"
  return 1
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

check_disk() {
  local path=$REPO_ROOT avail
  while [[ ! -e $path ]]; do path=$(dirname "$path"); done
  avail=$(df -Pk "$path" | awk 'NR==2{print $4}')
  avail=$((avail*1024))
  if (( avail < 600*1024*1024 )); then c_fail "Only $(human $avail) free on the filesystem holding $REPO_ROOT (need ~2 GB)"; return 1
  elif (( avail < 2*1024*1024*1024 )); then c_warn "$(human $avail) free for $REPO_ROOT - ~2 GB recommended (more if you keep several versions)"
  else c_ok "$(human $avail) free for $REPO_ROOT"; fi
}

check_ip_forward() {
  if [[ $(sysctl -n net.ipv4.ip_forward 2>/dev/null) == 1 ]]; then
    c_warn "net.ipv4.ip_forward=1 - a gateway proxy host should not route packets between segments"
    hint "If nothing else needs it: sysctl -w net.ipv4.ip_forward=0 (and persist in /etc/sysctl.d)"
  else c_ok "IP forwarding is disabled"; fi
}

# =============================================================================
#  HAProxy / nginx helpers
# =============================================================================
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
# Managed by $SCRIPT_NAME v$SCRIPT_VERSION - runbook Stage 3 (OpAMP relay hop 1)
# Generated $(date -Is) on $(hostname -s)
# NOTE: HAProxy has no backslash line continuation - keep each 'server' on ONE line.
# -----------------------------------------------------------------------------
global
    log stdout format raw local0 info
    maxconn ${HAPROXY_MAXCONN}
    ca-base ${CA_BASE}
    ssl-default-server-options ssl-min-ver TLSv1.2
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

resolvers bpdns
    parse-resolv-conf
    resolve_retries 3
    timeout resolve 2s
    timeout retry   2s
    hold valid 30s
    hold other 30s
    hold refused 30s
    hold nx 30s
    hold timeout 30s

frontend opamp_in
    bind ${DMZ_GW_IP}:${OPAMP_PORT}
    option forwardfor
${debug_lines}
    default_backend bindplane_cloud

backend bindplane_cloud
    http-request set-header Host ${BP_CLOUD_HOST}
    server cloud ${BP_CLOUD_HOST}:443 ssl verify required ca-file ${CA_FILE} sni str(${BP_CLOUD_HOST}) alpn http/1.1 resolvers bpdns init-addr last,libc,none check

frontend stats_in
    bind 127.0.0.1:${STATS_PORT}
    stats enable
    stats uri /stats
    stats refresh 10s
EOF
}

render_nginx_site() {
  cat <<EOF
# Managed by $SCRIPT_NAME v$SCRIPT_VERSION - runbook §2.5 (offline package origin)
# Bound to the Fortigate-facing address only - never 0.0.0.0 (§2.7).
server {
    listen ${DMZ_GW_IP}:${REPO_PORT};
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
    # never serve partial downloads or hidden files
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

describe_check_status() {
  local s=${1#\*}; s=$(trim "$s"); s=${s%%[[:space:]]*}
  case $s in
    L4OK|L6OK|L7OK) echo "healthy" ;;
    L4TOUT) echo "TCP connect to $BP_CLOUD_HOST:443 timed out: the Checkpoint is silently dropping this host -> cloud:443." ;;
    L4CON)  echo "TCP connection refused/unreachable: a firewall is rejecting, or there is no route to the internet from this host." ;;
    L6TOUT) echo "TLS handshake timed out: an inline device (TLS inspection/IPS) is holding the handshake." ;;
    L6RSP)  echo "TLS handshake failed: most often certificate verification (TLS inspection with a CA not in $CA_FILE)." ;;
    SOCKERR) echo "local socket error: check file-descriptor limits and journalctl -u haproxy." ;;
    "") echo "no check result yet" ;;
    *) echo "check status '$1'" ;;
  esac
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

explain_haproxy_log_line() {
  local line=$1
  [[ -n $line ]] || { warn "No HAProxy log line found for this request (journalctl -u haproxy -n 20)"; return 1; }
  say "      HAProxy log: $(cut -c1-200 <<<"$line")"
  if [[ $line =~ opamp_in[[:space:]]+([^[:space:]]+)/([^[:space:]]+)[[:space:]]+([-0-9]+/[-0-9]+/[-0-9]+/[-0-9]+/[-0-9]+)[[:space:]]+([0-9]+)[[:space:]]+[0-9]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+([^[:space:]]{4}) ]]; then
    local be=${BASH_REMATCH[1]} sv=${BASH_REMATCH[2]} tm=${BASH_REMATCH[3]} st=${BASH_REMATCH[4]} fl=${BASH_REMATCH[5]}
    say "        backend/server : $be/$sv $( [[ $sv == '<NOSRV>' ]] && echo '<- HAProxy never chose a server (backend DOWN or unresolved)')"
    say "        timers Tq/Tw/Tc/Tr/Tt (ms): $tm $( [[ $tm =~ ^[-0-9]+/[-0-9]+/[0-9]+/[0-9]+/ ]] && echo '<- a real round trip to the cloud happened')"
    say "        status : $st     termination flags: $fl ($(describe_term_flags "$fl"))"
  fi
  return 0
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

# classify_probe -> 0 pass, 1 fail (fills FAIL_*)
classify_probe() {
  local where=$1
  if [[ $PROBE_STATUS == 403 && ${PROBE_VIA,,} == *google* ]]; then
    ok "PASS: 403 with '$PROBE_VIA' - the request traversed hop 1, completed TLS with the right SNI/Host and reached Bindplane Cloud"
    hint "This 403 is Google Cloud Armor rejecting a synthetic handshake - it is the expected pass condition (§4.2)."
    return 0
  fi
  if [[ $PROBE_STATUS == 101 ]]; then ok "PASS: 101 Switching Protocols - the path works and Cloud Armor let the probe through"; return 0; fi
  if [[ $PROBE_STATUS == 404 ]]; then
    fail "Probe returned 404." "Host header or SNI wrong, or the path is not /v1/opamp." \
         "Both 'http-request set-header Host' and 'sni str(...)' must name $BP_CLOUD_HOST (grep -nE 'set-header|sni' $HAPROXY_CFG)."; return 1
  fi
  if [[ $PROBE_STATUS == 503 ]]; then
    local cs; cs=$(stats_field bindplane_cloud cloud check_status)
    fail "Probe returned 503 - HAProxy could not reach the cloud backend." \
         "Backend health check: ${cs:-unknown} - $(describe_check_status "$cs")\nTypical causes: DNS, the Checkpoint rule for this host -> $BP_CLOUD_HOST:443, or certificate verification." \
         "Run: $0 --diagnose   (checks DNS, direct TLS and the backend state)\njournalctl -u haproxy -n 30 --no-pager"; return 1
  fi
  if [[ $PROBE_STATUS == 403 ]]; then
    fail "Probe returned 403 but WITHOUT 'Via: 1.1 google'." \
         "Something other than Bindplane's front end answered - e.g. a TLS-inspecting proxy or a block page." \
         "Inspect the full response in the evidence file and the issuer of the cloud certificate (--diagnose)."; return 1
  fi
  if [[ -n $PROBE_STATUS ]]; then
    fail "Probe returned HTTP $PROBE_STATUS." "Unexpected response from the relay path." "Read the response headers above and the HAProxy log line; run --diagnose."; return 1
  fi
  case $PROBE_RC in
    7)  fail "Connection refused on $where." "HAProxy is not listening on that address." "ss -lntp | grep :$OPAMP_PORT ; systemctl status haproxy" ;;
    28) fail "The probe hung, then timed out." "A firewall is dropping silently rather than rejecting, or the backend connect is hanging." "Raise with the network team; check the backend: $0 --diagnose" ;;
    52) fail "HAProxy closed the connection without a response." "Protocol problem between HAProxy and the cloud (ALPN/TLS)." "journalctl -u haproxy -n 30 --no-pager" ;;
    *)  fail "The probe failed (curl exit $PROBE_RC)." "See the output above." "journalctl -u haproxy -n 30 --no-pager" ;;
  esac
  return 1
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

explain_service_start() { # SERVICE LOGFILE
  local svc=$1 f=$2
  if grep -qE 'Cannot assign requested address' "$f"; then
    fail "$svc could not bind to $DMZ_GW_IP." "That address is not (or no longer) assigned to this host." "ip -br addr ; re-run with --reconfigure to choose the correct address."
  elif grep -qE 'Address already in use' "$f"; then
    fail "$svc could not bind: the port is already in use." "Another process is listening on the same port." "ss -lntp | grep -E ':($OPAMP_PORT|$REPO_PORT|$STATS_PORT) '"
  elif grep -qE 'Cannot raise FD limit|Too many open files|setrlimit' "$f"; then
    fail "$svc could not get enough file descriptors ($(grep -m1 -oE 'limit is [0-9]+' "$f" || echo 'limit too low'))." \
         "HAProxy needs about 2 x maxconn descriptors (maxconn ${HAPROXY_MAXCONN:-?} -> ~$(( ${HAPROXY_MAXCONN:-0} * 2 + 20 ))), but the service limit is lower." \
         "Make sure the §3.5 drop-in is active: systemctl daemon-reload && systemctl show haproxy -p LimitNOFILE\nOr lower maxconn: re-run with --reconfigure."
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

# =============================================================================
#  Artefact helpers (Stage 2.2)
# =============================================================================
versioned_name() { printf '%s_%s.%s' "${1%.*}" "$2" "${1##*.}"; }

# get_artefact REL URL KIND ASSET VERSION [nocheck]
get_artefact() {
  local rel=$1 url=$2 kind=$3 asset=$4 ver=$5 nocheck=${6:-}
  local dest="$REPO_ROOT/$rel" part="$REPO_ROOT/$rel.part" have sum want why size
  have=$(manifest_get "$rel")
  if [[ -f $dest ]]; then
    sum=$(sha256 "$dest")
    if [[ $have == "$ver|"* && $sum == "${have#*|}" ]]; then ok "$rel - already staged and verified"; return 0; fi
    # imported content (e.g. a repository tarball, §7.2): accept it when a checksum list vouches for it
    if [[ -z $have ]]; then
      want=""
      [[ -n $UPSTREAM_SUMS && -z $nocheck ]] && want=$(awk -v n="$asset" '$2==n || $2==("*" n) {print $1; exit}' "$UPSTREAM_SUMS")
      [[ -z $want && -f $REPO_ROOT/SHA256SUMS ]] && want=$(awk -v n="$rel" '$2==n {print $1; exit}' "$REPO_ROOT/SHA256SUMS")
      if [[ -n $want && $want == "$sum" ]] && validate_kind "$dest" "$kind" >/dev/null; then
        manifest_set "$rel" "$ver" "$sum"; ok "$rel - present (imported) and verified against SHA256SUMS"; return 0
      fi
    fi
  fi
  if ! download "$url" "$part" "$rel"; then
    explain_curl "$DL_RC" "$DL_CODE" "$url"
    err "$rel - download failed"; [[ -n $DL_ERR ]] && hint "curl said: $DL_ERR"
    return 1
  fi
  if ! why=$(validate_kind "$part" "$kind"); then
    rm -f "$part"
    fail "$rel is not what it should be: $why" \
         "The URL returned something other than the release artefact (block page, captive portal or truncated transfer)." \
         "Fetch it by hand from this host and inspect: curl -sSIL '$url'"
    err "$rel - invalid content"; return 1
  fi
  sum=$(sha256 "$part"); size=$(human "$(stat -c %s "$part")")
  if [[ -z $nocheck && -n $UPSTREAM_SUMS ]]; then
    want=$(awk -v n="$asset" '$2==n || $2==("*" n) {print $1; exit}' "$UPSTREAM_SUMS")
    if [[ -n $want && $want != "$sum" ]]; then
      rm -f "$part"
      fail "Checksum mismatch for $asset." \
           "The file differs from the publisher's SHA256SUMS: truncated transfer, a content-rewriting proxy, or tampering." \
           "Choose [r] to download again. If it repeats, check content inspection on github.com / objects.githubusercontent.com."
      err "$rel - checksum mismatch"; return 1
    fi
    if [[ -n $want ]]; then ok "$rel - $size, matches the publisher's SHA256SUMS"
    else ok "$rel - $size, file type verified (not listed in the publisher's SHA256SUMS)"; fi
  else
    ok "$rel - $size, file type verified"
  fi
  archive_previous "$rel" "$ver"
  mv -f "$part" "$dest" && chmod 644 "$dest"
  manifest_set "$rel" "$ver" "$sum"
}

fetch_release_metadata() {
  local v=$1 code rc json="$RUN_TMP/release.json" hdr="$RUN_TMP/release.hdr" recent
  REL_ASSETS=""; REL_ASSETS_KNOWN=0
  info "Reading the real asset names of $v from the GitHub API (§2.2: read them rather than assume them)"
  code=$(curl -sS --connect-timeout 20 --max-time 60 "${CURL_PROXY_OPTS[@]}" -H 'Accept: application/vnd.github+json' \
         -D "$hdr" -o "$json" -w '%{http_code}' "$GH_API/releases/tags/$v" 2>"$RUN_TMP/release.err"); rc=$?
  if (( rc != 0 )); then
    explain_curl "$rc" "" "$GH_API"
    warn "GitHub API not reachable: $FAIL_WHAT"
    hint "Continuing with the standard asset names - the downloads will show whether they are right."
    FAIL_WHAT="" FAIL_WHY="" FAIL_FIX=""
    return 0
  fi
  case $code in
    200)
      REL_ASSETS=$(jq -r '.assets[].name' "$json" 2>/dev/null)
      if [[ -z $REL_ASSETS ]]; then warn "Release $v returned no asset list - continuing with standard names"; return 0; fi
      REL_ASSETS_KNOWN=1
      ok "Release $v found with $(wc -l <<<"$REL_ASSETS") assets"
      log "assets: $(tr '\n' ' ' <<<"$REL_ASSETS")" ;;
    404)
      recent=$(curl -sS --connect-timeout 20 --max-time 60 "${CURL_PROXY_OPTS[@]}" "$GH_API/releases?per_page=10" 2>/dev/null | jq -r '.[].tag_name' 2>/dev/null | tr '\n' ' ')
      fail "Release tag $v does not exist on github.com/$GH_REPO." \
           "BP_VERSION must match a published release tag exactly; it becomes the version for the whole estate (§1.3)." \
           "Recent releases: ${recent:-<could not list>}\nRe-run with --reconfigure and pick one - normally the version the DMZ collector runs (${DET_VERSION:-unknown})."
      return 1 ;;
    403|429)
      if grep -qi '^x-ratelimit-remaining: 0' "$hdr"; then warn "GitHub API rate limit reached for this public IP - continuing with standard asset names"
      else warn "GitHub API refused the request (HTTP $code; proxy policy?) - continuing with standard asset names"; fi ;;
    *) warn "GitHub API returned HTTP $code - continuing with standard asset names" ;;
  esac
  return 0
}

fetch_upstream_sums() {
  local v=$1 name="observiq-otel-collector-$1-SHA256SUMS"
  UPSTREAM_SUMS=""
  if (( REL_ASSETS_KNOWN )) && ! grep -qxF "$name" <<<"$REL_ASSETS"; then
    warn "The release publishes no $name - artefacts will be verified by file type only"; return 0
  fi
  if get_artefact "packages/$name" "$GH_DL/$v/$name" sums "$name" "$v" nocheck; then
    UPSTREAM_SUMS="$REPO_ROOT/packages/$name"
  else
    warn "Could not fetch the publisher's $name - artefacts will be verified by file type only"
    FAIL_WHAT="" FAIL_WHY="" FAIL_FIX=""
  fi
}

# The unversioned "current" files (MSI, install scripts) are kept under a versioned name when a
# newer, already-verified download replaces them - a rollback never needs an internet fetch (§13.4).
archive_previous() {
  local rel=$1 ver=$2 have old vrel
  case $rel in windows/observiq-otel-collector.msi|windows/install_windows.ps1|scripts/install_unix.sh) ;; *) return 0 ;; esac
  [[ -f $REPO_ROOT/$rel ]] || return 0
  have=$(manifest_get "$rel"); old=${have%%|*}
  [[ -n $old && $old != "$ver" ]] || return 0
  vrel=$(versioned_name "$rel" "$old")
  if [[ ! -e $REPO_ROOT/$vrel ]]; then
    mv -f "$REPO_ROOT/$rel" "$REPO_ROOT/$vrel"
    manifest_set "$vrel" "$old" "${have#*|}"
    info "Kept the previous $rel as $vrel (rollback copy, §13.4)"
  fi
}

get_windows_script() {
  local v=$1 url
  for url in "$GH_DL/$v/install_windows.ps1" "$BDOT_CDN/$v/install_windows.ps1"; do
    if [[ $url == "$GH_DL"* ]] && (( REL_ASSETS_KNOWN )) && ! grep -qxF install_windows.ps1 <<<"$REL_ASSETS"; then continue; fi
    get_artefact "windows/install_windows.ps1" "$url" ps1 install_windows.ps1 "$v" && return 0
  done
  FAIL_WHAT="" FAIL_WHY="" FAIL_FIX=""
  warn "Could not stage install_windows.ps1 - the MSI alone is sufficient (Stage 9.2 is a script-free install path)."
  hint "If you need the script, take the current URL from the console's Windows install command."
  return 1
}

# apt-get download encodes an epoch as "%3a" in the file name (zlib1g_1%3a1.3...deb). wget-based
# mirroring (§6.1) cannot fetch such names (it requests %3a, nginx decodes it to ':', 404), so files
# are stored under the Debian pool convention without the epoch (zlib1g_1.3...deb).
deb_pool_name() { sed -E 's/_[0-9]+%3[aA]/_/' <<<"$1"; }

os_field() { ( . /etc/os-release 2>/dev/null; eval "printf '%s' \"\${$1:-}\"" ); }

write_version_info() {
  local apt_line="not built (internal mirror used)"
  if [[ $BUILD_APT_REPO == yes && -f $REPO_ROOT/apt/Packages ]]; then
    apt_line="ubuntu-$(os_field VERSION_ID)-$(os_field VERSION_CODENAME)-$(dpkg --print-architecture)"
  fi
  {
    echo "current_collector_version=$BP_VERSION"
    echo "staged_versions=$(find "$REPO_ROOT/packages" -maxdepth 1 -name 'observiq-otel-collector_v*_linux_amd64.deb' -printf '%f\n' 2>/dev/null | sed -E 's/^observiq-otel-collector_//; s/_linux_amd64\.deb$//' | sort -V | tr '\n' ' ')"
    echo "apt_repo_built_for=$apt_line"
    echo "apt_repo_signed=${SIGN_APT_REPO:-no}"
    echo "origin_host=$(hostname -s) ($DMZ_GW_IP)"
    echo "updated=$(date -Is)"
  } >"$REPO_ROOT/VERSION-INFO"
  chmod 644 "$REPO_ROOT/VERSION-INFO"
}

write_repo_readme() {
  cat >"$REPO_ROOT/README.txt" <<EOF
CUSTOMER Bindplane - offline package origin ($(hostname -s), site: $SITE)
Served by nginx on http://$DMZ_GW_IP:$REPO_PORT/ (runbook Stage 2). Managed by $SCRIPT_NAME.

  packages/   collector .deb/.rpm per version + the publisher's SHA256SUMS
  scripts/    install_unix.sh (do NOT use it on isolated hosts - it hangs offline, §6.4)
  windows/    observiq-otel-collector.msi (current), install_windows.ps1, older versions as *_vX.Y.Z.msi
  apt/        flat apt repository: nginx, haproxy, wget + dependencies (Ubuntu, see VERSION-INFO)
  rpm/        (empty - build RHEL repositories on a RHEL host of the same major version, §2.3)
  SHA256SUMS  checksums of every file above - verify after every transfer
  VERSION-INFO  current version, Ubuntu release the apt repository was built for

LIVE gateway (Ubuntu), §5.2:
  echo "deb $([[ ${SIGN_APT_REPO:-no} == yes ]] && echo '[signed-by=/etc/apt/keyrings/bindplane-repo.gpg]' || echo '[trusted=yes]') http://$DMZ_GW_IP:$REPO_PORT/apt ./" | sudo tee /etc/apt/sources.list.d/bindplane-local.list
  sudo apt-get -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/bindplane-local.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 update
Mirror, §6.1:
  cd /srv/bindplane && sudo wget -r -np -nH -N -R 'index.html*' http://$DMZ_GW_IP:$REPO_PORT/ && sudo sha256sum -c SHA256SUMS
EOF
  chmod 644 "$REPO_ROOT/README.txt"
}

# =============================================================================
#  BUILD STEPS  (each returns 0 = done, 1 = failed, 3 = skipped on purpose)
# =============================================================================
step_preflight() {
  local f="$EVIDENCE_DIR/preflight-$RUN_TS.txt"
  CHK_FAILS=0; CHK_WARNS=0
  info "Recording the host baseline to $f"
  {
    echo "# pre-flight $(date -Is) on $(hostname)"
    echo "## identity and OS"; hostnamectl 2>&1 || hostname; grep -E '^(NAME|VERSION_ID)=' /etc/os-release
    echo "## interfaces and routing"; ip -br addr; ip route show default
    echo "## time"; timedatectl status 2>&1
    echo "## disk"; df -h /var /opt /srv 2>&1
    echo "## name resolution"; resolvectl status 2>/dev/null || cat /etc/resolv.conf
  } >"$f" 2>&1
  check_os
  if is_local_ip "$DMZ_GW_IP"; then c_ok "DMZ_GW_IP $DMZ_GW_IP is on interface $(iface_of_ip "$DMZ_GW_IP")"
  else c_fail "DMZ_GW_IP $DMZ_GW_IP is not assigned to this host"; hint "Re-run with --reconfigure to choose the correct address."; fi
  check_collector
  check_time
  check_dns "$BP_CLOUD_HOST"
  if command -v openssl >/dev/null; then check_tls "$BP_CLOUD_HOST"; else c_warn "openssl not installed yet - TLS check deferred (run --diagnose later)"; fi
  check_port_free "$OPAMP_PORT" haproxy
  check_port_free "$REPO_PORT" nginx
  check_port_free "$STATS_PORT" haproxy
  check_disk
  check_ip_forward
  if (( CHK_FAILS > 0 )); then
    fail "$CHK_FAILS pre-flight check(s) failed, $CHK_WARNS warning(s)." \
         "See the [FAIL] lines and hints above. Runbook gate §1.3: DNS, the Checkpoint rule set, TLS inspection or clock skew are resolved at this tier - no proxy hop will fix them." \
         "Fix the failing items, then choose [r] to re-check.\nIf you knowingly accept a failure (e.g. you only want to build the repository today), choose [s]."
    return 1
  fi
  if (( CHK_WARNS > 0 )); then
    warn "$CHK_WARNS warning(s) above."
    ask_yn "Continue despite the warnings?" y || { fail "Stopped at your request after pre-flight warnings." "" "Resolve the warnings, then re-run."; return 1; }
  fi
  ok "Pre-flight passed"
}

step_base_packages() {
  local pkgs=(curl ca-certificates jq wget dpkg-dev apt-utils openssl gzip iproute2) c missing=""
  [[ $SIGN_APT_REPO == yes ]] && pkgs+=(gnupg)
  apt_get "Refreshing package lists (apt-get update)" update || return 1
  if grep -qE '^(W|E): (Failed to fetch|Some index files failed)' "$LAST_OUT"; then
    warn "apt-get update could not refresh every source (W: lines above)."
    hint "If the Ubuntu archive itself failed, the downloads in the os_repo step will fail too."
  fi
  local -a absent=()
  for c in "${pkgs[@]}"; do dpkg-query -W -f='${Status}' "$c" 2>/dev/null | grep -q 'ok installed' || absent+=("$c"); done
  if (( ${#absent[@]} )); then
    # --no-upgrade: never upgrade packages that are already installed (change control)
    apt_get "Installing missing base packages: ${absent[*]}" install -y --no-install-recommends --no-upgrade "${absent[@]}" || return 1
  else
    ok "Base packages already installed (nothing upgraded): ${pkgs[*]}"
  fi
  for c in curl jq wget dpkg-scanpackages apt-ftparchive openssl sha256sum ss; do command -v "$c" >/dev/null || missing+=" $c"; done
  [[ -z $missing ]] || { fail "Required commands still missing:$missing" "The packages did not install correctly." "apt-get install --reinstall ${pkgs[*]}"; return 1; }
  ok "All required tools are present"
}

step_repo_layout() {
  run "Creating $REPO_ROOT/{packages,scripts,windows,apt,rpm}" mkdir -p "$REPO_ROOT"/{packages,scripts,windows,apt,rpm} \
    || { fail "Could not create $REPO_ROOT." "The filesystem is read-only or full." "findmnt -T $REPO_ROOT ; df -h $REPO_ROOT"; return 1; }
  chmod 755 "$REPO_ROOT" "$REPO_ROOT"/{packages,scripts,windows,apt,rpm}
  write_repo_readme
  ok "Layout ready: $REPO_ROOT/{packages,scripts,windows,apt,rpm}"
}

step_collector_artefacts() {
  local v=$BP_VERSION base="$GH_DL/$BP_VERSION" item rel asset kind similar
  local -a plan=()
  fetch_release_metadata "$v" || return 1
  fetch_upstream_sums "$v"
  plan+=("packages/observiq-otel-collector_${v}_linux_amd64.deb|observiq-otel-collector_${v}_linux_amd64.deb|deb-amd64")
  [[ $STAGE_RPM == yes ]]     && plan+=("packages/observiq-otel-collector_${v}_linux_amd64.rpm|observiq-otel-collector_${v}_linux_amd64.rpm|rpm")
  [[ $STAGE_ARM64 == yes ]]   && plan+=("packages/observiq-otel-collector_${v}_linux_arm64.deb|observiq-otel-collector_${v}_linux_arm64.deb|deb-arm64")
  plan+=("scripts/install_unix.sh|install_unix.sh|sh")
  [[ $STAGE_WINDOWS == yes ]] && plan+=("windows/observiq-otel-collector.msi|observiq-otel-collector.msi|msi")
  for item in "${plan[@]}"; do
    IFS='|' read -r rel asset kind <<<"$item"
    if (( REL_ASSETS_KNOWN )) && ! grep -qxF "$asset" <<<"$REL_ASSETS"; then
      similar=$(grep -E 'linux_amd64|linux_arm64|\.msi$|install_' <<<"$REL_ASSETS" | grep -v '\.sig$' | head -n 8 | tr '\n' ' ')
      fail "Release $v has no asset named $asset." "The asset naming changed upstream, or this version does not ship that artefact." \
           "Assets with similar names: ${similar:-none}\nRelease page: https://github.com/$GH_REPO/releases/tag/$v"
      return 1
    fi
    get_artefact "$rel" "$base/$asset" "$kind" "$asset" "$v" || return 1
  done
  chmod 755 "$REPO_ROOT/scripts/install_unix.sh"
  [[ $STAGE_WINDOWS == yes ]] && { get_windows_script "$v" || true; }
  write_version_info
  [[ $(state_get checksums) == "done" ]] && state_set checksums pending
  ok "Collector artefacts for $v are staged in $REPO_ROOT"
}

sign_apt_repo() {
  local d="$REPO_ROOT/apt" fpr
  if [[ $SIGN_APT_REPO != yes ]]; then
    if [[ -e $d/InRelease || -e $d/Release.gpg ]]; then rm -f "$d/InRelease" "$d/Release.gpg"; info "Removed old signatures (signing is disabled)"; fi
    return 0
  fi
  command -v gpg >/dev/null || { fail "gpg is not installed." "Signing was requested but gnupg is missing." "apt-get install gnupg ; then retry"; return 1; }
  install -d -m 700 "$GNUPG_DIR"
  fpr=$(gpg --homedir "$GNUPG_DIR" --list-secret-keys --with-colons 2>/dev/null | awk -F: '/^fpr:/{print $10; exit}')
  if [[ -z $fpr ]]; then
    run "Generating a dedicated repository signing key (RSA 4096, 3-year expiry, stored in $GNUPG_DIR)" \
      gpg --batch --homedir "$GNUPG_DIR" --pinentry-mode loopback --passphrase '' \
          --quick-gen-key "CUSTOMER Bindplane Repo ($(hostname -s)) <bindplane-repo@$(hostname -s).invalid>" rsa4096 sign 3y \
      || { fail "GPG key generation failed." "See the gpg output above." "Check entropy/permissions on $GNUPG_DIR, or set signing to 'no' with --reconfigure."; return 1; }
    fpr=$(gpg --homedir "$GNUPG_DIR" --list-secret-keys --with-colons 2>/dev/null | awk -F: '/^fpr:/{print $10; exit}')
  fi
  run "Signing Release -> Release.gpg" gpg --batch --yes --homedir "$GNUPG_DIR" --local-user "$fpr" --armor --detach-sign --output "$d/Release.gpg" "$d/Release" || { fail "Signing failed." "" "See the gpg output above."; return 1; }
  run "Signing Release -> InRelease"   gpg --batch --yes --homedir "$GNUPG_DIR" --local-user "$fpr" --clearsign --output "$d/InRelease" "$d/Release" || { fail "Signing failed." "" "See the gpg output above."; return 1; }
  gpg --homedir "$GNUPG_DIR" --export "$fpr" >"$STATE_DIR/bindplane-repo-keyring.gpg"
  gpg --homedir "$GNUPG_DIR" --armor --export "$fpr" >"$STATE_DIR/bindplane-repo-key.asc"
  chmod 644 "$STATE_DIR/bindplane-repo-keyring.gpg" "$STATE_DIR/bindplane-repo-key.asc"
  ok "Repository metadata signed with key $fpr"
  hint "Distribute $STATE_DIR/bindplane-repo-keyring.gpg to /etc/apt/keyrings/bindplane-repo.gpg on the isolated hosts"
  hint "through your configuration-management channel (§5.4) - not over this HTTP repository."
}

# apt_print_uris OUTFILE PKG... -> URIs of files still to download; unresolvable names in APT_BAD
APT_BAD=()
apt_print_uris() {
  local out=$1 p; shift
  APT_BAD=(); : >"$out"; : >"$out.err"
  if ! apt-get -q "${APT_PROXY_OPTS[@]}" download --print-uris "$@" >"$out" 2>"$out.err"; then
    warn "Bulk resolution failed - resolving the packages one by one (slower)"
    : >"$out"
    for p in "$@"; do
      apt-get -q "${APT_PROXY_OPTS[@]}" download --print-uris "$p" >>"$out" 2>>"$out.err" || APT_BAD+=("$p")
    done
  fi
  cp -f "$out.err" "$RUN_TMP/apt.uris.err" 2>/dev/null
  log_file "$out.err"
}

step_os_repo() {
  if [[ $BUILD_APT_REPO != yes ]]; then
    info "Skipped by configuration: CUSTOMER's internal Ubuntu mirror provides OS packages (runbook §2, 'Preferred alternative')."
    return 3
  fi
  local d="$REPO_ROOT/apt" native line fn size total=0 p
  local -a pkgs deps=() need=() missing=()
  native=$(dpkg --print-architecture)
  read -r -a pkgs <<<"nginx haproxy wget ${EXTRA_APT_PKGS:-}"
  cd "$d" || { fail "Cannot enter $d." "The repository layout is missing." "Run: $0 --from repo_layout"; return 1; }
  run "Resolving the recursive dependency closure of: ${pkgs[*]}" \
      apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts --no-breaks --no-replaces --no-enhances "${pkgs[@]}" \
      || { explain_apt_failure "$LAST_OUT"; return 1; }
  # Lines that start with a letter/digit are package names; <virtual> ones are skipped.
  while IFS= read -r line; do
    if [[ $line == *:* ]]; then [[ ${line#*:} == "$native" ]] || continue; line=${line%%:*}; fi
    deps+=("$line")
  done < <(grep -E '^[A-Za-z0-9]' "$LAST_OUT" | sort -u)
  info "${#deps[@]} packages in the dependency closure"
  # apt-get download --print-uris lists only files that are NOT already complete in the current
  # directory, so a re-run downloads only what is missing.
  apt_print_uris "$RUN_TMP/apt.uris" "${deps[@]}"
  for p in "${pkgs[@]}"; do
    if contains_word "${APT_BAD[*]:-}" "$p"; then
      fail "apt cannot download '$p'." "$(grep -m1 -E '^E:' "$RUN_TMP/apt.uris.err")" \
           "Check the name with: apt-cache policy $p\nIf the package lists are stale: $0 --only base_packages"
      return 1
    fi
  done
  (( ${#APT_BAD[@]} )) && warn "Skipped ${#APT_BAD[@]} name(s) with no downloadable candidate (normally virtual packages): ${APT_BAD[*]}"
  total=$(( ${#deps[@]} - ${#APT_BAD[@]} ))
  while read -r _ fn size _; do
    [[ -n ${fn:-} ]] || continue
    p=${fn%%_*}; fn=$(deb_pool_name "$fn")
    [[ -f $fn && $(stat -c %s "$fn") == "$size" ]] || need+=("$p")
  done <"$RUN_TMP/apt.uris"
  info "$(( total - ${#need[@]} )) of $total package files already staged, ${#need[@]} to download"
  if (( ${#need[@]} )); then
    info "(the warning 'Download is performed unsandboxed as root' is expected and harmless, §2.3)"
    apt_get "Downloading ${#need[@]} package file(s) into $d" download "${need[@]}" || return 1
  fi
  local renamed=0 f
  for f in ./*%3[aA]*.deb; do
    [[ -e $f ]] || continue
    mv -f "$f" "$(deb_pool_name "$f")"; renamed=$((renamed+1))
  done
  (( renamed )) && info "Renamed $renamed epoch-encoded file name(s) (%3a) to the Debian pool convention so wget mirroring (§6.1) can fetch them"
  # verify: anything apt still wants must exist under its pool name with the right size
  apt_print_uris "$RUN_TMP/apt.uris2" "${deps[@]}"
  while read -r _ fn size _; do
    [[ -n ${fn:-} ]] || continue
    fn=$(deb_pool_name "$fn")
    [[ -f $fn && $(stat -c %s "$fn") == "$size" ]] || missing+=("$fn")
  done <"$RUN_TMP/apt.uris2"
  if (( ${#missing[@]} )); then
    fail "${#missing[@]} package file(s) are missing or truncated after the download." "Interrupted transfer or a mirror problem: ${missing[*]:0:5}" "Choose [r] to retry - complete files are not downloaded again."
    return 1
  fi
  ok "All $total package files are present"
  run "Building the Packages index (dpkg-scanpackages)" sh -c 'dpkg-scanpackages --multiversion . /dev/null > Packages.tmp && mv -f Packages.tmp Packages' \
    || { fail "dpkg-scanpackages failed." "A .deb in $d is corrupt." "Delete the file named above and retry."; return 1; }
  run "Compressing Packages.gz" sh -c 'gzip -9c Packages > Packages.gz.tmp && mv -f Packages.gz.tmp Packages.gz' || { fail "gzip failed." "" "Check free space: df -h $d"; return 1; }
  run "Writing the Release file (apt-ftparchive)" sh -c 'apt-ftparchive -o APT::FTPArchive::Release::Origin=CUSTOMER-Bindplane -o APT::FTPArchive::Release::Label=bindplane-local release . > Release.tmp && mv -f Release.tmp Release' \
    || { fail "apt-ftparchive failed." "apt-utils missing?" "apt-get install apt-utils ; then retry"; return 1; }
  for p in "${pkgs[@]}"; do
    grep -qx "Package: $p" Packages || { fail "The index does not list '$p'." "The package file was not downloaded." "Choose [r] to retry."; return 1; }
  done
  sign_apt_repo || return 1
  write_version_info
  [[ $(state_get checksums) == "done" ]] && state_set checksums pending
  ok "apt repository ready: $(grep -c '^Package:' Packages) package entries in $d"
  warn "These .debs are for Ubuntu $(os_field VERSION_ID) ($(os_field VERSION_CODENAME), $native). The isolated hosts must run the SAME release."
}

step_checksums() {
  local bad
  cd "$REPO_ROOT" || { fail "Cannot enter $REPO_ROOT." "" "Run: $0 --from repo_layout"; return 1; }
  bad=$(find . -type f \( -name '*%*' -o -name '*:*' -o -name '* *' -o -name '*#*' -o -name '*\?*' \) ! -name '*.part' | head -n 5)
  if [[ -n $bad ]]; then
    fail "File names that cannot be mirrored over HTTP were found: $(tr '\n' ' ' <<<"$bad")" \
         "Names containing % : space # or ? are mangled by URL encoding; wget mirroring (§6.1) would miss them and the LIVE-side checksum check would fail." \
         "Rename or remove them (for .deb files: $0 --only os_repo renames them automatically), then retry."
    return 1
  fi
  write_repo_readme
  run "Computing SHA256SUMS over the repository" bash -c '
      { find packages windows scripts apt rpm -type f ! -name "*.part" ! -name "*.tmp" ! -name ".*" 2>/dev/null
        find . -maxdepth 1 -type f ! -name "SHA256SUMS*" ! -name ".*" -printf "%P\n"; } \
      | LC_ALL=C sort | xargs -r -d "\n" sha256sum > SHA256SUMS.tmp && [ -s SHA256SUMS.tmp ]' \
    || { rm -f SHA256SUMS.tmp; fail "Could not compute checksums." "A file could not be read, or the repository is empty." "ls -laR $REPO_ROOT | head -50"; return 1; }
  mv -f SHA256SUMS.tmp SHA256SUMS
  run "Making the repository world-readable (chmod -R a+rX)" chmod -R a+rX "$REPO_ROOT" || return 1
  run "Self-check (sha256sum -c SHA256SUMS)" sha256sum -c --quiet SHA256SUMS \
    || { fail "A file changed while checksums were computed." "Another process is writing into $REPO_ROOT." "Choose [r] to retry."; return 1; }
  ok "$(wc -l <SHA256SUMS) files listed in SHA256SUMS, $(du -sh "$REPO_ROOT" | cut -f1) in total"
}

step_nginx() {
  local rc others code
  if ! dpkg -s nginx >/dev/null 2>&1; then
    block_service_autostart
    apt_get "Installing nginx (auto-start suppressed so it never listens on *:80)" install -y nginx; rc=$?
    unblock_service_autostart
    (( rc == 0 )) || return 1
  else ok "nginx already installed"; fi
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
    [[ -z $FAIL_WHAT || $FAIL_WHAT == "nginx failed to start." ]] && fail "nginx -t rejected the configuration." "$(grep -m1 -E 'emerg|error' "$LAST_OUT")" "Edit $NGINX_SITE or the file named above, then retry."
    return 1
  fi
  run "Enabling nginx at boot" systemctl enable nginx
  if systemctl is-active --quiet nginx; then
    run "Reloading nginx" systemctl reload nginx || { service_restart_checked nginx || return 1; }
  else
    service_restart_checked nginx || return 1
  fi
  verify_listener "$REPO_PORT" "$DMZ_GW_IP" nginx || return 1
  code=$(lcurl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://$DMZ_GW_IP:$REPO_PORT/")
  [[ $code == 200 ]] || { fail "The repository index returned HTTP ${code:-no response}." "nginx is running but cannot serve $REPO_ROOT." "tail $NGINX_ERROR_LOG ; ls -ld $REPO_ROOT"; return 1; }
  ok "Index http://$DMZ_GW_IP:$REPO_PORT/ returns 200"
  if [[ -f $REPO_ROOT/SHA256SUMS ]]; then
    lcurl -s --max-time 10 "http://$DMZ_GW_IP:$REPO_PORT/SHA256SUMS" -o "$RUN_TMP/sums.http"
    cmp -s "$RUN_TMP/sums.http" "$REPO_ROOT/SHA256SUMS" && ok "SHA256SUMS served correctly ($(wc -l <"$REPO_ROOT/SHA256SUMS") entries)" \
      || { fail "SHA256SUMS served over HTTP differs from the file on disk." "Wrong root directory or a caching layer." "grep root $NGINX_SITE"; return 1; }
  fi
  code=$(lcurl -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST "http://$DMZ_GW_IP:$REPO_PORT/")
  [[ $code == 403 || $code == 405 ]] && ok "Read-only: non-GET methods are refused ($code)"
}

step_haproxy_install() {
  local rc v mm
  if dpkg -s haproxy >/dev/null 2>&1; then ok "haproxy already installed"
  else
    block_service_autostart
    apt_get "Installing haproxy" install -y haproxy; rc=$?
    unblock_service_autostart
    (( rc == 0 )) || return 1
  fi
  v=$(haproxy -v 2>/dev/null | head -n1)
  [[ -n $v ]] || { fail "haproxy -v printed nothing." "The haproxy binary is missing or broken." "apt-get install --reinstall haproxy"; return 1; }
  mm=$(grep -oE 'version [0-9]+\.[0-9]+' <<<"$v" | awk '{print $2}')
  if [[ -n $mm ]] && (( ${mm%%.*} < 2 )); then
    fail "$v is too old." "The hop 1 configuration needs HAProxy 2.0 or later (server-side ALPN, parse-resolv-conf)." "Use Ubuntu 20.04 or later."; return 1
  fi
  ok "$v"
}

step_haproxy_config() {
  local new="$RUN_TMP/haproxy.cfg.new" first
  is_local_ip "$DMZ_GW_IP" || { fail "$DMZ_GW_IP is not assigned to this host." "The address changed since configuration." "Re-run with --reconfigure."; return 1; }
  [[ -s $CA_FILE ]] || { fail "CA bundle $CA_FILE is missing." "ca-certificates is not installed." "apt-get install --reinstall ca-certificates"; return 1; }
  if [[ -f $HAPROXY_CFG ]] && ! grep -q "Managed by $SCRIPT_NAME" "$HAPROXY_CFG" && grep -qE '^[[:space:]]*(frontend|listen)[[:space:]]' "$HAPROXY_CFG"; then
    warn "HAProxy on this host already has a custom configuration: $(grep -E '^[[:space:]]*(frontend|listen)[[:space:]]' "$HAPROXY_CFG" | awk '{print $1" "$2}' | tr '\n' ' ')"
    hint "This step replaces $HAPROXY_CFG entirely (a backup is kept). Other services relying on it would stop working."
    if ! ask_yn "Replace the existing HAProxy configuration?" n; then
      fail "Existing HAProxy configuration left untouched." "This host's HAProxy already serves other frontends." \
           "The runbook expects a dedicated gateway. Either move the other frontends elsewhere, or merge the hop-1 sections\n($STATE_DIR/haproxy.cfg.hop1-candidate) into the existing file by hand, then choose [s] for this step."
      render_haproxy_cfg >"$new"; cp -f "$new" "$STATE_DIR/haproxy.cfg.hop1-candidate" 2>/dev/null
      return 1
    fi
  fi
  render_haproxy_cfg >"$new"
  if ! run "Validating the new configuration before installing it (haproxy -c)" haproxy -c -f "$new"; then
    first=$(grep -m1 -F '[ALERT]' "$LAST_OUT")
    fail "haproxy -c rejected the generated configuration." \
         "First alert: ${first:-see output}\nOnly the FIRST alert is real - later ones are the parser losing its place (§3.1)." \
         "The live configuration was NOT changed. Fix the cause, then choose [r]. The candidate file is $new."
    cp -f "$new" "$STATE_DIR/haproxy.cfg.rejected" 2>/dev/null
    return 1
  fi
  if [[ -f $HAPROXY_CFG && ! -f $HAPROXY_CFG.orig ]]; then cp -p "$HAPROXY_CFG" "$HAPROXY_CFG.orig"; info "Saved the package default as $HAPROXY_CFG.orig"; fi
  if [[ -f $HAPROXY_CFG ]] && ! grep -q "Managed by $SCRIPT_NAME" "$HAPROXY_CFG" && ! cmp -s "$HAPROXY_CFG" "$HAPROXY_CFG.orig"; then
    cp -p "$HAPROXY_CFG" "$HAPROXY_CFG.bak-$RUN_TS"; info "Backed up the existing configuration to $HAPROXY_CFG.bak-$RUN_TS"
  fi
  install -m 644 -o root -g root "$new" "$HAPROXY_CFG"
  run "Re-validating the installed configuration" haproxy -c -f "$HAPROXY_CFG" || { fail "Installed configuration failed validation." "" "Restore with: cp $HAPROXY_CFG.orig $HAPROXY_CFG"; return 1; }
  grep -q 'timeout tunnel  24h' "$HAPROXY_CFG" && ok "timeout tunnel 24h present (without it every OpAMP session drops within a minute)"
  ok "Hop 1 configuration installed: $DMZ_GW_IP:$OPAMP_PORT -> $BP_CLOUD_HOST:443 (TLS, SNI, Host rewrite, ALPN http/1.1)"
}

step_haproxy_limits() {
  install -d -m 755 "$HAPROXY_DROPIN_DIR"
  printf '# Managed by %s - runbook §3.5\n[Service]\nLimitNOFILE=65535\n' "$SCRIPT_NAME" >"$HAPROXY_DROPIN"
  chmod 644 "$HAPROXY_DROPIN"
  run "Reloading systemd units (daemon-reload)" systemctl daemon-reload || { fail "systemctl daemon-reload failed." "" "journalctl -n 20"; return 1; }
  ok "LimitNOFILE=65535 set for haproxy (maxconn $HAPROXY_MAXCONN: keep it >= 2x the projected agent count)"
}

ufw_active() { command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; }

step_host_firewall() {
  local src port label
  if ufw_active; then
    info "ufw is active - adding narrowly-scoped allow rules to $DMZ_GW_IP"
    touch "$UFW_RECORD"; chmod 600 "$UFW_RECORD"
    # remove rules this script added earlier that no longer match the answers
    local osrc oport odst keep="$RUN_TMP/ufw.keep"
    : >"$keep"
    while read -r osrc oport odst; do
      [[ -n $osrc ]] || continue; odst=${odst:-$DMZ_GW_IP}
      if [[ $odst == "$DMZ_GW_IP" ]] && contains_word "$FW_SOURCES" "$osrc" && contains_word "$FW_PORTS" "$oport"; then
        echo "$osrc $oport $odst" >>"$keep"
      else
        run "remove old rule $osrc -> $odst tcp/$oport" ufw delete allow proto tcp from "$osrc" to "$odst" port "$oport" || warn "Could not remove it - check: ufw status numbered"
      fi
    done <"$UFW_RECORD"
    cp -f "$keep" "$UFW_RECORD"
    for src in $FW_SOURCES; do
      for port in $FW_PORTS; do
        case $port in "$OPAMP_PORT") label="bindplane opamp hop1";; "$REPO_PORT") label="bindplane package repo";; "$OTLP_PORT") label="bindplane otlp";; *) label="bindplane";; esac
        run "allow $src -> $DMZ_GW_IP tcp/$port" ufw allow proto tcp from "$src" to "$DMZ_GW_IP" port "$port" comment "$label" \
          || { fail "ufw refused the rule for $src tcp/$port." "See the ufw output above." "ufw status verbose"; return 1; }
        grep -qxF "$src $port $DMZ_GW_IP" "$UFW_RECORD" || echo "$src $port $DMZ_GW_IP" >>"$UFW_RECORD"
      done
    done
    ufw status numbered >"$EVIDENCE_DIR/ufw-status-$RUN_TS.txt" 2>&1
  else
    info "ufw is not active - no host-firewall changes made"
    if iptables -S INPUT 2>/dev/null | grep -q '^-P INPUT DROP' || nft list ruleset 2>/dev/null | grep -qE 'hook input .*policy drop'; then
      warn "The INPUT policy is DROP but ufw is not managing it: allow tcp/${FW_PORTS// /,} from ${FW_SOURCES} to $DMZ_GW_IP in your firewall tooling"
    fi
  fi
  info "Perimeter rules are still needed (network team):"
  say  "        Fortigate : ${LIVE_GW_IP:-LIVE_GW} -> $DMZ_GW_IP  tcp/$OPAMP_PORT (OpAMP), tcp/$OTLP_PORT (OTLP), tcp/$REPO_PORT (packages)"
  say  "        Checkpoint: $DMZ_GW_IP -> $BP_CLOUD_HOST tcp/443 (direct, no TLS inspection)"
  return 0
}

step_haproxy_start() {
  local i st cs lim
  run "Enabling haproxy at boot" systemctl enable haproxy
  service_restart_checked haproxy || return 1
  verify_listener "$OPAMP_PORT" "$DMZ_GW_IP" haproxy || return 1
  if stats_csv | grep -q '^bindplane_cloud,'; then ok "Stats endpoint http://127.0.0.1:$STATS_PORT/stats is answering"
  else fail "The stats endpoint does not answer." "The stats_in frontend did not bind 127.0.0.1:$STATS_PORT." "ss -lntp | grep $STATS_PORT ; journalctl -u haproxy -n 20"; return 1; fi
  lim=$(systemctl show haproxy -p LimitNOFILE --value 2>/dev/null)
  [[ $lim == 65535 ]] && ok "haproxy runs with LimitNOFILE=65535" || warn "haproxy LimitNOFILE is '${lim:-?}' (expected 65535) - run: systemctl daemon-reload && systemctl restart haproxy"
  info "Waiting for the cloud backend health check (TCP + TLS to $BP_CLOUD_HOST:443) ..."
  for i in $(seq 1 30); do
    st=$(stats_field bindplane_cloud cloud status); cs=$(stats_field bindplane_cloud cloud check_status)
    [[ $st == UP* ]] && break
    [[ $st == DOWN* && $i -ge 8 ]] && break
    sleep 1
  done
  if [[ $st == UP* ]]; then ok "Backend bindplane_cloud/cloud is UP (check: ${cs:-?})"; return 0; fi
  fail "Backend bindplane_cloud/cloud is ${st:-unknown} (check: ${cs:-none})." \
       "$(describe_check_status "$cs")\nHAProxy answers 503 to every agent while the backend is down." \
       "Run: $0 --diagnose   (DNS, direct TLS, clock)\nLast check detail: $(stats_field bindplane_cloud cloud last_chk)"
  return 1
}

step_probe_hop1() {
  local out="$EVIDENCE_DIR/probe-hop1-$RUN_TS.txt" since line
  since=$(date '+%Y-%m-%d %H:%M:%S'); sleep 1
  info "Probing ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp with a synthetic WebSocket handshake (§4.1)"
  probe_opamp "http://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp" "$out"
  head -n 12 "$out" | awk '{sub(/\r$/,""); print "      | " $0}'
  sleep 2
  line=$(haproxy_log_since "$since")
  explain_haproxy_log_line "$line"
  [[ -n $line ]] && printf '\n# HAProxy log line\n%s\n' "$line" >>"$out"
  classify_probe "$DMZ_GW_IP:$OPAMP_PORT"
}

hop_restore() { # put the direct manager.yaml back after a §4.4 test
  [[ -f $HOP_MARKER ]] || { HOP_TEST_ACTIVE=0; return 0; }
  if [[ ! -f $MANAGER_YAML.direct ]]; then
    err "Cannot restore the direct connection: $MANAGER_YAML.direct is missing."
    hint "Set 'endpoint:' in $MANAGER_YAML back to: $(cat "$HOP_MARKER") and restart $COLLECTOR_SVC"
    return 1
  fi
  cp -p "$MANAGER_YAML.direct" "$MANAGER_YAML"
  systemctl restart "$COLLECTOR_SVC" >/dev/null 2>&1 9>&-
  if [[ $(yaml_get endpoint) == "$(cat "$HOP_MARKER")" ]]; then
    ok "Direct connection restored (endpoint: $(yaml_get endpoint)) and collector restarted"
    rm -f "$HOP_MARKER"; HOP_TEST_ACTIVE=0; return 0
  fi
  err "manager.yaml endpoint is '$(yaml_get endpoint)' after restore - expected '$(cat "$HOP_MARKER")'"
  return 1
}

step_collector_via_hop1() {
  local orig relay="ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp" before=0 i scur stot0 stot connected=0 console=0 errs since
  say "  This is the definitive test (§4.4): the DMZ collector is pointed at its own relay for about"
  say "  a minute, then the direct connection is restored. The collector restarts twice; any pipelines"
  say "  it runs pause for a few seconds each time. An interruption (Ctrl+C, SSH drop) restores it."
  if ! ask_yn "Run the real-collector test now?" y; then
    warn "Skipped. Gate §4.4 is NOT satisfied - do not start Stage 5 until it passes."
    hint "Run it later with: $0 --only collector_via_hop1"
    return 3
  fi
  systemctl is-active --quiet haproxy || { fail "haproxy is not running." "" "$0 --only haproxy_start"; return 1; }
  [[ -r $MANAGER_YAML ]] || { fail "$MANAGER_YAML not found." "The collector is not installed here." "Complete Stage 1 first."; return 1; }
  orig=$(yaml_get endpoint)
  [[ -n $orig ]] || { fail "manager.yaml has no endpoint line." "" "Check $MANAGER_YAML"; return 1; }
  if [[ $orig == ws://*:$OPAMP_PORT/* ]]; then
    fail "manager.yaml already points at a relay ($orig)." "A previous test was not restored." \
         "Restore the direct copy: cp -p $MANAGER_YAML.direct $MANAGER_YAML && systemctl restart $COLLECTOR_SVC"; return 1
  fi
  cp -p "$MANAGER_YAML" "$MANAGER_YAML.direct" || { fail "Could not back up manager.yaml." "" "df -h $COLLECTOR_HOME"; return 1; }
  printf '%s\n' "$orig" >"$HOP_MARKER"; chmod 600 "$HOP_MARKER"; HOP_TEST_ACTIVE=1
  sed -i -E "s|^endpoint:.*|endpoint: $relay|" "$MANAGER_YAML"
  [[ $(yaml_get endpoint) == "$relay" ]] || { hop_restore; fail "Could not rewrite the endpoint in manager.yaml." "" "Inspect $MANAGER_YAML"; return 1; }
  ok "manager.yaml now points at $relay (backup: $MANAGER_YAML.direct)"
  [[ -r $COLLECTOR_LOG ]] && before=$(wc -l <"$COLLECTOR_LOG")
  stot0=$(stats_field bindplane_cloud cloud stot); stot0=${stot0:-0}
  since=$(date '+%Y-%m-%d %H:%M:%S')
  run "Restarting the collector through hop 1" systemctl restart "$COLLECTOR_SVC"
  info "Waiting up to 90s for a live tunnel through HAProxy ..."
  for i in $(seq 1 90); do
    scur=$(stats_field bindplane_cloud cloud scur); stot=$(stats_field bindplane_cloud cloud stot)
    if [[ ${scur:-0} =~ ^[0-9]+$ ]] && (( ${scur:-0} >= 1 && ${stot:-0} > stot0 )); then
      sleep 10   # make sure it stays up rather than dropping immediately
      scur=$(stats_field bindplane_cloud cloud scur)
      (( ${scur:-0} >= 1 )) && { connected=1; break; }
    fi
    (( TTY_OUT )) && printf '\r      %2ds  sessions=%s total=%s ' "$i" "${scur:-?}" "${stot:-?}"
    sleep 1
  done
  (( TTY_OUT )) && printf '\r\e[K'
  { echo "# §4.4 test $(date -Is)"; echo "relay endpoint: $relay"; echo "tunnel census:"; tunnel_census; } >"$EVIDENCE_DIR/hop1-collector-test-$RUN_TS.txt" 2>&1
  if [[ -r $COLLECTOR_LOG ]]; then
    errs=$(tail -n +"$((before+1))" "$COLLECTOR_LOG" 2>/dev/null | grep -iE 'error|refused|denied|timeout|unauthor|forbidden|bad handshake' | tail -n 8)
    [[ -n $errs ]] && { warn "Collector log lines since the restart:"; printf '%s\n' "$errs" | redact_stream | cut -c1-220 | sed 's/^/         /'; }
  fi
  if (( connected )); then
    ok "Live tunnel through hop 1: bindplane_cloud/cloud scur=$scur"
    tunnel_census
    say "  Check the Bindplane console now: Agents -> this agent ($(hostname -s), agent_id $(yaml_get agent_id))."
    if ask_yn "Is it shown as Connected?" y; then console=1; fi
  fi
  info "Restoring the direct connection"
  hop_restore || { fail "The direct connection could not be restored automatically." "See the messages above." "cp -p $MANAGER_YAML.direct $MANAGER_YAML && systemctl restart $COLLECTOR_SVC"; return 1; }
  sleep 3
  systemctl is-active --quiet "$COLLECTOR_SVC" && ok "Collector is running on its direct connection again" || warn "Collector is not active after restore - check: journalctl -u $COLLECTOR_SVC -n 30"
  if (( connected && console )); then
    echo "result: PASS (tunnel established, console showed Connected)" >>"$EVIDENCE_DIR/hop1-collector-test-$RUN_TS.txt"
    ok "PASS: a real collector authenticated through hop 1 (gate §4.4)"; return 0
  fi
  echo "result: FAIL (tunnel=$connected console=$console)" >>"$EVIDENCE_DIR/hop1-collector-test-$RUN_TS.txt"
  if (( connected )); then
    fail "The tunnel was up but the console did not show the agent as Connected." \
         "Authentication through the relay failed (wrong secret, or the Host/SNI rewrite reaches the wrong tenant), or the console was not refreshed." \
         "Re-check the agent in the console, then re-run: $0 --only collector_via_hop1"
    return 1
  fi
  explain_haproxy_log_line "$(haproxy_log_since "$since")" || true
  if grep -qiE 'unauthor|401' <<<"${errs:-}"; then
    fail "No tunnel: the collector reported an authorisation error." "The secret key in manager.yaml is not accepted through the relay." "Compare secret_key with the console (Agents -> Install Agents) and retry."
  elif grep -qE '502' <<<"${errs:-}"; then
    fail "No tunnel: HAProxy answered 502 Bad Gateway to the collector." \
         "The cloud's answer to the WebSocket upgrade was invalid or the connection was reset mid-handshake - typically an inline device (TLS inspection, IPS, web filter) between this host and $BP_CLOUD_HOST interfering with the upgrade." \
         "Check the termination flags in the HAProxy log line above; ask the network team to exempt this host -> $BP_CLOUD_HOST:443 from inspection."
  elif grep -qE '503' <<<"${errs:-}"; then
    fail "No tunnel: HAProxy answered 503 to the collector." "The cloud backend is down (health check: $(stats_field bindplane_cloud cloud check_status))." "Run: $0 --diagnose"
  elif grep -qiE 'refused' <<<"${errs:-}"; then
    fail "No tunnel: connection refused to $relay." "HAProxy is not listening on $DMZ_GW_IP:$OPAMP_PORT." "ss -lntp | grep :$OPAMP_PORT ; systemctl status haproxy"
  else
    fail "No tunnel through HAProxy within 90 seconds." \
         "The collector did not open a WebSocket via the relay. Check the collector log lines above and the HAProxy log." \
         "journalctl -u haproxy -n 30 --no-pager ; tail -n 50 $COLLECTOR_LOG ; then: $0 --only collector_via_hop1"
  fi
  return 1
}

write_next_steps() {
  local live_name="bp-gw-live-01" site_label=primary repo_line
  [[ $SITE == dr ]] && { live_name="bp-gw-drlive-01"; site_label=dr; }
  repo_line="deb [trusted=yes] http://$DMZ_GW_IP:$REPO_PORT/apt ./"
  [[ $SIGN_APT_REPO == yes ]] && repo_line="deb [signed-by=/etc/apt/keyrings/bindplane-repo.gpg] http://$DMZ_GW_IP:$REPO_PORT/apt ./"
  cat >"$NEXT_STEPS_FILE" <<EOF
# =============================================================================
# Hand-off for the LIVE gateway ($live_name) - runbook Stages 5 and 6
# Generated by $SCRIPT_NAME on $(hostname -s) at $(date -Is)
# DMZ side: repository http://$DMZ_GW_IP:$REPO_PORT/  relay ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp
# =============================================================================
export DMZ_GW_IP='$DMZ_GW_IP'
export LIVE_GW_IP='$LIVE_GW_IP'
export BP_VERSION='$BP_VERSION'
export BP_CLOUD_HOST='$BP_CLOUD_HOST'
export BP_SECRET='<paste from the console - never stored in this file>'

# 5.1 path to the DMZ repository (if this fails: Fortigate rule $live_name -> $DMZ_GW_IP tcp/$REPO_PORT)
curl -s --max-time 5 http://$DMZ_GW_IP:$REPO_PORT/ | head -20

# 5.2 apt from the DMZ repository only (Ubuntu $(os_field VERSION_ID) - must match the LIVE host's release)
$( [[ $SIGN_APT_REPO == yes ]] && echo "# first install the key from $STATE_DIR/bindplane-repo-keyring.gpg as /etc/apt/keyrings/bindplane-repo.gpg (via config management)" )
echo "$repo_line" | sudo tee /etc/apt/sources.list.d/bindplane-local.list
sudo apt-get -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/bindplane-local.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 update
sudo apt-get -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/bindplane-local.list -o Dir::Etc::sourceparts=- install -y nginx haproxy wget

# 6.1 mirror the repository
sudo mkdir -p /srv/bindplane && cd /srv/bindplane
sudo wget -r -np -nH -N -R 'index.html*' http://$DMZ_GW_IP:$REPO_PORT/
sudo sha256sum -c SHA256SUMS

# 6.3 hop 2 backend line (rewrites nothing; keep 'timeout tunnel 24h' there too)
#     server dmz $DMZ_GW_IP:$OPAMP_PORT check

# 6.3 validate the chain from the LIVE host (expect 403 with 'Via: 1.1 google')
curl -i -sS --max-time 10 --http1.1 -H 'Connection: Upgrade' -H 'Upgrade: websocket' \\
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \\
  -H "Authorization: Secret-Key \${BP_SECRET}" http://\${LIVE_GW_IP}:$OPAMP_PORT/v1/opamp | head -20

# 6.4 collector on the LIVE gateway - dpkg, NOT install_unix.sh (it hangs offline)
sudo dpkg -i /srv/bindplane/packages/observiq-otel-collector_${BP_VERSION}_linux_amd64.deb
#   manager.yaml:
#     endpoint: ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp
#     secret_key: \${BP_SECRET}
#     labels: "site=$site_label,segment=$( [[ $SITE == dr ]] && echo dr-live || echo prod-live ),role=gateway"
#     agent_name: $live_name

# Watch hop 1 from the DMZ host while you test:
#   journalctl -u haproxy -f        curl -s '$STATS_URL' | awk -F, '\$1=="bindplane_cloud"{print \$1,\$2,"status="\$18,"scur="\$5}'
EOF
  chmod 644 "$NEXT_STEPS_FILE"
}

step_evidence() {
  local d="$EVIDENCE_DIR/pack-$RUN_TS" tarball
  mkdir -p "$d"
  {
    echo "# Evidence pack - $(hostname -s) - $(date -Is) - $SCRIPT_NAME v$SCRIPT_VERSION"
    echo "## versions"; haproxy -v 2>&1 | head -n1; nginx -v 2>&1; echo "collector $(collector_version)"
    echo "## listeners"; ss -lntp 2>/dev/null | grep -E ":($OPAMP_PORT|$OTLP_PORT|5514|$REPO_PORT|$STATS_PORT) "
    echo "## established OpAMP/OTLP sessions"; ss -tn 2>/dev/null | grep -cE ":($OPAMP_PORT|$OTLP_PORT) "
    echo "## tunnel census"; tunnel_census
    echo "## haproxy -c"; haproxy -c -f "$HAPROXY_CFG" 2>&1
    echo "## step progress"; cat "$STATE_FILE" 2>/dev/null
    echo "## host firewall"; ufw status verbose 2>&1 || true
    echo "## ip_forward"; sysctl net.ipv4.ip_forward 2>&1
  } >"$d/summary.txt" 2>&1
  cp -f "$HAPROXY_CFG" "$d/haproxy.cfg" 2>/dev/null
  cp -f "$NGINX_SITE" "$d/nginx-bindplane-repo.conf" 2>/dev/null
  cp -f "$REPO_ROOT/SHA256SUMS" "$REPO_ROOT/VERSION-INFO" "$d/" 2>/dev/null
  [[ -r $MANAGER_YAML ]] && sed -E 's/^(secret_key:).*/\1 ***REDACTED***/' "$MANAGER_YAML" >"$d/manager.yaml.redacted"
  write_next_steps
  cp -f "$NEXT_STEPS_FILE" "$d/"
  tarball="$LOG_DIR/bp-dmz-evidence-$(hostname -s)-$RUN_TS.tar.gz"
  ( cd "$EVIDENCE_DIR" && tar -czf "$tarball" --exclude='pack-*.tar.gz' . ) 2>/dev/null
  # final scrub: no file in the pack may contain the secret
  if [[ -n $BP_SECRET ]] && grep -rqF "$BP_SECRET" "$EVIDENCE_DIR" 2>/dev/null; then
    warn "The secret key was found in an evidence file - scrubbing"
    grep -rlF "$BP_SECRET" "$EVIDENCE_DIR" | while read -r f; do sed -i "s/$(sed_escape "$BP_SECRET")/***REDACTED***/g" "$f"; done
    ( cd "$EVIDENCE_DIR" && tar -czf "$tarball" . ) 2>/dev/null
  fi
  chmod 600 "$tarball" 2>/dev/null
  ok "Evidence pack: $tarball"
  ok "LIVE-gateway hand-off notes: $NEXT_STEPS_FILE"
}

# =============================================================================
#  Diagnostics (--diagnose, and [d] in the failure menu) - read-only
# =============================================================================
section() { printf '\n%s--- %s ---%s\n' "$C_BLD" "$*" "$C_OFF"; log "---- $*"; }

run_diagnostics() {
  local svc a e first cs st sums code
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

  section "2. Listeners"
  ss -H -lntp 2>/dev/null | grep -E ":($OPAMP_PORT|$OTLP_PORT|5514|$REPO_PORT|$STATS_PORT)[[:space:]]" | awk '{printf "      %-24s %s\n", $4, $6}'
  if [[ -n $DMZ_GW_IP ]]; then
    if verify_listener "$OPAMP_PORT" "$DMZ_GW_IP" haproxy >/dev/null; then c_ok "HAProxy hop 1 bound to $DMZ_GW_IP:$OPAMP_PORT only"; else c_fail "$FAIL_WHAT"; hint "$FAIL_FIX"; fi
    if verify_listener "$REPO_PORT" "$DMZ_GW_IP" nginx >/dev/null; then c_ok "Repository bound to $DMZ_GW_IP:$REPO_PORT only"; else c_fail "$FAIL_WHAT"; hint "$FAIL_FIX"; fi
  else c_warn "DMZ_GW_IP unknown (no saved configuration) - listener checks skipped"; fi

  section "3. Configuration files"
  if [[ -f $HAPROXY_CFG ]] && command -v haproxy >/dev/null; then
    if haproxy -c -f "$HAPROXY_CFG" >"$RUN_TMP/hc.out" 2>&1; then c_ok "haproxy -c: configuration is valid"
    else first=$(grep -m1 -F '[ALERT]' "$RUN_TMP/hc.out"); c_fail "haproxy -c: ${first:-invalid}"; hint "Only the first alert is real (§3.1)."; fi
    grep -qE '^[[:space:]]*timeout[[:space:]]+tunnel' "$HAPROXY_CFG" && c_ok "timeout tunnel is set" \
      || { c_fail "timeout tunnel is missing - agents connect then drop every ~50s"; }
    grep -qE '\\[[:space:]]*$' "$HAPROXY_CFG" && c_fail "A line ends in '\\' - HAProxy has no line continuation (§3.1)"
    grep -q 'capture request header Authorization' "$HAPROXY_CFG" && c_warn "Temporary header capture is ON - turn it off before handover: $0 --proxy-debug off"
  else c_warn "$HAPROXY_CFG not present"; fi
  if command -v nginx >/dev/null; then
    nginx -t >"$RUN_TMP/nt.out" 2>&1 && c_ok "nginx -t: configuration is valid" || c_fail "nginx -t: $(grep -m1 -E 'emerg|error' "$RUN_TMP/nt.out")"
  fi

  section "4. Tunnel census (HAProxy stats)"
  if stats_csv | grep -q '^bindplane_cloud,'; then
    tunnel_census
    st=$(stats_field bindplane_cloud cloud status); cs=$(stats_field bindplane_cloud cloud check_status)
    [[ $st == UP* ]] && c_ok "Cloud backend is $st ($cs)" || { c_fail "Cloud backend is ${st:-?} ($cs)"; hint "$(describe_check_status "$cs")"; }
  else c_warn "HAProxy stats not reachable on 127.0.0.1:$STATS_PORT"; fi

  section "5. Upstream path (this host -> $BP_CLOUD_HOST:443, direct)"
  check_dns "$BP_CLOUD_HOST"
  check_tls "$BP_CLOUD_HOST"
  check_time

  section "6. Hop 1 probe (§4.1)"
  if [[ -n $DMZ_GW_IP && -n $BP_SECRET ]] && systemctl is-active --quiet haproxy; then
    probe_opamp "http://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp" "$RUN_TMP/diag.probe"
    say "      response: $(grep -aE '^HTTP/' "$RUN_TMP/diag.probe" | tail -n1 | tr -d '\r')   ${PROBE_VIA:-}"
    if classify_probe "$DMZ_GW_IP:$OPAMP_PORT" >/dev/null; then c_ok "Probe: ${PROBE_STATUS} ${PROBE_VIA} - path works end to end"
    else c_fail "Probe: $FAIL_WHAT"; hint "$FAIL_WHY"; fi
  else c_warn "Probe skipped (haproxy not running, or no DMZ_GW_IP/secret available)"; fi

  section "7. Package origin (:$REPO_PORT)"
  if [[ -n $DMZ_GW_IP ]]; then
    code=$(lcurl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$DMZ_GW_IP:$REPO_PORT/")
    if [[ $code == 200 ]]; then c_ok "Index http://$DMZ_GW_IP:$REPO_PORT/ answers 200"
    else c_fail "Index http://$DMZ_GW_IP:$REPO_PORT/ answers $([[ ${code:-000} == 000 ]] && echo 'nothing (nginx not listening?)' || echo "HTTP $code")"; fi
  fi
  if [[ -f $REPO_ROOT/SHA256SUMS ]]; then
    sums=$(cd "$REPO_ROOT" && sha256sum -c --quiet SHA256SUMS 2>&1 | head -n 5)
    [[ -z $sums ]] && c_ok "All $(wc -l <"$REPO_ROOT/SHA256SUMS") files match SHA256SUMS" || { c_fail "Checksum problems:"; printf '%s\n' "$sums" | sed 's/^/         /'; hint "Re-run: $0 --only checksums (after fixing the files)"; }
    [[ -f $REPO_ROOT/VERSION-INFO ]] && sed 's/^/      /' "$REPO_ROOT/VERSION-INFO"
  else c_warn "No $REPO_ROOT/SHA256SUMS yet"; fi
  if [[ -s $NGINX_ACCESS_LOG ]]; then
    say "      clients seen recently (who mirrored from us):"
    tail -n 2000 "$NGINX_ACCESS_LOG" | awk '{print $1}' | sort | uniq -c | sort -rn | head -n 5 | sed 's/^/        /'
  fi

  section "8. DMZ collector (Stage 1)"
  check_collector

  section "9. Gateway hygiene"
  check_ip_forward
  check_disk
  if ufw_active; then c_ok "ufw active; bindplane rules:"; ufw status 2>/dev/null | grep -i bindplane | sed 's/^/        /'
  else say "      ufw not active"; fi
  [[ -n $(apparmor_denials) ]] && { c_warn "Recent AppArmor denials for haproxy/nginx:"; apparmor_denials | sed 's/^/        /'; }
  if systemctl cat haproxy >/dev/null 2>&1; then
    [[ $(systemctl show haproxy -p LimitNOFILE --value 2>/dev/null) == 65535 ]] && c_ok "haproxy LimitNOFILE=65535" || c_warn "haproxy LimitNOFILE is not 65535 (§3.5)"
  fi

  section "10. Recent HAProxy log"
  journalctl -u haproxy -n 200 --no-pager -o cat 2>/dev/null | grep -vE ' stats_in |HTTPCLIENT' | tail -n 8 | cut -c1-200 | sed 's/^/      /'

  echo
  if (( CHK_FAILS )); then err "Diagnostics: $CHK_FAILS failure(s), $CHK_WARNS warning(s) - fix the first failure first; most problems are one segment away from where they appear."
  else ok "Diagnostics: no failures, $CHK_WARNS warning(s)"
    hint "If an agent still is not Connected: probe 403 + 'Via: 1.1 google' means the path is fine - check that host's manager.yaml, clock and agent_id."
    hint "Escalate to Bindplane if sessions drop with no event at either proxy or firewall (include both HAProxy configs and collector.log)."
  fi
  return 0
}

action_diagnose() {
  init_defaults; load_config || true
  detect_defaults
  BP_CLOUD_HOST=${BP_CLOUD_HOST:-${DET_CLOUD_HOST:-app.bindplane.com}}
  BP_SECRET=${BP_SECRET:-$DET_SECRET}
  [[ -z $DMZ_GW_IP && -f $HAPROXY_CFG ]] && DMZ_GW_IP=$(sed -nE "s/^[[:space:]]*bind[[:space:]]+([0-9.]+):$OPAMP_PORT.*/\1/p" "$HAPROXY_CFG" | head -n1)
  set_proxy_opts
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
  local p h
  p=$(state_get probe_hop1); h=$(state_get collector_via_hop1)
  if [[ $p == "done" && $h == "done" ]]; then ok "Gates §4.2 and §4.4 PASSED - the LIVE gateway build (Stage 5) may start"
  else
    [[ $p == "done" ]] || warn "Gate §4.2 (probe 403 + Via: 1.1 google) not yet passed"
    [[ $h == "done" ]] || warn "Gate §4.4 (real collector through hop 1) not yet passed"
    hint "Do not start Stage 5 until both pass (runbook §4.4)."
  fi
}

show_config() {
  printf '  %-30s %s\n' \
    "Site" "$SITE" \
    "Bindplane Cloud host" "$BP_CLOUD_HOST" \
    "Secret key" "$(mask "$BP_SECRET") (${#BP_SECRET} chars)" \
    "Collector version (estate)" "$BP_VERSION" \
    "DMZ gateway IP (bind)" "$DMZ_GW_IP${DMZ_GW_IP:+ on $(iface_of_ip "$DMZ_GW_IP")}" \
    "LIVE gateway IP" "$LIVE_GW_IP" \
    "Host-firewall sources/ports" "${FW_SOURCES:-?} -> tcp ${FW_PORTS:-?} $(ufw_active && echo '(ufw active)' || echo '(ufw inactive: not applied)')" \
    "HAProxy maxconn" "$HAPROXY_MAXCONN" \
    "Stage RPM / ARM64 / Windows" "${STAGE_RPM:-?} / ${STAGE_ARM64:-?} / ${STAGE_WINDOWS:-?}" \
    "Local apt repository" "${BUILD_APT_REPO:-?}${EXTRA_APT_PKGS:+ (+ $EXTRA_APT_PKGS)}$( [[ $SIGN_APT_REPO == yes ]] && echo ', signed')" \
    "Download proxy" "${DL_PROXY:-none (direct)}" \
    "Pause between steps" "${PAUSE_BETWEEN_STEPS:-no}"
}

action_status() {
  init_defaults
  if load_config; then banner_line "Saved configuration ($CONF_FILE)"; show_config; else warn "No saved configuration yet"; fi
  banner_line "Step progress"; show_progress
  echo; show_gates
  [[ -f $HOP_MARKER ]] && warn "A §4.4 test is marked in progress - the next run restores manager.yaml first"
}

action_list() {
  local s i=0
  for s in "${STEPS[@]}"; do i=$((i+1)); printf '  %2d  %-20s %-52s runbook %s\n' "$i" "$s" "${STEP_TITLE[$s]}" "${STEP_REF[$s]}"; done
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

action_export_repo() {
  local dir=${ACTION_ARG:-/var/tmp} name need avail
  init_defaults; load_config || true
  [[ -f $REPO_ROOT/SHA256SUMS ]] || { err "$REPO_ROOT/SHA256SUMS not found - build the repository first."; exit 1; }
  install -d "$dir" || exit 1
  need=$(du -sk "$REPO_ROOT" | awk '{print $1}'); avail=$(df -Pk "$dir" | awk 'NR==2{print $4}')
  (( avail > need )) || { err "Not enough space in $dir ($(human $((avail*1024))) free, need ~$(human $((need*1024))))"; exit 1; }
  name="bindplane-repo-${BP_VERSION:-unknown}-$(date +%Y%m%d).tar.gz"
  banner_line "Export the repository for controlled transfer (runbook §7.2)"
  run "Verifying the repository (sha256sum -c)" bash -c "cd '$REPO_ROOT' && sha256sum -c --quiet SHA256SUMS" || { err "Fix the repository first (--only checksums)"; exit 1; }
  run "Packaging $REPO_ROOT -> $dir/$name" tar -czf "$dir/$name" -C "$(dirname "$REPO_ROOT")" "$(basename "$REPO_ROOT")" || exit 1
  ( cd "$dir" && sha256sum "$name" >"$name.sha256" )
  ok "$(cat "$dir/$name.sha256")"
  say "  Record this checksum at both ends. On the receiving DMZ host (same Ubuntu release: $(os_field VERSION_ID)):"
  say "    sha256sum -c $name.sha256 && sudo tar -xzf $name -C $(dirname "$REPO_ROOT") && sudo chmod -R a+rX $REPO_ROOT"
  say "    cd $REPO_ROOT && sudo sha256sum -c SHA256SUMS"
  say "  If that host cannot reach the Ubuntu mirrors, install the proxy software from the imported repository first:"
  say "    echo 'deb [trusted=yes] file:$REPO_ROOT/apt ./' | sudo tee /etc/apt/sources.list.d/bindplane-import.list"
  say "    sudo apt-get -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/bindplane-import.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 update"
  say "    sudo apt-get -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/bindplane-import.list -o Dir::Etc::sourceparts=- install -y nginx haproxy"
  say "  Then run this script there (site 'dr'). Imported artefacts are verified against SHA256SUMS instead of"
  say "  being downloaded again; if the base_packages/os_repo steps cannot reach a mirror, choose [s] - the"
  say "  imported repository already contains their output."
}

upgrade_local_collector() {
  local arch deb aid0 aid1 v
  arch=$(dpkg --print-architecture)
  deb="$REPO_ROOT/packages/observiq-otel-collector_${BP_VERSION}_linux_${arch}.deb"
  [[ -f $deb ]] || { err "$deb is not staged"; return 1; }
  aid0=$(yaml_get agent_id)
  run "Installing $deb" dpkg -i "$deb" || { err "dpkg failed - the previous version is still installed"; return 1; }
  sleep 5
  v=$(collector_version)
  [[ $v == "$BP_VERSION" ]] && ok "Collector now reports $v" || warn "Collector reports '${v:-?}' (expected $BP_VERSION)"
  systemctl is-active --quiet "$COLLECTOR_SVC" && ok "Collector is running" || err "Collector is not running - escalate to Bindplane if an upgrade leaves it stopped (§13.3)"
  aid1=$(yaml_get agent_id)
  if [[ $aid0 == "$aid1" ]]; then ok "agent_id unchanged ($aid1)"
  else err "agent_id CHANGED ($aid0 -> $aid1): the host re-registered as a new agent - escalate to Bindplane (§13.3)"; fi
}

action_fetch_version() {
  local newv=$ACTION_ARG old msg
  init_defaults; load_config || { err "No saved configuration - run the full build first."; exit 1; }
  msg=$(v_version "$newv") || { err "$msg"; exit 2; }
  [[ $newv == v* ]] || newv="v$newv"
  set_proxy_opts
  old=$BP_VERSION
  banner_line "Stage collector $newv next to $old (runbook §13.3, DMZ part)"
  BP_VERSION=$newv
  FORCE_ALL=1; ADHOC=1
  run_steps collector_artefacts checksums
  ADHOC=0
  save_config
  ok "$newv is now the current version in $REPO_ROOT (previous versions are kept for rollback, §13.4)"
  if ask_yn "Upgrade THIS host's collector to $newv now (DMZ gateways are upgraded first, §13.2)?" n; then
    upgrade_local_collector
    hint "Rollback if needed: dpkg -i --force-downgrade $REPO_ROOT/packages/observiq-otel-collector_${old}_linux_$(dpkg --print-architecture).deb"
  fi
  say "  Next, on the LIVE gateway: sudo /usr/local/bin/bp-mirror-sync   (pulls only the delta, §13.3)"
}

action_rollback() {
  local src port others
  init_defaults; load_config || true
  banner_line "Rollback - back out the changes made by this script"
  say "  This will:"
  say "    - restore the collector's direct connection if a §4.4 test is pending"
  say "    - restore $HAPROXY_CFG from $HAPROXY_CFG.orig, then stop and disable haproxy"
  say "    - remove the nginx site 'bindplane-repo' (and stop nginx if no other site is enabled)"
  say "    - remove $HAPROXY_DROPIN and the ufw rules this script added"
  say "    - clear step progress (your answers are kept)"
  say "  Packages stay installed and $REPO_ROOT is kept unless you choose to delete it."
  ask_yn "Proceed with the rollback?" n || { info "Nothing changed"; return 0; }
  [[ -f $HOP_MARKER ]] && hop_restore
  if [[ -f $HAPROXY_CFG.orig ]]; then cp -p "$HAPROXY_CFG" "$HAPROXY_CFG.rolledback-$RUN_TS" 2>/dev/null; cp -p "$HAPROXY_CFG.orig" "$HAPROXY_CFG"; ok "haproxy.cfg restored (previous copy: $HAPROXY_CFG.rolledback-$RUN_TS)"; fi
  if systemctl cat haproxy >/dev/null 2>&1; then systemctl disable --now haproxy >/dev/null 2>&1 && ok "haproxy stopped and disabled"; fi
  rm -f "$HAPROXY_DROPIN" && rmdir "$HAPROXY_DROPIN_DIR" 2>/dev/null; systemctl daemon-reload 2>/dev/null; ok "LimitNOFILE drop-in removed"
  if [[ -e $NGINX_LINK || -e $NGINX_SITE ]]; then
    rm -f "$NGINX_LINK" "$NGINX_SITE"; ok "nginx site bindplane-repo removed"
    others=$(find /etc/nginx/sites-enabled -mindepth 1 -maxdepth 1 2>/dev/null | head -n1)
    if [[ -z $others ]]; then systemctl disable --now nginx >/dev/null 2>&1 && ok "nginx stopped and disabled (no other sites)"
    else systemctl reload nginx >/dev/null 2>&1 && ok "nginx reloaded (other sites remain)"; fi
  fi
  if [[ -s $UFW_RECORD ]] && command -v ufw >/dev/null; then
    local dst
    while read -r src port dst; do
      [[ -n $src ]] || continue; dst=${dst:-$DMZ_GW_IP}
      ufw delete allow proto tcp from "$src" to "$dst" port "$port" >/dev/null 2>&1 && ok "ufw rule removed: $src -> $dst tcp/$port" || warn "Could not remove ufw rule $src -> $dst tcp/$port (check: ufw status numbered)"
    done <"$UFW_RECORD"
    rm -f "$UFW_RECORD"
  fi
  if ask_yn "Also DELETE the repository contents in $REPO_ROOT (downloads would have to be repeated)?" n; then
    rm -rf --one-file-system "${REPO_ROOT:?}"/{packages,scripts,windows,apt,rpm} "$REPO_ROOT"/{SHA256SUMS,VERSION-INFO,README.txt}
    rm -f "$MANIFEST"; ok "Repository contents deleted"
  fi
  rm -f "$STATE_FILE"; ok "Step progress cleared"
  hint "Packages left installed. To remove them: apt-get purge haproxy nginx nginx-common"
}

# =============================================================================
#  Configuration dialogue
# =============================================================================
choose_dmz_ip() {
  local defif rows=() r i=0 ifc ip def="" sel msg note
  defif=$(default_iface)
  mapfile -t rows < <(ip -o -4 addr show scope global 2>/dev/null | awk '{print $2" "$4}')
  (( ${#rows[@]} )) || { err "No global IPv4 address found on this host."; return 1; }
  say "  IPv4 addresses on this host:"
  for r in "${rows[@]}"; do
    i=$((i+1)); ifc=${r%% *}; ip=${r#* }; ip=${ip%/*}; note=""
    [[ $ifc == "$defif" ]] && note="<- default route (likely internet-facing)"
    printf '     %d) %-14s %-20s %s\n' "$i" "$ifc" "${r#* }" "$note"
    [[ -z $def && $ifc != "$defif" ]] && def=$ip
  done
  [[ -n $DMZ_GW_IP ]] && def=$DMZ_GW_IP
  [[ -z $def ]] && { def=${rows[0]#* }; def=${def%/*}; }
  while :; do
    ask sel "Fortigate-facing address for HAProxy :$OPAMP_PORT and the repository :$REPO_PORT (number or IP)" "$def" || return 1
    if [[ $sel =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#rows[@]} )); then sel=${rows[$((sel-1))]#* }; sel=${sel%/*}; fi
    if ! msg=$(v_local_ip "$sel"); then warn "  $msg"; { (( ASSUME_YES )) || [[ -z $TTY ]]; } && return 1; continue; fi
    if [[ $(iface_of_ip "$sel") == "$defif" ]]; then
      if (( ${#rows[@]} > 1 )); then
        warn "  $sel is on the default-route interface ($defif). The runbook binds to the Fortigate-facing interface, never the internet-facing one."
        ask_yn "Use $sel anyway?" n || continue
      else
        info "  Single-interface host: services will bind to $sel; perimeter rules must restrict who can reach it."
      fi
    fi
    DMZ_GW_IP=$sel; return 0
  done
}

gather_config() {
  local first=${1:-0} live_name
  detect_defaults
  banner_line "Configuration"
  say "  Press Enter to accept the value in [brackets]. For optional values type 'none' to clear them."
  ask SITE "Site of this DMZ gateway (primary/dr)" "${SITE:-primary}" v_site || return 1
  ask BP_CLOUD_HOST "Bindplane Cloud host name" "${BP_CLOUD_HOST:-${DET_CLOUD_HOST:-app.bindplane.com}}" v_host || return 1
  if [[ -n $BP_SECRET ]]; then
    say "  Secret key: $(mask "$BP_SECRET") (saved, ${#BP_SECRET} chars)"
    ask_yn "Keep the saved secret key?" y || ask_secret BP_SECRET "Bindplane secret key (console -> Agents -> Install Agents)" || return 1
  elif [[ -n $DET_SECRET ]]; then
    say "  Secret key found in $MANAGER_YAML: $(mask "$DET_SECRET")"
    if ask_yn "Use this key (the one the DMZ collector already authenticates with)?" y; then BP_SECRET=$DET_SECRET
    else ask_secret BP_SECRET "Bindplane secret key (console -> Agents -> Install Agents)" || return 1; fi
  else
    ask_secret BP_SECRET "Bindplane secret key (console -> Agents -> Install Agents)" || return 1
  fi
  [[ $BP_SECRET =~ ^[0-9A-HJKMNP-TV-Z]{26}$ ]] || warn "  The key is not a 26-character ULID - double-check it (an invalid key fails exactly like a wrong one)."
  [[ -n $DET_SECRET && $BP_SECRET != "$DET_SECRET" ]] && warn "  This key differs from the one in $MANAGER_YAML."
  ask BP_VERSION "Collector version to stage for the estate (release tag)" "${BP_VERSION:-$DET_VERSION}" v_version || return 1
  [[ $BP_VERSION == v* ]] || BP_VERSION="v$BP_VERSION"
  [[ -n $DET_VERSION && $BP_VERSION != "$DET_VERSION" ]] && warn "  The DMZ collector runs $DET_VERSION - runbook §1.3 makes that the version for the whole estate."
  choose_dmz_ip || return 1
  live_name=$([[ $SITE == dr ]] && echo bp-gw-drlive-01 || echo bp-gw-live-01)
  ask LIVE_GW_IP "LIVE gateway address ($live_name, its LIVE-facing interface)" "$LIVE_GW_IP" v_remote_ip || return 1
  if ufw_active; then
    say "  ufw is active here: rules will allow only these sources to reach $DMZ_GW_IP."
    ask FW_SOURCES "Allowed sources (IPs/CIDRs: the LIVE gateway plus any PROD-DMZ log-source subnets)" "${FW_SOURCES:-$LIVE_GW_IP}" v_sources || return 1
    ask FW_PORTS "TCP ports to allow from them" "${FW_PORTS:-$OPAMP_PORT $REPO_PORT $OTLP_PORT}" v_ports || return 1
  else
    FW_SOURCES=${FW_SOURCES:-$LIVE_GW_IP}; FW_PORTS=${FW_PORTS:-"$OPAMP_PORT $REPO_PORT $OTLP_PORT"}
  fi
  ask HAPROXY_MAXCONN "HAProxy maxconn (>= 2x projected agents; 20000 supports ~10,000)" "${HAPROXY_MAXCONN:-20000}" v_maxconn || return 1
  say "  Collector artefacts to stage (§2.2 - everything the estate needs):"
  ask_yn_var STAGE_RPM     "  RPM for RHEL log sources?" yes
  ask_yn_var STAGE_ARM64   "  ARM64 .deb?" yes
  ask_yn_var STAGE_WINDOWS "  Windows MSI and install_windows.ps1?" yes
  say "  OS packages for the isolated hosts (§2.3). Answer n if CUSTOMER runs an internal Ubuntu mirror reachable from PROD-LIVE."
  ask_yn_var BUILD_APT_REPO "  Build the local apt repository (nginx, haproxy, wget + dependencies)?" yes
  if [[ $BUILD_APT_REPO == yes ]]; then
    ask EXTRA_APT_PKGS "  Extra Ubuntu packages to include (space-separated, or 'none')" "$EXTRA_APT_PKGS" v_pkgs 1 || return 1
    ask_yn_var SIGN_APT_REPO "  GPG-sign the repository (only if CUSTOMER requires signed repositories, §5.4)?" no
  else SIGN_APT_REPO=no; EXTRA_APT_PKGS=""; fi
  if (( first )); then DL_PROXY=${DL_PROXY:-$DET_PROXY}; fi
  ask DL_PROXY "Outbound proxy for downloads from this host ('none' = direct)" "$DL_PROXY" v_proxy 1 || return 1
  ask_yn_var PAUSE_BETWEEN_STEPS "Pause for confirmation between steps?" no
  return 0
}

config_complete() {
  local k
  for k in SITE BP_CLOUD_HOST BP_SECRET BP_VERSION DMZ_GW_IP LIVE_GW_IP FW_SOURCES FW_PORTS HAPROXY_MAXCONN STAGE_RPM STAGE_ARM64 STAGE_WINDOWS BUILD_APT_REPO PAUSE_BETWEEN_STEPS; do
    [[ -n ${!k-} ]] || return 1
  done
}

confirm_config() {
  local c
  while :; do
    banner_line "Please review"
    show_config
    if (( ASSUME_YES )) || [[ -z $TTY ]]; then return 0; fi
    c=$(choose "  Proceed with these values? [y]es / [e]dit / [q]uit: " yeq y)
    case $c in y) return 0 ;; e) gather_config 0 || return 1 ;; q) return 1 ;; esac
  done
}

# Steps whose result depends on a changed answer are re-run automatically.
declare -A DEPENDS=(
  [SITE]="repo_layout evidence"
  [BP_CLOUD_HOST]="preflight haproxy_config haproxy_start probe_hop1 collector_via_hop1 evidence"
  [BP_SECRET]="probe_hop1 collector_via_hop1"
  [BP_VERSION]="collector_artefacts checksums evidence"
  [DMZ_GW_IP]="preflight repo_layout nginx haproxy_config host_firewall haproxy_start probe_hop1 collector_via_hop1 checksums evidence"
  [LIVE_GW_IP]="host_firewall evidence"
  [FW_SOURCES]="host_firewall" [FW_PORTS]="host_firewall"
  [HAPROXY_MAXCONN]="haproxy_config haproxy_start probe_hop1"
  [STAGE_RPM]="collector_artefacts checksums" [STAGE_ARM64]="collector_artefacts checksums" [STAGE_WINDOWS]="collector_artefacts checksums"
  [BUILD_APT_REPO]="os_repo checksums" [EXTRA_APT_PKGS]="os_repo checksums" [SIGN_APT_REPO]="base_packages os_repo checksums"
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
      "step_$step"; rc=$?
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

final_summary() {
  banner_line "Result"
  show_progress
  echo
  show_gates
  echo
  say "  Repository      : http://$DMZ_GW_IP:$REPO_PORT/   ($REPO_ROOT)"
  say "  OpAMP relay     : ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp  ->  wss://$BP_CLOUD_HOST/v1/opamp"
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
    gather_config "$(( ! had ))" || { err "Configuration was not completed - nothing changed."; exit 1; }
    confirm_config || { info "Stopped before making changes."; exit 0; }
    save_config; ok "Answers saved to $CONF_FILE (root-only, mode 0600)"
  else
    banner_line "Using saved answers ($CONF_FILE)"
    show_config
    say "  (run with --reconfigure to change any of them)"
    if [[ -n $TTY ]] && (( ! ASSUME_YES )) && ! ask_yn "Continue with these values?" y; then
      gather_config 0 && confirm_config || { info "Stopped before making changes."; exit 0; }
      save_config; ok "Answers saved"
    fi
  fi
  (( had )) && invalidate_changed
  set_proxy_opts

  if [[ -n $ONLY_STEP ]]; then
    list=("$ONLY_STEP"); FORCED[$ONLY_STEP]=1
    # repository content changed -> SHA256SUMS must follow in the same run
    if contains_word "repo_layout collector_artefacts os_repo" "$ONLY_STEP"; then list+=(checksums); FORCED[checksums]=1; fi
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
  run_steps "${list[@]}"
  final_summary
}

# =============================================================================
#  Entry point
# =============================================================================
usage() {
  cat <<EOF
$SCRIPT_NAME v$SCRIPT_VERSION - CUSTOMER Bindplane DMZ gateway build (runbook v1.0, Stages 2-4) for Ubuntu

Usage: sudo bash $0 [options]

Build (default): asks for the values it needs, then runs every pending step.
Re-running resumes at the first unfinished step; completed steps are skipped.
  --reconfigure        ask all questions again (previous answers are the defaults)
  --from STEP          re-run STEP and every step after it
  --only STEP          re-run just STEP (e.g. --only probe_hop1)
  --pause              pause for confirmation between steps
  -y, --yes            accept saved/default answers without prompting; quit on the first failure

Operations:
  --status             saved answers (secret masked), step progress and gate status
  --list-steps         list step names
  --diagnose           read-only health check of the whole DMZ side (troubleshooting reference)
  --fetch-version VER  stage collector VER next to the current one (upgrade, §13.3); keeps old versions
  --export-repo [DIR]  tar up $REPO_ROOT for controlled transfer to the DR-DMZ host (§7.2; default /var/tmp)
  --proxy-debug on|off temporary HAProxy header capture for troubleshooting (remove before handover)
  --rollback           back out this script's changes (HAProxy config, nginx site, ufw rules, drop-in)
  --reset              forget step progress (answers are kept)
  --no-color           plain output
  -h, --help           this help

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
      --fetch-version) need=1; ACTION=fetch; ACTION_ARG=${2:-} ;;
      --fetch-version=*) ACTION=fetch; ACTION_ARG=${1#*=} ;;
      --export-repo)   ACTION="export"; if [[ -n ${2:-} && ${2:0:1} != - ]]; then ACTION_ARG=$2; shift; fi ;;
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
  [[ -n $DL_PID ]] && kill "$DL_PID" 2>/dev/null
  echo
  warn "Received SIG$sig - stopping safely."
  unblock_service_autostart
  if (( HOP_TEST_ACTIVE )) || [[ -f $HOP_MARKER ]]; then warn "Restoring the collector's direct connection first ..."; hop_restore; fi
  [[ -n $CURRENT_STEP ]] && state_set "$CURRENT_STEP" interrupted
  info "Progress is saved. Re-run the script to resume${CURRENT_STEP:+ at: ${STEP_TITLE[$CURRENT_STEP]}}."
  [[ -n $LOG_FILE ]] && info "Log: $LOG_FILE"
  exit 130
}

on_exit() {
  [[ -n $DL_PID ]] && kill "$DL_PID" 2>/dev/null
  unblock_service_autostart
  [[ -n $RUN_TMP && -d $RUN_TMP ]] && rm -rf "$RUN_TMP"
}

main() {
  local c miss=""
  parse_args "$@"
  setup_colors
  [[ $ACTION == help ]] && { usage; exit 0; }
  (( EUID == 0 )) || { echo "This script must run as root:  sudo bash $0 $*" >&2; exit 1; }
  for c in systemctl journalctl ss ip awk sed grep flock sha256sum od stat df mktemp; do command -v "$c" >/dev/null || miss+=" $c"; done
  [[ -z $miss ]] || { echo "Missing required commands:$miss (is this Ubuntu?)" >&2; exit 1; }

  install -d -m 700 "$STATE_DIR" "$LOG_DIR" "$EVIDENCE_DIR" || { echo "Cannot create $STATE_DIR / $LOG_DIR" >&2; exit 1; }
  LOG_FILE="$LOG_DIR/run-$RUN_TS-$ACTION.log"; : >"$LOG_FILE"; chmod 600 "$LOG_FILE"
  RUN_TMP=$(mktemp -d "/tmp/$SCRIPT_NAME.XXXXXX") || exit 1
  if [[ -c /dev/tty ]] && ( : </dev/tty ) 2>/dev/null; then TTY=/dev/tty; fi

  exec 9>>"$LOCK_FILE"
  if ! flock -n 9; then
    echo "Another $SCRIPT_NAME run is in progress (PID $(head -n1 "$LOCK_FILE" 2>/dev/null || echo '?'), lock $LOCK_FILE)." >&2
    echo "Wait for it to finish, or check: ps -fp \$(head -n1 $LOCK_FILE)" >&2
    exit 1
  fi
  printf '%s\n' "$$" >"$LOCK_FILE"
  trap 'on_signal INT' INT; trap 'on_signal TERM' TERM; trap 'on_signal HUP' HUP; trap on_exit EXIT
  unblock_service_autostart   # remove a stale policy-rc.d from an interrupted run

  banner_line "CUSTOMER Bindplane - DMZ gateway build   ($SCRIPT_NAME v$SCRIPT_VERSION, runbook v1.0 Stages 2-4)"
  say "  Host: $(hostname -s)   Action: $ACTION   Log: $LOG_FILE"
  log "args: $*"
  if [[ $ACTION == build && -n ${SSH_CONNECTION:-} && -z ${TMUX:-}${STY:-} ]]; then
    say "  Tip: over SSH, run inside tmux or screen. If the session drops, re-run the script - it resumes."
  fi
  if [[ -f $HOP_MARKER ]]; then
    warn "A previous run was interrupted during the §4.4 test - the collector may still point at the relay."
    hop_restore || warn "Automatic restore failed - see the hint above before continuing."
  fi

  case $ACTION in
    build)      action_build ;;
    status)     action_status ;;
    list)       action_list ;;
    diagnose)   action_diagnose ;;
    fetch)      action_fetch_version ;;
    export)     action_export_repo ;;
    proxydebug) action_proxy_debug ;;
    rollback)   action_rollback ;;
    reset)      action_reset ;;
  esac
}

main "$@"

#!/usr/bin/env bash
# =============================================================================
#  bp-live-collector-v2.sh  -  CBSL Bindplane: the v2 collector
#                              (bindplane-otel-collector) on the LIVE gateway
# =============================================================================
#  Installs (or repairs), configures and verifies the v2 collector on
#  bp-gw-live-01 / bp-gw-drlive-01, and writes v2 hand-off notes for the
#  log sources. bp-live-setup.sh builds everything else on this host (mirror,
#  nginx, HAProxy hop 2) and leaves the collector steps to this script.
#
#  The v2 package is laid out differently from the v1 one in the runbook:
#     v1  observiq-otel-collector    /opt/observiq-otel-collector   manager.yaml
#     v2  bindplane-otel-collector   /opt/bindplane-otel-collector  supervisor.yaml
#  In v2 the OpAMP supervisor (opampsupervisor) holds the connection to
#  Bindplane and runs the collector; supervisor.yaml is written here the same
#  way the vendor's v2 installer writes it.
#
#  Resumable: progress is saved after every step - re-run to continue.
#  Explains every failure, then offers retry / diagnostics / skip / quit.
#  The secret key is never saved by this script (it lives only in
#  supervisor.yaml, mode 0600).
#
#  Usage:  sudo bash bp-live-collector-v2.sh          (then follow the prompts)
#          sudo bash bp-live-collector-v2.sh --help
# =============================================================================

SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="bp-live-collector-v2"

set -uo pipefail
umask 022
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

# Shared with bp-live-setup.sh ------------------------------------------------------
STATE_DIR=${BP_STATE_DIR:-/var/lib/bp-live-setup}
LOG_DIR=${BP_LOG_DIR:-/var/log/bp-live-setup}
REPO_ROOT=${BP_REPO_ROOT:-/srv/bindplane}
LIVE_CONF="$STATE_DIR/setup.conf"              # bp-live-setup.sh answers (read; BP_VERSION updated)
LIVE_STATE_FILE="$STATE_DIR/progress"          # bp-live-setup.sh progress (its collector steps are marked done)
LOCK_FILE="/run/bp-live-setup.lock"            # same lock: never runs alongside bp-live-setup.sh
EVIDENCE_DIR="$LOG_DIR/evidence"
NEXT_STEPS_FILE="$LOG_DIR/NEXT-STEPS-LOG-SOURCES.txt"
# This script's own answers (no secret), progress and completion marker
CONF_FILE="$STATE_DIR/collector-v2.conf"
STATE_FILE="$STATE_DIR/collector-v2.progress"
V2_MARKER="$STATE_DIR/collector-v2.done"
LOG_MARK="$STATE_DIR/collector-v2.logmark"

V2_PKG="bindplane-otel-collector"; V2_SVC="bindplane-otel-collector"
V2_HOME=${BP_V2_HOME:-/opt/bindplane-otel-collector}
V2_UNIT="/usr/lib/systemd/system/bindplane-otel-collector.service"
V2_OVERRIDE_DIR="/etc/systemd/system/bindplane-otel-collector.service.d"
SUP_YAML="$V2_HOME/supervisor.yaml"
SUP_LOG="$V2_HOME/supervisor.log"
AGENT_LOG="$V2_HOME/supervisor_storage/agent.log"
EFFECTIVE_YAML="$V2_HOME/supervisor_storage/effective.yaml"
V1_PKG="observiq-otel-collector"; V1_SVC="observiq-otel-collector"
COLLECTOR_PKG=$V1_PKG                          # for collector_installed_version (v1 detection)

OPAMP_PORT=3001
OTLP_PORT=4317
REPO_PORT=8080
STATS_PORT=8404
STATS_URL="http://127.0.0.1:${STATS_PORT}/stats;csv"
REPO_KEYRING=""; REPO_SIGNED="no"              # referenced by the shared apt/dpkg explanations

STEPS=(preflight package path config start verify handoff)
declare -A STEP_TITLE=(
  [preflight]="Pre-flight checks (and the v1 collector, if present)"
  [package]="Install or repair the v2 package from the mirror"
  [path]="Path to the DMZ gateway (OpAMP relay hop 1)"
  [config]="Write supervisor.yaml"
  [start]="Enable and start the v2 collector"
  [verify]="Verify the collector is connected"
  [handoff]="Mirror check, evidence, log-source hand-off"
)
declare -A STEP_REF=(
  [preflight]="Pre-flight" [package]="§6.4 (v2)" [path]="§5.1, §6.3" [config]="§6.4 (v2)"
  [start]="§6.4 (v2)" [verify]="§6.5" [handoff]="§12.1, Stage 8"
)

CONF_KEYS=(SITE DMZ_GW_IP LIVE_GW_IP V2_VERSION V2_LABELS PAUSE_BETWEEN_STEPS)
init_defaults() { SITE="" DMZ_GW_IP="" LIVE_GW_IP="" V2_VERSION="" V2_LABELS="" PAUSE_BETWEEN_STEPS="no"; }
# Steps whose result depends on a changed answer run again
declare -A DEPENDS=(
  [V2_VERSION]="package start verify handoff"
  [DMZ_GW_IP]="path config start verify handoff"
  [V2_LABELS]="config start verify handoff"
  [SITE]="handoff" [LIVE_GW_IP]="handoff"
)

# Runtime globals -------------------------------------------------------------------
ACTION="build"; ACTION_ARG=""; FROM_STEP=""; ONLY_STEP=""; DEB_ARG=""; V1_ACTION=""
ASSUME_YES=0; RECONFIGURE=0; FORCE_PAUSE=0; USE_COLOR=1; FORCE_ALL=0; ADHOC=0
CURRENT_STEP=""; FAIL_WHAT=""; FAIL_WHY=""; FAIL_FIX=""; LAST_OUT=""
RUN_TS=$(date +%Y%m%d-%H%M%S)
LOG_FILE=""; RUN_TMP=""; TTY=""; TTY_OUT=0
ENV_SECRET=${BP_SECRET:-}; BP_SECRET=""
PROBE_STATUS=""; PROBE_VIA=""; PROBE_RC=0
CHK_FAILS=0; CHK_WARNS=0
declare -A FORCED=() OLD_CONF=()

# =============================================================================
#  Shared helpers (verbatim from bp-dmz-setup.sh / bp-live-setup.sh)
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
is_ipv4() {
  local ip=$1 o
  [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
}
local_ipv4s() { ip -o -4 addr show 2>/dev/null | awk '{split($4,a,"/"); print a[1]}'; }
is_local_ip() { local_ipv4s | grep -qxF "$1"; }
v_version(){ [[ $1 =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.]+)?$ ]] || { echo "'$1' is not a release tag. Use the form v1.108.1"; return 1; }; }
v_ipv4()   { is_ipv4 "$1" || { echo "'$1' is not a valid IPv4 address."; return 1; }; }
v_site()   { [[ $1 == primary || $1 == dr ]] || { echo "Enter 'primary' or 'dr'."; return 1; }; }
v_remote_ip(){
  is_ipv4 "$1" || { echo "'$1' is not a valid IPv4 address."; return 1; }
  is_local_ip "$1" && { echo "$1 belongs to THIS host - enter the LIVE gateway's address."; return 1; }
  return 0
}
v_labels() { [[ $1 =~ ^[A-Za-z0-9_.-]+=[A-Za-z0-9_.-]+(,[A-Za-z0-9_.-]+=[A-Za-z0-9_.-]+)*$ ]] || { echo "Use key=value pairs separated by commas, e.g. site=primary,segment=prod-live,role=gateway"; return 1; }; }
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
os_field() { ( . /etc/os-release 2>/dev/null; eval "printf '%s' \"\${$1:-}\"" ); }
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
check_space() { # PATH MIN_GB LABEL
  local path=$1 min=$2 label=$3 avail fs
  while [[ ! -e $path ]]; do path=$(dirname "$path"); done
  avail=$(( $(df -Pk "$path" | awk 'NR==2{print $4}') * 1024 ))
  fs=$(df -P "$path" | awk 'NR==2{print $6}')
  if (( avail < min * 1024 * 1024 * 1024 / 4 )); then c_fail "Only $(human $avail) free for $label (filesystem $fs) - need ~${min} GB"; return 1
  elif (( avail < min * 1024 * 1024 * 1024 )); then c_warn "$(human $avail) free for $label (filesystem $fs) - ~${min} GB recommended"
  else c_ok "$(human $avail) free for $label (filesystem $fs)"; fi
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
collector_installed_version() { # v1.2.3 from dpkg, or empty
  local v; v=$(dpkg-query -W -f='${Status}|${Version}' "$COLLECTOR_PKG" 2>/dev/null)
  [[ $v == *"ok installed|"* ]] && printf 'v%s' "${v##*|}"
}
# stats_csv -> raw CSV from the local stats frontend
stats_csv() { lcurl -s --max-time 5 "$STATS_URL" 2>/dev/null; }
# stats_field PXNAME SVNAME FIELD   (field looked up by header name)
stats_field() {
  stats_csv | awk -F, -v px="$1" -v sv="$2" -v f="$3" '
    NR==1 { sub(/^# */,""); for (i=1;i<=NF;i++) idx[$i]=i; next }
    $1==px && $2==sv && (f in idx) { print $(idx[f]); exit }'
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
apparmor_denials() { # recent AppArmor denials for haproxy/nginx
  { journalctl -k --since "-30min" --no-pager 2>/dev/null || dmesg 2>/dev/null; } | grep -i 'apparmor="DENIED"' | grep -iE 'haproxy|nginx' | tail -n 5
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
section() { printf '\n%s--- %s ---%s\n' "$C_BLD" "$*" "$C_OFF"; log "---- $*"; }
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

# =============================================================================
#  Answers, state of bp-live-setup.sh
# =============================================================================
save_config() {
  local tmp k
  tmp=$(mktemp "$STATE_DIR/.v2conf.XXXXXX") || return 1
  { echo "# $SCRIPT_NAME answers - written $(date -Is). No secret key here: it lives only in $SUP_YAML (0600)."
    for k in "${CONF_KEYS[@]}"; do printf '%s=%q\n' "$k" "${!k-}"; done; } >"$tmp"
  chmod 600 "$tmp" && mv -f "$tmp" "$CONF_FILE"
}
# live_conf_get KEY - a value from bp-live-setup.sh's answers (empty if absent)
live_conf_get() {
  [[ -f $LIVE_CONF && $(stat -c %u "$LIVE_CONF") == 0 ]] || return 0
  # shellcheck disable=SC1090
  ( source "$LIVE_CONF" >/dev/null 2>&1; printf '%s' "${!1-}" )
}
# live_conf_set KEY VALUE - change one answer in bp-live-setup.sh's answers
live_conf_set() {
  [[ -f $LIVE_CONF ]] || return 0
  local k=$1 line tmp
  line=$(printf '%s=%q' "$k" "$2")
  tmp=$(mktemp "$STATE_DIR/.liveconf.XXXXXX") || return 1
  if grep -q "^$k=" "$LIVE_CONF"; then
    while IFS= read -r l; do [[ $l == "$k="* ]] && printf '%s\n' "$line" || printf '%s\n' "$l"; done <"$LIVE_CONF" >"$tmp"
  else cat "$LIVE_CONF" >"$tmp"; printf '%s\n' "$line" >>"$tmp"; fi
  chmod 600 "$tmp" && mv -f "$tmp" "$LIVE_CONF"
}
# live_state_set STEP STATUS - record a bp-live-setup.sh step
live_state_set() {
  local tmp
  tmp=$(mktemp "$STATE_DIR/.progress.XXXXXX") || return 1
  { [[ -f $LIVE_STATE_FILE ]] && grep -v "^$1|" "$LIVE_STATE_FILE"; printf '%s|%s|%s\n' "$1" "$2" "$(date -Is)"; } >"$tmp"
  chmod 600 "$tmp"; mv -f "$tmp" "$LIVE_STATE_FILE"
  log "LIVE-STATE $1=$2"
}
live_state_get() { [[ -f $LIVE_STATE_FILE ]] && grep "^$1|" "$LIVE_STATE_FILE" | tail -n1 | cut -d'|' -f2; }
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
#  v2 package helpers
# =============================================================================
is_v2_version() { [[ $1 =~ ^v?([2-9]|[1-9][0-9]+)\. ]]; }
v_v2_version() {
  v_version "$1" || return 1
  is_v2_version "$1" || { echo "'$1' is a v1 release - this script is for the v2 package (bindplane-otel-collector, v2.x tags such as v2.0.1-beta.6). For v1 use bp-live-setup.sh."; return 1; }
  return 0
}
deb_version_of() { local v=${1#v}; printf '%s' "${v//-/\~}"; }          # v2.0.1-beta.6 -> 2.0.1~beta.6
v2_status() { dpkg-query -W -f='${Status}' "$V2_PKG" 2>/dev/null; }
v2_installed_version() {
  local v; v=$(dpkg-query -W -f='${Status}|${Version}' "$V2_PKG" 2>/dev/null)
  [[ $v == *"ok installed|"* ]] && { v=${v##*|}; printf 'v%s' "${v//\~/-}"; }
}
v2_owner() { stat -c '%U:%G' "$V2_HOME" 2>/dev/null || echo bdot:bdot; }
sup_get() { # field from supervisor.yaml: endpoint | labels | secret
  [[ -r $SUP_YAML ]] || return 0
  case $1 in
    endpoint) sed -nE 's/^[[:space:]]+endpoint:[[:space:]]*"?([^"[:space:]]+)"?.*/\1/p' "$SUP_YAML" | head -n1 ;;
    labels)   sed -nE 's/^[[:space:]]+service\.labels:[[:space:]]*"?([^"]*)"?.*/\1/p' "$SUP_YAML" | head -n1 ;;
    secret)   sed -nE 's/^[[:space:]]*Authorization:[[:space:]]*"?Secret-Key[[:space:]]+([^"[:space:]]+)"?.*/\1/p' "$SUP_YAML" | head -n1 ;;
  esac
}
# local address of the supervisor's established OpAMP session to hop 1
v2_conn() { ss -Htnp state established dst "$DMZ_GW_IP:$OPAMP_PORT" 2>/dev/null | grep -i 'opampsupervisor' | awk '{print $3}' | head -n1; }
agent_running() { pgrep -f "^$V2_HOME/bindplane-otel-collector( |$)|^\./bindplane-otel-collector( |$)" >/dev/null 2>&1; }
# warnings the v2 collector prints on every start (vendor bootstrap config) - not problems
BENIGN_RE='Using legacy service\.telemetry\.resource|Capabilities is deprecated'
log_lines() { [[ -r $1 ]] && wc -l <"$1" || echo 0; }
# last N problem lines of a log since line FROM (secrets redacted, long JSON trimmed)
log_errors() { # FILE FROM N
  [[ -r $1 ]] || return 0
  local from=${2:-0}; (( from < 0 )) && from=0
  tail -n +"$(( from + 1 ))" "$1" 2>/dev/null \
    | grep -iE '"level":"(error|warn)"|\berror\b|failed|refused|unauthori|forbidden|denied|bad handshake|status[ =:]*[45][0-9][0-9]|[^0-9](401|403)[^0-9]' \
    | grep -vE "$BENIGN_RE" | sed -E 's/"stacktrace":"[^"]*"//; s/"caller":"[^"]*",?//; s/"resource":\{[^}]*\},?//; s/,\}$/}/' | tail -n "${3:-6}" | cut -c1-240 | redact_stream
}
http_code_in_logs() { # FILE FROM -> 401/403/404/5xx seen in the log, if any
  [[ -r $1 ]] || return 0
  local from=${2:-0}; (( from < 0 )) && from=0
  tail -n +"$(( from + 1 ))" "$1" 2>/dev/null | grep -oE '(status( code)?[ =:"]*|HTTP/1\.1 |response code[ =:]*)[45][0-9]{2}|bad handshake.{0,40}[45][0-9]{2}' | grep -oE '[45][0-9]{2}' | tail -n1
}
# the secret key: environment, the existing supervisor.yaml, or a prompt - never stored by this script
ensure_secret() {
  [[ -n $BP_SECRET ]] && return 0
  local existing; existing=$(sup_get secret)
  if [[ -n $ENV_SECRET ]]; then
    BP_SECRET=$ENV_SECRET; info "Using the secret key from the BP_SECRET environment variable ($(mask "$BP_SECRET"))"
  elif [[ -n $existing ]] && { (( ! RECONFIGURE )) || ask_yn "Keep the secret key already in supervisor.yaml ($(mask "$existing"))?" y; }; then
    BP_SECRET=$existing; info "Using the secret key already in $SUP_YAML ($(mask "$BP_SECRET")) - to replace it: --reconfigure"
  else
    say "  The collector needs the Bindplane secret key (console -> Agents -> Install Agents)."
    say "  It is written only to $SUP_YAML (mode 0600) - this script does not keep a copy."
    ask_secret BP_SECRET "Bindplane secret key" || { fail "No secret key was provided." "It is required in supervisor.yaml." "Re-run interactively, or set BP_SECRET in the environment for an unattended run."; return 1; }
  fi
  [[ $BP_SECRET =~ ^[0-9A-HJKMNP-TV-Z]{26}$ ]] || warn "The key is not a 26-character ULID - double-check it (a wrong key fails exactly like an invalid one)."
  return 0
}
pick() { # PROMPT ALLOWED DEFAULT - a menu choice; the default when unattended
  if (( ASSUME_YES )) || [[ -z $TTY ]]; then log "MENU default $3"; echo "$3"; else choose "$1" "$2" "$3"; fi
}
# files in the mirror that carry v2 content under the v1 name (e.g. a renamed download)
misnamed_files() {
  find "$REPO_ROOT/packages" "$REPO_ROOT/windows" -maxdepth 1 -type f \
       \( -name 'observiq-otel-collector_v[2-9]*' -o -name 'observiq-otel-collector-v[2-9]*-SHA256SUMS' \) 2>/dev/null | sort
}
mirror_msi_rel() { # VERSION -> windows/... path of the v2 MSI in the mirror (empty if none)
  local v=$1
  if [[ -f $REPO_ROOT/windows/${V2_PKG}_${v}.msi ]]; then echo "windows/${V2_PKG}_${v}.msi"
  elif [[ -f $REPO_ROOT/windows/${V2_PKG}.msi ]] && grep -qx "current_collector_version=$v" "$REPO_ROOT/VERSION-INFO" 2>/dev/null; then echo "windows/${V2_PKG}.msi"
  fi
}

# =============================================================================
#  Steps  (0 = done, 1 = failed, 3 = skipped on purpose)
# =============================================================================
step_preflight() {
  local c miss="" v1 st a
  CHK_FAILS=0; CHK_WARNS=0
  check_os
  for c in dpkg dpkg-deb dpkg-query ss curl systemctl sha256sum stat timeout pgrep; do command -v "$c" >/dev/null || miss+=" $c"; done
  [[ -z $miss ]] || { fail "Missing commands:$miss" "A minimal image without these tools." "apt-get install iproute2 curl procps coreutils (from the DMZ repository)"; return 1; }
  c_ok "Required tools present"
  check_time
  check_space "$V2_HOME" 1 "the collector ($V2_HOME)"
  if [[ -f $LIVE_STATE_FILE ]]; then
    for c in mirror probe_chain; do
      st=$(live_state_get "$c")
      [[ $st == "done" ]] || c_warn "bp-live-setup.sh step '$c' is ${st:-pending} - the collector itself does not need it, but the log sources will"
    done
  else
    c_warn "No bp-live-setup.sh progress in $STATE_DIR - the mirror/HAProxy build is not recorded on this host"
  fi
  v1=$(collector_installed_version)
  if [[ -n $v1 ]] && ! systemctl is-active --quiet "$V1_SVC" && [[ $(systemctl is-enabled "$V1_SVC" 2>/dev/null) != enabled ]] && [[ -z $V1_ACTION ]]; then
    c_ok "The v1 collector package $v1 is installed but stopped and disabled - it will not run next to v2"
    hint "Remove it when no longer needed: dpkg --purge $V1_PKG   (or: $0 --only preflight --v1 remove)"
  elif [[ -n $v1 ]]; then
    st=$(systemctl is-active "$V1_SVC" 2>/dev/null)
    warn "The v1 collector $v1 ($V1_PKG) is installed on this host too (service: ${st:-unknown})."
    say "  Running v1 and v2 together means two agents for one host in the console, each with its own config."
    a=$V1_ACTION
    if [[ -z $a ]]; then
      if (( ASSUME_YES )) || [[ -z $TTY ]]; then
        fail "The v1 collector is installed and no choice was given for it." "Unattended runs never change the v1 collector on their own." \
             "Re-run interactively, or add --v1 stop (stop+disable, package kept), --v1 remove (dpkg --purge) or --v1 keep"
        return 1
      fi
      a=$(pick "  [s] stop + disable v1 (package kept for rollback)   [r] remove v1 (dpkg --purge)   [k] keep both   [q] quit: " srkq s)
      case $a in s) a=stop ;; r) a=remove ;; k) a=keep ;; *) info "Stopped - nothing changed."; exit 0 ;; esac
    fi
    case $a in
      stop)   run "Stopping and disabling $V1_SVC" systemctl disable --now "$V1_SVC" || return 1
              ok "v1 collector stopped and disabled (its package and manager.yaml are kept - re-enable: systemctl enable --now $V1_SVC)" ;;
      remove) systemctl disable --now "$V1_SVC" >/dev/null 2>&1
              run_stream "Removing $V1_PKG (dpkg --purge)" dpkg --purge "$V1_PKG" || { fail "dpkg could not remove $V1_PKG." "See the output above." "dpkg -l $V1_PKG ; dpkg --purge $V1_PKG"; return 1; }
              ok "v1 collector removed" ;;
      keep)   warn "Keeping the v1 collector running next to v2 at your request" ;;
    esac
  else
    c_ok "No v1 collector on this host"
  fi
  (( CHK_FAILS == 0 )) || { fail "Pre-flight found $CHK_FAILS problem(s)." "See the [FAIL] lines above." "Fix them, then choose [r]."; return 1; }
  return 0
}

# find_v2_deb -> DEB (verified path) ; prefers the real name, accepts a renamed copy if its content is right
find_v2_deb() {
  local arch v=$V2_VERSION dv name f rel pkg ver want got pubsums cands=() why=""
  arch=$(dpkg --print-architecture); dv=$(deb_version_of "$v"); name="${V2_PKG}_${v}_linux_${arch}.deb"
  pubsums="$REPO_ROOT/packages/${V2_PKG}-${v}-SHA256SUMS"
  [[ -n $DEB_ARG ]] && cands+=("$DEB_ARG")
  cands+=("$REPO_ROOT/packages/$name" "$REPO_ROOT/packages/observiq-otel-collector_${v}_linux_${arch}.deb")
  while IFS= read -r f; do cands+=("$f"); done < <(find /root /home /tmp /opt/bp-install -maxdepth 3 -type f -name "*otel-collector*${v}*_linux_${arch}.deb" 2>/dev/null)
  DEB=""
  for f in "${cands[@]}"; do
    [[ -f $f ]] || continue
    pkg=$(dpkg-deb -f "$f" Package 2>/dev/null); ver=$(dpkg-deb -f "$f" Version 2>/dev/null)
    if [[ $pkg != "$V2_PKG" || $ver != "$dv" ]]; then why+="\n  $f: package '${pkg:-not a .deb}' version '${ver:-?}'"; continue; fi
    [[ $(dpkg-deb -f "$f" Architecture 2>/dev/null) == "$arch" ]] || { why+="\n  $f: wrong architecture"; continue; }
    got=$(sha256 "$f"); want=""
    [[ -f $pubsums ]] && want=$(awk -v n="$name" '$2==n || $2==("*" n) {print $1; exit}' "$pubsums")
    if [[ -n $want ]]; then
      [[ $want == "$got" ]] || { why+="\n  $f: does NOT match the publisher's checksum for $name"; continue; }
      ok "$f matches the publisher's SHA256SUMS for $name"
    else
      rel=${f#"$REPO_ROOT"/}
      [[ $rel != "$f" && -f $REPO_ROOT/SHA256SUMS ]] && want=$(awk -v n="$rel" '$2==n {print $1; exit}' "$REPO_ROOT/SHA256SUMS")
      if [[ -n $want ]]; then
        [[ $want == "$got" ]] || { why+="\n  $f: does not match the mirror's SHA256SUMS (corrupt or partial copy)"; continue; }
        ok "$f matches the mirror's SHA256SUMS"
      else
        warn "$f has no checksum to verify against (no publisher or mirror SHA256SUMS entry)"
        ask_yn "Install it anyway (package name, version and architecture are right)?" n || { why+="\n  $f: unverified, not used"; continue; }
      fi
    fi
    [[ $(basename "$f") != "$name" ]] && info "$(basename "$f") is the v2 package under another name (a renamed copy) - its content is what matters"
    DEB=$f; return 0
  done
  fail "No usable $V2_PKG $v package (.deb, $arch) was found." \
       "Looked in $REPO_ROOT/packages (real and v1-style names), /root, /home, /tmp, /opt/bp-install.${why:+ Rejected:$why}" \
       "Stage it on the DMZ host:  bp-dmz-update-repo.sh --versions $v   then here:  bp-mirror-sync\nOr give the file:  $0 --deb /path/to/$name"
  return 1
}

step_package() {
  local st inst
  st=$(v2_status); inst=$(v2_installed_version)
  if [[ $inst == "$V2_VERSION" && -x $V2_HOME/opampsupervisor && -x $V2_HOME/bindplane-otel-collector && -f $V2_UNIT ]]; then
    ok "$V2_PKG $inst is installed ($V2_HOME, service $V2_SVC)"
    return 0
  fi
  if [[ -n $st && $st != *"ok installed"* ]]; then
    warn "$V2_PKG is in state '$st' (an install was interrupted) - installing it again"
    hint "The package's install script deletes its staging area, so 'dpkg --configure' cannot finish it - unpacking it again can."
  elif [[ -n $inst && $inst != "$V2_VERSION" ]]; then
    info "Installed: $inst, wanted: $V2_VERSION - replacing it (supervisor.yaml and the agent's identity in supervisor_storage/ are kept)"
  elif [[ -n $inst ]]; then
    warn "$V2_PKG $inst is registered, but files are missing from $V2_HOME - reinstalling"
  fi
  find_v2_deb || return 1
  info "Installing with dpkg - NOT with install_unix.sh, which needs the internet"
  dpkg_install "$DEB" || return 1
  inst=$(v2_installed_version)
  [[ $inst == "$V2_VERSION" ]] || { fail "dpkg finished, but $V2_PKG reports '${inst:-not installed}'." "The package scripts failed part-way." "dpkg -l $V2_PKG ; journalctl -n 30 ; then choose [r]"; return 1; }
  [[ -f $V2_UNIT && -x $V2_HOME/opampsupervisor ]] || { fail "$V2_PKG is installed but $V2_UNIT or $V2_HOME/opampsupervisor is missing." "The post-install script failed part-way." "Choose [r] to install it again."; return 1; }
  ok "$V2_PKG $inst installed; runtime owner of $V2_HOME: $(v2_owner)"
}

step_path() {
  local st out="$EVIDENCE_DIR/v2-probe-hop1-$RUN_TS.txt"
  st=$(tcp_state "$DMZ_GW_IP" "$OPAMP_PORT")
  explain_tcp "$DMZ_GW_IP" "$OPAMP_PORT" "$st" "OpAMP relay hop 1" || {
    fail "This host cannot open tcp/$OPAMP_PORT to the DMZ gateway $DMZ_GW_IP ($st)." "See the hint above." "Fix the path (Fortigate rule this host -> $DMZ_GW_IP tcp/$OPAMP_PORT, HAProxy on the DMZ host), then choose [r]."
    return 1; }
  ensure_secret || return 1
  info "Probing ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp (hop 1 -> Bindplane Cloud) the way bp-live-setup.sh does (§6.3)"
  probe_opamp "http://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp" "$out"
  head -n 8 "$out" | redact_stream | awk '{sub(/\r$/,""); print "      | " $0}'
  classify_probe "hop 1 ($DMZ_GW_IP)" || return 1
  hint "The probe's 403 is expected (it is curl, not a collector); a real collector with the right key gets 101 and stays connected."
}

render_supervisor_yaml() {
  cat <<EOF
server:
  endpoint: "ws://${DMZ_GW_IP}:${OPAMP_PORT}/v1/opamp"
  headers:
    Authorization: "Secret-Key ${BP_SECRET}"
    User-Agent: "bindplane-otel-collector/${V2_VERSION#v}"
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
      service.labels: "${V2_LABELS}"
storage:
  directory: "$V2_HOME/supervisor_storage"
telemetry:
  logs:
    level: 0
    output_paths: ["$SUP_LOG"]
EOF
}

step_config() {
  local new="$RUN_TMP/supervisor.yaml" owner tmp old_ep old_lb old_key
  [[ -d $V2_HOME ]] || { fail "$V2_HOME does not exist." "The v2 package is not installed." "$0 --only package"; return 1; }
  ensure_secret || return 1
  ( umask 077; render_supervisor_yaml >"$new" )
  if [[ -f $SUP_YAML ]] && cmp -s "$new" "$SUP_YAML"; then
    ok "supervisor.yaml already has the right endpoint, key and labels"
  else
    if [[ -f $SUP_YAML ]]; then
      old_ep=$(sup_get endpoint); old_lb=$(sup_get labels); old_key=$(sup_get secret)
      cp -p "$SUP_YAML" "$STATE_DIR/supervisor.yaml.bak-$RUN_TS"; chmod 600 "$STATE_DIR/supervisor.yaml.bak-$RUN_TS"
      info "Previous supervisor.yaml saved as $STATE_DIR/supervisor.yaml.bak-$RUN_TS"
      [[ $old_ep != "ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp" ]] && say "      endpoint: ${old_ep:-<none>}  ->  ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp"
      [[ $old_lb != "$V2_LABELS" ]] && say "      labels:   ${old_lb:-<none>}  ->  $V2_LABELS"
      [[ -n $old_key && $old_key != "$BP_SECRET" ]] && say "      secret key: replaced ($(mask "$old_key") -> $(mask "$BP_SECRET"))"
      [[ -z $old_key ]] && say "      secret key: added (the package's default file has none)"
    fi
    owner=$(v2_owner)
    tmp=$(mktemp "$V2_HOME/.supervisor.XXXXXX") || { fail "Cannot write in $V2_HOME." "Disk full or read-only filesystem." "df -h $V2_HOME"; return 1; }
    chmod 600 "$tmp"; cat "$new" >"$tmp"
    chown "$owner" "$tmp" 2>/dev/null || warn "Could not chown supervisor.yaml to $owner - leaving it root-owned (the service runs as root)"
    mv -f "$tmp" "$SUP_YAML"
    ok "Wrote $SUP_YAML (endpoint ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp, owner $owner, mode 0600)"
  fi
  rm -f "$new"
  if command -v python3 >/dev/null && python3 -c 'import yaml' 2>/dev/null; then
    python3 -c 'import sys,yaml; yaml.safe_load(open(sys.argv[1]))' "$SUP_YAML" 2>"$RUN_TMP/yaml.err" \
      || { fail "supervisor.yaml is not valid YAML: $(tail -n1 "$RUN_TMP/yaml.err")" "A character in the labels or key broke the file." "Check the labels (key=value,key=value) and the key, then: $0 --reconfigure"; return 1; }
    ok "supervisor.yaml parses as YAML"
  fi
  hint "Labels \"$V2_LABELS\" are how configurations get assigned in bulk in the console (§6.4) - not cosmetic."
}

explain_service_start() { # SERVICE JOURNAL_FILE
  local f=$2 extra=""
  [[ -r $SUP_LOG ]] && extra=$(tail -n 20 "$SUP_LOG" | redact_stream)
  printf '%s\n' "$extra" >>"$f"
  if grep -qiE 'yaml|unmarshal|cannot parse|invalid config|decoding failed' "$f"; then
    fail "The supervisor rejected supervisor.yaml." "$(grep -m1 -iE 'yaml|unmarshal|cannot parse|invalid config|decoding failed' "$f" | cut -c1-200)" "Check $SUP_YAML (it was written by this script - re-run: $0 --only config)"
  elif grep -qiE 'permission denied' "$f"; then
    fail "The supervisor could not open a file (permission denied)." "$(grep -m1 -i 'permission denied' "$f" | cut -c1-200)" "ls -la $V2_HOME $V2_HOME/supervisor_storage ; owner should be $(v2_owner)"
  elif grep -qiE 'no such file|executable file not found|not found' "$f"; then
    fail "The supervisor could not find a file it needs." "$(grep -m1 -iE 'no such file|not found' "$f" | cut -c1-200)" "Reinstall the package: $0 --only package"
  elif [[ -n $(apparmor_denials) ]]; then
    fail "$1 was blocked by AppArmor." "$(apparmor_denials | tail -n 2)" "aa-status ; adjust the profile"
  else
    fail "$1 failed to start." "See the journal and supervisor.log lines above." "systemctl status $1 --no-pager ; journalctl -u $1 -n 50 --no-pager ; tail -n 50 $SUP_LOG"
  fi
}

step_start() {
  local n0 n1
  [[ -f $V2_UNIT ]] || { fail "$V2_UNIT is missing." "The v2 package is not (fully) installed." "$0 --only package"; return 1; }
  run "Reloading systemd units" systemctl daemon-reload || return 1
  run "Enabling $V2_SVC at boot" systemctl enable "$V2_SVC" || return 1
  log_lines "$SUP_LOG" >"$LOG_MARK"; log_lines "$AGENT_LOG" >>"$LOG_MARK"
  service_restart_checked "$V2_SVC" || return 1
  n0=$(systemctl show -p NRestarts --value "$V2_SVC" 2>/dev/null); n0=${n0:-0}
  info "Watching for 10s that it stays up (the unit restarts on failure every 5s)"
  sleep 10
  n1=$(systemctl show -p NRestarts --value "$V2_SVC" 2>/dev/null); n1=${n1:-0}
  if ! systemctl is-active --quiet "$V2_SVC" || (( n1 > n0 )); then
    journalctl -u "$V2_SVC" -n 30 --no-pager >"$RUN_TMP/j.v2" 2>&1; show_tail "$RUN_TMP/j.v2" 12
    explain_service_start "$V2_SVC" "$RUN_TMP/j.v2"
    FAIL_WHAT="$V2_SVC keeps stopping (restarts: $n0 -> $n1). $FAIL_WHAT"
    return 1
  fi
  n1=$(systemctl show -p MainPID --value "$V2_SVC" 2>/dev/null)
  ok "$V2_SVC is running and stable${n1:+ (pid $n1)}"
}

step_verify() {
  local i c1="" c2="" errs aerrs code console=0 m_sup=0 m_agent=0 st name
  name=$(hostname -s)
  { read -r m_sup; read -r m_agent; } <"$LOG_MARK" 2>/dev/null
  m_sup=${m_sup:-0}; m_agent=${m_agent:-0}
  for i in $(seq 1 15); do systemctl is-active --quiet "$V2_SVC" && break; sleep 1; done
  systemctl is-active --quiet "$V2_SVC" || { fail "$V2_SVC is not running." "It stopped after starting." "journalctl -u $V2_SVC -n 50 --no-pager ; tail -n 50 $SUP_LOG ; then: $0 --only start"; return 1; }
  ok "$V2_SVC is active ($(v2_installed_version))"
  info "Waiting up to 60s for the supervisor's OpAMP session to hop 1 ($DMZ_GW_IP:$OPAMP_PORT) ..."
  for i in $(seq 1 60); do c1=$(v2_conn); [[ -n $c1 ]] && break; sleep 1; done
  [[ -n $c1 ]] && { sleep 15; c2=$(v2_conn); }
  if agent_running; then ok "The collector process (bindplane-otel-collector) is running under the supervisor"
  else warn "The collector process is not running yet (the supervisor starts it after it has its configuration)"; fi
  [[ -f $EFFECTIVE_YAML ]] && ok "Effective collector config present ($EFFECTIVE_YAML)"
  st=$(sed -n 's/^instance_id:[[:space:]]*//p' "$V2_HOME/supervisor_storage/persistent_state.yaml" 2>/dev/null)
  [[ -n $st ]] && ok "Agent identity (instance_id) $st - kept across restarts and upgrades in supervisor_storage/"
  errs=$(log_errors "$SUP_LOG" "$m_sup" 6); aerrs=$(log_errors "$AGENT_LOG" "$m_agent" 4)
  [[ -n $errs ]] && { warn "supervisor.log problems since the start:"; printf '%s\n' "$errs" | sed 's/^/         /'; }
  [[ -n $aerrs ]] && { warn "agent.log problems since the start:"; printf '%s\n' "$aerrs" | sed 's/^/         /'; }
  if [[ -n $c1 && $c1 == "$c2" ]]; then
    ok "Stable OpAMP session to hop 1 from $c1 (held 15s+ - a rejected session would have dropped)"
    say "  Check the Bindplane console now: Agents -> $name (v2 agents are listed by host name)."
    ask_yn "Is $name shown as Connected?" y && console=1
  fi
  { echo "# §6.5 (v2) $(date -Is)"; ss -tnp state established dst "$DMZ_GW_IP:$OPAMP_PORT" 2>&1
    echo "version=$(v2_installed_version) session=${c1:-none}/${c2:-none} console_connected=$console"
    echo "## supervisor.log (last 30)"; tail -n 30 "$SUP_LOG" 2>/dev/null | redact_stream; } >"$EVIDENCE_DIR/collector-v2-verify-$RUN_TS.txt"
  if (( console )); then ok "PASS: the LIVE v2 collector is managed from Bindplane Cloud through the relay (§6.5 gate)"; return 0; fi
  code=$(http_code_in_logs "$SUP_LOG" "$m_sup")
  if [[ -z $c1 || $c1 != "$c2" ]] && [[ -n $code ]]; then
    case $code in
      401|403) fail "Bindplane refused the connection with HTTP $code." \
                    "A real collector getting $code means the secret key in supervisor.yaml was rejected (wrong key, or a key from another Bindplane organization)." \
                    "Copy the key again from the console (Agents -> Install Agents), then: $0 --reconfigure (answer 'n' to keeping the key)" ;;
      404)     fail "The connection was answered with HTTP 404." "Host header or SNI at hop 1 does not name the cloud host, or the path is not /v1/opamp." "On the DMZ host: grep -nE 'set-header|sni' /etc/haproxy/haproxy.cfg ; bp-dmz-setup.sh --diagnose" ;;
      5*)      fail "The connection was answered with HTTP $code by the relay chain." "Hop 1 cannot reach Bindplane Cloud (DNS, Checkpoint rule or certificate on the DMZ host)." "On the DMZ host: bp-dmz-setup.sh --diagnose" ;;
      *)       fail "The connection was answered with HTTP $code." "See the supervisor.log lines above." "$0 --diagnose" ;;
    esac
  elif [[ -z $c1 ]]; then
    st=$(tcp_state "$DMZ_GW_IP" "$OPAMP_PORT")
    if [[ $st != open ]]; then explain_tcp "$DMZ_GW_IP" "$OPAMP_PORT" "$st" "OpAMP relay hop 1"
      fail "The supervisor cannot open a connection to hop 1 ($st)." "See the hint above." "Fix the path, then: $0 --only verify"
    else
      fail "The supervisor did not hold an OpAMP session to $DMZ_GW_IP:$OPAMP_PORT within 60s." \
           "Hop 1 is reachable, so the session is refused straight away (usually the secret key) or the supervisor uses another endpoint." \
           "grep -n endpoint $SUP_YAML ; tail -n 50 $SUP_LOG ; journalctl -u $V2_SVC -n 30 --no-pager"
    fi
  elif [[ $c1 != "$c2" ]]; then
    fail "The OpAMP session keeps reconnecting (local port changed $c1 -> ${c2:-none})." \
         "Hop 1 or Bindplane Cloud closes it after the upgrade - typically a wrong secret key, or an inline device at the DMZ edge." \
         "Compare the key with the console ($0 --reconfigure to replace it).\nOn the DMZ host: journalctl -u haproxy -n 30 (termination flags)."
  else
    fail "The session is up but the console does not show $name as Connected." \
         "The key belongs to another organization, the console list was not refreshed, or the agent is listed under another name." \
         "Refresh the console and search for $name / the labels \"$V2_LABELS\", then: $0 --only verify"
  fi
  return 1
}

write_next_steps_v2() {
  local seg site_label arch v=$V2_VERSION msi deb_ok rpm_ok
  seg=$([[ $SITE == dr ]] && echo dr-live || echo prod-live); site_label=$([[ $SITE == dr ]] && echo dr || echo primary)
  arch=$(dpkg --print-architecture)
  msi=$(mirror_msi_rel "$v")
  [[ -f $REPO_ROOT/packages/${V2_PKG}_${v}_linux_amd64.deb ]] && deb_ok="" || deb_ok="   # NOT in the mirror yet - stage it on the DMZ host first (see the top)"
  [[ -f $REPO_ROOT/packages/${V2_PKG}_${v}_linux_amd64.rpm ]] && rpm_ok="" || rpm_ok="   # NOT in the mirror yet"
  cat >"$NEXT_STEPS_FILE" <<EOF
# =============================================================================
# Hand-off for the ${seg^^} log sources - v2 collector (${V2_PKG} ${v})
# Generated by $SCRIPT_NAME on $(hostname -s) at $(date -Is)
# Gateway for this segment: $LIVE_GW_IP  (repository :$REPO_PORT, OpAMP :$OPAMP_PORT, OTLP :$OTLP_PORT)
#
# $v is a PRE-RELEASE. The runbook's Stage 8/9 commands are for v1 (manager.yaml);
# use these instead. The v2 package lives in /opt/bindplane-otel-collector and is
# configured by supervisor.yaml. Never use install_unix.sh offline.$( [[ -n $deb_ok ]] && printf '\n# NOTE: the mirror has no %s_%s_* files yet - on the DMZ host run  bp-dmz-update-repo.sh --versions %s  then on this gateway  bp-mirror-sync' "$V2_PKG" "$v" "$v" )
# =============================================================================

## Linux (Ubuntu) log source - as root
export V='$v'
export GW_IP='$LIVE_GW_IP'
read -rsp 'Bindplane secret key: ' BP_SECRET; echo
mkdir -p /opt/bp-install && cd /opt/bp-install
curl -fL -O "http://\${GW_IP}:$REPO_PORT/packages/${V2_PKG}_\${V}_linux_amd64.deb"$deb_ok
curl -fL -O "http://\${GW_IP}:$REPO_PORT/SHA256SUMS"
grep " packages/${V2_PKG}_\${V}_linux_amd64.deb\$" SHA256SUMS | sed 's# packages/# #' | sha256sum -c -
dpkg -i "${V2_PKG}_\${V}_linux_amd64.deb"
install -m 600 -o bdot -g bdot /dev/null /opt/bindplane-otel-collector/supervisor.yaml
tee /opt/bindplane-otel-collector/supervisor.yaml >/dev/null <<EOT
server:
  endpoint: "ws://\${GW_IP}:$OPAMP_PORT/v1/opamp"
  headers:
    Authorization: "Secret-Key \${BP_SECRET}"
    User-Agent: "bindplane-otel-collector/\${V#v}"
  tls:
    insecure: true
    insecure_skip_verify: true
capabilities:
  accepts_remote_config: true
  reports_remote_config: true
  reports_available_components: true
agent:
  executable: "/opt/bindplane-otel-collector/bindplane-otel-collector"
  config_apply_timeout: 30s
  bootstrap_timeout: 5s
  args: ["--feature-gates", "service.AllowNoPipelines"]
  description:
    non_identifying_attributes:
      service.labels: "site=$site_label,segment=$seg,zone=<zone>,os=ubuntu,role=source"
storage:
  directory: "/opt/bindplane-otel-collector/supervisor_storage"
telemetry:
  logs:
    level: 0
    output_paths: ["/opt/bindplane-otel-collector/supervisor.log"]
EOT
unset BP_SECRET
systemctl enable bindplane-otel-collector && systemctl restart bindplane-otel-collector
ss -tnp | grep ':$OPAMP_PORT'          # one ESTAB from opampsupervisor to $LIVE_GW_IP:$OPAMP_PORT
tail -n 30 /opt/bindplane-otel-collector/supervisor.log

## RHEL log source - same, with the RPM and os=rhel in the labels
curl -fL -O "http://\${GW_IP}:$REPO_PORT/packages/${V2_PKG}_\${V}_linux_amd64.rpm"$rpm_ok
rpm -U "${V2_PKG}_\${V}_linux_amd64.rpm"            # then the same supervisor.yaml, enable + restart

## Windows log source - elevated PowerShell. MSI properties as used by the v2 install_windows.ps1;
## try it on one test machine first. Write the gateway as \${Gateway} - "\$Gateway:$REPO_PORT" comes out empty.
\$Gateway = '$LIVE_GW_IP'
New-Item -ItemType Directory -Force -Path C:\\bp-install | Out-Null
Invoke-WebRequest -Uri "http://\${Gateway}:$REPO_PORT/${msi:-windows/<v2 MSI - not in the mirror yet>}" -OutFile 'C:\\bp-install\\bindplane-otel-collector.msi' -UseBasicParsing
(Invoke-WebRequest -Uri "http://\${Gateway}:$REPO_PORT/SHA256SUMS" -UseBasicParsing).Content -split "\`n" | Select-String '${msi:-windows/}\$'
(Get-FileHash 'C:\\bp-install\\bindplane-otel-collector.msi' -Algorithm SHA256).Hash     # must match the line above
\$Key = Read-Host 'Bindplane secret key'
Start-Process msiexec.exe -Wait -ArgumentList '/i','C:\\bp-install\\bindplane-otel-collector.msi','/qn','/norestart','ENABLEMANAGEMENT=1',"OPAMPENDPOINT=ws://\${Gateway}:$OPAMP_PORT/v1/opamp","OPAMPSECRETKEY=\$Key",'OPAMPLABELS=site=$site_label,segment=$seg,zone=<zone>,os=windows,role=source'
Remove-Variable Key

## After each batch (§8.9 / §12.1), on this gateway:
ss -Htn state established "( sport = :$OPAMP_PORT )" | grep -c '$LIVE_GW_IP:$OPAMP_PORT'     # one per log source
EOF
  chmod 644 "$NEXT_STEPS_FILE"
}

step_handoff() {
  local f mis=() listed=() d="$EVIDENCE_DIR/collector-v2-$RUN_TS.txt" s
  # 1. mirror: the v2 files under their real names (log sources download those)
  while IFS= read -r f; do [[ -n $f ]] && mis+=("$f"); done < <(misnamed_files)
  if [[ -f $REPO_ROOT/packages/${V2_PKG}_${V2_VERSION}_linux_amd64.deb ]]; then
    ok "The mirror holds ${V2_PKG}_${V2_VERSION}_linux_amd64.deb under its real name"
  else
    warn "The mirror has no ${V2_PKG}_${V2_VERSION}_* files under their real names - the log sources need them."
    say  "  On the DMZ host (bp-gw-dmz-01), with the updated scripts:"
    say  "    sudo rm -f /srv/bindplane/packages/observiq-otel-collector_${V2_VERSION}_* /srv/bindplane/packages/observiq-otel-collector-${V2_VERSION}-SHA256SUMS"
    say  "    sudo bash bp-dmz-update-repo.sh --versions $V2_VERSION        # keep the current version as it is"
    say  "  Then here:  sudo bp-mirror-sync && sudo bash $0 --only handoff"
  fi
  if (( ${#mis[@]} )); then
    warn "Files in the mirror carry v2 content under the v1 name (renamed copies):"
    printf '         %s\n' "${mis[@]#"$REPO_ROOT"/}"
    for f in "${mis[@]}"; do grep -qF " ${f#"$REPO_ROOT"/}" "$REPO_ROOT/SHA256SUMS" 2>/dev/null && listed+=("$f"); done
    if (( ${#listed[@]} )); then
      hint "They are still listed in the DMZ repository's SHA256SUMS - remove them on the DMZ host (commands above); the next bp-mirror-sync would fetch them again."
    elif [[ -f $REPO_ROOT/packages/${V2_PKG}_${V2_VERSION}_linux_amd64.deb ]] && ask_yn "The DMZ no longer lists them. Delete these local copies?" y; then
      rm -f "${mis[@]}" && ok "Removed ${#mis[@]} renamed copy/copies from the mirror"
    fi
  fi
  # 2. bp-live-setup.sh: its collector steps are done by this script
  if [[ -f $LIVE_STATE_FILE || -f $LIVE_CONF ]]; then
    for s in collector_install collector_config collector_verify; do live_state_set "$s" "done"; done
    live_conf_set BP_VERSION "$V2_VERSION"
    ok "bp-live-setup.sh: collector steps marked done, BP_VERSION=$V2_VERSION (it leaves the v2 collector to this script)"
  fi
  { echo "version=$V2_VERSION"; echo "endpoint=ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp"; echo "labels=$V2_LABELS"; echo "date=$(date -Is)"; } >"$V2_MARKER"
  chmod 600 "$V2_MARKER"
  # 3. evidence + hand-off notes
  {
    echo "# v2 collector evidence - $(hostname -s) - $(date -Is) - $SCRIPT_NAME v$SCRIPT_VERSION"
    echo "## package"; dpkg-query -W -f='${Package} ${Version} ${Status}\n' "$V2_PKG" "$V1_PKG" 2>&1
    echo "## service"; systemctl is-active "$V2_SVC" 2>&1; systemctl is-enabled "$V2_SVC" 2>&1
    echo "## sessions to hop 1"; ss -tnp state established dst "$DMZ_GW_IP:$OPAMP_PORT" 2>&1
    echo "## supervisor.yaml (key redacted)"; sed -E 's/(Secret-Key )[^"]*/\1***REDACTED***/' "$SUP_YAML" 2>&1
    echo "## supervisor.log (last 40)"; tail -n 40 "$SUP_LOG" 2>/dev/null
  } 2>&1 | redact_stream >"$d"
  chmod 600 "$d"
  write_next_steps_v2
  ok "Evidence: $d"
  ok "Log-source hand-off notes (v2): $NEXT_STEPS_FILE"
}

# =============================================================================
#  Diagnostics (--diagnose, and [d] in the failure menu) - read-only
# =============================================================================
run_diagnostics() {
  local st e c1 key n
  CHK_FAILS=0; CHK_WARNS=0
  banner_line "Diagnostics (read-only) - v2 collector on $(hostname -s)"
  section "1. Packages"
  [[ -n $(v2_installed_version) ]] && c_ok "$V2_PKG $(v2_installed_version) installed ($(v2_status))" || c_fail "$V2_PKG is not installed (status: $(v2_status || echo none))"
  if [[ -n $(collector_installed_version) ]]; then
    if systemctl is-active --quiet "$V1_SVC"; then c_warn "The v1 collector $(collector_installed_version) is RUNNING too - two agents for this host"
    else say "      v1 package $(collector_installed_version) still installed (stopped) - remove when no longer needed: dpkg --purge $V1_PKG"; fi
  fi
  for f in "$V2_HOME/opampsupervisor" "$V2_HOME/bindplane-otel-collector"; do [[ -x $f ]] && c_ok "$f present" || c_fail "$f missing"; done
  [[ -f $V2_UNIT ]] && c_ok "Unit file $V2_UNIT present" || c_fail "Unit file $V2_UNIT missing"
  section "2. supervisor.yaml"
  if [[ -f $SUP_YAML ]]; then
    say "      endpoint: $(sup_get endpoint)   labels: $(sup_get labels)   owner/mode: $(stat -c '%U:%G %a' "$SUP_YAML")"
    key=$(sup_get secret); [[ -n $key ]] && c_ok "Secret key present ($(mask "$key"))" || c_fail "No secret key in supervisor.yaml (the package default has none)"
    [[ -n ${DMZ_GW_IP:-} && $(sup_get endpoint) != "ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp" ]] && c_fail "Endpoint is not ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp"
    [[ $(stat -c %a "$SUP_YAML") == 600 ]] || c_warn "supervisor.yaml is not mode 600 (it holds the secret key)"
  else c_fail "$SUP_YAML missing"; fi
  section "3. Service"
  st=$(systemctl is-active "$V2_SVC" 2>/dev/null)
  [[ $st == active ]] && c_ok "$V2_SVC active, $(systemctl is-enabled "$V2_SVC" 2>/dev/null) at boot, restarts since start: $(n=$(systemctl show -p NRestarts --value "$V2_SVC" 2>/dev/null); echo "${n:-?}")" || c_fail "$V2_SVC is ${st:-unknown}"
  pgrep -f opampsupervisor >/dev/null && c_ok "opampsupervisor process running" || c_warn "opampsupervisor process not running"
  agent_running && c_ok "collector process running" || c_warn "collector process not running"
  section "4. Path to hop 1 ($DMZ_GW_IP:$OPAMP_PORT, source $(route_src "$DMZ_GW_IP"))"
  if [[ -n ${DMZ_GW_IP:-} ]]; then
    st=$(tcp_state "$DMZ_GW_IP" "$OPAMP_PORT")
    [[ $st == open ]] && c_ok "TCP $DMZ_GW_IP:$OPAMP_PORT open" || { c_fail "TCP $DMZ_GW_IP:$OPAMP_PORT $st"; explain_tcp "$DMZ_GW_IP" "$OPAMP_PORT" "$st" "hop 1" >/dev/null 2>&1; }
    BP_SECRET=${BP_SECRET:-$(sup_get secret)}
    if [[ $st == open && -n $BP_SECRET ]]; then
      probe_opamp "http://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp" "$RUN_TMP/diag.probe"
      if classify_probe "hop 1" >/dev/null; then c_ok "Probe through hop 1: $PROBE_STATUS $PROBE_VIA (reaches Bindplane Cloud)"; else c_fail "Probe: $FAIL_WHAT"; hint "$FAIL_FIX"; fi
    fi
    c1=$(v2_conn)
    [[ -n $c1 ]] && c_ok "OpAMP session established from $c1" || c_fail "No established OpAMP session from opampsupervisor to $DMZ_GW_IP:$OPAMP_PORT"
  else c_warn "DMZ_GW_IP unknown (no saved answers) - path checks skipped"; fi
  section "5. Logs"
  e=$(log_errors "$SUP_LOG" "$(( $(log_lines "$SUP_LOG") - 300 ))" 6); [[ -n $e ]] && { c_warn "Recent supervisor.log problems:"; printf '%s\n' "$e" | sed 's/^/         /'; } || c_ok "No recent problems in supervisor.log"
  e=$(log_errors "$AGENT_LOG" "$(( $(log_lines "$AGENT_LOG") - 300 ))" 4); [[ -n $e ]] && { c_warn "Recent agent.log problems:"; printf '%s\n' "$e" | sed 's/^/         /'; }
  n=$(http_code_in_logs "$SUP_LOG" "$(( $(log_lines "$SUP_LOG") - 300 ))"); [[ $n == 401 || $n == 403 ]] && hint "HTTP $n in the supervisor log = the secret key was rejected."
  section "6. Host"
  check_time
  check_space "$V2_HOME" 1 "the collector"
  section "7. Mirror"
  [[ -f $REPO_ROOT/packages/${V2_PKG}_${V2_VERSION:-x}_linux_amd64.deb ]] && c_ok "${V2_PKG}_${V2_VERSION}_linux_amd64.deb is in the mirror (log sources)" || c_warn "${V2_PKG}_${V2_VERSION:-<version>}_linux_amd64.deb is not in the mirror under its real name"
  [[ -n $(misnamed_files) ]] && c_warn "Renamed v2 copies under the v1 name in the mirror: $(misnamed_files | xargs -r -n1 basename | tr '\n' ' ')"
  echo; say "  Diagnostics: $CHK_FAILS problem(s), $CHK_WARNS warning(s)."
}

# =============================================================================
#  Configuration dialogue
# =============================================================================
newest_mirror_v2() {
  find "$REPO_ROOT/packages" -maxdepth 1 \( -name "${V2_PKG}_v*_linux_amd64.deb" -o -name 'observiq-otel-collector_v[2-9]*_linux_amd64.deb' \) -printf '%f\n' 2>/dev/null \
    | sed -E 's/^[a-z-]+_(v[^_]+)_linux_.*/\1/' | sort -V | tail -n1
}
gather_config() {
  local d seg site_label
  banner_line "Configuration"
  say "  Press Enter to accept the value in [brackets]. Values come from bp-live-setup.sh where it has them."
  ask SITE "Site of this LIVE gateway (primary/dr)" "${SITE:-$(live_conf_get SITE)}" v_site || return 1
  SITE=${SITE:-primary}
  ask DMZ_GW_IP "DMZ gateway address (hop 1; the collector connects to ws://<it>:$OPAMP_PORT/v1/opamp)" "${DMZ_GW_IP:-$(live_conf_get DMZ_GW_IP)}" v_remote_ip || return 1
  ask LIVE_GW_IP "This gateway's LIVE-facing address (only used in the log-source notes)" "${LIVE_GW_IP:-$(live_conf_get LIVE_GW_IP)}" v_ipv4 || return 1
  d=${V2_VERSION:-$(v2_installed_version)}; [[ -z $d ]] && is_v2_version "$(live_conf_get BP_VERSION)" && d=$(live_conf_get BP_VERSION); d=${d:-$(newest_mirror_v2)}
  ask V2_VERSION "v2 collector version (release tag)" "$d" v_v2_version || return 1
  [[ $V2_VERSION == v* ]] || V2_VERSION="v$V2_VERSION"
  [[ $V2_VERSION == *-* ]] && warn "  $V2_VERSION is a PRE-RELEASE - use it in production only with CBSL's approval"
  seg=$([[ $SITE == dr ]] && echo dr-live || echo prod-live); site_label=$([[ $SITE == dr ]] && echo dr || echo primary)
  d=${V2_LABELS:-$(live_conf_get AGENT_LABELS)}; d=${d:-"site=$site_label,segment=$seg,role=gateway"}
  ask V2_LABELS "Agent labels (key=value,...)" "$d" v_labels || return 1
  return 0
}
show_config() {
  printf '  %-30s %s\n' \
    "Site" "$SITE" \
    "Collector" "$V2_PKG $V2_VERSION (installed: $(v2_installed_version || true))" \
    "Endpoint (hop 1)" "ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp" \
    "Labels" "$V2_LABELS" \
    "Name in the console" "$(hostname -s) (v2 agents use the host name)" \
    "LIVE gateway (for the notes)" "$LIVE_GW_IP" \
    "Secret key" "asked when needed, kept only in $SUP_YAML"
}
config_complete() { [[ -n $SITE && -n $DMZ_GW_IP && -n $LIVE_GW_IP && -n $V2_VERSION && -n $V2_LABELS ]]; }
confirm_config() {
  local c
  while :; do
    banner_line "Please review"; show_config
    if (( ASSUME_YES )) || [[ -z $TTY ]]; then return 0; fi
    c=$(choose "  Proceed with these values? [y]es / [e]dit / [q]uit: " yeq y)
    case $c in y) return 0 ;; e) gather_config || return 1 ;; q) return 1 ;; esac
  done
}

# =============================================================================
#  Actions
# =============================================================================
action_build() {
  local have=0 s i start=0
  init_defaults
  load_config && have=1
  snapshot_config
  if (( ! have )) || (( RECONFIGURE )) || ! config_complete; then
    (( ! have )) && info "First run - asking for the values this script needs"
    gather_config || { err "Configuration not completed - nothing changed."; exit 1; }
    confirm_config || { info "Stopped before making changes."; exit 0; }
    save_config; (( have )) && invalidate_changed
    if (( RECONFIGURE )) && [[ -n $(sup_get secret) ]]; then
      ensure_secret || exit 1
      if [[ $BP_SECRET != "$(sup_get secret)" ]]; then
        for s in config start verify handoff; do [[ $(state_get "$s") == pending ]] || state_set "$s" pending; done
        info "Secret key changed - supervisor.yaml is rewritten and the collector restarted"
      fi
    fi
  else
    banner_line "Saved answers ($CONF_FILE)"; show_config
  fi
  if [[ -n $ONLY_STEP ]]; then FORCED[$ONLY_STEP]=1; run_steps "$ONLY_STEP"; final_summary; return; fi
  if [[ -n $FROM_STEP ]]; then
    for i in "${!STEPS[@]}"; do [[ ${STEPS[$i]} == "$FROM_STEP" ]] && start=$i; done
    for s in "${STEPS[@]:$start}"; do FORCED[$s]=1; done
    run_steps "${STEPS[@]:$start}"; final_summary; return
  fi
  if all_steps_settled; then
    ok "Every step is already complete."
    show_progress
    say "  Re-check: $0 --only verify    Health: $0 --diagnose    Change values: $0 --reconfigure"
    return 0
  fi
  run_steps "${STEPS[@]}"
  final_summary
}
final_summary() {
  local c1
  banner_line "Result"
  show_progress
  c1=$(v2_conn)
  echo
  say "  Collector      : $V2_PKG $(v2_installed_version) - service $(systemctl is-active "$V2_SVC" 2>/dev/null)"
  say "  OpAMP session  : ${c1:-none} -> ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp"
  say "  Config / logs  : $SUP_YAML ; $SUP_LOG ; $AGENT_LOG"
  say "  Hand-off notes : $NEXT_STEPS_FILE"
  say "  This run's log : $LOG_FILE"
  if all_steps_settled; then
    say "  Next: sudo bash bp-live-setup.sh   (the UPDATED copy) - it finishes its evidence step and leaves the collector to this script"
  fi
}
action_status() {
  init_defaults; load_config || warn "No saved answers yet ($CONF_FILE)"
  banner_line "v2 collector on $(hostname -s)"
  show_progress
  echo
  say "  Package : $(dpkg-query -W -f='${Package} ${Version} ${Status}' "$V2_PKG" 2>/dev/null || echo "$V2_PKG not installed")"
  say "  Service : $(systemctl is-active "$V2_SVC" 2>/dev/null) / $(systemctl is-enabled "$V2_SVC" 2>/dev/null)"
  [[ -n $DMZ_GW_IP ]] && say "  Session : $(v2_conn || true) -> $DMZ_GW_IP:$OPAMP_PORT"
  say "  Endpoint: $(sup_get endpoint)   Labels: $(sup_get labels)"
  if [[ -n $(collector_installed_version) ]]; then
    if systemctl is-active --quiet "$V1_SVC"; then warn "The v1 collector $(collector_installed_version) is RUNNING too - two agents for this host"
    else say "  v1      : package $(collector_installed_version) still installed, service $(systemctl is-active "$V1_SVC" 2>/dev/null)/$(systemctl is-enabled "$V1_SVC" 2>/dev/null)"; fi
  fi
  return 0
}
action_diagnose() { init_defaults; load_config || true; run_diagnostics; }
action_upgrade() {
  local newv=$ACTION_ARG msg
  init_defaults; load_config || { err "No saved answers - run the full setup first: $0"; exit 1; }
  [[ -n $newv ]] || { newv=$(newest_mirror_v2); info "Newest v2 version in the mirror: ${newv:-none}"; }
  [[ -n $newv ]] || { err "No v2 package in the mirror. Stage it on the DMZ host (bp-dmz-update-repo.sh --versions <v2 tag>), then bp-mirror-sync."; exit 1; }
  [[ $newv == v* ]] || newv="v$newv"
  msg=$(v_v2_version "$newv") || { err "$msg"; exit 2; }
  [[ $newv == "$(v2_installed_version)" ]] && { ok "$V2_PKG $newv is already installed - nothing to do"; return 0; }
  ask_yn "Change the v2 collector $(v2_installed_version || echo '<none>') -> $newv now (supervisor.yaml and the agent identity are kept)?" y || { info "Nothing changed"; return 0; }
  V2_VERSION=$newv; save_config
  for s in package start verify handoff; do FORCED[$s]=1; done
  run_steps package start verify handoff
  hint "Rollback: $0 --upgrade <previous version>  (keep the previous version in the mirror, §13.4)"
}
action_remove() {
  init_defaults; load_config || true
  banner_line "Remove the v2 collector from this host"
  say "  This stops and disables $V2_SVC, purges the $V2_PKG package (it deletes $V2_HOME,"
  say "  including supervisor.yaml and the agent identity), and clears this script's progress."
  say "  The agent then shows as disconnected in the console - delete it there if it is not coming back."
  ask_yn "Remove the v2 collector now?" n || { info "Nothing changed"; return 0; }
  [[ -f $SUP_YAML ]] && { cp -p "$SUP_YAML" "$STATE_DIR/supervisor.yaml.removed-$RUN_TS"; chmod 600 "$STATE_DIR/supervisor.yaml.removed-$RUN_TS"; info "supervisor.yaml kept as $STATE_DIR/supervisor.yaml.removed-$RUN_TS"; }
  systemctl disable --now "$V2_SVC" >/dev/null 2>&1
  run_stream "Purging $V2_PKG" dpkg --purge "$V2_PKG" || { err "dpkg could not remove the package - see above"; exit 1; }
  rm -f "$V2_OVERRIDE_DIR/10-package-customizations-username.conf"; rmdir "$V2_OVERRIDE_DIR" 2>/dev/null
  systemctl daemon-reload 2>/dev/null
  rm -f "$STATE_FILE" "$V2_MARKER" "$LOG_MARK"
  if [[ -f $LIVE_STATE_FILE ]]; then for s in collector_install collector_config collector_verify evidence; do live_state_set "$s" pending; done; fi
  ok "v2 collector removed"
  say "  To install the v1 collector instead: sudo bash bp-live-setup.sh --reconfigure   (choose a v1.x version)"
}
action_reset() { rm -f "$STATE_FILE" "$LOG_MARK"; ok "Progress cleared (answers kept in $CONF_FILE; the collector is untouched)"; }

usage() {
  cat <<EOF
$SCRIPT_NAME v$SCRIPT_VERSION - the v2 collector ($V2_PKG) on the LIVE gateway

Usage: sudo bash $0 [options]

Default: install/repair, configure (supervisor.yaml), start and verify the v2 collector, then write
the evidence and the v2 hand-off notes for the log sources. Resumes where it stopped.

  --status             progress, package, service and session
  --diagnose           read-only health check
  --reconfigure        ask all values again (and whether to keep the secret key)
  --upgrade [VERSION]  install another v2 version from the mirror (default: the newest), keep the config
  --remove             stop and purge the v2 collector (e.g. to go back to v1)
  --only STEP          run one step again          --from STEP   run from STEP onwards
  --deb FILE           use this .deb (when it is not in $REPO_ROOT/packages)
  --v1 stop|remove|keep  what to do with a v1 collector on this host in an unattended run
  -y, --yes            no questions (secret key from BP_SECRET or the existing supervisor.yaml)
  --pause              pause after each step         --no-color   plain output
  -h, --help           this help

Steps: ${STEPS[*]}
Shares $STATE_DIR and the lock with bp-live-setup.sh; the secret key is never saved by this script.
EOF
}
parse_args() {
  local s
  while (( $# )); do
    case $1 in
      --status) ACTION=status ;;
      --diagnose) ACTION=diagnose ;;
      --reconfigure) RECONFIGURE=1 ;;
      --upgrade) ACTION=upgrade; if [[ ${2:-} =~ ^v?[0-9] ]]; then ACTION_ARG=$2; shift; fi ;;
      --remove) ACTION=remove ;;
      --reset) ACTION=reset ;;
      --only) ONLY_STEP=${2:-}; shift ;;
      --from) FROM_STEP=${2:-}; shift ;;
      --deb) DEB_ARG=${2:-}; shift ;;
      --v1) V1_ACTION=${2:-}; shift ;;
      -y|--yes) ASSUME_YES=1 ;;
      --pause) FORCE_PAUSE=1 ;;
      --no-color) USE_COLOR=0 ;;
      -h|--help) ACTION=help ;;
      --version) echo "$SCRIPT_NAME $SCRIPT_VERSION"; exit 0 ;;
      *) echo "Unknown option: $1   (see --help)" >&2; exit 2 ;;
    esac
    shift
  done
  for s in "$ONLY_STEP" "$FROM_STEP"; do
    [[ -z $s ]] || contains_word "${STEPS[*]}" "$s" || { echo "Unknown step '$s'. Steps: ${STEPS[*]}" >&2; exit 2; }
  done
  [[ -z $V1_ACTION || $V1_ACTION =~ ^(stop|remove|keep)$ ]] || { echo "--v1 takes stop, remove or keep" >&2; exit 2; }
  [[ -z $DEB_ARG || -f $DEB_ARG ]] || { echo "--deb: $DEB_ARG does not exist" >&2; exit 2; }
}

on_signal() {
  local sig=$1
  trap '' INT TERM HUP
  [[ -n $TTY ]] && stty echo <"$TTY" 2>/dev/null
  echo; warn "Received SIG$sig - stopping safely."
  [[ -n $CURRENT_STEP ]] && state_set "$CURRENT_STEP" interrupted
  info "Progress is saved. Re-run the script to continue."
  [[ -n $LOG_FILE ]] && info "Log: $LOG_FILE"
  exit 130
}
on_exit() { [[ -n $RUN_TMP && -d $RUN_TMP ]] && rm -rf "$RUN_TMP"; }

main() {
  local c miss=""
  parse_args "$@"
  setup_colors
  [[ $ACTION == help ]] && { usage; exit 0; }
  (( EUID == 0 )) || { echo "This script must run as root:  sudo bash $0 $*" >&2; exit 1; }
  for c in awk sed grep flock stat mktemp dpkg ss; do command -v "$c" >/dev/null || miss+=" $c"; done
  [[ -z $miss ]] || { echo "Missing required commands:$miss" >&2; exit 1; }
  install -d -m 700 "$STATE_DIR" "$LOG_DIR" "$EVIDENCE_DIR" || exit 1
  LOG_FILE="$LOG_DIR/run-$RUN_TS-collector-v2.log"; : >"$LOG_FILE"; chmod 600 "$LOG_FILE"
  RUN_TMP=$(mktemp -d "/tmp/$SCRIPT_NAME.XXXXXX") || exit 1
  if [[ -c /dev/tty ]] && ( : </dev/tty ) 2>/dev/null; then TTY=/dev/tty; fi
  exec 9>>"$LOCK_FILE"
  if ! flock -n 9; then
    echo "bp-live-setup.sh or another copy of this script is running (lock $LOCK_FILE). Wait for it to finish, then re-run." >&2
    exit 1
  fi
  printf '%s\n' "$$" >"$LOCK_FILE"
  trap 'on_signal INT' INT; trap 'on_signal TERM' TERM; trap 'on_signal HUP' HUP; trap on_exit EXIT
  banner_line "CBSL Bindplane - LIVE gateway v2 collector   ($SCRIPT_NAME v$SCRIPT_VERSION)"
  say "  Host: $(hostname -s)   Action: $ACTION   Log: $LOG_FILE"
  case $ACTION in
    build)    action_build ;;
    status)   action_status ;;
    diagnose) action_diagnose ;;
    upgrade)  action_upgrade ;;
    remove)   action_remove ;;
    reset)    action_reset ;;
  esac
}

main "$@"

#!/usr/bin/env bash
# =============================================================================
#  bp-dmz-update-repo.sh  -  CBSL Bindplane: update the collector packages in
#                            the DMZ repository (/srv/bindplane)
# =============================================================================
#  Runbook §13.3 (offline upgrade, DMZ part) and §13.4 (keep the previous
#  version for rollback). Run it on bp-gw-dmz-01 / bp-gw-drdmz-01 after
#  bp-dmz-setup.sh has built the repository.
#
#    * asks which release tags to add (e.g. v1.109.0 v2.0.1-beta.6)
#    * reads the real asset names of each release - the package was renamed in
#      v2: observiq-otel-collector_* (v1.x) -> bindplane-otel-collector_* (v2.x)
#    * downloads and verifies every file (publisher SHA256SUMS + file type)
#    * lets you choose the "current" version (VERSION-INFO, unversioned MSI and
#      install scripts) and optionally remove old versions
#    * optionally refreshes the Ubuntu packages in apt/ (nginx, haproxy, ...)
#    * rebuilds SHA256SUMS and checks nginx serves the result
#
#  Resumable: progress is saved after every step; re-run to continue. It shares
#  the lock, answers and download records of bp-dmz-setup.sh, so the two never
#  run at the same time and never download a verified file twice.
#
#  Usage:  sudo bash bp-dmz-update-repo.sh            (interactive)
#          sudo bash bp-dmz-update-repo.sh --help
# =============================================================================

SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="bp-dmz-update-repo"

set -uo pipefail
umask 022
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

# Shared with bp-dmz-setup.sh -----------------------------------------------------
STATE_DIR=${BP_STATE_DIR:-/var/lib/bp-dmz-setup}
LOG_DIR=${BP_LOG_DIR:-/var/log/bp-dmz-setup}
REPO_ROOT=${BP_REPO_ROOT:-/srv/bindplane}
CONF_FILE="$STATE_DIR/setup.conf"
MANIFEST="$STATE_DIR/artefacts.manifest"
GNUPG_DIR="$STATE_DIR/gnupg"
LOCK_FILE="/run/bp-dmz-setup.lock"          # same lock: never runs alongside bp-dmz-setup.sh
EVIDENCE_DIR="$LOG_DIR/evidence"
# This script's own progress and plan
STATE_FILE="$STATE_DIR/update-progress"
PLAN_FILE="$STATE_DIR/update-plan.conf"

REPO_PORT=8080
GH_REPO="observIQ/bindplane-otel-collector"
GH_API="https://api.github.com/repos/$GH_REPO"
GH_DL="https://github.com/$GH_REPO/releases/download"
BDOT_CDN="https://bdot.bindplane.com"

# bp-dmz-setup.sh answers (loaded from $CONF_FILE when present)
CONF_KEYS=(SITE BP_CLOUD_HOST BP_SECRET BP_VERSION DMZ_GW_IP LIVE_GW_IP
           FW_SOURCES FW_PORTS HAPROXY_MAXCONN STAGE_RPM STAGE_ARM64
           STAGE_WINDOWS BUILD_APT_REPO EXTRA_APT_PKGS SIGN_APT_REPO DL_PROXY
           PAUSE_BETWEEN_STEPS PROXY_DEBUG)
# shellcheck disable=SC2034  # saved/restored via save_config/load_config
init_defaults() {
  SITE="" BP_CLOUD_HOST="" BP_SECRET="" BP_VERSION="" DMZ_GW_IP="" LIVE_GW_IP=""
  FW_SOURCES="" FW_PORTS="" HAPROXY_MAXCONN="" STAGE_RPM="" STAGE_ARM64=""
  STAGE_WINDOWS="" BUILD_APT_REPO="" EXTRA_APT_PKGS="" SIGN_APT_REPO=""
  DL_PROXY="" PAUSE_BETWEEN_STEPS="" PROXY_DEBUG="no"
}

# The update plan (persisted in $PLAN_FILE so an interrupted update resumes as planned)
PLAN_KEYS=(UPD_VERSIONS UPD_CURRENT UPD_PRUNE UPD_OS UPD_CREATED UPD_PREV STAGE_RPM STAGE_ARM64 STAGE_WINDOWS)
UPD_VERSIONS="" UPD_CURRENT="" UPD_PRUNE="" UPD_OS="no" UPD_CREATED="" UPD_PREV=""

STEPS=()
declare -A STEP_TITLE=() STEP_REF=()

# Runtime globals -------------------------------------------------------------------
ACTION="update"; ARG_VERSIONS=""; ARG_CURRENT=""; ARG_PRUNE=""; ARG_OS=""; ARG_PROXY=""; RECONF=0; HAVE_CONF=0; ALLOW_PRE=0
ASSUME_YES=0; USE_COLOR=1; FORCE_ALL=0; FORCE_PAUSE=0; ADHOC=0; PAUSE_BETWEEN_STEPS=no
CURRENT_STEP=""; DL_PID=""; POLICY_RC_CREATED=0
FAIL_WHAT=""; FAIL_WHY=""; FAIL_FIX=""; LAST_OUT=""
RUN_TS=$(date +%Y%m%d-%H%M%S)
LOG_FILE=""; RUN_TMP=""; TTY=""; TTY_OUT=0
UPSTREAM_SUMS=""; REL_ASSETS=""; REL_ASSETS_KNOWN=0
CURL_PROXY_OPTS=(); APT_PROXY_OPTS=()
# Collector package names: v2.x first (bindplane-otel-collector), then v1.x (observiq-otel-collector)
PRODUCTS=(bindplane-otel-collector observiq-otel-collector)
EXPECT_PKG=""; REL_PRODUCT=""; REL_PRERELEASE="unknown"; REL_SOURCE=""; FETCH_VERSION=""
CHK_FAILS=0; CHK_WARNS=0
declare -A FORCED=()

# =============================================================================
#  Shared helpers (verbatim from bp-dmz-setup.sh)
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
v_proxy()  { [[ -z $1 || $1 =~ ^https?://[^[:space:]]+$ ]] || { echo "Use the form http://proxy.example:8080 (or 'none')."; return 1; }; }
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
         "Ask the network team to permit archive.ubuntu.com / security.ubuntu.com (or CBSL's internal mirror),\nor re-run with --reconfigure and set the outbound proxy (http://user:pass@host:port if it needs auth)."
  elif grep -qE '^(Err|E):.* (40[0-9]|50[0-9]) [A-Z]' "$f" || grep -qE '^  +(40[0-9]|50[0-9]) +[A-Z][a-z]' "$f"; then
    fail "The mirror or proxy refused apt's requests: $(grep -m1 -oE '(40[0-9]|50[0-9]) +[A-Za-z ]+' "$f" | head -n1 | sed -E 's/ +/ /g; s/ $//')." \
         "403/405: the forward proxy does not allow apt's plain-HTTP requests, or URL filtering blocks the mirror. 407: the proxy wants credentials. 5xx: mirror/proxy fault.\nThe 'no longer signed' lines that follow are a consequence, not a separate problem." \
         "If this host does not need a proxy for the Ubuntu mirrors: re-run with --reconfigure and set the proxy to 'none'.\nOtherwise ask for the mirrors to be allowed through the proxy, or use CBSL's internal mirror."
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
    7)  if [[ -n ${DL_PROXY:-} ]] && [[ ${DL_ERR:-} == *"$(sed -E 's#^https?://([^@/]*@)?##; s#/.*##; s#:.*##' <<<"$DL_PROXY")"* ]]; then
          fail "Could not connect to the outbound proxy $DL_PROXY." "The proxy is down, the address/port is wrong, or the Checkpoint blocks this host -> proxy." \
               "Test: curl -sSI -x $DL_PROXY https://github.com\nCorrect it with --reconfigure (or 'none' for direct access)."
          return
        fi
        fail "Could not connect to $host (connection refused or blocked)." \
             "The Checkpoint does not permit HTTPS from this host to $host, or a forward proxy is mandatory." \
             "Downloads need HTTPS to: github.com, release-assets.githubusercontent.com and objects.githubusercontent.com\n(release downloads redirect there), api.github.com and bdot.bindplane.com. Ask the network team, or set a proxy with --reconfigure." ;;
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
          404) fail "HTTP 404 from $host: the file does not exist." "Version ${FETCH_VERSION:-$BP_VERSION} does not match a published release tag, or the asset name changed." \
                    "Check the release page: https://github.com/$GH_REPO/releases/tag/${FETCH_VERSION:-$BP_VERSION}\n$( [[ $ACTION == build ]] && echo 'Re-run with --reconfigure to change the version.' || echo 'Use the exact tag, e.g. v1.108.1.')" ;;
          403) fail "HTTP 403 from $host." "A proxy/URL-category filter blocks GitHub downloads, or GitHub rate-limited this address." "Try again later, or ask for github.com, release-assets.githubusercontent.com and objects.githubusercontent.com to be permitted." ;;
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
      if [[ -n ${EXPECT_PKG:-} ]]; then
        [[ $pkg == "$EXPECT_PKG" ]] || { echo "package name is '$pkg', expected $EXPECT_PKG"; return 1; }
      else
        contains_word "${PRODUCTS[*]}" "$pkg" || { echo "package name is '$pkg', expected one of: ${PRODUCTS[*]}"; return 1; }
      fi
      [[ $arch == "${kind#deb-}" ]] || { echo "architecture is '$arch', expected ${kind#deb-}"; return 1; } ;;
    rpm)  [[ $magic == edabeedb* ]] || { echo "not an RPM package (magic $magic)"; return 1; } ;;
    msi)  [[ $magic == d0cf11e0a1b11ae1 ]] || { echo "not a Windows MSI (magic $magic)"; return 1; } ;;
    sh)   [[ $(head -c 2 "$f") == '#!' ]] || { echo "not a shell script"; return 1; } ;;
    ps1)  : ;;
    sums) grep -qE '^[0-9a-f]{64}[[:space:]]+' "$f" || { echo "not a SHA256SUMS file"; return 1; } ;;
  esac
  return 0
}
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
           "Choose [r] to download again. If it repeats, check content inspection on github.com / release-assets.githubusercontent.com."
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
gh_code() { # URL OUTFILE [curl args...] -> prints the HTTP code ("000" on a network failure)
  local url=$1 out=$2; shift 2
  curl -sS --connect-timeout 20 --max-time 60 "${CURL_PROXY_OPTS[@]}" -o "$out" -w '%{http_code}' "$@" "$url" 2>"$RUN_TMP/gh.err"
}
# probe_asset VERSION NAME -> 0 exists, 1 not published (404), 2 network/other problem (FAIL_* set)
probe_asset() {
  local code rc url="$GH_DL/$1/$2"
  code=$(curl -sS -L --connect-timeout 20 --max-time 60 "${CURL_PROXY_OPTS[@]}" -r 0-0 -o /dev/null -w '%{http_code}' "$url" 2>"$RUN_TMP/probe.err"); rc=$?
  if (( rc != 0 )); then DL_ERR=$(tail -n1 "$RUN_TMP/probe.err"); explain_curl "$rc" "" "$url"; return 2; fi
  [[ $code == 200 || $code == 206 ]] && return 0
  [[ $code == 404 ]] && return 1
  explain_curl 22 "$code" "$url"; return 2
}
recent_releases() { # newest first; API, falling back to the releases page
  local tags
  tags=$(curl -sS --connect-timeout 20 --max-time 60 "${CURL_PROXY_OPTS[@]}" "$GH_API/releases?per_page=15" 2>/dev/null \
         | jq -r '.[] | .tag_name + (if .prerelease then "(pre-release)" else "" end)' 2>/dev/null)
  [[ -z $tags ]] && tags=$(curl -sS --connect-timeout 20 --max-time 60 "${CURL_PROXY_OPTS[@]}" "https://github.com/$GH_REPO/releases" 2>/dev/null \
         | grep -oE "/$GH_REPO/releases/tag/[^\"]+" | sed 's#.*/tag/##' | awk '!seen[$0]++' | head -n 15)
  printf '%s' "${tags:-<could not list releases>}" | tr '\n' ' '
}
# discover_release VERSION -> REL_ASSETS REL_ASSETS_KNOWN REL_PRODUCT REL_PRERELEASE REL_SOURCE
discover_release() {
  local v=$1 code p rc json="$RUN_TMP/release.json"
  REL_ASSETS=""; REL_ASSETS_KNOWN=0; REL_PRODUCT=""; REL_PRERELEASE=unknown; REL_SOURCE=""
  info "Reading the real asset names of $v (§2.2: read them rather than assume them)"
  code=$(gh_code "$GH_API/releases/tags/$v" "$json" -H 'Accept: application/vnd.github+json')
  if [[ $code == 200 ]]; then
    REL_ASSETS=$(jq -r '.assets[].name' "$json" 2>/dev/null)
    [[ $(jq -r '.prerelease' "$json" 2>/dev/null) == true ]] && REL_PRERELEASE=yes || REL_PRERELEASE=no
    [[ -n $REL_ASSETS ]] && { REL_ASSETS_KNOWN=1; REL_SOURCE="GitHub API"; }
  elif [[ $code == 404 ]]; then
    fail "Release tag $v does not exist on github.com/$GH_REPO." "The tag must match a published release exactly, e.g. v1.108.1 or v2.0.1-beta.6." "Recent releases: $(recent_releases)"
    return 1
  fi
  if (( ! REL_ASSETS_KNOWN )); then
    code=$(gh_code "https://github.com/$GH_REPO/releases/expanded_assets/$v" "$RUN_TMP/assets.html")
    if [[ $code == 200 ]]; then
      REL_ASSETS=$(grep -oE "/$GH_REPO/releases/download/$(sed_escape "$v")/[^\"?]+" "$RUN_TMP/assets.html" | sed 's#.*/##' | sort -u)
      [[ -n $REL_ASSETS ]] && { REL_ASSETS_KNOWN=1; REL_SOURCE="release page"; }
    elif [[ $code == 404 ]]; then
      fail "Release tag $v does not exist on github.com/$GH_REPO." "The tag must match a published release exactly, e.g. v1.108.1 or v2.0.1-beta.6." "Recent releases: $(recent_releases)"
      return 1
    fi
  fi
  if (( REL_ASSETS_KNOWN )); then
    for p in "${PRODUCTS[@]}"; do grep -qxF "${p}_${v}_linux_amd64.deb" <<<"$REL_ASSETS" && { REL_PRODUCT=$p; break; }; done
    if [[ -z $REL_PRODUCT ]]; then
      fail "Release $v has no Linux amd64 .deb under a known name." \
           "The naming changed again upstream. Linux packages in the release: $(grep -E '_linux_amd64\.deb$' <<<"$REL_ASSETS" | tr '\n' ' ')" \
           "Check https://github.com/$GH_REPO/releases/tag/$v - the script knows: ${PRODUCTS[*]}"
      return 1
    fi
    ok "Release $v: $(wc -l <<<"$REL_ASSETS") assets (read from the $REL_SOURCE), package $REL_PRODUCT"
    log "assets: $(tr '\n' ' ' <<<"$REL_ASSETS")"
  else
    warn "The release metadata is not readable (API and release page blocked?) - probing the download URLs instead"
    for p in "${PRODUCTS[@]}"; do
      probe_asset "$v" "${p}_${v}_linux_amd64.deb"; rc=$?
      if (( rc == 0 )); then REL_PRODUCT=$p; REL_SOURCE="download probe"; break; fi
      (( rc == 2 )) && return 1
    done
    if [[ -z $REL_PRODUCT ]]; then
      fail "No Linux amd64 package exists for $v under either naming scheme." "The tag does not exist, or the asset naming changed." \
           "Recent releases: $(recent_releases)\nRelease page: https://github.com/$GH_REPO/releases/tag/$v"
      return 1
    fi
    ok "Release $v: package $REL_PRODUCT (found by probing the download URL)"
  fi
  [[ $REL_PRERELEASE == unknown && $v == *-* ]] && REL_PRERELEASE=yes
  [[ $REL_PRERELEASE == unknown ]] && REL_PRERELEASE=no
  [[ $REL_PRERELEASE == yes ]] && warn "$v is a PRE-RELEASE - not for production unless CBSL has approved it"
  [[ $REL_PRODUCT == bindplane-otel-collector ]] && warn "$v is the v2 package 'bindplane-otel-collector' (supervisor.yaml in /opt/bindplane-otel-collector) - see the notes at the end"
  return 0
}
asset_listed() { (( ! REL_ASSETS_KNOWN )) || grep -qxF "$1" <<<"$REL_ASSETS"; }
# product_of_version VERSION -> package name of a staged version
product_of_version() {
  local p
  for p in "${PRODUCTS[@]}"; do compgen -G "$REPO_ROOT/packages/${p}_${1}_linux_*" >/dev/null && { echo "$p"; return 0; }; done
  return 1
}
# staged_list -> "package version" lines, oldest first
staged_list() {
  find "$REPO_ROOT/packages" -maxdepth 1 -name '*-otel-collector_v*_linux_amd64.deb' -printf '%f\n' 2>/dev/null \
    | sed -nE 's/^(observiq-otel-collector|bindplane-otel-collector)_(v[^_]+)_linux_amd64\.deb$/\1 \2/p' | sort -k2,2V
}
fetch_upstream_sums() { # VERSION PRODUCT
  local v=$1 name="${2:-observiq-otel-collector}-$1-SHA256SUMS"
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
  case $rel in windows/*-otel-collector.msi|windows/install_windows.ps1|scripts/install_unix.sh) ;; *) return 0 ;; esac
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
get_windows_script() { # VERSION [current yes|no]
  local v=$1 url rel="windows/install_windows.ps1"
  [[ ${2:-yes} == yes ]] || rel="windows/install_windows_${v}.ps1"
  for url in "$GH_DL/$v/install_windows.ps1" "$BDOT_CDN/$v/install_windows.ps1"; do
    if [[ $url == "$GH_DL"* ]] && (( REL_ASSETS_KNOWN )) && ! grep -qxF install_windows.ps1 <<<"$REL_ASSETS"; then continue; fi
    get_artefact "$rel" "$url" ps1 install_windows.ps1 "$v" && return 0
  done
  FAIL_WHAT="" FAIL_WHY="" FAIL_FIX=""
  warn "Could not stage install_windows.ps1 - the MSI alone is sufficient (Stage 9.2 is a script-free install path)."
  hint "If you need the script, take the current URL from the console's Windows install command."
  return 1
}
stage_collector_version() {
  local v=$1 current=${2:-yes} p base item rel asset kind need
  local -a plan=()
  FETCH_VERSION=$v
  discover_release "$v" || return 1
  p=$REL_PRODUCT; EXPECT_PKG=$p; base="$GH_DL/$v"
  fetch_upstream_sums "$v" "$p"
  plan+=("packages/${p}_${v}_linux_amd64.deb|${p}_${v}_linux_amd64.deb|deb-amd64|required")
  [[ $STAGE_RPM == yes ]]   && plan+=("packages/${p}_${v}_linux_amd64.rpm|${p}_${v}_linux_amd64.rpm|rpm|wanted")
  [[ $STAGE_ARM64 == yes ]] && plan+=("packages/${p}_${v}_linux_arm64.deb|${p}_${v}_linux_arm64.deb|deb-arm64|wanted")
  if [[ $current == yes ]]; then plan+=("scripts/install_unix.sh|install_unix.sh|sh|wanted")
  else plan+=("scripts/install_unix_${v}.sh|install_unix.sh|sh|wanted"); fi
  if [[ $STAGE_WINDOWS == yes ]]; then
    if [[ $current == yes ]]; then plan+=("windows/${p}.msi|${p}.msi|msi|wanted")
    else plan+=("windows/${p}_${v}.msi|${p}.msi|msi|wanted"); fi
  fi
  for item in "${plan[@]}"; do
    IFS='|' read -r rel asset kind need <<<"$item"
    if ! asset_listed "$asset"; then
      if [[ $need == required ]]; then
        fail "Release $v has no asset named $asset." "This version does not ship that artefact." \
             "Assets: $(grep -vE '\.sig$' <<<"$REL_ASSETS" | head -n 12 | tr '\n' ' ')\nRelease page: https://github.com/$GH_REPO/releases/tag/$v"
        return 1
      fi
      warn "$v does not publish $asset - skipped"; continue
    fi
    if ! get_artefact "$rel" "$base/$asset" "$kind" "$asset" "$v"; then
      if [[ $need != required ]] && (( ! REL_ASSETS_KNOWN )) && [[ ${DL_CODE:-} == 404 ]]; then
        warn "$asset is not published for $v - skipped"; FAIL_WHAT="" FAIL_WHY="" FAIL_FIX=""; continue
      fi
      return 1
    fi
  done
  chmod 755 "$REPO_ROOT"/scripts/install_unix*.sh 2>/dev/null
  [[ $STAGE_WINDOWS == yes ]] && { get_windows_script "$v" "$current" || true; }
  EXPECT_PKG=""; FETCH_VERSION=""
  return 0
}
# promote_current VERSION - give an already-staged version the unversioned "current" names
promote_current() {
  local v=$1 p pair vrel urel have sum
  p=$(product_of_version "$v") || { fail "$v is not staged in $REPO_ROOT/packages." "" "Stage it first."; return 1; }
  for pair in "windows/${p}_${v}.msi|windows/${p}.msi" "scripts/install_unix_${v}.sh|scripts/install_unix.sh" "windows/install_windows_${v}.ps1|windows/install_windows.ps1"; do
    vrel=${pair%%|*}; urel=${pair#*|}
    [[ -f $REPO_ROOT/$vrel ]] || continue
    archive_previous "$urel" "$v"
    have=$(manifest_get "$vrel"); sum=${have#*|}; [[ -n $have ]] || sum=$(sha256 "$REPO_ROOT/$vrel")
    mv -f "$REPO_ROOT/$vrel" "$REPO_ROOT/$urel"
    manifest_set "$urel" "$v" "$sum"; manifest_del "$vrel"
    info "$urel now holds $v"
  done
  BP_VERSION=$v
  return 0
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
    echo "current_package=$(product_of_version "$BP_VERSION" || echo unknown)"
    echo "staged_versions=$(staged_list | awk '{print $2}' | paste -sd' ')"
    echo "staged_packages=$(staged_list | awk '{print $1":"$2}' | paste -sd' ')"
    echo "apt_repo_built_for=$apt_line"
    echo "apt_repo_signed=${SIGN_APT_REPO:-no}"
    echo "origin_host=$(hostname -s) ($DMZ_GW_IP)"
    echo "updated=$(date -Is)"
  } >"$REPO_ROOT/VERSION-INFO"
  chmod 644 "$REPO_ROOT/VERSION-INFO"
}
write_repo_readme() {
  cat >"$REPO_ROOT/README.txt" <<EOF
CBSL Bindplane - offline package origin ($(hostname -s), site: $SITE)
Served by nginx on http://$DMZ_GW_IP:$REPO_PORT/ (runbook Stage 2). Managed by bp-dmz-setup.sh / bp-dmz-update-repo.sh.

  packages/   collector .deb/.rpm per version + the publisher's SHA256SUMS
              (v1.x: observiq-otel-collector_*   v2.x: bindplane-otel-collector_*)
  scripts/    install_unix.sh (do NOT use it on isolated hosts - it hangs offline, §6.4)
  windows/    <package>.msi (current), install_windows.ps1, other versions as *_vX.Y.Z.msi
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
          --quick-gen-key "CBSL Bindplane Repo ($(hostname -s)) <bindplane-repo@$(hostname -s).invalid>" rsa4096 sign 3y \
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
    info "Skipped by configuration: CBSL's internal Ubuntu mirror provides OS packages (runbook §2, 'Preferred alternative')."
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
  run "Writing the Release file (apt-ftparchive)" sh -c 'apt-ftparchive -o APT::FTPArchive::Release::Origin=CBSL-Bindplane -o APT::FTPArchive::Release::Label=bindplane-local release . > Release.tmp && mv -f Release.tmp Release' \
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
section() { printf '\n%s--- %s ---%s\n' "$C_BLD" "$*" "$C_OFF"; log "---- $*"; }
status_word() {
  case $1 in
    done) printf '%sdone%s' "$C_GRN" "$C_OFF" ;; skipped) printf '%sSKIPPED%s' "$C_YLW" "$C_OFF" ;;
    failed) printf '%sFAILED%s' "$C_RED" "$C_OFF" ;; running|interrupted) printf '%sINTERRUPTED%s' "$C_YLW" "$C_OFF" ;;
    *) printf 'pending' ;;
  esac
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

# =============================================================================
#  Plan persistence
# =============================================================================
save_plan() {
  local tmp k
  tmp=$(mktemp "$STATE_DIR/.plan.XXXXXX") || return 1
  { echo "# $SCRIPT_NAME plan - $(date -Is)"; for k in "${PLAN_KEYS[@]}"; do printf '%s=%q\n' "$k" "${!k-}"; done; } >"$tmp"
  chmod 600 "$tmp" && mv -f "$tmp" "$PLAN_FILE"
}
load_plan() {
  [[ -f $PLAN_FILE ]] || return 1
  [[ $(stat -c %u "$PLAN_FILE") == 0 && $(stat -c %a "$PLAN_FILE") == 600 ]] || { err "Refusing to read $PLAN_FILE (must be root-owned, mode 600)"; exit 1; }
  # shellcheck disable=SC1090
  source "$PLAN_FILE"
}
clear_plan() { rm -f "$PLAN_FILE" "$STATE_FILE"; }

build_steps() {
  local v
  STEPS=(preflight); STEP_TITLE=([preflight]="Pre-flight checks"); STEP_REF=([preflight]="§13.3")
  for v in $UPD_VERSIONS; do STEPS+=("fetch:$v"); STEP_TITLE["fetch:$v"]="Stage collector $v"; STEP_REF["fetch:$v"]="§2.2, §13.3"; done
  STEPS+=(set_current); STEP_REF[set_current]="§13.3"
  if [[ $UPD_CURRENT == "${UPD_PREV:-}" ]]; then STEP_TITLE[set_current]="Keep $UPD_CURRENT as the current version"
  else STEP_TITLE[set_current]="Make $UPD_CURRENT the current version"; fi
  for v in $UPD_PRUNE; do STEPS+=("prune:$v"); STEP_TITLE["prune:$v"]="Remove version $v from the repository"; STEP_REF["prune:$v"]="§13.4"; done
  if [[ $UPD_OS == yes ]]; then STEPS+=(os_refresh); STEP_TITLE[os_refresh]="Refresh the Ubuntu packages in apt/"; STEP_REF[os_refresh]="§2.3, §13.7"; fi
  STEPS+=(checksums verify_served)
  STEP_TITLE[checksums]="Repository checksums (SHA256SUMS)"; STEP_REF[checksums]="§2.4"
  STEP_TITLE[verify_served]="Check nginx serves the updated repository"; STEP_REF[verify_served]="§2.7"
}

is_prerelease() { [[ $1 == *-* ]]; }   # semver: a hyphen marks a pre-release (v2.0.1-beta.6)

# =============================================================================
#  Steps
# =============================================================================
step_preflight() {
  local need_b=0 free_b v c
  [[ -d $REPO_ROOT/packages ]] || { fail "$REPO_ROOT/packages does not exist." "The repository has not been built on this host." "Run bp-dmz-setup.sh first (Stage 2), or set BP_REPO_ROOT if it lives elsewhere."; return 1; }
  [[ -w $REPO_ROOT/packages ]] || { fail "$REPO_ROOT is not writable." "Read-only filesystem or wrong permissions." "findmnt -T $REPO_ROOT"; return 1; }
  for v in $UPD_VERSIONS; do product_of_version "$v" >/dev/null || need_b=$((need_b + 450*1024*1024)); done
  free_b=$(( $(df -Pk "$REPO_ROOT" | awk 'NR==2{print $4}') * 1024 ))
  if (( need_b > 0 && free_b < need_b + 200*1024*1024 )); then
    fail "Not enough disk space: $(human $free_b) free, about $(human $need_b) needed for the new versions." "Each collector version is up to ~450 MB with RPM, ARM64 and MSI." \
         "Free space (df -h $REPO_ROOT), stage fewer versions, or remove old ones in the same run (they are removed after the new ones are staged)."
    return 1
  fi
  ok "$(human $free_b) free in $REPO_ROOT (about $(human $need_b) needed)"
  for c in curl jq sha256sum dpkg-deb; do command -v "$c" >/dev/null || { fail "$c is missing." "bp-dmz-setup.sh installs it in its base_packages step." "apt-get install curl jq coreutils dpkg"; return 1; }; done
  ok "Tools present; downloads use $( [[ -n ${DL_PROXY:-} ]] && echo "proxy $DL_PROXY" || echo 'the system default route/proxy')"
}

step_fetch() { # VERSION
  local v=$1 cur=no
  # a version that is already current keeps its unversioned names (nothing is fetched twice)
  [[ $v == "${BP_VERSION:-}" && -n $(manifest_get "scripts/install_unix.sh") && $(manifest_get "scripts/install_unix.sh") == "$v|"* ]] && cur=yes
  stage_collector_version "$v" "$cur" || return 1
  ok "Collector $v ($(product_of_version "$v")) is staged"
}

step_set_current() {
  local v=$UPD_CURRENT p
  p=$(product_of_version "$v") || { fail "$v is not staged in $REPO_ROOT/packages." "It was neither in the plan nor already in the repository." "Re-plan: $0 --new"; return 1; }
  if [[ $v == "${BP_VERSION:-}" ]] && { [[ ${STAGE_WINDOWS:-yes} != yes ]] || [[ $(manifest_get "windows/$p.msi") == "$v|"* ]]; }; then
    ok "$v is already the current version"
  else
    promote_current "$v" || return 1
    ok "$v ($p) is now the current version"
  fi
  BP_VERSION=$v
  write_version_info
  (( HAVE_CONF )) && { save_conf_keys BP_VERSION && ok "bp-dmz-setup.sh answers updated: BP_VERSION=$v"; }
  return 0
}
# save_conf_keys KEY... - write only these keys into bp-dmz-setup.sh's answers file (everything else,
# including one-off choices made for this update, stays as bp-dmz-setup.sh saved it)
save_conf_keys() {
  local -A vals=(); local k
  for k in "$@"; do vals[$k]=${!k-}; done
  ( SCRIPT_NAME=bp-dmz-setup; load_config || exit 1; for k in "${!vals[@]}"; do printf -v "$k" '%s' "${vals[$k]}"; done; save_config )
}

step_prune() { # VERSION
  local v=$1 p f n=0 freed=0 rel
  [[ $v == "${BP_VERSION:-}" ]] && { fail "$v is the current version and cannot be removed." "" "Choose another current version first."; return 1; }
  p=$(product_of_version "$v") || { ok "$v is not in the repository (already removed)"; return 0; }
  while IFS= read -r f; do
    [[ -n $f ]] || continue
    freed=$((freed + $(stat -c %s "$f"))); rel=${f#"$REPO_ROOT"/}
    rm -f "$f" && { manifest_del "$rel"; n=$((n+1)); log "removed $rel"; }
  done < <(find "$REPO_ROOT/packages" "$REPO_ROOT/windows" "$REPO_ROOT/scripts" -maxdepth 1 -type f \
             \( -name "${p}_${v}_linux_*" -o -name "${p}-${v}-SHA256SUMS" -o -name "*_${v}.msi" -o -name "install_windows_${v}.ps1" -o -name "install_unix_${v}.sh" \) 2>/dev/null
           # the unversioned MSI of the other package family can still hold this version (v1 MSI while v2 is current)
           for rel in windows/observiq-otel-collector.msi windows/bindplane-otel-collector.msi; do
             [[ -f $REPO_ROOT/$rel && $(manifest_get "$rel") == "$v|"* ]] && echo "$REPO_ROOT/$rel"
           done)
  write_version_info
  ok "Removed $n file(s) of $v ($(human $freed) freed)"
  hint "LIVE mirrors keep their copy until removed there (wget -N never deletes)."
}

step_os_refresh() {
  if [[ ${BUILD_APT_REPO:-no} != yes ]]; then info "No apt repository on this host (CBSL internal mirror is used) - nothing to refresh"; return 3; fi
  if [[ ${SIGN_APT_REPO:-no} == yes ]] && ! gpg --homedir "$GNUPG_DIR" --list-secret-keys >/dev/null 2>&1; then
    fail "The repository is signed, but no signing key is in $GNUPG_DIR." \
         "Re-signing with a new key would make every LIVE host reject the repository (NO_PUBKEY)." \
         "Restore $GNUPG_DIR from backup, or re-key deliberately with bp-dmz-setup.sh and redistribute the public key."
    return 1
  fi
  apt_get "Refreshing the Ubuntu package lists (apt-get update)" update || return 1
  step_os_repo
}

step_verify_served() {
  local code f n=0 bad=""
  if [[ -z ${DMZ_GW_IP:-} ]] || ! systemctl is-active --quiet nginx; then
    warn "nginx is not running here or DMZ_GW_IP is unknown - skipping the HTTP check"; return 3
  fi
  lcurl -s --max-time 15 "http://$DMZ_GW_IP:$REPO_PORT/SHA256SUMS" -o "$RUN_TMP/sums.http"
  cmp -s "$RUN_TMP/sums.http" "$REPO_ROOT/SHA256SUMS" \
    || { fail "nginx serves a different SHA256SUMS than the one on disk." "Wrong root directory, or nginx is not the bindplane-repo site." "grep root /etc/nginx/sites-enabled/bindplane-repo ; bp-dmz-setup.sh --only nginx"; return 1; }
  ok "nginx serves the new SHA256SUMS ($(wc -l <"$REPO_ROOT/SHA256SUMS") files)"
  for f in $(awk '{print $2}' "$REPO_ROOT/SHA256SUMS" | grep -E '^(packages|windows)/' ); do
    code=$(lcurl -s -o /dev/null -r 0-0 -w '%{http_code}' --max-time 10 "http://$DMZ_GW_IP:$REPO_PORT/$f")
    [[ $code == 200 || $code == 206 ]] && n=$((n+1)) || bad+="$f($code) "
  done
  [[ -z $bad ]] || { fail "Some files are not downloadable over HTTP: $bad" "Permissions or a file name nginx cannot serve." "chmod -R a+rX $REPO_ROOT ; check the names"; return 1; }
  ok "All $n package/installer files answer over http://$DMZ_GW_IP:$REPO_PORT/"
}

# =============================================================================
#  Diagnostics (offered from the failure menu)
# =============================================================================
c_ok()   { ok "$@"; }
c_warn() { warn "$@"; CHK_WARNS=$((CHK_WARNS+1)); }
c_fail() { err "$@"; CHK_FAILS=$((CHK_FAILS+1)); }
run_diagnostics() {
  local h addrs code v parts free_b logn
  CHK_FAILS=0; CHK_WARNS=0; logn=$(wc -l <"$LOG_FILE" 2>/dev/null || echo 0)
  banner_line "Diagnostics (read-only)"
  section "1. Download path to GitHub"
  say "      proxy: ${DL_PROXY:-none - direct / system default}   (env https_proxy=${https_proxy:-${HTTPS_PROXY:-unset}})"
  for h in github.com api.github.com release-assets.githubusercontent.com objects.githubusercontent.com; do
    if [[ -n ${DL_PROXY:-} ]]; then break; fi   # through a proxy only the proxy resolves names
    addrs=$(getent ahostsv4 "$h" 2>/dev/null | awk '{print $1}' | sort -u | head -n 3 | tr '\n' ' ')
    [[ -n $addrs ]] && c_ok "DNS: $h -> $addrs" || c_fail "DNS: cannot resolve $h (resolvectl status)"
  done
  code=$(gh_code "https://github.com/$GH_REPO/releases" /dev/null)
  case $code in
    200) c_ok "https://github.com/$GH_REPO/releases answers 200" ;;
    000) c_fail "github.com is unreachable: $(tail -n1 "$RUN_TMP/gh.err" 2>/dev/null)"; hint "Firewall/proxy: this host needs HTTPS to github.com and release-assets.githubusercontent.com (§1.4)." ;;
    *)   c_fail "github.com answers HTTP $code (proxy block page or URL filter?)" ;;
  esac
  code=$(gh_code "$GH_API/rate_limit" "$RUN_TMP/rl.json")
  if [[ $code == 200 ]]; then c_ok "GitHub API reachable ($(jq -r '.resources.core.remaining' "$RUN_TMP/rl.json" 2>/dev/null) of $(jq -r '.resources.core.limit' "$RUN_TMP/rl.json" 2>/dev/null) requests left this hour)"
  else c_warn "GitHub API not usable (HTTP $code) - asset names are then read from the release page or by probing"; fi
  for v in $UPD_VERSIONS; do
    for h in "${PRODUCTS[@]}"; do
      code=$(gh_code "$GH_DL/$v/${h}_${v}_linux_amd64.deb" /dev/null -L -r 0-0)
      if [[ $code == 200 || $code == 206 ]]; then c_ok "$v: ${h}_${v}_linux_amd64.deb is downloadable"; continue 2; fi
    done
    c_fail "$v: no downloadable Linux amd64 package under either name (last HTTP $code)"
    hint "Release page: https://github.com/$GH_REPO/releases/tag/$v"
  done
  section "2. Disk and repository"
  free_b=$(( $(df -Pk "$REPO_ROOT" 2>/dev/null | awk 'NR==2{print $4}') * 1024 ))
  (( free_b > 1024*1024*1024 )) && c_ok "$(human $free_b) free for $REPO_ROOT" || c_warn "Only $(human $free_b) free for $REPO_ROOT"
  parts=$(find "$REPO_ROOT" -name '*.part' -printf '%P (%s bytes)\n' 2>/dev/null | head -n 5)
  [[ -n $parts ]] && { say "      partial downloads (resumed on retry):"; sed 's/^/        /' <<<"$parts"; }
  if [[ -f $REPO_ROOT/SHA256SUMS ]]; then
    if ( cd "$REPO_ROOT" && sha256sum -c --quiet SHA256SUMS ) >/dev/null 2>&1; then c_ok "Files listed in SHA256SUMS are intact"
    else c_warn "SHA256SUMS does not match the files yet (expected mid-update; the checksums step rebuilds it)"; fi
  fi
  section "3. nginx"
  if systemctl is-active --quiet nginx 2>/dev/null; then
    c_ok "nginx is active"
    [[ -n ${DMZ_GW_IP:-} ]] && { code=$(lcurl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$DMZ_GW_IP:$REPO_PORT/"); [[ $code == 200 ]] && c_ok "http://$DMZ_GW_IP:$REPO_PORT/ answers 200" || c_fail "http://$DMZ_GW_IP:$REPO_PORT/ answers ${code:-nothing}"; }
  else c_warn "nginx is not active (systemctl status nginx)"; fi
  section "4. Log lines before the failure"
  head -n "$logn" "$LOG_FILE" 2>/dev/null | grep -vE '^[0-9-]+ [0-9:]+ (ANSWER|MENU) ' | tail -n 12 | sed 's/^/      /'
  echo; say "  Diagnostics: $CHK_FAILS problem(s), $CHK_WARNS warning(s)."
}

# =============================================================================
#  Planning dialogue
# =============================================================================
show_repo_state() {
  local p v mark rows
  rows=$(staged_list)
  if [[ -z $rows ]]; then say "  (no collector versions staged yet)"; return; fi
  while read -r p v; do
    mark=""; [[ $v == "${BP_VERSION:-}" ]] && mark="  <- current"
    is_prerelease "$v" && mark+="  (pre-release)"
    printf '     %-16s %-26s %s\n' "$v" "$p" "$mark"
  done <<<"$rows"
}

v_versions() { local x; [[ -n $1 ]] || return 0; for x in $1; do v_version "$x" >/dev/null || { echo "'$x' is not a release tag (use the form v1.109.0 or v2.0.1-beta.6)."; return 1; }; done; return 0; }
# Format check plus a quick existence probe of each tag on GitHub (both package namings); results cached
v_versions_online() {
  local x p rc found
  v_versions "$1" || return 1
  for x in $1; do
    [[ $x == v* ]] || x="v$x"
    grep -q "^$x " "$RUN_TMP/tags" 2>/dev/null && continue
    printf '      checking %s on GitHub ...\n' "$x" >&2
    found=""
    for p in "${PRODUCTS[@]}"; do
      probe_asset "$x" "${p}_${x}_linux_amd64.deb"; rc=$?
      (( rc == 0 )) && { found=$p; break; }
      (( rc == 2 )) && { found="?"; break; }
    done
    [[ -n $found ]] || { echo "Release $x does not exist on github.com/$GH_REPO (no Linux package under either name). Check the tag, e.g. v1.108.1 or v2.0.1-beta.6."; return 1; }
    echo "$x $found" >>"$RUN_TMP/tags"
  done
  return 0
}
norm_versions() { local x out=""; for x in $1; do [[ ${x,,} == none || $x == - ]] && continue; [[ $x == v* ]] || x="v$x"; contains_word "$out" "$x" || out+="${out:+ }$x"; done; printf '%s' "$out"; }
v_current_choice() { contains_word "$CANDIDATES" "$1" || { echo "Choose one of: $CANDIDATES"; return 1; }; }
v_prune_list() {
  local x; [[ -n $1 ]] || return 0
  for x in $1; do
    [[ $x == v* ]] || x="v$x"
    contains_word "$STAGED" "$x" || { echo "$x is not in the repository (staged: $STAGED)"; return 1; }
    [[ $x == "$UPD_CURRENT" ]] && { echo "$x will be the current version - it cannot be removed."; return 1; }
  done
  return 0
}

CANDIDATES=""; STAGED=""
plan_dialogue() {
  local def_cur newest_stable cur_p x keep p msg rr
  STAGED=$(staged_list | awk '{print $2}' | tr '\n' ' '); STAGED=$(trim "$STAGED")
  banner_line "Repository $REPO_ROOT"
  show_repo_state
  if (( ! ASSUME_YES )) && [[ -n $TTY ]]; then
    rr=$(recent_releases)
    if [[ $rr == "<could not"* ]]; then info "Recent releases: not listable from here (GitHub API/release page blocked) - tags are still checked as you enter them"
    else info "Recent releases on GitHub: $rr"; fi
  fi
  banner_line "What to change"
  if [[ -n $ARG_VERSIONS ]]; then
    UPD_VERSIONS=$(norm_versions "$ARG_VERSIONS")
    [[ $UPD_VERSIONS == none ]] && UPD_VERSIONS=""
    msg=$(v_versions_online "$UPD_VERSIONS") || { err "$msg"; return 1; }
  else
    say "  Release tags look like v1.108.1 (package observiq-otel-collector) or v2.0.1-beta.6 (bindplane-otel-collector)."
    ask UPD_VERSIONS "Collector versions to add (space-separated release tags, or 'none')" "" v_versions_online 1 || return 1
    UPD_VERSIONS=$(norm_versions "$UPD_VERSIONS")
  fi
  for x in $UPD_VERSIONS; do
    p=$(awk -v t="$x" '$1==t{print $2; exit}' "$RUN_TMP/tags" 2>/dev/null)
    case $p in
      bindplane-otel-collector) info "  $x: bindplane-otel-collector (v2 package naming)$(is_prerelease "$x" && echo ', PRE-RELEASE')" ;;
      observiq-otel-collector)  info "  $x: observiq-otel-collector$(is_prerelease "$x" && echo ', PRE-RELEASE')" ;;
      *) warn "  $x: could not be checked now (network) - it is verified when downloading" ;;
    esac
    contains_word "$STAGED" "$x" && info "     (already staged - its files are re-verified, nothing is downloaded twice)"
  done
  if [[ -z $UPD_VERSIONS ]]; then :
  elif (( HAVE_CONF )); then
    say "  Artefacts per version (from the bp-dmz-setup answers): amd64 .deb, RPM ${STAGE_RPM:-yes}, ARM64 ${STAGE_ARM64:-yes}, Windows ${STAGE_WINDOWS:-yes}"
    if [[ -n $UPD_VERSIONS ]] && (( ! ASSUME_YES )) && [[ -n $TTY ]] && ask_yn "Change which artefacts are staged?" n; then
      ask_yn_var STAGE_RPM "  RPM for RHEL log sources?" yes; ask_yn_var STAGE_ARM64 "  ARM64 .deb?" yes; ask_yn_var STAGE_WINDOWS "  Windows MSI and install_windows.ps1?" yes
    fi
  else
    STAGE_RPM=${STAGE_RPM:-yes}; STAGE_ARM64=${STAGE_ARM64:-yes}; STAGE_WINDOWS=${STAGE_WINDOWS:-yes}
    ask_yn_var STAGE_RPM "  Stage the RPM (RHEL log sources)?" yes; ask_yn_var STAGE_ARM64 "  Stage the ARM64 .deb?" yes; ask_yn_var STAGE_WINDOWS "  Stage the Windows MSI and install script?" yes
  fi
  CANDIDATES=$(printf '%s\n' $STAGED $UPD_VERSIONS | grep . | sort -uV | tr '\n' ' ')
  [[ -n $(trim "$CANDIDATES") ]] || { err "Nothing staged and nothing to add."; return 1; }
  # default current: the newest stable version of the package family already in use
  cur_p=$(product_of_version "${BP_VERSION:-none}" 2>/dev/null || echo observiq-otel-collector)
  newest_stable=$(printf '%s\n' $UPD_VERSIONS | grep -v -- - | sort -V | tail -n1)
  def_cur=${BP_VERSION:-}
  if [[ -n $newest_stable ]]; then
    if [[ -z $def_cur ]] || [[ $(printf '%s\n%s\n' "$def_cur" "$newest_stable" | sort -V | tail -n1) == "$newest_stable" ]]; then def_cur=$newest_stable; fi
  fi
  [[ -z $def_cur ]] && def_cur=$(tr ' ' '\n' <<<"$CANDIDATES" | grep . | tail -n1)
  say "  The current version is what VERSION-INFO, the unversioned MSI/install scripts and the LIVE"
  say "  defaults point at. Other versions stay staged for upgrades and rollback (§13.4)."
  if [[ -n $ARG_CURRENT ]]; then UPD_CURRENT=$(norm_versions "$ARG_CURRENT"); v_current_choice "$UPD_CURRENT" >/dev/null || { err "$(v_current_choice "$UPD_CURRENT")"; return 1; }
  else ask UPD_CURRENT "Current version after the update" "$def_cur" v_current_choice || return 1; fi
  if is_prerelease "$UPD_CURRENT" && [[ $UPD_CURRENT != "${BP_VERSION:-}" ]]; then
    warn "  $UPD_CURRENT is a PRE-RELEASE. Making it current points the LIVE side and new installs at it."
    if (( ALLOW_PRE )); then info "  --allow-prerelease given: accepted"
    elif ! ask_yn "Really make a pre-release the current version?" n; then
      [[ -n $ARG_CURRENT ]] && { err "--current $UPD_CURRENT is a pre-release: add --allow-prerelease to confirm."; return 1; }
      UPD_CURRENT=$def_cur; is_prerelease "$UPD_CURRENT" && UPD_CURRENT=${BP_VERSION:-}
      [[ -n $UPD_CURRENT ]] || return 1
      info "  Keeping $UPD_CURRENT as current"
    fi
  fi
  if [[ $UPD_CURRENT == v2.* && $cur_p == observiq-otel-collector ]]; then
    warn "  $UPD_CURRENT is the v2 package (bindplane-otel-collector). The deployed collectors, bp-live-setup.sh and the"
    warn "  runbook's manager.yaml steps are v1. Making v2 current changes what new installs get - plan the migration first."
    if (( ALLOW_PRE )); then info "  --allow-prerelease given: accepted"
    elif ! ask_yn "Make the v2 package the current version anyway?" n; then
      [[ -n $ARG_CURRENT ]] && { err "--current $UPD_CURRENT switches the current package to v2: add --allow-prerelease to confirm."; return 1; }
      UPD_CURRENT=${BP_VERSION:-$def_cur}; info "  Keeping $UPD_CURRENT as current"
    fi
  fi
  if [[ -n $ARG_PRUNE ]]; then UPD_PRUNE=$(norm_versions "$ARG_PRUNE"); v_prune_list "$UPD_PRUNE" >/dev/null || { err "$(v_prune_list "$UPD_PRUNE")"; return 1; }
  elif [[ -n $(trim "$STAGED") ]]; then
    ask UPD_PRUNE "Versions to REMOVE from the repository (space-separated, or 'none')" "" v_prune_list 1 || return 1
    UPD_PRUNE=$(norm_versions "$UPD_PRUNE")
  fi
  keep=$(printf '%s\n' $CANDIDATES | grep -vxF -f <(printf '%s\n' $UPD_PRUNE "") | grep -vxF "$UPD_CURRENT" | wc -l)
  (( keep == 0 )) && warn "  After this update only $UPD_CURRENT remains - §13.4 recommends keeping the previous version for rollback."
  if [[ -n $ARG_OS ]]; then UPD_OS=$ARG_OS
  elif [[ ${BUILD_APT_REPO:-no} == yes || -f $REPO_ROOT/apt/Packages ]]; then
    BUILD_APT_REPO=yes
    ask_yn_var UPD_OS "Also refresh the Ubuntu packages in apt/ (nginx, haproxy, wget + deps) to their latest versions?" no
  fi
  UPD_CREATED=$(date -Is); UPD_PREV=${BP_VERSION:-}
  return 0
}

show_plan() {
  local arts="-"
  if [[ -n $UPD_VERSIONS ]]; then
    arts="amd64 .deb"
    [[ $STAGE_RPM == yes ]] && arts+=", RPM"
    [[ $STAGE_ARM64 == yes ]] && arts+=", ARM64 .deb"
    [[ $STAGE_WINDOWS == yes ]] && arts+=", MSI + install_windows.ps1"
    arts+=", install_unix.sh"
  fi
  printf '  %-28s %s\n' \
    "Versions to add" "${UPD_VERSIONS:-none}" \
    "Artefacts per version" "$arts" \
    "Current version afterwards" "$UPD_CURRENT (now: ${BP_VERSION:-unknown})" \
    "Versions to remove" "${UPD_PRUNE:-none}" \
    "Refresh Ubuntu packages" "${UPD_OS:-no}" \
    "Download proxy" "${DL_PROXY:-none (system default)}"
}

# =============================================================================
#  Actions
# =============================================================================
load_context() {
  init_defaults
  if load_config; then HAVE_CONF=1
    if (( RECONF )); then
      ask DL_PROXY "Outbound proxy for downloads ('none' = direct)" "${DL_PROXY:-}" v_proxy 1 || exit 1
      save_conf_keys DL_PROXY && ok "Saved the download proxy to the bp-dmz-setup.sh answers"
    fi
  else
    HAVE_CONF=0
    warn "No bp-dmz-setup.sh answers found ($CONF_FILE) - asking for the few values needed"
    BP_VERSION=$(sed -n 's/^current_collector_version=//p' "$REPO_ROOT/VERSION-INFO" 2>/dev/null)
    [[ -f $REPO_ROOT/apt/Packages ]] && BUILD_APT_REPO=yes || BUILD_APT_REPO=no
    [[ -f $REPO_ROOT/apt/InRelease || -f $REPO_ROOT/apt/Release.gpg ]] && SIGN_APT_REPO=yes || SIGN_APT_REPO=no
    DMZ_GW_IP=$(sed -nE "s/^[[:space:]]*listen[[:space:]]+([0-9.]+):$REPO_PORT\b.*/\1/p" /etc/nginx/sites-enabled/bindplane-repo 2>/dev/null | head -n1)
    ask DMZ_GW_IP "Address nginx serves the repository on (DMZ_GW_IP)" "$DMZ_GW_IP" v_ipv4 || exit 1
    [[ -n $ARG_PROXY ]] || { ask DL_PROXY "Outbound proxy for downloads ('none' = direct)" "${https_proxy:-${HTTPS_PROXY:-}}" v_proxy 1 || exit 1; }
  fi
  if [[ -n $ARG_PROXY ]]; then DL_PROXY=$ARG_PROXY; [[ $DL_PROXY == none ]] && DL_PROXY=""; info "Download proxy for this run: ${DL_PROXY:-none (direct)}"; fi
  set_proxy_opts
}

action_update() {
  local c
  load_context
  if load_plan && [[ -f $STATE_FILE ]] && grep -qvE '\|(done|skipped)\|' "$STATE_FILE" 2>/dev/null; then
    build_steps
    banner_line "An unfinished update was found (planned $UPD_CREATED)"
    show_plan
    for c in "${STEPS[@]}"; do printf '   %-44s %s\n' "${STEP_TITLE[$c]}" "$(status_word "$(state_get "$c")")"; done
    if ask_yn "Resume it?" y; then run_steps "${STEPS[@]}"; finish; return; fi
    clear_plan; UPD_VERSIONS="" UPD_CURRENT="" UPD_PRUNE="" UPD_OS="no"
  fi
  clear_plan
  plan_dialogue || { err "Planning was not completed - nothing changed."; exit 1; }
  if [[ -z $UPD_VERSIONS && $UPD_CURRENT == "${BP_VERSION:-}" && -z $UPD_PRUNE && $UPD_OS != yes ]]; then
    ok "Nothing to change."; exit 0
  fi
  banner_line "Planned update"
  show_plan
  if (( ! ASSUME_YES )) && [[ -n $TTY ]]; then
    c=$(choose "  Proceed? [y]es / [q]uit: " yq y); [[ $c == y ]] || { info "Stopped before making changes."; exit 0; }
  fi
  save_plan; build_steps
  run_steps "${STEPS[@]}"
  finish
}

finish() {
  local v p inst
  banner_line "Result"
  show_repo_state
  echo
  ok "Repository updated. Current version: $BP_VERSION ($(product_of_version "$BP_VERSION" || echo '?'))"
  say "  Next, on each LIVE gateway (bp-gw-live-01 / bp-gw-drlive-01):"
  say "    sudo bp-mirror-sync                                   # pulls only the new files"
  if [[ $UPD_OS == yes ]]; then
    say "    sudo apt-get -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/bindplane-local.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 update"
    say "    sudo apt-get install --only-upgrade nginx haproxy wget  # refreshed OS packages (§13.7), then: sudo haproxy -c -f /etc/haproxy/haproxy.cfg"
  fi
  if [[ $BP_VERSION != "${UPD_PREV:-}" && $(product_of_version "$BP_VERSION") == observiq-otel-collector ]]; then
    say "    sudo bash bp-live-setup.sh --upgrade-collector $BP_VERSION   # in the change window (§13.2 order: DMZ, LIVE, sources)"
  fi
  for v in $UPD_VERSIONS; do
    [[ $v == "$BP_VERSION" ]] && continue
    p=$(product_of_version "$v" || true)
    [[ $p == observiq-otel-collector ]] || continue
    if [[ $(printf '%s\n%s\n' "$v" "$BP_VERSION" | sort -V | tail -n1) == "$v" ]]; then
      say "    sudo bash bp-live-setup.sh --upgrade-collector $v   # $v is staged but not current - for a selective upgrade/test"
    else
      say "    ($v is older than the current version - staged as a rollback target, §13.4)"
    fi
  done
  [[ -n ${UPD_PREV:-} && $UPD_PREV != "$BP_VERSION" ]] && say "  Rollback (§13.4): $UPD_PREV $(contains_word "$UPD_PRUNE" "$UPD_PREV" && echo 'was REMOVED - re-add it with this script if needed' || echo 'is still staged - make it current again with this script')"
  inst=$(dpkg-query -W -f='${Version}' observiq-otel-collector 2>/dev/null || true)
  if [[ -n $inst && "v$inst" != "$BP_VERSION" && $(product_of_version "$BP_VERSION") == observiq-otel-collector ]]; then
    say "  This DMZ host's own collector is v$inst (repository current: $BP_VERSION). Change it first (§13.2: DMZ, LIVE, sources):"
    say "    sudo bash bp-dmz-setup.sh --fetch-version $BP_VERSION     # re-verifies the files, then offers the local upgrade"
  fi
  for v in $UPD_VERSIONS; do
    p=$(product_of_version "$v" || true)
    if [[ $p == bindplane-otel-collector ]]; then
      warn "$v is the v2 'bindplane-otel-collector' package. It is NOT an in-place upgrade of v1:"
      say  "      - different package, service and home (/opt/bindplane-otel-collector); installing it next to v1 runs TWO collectors"
      say  "      - configured by supervisor.yaml (server.endpoint + an 'Authorization: Secret-Key ...' header), not manager.yaml"
      say  "      - bp-live-setup.sh and the runbook's §6.4/§8.4 steps cover v1 only; it is staged here for testing/migration planning"
    fi
  done
  say "  Log: $LOG_FILE"
  clear_plan
}

action_status() {
  load_context >/dev/null 2>&1 || true
  banner_line "Repository $REPO_ROOT"
  show_repo_state
  [[ -f $REPO_ROOT/VERSION-INFO ]] && { echo; sed 's/^/  /' "$REPO_ROOT/VERSION-INFO"; }
  if load_plan; then build_steps; banner_line "Unfinished update (planned $UPD_CREATED)"; show_plan
    local c; for c in "${STEPS[@]}"; do printf '   %-44s %s\n' "${STEP_TITLE[$c]}" "$(status_word "$(state_get "$c")")"; done
  fi
}

action_verify() {
  load_context
  banner_line "Verify $REPO_ROOT"
  if ( cd "$REPO_ROOT" && sha256sum -c --quiet SHA256SUMS ) >"$RUN_TMP/v.out" 2>&1; then ok "All $(wc -l <"$REPO_ROOT/SHA256SUMS") files match SHA256SUMS"
  else err "Checksum problems:"; sed 's/^/      /' "$RUN_TMP/v.out" | head -n 10; hint "If files were changed on purpose: $0 --rehash"; fi
  step_verify_served || { (( $? == 3 )) || print_block "Problem" "$FAIL_WHAT\n$FAIL_FIX"; }
}

action_rehash() {
  load_context
  STEPS=(checksums verify_served); STEP_TITLE=([checksums]="Repository checksums (SHA256SUMS)" [verify_served]="Check nginx serves the updated repository"); STEP_REF=([checksums]="§2.4" [verify_served]="§2.7")
  ADHOC=1; FORCE_ALL=1
  [[ -n ${BP_VERSION:-} ]] && { write_version_info; ok "VERSION-INFO refreshed (current $BP_VERSION, staged: $(staged_list | awk '{print $2}' | paste -sd' '))"; }
  run_steps checksums verify_served
}

usage() {
  cat <<EOF
$SCRIPT_NAME v$SCRIPT_VERSION - update the collector packages in the DMZ repository ($REPO_ROOT)

Usage: sudo bash $0 [options]

Default: interactive - asks which release tags to add, which version is current afterwards,
which old versions to remove and whether to refresh the Ubuntu packages. Re-running after an
interruption offers to resume the unfinished update.

Non-interactive use (with -y):
  --versions "v1.109.0 v2.0.1-beta.6"   release tags to add
  --current v1.109.0                    version that becomes current (default: newest stable added)
  --prune "v1.107.0"                    versions to remove (never the current one)
  --allow-prerelease                    confirm a pre-release / v2 package as --current
  --os-packages yes|no                  refresh the Ubuntu packages in apt/ too
  --proxy http://host:port | none       download proxy for this run only (default: bp-dmz-setup.sh's answer)
  -y, --yes                             no questions; stop on the first failure

Other:
  --status       staged versions, current version, unfinished update
  --verify       check SHA256SUMS and that nginx serves every package
  --rehash       rebuild SHA256SUMS after a deliberate manual change
  --new          discard an unfinished update and plan a new one
  --reconfigure  ask for the download proxy again and save it (shared with bp-dmz-setup.sh)
  --no-color     plain output
  -h, --help     this help

Shares the lock, answers and download records of bp-dmz-setup.sh ($STATE_DIR).
Package names: v1.x observiq-otel-collector_<v>_linux_<arch>.deb, v2.x bindplane-otel-collector_<v>_linux_<arch>.deb
EOF
}

parse_args() {
  while (( $# )); do
    case $1 in
      --versions)    ARG_VERSIONS=${2:-}; shift ;;
      --versions=*)  ARG_VERSIONS=${1#*=} ;;
      --current)     ARG_CURRENT=${2:-}; shift ;;
      --current=*)   ARG_CURRENT=${1#*=} ;;
      --prune)       ARG_PRUNE=${2:-}; shift ;;
      --prune=*)     ARG_PRUNE=${1#*=} ;;
      --os-packages) ARG_OS=${2:-}; shift ;;
      --os-packages=*) ARG_OS=${1#*=} ;;
      --proxy)       ARG_PROXY=${2:-}; shift ;;
      --proxy=*)     ARG_PROXY=${1#*=} ;;
      --reconfigure) RECONF=1 ;;
      --allow-prerelease) ALLOW_PRE=1 ;;
      -y|--yes)      ASSUME_YES=1 ;;
      --status)      ACTION=status ;;
      --verify)      ACTION=verify ;;
      --rehash)      ACTION=rehash ;;
      --new)         ACTION=new ;;
      --no-color)    USE_COLOR=0 ;;
      -h|--help)     ACTION=help ;;
      --version)     echo "$SCRIPT_NAME $SCRIPT_VERSION"; exit 0 ;;
      *) echo "Unknown option: $1   (see --help)" >&2; exit 2 ;;
    esac
    shift
  done
  [[ -z $ARG_OS || $ARG_OS == yes || $ARG_OS == no ]] || { echo "--os-packages takes yes or no" >&2; exit 2; }
  [[ -z $ARG_PROXY || $ARG_PROXY == none || $ARG_PROXY =~ ^https?://[^[:space:]]+$ ]] || { echo "--proxy takes http://host:port or 'none'" >&2; exit 2; }
}

on_signal() {
  local sig=$1
  trap '' INT TERM HUP
  [[ -n $TTY ]] && stty echo <"$TTY" 2>/dev/null
  [[ -n $DL_PID ]] && kill "$DL_PID" 2>/dev/null
  echo; warn "Received SIG$sig - stopping safely."
  [[ -n $CURRENT_STEP ]] && state_set "$CURRENT_STEP" interrupted
  info "Progress is saved (partial downloads are resumed). Re-run the script and choose to resume."
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
  for c in curl awk sed grep flock sha256sum od stat df mktemp find; do command -v "$c" >/dev/null || miss+=" $c"; done
  [[ -z $miss ]] || { echo "Missing required commands:$miss" >&2; exit 1; }
  install -d -m 700 "$STATE_DIR" "$LOG_DIR" "$EVIDENCE_DIR" || exit 1
  LOG_FILE="$LOG_DIR/run-$RUN_TS-update.log"; : >"$LOG_FILE"; chmod 600 "$LOG_FILE"
  RUN_TMP=$(mktemp -d "/tmp/$SCRIPT_NAME.XXXXXX") || exit 1
  if [[ -c /dev/tty ]] && ( : </dev/tty ) 2>/dev/null; then TTY=/dev/tty; fi
  exec 9>>"$LOCK_FILE"
  if ! flock -n 9; then
    c=$(head -n1 "$LOCK_FILE" 2>/dev/null)
    if [[ $c =~ ^[0-9]+$ ]] && kill -0 "$c" 2>/dev/null; then c="PID $c: $(ps -o args= -p "$c" 2>/dev/null | cut -c1-80)"; else c="lock $LOCK_FILE"; fi
    echo "bp-dmz-setup.sh or another repository update is running ($c). Wait for it to finish, then re-run." >&2
    exit 1
  fi
  printf '%s\n' "$$" >"$LOCK_FILE"
  trap 'on_signal INT' INT; trap 'on_signal TERM' TERM; trap 'on_signal HUP' HUP; trap on_exit EXIT
  banner_line "CBSL Bindplane - DMZ repository update   ($SCRIPT_NAME v$SCRIPT_VERSION, runbook §13.3)"
  say "  Host: $(hostname -s)   Repository: $REPO_ROOT   Log: $LOG_FILE"
  case $ACTION in
    update) action_update ;;
    new)    clear_plan; ACTION=update; action_update ;;
    status) action_status ;;
    verify) action_verify ;;
    rehash) action_rehash ;;
  esac
}

main "$@"

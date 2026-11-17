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
#  bp-live-setup-rhel.sh  -  LIVE gateway build (RHEL 8 / RHEL 9, no internet)
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
#  Third-party software: it downloads, installs and configures software that
#  NCINGA does not own - the Bindplane / OpenTelemetry collector (observIQ,
#  Apache License 2.0), HAProxy, nginx and other RHEL packages - each subject
#  to its own licence. Product names are trademarks of their respective owners;
#  no affiliation or endorsement is implied.
# =============================================================================
#  The LIVE-side stages of the NCINGA Bindplane air-gapped deployment runbook
#  (the § numbers in messages refer to it), on the LIVE gateway - for example
#  bp-gw-live-01, or bp-gw-drlive-01 at the DR site:
#
#    Stage 5 ....... software with no repository: path check to the DMZ
#                    gateway (§5.1), dnf pointed ONLY at the DMZ repository
#                    (§5.2, metadata signed or unsigned §5.4), nginx/haproxy/wget (§5.5)
#    Stage 6 ....... mirror of the DMZ repository + bp-mirror-sync (§6.1),
#                    nginx serving it to the LIVE segment on LIVE_GW_IP:8080
#                    (§6.2), HAProxy hop 2 on LIVE_GW_IP:3001 (§6.3), the
#                    collector installed from the mirror and verified (§6.4/6.5)
#    Stage 12.1 .... socket census + evidence pack + log-source hand-off
#
#  The collector: you pick any version staged on the DMZ repository, of either
#  family - the script installs and configures it accordingly:
#    v1  observiq-otel-collector    /opt/observiq-otel-collector   manager.yaml
#    v2  bindplane-otel-collector   /opt/bindplane-otel-collector  supervisor.yaml
#  Switching a host between families is a migration: the script asks what to do
#  with the collector of the other family (stop, remove or keep).
#
#  Prerequisite: the DMZ side (bp-dmz-setup-rhel.sh) is complete and its gates
#  §4.2/§4.4 passed, with the dnf repository built on the SAME RHEL major release
#  as this host. This host needs internal-firewall rules to the DMZ gateway on
#  tcp/8080 (packages), tcp/3001 (OpAMP) and later tcp/4317 (OTLP).
#
#  RHEL edition - what differs from the Ubuntu script (same steps, state files, mirror layout):
#    * packages ........ dnf / rpm. /etc/yum.repos.d/bindplane-local.repo points at the DMZ's
#                        rpm/el<major>-<arch>/ repository; every dnf call of this script uses
#                        ONLY that repository (--disablerepo='*'), so unreachable RHSM/Satellite
#                        repositories never stall it. Packages are verified with gpgcheck=1
#                        against the vendor key already on this host; repo_gpgcheck=1 when the
#                        DMZ signed repomd.xml. RHEL never starts a service on install, so the
#                        Ubuntu policy-rc.d guard is not needed.
#    * collector ....... the x86_64 (or aarch64) .rpm from the mirror, rpm -U - never install_unix.sh.
#    * SELinux ......... new 'selinux' step: the mirror is labelled httpd_sys_content_t and
#                        tcp/3001 + tcp/8404 http_port_t. 3001 is ntop_port_t by default, so
#                        haproxy could neither bind it nor connect to hop 1 on it. Never disabled.
#    * host firewall ... firewalld rich rules (log-source subnets -> LIVE_GW_IP:port) instead of ufw.
#    * nginx ........... /etc/nginx/conf.d/bindplane-repo.conf; the stock nginx.conf (own server{}
#                        on *:80) is replaced by a minimal main config (original kept as .orig).
#    * HAProxy ......... RHEL 9 ships 2.4; RHEL 8 ships 1.8, which has no 'log stdout' - hop 2 then
#                        logs to /dev/log (hop 2 needs no resolvers and no ALPN, so nothing else changes).
#    * log-source notes  RPM first (os=rhel), the .deb path for Ubuntu sources when it is mirrored.
#
#  Design goals: interactive (asks for every value, offers detected defaults),
#  resumable (re-run resumes at the first unfinished step; Ctrl+C / SSH drop
#  are safe), explainable (each failure states what happened, the likely cause
#  and the fix; then retry / diagnostics / skip / quit), idempotent.
#
#  Usage:  sudo bash bp-live-setup-rhel.sh            (then follow the prompts)
#          sudo bash bp-live-setup-rhel.sh --help     (all options)
# =============================================================================

SCRIPT_VERSION="2.1.0-rhel"
SCRIPT_NAME="bp-live-setup"     # unchanged: same state directory, lock and "Managed by" markers
DMZ_TOOL="bp-dmz-setup-rhel.sh" # the DMZ-side script named in hints

set -uo pipefail
umask 022
export LC_ALL=C

# ----------------------------------------------------------------------------
# Fixed paths and ports (runbook values). Paths can be overridden via env.
# ----------------------------------------------------------------------------
STATE_DIR=${BP_STATE_DIR:-/var/lib/bp-live-setup}
LOG_DIR=${BP_LOG_DIR:-/var/log/bp-live-setup}
REPO_ROOT=${BP_REPO_ROOT:-/srv/bindplane}
CONF_FILE="$STATE_DIR/setup.conf"
STATE_FILE="$STATE_DIR/progress"
FW_RECORD="$STATE_DIR/firewalld-rules.added"   # "source port destination zone" per rich rule added
SELINUX_RECORD="$STATE_DIR/selinux-changes.added"   # labels this script added (for --rollback)
LOCK_FILE="/run/$SCRIPT_NAME.lock"
EVIDENCE_DIR="$LOG_DIR/evidence"
NEXT_STEPS_FILE="$LOG_DIR/NEXT-STEPS-LOG-SOURCES.txt"

DNF_REPO_ID="bindplane-local"
DNF_REPO_FILE="/etc/yum.repos.d/$DNF_REPO_ID.repo"
REPO_KEY_DEFAULT="/etc/pki/rpm-gpg/RPM-GPG-KEY-bindplane-repo"   # public key of the DMZ repository (repomd.xml signature)

# Platform facts: the DMZ repository must have been built for this major release and architecture.
OS_MAJOR=$( (. /etc/os-release 2>/dev/null; v=${VERSION_ID:-0}; printf '%s' "${v%%.*}") )
RPM_ARCH=$(uname -m)
RPM_REPO_REL="rpm/el${OS_MAJOR}-${RPM_ARCH}"
HAPROXY_COMPAT18=0; HAPROXY_VER=""             # set by detect_haproxy_mode (RHEL 8 ships HAProxy 1.8)
MIRROR_SYNC="/usr/local/bin/bp-mirror-sync"
MIRROR_LOG="/var/log/bp-mirror-sync.log"
SYNC_SERVICE="/etc/systemd/system/bp-mirror-sync.service"
SYNC_TIMER="/etc/systemd/system/bp-mirror-sync.timer"

# Collector families. use_family() points the COLLECTOR_* variables at the family of the chosen
# version (BP_VERSION); before that, at the family installed here (v1 when neither is).
V1_PKG="observiq-otel-collector";  V1_HOME=${BP_COLLECTOR_HOME:-/opt/observiq-otel-collector}
V2_PKG="bindplane-otel-collector"; V2_HOME=${BP_V2_HOME:-/opt/bindplane-otel-collector}
MANAGER_YAML="$V1_HOME/manager.yaml"
SUP_YAML="$V2_HOME/supervisor.yaml"
COLLECTOR_FAMILY=v1; COLLECTOR_PKG=$V1_PKG; COLLECTOR_SVC=$V1_PKG; COLLECTOR_HOME=$V1_HOME
COLLECTOR_CONF=$MANAGER_YAML; COLLECTOR_LOG="$V1_HOME/log/collector.log"
COLLECTOR_BIN="$V1_HOME/observiq-otel-collector"; COLLECTOR_PROC="observiq"
# warnings the collectors print on every start - not problems
BENIGN_LOG_RE='Capabilities is deprecated|Using legacy service\.telemetry\.resource'

HAPROXY_CFG="/etc/haproxy/haproxy.cfg"
HAPROXY_DROPIN_DIR="/etc/systemd/system/haproxy.service.d"
HAPROXY_DROPIN="$HAPROXY_DROPIN_DIR/limits.conf"
HAPROXY_CFGDIR="/etc/haproxy/conf.d"           # RHEL 9's unit also loads *.cfg from here
NGINX_MAIN="/etc/nginx/nginx.conf"              # RHEL: the stock file carries a server{} on *:80
NGINX_SITE="/etc/nginx/conf.d/bindplane-repo.conf"
NGINX_ACCESS_LOG="/var/log/nginx/bindplane-repo.access.log"
NGINX_ERROR_LOG="/var/log/nginx/bindplane-repo.error.log"

OPAMP_PORT=3001
OTLP_PORT=4317
REPO_PORT=8080
STATS_PORT=8404
STATS_URL="http://127.0.0.1:${STATS_PORT}/stats;csv"

# Build steps in execution order ------------------------------------------------
STEPS=(preflight dmz_path dnf_source os_packages mirror selinux nginx haproxy_config
       haproxy_limits host_firewall haproxy_start probe_chain collector_install
       collector_config collector_verify evidence)
declare -A STEP_TITLE=(
  [preflight]="Pre-flight checks"
  [dmz_path]="Path to the DMZ gateway (repository and relay)"
  [dnf_source]="Point dnf at the DMZ repository only"
  [os_packages]="Install nginx, HAProxy and wget from the DMZ repository"
  [mirror]="Mirror the DMZ repository into $REPO_ROOT"
  [selinux]="SELinux labels (mirror content, service ports)"
  [nginx]="Serve the mirror to the LIVE segment on :$REPO_PORT"
  [haproxy_config]="HAProxy hop 2 configuration"
  [haproxy_limits]="HAProxy file-descriptor limits"
  [host_firewall]="Host firewall (firewalld)"
  [haproxy_start]="Start HAProxy and check the path to hop 1"
  [probe_chain]="Validate the chain: probe through both hops"
  [collector_install]="Install the collector from the mirror"
  [collector_config]="Write the collector config and start it"
  [collector_verify]="Verify the LIVE collector is connected"
  [evidence]="Socket census, evidence pack, log-source hand-off"
)
declare -A STEP_REF=(
  [preflight]="Pre-flight, isolated hosts"  [dmz_path]="§5.1"
  [dnf_source]="§5.2, §5.4"                 [os_packages]="§5.2, §5.5"
  [mirror]="§6.1"                           [selinux]="RHEL: SELinux, §6.2, §6.3"
  [nginx]="§6.2"
  [haproxy_config]="§6.3, §3.1"             [haproxy_limits]="§6.3, §3.5"
  [host_firewall]="§5.6"                    [haproxy_start]="§6.3"
  [probe_chain]="§6.3"                      [collector_install]="§6.4"
  [collector_config]="§6.4"                 [collector_verify]="§6.5"
  [evidence]="§12.1, §12.4, Stage 8"
)

# Saved answers (persisted in $CONF_FILE). The secret key is deliberately NOT
# saved here: it lives only in manager.yaml (0600), and is asked for when needed.
CONF_KEYS=(SITE LIVE_GW_IP DMZ_GW_IP BP_VERSION PKG_SOURCE REPO_SIGNED REPO_KEY
           AGENT_NAME AGENT_LABELS FW_SOURCES FW_PORTS HAPROXY_MAXCONN MIRROR_TIMER
           PAUSE_BETWEEN_STEPS PROXY_DEBUG)

init_defaults() {
  SITE="" LIVE_GW_IP="" DMZ_GW_IP="" BP_VERSION="" PKG_SOURCE="" REPO_SIGNED=""
  REPO_KEY="" AGENT_NAME="" AGENT_LABELS="" FW_SOURCES="" FW_PORTS=""
  HAPROXY_MAXCONN="" MIRROR_TIMER="" PAUSE_BETWEEN_STEPS="" PROXY_DEBUG="no"
}

# Runtime globals -------------------------------------------------------------------
ACTION="build"; ACTION_ARG=""; FROM_STEP=""; ONLY_STEP=""
ASSUME_YES=0; RECONFIGURE=0; FORCE_PAUSE=0; USE_COLOR=1; FORCE_ALL=0; ADHOC=0
CURRENT_STEP=""; REPLACE_CONFIRMED=0
FAIL_WHAT=""; FAIL_WHY=""; FAIL_FIX=""; LAST_OUT=""
RUN_TS=$(date +%Y%m%d-%H%M%S)
LOG_FILE=""; RUN_TMP=""; TTY=""; TTY_OUT=0
ENV_SECRET=${BP_SECRET:-}; BP_SECRET=""; SECRET_SOURCE=""
DMZ_INFO=""; DMZ_VERSIONS=""; OTHER_ACTION=""; OTHER_SECRET=""
DNF_OPTS=()

# =============================================================================
#  Output, logging and prompts   (shared with bp-dmz-setup-rhel.sh)
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
v_repo_key() {
  [[ -n $1 ]] || { echo "Enter the path of the repository's public key."; return 1; }
  [[ -s $1 ]] || { echo "$1 does not exist yet. Copy RPM-GPG-KEY-bindplane-repo from the DMZ host (/var/lib/bp-dmz-setup/) here through your configuration-management channel (§5.4), then answer again."; return 1; }
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
# --- dnf restricted to the DMZ repository (§5.2) --------------------------------
# Only $DNF_REPO_ID is enabled for these calls, so dnf never reaches for the unreachable RHSM /
# Satellite / mirror repositories (that is what stalls on an isolated host); the subscription
# plugins are kept out of it for the same reason. Any proxy is bypassed for the DMZ address
# (proxy=_none_ in the repo file, no_proxy for curl's environment variables).
dnf_set_opts() {
  DNF_OPTS=(-y --color=never --setopt=install_weak_deps=False)
  if [[ ${PKG_SOURCE:-dmz} == dmz ]]; then
    DNF_OPTS+=("--disablerepo=*" "--enablerepo=$DNF_REPO_ID" "--disableplugin=subscription-manager,product-id")
  fi
}
# dnf_cmd ARGS... - dnf with the options above and the DMZ address exempt from any proxy
dnf_cmd() {
  dnf_set_opts
  env "no_proxy=${DMZ_GW_IP:-}${no_proxy:+,$no_proxy}" "NO_PROXY=${DMZ_GW_IP:-}${NO_PROXY:+,$NO_PROXY}" dnf "${DNF_OPTS[@]}" "$@"
}
dnf_run() {
  local desc=$1; shift
  run_stream "$desc" dnf_cmd "$@" && return 0
  explain_dnf_failure "$LAST_OUT"
  return 1
}

explain_dnf_failure() {
  local f=$1 dmz="${DMZ_GW_IP:-the DMZ gateway}"
  if grep -qE 'repomd\.xml GPG signature verification error|Bad GPG signature|repomd\.xml\.asc' "$f" && [[ ${REPO_SIGNED:-no} == yes ]]; then
    fail "dnf rejected the DMZ repository's metadata signature (repomd.xml.asc)." \
         "The key $REPO_KEY is not the one that signed the DMZ repository (re-signed with a new key?), or the metadata changed after signing." \
         "Copy /var/lib/bp-dmz-setup/RPM-GPG-KEY-bindplane-repo from the DMZ host to $REPO_KEY again (configuration-management channel, §5.4),\nthen drop the key dnf cached for the repository: dnf clean all --disablerepo='*' --enablerepo=$DNF_REPO_ID ; choose [r].\nIf the DMZ was rebuilt meanwhile: $DMZ_TOOL --only os_repo there first."
  elif grep -qE 'GPG check FAILED|Public key for .* is not installed|GPG keys listed .* are not correct|Couldn.t open file .*RPM-GPG-KEY|Curl error \(37\)' "$f"; then
    fail "dnf rejected a package signature from the DMZ repository." \
         "gpgcheck=1 verifies every package against $(vendor_gpgkey)$( [[ ${REPO_SIGNED:-no} == yes ]] && echo " and $REPO_KEY"). The key file is missing, or a staged package is signed by another publisher (EPEL, a third party)." \
         "ls -l /etc/pki/rpm-gpg/ ; rpm -qi gpg-pubkey | grep -E '^(Version|Summary)'\nAdd the publisher's key file to gpgkey= in $DNF_REPO_FILE, or remove that package from the DMZ repository."
  elif grep -qE "Curl error \((6|7|28|56)\).*$dmz|Failed to connect to $dmz|Connection timed out|Couldn.t connect to server|No route to host" "$f"; then
    fail "dnf could not reach the DMZ repository on $dmz:$REPO_PORT." \
         "The internal-firewall rule this host -> $dmz tcp/$REPO_PORT is missing, or nginx on the DMZ host is down (§5.1)." \
         "Test: curl -s --max-time 5 http://$dmz:$REPO_PORT/ | head ; on the DMZ host: $DMZ_TOOL --diagnose"
  elif grep -qE 'Status code: 404|Cannot download repomd\.xml|Failed to download metadata for repo .'"$DNF_REPO_ID" "$f"; then
    fail "The DMZ host serves no dnf repository at /$RPM_REPO_REL/." \
         "The DMZ repository was built for another RHEL major release or architecture (this host is el$OS_MAJOR-$RPM_ARCH), or it was not built at all (§2.3)." \
         "Check: curl -s http://$dmz:$REPO_PORT/VERSION-INFO | grep rpm_repo ; curl -sI http://$dmz:$REPO_PORT/$RPM_REPO_REL/repodata/repomd.xml\nBuild it on a DMZ-side host of the same major release, or use package source 'system' (--reconfigure)."
  elif grep -qE 'not registered (with an entitlement server|to Red Hat Subscription Management)|There are no enabled repos|no enabled repositor' "$f"; then
    if [[ ${PKG_SOURCE:-dmz} == dmz ]]; then
      fail "dnf has no usable repository." "$DNF_REPO_FILE is missing or disabled." "Run: $0 --only dnf_source"
    else
      fail "dnf has no usable repository (package source 'system')." "This host is not registered (RHSM / Satellite) or every repository is disabled." \
           "Register it, configure the customer's internal mirror in /etc/yum.repos.d, or switch to the DMZ repository (--reconfigure, package source 'dmz')."
    fi
  elif grep -qE 'No match for argument|Unable to find a match|No package .* available' "$f"; then
    fail "The repository does not offer: $(grep -m1 -oE '(Unable to find a match|No match for argument)[^.]*' "$f")." \
         "The DMZ repository was built without that package (§2.3), or the metadata here is stale." \
         "Run: $0 --only dnf_source ; on the DMZ host add it as an extra package ($DMZ_TOOL --reconfigure) and rebuild (--only os_repo)."
  elif grep -qE 'filtered out by modular filtering|Modular dependency problems' "$f"; then
    fail "dnf modularity blocked a package from the DMZ repository." "$DNF_REPO_FILE lacks module_hotfixes=1, or a different module stream is enabled here (RHEL 8: nginx)." \
         "Run: $0 --only dnf_source (rewrites the repo file) ; check: dnf module list --enabled"
  elif grep -qE 'nothing provides|conflicting requests|Problem: |cannot install both|requires .* but none of the providers' "$f"; then
    fail "dnf could not satisfy the dependencies from the DMZ repository." \
         "The DMZ repository was built on a different RHEL major release than this host, or a dependency was not staged (§2.3)." \
         "Compare: curl -s http://$dmz:$REPO_PORT/VERSION-INFO | grep rpm_repo  with  el$OS_MAJOR-$RPM_ARCH\nRebuild the DMZ repository on a host of the same major release, or add the package there (extra packages)."
  elif grep -qE 'conflicts with file from package|Transaction test error|Transaction check error' "$f"; then
    fail "The package transaction failed its test: $(grep -m1 -E 'conflicts with file|error' "$f" | cut -c1-200)." \
         "A package already on this host conflicts with one from the DMZ repository (different minor release or third-party build)." "Read the lines above; remove or update the conflicting package, then choose [r]."
  elif grep -qE 'scriptlet failed|%(pre|post)(un)?\(.*\) scriptlet' "$f"; then
    fail "A package's own install scriptlet failed: $(grep -m1 -E 'scriptlet failed' "$f" | cut -c1-160)." \
         "The lines just before it name the cause." "Fix that cause, then choose [r] (dnf reinstall <package> if it is half-installed)."
  elif grep -qE 'Hash Sum mismatch|Checksum doesn.t match|Downloading successful, but checksum doesn.t match|Interrupted by header callback' "$f"; then
    fail "dnf downloaded a file whose checksum did not match the repository metadata." \
         "The DMZ repository was being rebuilt while this host was reading it." "Wait until the DMZ run finishes, then choose [r] (the metadata is refreshed)."
  elif grep -qE 'No space left on device|more space needed|Disk Requirements' "$f"; then
    fail "The disk is full." "Not enough free space for the dnf cache or the transaction." "df -h /var / ; dnf clean packages"
  else
    fail "dnf failed." "First error: $(grep -m1 -E '^(Error|Errors|error)' "$f" || echo 'see the output above')" "Fix the reported problem, then choose [r] to retry."
  fi
}

# rpm_install FILE - rpm -U (install or upgrade; --oldpackage: the version was chosen explicitly),
# waiting for the rpm database lock that dnf-automatic or another admin session may hold
rpm_install() {
  local i
  for i in $(seq 1 30); do
    run_stream "rpm -U ${1#"$REPO_ROOT"/}" rpm -Uvh --replacepkgs --oldpackage "$1" && return 0
    if grep -qiE 'transaction lock|\.rpm\.lock|lock .*held|waiting for' "$LAST_OUT"; then
      warn "The rpm database lock is held by another process - waiting 10s ($i/30)"; sleep 10; continue
    fi
    break
  done
  explain_rpm_failure "$LAST_OUT" "$1"
  return 1
}
explain_rpm_failure() {
  local f=$1 pkg=${2##*/}
  if grep -qE 'Failed dependencies' "$f"; then
    fail "$pkg needs packages that are not installed: $(grep -A3 'Failed dependencies' "$f" | grep -E 'is needed by' | awk '{print $1}' | paste -sd' ')." \
         "The collector package declares a dependency this minimal host lacks." "Install it from the DMZ repository: dnf --disablerepo='*' --enablerepo=$DNF_REPO_ID install <name>, then choose [r]."
  elif grep -qE 'conflicts with file from package|conflicts with' "$f"; then
    fail "$pkg conflicts with an installed package: $(grep -m1 -E 'conflicts with' "$f" | cut -c1-200)." "Usually the collector of the other family (v1/v2) or a renamed package." "rpm -qa | grep -E 'otel-collector' ; resolve, then choose [r]."
  elif grep -qE 'scriptlet failed' "$f"; then
    fail "The package's own install scriptlet failed: $(grep -m1 'scriptlet failed' "$f")." "The lines just before it name the cause." "Fix that cause, then choose [r] - rpm -U --replacepkgs runs the scriptlets again."
  elif grep -qE 'NOKEY|signature|not signed|digest' "$f" && grep -qiE 'error' "$f"; then
    fail "rpm refused $pkg on a signature/digest check." \
         "This host enforces package signatures (%_pkgverify_level) and the publisher's key is not imported, or the file is damaged." \
         "The publisher key is in the mirror: packages/<package>-<tag>-gpg-keys.tar.gz (bdot-public-gpg-key.asc) - rpm --import it; or re-sync: $0 --only mirror"
  elif grep -qE 'No space left on device|needs .* on the .* filesystem' "$f"; then
    fail "The disk is full." "Not enough free space to unpack $pkg." "df -h /opt /var"
  else
    fail "rpm could not install $pkg." "First error: $(grep -m1 -iE 'error' "$f" || echo 'see the output above')" "Fix the reported problem, then choose [r]."
  fi
}

# =============================================================================
#  Detection helpers
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
pkg_version() { # PACKAGE -> installed version as a release tag (2.0.1~beta.6 -> v2.0.1-beta.6), or empty
  local v
  rpm -q --quiet "$1" 2>/dev/null || return 0
  v=$(rpm -q --qf '%{VERSION}\n' "$1" 2>/dev/null | sort -V | tail -n1)
  [[ -n $v ]] && { v=${v//\~/-}; printf 'v%s' "${v//_/-}"; }
  return 0
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
# collector_set_endpoint URL - point the active collector at another OpAMP endpoint
collector_set_endpoint() {
  if [[ $COLLECTOR_FAMILY == v2 ]]; then sed -i -E "s|^([[:space:]]+)endpoint:.*|\1endpoint: \"$1\"|" "$COLLECTOR_CONF"
  else sed -i -E "s|^endpoint:.*|endpoint: $1|" "$COLLECTOR_CONF"; fi
}
collector_version() {
  local v=""
  v=$(pkg_version "$COLLECTOR_PKG")
  if [[ -z $v && $COLLECTOR_FAMILY == v1 && -x $COLLECTOR_BIN ]]; then
    v=$("$COLLECTOR_BIN" --version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
  fi
  printf '%s' "$v"
}
collector_unit_env() { systemctl show "$COLLECTOR_SVC" -p Environment --value 2>/dev/null; }
os_field() { ( . /etc/os-release 2>/dev/null; eval "printf '%s' \"\${$1:-}\"" ); }

other_family() { [[ $1 == v2 ]] && echo v1 || echo v2; }
# the active family: that of the chosen version, else the one installed here
set_family() {
  if [[ -n ${BP_VERSION:-} ]]; then use_family "$(family_of_version "$BP_VERSION")"
  else case $(installed_family) in v2) use_family v2 ;; *) use_family v1 ;; esac; fi
}
collector_installed_version() { pkg_version "$COLLECTOR_PKG"; }      # of the active family
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
local_release() { printf 'el%s-%s' "$OS_MAJOR" "$RPM_ARCH"; }
# pkg_arch - this host's architecture in the release-asset naming (amd64 / arm64)
pkg_arch() { case $RPM_ARCH in x86_64) echo amd64 ;; aarch64) echo arm64 ;; *) echo "$RPM_ARCH" ;; esac; }
# vendor_gpgkey - file:// URL of the OS vendor's package-signing key on this host (as its own repositories
# reference it): the staged OS packages are verified with it (gpgcheck=1) - no trust in the HTTP channel needed
vendor_gpgkey() {
  local k f
  k=$(grep -hE '^[[:space:]]*gpgkey[[:space:]]*=' /etc/yum.repos.d/*.repo 2>/dev/null | grep -v "$REPO_KEY_DEFAULT" \
      | grep -oE 'file:///etc/pki/rpm-gpg/[^[:space:],]+' | grep -v bindplane | head -n1)
  if [[ -z $k ]]; then
    for f in /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release "/etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-$OS_MAJOR" \
             "/etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-$OS_MAJOR" /etc/pki/rpm-gpg/RPM-GPG-KEY-oracle; do
      [[ -f $f ]] && { k="file://$f"; break; }
    done
  fi
  printf '%s' "${k:-file:///etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release}"
}

# --- the DMZ gateway ---------------------------------------------------------------
dmz_url() { printf 'http://%s:%s%s' "$DMZ_GW_IP" "$REPO_PORT" "${1:-/}"; }
dmz_get() { lcurl -fsS --max-time 15 "$(dmz_url "$1")" 2>/dev/null; }
dmz_code() { lcurl -s -o /dev/null -w '%{http_code}' --max-time 15 "$(dmz_url "$1")" 2>/dev/null; }
info_field() { sed -n "s/^$1=//p" <<<"$DMZ_INFO" | head -n1; }
# own_name_versions - "package_version_..." file names -> versions whose name matches their family
# (a v2 release saved under the v1 name, i.e. a renamed download, is ignored)
own_name_versions() {
  local f p v
  while read -r f; do
    p=${f%%_v*}; v=${f#*_}; v=${v%%_linux_*}
    [[ $p == "$(product_of_family "$(family_of_version "$v")")" ]] && echo "$v"
  done | awk '!seen[$0]++' | paste -sd' '
}
# versions staged on the DMZ repository, both families (v1 newest first, then v2)
fetch_dmz_info() {
  local idx arch
  arch=$(pkg_arch)
  DMZ_INFO=$(dmz_get /VERSION-INFO); idx=$(dmz_get /packages/)
  DMZ_VERSIONS=$(order_tags "$(grep -oE "($V1_PKG|$V2_PKG)_v[0-9][^\"<>_/]*_linux_${arch}\.rpm" <<<"$idx" | own_name_versions)")
}
# versions in the local mirror, both families
mirror_versions() {
  local arch; arch=$(pkg_arch)
  order_tags "$(find "$REPO_ROOT/packages" -maxdepth 1 \( -name "${V1_PKG}_v*_linux_${arch}.rpm" -o -name "${V2_PKG}_v*_linux_${arch}.rpm" \) -printf '%f\n' 2>/dev/null | own_name_versions)"
}
# pkg_rel VERSION -> packages/<family package>_<version>_linux_<arch>.rpm
pkg_rel() { printf 'packages/%s_%s_linux_%s.rpm' "$(product_of_family "$(family_of_version "$1")")" "$1" "$(pkg_arch)"; }
v_live_version() {
  local x=$1
  v_version "$x" || return 1
  [[ $x == v* ]] || x="v$x"
  if [[ -n $DMZ_VERSIONS ]] && ! contains_word "$DMZ_VERSIONS" "$x" && [[ ! -f $REPO_ROOT/$(pkg_rel "$x") ]]; then
    echo "$x is not staged on the DMZ repository. Staged: $DMZ_VERSIONS (add versions on the DMZ host: $DMZ_TOOL --choose-versions)"; return 1
  fi
  return 0
}
# pick_collector_version - choose the version to install from what the DMZ (or the mirror) has staged
pick_collector_version() {
  local list def inst1 inst2 cur1 cur2 dflt fam t n=0 flags reply defn=""
  local -a idx=()
  list=${DMZ_VERSIONS:-$(mirror_versions)}
  inst1=$(pkg_version "$V1_PKG"); inst2=$(pkg_version "$V2_PKG")
  dflt=$(info_field current_collector_version); cur1=$(info_field current_v1); cur2=$(info_field current_v2)
  if [[ -z $list ]]; then
    warn "  No collector versions could be listed (DMZ repository not reachable and no mirror yet)"
    ask BP_VERSION "Collector version to install (release tag, v1.x or v2.x)" "${BP_VERSION:-$dflt}" v_version || return 1
    [[ $BP_VERSION == v* ]] || BP_VERSION="v$BP_VERSION"; return 0
  fi
  def=${BP_VERSION:-}; contains_word "$list" "$def" || def=""
  for t in $inst1 $inst2 $dflt; do [[ -z $def ]] && contains_word "$list" "$t" && def=$t; done
  [[ -z $def ]] && def=${list%% *}
  say "  Collector versions staged on the DMZ repository - pick the one for this gateway:"
  for fam in v1 v2; do
    if [[ $fam == v1 ]]; then printf '     %sv1  observiq-otel-collector%s  - manager.yaml; the stable line the runbook describes\n' "$C_BLD" "$C_OFF"
    else printf '     %sv2  bindplane-otel-collector%s - OpAMP supervisor + supervisor.yaml\n' "$C_BLD" "$C_OFF"; fi
    for t in $list; do
      [[ $(family_of_version "$t") == "$fam" ]] || continue
      n=$((n+1)); idx[n]=$t; [[ $t == "$def" ]] && defn=$n
      flags=""; is_prerelease "$t" && flags+=" pre-release"
      [[ $t == "$dflt" ]] && flags+=" (DMZ default)"; [[ $t == "$cur1" || $t == "$cur2" ]] && flags+=" (current $fam)"
      [[ $t == "$inst1" || $t == "$inst2" ]] && flags+=" (installed here)"
      printf '        %2d) %-16s%s\n' "$n" "$t" "$flags"
    done
  done
  while :; do
    ask reply "Collector version to install (number or tag)" "${defn:-1}" || return 1
    [[ $reply =~ ^[0-9]+$ && -n ${idx[reply]-} ]] && reply=${idx[reply]}
    [[ $reply == v* ]] || reply="v$reply"
    if contains_word "$list" "$reply"; then BP_VERSION=$reply; break; fi
    warn "  $reply is not staged on the DMZ repository - choose a number from the list"
    { (( ASSUME_YES )) || [[ -z $TTY ]]; } && return 1
  done
  set_family
  info "  $BP_VERSION: $(family_label "$COLLECTOR_FAMILY")$(is_prerelease "$BP_VERSION" && echo ' - PRE-RELEASE: production use needs the customer'"'"'s approval')"
  t=$(pkg_version "$(product_of_family "$(other_family "$COLLECTOR_FAMILY")")")
  [[ -n $t ]] && warn "  This host runs the $(other_family "$COLLECTOR_FAMILY") collector $t - the install step asks what to do with it (stop, remove or keep)"
  return 0
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
             hint "The internal firewall is silently dropping ${src:-this host} -> $h tcp/$p: the rule is missing or not yet installed. Raise it with the network team." ;;
    refused) err "TCP $h:$p refused ($what)"
             hint "The DMZ host answered but nothing listens on $h:$p: the service there is stopped or bound to another address. On the DMZ host: $DMZ_TOOL --diagnose" ;;
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
  local id name like
  id=$(os_field ID); name=$(os_field PRETTY_NAME); like=$(os_field ID_LIKE)
  case $id in
    rhel)
      case $OS_MAJOR in 8|9) c_ok "OS: $name ($RPM_ARCH)";;
        *) c_warn "OS: $name - this script was written for RHEL 8 and 9";; esac ;;
    rocky|almalinux|ol|centos|circle|navy)
      case $OS_MAJOR in 8|9) c_ok "OS: $name ($RPM_ARCH) - a RHEL $OS_MAJOR rebuild; RHEL is the reference platform";;
        *) c_warn "OS: $name - this script was written for RHEL 8 and 9";; esac ;;
    *)
      if [[ " $like " == *" rhel "* ]]; then c_warn "OS: $name - RHEL-like but not tested; commands may differ"
      else c_warn "OS: $name - this script targets RHEL 8/9 (use bp-live-setup.sh on Ubuntu)"; fi ;;
  esac
}
check_selinux() {
  local mode
  mode=$(getenforce 2>/dev/null || echo unknown)
  case $mode in
    Enforcing)  c_ok "SELinux: Enforcing - the 'selinux' step labels $REPO_ROOT and tcp/$OPAMP_PORT, tcp/$STATS_PORT (it is never disabled)" ;;
    Permissive) c_warn "SELinux: Permissive - denials are only logged. Labels are set anyway, so nothing breaks when it returns to Enforcing" ;;
    Disabled)   c_ok "SELinux: Disabled - no labelling needed (confirm this matches the customer's hardening baseline)" ;;
    *)          c_warn "SELinux state unknown (getenforce not available)" ;;
  esac
}
check_time() {
  local sync
  sync=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
  case $sync in
    yes) c_ok "System clock is NTP-synchronised" ;;
    no)  c_warn "System clock is NOT NTP-synchronised - TLS and OpAMP both fail on clock skew"; hint "timedatectl status ; chronyc sources -v (on an isolated segment chrony needs an internal NTP server)" ;;
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
  local v ep aid st f
  for f in v1 v2; do
    v=$(pkg_version "$(product_of_family "$f")")
    [[ -n $v ]] || continue
    st=$(systemctl is-active "$(product_of_family "$f")" 2>/dev/null)
    if [[ $f == "$COLLECTOR_FAMILY" ]]; then
      ep=$(yaml_get endpoint); aid=$(yaml_get agent_id)
      c_ok "Collector $v installed - $(family_label "$f") (service: ${st:-unknown}, runtime owner $(collector_owner))"
      if [[ -n $ep && -n $DMZ_GW_IP && $ep != "ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp" ]]; then c_warn "$(basename "$COLLECTOR_CONF") endpoint is $ep - it will be set to ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp"
      elif [[ -n $ep ]]; then c_ok "$(basename "$COLLECTOR_CONF") endpoint: $ep"; fi
      [[ -n $aid ]] && c_ok "Existing agent identity $aid will be kept (no duplicate agent in the console)"
    else
      c_warn "The $(family_label "$f") collector $v is installed too (service: ${st:-unknown}) - the install step asks what to do with it"
    fi
  done
  [[ $(installed_family) == none ]] && c_ok "No collector installed yet (it is installed from the mirror in step collector_install)"
  return 0
}

# =============================================================================
#  HAProxy / nginx helpers
# =============================================================================
# detect_haproxy_mode - RHEL 8 ships HAProxy 1.8, which predates 'log stdout' (added in 1.9).
detect_haproxy_mode() {
  HAPROXY_COMPAT18=0; HAPROXY_VER=""
  command -v haproxy >/dev/null || return 0
  HAPROXY_VER=$(haproxy -v 2>/dev/null | head -n1 | grep -oE 'version [0-9]+\.[0-9]+' | awk '{print $2}')
  [[ -n $HAPROXY_VER ]] || return 0
  if (( ${HAPROXY_VER%%.*} == 1 && ${HAPROXY_VER#*.} < 9 )); then HAPROXY_COMPAT18=1; fi
  return 0
}
# haproxy_cfgdir_args - "-f <dir>" when the haproxy unit also loads $HAPROXY_CFGDIR (RHEL 9) and it holds *.cfg
haproxy_cfgdir_args() {
  [[ $(systemctl cat haproxy 2>/dev/null) == *CFGDIR* ]] || return 0
  compgen -G "$HAPROXY_CFGDIR/*.cfg" >/dev/null || return 0
  printf '%s\n' -f "$HAPROXY_CFGDIR"
}
# haproxy_check FILE - 'haproxy -c' exactly as the unit will load it (main file + conf.d when used)
haproxy_check() {
  local -a extra=()
  mapfile -t extra < <(haproxy_cfgdir_args)
  haproxy -c -f "$1" "${extra[@]}"
}
# conf_is_pristine FILE - 0 when FILE's content is exactly what its RPM shipped (rpm -V: no size/digest change)
conf_is_pristine() {
  local f=$1 pkg changes
  pkg=$(rpm -qf --qf '%{NAME}\n' "$f" 2>/dev/null | head -n1)
  [[ -n $pkg && $pkg != *" "* ]] || return 1          # "file ... is not owned by any package"
  changes=$(rpm -V "$pkg" 2>/dev/null)                # captured first: rpm -V exits 1 on changes (pipefail)
  ! awk -v f="$f" '$NF==f && ($1 ~ /[S5]/ || $1 == "missing") {found=1} END {exit !found}' <<<"$changes"
}

# Hop 2 (§6.3): rewrites nothing, terminates nothing; the backend is an IP
# literal so there is no resolvers section on a segment with no DNS.
render_haproxy_cfg() {
  local user_lines="" debug_lines="" log_line="    log stdout format raw local0 info" mode_note=""
  detect_haproxy_mode
  if (( HAPROXY_COMPAT18 )); then   # journald owns /dev/log on RHEL
    log_line="    log /dev/log local0 info"
    mode_note="# HAProxy 1.8 compatibility mode (RHEL 8): logs go to /dev/log - 1.8 has no 'log stdout'."
  fi
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
${mode_note}
global
${log_line}
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

# render_nginx_main - RHEL's stock nginx.conf defines its own server{} on *:80 and [::]:80 inside http{}.
# It is replaced by this minimal main configuration: same user, pid file and module include as the
# package (the systemd unit expects /run/nginx.pid), every server{} lives in conf.d.
render_nginx_main() {
  printf '# Managed by %s - runbook §6.2 (RHEL). Original: %s.orig\n' "$SCRIPT_NAME" "$NGINX_MAIN"
  cat <<'EOF'
# Deliberately contains no server{} block: the package default listened on *:80 and [::]:80.
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

# dynamic modules installed as RPMs (nginx-mod-*)
include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 1024;
}

http {
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" "$http_user_agent"';
    access_log  /var/log/nginx/access.log  main;

    sendfile            on;
    tcp_nopush          on;
    keepalive_timeout   65;
    types_hash_max_size 4096;
    server_tokens       off;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    include /etc/nginx/conf.d/*.conf;
}
EOF
}

render_nginx_site() {
  cat <<EOF
# Managed by $SCRIPT_NAME v$SCRIPT_VERSION - runbook §6.2 (mirror served to the LIVE segment)
# Bound to the LIVE-facing address only: this host also faces the internal firewall, and a
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
         "Find the extra listener: grep -rnE 'listen|bind' $NGINX_MAIN /etc/nginx/conf.d $HAPROXY_CFG $HAPROXY_CFGDIR"; return 1
  fi
  if ! grep -qF " $ip:$port " <<<" $(awk '{print $4}' <<<"$lines" | tr '\n' ' ') "; then
    fail "TCP $port is not bound to $ip." "Listeners found: $(awk '{print $4}' <<<"$lines" | tr '\n' ' ')" "Check the configuration of $proc."; return 1
  fi
  grep -q "\"$proc" <<<"$lines" || warn "TCP $port is owned by an unexpected process: $(grep -oE 'users:\(\("[^"]+"' <<<"$lines" | cut -d'"' -f2 | sort -u | tr '\n' ' ')"
  ok "Listening on $ip:$port only (not on the internet-facing interface)"
}
selinux_enabled() { command -v getenforce >/dev/null && [[ $(getenforce 2>/dev/null) != Disabled ]]; }
selinux_denials() { # SELinux AVC denials for haproxy/nginx in the last 10 minutes
  selinux_enabled || return 0
  if command -v ausearch >/dev/null; then
    ausearch -m AVC,USER_AVC -ts recent 2>/dev/null
  else
    journalctl --since "-10min" --no-pager -o cat 2>/dev/null
  fi | grep -E 'avc: +denied' | grep -E 'comm="(haproxy|nginx)"' | tail -n 5
}
# selinux_restore PATH... - reset files this script wrote to their default SELinux label
selinux_restore() { selinux_enabled && command -v restorecon >/dev/null && restorecon "$@" 2>/dev/null; return 0; }

describe_check_status() { # hop 2 backend = plain TCP check to hop 1
  local s=${1#\*}; s=$(trim "$s"); s=${s%%[[:space:]]*}
  case $s in
    L4OK|L6OK|L7OK) echo "healthy" ;;
    L4TOUT) echo "TCP connect to hop 1 ($DMZ_GW_IP:$OPAMP_PORT) timed out: the internal firewall is silently dropping this host -> DMZ tcp/$OPAMP_PORT (rule missing)." ;;
    L4CON)  echo "connection to hop 1 refused/unreachable: HAProxy on the DMZ host is stopped or not bound to $DMZ_GW_IP, a firewall is rejecting - or SELinux here denies haproxy the connect to tcp/$OPAMP_PORT (run: $0 --only selinux)." ;;
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
              "On the DMZ host: grep -nE 'set-header|sni' /etc/haproxy/haproxy.cfg ; $DMZ_TOOL --diagnose" ;;
    503) st=$(stats_field hop1_dmz dmz status); cs=$(stats_field hop1_dmz dmz check_status)
         if [[ $where == *"$LIVE_GW_IP"* && $st != UP* ]]; then
           fail "Probe via $where returned 503 - hop 2 has no healthy hop 1." "Hop 2 backend check: ${cs:-unknown} - $(describe_check_status "$cs")" \
                "Check the internal-firewall rule this host -> $DMZ_GW_IP tcp/$OPAMP_PORT and HAProxy on the DMZ host ($DMZ_TOOL --diagnose there)."
         else
           fail "Probe via $where returned 503 - hop 1 (DMZ) cannot reach Bindplane Cloud." "The 503 comes from hop 1: DNS, the perimeter-firewall rule or certificate verification on the DMZ host." \
                "On the DMZ host: $DMZ_TOOL --diagnose"
         fi ;;
    403) fail "Probe via $where returned 403 WITHOUT 'Via: 1.1 google'." "Something other than Bindplane's front end answered (an inspection device or block page)." "Inspect the response headers in the evidence file; check the DMZ side with $DMZ_TOOL --diagnose." ;;
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
  elif [[ -n $(selinux_denials) ]] || { grep -qE 'Permission denied' "$f" && [[ $(getenforce 2>/dev/null) == Enforcing ]]; }; then
    fail "$svc was blocked by SELinux." \
         "$(selinux_denials | tail -n 2 | cut -c1-240)\nTypically a port or file label that $svc's SELinux domain may not use (tcp/$OPAMP_PORT is ntop_port_t by default)." \
         "Re-apply the labels: $0 --only selinux\nInspect: ausearch -m AVC -ts recent -c $svc | audit2why ; semanage port -l | grep -wE '$OPAMP_PORT|$REPO_PORT|$STATS_PORT'\nLabel the port or path - do not disable SELinux."
  elif grep -qE 'Cannot raise FD limit|Too many open files|setrlimit' "$f"; then
    fail "$svc could not get enough file descriptors ($(grep -m1 -oE 'limit is [0-9]+' "$f" || echo 'limit too low'))." \
         "HAProxy needs about 2 x maxconn descriptors (maxconn ${HAPROXY_MAXCONN:-?} -> ~$(( ${HAPROXY_MAXCONN:-0} * 2 + 20 ))), but the service limit is lower." \
         "Make sure the drop-in is active: systemctl daemon-reload && systemctl show haproxy -p LimitNOFILE\nOr lower maxconn: re-run with --reconfigure."
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
firewalld_active() { command -v firewall-cmd >/dev/null && [[ $(firewall-cmd --state 2>/dev/null) == running ]]; }
# fw_zone - the zone that handles traffic arriving on LIVE_GW_IP's interface (else the default zone)
fw_zone() {
  local ifc z=""
  ifc=$(iface_of_ip "$LIVE_GW_IP")
  [[ -n $ifc ]] && z=$(firewall-cmd --get-zone-of-interface="$ifc" 2>/dev/null)
  [[ -n $z ]] || z=$(firewall-cmd --get-default-zone 2>/dev/null)
  printf '%s' "$z"
}
# fw_rule SRC DST PORT - the rich rule this script adds (also the key used to find and remove it)
fw_rule() { printf 'rule family="ipv4" source address="%s" destination address="%s" port port="%s" protocol="tcp" accept' "$1" "$2" "$3"; }
fw_port_label() {
  case $1 in "$OPAMP_PORT") echo "opamp hop2" ;; "$REPO_PORT") echo "package mirror" ;; "$OTLP_PORT") echo "otlp" ;; *) echo "bindplane" ;; esac
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
  if [[ -n $ENV_SECRET ]]; then
    BP_SECRET=$ENV_SECRET; SECRET_SOURCE="environment"
    info "Using the secret key from the BP_SECRET environment variable ($(mask "$BP_SECRET"))"
  elif [[ -n $existing ]] && { (( ! RECONFIGURE )) || ask_yn "Keep the secret key already in $cf ($(mask "$existing"))?" y; }; then
    BP_SECRET=$existing; SECRET_SOURCE=$cf
    info "Using the secret key already in $COLLECTOR_CONF ($(mask "$BP_SECRET")) - to replace it run with --reconfigure"
  elif [[ -z $existing && -n $other ]] && ask_yn "Use the secret key of the $(other_family "$COLLECTOR_FAMILY") collector on this host ($(mask "$other"))?" y; then
    BP_SECRET=$other; SECRET_SOURCE="$(other_family "$COLLECTOR_FAMILY") collector config"
  else
    say "  The collector needs the Bindplane secret key (console -> Agents -> Install Agents)."
    say "  It is written only to $COLLECTOR_CONF (mode 0600) - this script does not keep a copy."
    ask_secret BP_SECRET "Bindplane secret key" || { fail "No secret key was provided." "It is required in $cf." "Re-run interactively, or set BP_SECRET in the environment for an unattended run."; return 1; }
    SECRET_SOURCE="prompt"
  fi
  log "secret key source: $SECRET_SOURCE"
  [[ $BP_SECRET =~ ^[0-9A-HJKMNP-TV-Z]{26}$ ]] || warn "The key is not a 26-character ULID - double-check it (an invalid key fails exactly like a wrong one)."
  return 0
}

# =============================================================================
#  BUILD STEPS  (each returns 0 = done, 1 = failed, 3 = skipped on purpose)
# =============================================================================
# enabled_other_repos - ids of enabled repositories in /etc/yum.repos.d other than ours (no dnf call: on an
# isolated host dnf itself may stall trying to refresh them)
enabled_other_repos() {
  awk '/^[[:space:]]*\[/ { if (id != "" && en) print id; id=$0; gsub(/[][[:space:]]/, "", id); en=1; next }
       /^[[:space:]]*enabled[[:space:]]*=/ { v=$0; sub(/^[^=]*=[[:space:]]*/, "", v); en=(v ~ /^(1|yes|true|True)/) }
       END { if (id != "" && en) print id }' /etc/yum.repos.d/*.repo 2>/dev/null | grep -vxF "$DNF_REPO_ID" | paste -sd' '
}

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
    echo "## name resolution"; cat /etc/resolv.conf 2>&1
    echo "## SELinux"; getenforce 2>&1; sestatus 2>&1 | head -n 5
    echo "## firewalld"; firewall-cmd --state 2>&1; firewall-cmd --get-active-zones 2>&1
    echo "## dnf repository files"; grep -HE '^\[|^enabled|^baseurl' /etc/yum.repos.d/*.repo 2>&1
  } >"$f" 2>&1
  check_os
  check_selinux
  if is_local_ip "$LIVE_GW_IP"; then c_ok "LIVE_GW_IP $LIVE_GW_IP is on interface $(iface_of_ip "$LIVE_GW_IP")"
  else c_fail "LIVE_GW_IP $LIVE_GW_IP is not assigned to this host"; hint "Re-run with --reconfigure to choose the correct address."; fi
  dev=$(route_dev "$DMZ_GW_IP"); src=$(route_src "$DMZ_GW_IP")
  if [[ -n $dev ]]; then c_ok "Route to the DMZ gateway $DMZ_GW_IP: via $dev, source address ${src:-?} (the internal-firewall rules must permit this source)"
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
    c_warn "A proxy is configured in the environment - this script bypasses it for the DMZ address (curl --noproxy, wget --no-proxy, dnf proxy=_none_ + no_proxy)"
  fi
  others=$(enabled_other_repos)
  if [[ -n $others ]]; then
    info "$(wc -w <<<"$others") other enabled dnf repositories ($(cut -d' ' -f1-4 <<<"$others")$( (( $(wc -w <<<"$others") > 4 )) && echo ' ...')) are unreachable from here;"
    hint "this script never uses them (dnf --disablerepo='*' --enablerepo=$DNF_REPO_ID). A plain 'dnf' or dnf-automatic on this host will stall on them -"
    hint "disable them if nothing else needs them: dnf config-manager --set-disabled <id>  (or subscription-manager config --rhsm.manage_repos=0)"
  fi
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
  info "Testing the internal firewall path from $(route_src "$DMZ_GW_IP") to the DMZ gateway $DMZ_GW_IP (§5.1 - if this fails, nothing else in Stage 5 works)"
  st8=$(tcp_state "$DMZ_GW_IP" "$REPO_PORT"); explain_tcp "$DMZ_GW_IP" "$REPO_PORT" "$st8" "package repository" || bad=1
  st3=$(tcp_state "$DMZ_GW_IP" "$OPAMP_PORT"); explain_tcp "$DMZ_GW_IP" "$OPAMP_PORT" "$st3" "OpAMP relay hop 1" || bad=1
  st4=$(tcp_state "$DMZ_GW_IP" "$OTLP_PORT")
  case $st4 in
    open) ok "TCP $DMZ_GW_IP:$OTLP_PORT reachable (OTLP - used once the Stage 11 configuration is pushed)" ;;
    refused) info "TCP $DMZ_GW_IP:$OTLP_PORT refused - normal until the DMZ gateway configuration (Stage 11) opens the Bindplane Gateway source; the internal firewall path itself is open" ;;
    *) warn "TCP $DMZ_GW_IP:$OTLP_PORT $st4 - telemetry to the DMZ gateway (Stage 11) will need the internal-firewall rule this host -> $DMZ_GW_IP tcp/$OTLP_PORT" ;;
  esac
  if (( bad )); then
    fail "The DMZ gateway is not reachable on the required ports." \
         "timeout = the internal firewall drops the traffic (rule missing); refused = the DMZ service is down or bound elsewhere; unreachable = routing/address." \
         "Rules needed: $(route_src "$DMZ_GW_IP") -> $DMZ_GW_IP tcp/$REPO_PORT and tcp/$OPAMP_PORT (tcp/$OTLP_PORT for Stage 11).\nOn the DMZ host: $DMZ_TOOL --status (gates §4.2/§4.4 must have passed)."
    return 1
  fi
  code=$(dmz_code /)
  [[ $code == 200 ]] || { fail "The DMZ repository index returned HTTP ${code:-nothing}." "Port $REPO_PORT answers but nginx on the DMZ host is not serving /srv/bindplane." "On the DMZ host: $DMZ_TOOL --only nginx"; return 1; }
  idx=$(dmz_get / | grep -oE 'href="[^"]+/"' | sed -E 's/href="//; s/"//' | tr '\n' ' ')
  ok "Repository index answers 200: $idx"
  [[ $(dmz_code /SHA256SUMS) == 200 ]] || { fail "The DMZ repository has no SHA256SUMS." "Stage 2.4 was not completed on the DMZ host." "On the DMZ host: $DMZ_TOOL --only checksums"; return 1; }
  ok "SHA256SUMS present ($(dmz_get /SHA256SUMS | wc -l) files)"
  fetch_dmz_info
  if [[ -n $DMZ_INFO ]]; then
    ok "DMZ repository: default $(info_field current_collector_version), staged ${DMZ_VERSIONS:-?}"
    built=$(info_field rpm_repo_built_for); mine=$(local_release)
    if [[ $PKG_SOURCE == dmz ]]; then
      if [[ $built == el[0-9]* && ${built%% *} != "$mine" ]]; then
        fail "The DMZ dnf repository was built for ${built%% *}, but this host is $mine." \
             "Packages from another RHEL major release or architecture will not satisfy this host's dependencies (§2.3: build on the same major release)." \
             "Build the repository on a DMZ-side host of the same major release, or use the customer's Satellite / internal mirror (--reconfigure, package source 'system')."
        return 1
      elif [[ $built != el[0-9]* ]]; then
        fail "The DMZ host did not build a dnf repository (${built:-no rpm_repo_built_for in VERSION-INFO - an Ubuntu-built origin?})." \
             "nginx/HAProxy for this host must then come from the customer's Satellite / internal RHEL mirror." \
             "Re-run with --reconfigure and choose package source 'system', or build the dnf repository on a RHEL $OS_MAJOR DMZ host ($DMZ_TOOL)."
        return 1
      fi
      [[ $(dmz_code "/$RPM_REPO_REL/repodata/repomd.xml") == 200 ]] \
        || { fail "VERSION-INFO names a dnf repository, but /$RPM_REPO_REL/repodata/repomd.xml is not served." "The repository was moved or is being rebuilt." "On the DMZ host: $DMZ_TOOL --only os_repo"; return 1; }
      ok "dnf repository built for $built - matches this host"
    fi
  else
    warn "No VERSION-INFO on the DMZ repository (built without $DMZ_TOOL?) - RHEL release compatibility cannot be checked automatically"
    [[ $PKG_SOURCE == dmz && $(dmz_code "/$RPM_REPO_REL/repodata/repomd.xml") != 200 ]] && { fail "The DMZ repository has no /$RPM_REPO_REL/ dnf repository." "The OS-package repository (§2.3) was not built for el$OS_MAJOR-$RPM_ARCH." "Build it on the DMZ host, or use package source 'system' (--reconfigure)."; return 1; }
  fi
  if [[ -n $BP_VERSION && " $DMZ_VERSIONS " != *" $BP_VERSION "* && -n $DMZ_VERSIONS ]]; then
    fail "Collector $BP_VERSION is not staged on the DMZ repository (available: $DMZ_VERSIONS)." "BP_VERSION must be a version the DMZ host has downloaded." \
         "Re-run with --reconfigure and pick one of: $DMZ_VERSIONS - or stage it on the DMZ host: $DMZ_TOOL --choose-versions"
    return 1
  fi
  [[ -n $BP_VERSION ]] && ok "Collector $BP_VERSION ($(family_label "$(family_of_version "$BP_VERSION")")) is staged on the DMZ repository"
  ok "Path to the DMZ gateway is good"
}

# render_repo_file KEYS SIGNED - the dnf repository definition for the DMZ repository
render_repo_file() {
  cat <<EOF
# Managed by $SCRIPT_NAME - runbook §5.2: the DMZ repository is the ONLY source this script uses
[$DNF_REPO_ID]
name=NCINGA Bindplane offline repository (DMZ $DMZ_GW_IP)
baseurl=http://$DMZ_GW_IP:$REPO_PORT/$RPM_REPO_REL/
enabled=1
# every package is verified against the vendor key already on this host
gpgcheck=1
gpgkey=$1
# repomd.xml signature (only when the DMZ host signs the metadata, §5.4)
repo_gpgcheck=$2
# RHEL 8: nginx is a modular package - lets it install from a repository without module metadata
module_hotfixes=1
# straight to the DMZ host, never through a proxy
proxy=_none_
skip_if_unavailable=False
EOF
}

step_dnf_source() {
  local keys vkey out p missing="" signed=0 tmpk new="$RUN_TMP/repo.new"
  if [[ $PKG_SOURCE == system ]]; then
    info "Package source: this host's own dnf repositories (Satellite / internal mirror) - no DMZ repository file is written"
    dnf_run "Refreshing repository metadata (dnf makecache)" makecache --refresh || return 1
    return 0
  fi
  vkey=$(vendor_gpgkey)
  [[ -s ${vkey#file://} ]] || { fail "The OS vendor's package-signing key ${vkey#file://} is missing." "gpgcheck=1 verifies every staged package with it; it normally ships with the OS (redhat-release)." \
                                  "Copy it from another RHEL $OS_MAJOR host via configuration management, then choose [r]."; return 1; }
  keys=$vkey
  if [[ $REPO_SIGNED == yes ]]; then
    [[ -s $REPO_KEY ]] || { fail "The repository key $REPO_KEY is missing." "Signed repository metadata needs the DMZ host's public key here (§5.4)." "Copy /var/lib/bp-dmz-setup/RPM-GPG-KEY-bindplane-repo from the DMZ host to $REPO_KEY via configuration management, then retry."; return 1; }
    # dnf wants an ASCII-armoured key; convert a binary one (e.g. an apt keyring) when gpg is available
    if ! head -c 200 "$REPO_KEY" | grep -q 'BEGIN PGP PUBLIC KEY BLOCK'; then
      command -v gpg >/dev/null || { fail "$REPO_KEY is not an ASCII-armoured key, and gpg is not installed to convert it." "" "Provide RPM-GPG-KEY-bindplane-repo (armoured) from the DMZ host's /var/lib/bp-dmz-setup/."; return 1; }
      tmpk=$(mktemp -d)
      if gpg --batch --homedir "$tmpk" --import "$REPO_KEY" >/dev/null 2>&1 && gpg --batch --homedir "$tmpk" --armor --export >"$REPO_KEY.tmp" 2>/dev/null && [[ -s $REPO_KEY.tmp ]]; then
        mv -f "$REPO_KEY.tmp" "$REPO_KEY"; info "Converted the binary key in $REPO_KEY to the ASCII-armoured form dnf expects"
      else
        rm -rf "$tmpk" "$REPO_KEY.tmp"
        fail "Could not convert $REPO_KEY to an ASCII-armoured key." "" "Provide RPM-GPG-KEY-bindplane-repo from the DMZ host's /var/lib/bp-dmz-setup/."; return 1
      fi
      rm -rf "$tmpk"
    fi
    chmod 644 "$REPO_KEY"; selinux_restore "$REPO_KEY"
    keys+=" file://$REPO_KEY"; signed=1
  else
    info "Unsigned repository metadata: acceptable on an internal host reached over a single permitted rule (§5.2) - every package is still verified against the vendor key (gpgcheck=1)"
  fi
  render_repo_file "$keys" "$signed" >"$new"
  if [[ -f $DNF_REPO_FILE ]] && ! cmp -s "$new" "$DNF_REPO_FILE"; then cp -p "$DNF_REPO_FILE" "$STATE_DIR/$DNF_REPO_ID.repo.bak-$RUN_TS"; info "Previous $DNF_REPO_FILE saved in $STATE_DIR"; fi
  install -m 644 -o root -g root "$new" "$DNF_REPO_FILE"; selinux_restore "$DNF_REPO_FILE"
  ok "Wrote $DNF_REPO_FILE: baseurl http://$DMZ_GW_IP:$REPO_PORT/$RPM_REPO_REL/ (gpgcheck=1$( (( signed )) && echo ', repo_gpgcheck=1'))"
  dnf_run "Refreshing the DMZ repository metadata (dnf makecache, this repository only)" makecache --refresh || return 1
  out=$(dnf_cmd -q repoquery --qf '%{name} %{evr}' --latest-limit 1 nginx haproxy wget 2>&1)
  log "$out"
  for p in nginx haproxy wget; do grep -q "^$p " <<<"$out" || missing+=" $p"; done
  if [[ -n $missing ]]; then
    fail "The DMZ repository does not offer:$missing." "It was built without them (§2.3), or for another release." "Check http://$DMZ_GW_IP:$REPO_PORT/$RPM_REPO_REL/ ; rebuild with $DMZ_TOOL --only os_repo on the DMZ host"
    return 1
  fi
  ok "dnf sees $(awk '$1=="nginx"||$1=="haproxy" {printf "%s %s, ", $1, $2}' <<<"$out" | sed 's/, $//') from the DMZ repository"
}

# dnf_plan_upgrades PLANFILE - "name -> version" of packages already installed that a transaction would
# upgrade (parses dnf's table, including names wrapped onto their own line)
dnf_plan_upgrades() {
  awk 'BEGIN { arch = "^(x86_64|noarch|aarch64|i686|ppc64le|s390x)$" }
       /^Upgrading( dependencies)?:/ { u=1; next }
       /^[A-Z]/ { u=0 }
       u && NF==1 { pend=$1; next }
       u && $2 ~ arch { print $1 " -> " $3; pend=""; next }
       u && $1 ~ arch && pend != "" { print pend " -> " $2; pend="" }' "$1"
}

step_os_packages() {
  local -a want=(nginx haproxy wget) absent=() upgrades=()
  local p n
  # semanage labels this host's ports and mirror (selinux step); the DMZ repository stages it
  selinux_enabled && ! command -v semanage >/dev/null && want+=(policycoreutils-python-utils)
  for p in "${want[@]}"; do rpm -q --quiet "$p" || absent+=("$p"); done
  if (( ${#absent[@]} )); then
    # dry run (dnf answers 'no' and exits 1 - resolution problems show as Error:/Problem: lines)
    dnf_cmd --assumeno install "${absent[@]}" >"$RUN_TMP/plan.out" 2>&1
    log_file "$RUN_TMP/plan.out"
    if grep -qE '^(Error|Problem)' "$RUN_TMP/plan.out"; then explain_dnf_failure "$RUN_TMP/plan.out"; show_tail "$RUN_TMP/plan.out" 12; return 1; fi
    mapfile -t upgrades < <(dnf_plan_upgrades "$RUN_TMP/plan.out")
    n=$(grep -oE '^Install +[0-9]+' "$RUN_TMP/plan.out" | awk '{print $2}')
    info "To install: ${n:-?} package(s) for ${absent[*]}"
    if (( ${#upgrades[@]} )); then
      warn "This also UPGRADES ${#upgrades[@]} package(s) already on this host (their newer versions are dependencies -"
      warn "the DMZ host runs a newer RHEL $OS_MAJOR minor release):"
      printf '         %s\n' "${upgrades[@]:0:15}"
      ask_yn "Proceed with these upgrades (change control)?" y || { fail "Stopped before upgrading existing packages." "" "Review the list above with your change board, then retry."; return 1; }
    fi
    dnf_run "Installing ${absent[*]} from the DMZ repository (RHEL never starts or enables a service on install)" install "${absent[@]}" || return 1
  else
    ok "$(printf '%s, ' "${want[@]}" | sed 's/, $//') are already installed"
  fi
  ok "$(nginx -v 2>&1)"
  ok "$(haproxy -v 2>/dev/null | head -n1)"
  ok "$(wget --version 2>/dev/null | head -n1)"
  detect_haproxy_mode
  (( HAPROXY_COMPAT18 )) && info "HAProxy $HAPROXY_VER (RHEL 8): hop 2 is rendered in 1.8 compatibility mode - it logs to /dev/log (1.8 has no 'log stdout')"
  return 0
}

write_mirror_sync() {
  cat >"$MIRROR_SYNC" <<'EOF'
#!/usr/bin/env bash
# bp-mirror-sync - pull the DMZ package origin into the local mirror and verify it
# (runbook §6.1 / §13.3). Generated by bp-live-setup - re-run it to change the origin.
# Exit codes: 0 ok | 3 disk | 4 network (internal-firewall rule / DMZ nginx) | 8 HTTP error on a file | 20 checksum | 75 already running
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
    echo "$(date -Is) ERROR: wget exit $rc (4 = network: internal-firewall rule to the DMZ host or its nginx; 8 = a file returned an HTTP error; 3 = disk)"
    return "$rc"
  fi
  if ! ( cd "$ROOT" && sha256sum -c --quiet SHA256SUMS ); then
    echo "$(date -Is) ERROR: checksum verification failed - truncated transfer, or the origin changed mid-copy. Run bp-mirror-sync again (df -h $ROOT)."
    return 20
  fi
  chmod -R a+rX "$ROOT"
  # SELinux: files fetched into a labelled tree inherit its label; restorecon also fixes anything copied in by hand
  if command -v restorecon >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" != Disabled ]; then restorecon -R "$ROOT"; fi
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
      4)  fail "The mirror sync could not talk to the DMZ repository (wget exit 4)." "Network failure: the internal-firewall rule this host -> $DMZ_GW_IP tcp/$REPO_PORT, or nginx on the DMZ host." "curl -s --max-time 5 $(dmz_url /) | head ; then choose [r] - completed files are not fetched again." ;;
      8)  fail "Some files in the DMZ index could not be downloaded (wget exit 8): ${notfound:-see output}" \
               "The DMZ index links to a name nginx cannot serve (one containing '%' or '#' from a hand-built repository), or a file was removed on the DMZ host during the sync." \
               "On the DMZ host: $DMZ_TOOL --only checksums (it reports such names), then choose [r]." ;;
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
                 "On the DMZ host: $DMZ_TOOL --only checksums   then here: choose [r]."
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
  ok "Repeatable sync installed: $MIRROR_SYNC  (log: $MIRROR_LOG)"
  configure_sync_timer
}

# ---- SELinux (RHEL) ---------------------------------------------------------------------------------
# Default policy: httpd_t (nginx) may bind http_port_t and http_cache_port_t (8080 is http_cache_port_t);
# haproxy_t may bind and connect to http_port_t and http_cache_port_t. tcp/3001 is ntop_port_t, so hop 2
# could neither listen on it nor reach hop 1 on it; tcp/8404 is unlabelled. Both become http_port_t.
# The mirror is labelled httpd_sys_content_t (read-only web content).
selinux_record() { touch "$SELINUX_RECORD"; chmod 600 "$SELINUX_RECORD"; grep -qxF "$1" "$SELINUX_RECORD" || echo "$1" >>"$SELINUX_RECORD"; }
# selinux_port_type PORT - effective SELinux type of tcp/PORT: local customisations win, then the narrowest
# policy definition (an exact port beats a range such as unreserved_port_t 1024-32767)
selinux_port_type() {
  local p=$1 f="$RUN_TMP/semanage.ports"
  if [[ ! -s $f ]]; then semanage port -l -C >"$f.local" 2>/dev/null; semanage port -l >"$f" 2>/dev/null; fi
  awk -v p="$p" '
    $2=="tcp" { for (i=3; i<=NF; i++) { x=$i; gsub(/,/, "", x)
        if (x ~ /^[0-9]+-[0-9]+$/) { split(x, r, "-"); lo=r[1]+0; hi=r[2]+0 } else if (x ~ /^[0-9]+$/) { lo=x+0; hi=lo } else continue
        if (p+0 >= lo && p+0 <= hi) { w=hi-lo; if (FILENAME==ARGV[1]) w-=1000000; if (best=="" || w<bw) { best=$1; bw=w } } } }
    END { print (best=="" ? "unlabelled" : best) }' "$f.local" "$f"
}
selinux_ports_changed() { rm -f "$RUN_TMP/semanage.ports" "$RUN_TMP/semanage.ports.local"; }
# selinux_label_port PORT WHO - make tcp/PORT usable by nginx/haproxy (http_port_t unless already allowed)
selinux_label_port() {
  local port=$1 who=$2 cur out="$RUN_TMP/semanage.out" mode
  cur=$(selinux_port_type "$port")
  if [[ $cur == http_port_t || $cur == http_cache_port_t ]]; then ok "tcp/$port is $cur - $who may use it"; return 0; fi
  printf '    Labelling tcp/%s http_port_t (was %s) so %s may use it ... ' "$port" "$cur" "$who"
  if semanage port -a -t http_port_t -p tcp "$port" >"$out" 2>&1; then mode=added
  elif semanage port -m -t http_port_t -p tcp "$port" >>"$out" 2>&1; then mode=modified
  else
    printf '%sFAILED%s\n' "$C_RED" "$C_OFF"; show_tail "$out" 6; log_file "$out"
    fail "semanage could not label tcp/$port." "See the semanage output above." "Run by hand: semanage port -a -t http_port_t -p tcp $port   (or -m if it is already defined)"
    return 1
  fi
  printf '%sok%s\n' "$C_GRN" "$C_OFF"; log_file "$out"
  selinux_record "port|$port|$mode|$cur"; selinux_ports_changed
  cur=$(selinux_port_type "$port")
  [[ $cur == http_port_t ]] || { fail "tcp/$port still reads as $cur after labelling." "A conflicting local customisation exists." "semanage port -l -C ; semanage port -l | grep -w $port"; return 1; }
}
selinux_label_repo() {
  local spec="${REPO_ROOT%/}(/.*)?" cur ctx
  cur=$(semanage fcontext -l -C 2>/dev/null | awk -v s="$spec" '$1==s {print $NF; exit}')
  if [[ $cur == *:httpd_sys_content_t:* ]]; then ok "$REPO_ROOT is registered as httpd_sys_content_t"
  elif [[ -n $cur ]]; then
    run "Changing the label rule for $REPO_ROOT to httpd_sys_content_t (was ${cur})" semanage fcontext -m -t httpd_sys_content_t "$spec" \
      || { fail "semanage fcontext -m failed." "See the output above." "semanage fcontext -l -C"; return 1; }
    cur=${cur#*:*:}; selinux_record "fcontext|$spec|modified|${cur%%:*}"
  else
    run "Registering $REPO_ROOT as web content (httpd_sys_content_t)" semanage fcontext -a -t httpd_sys_content_t "$spec" \
      || { fail "semanage fcontext -a failed." "See the output above." "semanage fcontext -l | grep '${REPO_ROOT}'"; return 1; }
    selinux_record "fcontext|$spec|added|"
  fi
  run "Applying labels (restorecon -R $REPO_ROOT)" restorecon -R "$REPO_ROOT" \
    || { fail "restorecon failed on $REPO_ROOT." "The filesystem may not support SELinux labels (NFS/CIFS)." "findmnt -T $REPO_ROOT ; for NFS: setsebool -P httpd_use_nfs on"; return 1; }
  ctx=$(stat -c %C "$REPO_ROOT" 2>/dev/null)
  if [[ $ctx == *:httpd_sys_content_t:* ]]; then ok "$REPO_ROOT is labelled $ctx"
  else
    fail "$REPO_ROOT is labelled '${ctx:-?}', not httpd_sys_content_t." \
         "The filesystem does not keep SELinux labels (NFS/CIFS mount?), or a more specific rule wins." \
         "findmnt -T $REPO_ROOT ; semanage fcontext -l | grep '$REPO_ROOT'\nFor NFS: setsebool -P httpd_use_nfs on (then choose [s] for this step)"
    return 1
  fi
}

step_selinux() {
  if ! selinux_enabled; then info "SELinux is disabled on this host - nothing to label."; return 3; fi
  command -v semanage >/dev/null || { fail "semanage is not installed." "policycoreutils-python-utils is missing (os_packages installs it from the DMZ repository when SELinux is enabled)." \
                                         "$0 --only os_packages ; or: dnf --disablerepo='*' --enablerepo=$DNF_REPO_ID install policycoreutils-python-utils"; return 1; }
  install -d -m 755 "$REPO_ROOT"
  info "SELinux is $(getenforce) - labelling what nginx and haproxy need (this takes a few seconds per change)"
  selinux_label_repo || return 1
  selinux_label_port "$REPO_PORT" nginx || return 1
  selinux_label_port "$OPAMP_PORT" "haproxy (listen here, connect to hop 1)" || return 1
  selinux_label_port "$STATS_PORT" haproxy || return 1
  if [[ $(getsebool haproxy_connect_any 2>/dev/null) == *"--> on" ]]; then
    info "haproxy_connect_any is on (set outside this script) - this configuration does not need it"
  fi
  ok "SELinux labels in place (the collector itself runs unconfined and needs none)"
}

# nginx_main_config - replace RHEL's stock nginx.conf (its built-in server{} listens on *:80 and [::]:80)
nginx_main_config() {
  local new="$RUN_TMP/nginx.conf.new"
  render_nginx_main >"$new"
  if [[ -f $NGINX_MAIN ]] && grep -q "Managed by $SCRIPT_NAME" "$NGINX_MAIN"; then
    cmp -s "$new" "$NGINX_MAIN" && { ok "$NGINX_MAIN is already the managed main configuration"; return 0; }
  elif [[ -f $NGINX_MAIN ]] && ! conf_is_pristine "$NGINX_MAIN"; then
    warn "$NGINX_MAIN has local changes (it is not the file the nginx package shipped)."
    hint "This step replaces it with a minimal main configuration that only includes /etc/nginx/conf.d (a backup is kept)."
    if ! ask_yn "Replace $NGINX_MAIN?" n; then
      fail "$NGINX_MAIN left untouched." "It carries local changes; the stock server{} on *:80 may still be in it." \
           "Remove every server{} that listens on a wildcard address from $NGINX_MAIN by hand, then choose [s] for this step,\nor re-run and allow the replacement."
      return 1
    fi
    cp -p "$NGINX_MAIN" "$NGINX_MAIN.bak-$RUN_TS"; info "Backed up the existing file to $NGINX_MAIN.bak-$RUN_TS"
  fi
  if [[ -f $NGINX_MAIN && ! -f $NGINX_MAIN.orig ]] && ! grep -q "Managed by $SCRIPT_NAME" "$NGINX_MAIN"; then
    cp -p "$NGINX_MAIN" "$NGINX_MAIN.orig"; info "Saved the package nginx.conf as $NGINX_MAIN.orig"
  fi
  install -m 644 -o root -g root "$new" "$NGINX_MAIN"
  selinux_restore "$NGINX_MAIN"
  ok "Installed the managed $NGINX_MAIN (no server{} of its own - the stock one listened on *:80 and [::]:80)"
}

step_nginx() {
  local others code
  rpm -q --quiet nginx || { fail "nginx is not installed." "The os_packages step did not complete." "$0 --only os_packages"; return 1; }
  nginx_main_config || return 1
  others=$(grep -lE '^[[:space:]]*listen[[:space:]]' /etc/nginx/conf.d/*.conf 2>/dev/null | grep -vxF "$NGINX_SITE" | xargs -r -n1 basename | tr '\n' ' ')
  [[ -n $others ]] && warn "Other nginx server configurations in /etc/nginx/conf.d will keep running: $others(make sure none listens on a wildcard address)"
  render_nginx_site >"$RUN_TMP/nginx.site"
  install -m 644 -o root -g root "$RUN_TMP/nginx.site" "$NGINX_SITE"
  selinux_restore "$NGINX_SITE"
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
  [[ $code == 200 ]] || { fail "The mirror index returned HTTP ${code:-no response}." "nginx is running but cannot serve $REPO_ROOT (403 on RHEL is usually the SELinux label)." \
                            "tail $NGINX_ERROR_LOG ; ls -ldZ $REPO_ROOT   (expect httpd_sys_content_t; fix: $0 --only selinux)"; return 1; }
  lcurl -s --max-time 10 "http://$LIVE_GW_IP:$REPO_PORT/SHA256SUMS" -o "$RUN_TMP/sums.http"
  cmp -s "$RUN_TMP/sums.http" "$REPO_ROOT/SHA256SUMS" \
    || { fail "SHA256SUMS served over HTTP differs from the file on disk." "Wrong root directory or a caching layer." "grep root $NGINX_SITE"; return 1; }
  ok "Mirror served on http://$LIVE_GW_IP:$REPO_PORT/ ($(wc -l <"$REPO_ROOT/SHA256SUMS") files) - log sources install from here (Stage 8)"
}

step_haproxy_config() {
  local new="$RUN_TMP/haproxy.cfg.new" first
  command -v haproxy >/dev/null || { fail "haproxy is not installed." "The os_packages step did not complete." "$0 --only os_packages"; return 1; }
  is_local_ip "$LIVE_GW_IP" || { fail "$LIVE_GW_IP is not assigned to this host." "The address changed since configuration." "Re-run with --reconfigure."; return 1; }
  if compgen -G "$HAPROXY_CFGDIR/*.cfg" >/dev/null && [[ $(systemctl cat haproxy 2>/dev/null) == *CFGDIR* ]]; then
    warn "The haproxy unit also loads $HAPROXY_CFGDIR/*.cfg: $(cd "$HAPROXY_CFGDIR" && printf '%s ' ./*.cfg)"
    hint "They are validated together with hop 2 and keep running - make sure none binds a wildcard address."
  fi
  # RHEL's stock haproxy.cfg is a sample with 'frontend main *:5000' - it is replaced silently (kept as .orig)
  if [[ -f $HAPROXY_CFG ]] && ! grep -q "Managed by $SCRIPT_NAME" "$HAPROXY_CFG" && ! conf_is_pristine "$HAPROXY_CFG" \
     && grep -qE '^[[:space:]]*(frontend|listen)[[:space:]]' "$HAPROXY_CFG"; then
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
  if ! run "Validating the new configuration before installing it (haproxy -c)" haproxy_check "$new"; then
    first=$(grep -m1 -F '[ALERT]' "$LAST_OUT")
    fail "haproxy -c rejected the generated configuration." "First alert: ${first:-see output}\nOnly the FIRST alert is real - later ones are the parser losing its place (§3.1)." \
         "The live configuration was NOT changed. The candidate file is $STATE_DIR/haproxy.cfg.rejected."
    cp -f "$new" "$STATE_DIR/haproxy.cfg.rejected" 2>/dev/null
    return 1
  fi
  if [[ -f $HAPROXY_CFG && ! -f $HAPROXY_CFG.orig ]] && ! grep -q "Managed by $SCRIPT_NAME" "$HAPROXY_CFG"; then cp -p "$HAPROXY_CFG" "$HAPROXY_CFG.orig"; info "Saved the package default as $HAPROXY_CFG.orig"; fi
  if [[ -f $HAPROXY_CFG ]] && ! grep -q "Managed by $SCRIPT_NAME" "$HAPROXY_CFG" && ! cmp -s "$HAPROXY_CFG" "$HAPROXY_CFG.orig"; then
    cp -p "$HAPROXY_CFG" "$HAPROXY_CFG.bak-$RUN_TS"; info "Backed up the existing configuration to $HAPROXY_CFG.bak-$RUN_TS"
  fi
  install -m 644 -o root -g root "$new" "$HAPROXY_CFG"
  selinux_restore "$HAPROXY_CFG"
  run "Re-validating the installed configuration" haproxy_check "$HAPROXY_CFG" || { fail "Installed configuration failed validation." "" "Restore with: cp $HAPROXY_CFG.orig $HAPROXY_CFG"; return 1; }
  ok "timeout tunnel 24h set here too (the shortest value in the chain wins - a correct hop 1 does not rescue hop 2)"
  ok "Hop 2 installed: $LIVE_GW_IP:$OPAMP_PORT -> hop 1 $DMZ_GW_IP:$OPAMP_PORT (no Host rewrite, no resolvers)$( (( HAPROXY_COMPAT18 )) && echo '; HAProxy 1.8 mode: logs to /dev/log')"
}

step_haproxy_limits() {
  install -d -m 755 "$HAPROXY_DROPIN_DIR"
  printf '# Managed by %s - runbook §6.3 / §3.5\n[Service]\nLimitNOFILE=65535\n' "$SCRIPT_NAME" >"$HAPROXY_DROPIN"
  chmod 644 "$HAPROXY_DROPIN"
  run "Reloading systemd units (daemon-reload)" systemctl daemon-reload || { fail "systemctl daemon-reload failed." "" "journalctl -n 20"; return 1; }
  ok "LimitNOFILE=65535 set for haproxy (maxconn $HAPROXY_MAXCONN: keep it >= 2x the projected agent count)"
}

step_host_firewall() {
  local src port zone rule changed=0 z srcs osrc oport odst ozone keep="$RUN_TMP/fw.keep"
  if firewalld_active && [[ -z $FW_SOURCES || $FW_SOURCES == none ]]; then
    fail "firewalld is running, but no log-source subnets are configured." "firewalld was not running when the questions were asked, so no sources were recorded." \
         "Re-run with --reconfigure and enter the LIVE log-source subnets (they need tcp/${FW_PORTS// /,} to $LIVE_GW_IP)."
    return 1
  fi
  if firewalld_active; then
    zone=$(fw_zone)
    [[ -n $zone ]] || { fail "Could not determine the firewalld zone for $LIVE_GW_IP." "" "firewall-cmd --get-active-zones ; firewall-cmd --get-default-zone"; return 1; }
    info "firewalld is running - allowing the LIVE log sources to reach $LIVE_GW_IP (zone '$zone'; outbound to the DMZ host is not filtered by firewalld)"
    touch "$FW_RECORD"; chmod 600 "$FW_RECORD"; : >"$keep"
    # remove rules this script added earlier that no longer match the answers
    while read -r osrc oport odst ozone; do
      [[ -n $osrc ]] || continue; odst=${odst:-$LIVE_GW_IP}; ozone=${ozone:-$zone}
      if [[ $odst == "$LIVE_GW_IP" && $ozone == "$zone" ]] && contains_word "$FW_SOURCES" "$osrc" && contains_word "$FW_PORTS" "$oport"; then
        echo "$osrc $oport $odst $ozone" >>"$keep"
      elif run "remove old rule $osrc -> $odst tcp/$oport (zone $ozone)" firewall-cmd --permanent --zone="$ozone" --remove-rich-rule="$(fw_rule "$osrc" "$odst" "$oport")"; then changed=1
      else warn "Could not remove it - check: firewall-cmd --zone=$ozone --list-rich-rules"; fi
    done <"$FW_RECORD"
    cp -f "$keep" "$FW_RECORD"
    for src in $FW_SOURCES; do
      for port in $FW_PORTS; do
        rule=$(fw_rule "$src" "$LIVE_GW_IP" "$port")
        if firewall-cmd --permanent --zone="$zone" --query-rich-rule="$rule" >/dev/null 2>&1; then
          ok "allow $src -> $LIVE_GW_IP tcp/$port ($(fw_port_label "$port")) - already present"
        else
          run "allow $src -> $LIVE_GW_IP tcp/$port ($(fw_port_label "$port"))" firewall-cmd --permanent --zone="$zone" --add-rich-rule="$rule" \
            || { fail "firewalld refused the rule for $src tcp/$port." "See the firewall-cmd output above." "firewall-cmd --zone=$zone --list-all"; return 1; }
          changed=1
        fi
        grep -qxF "$src $port $LIVE_GW_IP $zone" "$FW_RECORD" || echo "$src $port $LIVE_GW_IP $zone" >>"$FW_RECORD"
        # the runtime configuration must carry it too (a permanent-only rule does nothing until a reload)
        firewall-cmd --zone="$zone" --query-rich-rule="$rule" >/dev/null 2>&1 || changed=1
      done
    done
    if (( changed )); then
      run "Activating the permanent rules (firewall-cmd --reload)" firewall-cmd --reload \
        || { fail "firewall-cmd --reload failed." "The permanent configuration is invalid." "firewall-cmd --check-config ; journalctl -u firewalld -n 20"; return 1; }
    fi
    # firewalld picks a zone by SOURCE before interface: a source bound to another zone bypasses these rules
    while read -r z srcs; do
      [[ $z != "$zone" ]] || continue
      for src in $FW_SOURCES; do contains_word "$srcs" "$src" && warn "Source $src is bound to firewalld zone '$z' - that zone's rules apply to it, not the rules added to '$zone'"; done
    done < <(firewall-cmd --get-active-zones 2>/dev/null | awk '/^[^[:space:]]/ {z=$1} /^[[:space:]]+sources:/ {sub(/^[[:space:]]+sources:[[:space:]]*/, ""); print z, $0}')
    { firewall-cmd --get-active-zones; firewall-cmd --zone="$zone" --list-all; } >"$EVIDENCE_DIR/firewalld-$RUN_TS.txt" 2>&1
  else
    info "firewalld is not running - no host-firewall changes made"
    if nft list ruleset 2>/dev/null | grep -qE 'hook input .*policy drop' || iptables -S INPUT 2>/dev/null | grep -q '^-P INPUT DROP'; then
      warn "The INPUT policy is DROP but firewalld is not managing it: allow tcp/${FW_PORTS// /,} from the LIVE log sources to $LIVE_GW_IP in your firewall tooling"
    fi
  fi
  info "Perimeter rules still needed (network team):"
  say  "        internal firewall : $(route_src "$DMZ_GW_IP") -> $DMZ_GW_IP  tcp/$OPAMP_PORT (OpAMP), tcp/$REPO_PORT (packages), tcp/$OTLP_PORT (OTLP)"
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
  if [[ -n $(selinux_denials) ]]; then   # running, but something was denied (the hop-1 connect, or 1.8 logging to /dev/log)
    warn "SELinux denied haproxy something since it started (it is running):"; selinux_denials | cut -c1-200 | sed 's/^/         /'
    hint "A denied name_connect to tcp/$OPAMP_PORT keeps hop 1 DOWN: $0 --only selinux . Inspect: ausearch -m AVC -ts recent -c haproxy | audit2why"
    hint "If only /dev/log writes are denied (HAProxy 1.8), the relay works but logs nothing: ausearch -m AVC -ts recent -c haproxy | audit2allow -M bp-haproxy-log && semodule -i bp-haproxy-log.pp"
  fi
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
       "Re-test: $0 --only dmz_path ; SELinux labels: $0 --only selinux ; on the DMZ host: $DMZ_TOOL --diagnose\nLast check detail: $(stats_field hop1_dmz dmz last_chk)"
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
    fail "$w" "The direct probe to hop 1 fails too ($PROBE_STATUS${PROBE_STATUS:+ }curl exit $PROBE_RC), so the fault is at or beyond hop 1: the internal-firewall rule, or the DMZ side.\n$y" \
         "$x\nOn the DMZ host: $DMZ_TOOL --diagnose"
  fi
  return 1
}

# handle_other_family FAMILY VERSION - the collector of the other family is installed on this host
handle_other_family() {
  local f=$1 v=$2 svc a
  svc=$(product_of_family "$f")
  if ! systemctl is-active --quiet "$svc" && [[ $(systemctl is-enabled "$svc" 2>/dev/null) != enabled ]] && [[ $OTHER_ACTION != remove ]]; then
    ok "The $(family_label "$f") collector $v is stopped and disabled - its package stays for rollback"
    return 0
  fi
  warn "The $(family_label "$f") collector $v is installed here; this gateway is being set up with $(family_label "$COLLECTOR_FAMILY") $BP_VERSION."
  say  "  Two collectors on one host are two agents in the console, each with its own configuration."
  OTHER_SECRET=$( use_family "$f"; yaml_get secret_key )
  a=$OTHER_ACTION
  if [[ -z $a ]]; then
    if (( ASSUME_YES )) || [[ -z $TTY ]]; then
      fail "The $f collector is installed and no choice was given for it." "Unattended runs never change the other collector on their own." \
           "Re-run interactively, or add --other-collector stop (stop + disable, package kept), remove (rpm -e) or keep"
      return 1
    fi
    a=$(choose "  [s] stop + disable it (package kept for rollback)   [r] remove it (rpm -e)   [k] keep both   [q] quit: " srkq s)
    case $a in s) a=stop ;; r) a=remove ;; k) a=keep ;; *) fail "Stopped at your request." "" "Re-run when you have decided what to do with the $f collector."; return 1 ;; esac
  fi
  case $a in
    stop)   run "Stopping and disabling $svc" systemctl disable --now "$svc" || return 1
            ok "The $f collector is stopped and disabled (package and config kept - back: systemctl enable --now $svc)" ;;
    remove) systemctl disable --now "$svc" >/dev/null 2>&1
            run_stream "Removing $svc (rpm -e)" rpm -e "$svc" || { fail "rpm could not remove $svc." "See the output above." "rpm -q $svc ; rpm -e $svc"; return 1; }
            ok "The $f collector is removed - its agent shows as disconnected in the console (delete it there)" ;;
    keep)   warn "Keeping the $f collector running next to the new one at your request" ;;
  esac
  return 0
}

step_collector_install() {
  local pkgf rel want got inst ofam ov name
  rel=$(pkg_rel "$BP_VERSION"); pkgf="$REPO_ROOT/$rel"
  ofam=$(other_family "$COLLECTOR_FAMILY"); ov=$(pkg_version "$(product_of_family "$ofam")")
  if [[ -n $ov ]]; then handle_other_family "$ofam" "$ov" || return 1; fi
  if [[ ! -f $pkgf ]]; then
    fail "$rel is not in the mirror." "Mirrored versions: $(mirror_versions)" "Pick one of them with --reconfigure, or stage $BP_VERSION on the DMZ host ($DMZ_TOOL --choose-versions) and run: $0 --only mirror"
    return 1
  fi
  want=$(awk -v n="$rel" '$2==n {print $1; exit}' "$REPO_ROOT/SHA256SUMS"); got=$(sha256 "$pkgf")
  [[ -n $want && $want == "$got" ]] || { fail "$rel does not match SHA256SUMS." "Corrupt or partial mirror copy." "$0 --only mirror"; return 1; }
  name=$(rpm -qp --nosignature --qf '%{NAME}' "$pkgf" 2>/dev/null)
  [[ $name == "$COLLECTOR_PKG" ]] || { fail "$rel does not contain the $COLLECTOR_PKG package (${name:-not an .rpm})." "A renamed or wrong file in the repository." "Re-stage it on the DMZ host ($DMZ_TOOL --choose-versions), then: $0 --only mirror"; return 1; }
  ok "$rel verified against SHA256SUMS ($COLLECTOR_PKG)"
  if [[ $(rpm -q "$COLLECTOR_PKG" 2>/dev/null | grep -c "^$COLLECTOR_PKG-") -gt 1 ]]; then
    # an interrupted rpm transaction can leave two versions registered - installing again cleans it up
    warn "$COLLECTOR_PKG is registered twice in the rpm database (an earlier upgrade was interrupted) - reinstalling it"
    REPLACE_CONFIRMED=1
  fi
  inst=$(collector_installed_version)
  if [[ $inst == "$BP_VERSION" ]]; then ok "Collector $inst ($COLLECTOR_PKG) is already installed"; return 0; fi
  if [[ -n $inst ]] && (( ! REPLACE_CONFIRMED )); then
    warn "Collector $inst is installed; the chosen version is $BP_VERSION"
    ask_yn "Replace $inst with $BP_VERSION from the mirror?" y || { warn "Keeping $inst"; return 0; }
  fi
  info "Installing the package directly with rpm - NOT with install_unix.sh, which needs the internet (§6.4)"
  rpm_install "$pkgf" || return 1
  systemctl daemon-reload 2>/dev/null
  systemctl cat "$COLLECTOR_SVC" >/dev/null 2>&1 || { fail "The package installed but $COLLECTOR_SVC.service is missing." "The package scriptlets failed part-way." "rpm -q $COLLECTOR_PKG ; choose [r] to install it again"; return 1; }
  ok "Collector $(collector_version) installed ($(family_label "$COLLECTOR_FAMILY")); runtime owner of $COLLECTOR_HOME: $(collector_owner)"
  [[ $COLLECTOR_FAMILY == v1 && $(collector_owner) != observiq-otel-collector:* ]] && hint "Note: v1.108+ uses the 'bdot' user, not 'observiq-otel-collector' as written in runbook §6.4/§8.4 - this script uses the actual owner."
  # the package swaps the binary but does not restart a running service - the old code keeps running until restarted
  if [[ -n $inst && -f $COLLECTOR_CONF ]] && systemctl is-active --quiet "$COLLECTOR_SVC"; then
    service_restart_checked "$COLLECTOR_SVC" || return 1
    info "Restarted so the new binary is the one running (the package does not restart it)"
  fi
  return 0
}

# write_manager_yaml (v1) / write_supervisor_yaml (v2) -> CONFIG_CHANGED=0|1
write_manager_yaml() {
  local endpoint="ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp" aid owner tmp
  CONFIG_CHANGED=1
  aid=$(yaml_get agent_id)
  if [[ -f $MANAGER_YAML && $(yaml_get endpoint) == "$endpoint" && $(yaml_get secret_key) == "$BP_SECRET" \
        && $(yaml_get labels) == "$AGENT_LABELS" && $(yaml_get agent_name) == "$AGENT_NAME" ]]; then
    CONFIG_CHANGED=0; ok "manager.yaml already has the right endpoint, key, labels and name"; return 0
  fi
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
}
render_supervisor_yaml() { # the layout the vendor's v2 installer writes
  cat <<EOF
server:
  endpoint: "ws://${DMZ_GW_IP}:${OPAMP_PORT}/v1/opamp"
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
    output_paths: ["$COLLECTOR_LOG"]
EOF
}
write_supervisor_yaml() {
  local new="$RUN_TMP/supervisor.yaml" owner tmp old_ep old_lb old_key
  CONFIG_CHANGED=1
  ( umask 077; render_supervisor_yaml >"$new" )
  if [[ -f $SUP_YAML ]] && cmp -s "$new" "$SUP_YAML"; then rm -f "$new"; CONFIG_CHANGED=0; ok "supervisor.yaml already has the right endpoint, key and labels"; return 0; fi
  if [[ -f $SUP_YAML ]]; then
    old_ep=$(yaml_get endpoint); old_lb=$(yaml_get labels); old_key=$(yaml_get secret_key)
    cp -p "$SUP_YAML" "$STATE_DIR/supervisor.yaml.bak-$RUN_TS"; chmod 600 "$STATE_DIR/supervisor.yaml.bak-$RUN_TS"
    info "Previous supervisor.yaml saved as $STATE_DIR/supervisor.yaml.bak-$RUN_TS"
    [[ $old_ep != "ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp" ]] && say "      endpoint: ${old_ep:-<none>}  ->  ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp"
    [[ $old_lb != "$AGENT_LABELS" ]] && say "      labels:   ${old_lb:-<none>}  ->  $AGENT_LABELS"
    [[ -n $old_key && $old_key != "$BP_SECRET" ]] && say "      secret key: replaced ($(mask "$old_key") -> $(mask "$BP_SECRET"))"
    [[ -z $old_key ]] && say "      secret key: added (the package's default file has none)"
  fi
  owner=$(collector_owner)
  tmp=$(mktemp "$V2_HOME/.supervisor.XXXXXX") || { rm -f "$new"; fail "Cannot write in $V2_HOME." "Disk full or read-only filesystem." "df -h $V2_HOME"; return 1; }
  chmod 600 "$tmp"; cat "$new" >"$tmp"; rm -f "$new"
  chown "$owner" "$tmp" 2>/dev/null || warn "Could not chown supervisor.yaml to $owner - leaving it root-owned (the service runs as root)"
  mv -f "$tmp" "$SUP_YAML"
  ok "Wrote $SUP_YAML (endpoint ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp, owner $owner, mode 0600)"
  if command -v python3 >/dev/null && python3 -c 'import yaml' 2>/dev/null; then
    python3 -c 'import sys,yaml; yaml.safe_load(open(sys.argv[1]))' "$SUP_YAML" 2>"$RUN_TMP/yaml.err" \
      || { fail "supervisor.yaml is not valid YAML: $(tail -n1 "$RUN_TMP/yaml.err")" "A character in the labels or key broke the file." "Check the labels (key=value,key=value) and the key: $0 --reconfigure"; return 1; }
  fi
  local id; id=$(yaml_get agent_id)
  [[ -n $id ]] && info "The agent identity ($id, supervisor_storage/) is kept - the console keeps this host as the same agent"
  return 0
}

step_collector_config() {
  CONFIG_CHANGED=1
  ensure_secret || return 1
  [[ -d $COLLECTOR_HOME ]] || { fail "$COLLECTOR_HOME does not exist." "The $COLLECTOR_PKG package is not installed." "$0 --only collector_install"; return 1; }
  if [[ $COLLECTOR_FAMILY == v2 ]]; then write_supervisor_yaml || return 1; else write_manager_yaml || return 1; fi
  hint "labels \"$AGENT_LABELS\" are how configurations get assigned in bulk later (§6.4) - not cosmetic."
  run "Reloading systemd units" systemctl daemon-reload
  run "Enabling the collector at boot" systemctl enable "$COLLECTOR_SVC"
  if (( CONFIG_CHANGED )) || ! systemctl is-active --quiet "$COLLECTOR_SVC"; then
    service_restart_checked "$COLLECTOR_SVC" || return 1
  fi
}

collector_conn() { # local address of the active collector's established OpAMP session to hop 1
  ss -Htnp state established dst "$DMZ_GW_IP:$OPAMP_PORT" 2>/dev/null | grep -iE "$COLLECTOR_PROC" | awk '{print $3}' | head -n1
}

step_collector_verify() {
  local i v aid c1="" c2="" errs before=0 console=0 name cf
  cf=$(basename "$COLLECTOR_CONF"); name=$( [[ $COLLECTOR_FAMILY == v2 ]] && hostname -s || echo "$AGENT_NAME" )
  [[ -r $COLLECTOR_LOG ]] && before=$(wc -l <"$COLLECTOR_LOG")
  for i in $(seq 1 15); do systemctl is-active --quiet "$COLLECTOR_SVC" && break; sleep 1; done
  systemctl is-active --quiet "$COLLECTOR_SVC" || { journalctl -u "$COLLECTOR_SVC" -n 20 --no-pager >"$RUN_TMP/col.j" 2>&1; show_tail "$RUN_TMP/col.j" 12
    fail "The collector service is not running." "It exits at start - see the journal above and $COLLECTOR_LOG." "journalctl -u $COLLECTOR_SVC -n 50 --no-pager ; tail -n 50 $COLLECTOR_LOG"; return 1; }
  ok "Collector service $COLLECTOR_SVC is active"
  v=$(collector_version); [[ $v == "$BP_VERSION" ]] && ok "Collector version $v ($(family_label "$COLLECTOR_FAMILY"))" || warn "Collector reports '${v:-?}' (chosen version $BP_VERSION)"
  for i in $(seq 1 30); do aid=$(yaml_get agent_id); [[ -n $aid ]] && break; sleep 1; done
  [[ -n $aid ]] && ok "Agent identity $aid" || warn "No agent identity recorded yet"
  if [[ $COLLECTOR_FAMILY == v2 ]]; then
    pgrep -f "$V2_HOME/bindplane-otel-collector" >/dev/null 2>&1 && ok "The collector process runs under the OpAMP supervisor" \
      || info "The supervisor starts the collector process once it has its configuration"
  fi
  info "Waiting up to 60s for the OpAMP session to hop 1 ($DMZ_GW_IP:$OPAMP_PORT) ..."
  for i in $(seq 1 60); do c1=$(collector_conn); [[ -n $c1 ]] && break; sleep 1; done
  if [[ -n $c1 ]]; then
    sleep 15; c2=$(collector_conn)
  fi
  errs=$(collector_log_errors "$before" 6)
  [[ -n $errs ]] && { warn "Collector log errors since the start:"; printf '%s\n' "$errs" | redact_stream | sed 's/^/         /'; }
  if [[ -n $c1 && $c1 == "$c2" ]]; then
    ok "Stable OpAMP session to hop 1 from $c1 (held for 15s+ - a rejected session would have dropped)"
    say "  Check the Bindplane console now: Agents -> $name (identity ${aid:-?})."
    ask_yn "Is $name shown as Connected?" y && console=1
  fi
  { echo "# §6.5 $(date -Is)"; ss -tnp state established dst "$DMZ_GW_IP:$OPAMP_PORT" 2>&1; echo "family=$COLLECTOR_FAMILY identity=$aid version=$v console_connected=$console"; } >"$EVIDENCE_DIR/collector-verify-$RUN_TS.txt"
  if (( console )); then
    ok "PASS: the LIVE collector is managed from Bindplane Cloud through the relay (§6.5 gate)"
    hint "Confirm the tunnel on the DMZ host: curl -s '$STATS_URL' | awk -F, '\$1==\"bindplane_cloud\"{print \$1,\$2,\"scur=\"\$5}'"
    return 0
  fi
  local code=""; code=$(http_code_in_log "$before")
  if [[ -z $c1 || $c1 != "$c2" ]] && [[ -n $code ]]; then
    case $code in
      401|403) fail "The upgrade to WebSocket was refused with HTTP $code (collector log: 'status=$code')." \
                    "A real collector getting $code means the secret key in $cf was rejected (wrong key, or a key from another Bindplane tenant). The 403 the synthetic probe gets is expected; a collector's is not." \
                    "Copy the key again from the console (Agents -> Install Agents), then: $0 --reconfigure (answer 'n' to keeping the key) and --only collector_config" ;;
      404)     fail "The upgrade was answered with HTTP 404." "Host header or SNI at hop 1 does not name the cloud host, or the path is not /v1/opamp." "On the DMZ host: grep -nE 'set-header|sni' /etc/haproxy/haproxy.cfg" ;;
      502|503) fail "The upgrade was answered with HTTP $code by the relay chain." "Hop 2 has no healthy hop 1 ($(stats_field hop1_dmz dmz check_status)), or hop 1 cannot reach Bindplane Cloud." "$0 --diagnose here; $DMZ_TOOL --diagnose on the DMZ host" ;;
      *)       fail "The upgrade was answered with HTTP $code." "See the collector log lines above." "$0 --diagnose" ;;
    esac
  elif [[ -z $c1 ]]; then
    local st; st=$(tcp_state "$DMZ_GW_IP" "$OPAMP_PORT")
    if [[ $st != open ]]; then explain_tcp "$DMZ_GW_IP" "$OPAMP_PORT" "$st" "OpAMP relay hop 1"
      fail "The collector cannot open a connection to hop 1 ($st)." "See the hint above." "Fix the path, then: $0 --only collector_verify"
    else
      fail "The collector did not hold an OpAMP session to $DMZ_GW_IP:$OPAMP_PORT within 60s." \
           "Hop 1 is reachable, so either the session is rejected at once (wrong secret key - the upgrade is refused and the collector backs off), or the collector is not using this endpoint." \
           "grep -n endpoint $COLLECTOR_CONF ; tail -n 50 $COLLECTOR_LOG ; journalctl -u $COLLECTOR_SVC -n 30"
    fi
  elif [[ $c1 != "$c2" ]]; then
    fail "The OpAMP session keeps reconnecting (local port changed $c1 -> ${c2:-none})." \
         "Hop 1 or Bindplane Cloud closes the session after the upgrade - typically a wrong secret_key, or an inline device at the DMZ edge." \
         "Compare the key with the console; to replace it: $0 --reconfigure (answer 'n' to keeping the key), then --only collector_config.\nOn the DMZ host: journalctl -u haproxy -n 30 (termination flags)."
  else
    fail "The session is up but the console does not show $name as Connected." \
         "Authentication was rejected (wrong secret key / tenant), or the console was not refreshed." \
         "Re-check the console, the secret key and the labels, then: $0 --only collector_verify"
  fi
  return 1
}

# msi_rel FAMILY VERSION -> windows/... name of that version's MSI in the mirror (plain name = family current)
msi_rel() {
  local p; p=$(product_of_family "$1")
  if [[ -f $REPO_ROOT/windows/${p}_${2}.msi ]]; then echo "windows/${p}_${2}.msi"
  elif [[ -f $REPO_ROOT/windows/${p}.msi ]]; then echo "windows/${p}.msi"
  else echo "windows/${p}_${2}.msi"; fi
}
# notes_for FAMILY VERSION SEG SITE_LABEL - Stage 8/9 log-source commands for one collector version
notes_for() {
  local fam=$1 v=$2 seg=$3 site_label=$4 p msi
  p=$(product_of_family "$fam"); msi=$(msi_rel "$fam" "$v")
  cat <<EOF
# -----------------------------------------------------------------------------
# $(family_label "$fam") $v$(is_prerelease "$v" && echo '  - PRE-RELEASE')
# -----------------------------------------------------------------------------
## Stage 8 - Linux (RHEL family) log source, as root (8.3 + 8.4); aarch64 hosts: linux_arm64.rpm
export V='$v'
export GW_IP='$LIVE_GW_IP'
read -rsp 'Bindplane secret key: ' BP_SECRET; echo
mkdir -p /opt/bp-install && cd /opt/bp-install
curl -fL -O "http://\${GW_IP}:$REPO_PORT/packages/${p}_\${V}_linux_amd64.rpm"
curl -fL -O "http://\${GW_IP}:$REPO_PORT/SHA256SUMS"
# verify THIS file (SHA256SUMS lists it as packages/...; the --ignore-missing form verifies nothing)
grep " packages/${p}_\${V}_linux_amd64.rpm\$" SHA256SUMS | sed 's# packages/# #' | sha256sum -c -
rpm -U "${p}_\${V}_linux_amd64.rpm"          # never install_unix.sh offline
EOF
  if [[ $fam == v1 ]]; then
    cat <<EOF
install -m 600 -o "\$(stat -c %U /opt/observiq-otel-collector)" -g "\$(stat -c %G /opt/observiq-otel-collector)" /dev/null /opt/observiq-otel-collector/manager.yaml
tee /opt/observiq-otel-collector/manager.yaml >/dev/null <<EOT
endpoint: ws://\${GW_IP}:$OPAMP_PORT/v1/opamp
secret_key: \${BP_SECRET}
labels: "site=$site_label,segment=$seg,zone=<zone>,os=rhel,role=source"
agent_name: \$(hostname -s)
EOT
unset BP_SECRET
systemctl enable observiq-otel-collector && systemctl restart observiq-otel-collector
ss -tnp | grep ':$OPAMP_PORT'                  # 8.9: one ESTAB to $LIVE_GW_IP:$OPAMP_PORT
EOF
  else
    cat <<EOF
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
      service.labels: "site=$site_label,segment=$seg,zone=<zone>,os=rhel,role=source"
storage:
  directory: "/opt/bindplane-otel-collector/supervisor_storage"
telemetry:
  logs:
    level: 0
    output_paths: ["/opt/bindplane-otel-collector/supervisor.log"]
EOT
unset BP_SECRET
systemctl enable bindplane-otel-collector && systemctl restart bindplane-otel-collector
ss -tnp | grep ':$OPAMP_PORT'                  # one ESTAB from opampsupervisor to $LIVE_GW_IP:$OPAMP_PORT
tail -n 30 /opt/bindplane-otel-collector/supervisor.log
EOF
  fi
  if [[ -f $REPO_ROOT/packages/${p}_${v}_linux_amd64.deb ]]; then
    cat <<EOF

## Stage 8 - Ubuntu/Debian log source (8.2): the same, with the .deb and os=ubuntu in the labels
curl -fL -O "http://\${GW_IP}:$REPO_PORT/packages/${p}_\${V}_linux_amd64.deb"
grep " packages/${p}_\${V}_linux_amd64.deb\$" SHA256SUMS | sed 's# packages/# #' | sha256sum -c -
dpkg -i "${p}_\${V}_linux_amd64.deb"
EOF
  fi
  cat <<EOF

## Stage 9 - Windows log source, elevated PowerShell. MSI properties as the vendor's install_windows.ps1 passes
## them; try it on one machine first. Write the gateway as \${Gateway} - "\$Gateway:$REPO_PORT" comes out empty.
\$Gateway = '$LIVE_GW_IP'
New-Item -ItemType Directory -Force -Path C:\\bp-install | Out-Null
Invoke-WebRequest -Uri "http://\${Gateway}:$REPO_PORT/$msi" -OutFile 'C:\\bp-install\\$p.msi' -UseBasicParsing
(Invoke-WebRequest -Uri "http://\${Gateway}:$REPO_PORT/SHA256SUMS" -UseBasicParsing).Content -split "\`n" | Select-String '$msi\$'
(Get-FileHash 'C:\\bp-install\\$p.msi' -Algorithm SHA256).Hash     # must match the line above
\$Key = Read-Host 'Bindplane secret key'
Start-Process msiexec.exe -Wait -ArgumentList '/i','C:\\bp-install\\$p.msi','/qn','/norestart','ENABLEMANAGEMENT=1',"OPAMPENDPOINT=ws://\${Gateway}:$OPAMP_PORT/v1/opamp","OPAMPSECRETKEY=\$Key",'OPAMPLABELS=site=$site_label,segment=$seg,zone=<zone>,os=windows,role=source'
Remove-Variable Key

EOF
}

write_next_steps() {
  local seg site_label fam v vers
  seg=$([[ $SITE == dr ]] && echo dr-live || echo prod-live); site_label=$([[ $SITE == dr ]] && echo dr || echo primary)
  vers=$(mirror_versions)
  {
    cat <<EOF
# =============================================================================
# Hand-off for the ${seg^^} log sources - runbook Stages 8, 9, 11, 13
# Generated by $SCRIPT_NAME on $(hostname -s) at $(date -Is)   (NCINGA internal)
# Gateway for this segment: $LIVE_GW_IP  (repository :$REPO_PORT, OpAMP :$OPAMP_PORT, OTLP :$OTLP_PORT)
# Collector versions in this gateway's mirror: ${vers:-none}
# This gateway runs: $BP_VERSION - $(family_label "$COLLECTOR_FAMILY")
# =============================================================================

EOF
    if [[ -f $REPO_ROOT/scripts/bp-agent-install-linux.sh || -f $REPO_ROOT/windows/bp-agent-install-windows.ps1 ]]; then
      cat <<EOF
# -----------------------------------------------------------------------------
# Recommended: the NCINGA offline agent installers in this gateway's mirror. They list the
# mirrored versions, verify checksum + publisher signature, ask for the secret key and labels,
# install, configure, start and verify - and resume where they stopped if anything fails.
# -----------------------------------------------------------------------------
## Linux log source (RHEL family .rpm, Ubuntu/Debian .deb), as root:
curl -fsSO http://$LIVE_GW_IP:$REPO_PORT/scripts/bp-agent-install-linux.sh && sudo bash bp-agent-install-linux.sh --gateway $LIVE_GW_IP
##   unattended (Ansible): BP_SECRET=... bash bp-agent-install-linux.sh -y --gateway $LIVE_GW_IP --collector-version <tag> \\
##                           --labels "site=$site_label,segment=$seg,zone=<zone>,os=<os>,role=source"

## Windows log source, elevated PowerShell:
Invoke-WebRequest -Uri "http://${LIVE_GW_IP}:$REPO_PORT/windows/bp-agent-install-windows.ps1" -OutFile "\$env:TEMP\\bp-agent-install-windows.ps1" -UseBasicParsing
powershell -ExecutionPolicy Bypass -File "\$env:TEMP\\bp-agent-install-windows.ps1" -Gateway $LIVE_GW_IP
##   unattended (SCCM/GPO): add -Unattended -CollectorVersion <tag> -Labels "..." with the key in the BP_SECRET environment variable

EOF
    fi
    cat <<EOF
# -----------------------------------------------------------------------------
# Manual alternative. Commands are given for the current version of each family; for another
# mirrored version change V (and the MSI name) - every file is in SHA256SUMS.
# -----------------------------------------------------------------------------

EOF
    for fam in "$COLLECTOR_FAMILY" "$(other_family "$COLLECTOR_FAMILY")"; do
      v=""
      [[ $(family_of_version "$BP_VERSION") == "$fam" ]] && v=$BP_VERSION
      [[ -z $v ]] && v=$(sed -n "s/^current_$fam=//p" "$REPO_ROOT/VERSION-INFO" 2>/dev/null)
      [[ -n $v ]] && contains_word "$vers" "$v" || v=$(for t in $vers; do [[ $(family_of_version "$t") == "$fam" ]] && echo "$t"; done | head -n1)
      [[ -n $v ]] && notes_for "$fam" "$v" "$seg" "$site_label"
    done
    cat <<EOF
## Stage 8.8 - Ansible: set  bp_gateway: "$LIVE_GW_IP"; the files are owned by the runtime user of the
##             installed version ('bdot' for v1.108+ and v2), not 'observiq-otel-collector'.

## Stage 11 - this gateway's configuration (${seg}-gateway, labels segment=$seg,role=gateway):
##   source Bindplane Gateway on $LIVE_GW_IP:$OTLP_PORT -> destination Bindplane Gateway $DMZ_GW_IP:$OTLP_PORT, gRPC, compression on.
##   Put volume-reducing processors HERE, not on the DMZ gateway (11.5).

## Stage 13.1 - disable automatic upgrades for every agent labelled segment=$seg: an OpAMP upgrade
##   hands the agent a URL it cannot reach from this segment. Upgrade offline instead:
##   DMZ: $DMZ_TOOL --choose-versions (pick the versions)   then here: $(basename "$0") --upgrade-collector <tag>

## Stage 13.7 - mirror ownership: run $MIRROR_SYNC after every DMZ-side change$( [[ $MIRROR_TIMER == yes ]] && echo " (a daily timer is enabled)" ).
EOF
  } >"$NEXT_STEPS_FILE"
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
  (( outbound > 0 )) && ok "Outbound sessions to the DMZ gateway exist" || warn "No outbound session to the DMZ gateway - destination misconfigured or internal-firewall rule missing (§12.1)"
  {
    echo "# Evidence pack - $(hostname -s) - $(date -Is) - $SCRIPT_NAME v$SCRIPT_VERSION"
    echo "## versions"; haproxy -v 2>&1 | head -n1; nginx -v 2>&1
    echo "collector $(collector_version) - $(family_label "$COLLECTOR_FAMILY")"; rpm -q "$V1_PKG" "$V2_PKG" haproxy nginx 2>&1
    echo "## OS"; os_field PRETTY_NAME; echo; uname -r
    echo "## listeners"; ss -lntp 2>/dev/null | grep -E ":($OPAMP_PORT|$OTLP_PORT|5514|$REPO_PORT|$STATS_PORT) "
    echo "## socket census"; echo "inbound=$inbound outbound=$outbound"; tunnel_census
    echo "## haproxy -c"; haproxy_check "$HAPROXY_CFG" 2>&1
    echo "## dnf source"; cat "$DNF_REPO_FILE" 2>/dev/null
    echo "## mirror"; cat "$REPO_ROOT/VERSION-INFO" 2>/dev/null; tail -n 3 "$MIRROR_LOG" 2>/dev/null
    echo "## step progress"; cat "$STATE_FILE" 2>/dev/null
    echo "## host firewall (firewalld)"; firewall-cmd --state 2>&1; firewall-cmd --get-active-zones 2>&1
    firewalld_active && firewall-cmd --zone="$(fw_zone)" --list-all 2>&1
    echo "## SELinux"; getenforce 2>&1
    if selinux_enabled && command -v semanage >/dev/null; then
      printf 'tcp/%s %s\n' "$OPAMP_PORT" "$(selinux_port_type "$OPAMP_PORT")" "$REPO_PORT" "$(selinux_port_type "$REPO_PORT")" "$STATS_PORT" "$(selinux_port_type "$STATS_PORT")"
      ls -ldZ "$REPO_ROOT" 2>&1
      echo "recent AVC denials (haproxy/nginx):"; selinux_denials
    fi
    echo "## ip_forward"; sysctl net.ipv4.ip_forward 2>&1
  } >"$d/summary.txt" 2>&1
  cp -f "$HAPROXY_CFG" "$d/haproxy.cfg" 2>/dev/null
  cp -f "$NGINX_SITE" "$d/nginx-bindplane-repo.conf" 2>/dev/null
  cp -f "$NGINX_MAIN" "$d/nginx.conf" 2>/dev/null
  cp -f "$DNF_REPO_FILE" "$d/" 2>/dev/null
  [[ -r $MANAGER_YAML ]] && sed -E 's/^(secret_key:).*/\1 ***REDACTED***/' "$MANAGER_YAML" >"$d/manager.yaml.redacted"
  [[ -r $SUP_YAML ]] && sed -E 's/(Secret-Key )[^"]*/\1***REDACTED***/' "$SUP_YAML" >"$d/supervisor.yaml.redacted"
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
  local svc a e st cs first code sums remote local_sums inbound outbound c1 aid p t ctx
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

  section "2. Listeners (bound to $LIVE_GW_IP only - never the internal-firewall-facing interface)"
  ss -H -lntp 2>/dev/null | grep -E ":($OPAMP_PORT|$OTLP_PORT|5514|$REPO_PORT|$STATS_PORT)[[:space:]]" \
    | awk -v ip="${LIVE_GW_IP:-x}" '$4 ~ "^(" ip "|127\\.0\\.0\\.1|0\\.0\\.0\\.0|\\*|\\[::\\]):" {printf "      %-24s %s\n", $4, $6}'
  if [[ -n $LIVE_GW_IP ]]; then
    if verify_listener "$OPAMP_PORT" "$LIVE_GW_IP" haproxy >/dev/null; then c_ok "HAProxy hop 2 bound to $LIVE_GW_IP:$OPAMP_PORT only"; else c_fail "$FAIL_WHAT"; hint "$FAIL_FIX"; fi
    if verify_listener "$REPO_PORT" "$LIVE_GW_IP" nginx >/dev/null; then c_ok "Mirror bound to $LIVE_GW_IP:$REPO_PORT only"; else c_fail "$FAIL_WHAT"; hint "$FAIL_FIX"; fi
  else c_warn "LIVE_GW_IP unknown (no saved configuration) - listener checks skipped"; fi
  ss -H -lnt "sport = :$OTLP_PORT" 2>/dev/null | grep -q . && c_ok "Collector listens on :$OTLP_PORT (Stage 11 configuration arrived)" \
    || say "      :$OTLP_PORT not listening yet - normal until the live-gateway configuration is rolled out (Stage 11)"

  section "3. Configuration files"
  if [[ -f $HAPROXY_CFG ]] && command -v haproxy >/dev/null; then
    detect_haproxy_mode
    (( HAPROXY_COMPAT18 )) && say "      HAProxy $HAPROXY_VER: configuration rendered in 1.8 compatibility mode (RHEL 8)"
    if haproxy_check "$HAPROXY_CFG" >"$RUN_TMP/hc.out" 2>&1; then c_ok "haproxy -c: configuration is valid"
    else first=$(grep -m1 -F '[ALERT]' "$RUN_TMP/hc.out"); c_fail "haproxy -c: ${first:-invalid}"; hint "Only the first alert is real (§3.1)."; fi
    grep -qE '^[[:space:]]*timeout[[:space:]]+tunnel' "$HAPROXY_CFG" && c_ok "timeout tunnel is set" \
      || c_fail "timeout tunnel is missing - agents connect then drop every ~50s (it must be set at BOTH hops)"
    grep -qE 'set-header[[:space:]]+Host' "$HAPROXY_CFG" && c_warn "Hop 2 rewrites the Host header - keep the rewrite at hop 1 only (§6.3)"
    grep -qE '\\[[:space:]]*$' "$HAPROXY_CFG" && c_fail "A line ends in '\\' - HAProxy has no line continuation (§3.1)"
    grep -q 'capture request header Authorization' "$HAPROXY_CFG" && c_warn "Temporary header capture is ON - turn it off before handover: $0 --proxy-debug off"
  else c_warn "$HAPROXY_CFG not present"; fi
  command -v nginx >/dev/null && { nginx -t >"$RUN_TMP/nt.out" 2>&1 && c_ok "nginx -t: configuration is valid" || c_fail "nginx -t: $(grep -m1 -E 'emerg|error' "$RUN_TMP/nt.out")"; }
  if [[ -f $NGINX_MAIN ]] && ! grep -q "Managed by $SCRIPT_NAME" "$NGINX_MAIN" && grep -qE '^[[:space:]]*listen[[:space:]]+(\[::\]:)?80[[:space:];]' "$NGINX_MAIN"; then
    c_warn "$NGINX_MAIN still has the stock server{} on *:80 / [::]:80"; hint "Re-run: $0 --only nginx (replaces it; the original is kept as $NGINX_MAIN.orig)"
  fi

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
      else hint "The same probe to hop 1 fails too ($PROBE_STATUS) -> internal-firewall rule or the DMZ side is down (run $DMZ_TOOL --diagnose there)"; fi
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

  section "8. dnf source"
  if [[ ${PKG_SOURCE:-dmz} == dmz ]]; then
    [[ -f $DNF_REPO_FILE ]] && c_ok "$DNF_REPO_FILE: $(sed -n 's/^baseurl=//p' "$DNF_REPO_FILE") (gpgcheck=$(sed -n 's/^gpgcheck=//p' "$DNF_REPO_FILE"), repo_gpgcheck=$(sed -n 's/^repo_gpgcheck=//p' "$DNF_REPO_FILE"))" || c_warn "$DNF_REPO_FILE missing"
    [[ ${REPO_SIGNED:-no} == yes ]] && { [[ -s $REPO_KEY ]] && c_ok "Repository key $REPO_KEY present" || c_fail "Repository key $REPO_KEY missing"; }
    [[ -n $(enabled_other_repos) ]] && say "      other enabled repositories (unreachable here, never used by this script): $(enabled_other_repos)"
  else say "      package source: this host's own dnf repositories (Satellite / internal mirror)"; fi

  section "9. LIVE collector"
  if [[ -n $(collector_installed_version) ]]; then
    st=$(systemctl is-active "$COLLECTOR_SVC" 2>/dev/null)
    [[ $st == active ]] && c_ok "Collector $(collector_version) active - $(family_label "$COLLECTOR_FAMILY")" || c_fail "Collector ($COLLECTOR_SVC) is $st"
    say "      endpoint: $(yaml_get endpoint)   name: $(yaml_get agent_name)   labels: $(yaml_get labels)"
    aid=$(yaml_get agent_id); [[ -n $aid ]] && c_ok "Agent identity $aid" || c_warn "No agent identity yet"
    c1=$(collector_conn)
    [[ -n $c1 ]] && c_ok "OpAMP session established from $c1 to $DMZ_GW_IP:$OPAMP_PORT" || c_fail "No established OpAMP session to $DMZ_GW_IP:$OPAMP_PORT"
    e=$(collector_log_errors 0 3)
    [[ -n $e ]] && { c_warn "Recent collector log problems ($(basename "$COLLECTOR_LOG")):"; printf '%s\n' "$e" | redact_stream | sed 's/^/         /'; }
    code=$(http_code_in_log "$(( $(wc -l <"$COLLECTOR_LOG" 2>/dev/null || echo 0) - 300 ))")
    [[ $code == 401 || $code == 403 ]] && hint "HTTP $code in the collector log = the secret key in $(basename "$COLLECTOR_CONF") was rejected."
  else c_warn "Collector ($(family_label "$COLLECTOR_FAMILY")) not installed"; fi
  st=$(pkg_version "$(product_of_family "$(other_family "$COLLECTOR_FAMILY")")")
  if [[ -n $st ]]; then
    if systemctl is-active --quiet "$(product_of_family "$(other_family "$COLLECTOR_FAMILY")")"; then c_warn "The $(other_family "$COLLECTOR_FAMILY") collector $st is RUNNING too - two agents for this host"
    else say "      $(other_family "$COLLECTOR_FAMILY") package $st is still installed (stopped) - remove it when no longer needed: rpm -e $(product_of_family "$(other_family "$COLLECTOR_FAMILY")")"; fi
  fi

  section "10. Gateway hygiene"
  check_time
  check_ip_forward
  check_space "$REPO_ROOT" 2 "the mirror"
  check_space "$COLLECTOR_HOME" 5 "the collector queue"
  if firewalld_active; then
    c_ok "firewalld running; rich rules to ${LIVE_GW_IP:-?} in zone $(fw_zone):"
    firewall-cmd --zone="$(fw_zone)" --list-rich-rules 2>/dev/null | grep -F "\"${LIVE_GW_IP:-none}\"" | sed 's/^/        /'
  else say "      firewalld not running"; fi
  if selinux_enabled; then
    if command -v semanage >/dev/null; then
      for p in "$REPO_PORT" "$OPAMP_PORT" "$STATS_PORT"; do
        t=$(selinux_port_type "$p")
        if [[ $t == http_port_t || $t == http_cache_port_t ]]; then c_ok "SELinux: tcp/$p is $t"
        else c_fail "SELinux: tcp/$p is $t - nginx/haproxy may not use it"; hint "$0 --only selinux"; fi
      done
    else c_warn "semanage not installed - SELinux port labels not checked (it comes from policycoreutils-python-utils)"; fi
    ctx=$(stat -c %C "$REPO_ROOT" 2>/dev/null)
    if [[ -z $ctx ]]; then :
    elif [[ $ctx == *:httpd_sys_content_t:* ]]; then c_ok "SELinux: $REPO_ROOT is httpd_sys_content_t"
    else c_fail "SELinux: $REPO_ROOT is labelled $ctx - nginx answers 403"; hint "$0 --only selinux"; fi
    [[ -n $(selinux_denials) ]] && { c_warn "Recent SELinux denials for haproxy/nginx:"; selinux_denials | cut -c1-200 | sed 's/^/        /'; }
  else say "      SELinux disabled"; fi
  systemctl cat haproxy >/dev/null 2>&1 && { [[ $(systemctl show haproxy -p LimitNOFILE --value 2>/dev/null) == 65535 ]] && c_ok "haproxy LimitNOFILE=65535" || c_warn "haproxy LimitNOFILE is not 65535"; }

  section "11. Socket census (§12.1) and recent HAProxy log"
  inbound=$(ss -Htn state established "( sport = :$OPAMP_PORT )" 2>/dev/null | grep -cF "${LIVE_GW_IP:-x}:$OPAMP_PORT")
  outbound=$(ss -Htn state established dst "${DMZ_GW_IP:-0.0.0.0}:$OPAMP_PORT" 2>/dev/null | wc -l)
  say "      inbound sessions from agents: $inbound   outbound sessions to hop 1: $outbound"
  (( inbound > 0 && outbound == 0 )) && c_fail "Inbound sessions but none outbound - the hop 1 destination is misconfigured or the internal-firewall rule is missing (§12.1)"
  journalctl -u haproxy -n 300 --no-pager -o cat 2>/dev/null | grep -E ' opamp_in |\[ALERT\]|hop1_dmz' | tail -n 6 | cut -c1-200 | sed 's/^/      /'

  echo
  if (( CHK_FAILS )); then err "Diagnostics: $CHK_FAILS failure(s), $CHK_WARNS warning(s) - fix the first failure first; most failures are a segment away from where they appear."
  else ok "Diagnostics: no failures, $CHK_WARNS warning(s)"
    hint "Escalate to Bindplane if sessions drop with no event at either proxy or the internal firewall (include both HAProxy configs and collector.log, and say it is a two-hop plain proxy chain)."
  fi
  return 0
}

action_diagnose() {
  init_defaults; load_config || true
  [[ -z $LIVE_GW_IP && -f $HAPROXY_CFG ]] && LIVE_GW_IP=$(sed -nE "s/^[[:space:]]*bind[[:space:]]+([0-9.]+):$OPAMP_PORT.*/\1/p" "$HAPROXY_CFG" | head -n1)
  [[ -z $DMZ_GW_IP && -f $HAPROXY_CFG ]] && DMZ_GW_IP=$(sed -nE "s/^[[:space:]]*server[[:space:]]+dmz[[:space:]]+([0-9.]+):.*/\1/p" "$HAPROXY_CFG" | head -n1)
  set_family
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
    "Collector version" "$BP_VERSION - $(family_label "$(family_of_version "${BP_VERSION:-v1.0.0}")")" \
    "OS package source" "$([[ $PKG_SOURCE == dmz ]] && echo "DMZ repository http://$DMZ_GW_IP:$REPO_PORT/$RPM_REPO_REL/" || echo 'system dnf repositories (Satellite / internal mirror)')" \
    "Metadata signed" "${REPO_SIGNED:-no}$([[ $REPO_SIGNED == yes ]] && echo " (key $REPO_KEY)") - packages: gpgcheck=1 against the vendor key" \
    "Agent name / labels" "$( [[ $(family_of_version "${BP_VERSION:-v1.0.0}") == v2 ]] && echo "$(hostname -s) (v2 uses the host name)" || echo "$AGENT_NAME") / $AGENT_LABELS" \
    "Secret key" "asked when needed (taken from the collector config if present); not saved by this script" \
    "Host-firewall sources/ports" "${FW_SOURCES:-?} -> tcp ${FW_PORTS:-?} $(firewalld_active && echo '(firewalld running)' || echo '(firewalld not running: not applied)')" \
    "HAProxy maxconn" "$HAPROXY_MAXCONN" \
    "Daily mirror sync timer" "${MIRROR_TIMER:-no}" \
    "Pause between steps" "${PAUSE_BETWEEN_STEPS:-no}"
}

action_status() {
  init_defaults
  if load_config; then set_family; banner_line "Saved configuration ($CONF_FILE)"; show_config; else warn "No saved configuration yet"; fi
  local a b; a=$(pkg_version "$V1_PKG"); b=$(pkg_version "$V2_PKG")
  say "  Installed here: $V1_PKG ${a:-not installed}   $V2_PKG ${b:-not installed}"
  say "  In the mirror : $(mirror_versions)"
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
  local newv=${ACTION_ARG:-} old msg aid0 aid1 inst i oldfam
  init_defaults; load_config || { err "No saved configuration - run the full build first."; exit 1; }
  set_family; oldfam=$COLLECTOR_FAMILY
  inst=$(collector_installed_version)
  banner_line "Offline collector upgrade on the LIVE gateway (runbook §13.2 / §13.3)"
  say "  Order: DMZ gateways first, then LIVE gateways, then log sources in batches (§13.2)."
  ADHOC=1; FORCE_ALL=1
  run_steps mirror
  ADHOC=0
  if [[ -z $newv ]]; then
    newv=$(for t in $(mirror_versions); do [[ $(family_of_version "$t") == "$oldfam" ]] && echo "$t"; done | grep -v -- - | sort_tags | tail -n1)
    [[ -z $newv ]] && newv=$(for t in $(mirror_versions); do [[ $(family_of_version "$t") == "$oldfam" ]] && echo "$t"; done | sort_tags | tail -n1)
    info "Newest $oldfam version in the mirror: ${newv:-none}"
  fi
  [[ -n $newv ]] || { err "No $oldfam collector version is in the mirror (mirrored: $(mirror_versions))."; exit 1; }
  [[ $newv == v* ]] || newv="v$newv"
  msg=$(v_version "$newv") || { err "$msg"; exit 2; }
  [[ -f $REPO_ROOT/$(pkg_rel "$newv") ]] || { err "$newv is not in the mirror (mirrored: $(mirror_versions)). Stage it on the DMZ host first: $DMZ_TOOL --choose-versions, then: sudo bp-mirror-sync"; exit 1; }
  [[ $newv == "$inst" ]] && { ok "Collector $inst is already installed - nothing to do"; return 0; }
  if [[ $(family_of_version "$newv") != "$oldfam" ]]; then
    warn "$newv is $(family_label "$(family_of_version "$newv")"); this host runs $(family_label "$oldfam") ${inst:-<none>}."
    say  "  This is a migration, not an upgrade: the new collector gets its own config and agent identity, and the"
    say  "  script asks what to do with the current one (stop, remove or keep)."
    if (( ASSUME_YES )) && [[ -n $OTHER_ACTION ]]; then info "Switching unattended (--other-collector $OTHER_ACTION given)"
    else ask_yn "Switch this gateway to $newv?" n || { info "Nothing changed (unattended runs need --other-collector stop|remove|keep to switch)"; return 0; }; fi
  else
    ask_yn "Upgrade the collector ${inst:-<none>} -> $newv now?" y || { info "Nothing changed"; return 0; }
  fi
  aid0=$(yaml_get agent_id); old=$BP_VERSION
  BP_VERSION=$newv; set_family; REPLACE_CONFIRMED=1
  FORCE_ALL=1; ADHOC=1
  if [[ $COLLECTOR_FAMILY != "$oldfam" ]]; then
    run_steps collector_install collector_config collector_verify
  else
    run_steps collector_install
  fi
  ADHOC=0
  sleep 5
  [[ $(collector_version) == "$newv" ]] && ok "Collector now reports $newv" || warn "Collector reports '$(collector_version)' (expected $newv)"
  systemctl is-active --quiet "$COLLECTOR_SVC" && ok "Collector is running" || err "Collector is not running after the change - escalate to Bindplane if an upgrade leaves it stopped (§13.3)"
  aid1=$(yaml_get agent_id)
  if [[ $COLLECTOR_FAMILY == "$oldfam" ]]; then
    if [[ $aid0 == "$aid1" ]]; then ok "Agent identity unchanged ($aid1) - the console still sees the same agent"
    else err "Agent identity CHANGED ($aid0 -> $aid1): the host re-registered as a new agent - escalate to Bindplane (§13.3)"; fi
  else info "Agent identity now ${aid1:-?} ($(family_label "$COLLECTOR_FAMILY")). The $oldfam agent shows as disconnected in the console - delete it there if it is not coming back."; fi
  for i in $(seq 1 60); do [[ -n $(collector_conn) ]] && break; sleep 1; done
  [[ -n $(collector_conn) ]] && ok "OpAMP session to hop 1 re-established" || warn "No OpAMP session after 60s - check: $0 --diagnose"
  save_config
  [[ $COLLECTOR_FAMILY == "$oldfam" ]] && hint "Rollback (§13.4): rpm -U --oldpackage $REPO_ROOT/$(pkg_rel "${inst:-$old}")   (keep the previous version in the mirror)"
  write_next_steps
}

action_rollback() {
  local src port dst zone others kind key mode old reload=0
  init_defaults; load_config || true
  banner_line "Rollback - back out the changes made by this script"
  say "  This will:"
  say "    - restore $HAPROXY_CFG from $HAPROXY_CFG.orig, then stop and disable haproxy"
  say "    - remove $NGINX_SITE, restore $NGINX_MAIN from .orig (stop nginx if nothing else is configured)"
  say "    - remove $HAPROXY_DROPIN, the firewalld rich rules and SELinux labels this script added, the bp-mirror-sync timer"
  say "    - clear step progress (your answers are kept)"
  say "  You will be asked separately about the collector, the dnf repository file and the mirror content."
  ask_yn "Proceed with the rollback?" n || { info "Nothing changed"; return 0; }
  if [[ -f $HAPROXY_CFG.orig ]]; then cp -p "$HAPROXY_CFG" "$HAPROXY_CFG.rolledback-$RUN_TS" 2>/dev/null; cp -p "$HAPROXY_CFG.orig" "$HAPROXY_CFG"; selinux_restore "$HAPROXY_CFG"; ok "haproxy.cfg restored (previous copy: $HAPROXY_CFG.rolledback-$RUN_TS)"; fi
  systemctl cat haproxy >/dev/null 2>&1 && systemctl disable --now haproxy >/dev/null 2>&1 && ok "haproxy stopped and disabled"
  rm -f "$HAPROXY_DROPIN"; rmdir "$HAPROXY_DROPIN_DIR" 2>/dev/null; systemctl daemon-reload 2>/dev/null; ok "LimitNOFILE drop-in removed"
  if [[ -e $NGINX_SITE ]]; then rm -f "$NGINX_SITE"; ok "nginx configuration bindplane-repo removed"; fi
  if [[ -f $NGINX_MAIN.orig ]] && grep -qs "Managed by $SCRIPT_NAME" "$NGINX_MAIN"; then
    cp -p "$NGINX_MAIN.orig" "$NGINX_MAIN"; selinux_restore "$NGINX_MAIN"; ok "nginx.conf restored from $NGINX_MAIN.orig"
  fi
  if systemctl cat nginx >/dev/null 2>&1; then
    others=$(grep -lE '^[[:space:]]*listen[[:space:]]' /etc/nginx/conf.d/*.conf 2>/dev/null | head -n1)
    if [[ -z $others ]]; then systemctl disable --now nginx >/dev/null 2>&1 && ok "nginx stopped and disabled (no other server configured in conf.d)"
    else systemctl reload nginx >/dev/null 2>&1 && ok "nginx reloaded (other servers remain: $others)"; fi
  fi
  if [[ -s $FW_RECORD ]] && firewalld_active; then
    while read -r src port dst zone; do
      [[ -n $src ]] || continue; dst=${dst:-$LIVE_GW_IP}; zone=${zone:-$(fw_zone)}
      if firewall-cmd --permanent --zone="$zone" --remove-rich-rule="$(fw_rule "$src" "$dst" "$port")" >/dev/null 2>&1; then
        ok "firewalld rule removed: $src -> $dst tcp/$port (zone $zone)"; reload=1
      else warn "Could not remove firewalld rule $src -> $dst tcp/$port (check: firewall-cmd --zone=$zone --list-rich-rules)"; fi
    done <"$FW_RECORD"
    (( reload )) && { firewall-cmd --reload >/dev/null 2>&1 && ok "firewalld reloaded" || warn "firewall-cmd --reload failed"; }
    rm -f "$FW_RECORD"
  elif [[ -s $FW_RECORD ]]; then
    warn "firewalld is not running - rich rules listed in $FW_RECORD were not removed (start firewalld and re-run --rollback)"
  fi
  if [[ -s $SELINUX_RECORD ]] && command -v semanage >/dev/null; then
    while IFS='|' read -r kind key mode old; do
      case $kind in
        port)     semanage port -d -p tcp "$key" >/dev/null 2>&1 && ok "SELinux: tcp/$key label removed (back to ${old:-policy default})" \
                    || warn "SELinux: could not remove the tcp/$key label (semanage port -l -C)" ;;
        fcontext) if [[ $mode == modified && -n $old ]]; then
                    semanage fcontext -m -t "$old" "$key" >/dev/null 2>&1 && ok "SELinux: file-context rule $key set back to $old" \
                      || warn "SELinux: could not restore the rule $key to $old (semanage fcontext -l -C)"
                  else
                    semanage fcontext -d "$key" >/dev/null 2>&1 && ok "SELinux: file-context rule $key removed" \
                      || warn "SELinux: could not remove the rule $key (semanage fcontext -l -C)"
                  fi
                  [[ -d $REPO_ROOT ]] && restorecon -R "$REPO_ROOT" 2>/dev/null ;;
      esac
    done <"$SELINUX_RECORD"
    rm -f "$SELINUX_RECORD"
  fi
  if [[ -f $SYNC_TIMER || -f $MIRROR_SYNC ]]; then
    systemctl disable --now bp-mirror-sync.timer >/dev/null 2>&1; rm -f "$SYNC_TIMER" "$SYNC_SERVICE" "$MIRROR_SYNC"; systemctl daemon-reload 2>/dev/null
    ok "bp-mirror-sync and its timer removed"
  fi
  set_family
  if [[ -n $(collector_installed_version) ]] && ask_yn "Also STOP and REMOVE the collector package $COLLECTOR_PKG (a copy of $(basename "$COLLECTOR_CONF") is kept)?" n; then
    [[ -f $COLLECTOR_CONF ]] && { cp -p "$COLLECTOR_CONF" "$STATE_DIR/$(basename "$COLLECTOR_CONF").rolledback-$RUN_TS"; chmod 600 "$STATE_DIR/$(basename "$COLLECTOR_CONF").rolledback-$RUN_TS"; }
    systemctl disable --now "$COLLECTOR_SVC" >/dev/null 2>&1
    run "Removing $COLLECTOR_PKG" rpm -e "$COLLECTOR_PKG" && ok "Collector removed (config copy: $STATE_DIR/$(basename "$COLLECTOR_CONF").rolledback-$RUN_TS)"
  fi
  if [[ -f $DNF_REPO_FILE ]] && ask_yn "Also remove the dnf repository file $DNF_REPO_FILE?" n; then rm -f "$DNF_REPO_FILE"; ok "dnf repository file removed"; fi
  if [[ -d $REPO_ROOT/packages ]] && ask_yn "Also DELETE the mirror content in $REPO_ROOT?" n; then
    rm -rf --one-file-system "${REPO_ROOT:?}"/{packages,scripts,windows,apt,rpm} "$REPO_ROOT"/{SHA256SUMS,VERSION-INFO,README.txt}; ok "Mirror content deleted"
  fi
  rm -f "$STATE_FILE"; ok "Step progress cleared"
  hint "nginx/haproxy packages are left installed. To remove them: dnf --disablerepo='*' remove haproxy nginx"
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
    [[ $ifc == "$dmzdev" ]] && note="<- route to the DMZ gateway (internal-firewall-facing)"
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
      warn "  $sel is on the interface that faces the internal firewall/DMZ ($dmzdev). §6.2: bind to the LIVE-facing interface only."
      ask_yn "Use $sel anyway?" n || continue
    fi
    LIVE_GW_IP=$sel; return 0
  done
}

gather_config() {
  local st def_labels def_name seg site_label
  banner_line "Configuration"
  say "  Press Enter to accept the value in [brackets]."
  ask SITE "Site of this LIVE gateway (primary/dr)" "${SITE:-primary}" v_site || return 1
  ask DMZ_GW_IP "DMZ gateway address ($([[ $SITE == dr ]] && echo bp-gw-drdmz-01 || echo bp-gw-dmz-01): the address its repository and relay listen on)" "$DMZ_GW_IP" v_remote_ip || return 1
  st=$(tcp_state "$DMZ_GW_IP" "$REPO_PORT")
  if [[ $st == open ]]; then
    fetch_dmz_info
    ok "  DMZ repository reachable: default collector $(info_field current_collector_version || true), dnf repository: $(info_field rpm_repo_built_for | cut -d' ' -f1) (this host: $(local_release)), metadata signed: $(info_field rpm_repo_signed)"
  else
    warn "  DMZ repository $DMZ_GW_IP:$REPO_PORT is $st right now - continuing; the dmz_path step will check again"
  fi
  choose_live_ip || return 1
  pick_collector_version || return 1
  if [[ -z $PKG_SOURCE ]]; then
    if [[ -z $DMZ_INFO || $(info_field rpm_repo_built_for) == "$(local_release)"* ]]; then PKG_SOURCE=dmz; else PKG_SOURCE=system; fi
  fi
  say "  Where should nginx/HAProxy/wget come from? 'dmz' = the DMZ repository (§5.2); 'system' = this host's own dnf"
  say "  repositories, e.g. the customer's Satellite / internal RHEL mirror reachable from the LIVE segment (runbook 'Preferred alternative')."
  ask PKG_SOURCE "OS package source (dmz/system)" "$PKG_SOURCE" v_pkg_source || return 1
  if [[ $PKG_SOURCE == dmz ]]; then
    [[ -z $REPO_SIGNED && $(info_field rpm_repo_signed) == yes ]] && REPO_SIGNED=yes
    ask_yn_var REPO_SIGNED "Is the DMZ repository's metadata GPG-signed (repomd.xml.asc, §5.4)?" no
    if [[ $REPO_SIGNED == yes ]]; then
      ask REPO_KEY "Path of the repository's public key on this host (distributed via config management)" "${REPO_KEY:-$REPO_KEY_DEFAULT}" v_repo_key || return 1
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
  if [[ $COLLECTOR_FAMILY == v2 ]]; then
    AGENT_NAME=$(hostname -s); info "  v2 agents are listed in the console by host name: $AGENT_NAME"
  else
    ask AGENT_NAME "Agent name shown in the console" "$def_name" v_agent_name || return 1
  fi
  def_labels=${AGENT_LABELS:-"site=$site_label,segment=$seg,role=gateway"}
  [[ -n $AGENT_LABELS && $AGENT_LABELS != *"segment=$seg"* ]] && def_labels="site=$site_label,segment=$seg,role=gateway"
  ask AGENT_LABELS "Agent labels (§8.5 scheme - configurations are assigned by these)" "$def_labels" v_labels || return 1
  if firewalld_active; then
    say "  firewalld is running here: rich rules will allow only these sources to reach $LIVE_GW_IP."
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
  [[ $REPO_SIGNED != yes || -n $REPO_KEY ]]
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
  [DMZ_GW_IP]="preflight dmz_path dnf_source mirror haproxy_config haproxy_start probe_chain collector_config collector_verify evidence"
  [BP_VERSION]="dmz_path collector_install collector_config collector_verify evidence"
  [PKG_SOURCE]="dmz_path dnf_source os_packages" [REPO_SIGNED]="dnf_source os_packages" [REPO_KEY]="dnf_source os_packages"
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
  say "  This collector  : $( [[ $COLLECTOR_FAMILY == v2 ]] && hostname -s || echo "$AGENT_NAME") - $COLLECTOR_PKG $(collector_version)  ->  ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp"
  say "  Collector config: $COLLECTOR_CONF   log: $COLLECTOR_LOG"
  say "  HAProxy stats   : curl -s '$STATS_URL'   (loopback only)"
  say "  Hand-off notes  : $NEXT_STEPS_FILE"
  say "  This run's log  : $LOG_FILE"
  say "  Health check    : $0 --diagnose"
}

action_build() {
  local had=0 list=() s found=0
  init_defaults
  load_config && had=1
  set_family
  snapshot_config
  if (( ! had || RECONFIGURE )) || ! config_complete; then
    (( had )) && (( ! RECONFIGURE )) && info "Some answers are missing - asking for them now."
    gather_config || { err "Configuration was not completed - nothing changed."; exit 1; }
    confirm_config || { info "Stopped before making changes."; exit 0; }
    save_config; ok "Answers saved to $CONF_FILE (root-only, mode 0600; the secret key is not stored there)"
    set_family
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
$SCRIPT_NAME v$SCRIPT_VERSION - NCINGA internal: Bindplane LIVE gateway build (runbook Stages 5-6) for RHEL 8 / RHEL 9

Usage: sudo bash $0 [options]

Build (default): asks for the values it needs, then runs every pending step.
Re-running resumes at the first unfinished step; completed steps are skipped.
  --reconfigure          ask all questions again (previous answers are the defaults)
  --from STEP            re-run STEP and every step after it
  --only STEP            re-run just STEP (e.g. --only probe_chain)
  --pause                pause for confirmation between steps
  -y, --yes              accept saved/default answers; quit on the first failure
                         (set BP_SECRET in the environment if no collector config exists yet)
  --other-collector stop|remove|keep
                         what to do with an installed collector of the other family (v1/v2) when
                         running unattended; interactive runs ask

Operations:
  --status               saved answers, step progress and gate status
  --list-steps           list step names
  --diagnose             read-only health check (troubleshooting flowchart, socket census §12.1)
  --sync-mirror          pull new/changed files from the DMZ repository and verify them
  --upgrade-collector [VER]  offline upgrade from the mirror (§13.3; default: newest mirrored of the same
                         family). A version of the other family switches the gateway (asks first).
  --proxy-debug on|off   temporary HAProxy header capture (remove before handover)
  --rollback             back out this script's changes (asks about collector, dnf repository file, mirror)
  --reset                forget step progress (answers are kept)
  --no-color             plain output
  -h, --help             this help

Files: answers $CONF_FILE (0600) | progress $STATE_FILE | logs $LOG_DIR
Steps: ${STEPS[*]}
Collectors: v1 observiq-otel-collector (manager.yaml), v2 bindplane-otel-collector (supervisor.yaml) - pick
any version staged on the DMZ repository; versions are added there with $DMZ_TOOL --choose-versions.
OS packages: dnf, ONLY from $DNF_REPO_FILE -> http://<DMZ>:$REPO_PORT/$RPM_REPO_REL/ (this host: $(local_release)).

(c) 2026 NCINGA. All rights reserved. NCINGA internal - proprietary and confidential; see the header.
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
      --other-collector) need=1; OTHER_ACTION=${2:-} ;;
      --other-collector=*) OTHER_ACTION=${1#*=} ;;
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
  [[ -z $OTHER_ACTION || $OTHER_ACTION =~ ^(stop|remove|keep)$ ]] || { echo "--other-collector takes stop, remove or keep" >&2; exit 2; }
}

on_signal() {
  local sig=$1
  trap '' INT TERM HUP
  [[ -n $TTY ]] && stty echo <"$TTY" 2>/dev/null
  echo
  warn "Received SIG$sig - stopping safely."
  [[ -n $CURRENT_STEP ]] && state_set "$CURRENT_STEP" interrupted
  info "Progress is saved. Re-run the script to resume${CURRENT_STEP:+ at: ${STEP_TITLE[$CURRENT_STEP]}}."
  [[ -n $LOG_FILE ]] && info "Log: $LOG_FILE"
  exit 130
}

on_exit() {
  [[ -n $RUN_TMP && -d $RUN_TMP ]] && rm -rf "$RUN_TMP"
}

main() {
  local c miss=""
  parse_args "$@"
  setup_colors
  [[ $ACTION == help ]] && { print_brand "$SCRIPT_NAME v$SCRIPT_VERSION - LIVE gateway build"; usage; exit 0; }
  (( EUID == 0 )) || { echo "This script must run as root:  sudo bash $0 $*" >&2; exit 1; }
  for c in systemctl journalctl ss ip awk sed grep flock sha256sum stat df mktemp timeout curl rpm dnf; do command -v "$c" >/dev/null || miss+=" $c"; done
  if [[ -n $miss ]]; then
    echo "Missing required commands:$miss (is this RHEL 8/9?)" >&2
    [[ $miss == *curl* ]] && echo "curl ships with RHEL; install it from the DMZ repository: dnf --disablerepo='*' --repofrompath=dmz,http://<DMZ>:$REPO_PORT/$RPM_REPO_REL/ install curl" >&2
    exit 1
  fi
  case $(os_field ID) in
    ubuntu|debian) echo "This is the RHEL edition; on $(os_field PRETTY_NAME) use bp-live-setup.sh." >&2; exit 1 ;;
  esac

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

  print_brand "$SCRIPT_NAME v$SCRIPT_VERSION - LIVE gateway build (runbook Stages 5-6)"
  set_family
  say "  Host: $(hostname -s)   Action: $ACTION   Collector here: $(case $(installed_family) in none) echo none ;; both) echo "v1 $(pkg_version "$V1_PKG") + v2 $(pkg_version "$V2_PKG")" ;; *) echo "$(family_label "$COLLECTOR_FAMILY") $(collector_version)" ;; esac)   Log: $LOG_FILE"
  log "args: $* (tty output: $TTY_OUT)"
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

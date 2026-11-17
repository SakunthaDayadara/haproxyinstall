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
#  bp-dmz-setup-rhel.sh  -  DMZ gateway build (RHEL 8 / RHEL 9)
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
#  The DMZ-side stages of the NCINGA Bindplane air-gapped deployment runbook
#  (the § numbers in messages refer to it), on the DMZ gateway - for example
#  bp-gw-dmz-01, or bp-gw-drdmz-01 at the DR site:
#
#    Pre-flight ........ host baseline + Stage 1 gate checks (§1.3 / §1.4)
#    Stage 2 ........... offline package origin for the isolated segments:
#                        collector artefacts for several v1 AND v2 releases
#                        (picked from the GitHub release list), local dnf
#                        repository (createrepo_c), checksums, SELinux labels,
#                        nginx bound to DMZ_GW_IP:8080
#    Stage 3 ........... HAProxy OpAMP relay hop 1 on DMZ_GW_IP:3001
#    Stage 4 ........... validation: synthetic probe (§4.1-4.3) and the
#                        definitive "real collector through the hop" test (§4.4)
#
#  Collector families - staged side by side, the file names differ:
#    v1  observiq-otel-collector_<tag>_linux_<arch>.rpm|deb    config manager.yaml
#    v2  bindplane-otel-collector_<tag>_linux_<arch>.rpm|deb   OpAMP supervisor, supervisor.yaml
#    https://github.com/observIQ/bindplane-otel-collector/releases/download/<tag>/<file>
#  On RHEL the x86_64 .rpm is the required artefact; the .deb is optional (Ubuntu log sources).
#
#  RHEL edition - what differs from the Ubuntu script (same steps, state files and repo layout):
#    * packages ........ dnf / rpm. RHEL never starts or enables a service on install, so
#                        the Ubuntu policy-rc.d guard is not needed.
#    * OS repository ... rpm/el<major>-<arch>/ built with 'dnf download --resolve --alldeps'
#                        and createrepo_c. Packages keep the vendor's signatures (gpgcheck=1
#                        on the isolated hosts); repomd.xml can additionally be GPG-signed.
#    * SELinux ......... new 'selinux' step: labels the repository httpd_sys_content_t and
#                        tcp/3001 + tcp/8404 http_port_t (3001 is ntop_port_t by default, so
#                        haproxy may not bind it). SELinux is labelled, never disabled.
#    * host firewall ... firewalld rich rules (source -> DMZ_GW_IP:port) instead of ufw.
#    * nginx ........... /etc/nginx/conf.d/bindplane-repo.conf. The stock nginx.conf has its
#                        own server{} on *:80 and [::]:80, so it is replaced by a minimal
#                        main config (original kept as nginx.conf.orig).
#    * HAProxy ......... RHEL 9 ships 2.4 (full config). RHEL 8 ships 1.8, which lacks
#                        'log stdout', 'parse-resolv-conf' and server-side ALPN: the config is
#                        rendered in 1.8 compatibility mode (log /dev/log, nameservers from
#                        /etc/resolv.conf, no ALPN - the cloud then answers HTTP/1.1).
#    * CA bundle ....... /etc/pki/tls/certs/ca-bundle.crt (update-ca-trust).
#    Rebuilds of the same major release (Rocky, AlmaLinux, Oracle Linux) are accepted with
#    a note; RHEL itself is the reference platform.
#
#  Stage 1 (this host's own collector, v1 or v2) must already be installed and
#  Connected; this script only verifies it.
#
#  Design goals
#    * interactive: asks for every value it needs, offers detected defaults
#    * resumable:   progress is saved after every step; re-running resumes at
#                   the first unfinished step. Ctrl+C / SSH drop is safe.
#    * explainable: every failure prints what happened, the likely cause and
#                   how to fix it, and offers retry / diagnostics / skip / quit
#    * idempotent:  every step can be re-run safely
#
#  Usage:  sudo bash bp-dmz-setup-rhel.sh            (then follow the prompts)
#          sudo bash bp-dmz-setup-rhel.sh --help     (all options)
# =============================================================================

SCRIPT_VERSION="2.1.0-rhel"
SCRIPT_NAME="bp-dmz-setup"     # unchanged: same state directory, lock and "Managed by" markers

set -uo pipefail
umask 022
export LC_ALL=C

# ----------------------------------------------------------------------------
# Fixed paths and ports (runbook values). Paths can be overridden via env.
# ----------------------------------------------------------------------------
STATE_DIR=${BP_STATE_DIR:-/var/lib/bp-dmz-setup}
LOG_DIR=${BP_LOG_DIR:-/var/log/bp-dmz-setup}
REPO_ROOT=${BP_REPO_ROOT:-/srv/bindplane}
CONF_FILE="$STATE_DIR/setup.conf"
STATE_FILE="$STATE_DIR/progress"
MANIFEST="$STATE_DIR/artefacts.manifest"
FW_RECORD="$STATE_DIR/firewalld-rules.added"   # "source port destination zone" per rich rule added
SELINUX_RECORD="$STATE_DIR/selinux-changes.added"   # labels this script added (for --rollback)
HOP_MARKER="$STATE_DIR/hop-test.in-progress"
GNUPG_DIR="$STATE_DIR/gnupg"
LOCK_FILE="/run/$SCRIPT_NAME.lock"
EVIDENCE_DIR="$LOG_DIR/evidence"
NEXT_STEPS_FILE="$LOG_DIR/NEXT-STEPS-LIVE-GATEWAY.txt"

# Collector families. use_family() points the COLLECTOR_* variables at one of them;
# main() picks the family installed on this host (v1 when neither or both are).
V1_PKG="observiq-otel-collector";  V1_HOME=${BP_COLLECTOR_HOME:-/opt/observiq-otel-collector}
V2_PKG="bindplane-otel-collector"; V2_HOME=${BP_V2_HOME:-/opt/bindplane-otel-collector}
MANAGER_YAML="$V1_HOME/manager.yaml"
SUP_YAML="$V2_HOME/supervisor.yaml"
COLLECTOR_FAMILY=v1; COLLECTOR_PKG=$V1_PKG; COLLECTOR_SVC=$V1_PKG; COLLECTOR_HOME=$V1_HOME
COLLECTOR_CONF=$MANAGER_YAML; COLLECTOR_LOG="$V1_HOME/log/collector.log"
COLLECTOR_BIN="$V1_HOME/observiq-otel-collector"; COLLECTOR_PROC="observiq"
# warnings the collectors print on every start - not problems
BENIGN_LOG_RE='Capabilities is deprecated|Using legacy service\.telemetry\.resource'

# Releases known when this script was written. Used only when GitHub's release listing
# (API, feed and page) is blocked; newer releases are then found by probing the download URLs.
KNOWN_RELEASES="v1.109.0 v1.108.1 v1.108.0 v1.107.0 v1.106.0 v1.105.1 v1.104.0 v1.103.0 v1.102.1 v2.0.1-beta.6 v2.0.1-beta.5"

HAPROXY_CFG="/etc/haproxy/haproxy.cfg"
HAPROXY_DROPIN_DIR="/etc/systemd/system/haproxy.service.d"
HAPROXY_DROPIN="$HAPROXY_DROPIN_DIR/limits.conf"
HAPROXY_CFGDIR="/etc/haproxy/conf.d"           # RHEL 9's unit also loads *.cfg from here
NGINX_MAIN="/etc/nginx/nginx.conf"              # RHEL: the stock file carries a server{} on *:80
NGINX_SITE="/etc/nginx/conf.d/bindplane-repo.conf"
NGINX_ACCESS_LOG="/var/log/nginx/bindplane-repo.access.log"
NGINX_ERROR_LOG="/var/log/nginx/bindplane-repo.error.log"

CA_BASE="/etc/pki/tls/certs"                   # RHEL row of the §3.3 table
CA_FILE="/etc/pki/tls/certs/ca-bundle.crt"     # -> /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem

# Platform facts. The local dnf repository is only valid for this major release and architecture.
OS_MAJOR=$( (. /etc/os-release 2>/dev/null; v=${VERSION_ID:-0}; printf '%s' "${v%%.*}") )
RPM_ARCH=$(uname -m)
RPM_REPO_REL="rpm/el${OS_MAJOR}-${RPM_ARCH}"
RPM_REPO_DIR="$REPO_ROOT/$RPM_REPO_REL"
RPM_REPO_KEY="$STATE_DIR/RPM-GPG-KEY-bindplane-repo"
# OS packages staged for the isolated hosts besides any extras: the LIVE gateway runs the same
# proxy software and needs semanage to label its own ports (SELinux).
RPM_REPO_PKGS="nginx haproxy wget policycoreutils-python-utils"
HAPROXY_COMPAT18=0                              # set by detect_haproxy_mode (RHEL 8 ships HAProxy 1.8)

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
STEPS=(preflight base_packages repo_layout selinux collector_artefacts os_repo checksums
       nginx haproxy_install haproxy_config haproxy_limits host_firewall
       haproxy_start probe_hop1 collector_via_hop1 evidence)
declare -A STEP_TITLE=(
  [preflight]="Pre-flight checks and Stage 1 baseline"
  [base_packages]="Base packages (dnf)"
  [repo_layout]="Repository layout under $REPO_ROOT"
  [selinux]="SELinux labels (repository content, service ports)"
  [collector_artefacts]="Download collector artefacts (RPM/DEB/ARM/Windows)"
  [os_repo]="Local dnf repository (nginx, haproxy, wget + deps)"
  [checksums]="Repository checksums (SHA256SUMS)"
  [nginx]="Serve the repository with nginx on :$REPO_PORT"
  [haproxy_install]="Install HAProxy"
  [haproxy_config]="HAProxy hop 1 configuration"
  [haproxy_limits]="HAProxy file-descriptor limits"
  [host_firewall]="Host firewall (firewalld)"
  [haproxy_start]="Start HAProxy and check the cloud backend"
  [probe_hop1]="Validate hop 1: synthetic OpAMP probe"
  [collector_via_hop1]="Validate hop 1: real collector through the hop"
  [evidence]="Evidence pack and LIVE-gateway hand-off notes"
)
declare -A STEP_REF=(
  [preflight]="Pre-flight, §1.3, §1.4"   [base_packages]="§1.1, §2.3"
  [repo_layout]="§2.1"                   [selinux]="RHEL: SELinux, §2.5, §3.7"
  [collector_artefacts]="§2.2"
  [os_repo]="§2.3, §5.4"                 [checksums]="§2.4"
  [nginx]="§2.5, §2.7"                   [haproxy_install]="§3.2"
  [haproxy_config]="§3.1, §3.3, §3.4"    [haproxy_limits]="§3.5"
  [host_firewall]="§3.6"                  [haproxy_start]="§3.7"
  [probe_hop1]="§4.1, §4.2, §4.3"        [collector_via_hop1]="§4.4"
  [evidence]="§12.4"
)

# Saved answers (persisted in $CONF_FILE) -----------------------------------------
CONF_KEYS=(SITE BP_CLOUD_HOST BP_SECRET BP_VERSION STAGE_VERSIONS DMZ_GW_IP LIVE_GW_IP
           FW_SOURCES FW_PORTS HAPROXY_MAXCONN STAGE_DEB STAGE_ARM64
           STAGE_WINDOWS BUILD_RPM_REPO EXTRA_RPM_PKGS SIGN_RPM_REPO DL_PROXY
           PAUSE_BETWEEN_STEPS PROXY_DEBUG)

init_defaults() {
  SITE="" BP_CLOUD_HOST="" BP_SECRET="" BP_VERSION="" STAGE_VERSIONS="" DMZ_GW_IP="" LIVE_GW_IP=""
  FW_SOURCES="" FW_PORTS="" HAPROXY_MAXCONN="" STAGE_DEB="" STAGE_ARM64=""
  STAGE_WINDOWS="" BUILD_RPM_REPO="" EXTRA_RPM_PKGS="" SIGN_RPM_REPO=""
  DL_PROXY="" PAUSE_BETWEEN_STEPS="" PROXY_DEBUG="no"
}

# Runtime globals -------------------------------------------------------------------
ACTION="build"; ACTION_ARG=""; FROM_STEP=""; ONLY_STEP=""
ASSUME_YES=0; RECONFIGURE=0; FORCE_PAUSE=0; USE_COLOR=1; FORCE_ALL=0
CURRENT_STEP=""; HOP_TEST_ACTIVE=0; DL_PID=""
FAIL_WHAT=""; FAIL_WHY=""; FAIL_FIX=""; LAST_OUT=""
RUN_TS=$(date +%Y%m%d-%H%M%S)
LAUNCH_DIR=$PWD; SCRIPT_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
LOG_FILE=""; RUN_TMP=""; TTY=""; TTY_OUT=0
DET_CLOUD_HOST=""; DET_SECRET=""; DET_VERSION=""; DET_PROXY=""
UPSTREAM_SUMS=""; REL_ASSETS=""; REL_ASSETS_KNOWN=0
CURL_PROXY_OPTS=(); DNF_PROXY_OPTS=()
ARG_VERSIONS=""; ARG_DEFAULT=""; STAGE_MIGRATED=0
CATALOGUE=""; CATALOGUE_SOURCE=""; MENU_TAGS=()

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
v_pkgs()   { [[ -z $1 || $1 =~ ^[A-Za-z0-9][A-Za-z0-9_+.-]*([[:space:]]+[A-Za-z0-9][A-Za-z0-9_+.-]*)*$ ]] || { echo "Space-separated RHEL package names only (e.g. tcpdump bind-utils)."; return 1; }; }
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
  CURL_PROXY_OPTS=(); DNF_PROXY_OPTS=()
  if [[ -n ${DL_PROXY:-} ]]; then
    CURL_PROXY_OPTS=(--proxy "$DL_PROXY")
    DNF_PROXY_OPTS=("--setopt=proxy=$DL_PROXY")
  fi
}

# dnf wrapper with proxy and failure explanation. dnf waits for another dnf/rpm process's lock
# by itself. Package scriptlets never start services on RHEL, so no policy-rc.d guard is needed.
dnf_run() {
  local desc=$1; shift
  run_stream "$desc" dnf -y --color=never "${DNF_PROXY_OPTS[@]}" "$@" && return 0
  explain_dnf_failure "$LAST_OUT"
  return 1
}

explain_dnf_failure() {
  local f=$1
  if grep -qE 'not registered (with an entitlement server|to Red Hat Subscription Management)|no enabled repositor(y|ies)|There are no enabled repos' "$f"; then
    fail "dnf has no usable repository." \
         "This RHEL host is not registered with Red Hat Subscription Management (or Satellite), or every repository is disabled." \
         "Register: subscription-manager register --org <org> --activationkey <key>   (or point it at the customer's Satellite / internal mirror)\nCheck: subscription-manager status ; dnf repolist\nIf this host has no package source at all (imported repository, §7.2), choose [s] for package steps that are already satisfied."
  elif grep -qE 'Curl error \(6\)|Could not resolve host' "$f"; then
    fail "dnf could not resolve the repository host names." \
         "DNS on this host cannot resolve external names, or the perimeter firewall blocks DNS." \
         "Check: cat /etc/resolv.conf ; getent hosts cdn.redhat.com   (or the Satellite / mirror host in /etc/yum.repos.d)\nIf egress must go through a forward proxy, re-run with --reconfigure and set it."
  elif grep -qE 'Curl error \((35|51|58|60|77)\)|certificate (verify failed|cannot be authenticated)|SSL certificate problem' "$f"; then
    fail "TLS to the repository failed." \
         "TLS inspection with a CA this host does not trust (§1.4), or an expired RHSM entitlement certificate (curl 58)." \
         "Trust the inspection CA: cp ca.crt /etc/pki/ca-trust/source/anchors/ && update-ca-trust\nOr request an inspection bypass for cdn.redhat.com. For curl 58: subscription-manager refresh"
  elif grep -qE 'Curl error \((7|28|56)\)|Failed to connect|Connection timed out|Network is unreachable|Status code: 407' "$f"; then
    fail "dnf could not connect to the repositories." \
         "The perimeter firewall does not permit HTTPS from this host to the repositories, or a forward proxy is required (407 = proxy wants credentials)." \
         "Ask the network team to permit cdn.redhat.com / subscription.rhsm.redhat.com (or the Satellite / internal mirror),\nor re-run with --reconfigure and set the outbound proxy (http://user:pass@host:port if it needs auth)."
  elif grep -qE 'Status code: (40[0-9]|50[0-9])' "$f"; then
    fail "The repository or proxy refused dnf's requests: $(grep -m1 -oE 'Status code: [0-9]+' "$f")." \
         "403: entitlement missing for this repository, or URL filtering on the proxy. 404: stale metadata or a wrong baseurl. 5xx: repository/proxy fault." \
         "Run: subscription-manager refresh ; dnf clean all ; then choose [r].\nIf a proxy is in the way, ask for cdn.redhat.com to be allowed through it."
  elif grep -qE 'Failed to download metadata for repo|Cannot download repomd\.xml|Errors during downloading metadata' "$f" \
       && ! grep -q 'Ignoring repositories' "$f"; then   # with skip_if_unavailable the failed repo was only skipped
    fail "dnf could not download repository metadata: $(grep -m1 -oE "for repo '[^']+'" "$f")." \
         "That repository is unreachable from this host (firewall, proxy, or a disabled/expired subscription)." \
         "Check: dnf repolist ; dnf makecache   - disable a repository that is not needed: dnf config-manager --set-disabled <repo>"
  elif grep -qE 'No match for argument|Unable to find a match|No package .* available' "$f"; then
    fail "dnf cannot find requested packages: $(grep -m1 -oE '(Unable to find a match|No match for argument|No package)[^.]*' "$f")." \
         "The BaseOS/AppStream repositories are not enabled or reachable$(grep -q 'Ignoring repositories' "$f" && echo " (dnf skipped: $(grep -m1 -oE 'Ignoring repositories: .*' "$f" | cut -d: -f2-))"), or the package needs another repository (EPEL, CodeReady Builder)." \
         "Check: dnf repolist ; dnf provides <package>   (subscription-manager repos --enable rhel-$OS_MAJOR-for-$RPM_ARCH-appstream-rpms)"
  elif grep -qE 'filtered out by modular filtering|Modular dependency problems' "$f"; then
    fail "dnf modularity blocked a package." \
         "A module stream (e.g. nginx on RHEL 8) is disabled or another stream is enabled." \
         "Check: dnf module list nginx ; enable a stream: dnf module enable nginx:<stream>   then choose [r]."
  elif grep -qE 'GPG check FAILED|Public key for .* is not installed|GPG keys listed .* are not correct|BAD signature' "$f"; then
    fail "dnf rejected a package signature." "A repository's signing key is missing or wrong, or a package was altered in transit." \
         "Fix or disable the offending repository listed above (rpm -q gpg-pubkey lists imported keys), then retry."
  elif grep -qE 'No space left on device|more space needed|Disk Requirements' "$f"; then
    fail "The disk is full." "Not enough free space for the dnf cache or $REPO_ROOT." "Check: df -h /var /srv ; dnf clean packages"
  elif grep -qE 'nothing provides|conflicting requests|Problem: |cannot install both' "$f"; then
    fail "dnf could not resolve package dependencies." "A required package is in a repository that is not enabled, or excludes/version locks block it." \
         "Read the 'Problem:' lines above. Check: dnf repolist ; grep -i exclude /etc/dnf/dnf.conf ; dnf versionlock list"
  else
    fail "dnf failed." "First error: $(grep -m1 -E '^(Error|Errors|error):' "$f" || echo 'see the output above')" "Fix the reported problem, then choose [r] to retry."
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
    DL_CODE=$(cat "$codef" 2>/dev/null); DL_ERR=$(grep . "$errf" 2>/dev/null | tail -n 1)
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
    6)  fail "Could not resolve $host." "DNS on this host cannot resolve external names." "Check: getent hosts $host ; cat /etc/resolv.conf ; nmcli dev show | grep -i dns\nOr configure an outbound proxy with --reconfigure." ;;
    7)  if [[ -n ${DL_PROXY:-} ]] && [[ ${DL_ERR:-} == *"$(sed -E 's#^https?://([^@/]*@)?##; s#/.*##; s#:.*##' <<<"$DL_PROXY")"* ]]; then
          fail "Could not connect to the outbound proxy $DL_PROXY." "The proxy is down, the address/port is wrong, or the perimeter firewall blocks this host -> proxy." \
               "Test: curl -sSI -x $DL_PROXY https://github.com\nCorrect it with --reconfigure (or 'none' for direct access)."
          return
        fi
        fail "Could not connect to $host (connection refused or blocked)." \
             "The perimeter firewall does not permit HTTPS from this host to $host, or a forward proxy is mandatory." \
             "Downloads need HTTPS to: github.com, release-assets.githubusercontent.com and objects.githubusercontent.com\n(release downloads redirect there), api.github.com and bdot.bindplane.com. Ask the network team, or set a proxy with --reconfigure." ;;
    28) fail "The download from $host timed out." \
             "A firewall is silently dropping the traffic, or the link is slower than 1 KB/s for 60s." \
             "Try: curl -sSI https://$host  ; raise with the network team. Partial files are kept and resumed on retry." ;;
    35|58|59|60|77|83|90|91)
        fail "TLS to $host failed (curl exit $rc)." \
             "TLS inspection is active on this destination and the inspection CA is not trusted by this host (runbook §1.4)." \
             "Check the issuer: echo | openssl s_client -connect $host:443 -servername $host 2>/dev/null | openssl x509 -noout -issuer\nEither request an inspection bypass, or install the CA: cp ca.crt /etc/pki/ca-trust/source/anchors/ && update-ca-trust" ;;
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
      # no dpkg on RHEL: read the control file with ar (binutils) + tar
      local pkg arch
      [[ $(head -c 8 "$f") == '!<arch>' ]] || { echo "not a Debian package (no ar header)"; return 1; }
      pkg=$(deb_field "$f" Package) || { echo "not a valid Debian package (control file unreadable)"; return 1; }
      arch=$(deb_field "$f" Architecture)
      expect_product "$pkg" || return 1
      [[ $arch == "${kind#deb-}" ]] || { echo "architecture is '$arch', expected ${kind#deb-}"; return 1; } ;;
    rpm-amd64|rpm-arm64)
      local pkg arch want
      [[ $magic == edabeedb* ]] || { echo "not an RPM package (magic $magic)"; return 1; }
      rpm -K --nosignature "$f" >/dev/null 2>&1 || { echo "RPM digest check failed (truncated or corrupt download)"; return 1; }
      pkg=$(rpm -qp --nosignature --qf '%{NAME}' "$f" 2>/dev/null) || { echo "rpm cannot read the package header"; return 1; }
      arch=$(rpm -qp --nosignature --qf '%{ARCH}' "$f" 2>/dev/null)
      want=$([[ $kind == rpm-arm64 ]] && echo aarch64 || echo x86_64)
      expect_product "$pkg" || return 1
      [[ $arch == "$want" ]] || { echo "architecture is '$arch', expected $want"; return 1; } ;;
    msi)  [[ $magic == d0cf11e0a1b11ae1 ]] || { echo "not a Windows MSI (magic $magic)"; return 1; } ;;
    sh)   [[ $(head -c 2 "$f") == '#!' ]] || { echo "not a shell script"; return 1; } ;;
    ps1)  : ;;
    sums) grep -qE '^[0-9a-f]{64}[[:space:]]+' "$f" || { echo "not a SHA256SUMS file"; return 1; } ;;
    gpgkeys) tar -tzf "$f" 2>/dev/null | grep -qE '(^|/)bdot-public-gpg-key\.asc$' \
               || { echo "not the publisher's gpg-keys.tar.gz (no bdot-public-gpg-key.asc inside)"; return 1; } ;;
  esac
  return 0
}

# expect_product NAME - the package name must be the expected collector package
expect_product() {
  if [[ -n ${EXPECT_PKG:-} ]]; then
    [[ $1 == "$EXPECT_PKG" ]] || { echo "package name is '$1', expected $EXPECT_PKG"; return 1; }
  else
    contains_word "${PRODUCTS[*]}" "$1" || { echo "package name is '$1', expected one of: ${PRODUCTS[*]}"; return 1; }
  fi
}

# deb_field FILE FIELD - one field of a .deb's control file, without dpkg (ar + tar)
deb_field() {
  local f=$1 field=$2 member ctl v
  member=$(ar t "$f" 2>/dev/null | grep -m1 -E '^control\.tar(\.(gz|xz|bz2|zst))?$') || return 1
  ctl=$(ar p "$f" "$member" 2>/dev/null | case $member in
      *.gz)  tar -xzO --wildcards '*control' ;;
      *.xz)  tar -xJO --wildcards '*control' ;;
      *.bz2) tar -xjO --wildcards '*control' ;;
      *.zst) zstd -dcq | tar -xO --wildcards '*control' ;;
      *)     tar -xO  --wildcards '*control' ;;
    esac 2>/dev/null)
  v=$(sed -nE "s/^${field}:[[:space:]]*//p" <<<"$ctl" | head -n1)
  [[ -n $v ]] && printf '%s\n' "$v"
}

# pkg_arch - this host's architecture in the release-asset naming (amd64 / arm64)
pkg_arch() { case $RPM_ARCH in x86_64) echo amd64 ;; aarch64) echo arm64 ;; *) echo "$RPM_ARCH" ;; esac; }

# =============================================================================
#  Detection helpers
# =============================================================================
# use_family v1|v2 - point the COLLECTOR_* variables at a collector family's layout
#   v1 observiq-otel-collector    /opt/observiq-otel-collector   manager.yaml, log/collector.log
#   v2 bindplane-otel-collector   /opt/bindplane-otel-collector  supervisor.yaml, supervisor.log
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
endpoint_host() { local h=${1#*://}; h=${h%%/*}; h=${h%%:*}; printf '%s' "$h"; }

collector_version() {
  local v=""
  v=$(pkg_version "$COLLECTOR_PKG")
  if [[ -z $v && $COLLECTOR_FAMILY == v1 && -x $COLLECTOR_BIN ]]; then
    v=$("$COLLECTOR_BIN" --version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
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
  if [[ -z $DET_PROXY ]]; then   # dnf's own proxy setting ([main] proxy=)
    DET_PROXY=$(sed -nE 's/^[[:space:]]*proxy[[:space:]]*=[[:space:]]*(https?:\/\/[^[:space:]]+).*/\1/p' /etc/dnf/dnf.conf /etc/yum.conf 2>/dev/null | head -n1)
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
      else c_warn "OS: $name - this script targets RHEL 8/9 (use bp-dmz-setup.sh on Ubuntu)"; fi ;;
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

# Enabled dnf repositories. Only a warning: base packages may already be installed and the local
# dnf repository can be switched off (Satellite / internal mirror).
check_repos() {
  local out ids
  out=$(timeout 120 dnf -q --color=never "${DNF_PROXY_OPTS[@]}" repolist --enabled 2>&1)
  # first column of each row, minus the header ("repo id") and RHSM/dnf notices
  ids=$(awk 'NF {print $1}' <<<"$out" | grep -E '^[A-Za-z0-9][A-Za-z0-9_.:-]*[A-Za-z0-9_]$' \
        | grep -vxE '(repo|This|Updating|Unable|Last|Error|Errors|Failed|Ignoring|Repository|There|No)' | paste -sd' ')
  if grep -qE 'not registered (with an entitlement server|to Red Hat Subscription Management)' <<<"$out"; then
    c_warn "This host is not registered with Red Hat Subscription Management"
    hint "subscription-manager register (or Satellite) is needed for the base_packages and os_repo steps unless another repository provides the packages."
  fi
  if [[ -n $ids ]]; then c_ok "dnf repositories enabled: $ids"
  else
    c_warn "No enabled dnf repository - base_packages, os_repo, nginx and haproxy_install will fail"
    hint "Register the host (subscription-manager register), or configure the customer's Satellite / internal mirror in /etc/yum.repos.d."
  fi
}

check_collector() {
  local st v ep sk aid errs cf
  cf=$(basename "$COLLECTOR_CONF")
  if [[ ! -d $COLLECTOR_HOME ]] || ! systemctl cat "$COLLECTOR_SVC" >/dev/null 2>&1; then
    c_fail "Collector not installed (neither $V1_PKG nor $V2_PKG is set up here)"
    hint "Stage 1 (§1.2) must be completed on this host first."
    return 1
  fi
  c_ok "Collector family: $(family_label "$COLLECTOR_FAMILY")"
  [[ $(installed_family) == both ]] && c_warn "Both collector families are installed ($V1_PKG $(pkg_version "$V1_PKG"), $V2_PKG $(pkg_version "$V2_PKG")) - checks use the $COLLECTOR_FAMILY one"
  st=$(systemctl is-active "$COLLECTOR_SVC" 2>/dev/null)
  if [[ $st == active ]]; then c_ok "Collector service $COLLECTOR_SVC is active"
  else c_fail "Collector service is '$st'"; hint "journalctl -u $COLLECTOR_SVC -n 50 --no-pager ; tail -n 50 $COLLECTOR_LOG"; fi
  v=$(collector_version); [[ -n $v ]] && c_ok "Collector version: $v" || c_warn "Could not read the collector version"
  if [[ ! -r $COLLECTOR_CONF ]]; then c_fail "$COLLECTOR_CONF is missing"; return 1; fi
  ep=$(yaml_get endpoint); sk=$(yaml_get secret_key); aid=$(yaml_get agent_id)
  [[ -n $ep ]] && c_ok "$cf endpoint: $ep" || c_fail "$cf has no endpoint"
  [[ -n $sk ]] && c_ok "$cf secret key present ($(mask "$sk"))" || c_fail "$cf has no secret key"
  if [[ -n $aid ]]; then c_ok "Agent identity: $aid"
  else c_warn "No agent identity yet - the collector has not started with this $cf"; hint "§1.3: the console must list this host as Connected before you continue."; fi
  if [[ $ep == ws://*:$OPAMP_PORT/* ]]; then
    c_warn "The collector points at a relay ($ep), not directly at the cloud"
    hint "Left over from a §4.4 test? The direct copy is $COLLECTOR_CONF.direct"
  fi
  if [[ -r $COLLECTOR_LOG ]]; then
    errs=$(tail -n 200 "$COLLECTOR_LOG" | grep -iE 'error|refused|denied|timeout|unauthor|status=4' | grep -vE "$BENIGN_LOG_RE" | tail -n 3)
    if [[ -n $errs ]]; then c_warn "Recent errors in $COLLECTOR_LOG (last 3 shown):"; printf '%s\n' "$errs" | redact_stream | cut -c1-220 | sed 's/^/         /'
    else c_ok "No recent errors in $(basename "$COLLECTOR_LOG")"; fi
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
    no)  c_warn "System clock is NOT NTP-synchronised - TLS and OpAMP both fail on clock skew"; hint "timedatectl status ; chronyc sources -v ; systemctl status chronyd" ;;
    *)   c_warn "Could not read clock sync state (timedatectl)" ;;
  esac
}

check_dns() {
  local host=$1 addrs
  addrs=$(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')
  if [[ -n $addrs ]]; then c_ok "DNS: $host -> $addrs"; return 0; fi
  c_fail "DNS: cannot resolve $host"
  hint "HAProxy resolves the cloud host via /etc/resolv.conf. Check: getent hosts $host ; cat /etc/resolv.conf ; nmcli dev show | grep -i dns"
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
    hint "HAProxy hop 1 connects directly (no forward proxy). The perimeter firewall must permit this host -> $host:443."
    hint "If the customer mandates a forward proxy for this host, hop 1 cannot work as designed - raise it before continuing."
    return 1
  fi
  c_fail "TLS: certificate verification failed for $host ($vrc)"
  if [[ $vrc == *"hostname mismatch"* ]]; then
    hint "The certificate presented does not cover $host: the name resolves to the wrong server, or an inline device presents its own certificate."
  fi
  hint "Issuer seen: ${issuer:-unknown}. An internal-CA issuer means TLS inspection is active (§1.4)."
  hint "HAProxy uses 'verify required' and will return 503 until this passes. Request an inspection bypass,"
  hint "or trust the CA: cp ca.crt /etc/pki/ca-trust/source/anchors/ && update-ca-trust   (RHEL crypto policy: update-crypto-policies --show)"
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
  local path=$REPO_ROOT avail need=$((300*1024*1024)) v
  while [[ ! -e $path ]]; do path=$(dirname "$path"); done
  for v in ${STAGE_VERSIONS:-$BP_VERSION}; do product_of_version "$v" >/dev/null 2>&1 || need=$((need + $( [[ ${STAGE_ARM64:-no} == yes ]] && echo 720 || echo 460 )*1024*1024)); done
  avail=$(df -Pk "$path" | awk 'NR==2{print $4}')
  avail=$((avail*1024))
  if (( avail < need )); then c_fail "Only $(human $avail) free on the filesystem holding $REPO_ROOT - about $(human $need) is needed for the versions to stage"; return 1
  elif (( avail < need * 2 )); then c_warn "$(human $avail) free for $REPO_ROOT ($(human $need) needed now) - little room for later versions"
  else c_ok "$(human $avail) free for $REPO_ROOT ($(human $need) needed for the versions to stage)"; fi
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
# detect_haproxy_mode - RHEL 8 ships HAProxy 1.8, which predates 'log stdout', 'parse-resolv-conf' and
# server-side 'alpn' (all added in 1.9). Sets HAPROXY_COMPAT18=1 for 1.8; HAPROXY_VER to "major.minor".
HAPROXY_VER=""
detect_haproxy_mode() {
  HAPROXY_COMPAT18=0; HAPROXY_VER=""
  command -v haproxy >/dev/null || return 0
  HAPROXY_VER=$(haproxy -v 2>/dev/null | head -n1 | grep -oE 'version [0-9]+\.[0-9]+' | awk '{print $2}')
  [[ -n $HAPROXY_VER ]] || return 0
  if (( ${HAPROXY_VER%%.*} == 1 && ${HAPROXY_VER#*.} < 9 )); then HAPROXY_COMPAT18=1; fi
  return 0
}
# resolv_nameservers - IPv4 nameservers from /etc/resolv.conf as HAProxy 'nameserver' lines (1.8 mode)
resolv_nameservers() {
  awk '$1=="nameserver" && $2 ~ /^[0-9]+(\.[0-9]+){3}$/ { n++; printf "    nameserver ns%d %s:53\n", n, $2 }' /etc/resolv.conf 2>/dev/null
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

render_haproxy_cfg() {
  local user_lines="" debug_lines="" log_line resolv_lines alpn=" alpn http/1.1" mode_note=""
  detect_haproxy_mode
  if (( HAPROXY_COMPAT18 )); then
    # 1.8: journald owns /dev/log on RHEL; nameservers are copied from /etc/resolv.conf at render time
    log_line="    log /dev/log local0 info"
    resolv_lines=$(resolv_nameservers)
    alpn=""
    mode_note=$'# HAProxy 1.8 compatibility mode (RHEL 8): log /dev/log instead of stdout, nameservers copied from
# /etc/resolv.conf (re-run --only haproxy_config after a DNS change), no server-side ALPN - with no ALPN
# extension the cloud answers HTTP/1.1, which the OpAMP WebSocket upgrade needs.'
  else
    log_line="    log stdout format raw local0 info"
    resolv_lines="    parse-resolv-conf"
  fi
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
${mode_note}
global
${log_line}
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
${resolv_lines}
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
    server cloud ${BP_CLOUD_HOST}:443 ssl verify required ca-file ${CA_FILE} sni str(${BP_CLOUD_HOST})${alpn} resolvers bpdns init-addr last,libc,none check

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
  printf '# Managed by %s - runbook §2.5/§2.7 (RHEL). Original: %s.orig\n' "$SCRIPT_NAME" "$NGINX_MAIN"
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
# Managed by $SCRIPT_NAME v$SCRIPT_VERSION - runbook §2.5 (offline package origin)
# Bound to the internal-firewall-facing address only - never 0.0.0.0 (§2.7).
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
    # text/plain so PowerShell's Invoke-WebRequest returns these as strings (§9.2 checksum check)
    location ~ ^/(SHA256SUMS|VERSION-INFO|README\.txt)\$ {
        limit_except GET HEAD { deny all; }
        default_type text/plain;
        try_files \$uri =404;
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
    L4TOUT) echo "TCP connect to $BP_CLOUD_HOST:443 timed out: the perimeter firewall is silently dropping this host -> cloud:443." ;;
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
         "Backend health check: ${cs:-unknown} - $(describe_check_status "$cs")\nTypical causes: DNS, the perimeter-firewall rule for this host -> $BP_CLOUD_HOST:443, or certificate verification." \
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

explain_service_start() { # SERVICE LOGFILE
  local svc=$1 f=$2
  if grep -qE 'Cannot assign requested address' "$f"; then
    fail "$svc could not bind to $DMZ_GW_IP." "That address is not (or no longer) assigned to this host." "ip -br addr ; re-run with --reconfigure to choose the correct address."
  elif grep -qE 'Address already in use' "$f"; then
    fail "$svc could not bind: the port is already in use." "Another process is listening on the same port." "ss -lntp | grep -E ':($OPAMP_PORT|$REPO_PORT|$STATS_PORT) '"
  elif [[ -n $(selinux_denials) ]] || { grep -qE 'Permission denied' "$f" && [[ $(getenforce 2>/dev/null) == Enforcing ]]; }; then
    fail "$svc was blocked by SELinux." \
         "$(selinux_denials | tail -n 2 | cut -c1-240)\nTypically a port or file label that $svc's SELinux domain may not use (tcp/$OPAMP_PORT is ntop_port_t by default)." \
         "Re-apply the labels: $0 --only selinux\nInspect: ausearch -m AVC -ts recent -c $svc | audit2why ; semanage port -l | grep -wE '$OPAMP_PORT|$REPO_PORT|$STATS_PORT'\nLabel the port or path - do not disable SELinux."
  elif grep -qE 'Cannot raise FD limit|Too many open files|setrlimit' "$f"; then
    fail "$svc could not get enough file descriptors ($(grep -m1 -oE 'limit is [0-9]+' "$f" || echo 'limit too low'))." \
         "HAProxy needs about 2 x maxconn descriptors (maxconn ${HAPROXY_MAXCONN:-?} -> ~$(( ${HAPROXY_MAXCONN:-0} * 2 + 20 ))), but the service limit is lower." \
         "Make sure the §3.5 drop-in is active: systemctl daemon-reload && systemctl show haproxy -p LimitNOFILE\nOr lower maxconn: re-run with --reconfigure."
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
# rel_for UNVERSIONED_REL VERSION -> where a version's file is kept: the unversioned "current" name when
# that already holds this version, otherwise the versioned name (staging never overwrites a current file)
rel_for() { if [[ $(manifest_get "$1") == "$2|"* ]]; then printf '%s' "$1"; else versioned_name "$1" "$2"; fi; }

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

# Collector package naming changed with v2: observiq-otel-collector_* (v1.x) became
# bindplane-otel-collector_* (v2.x). The real names are always read from the release (§2.2).
PRODUCTS=(bindplane-otel-collector observiq-otel-collector)
EXPECT_PKG=""; REL_PRODUCT=""; REL_PRERELEASE="unknown"; REL_SOURCE=""; FETCH_VERSION=""

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
    for p in "${PRODUCTS[@]}"; do grep -qxF "${p}_${v}_linux_amd64.rpm" <<<"$REL_ASSETS" && { REL_PRODUCT=$p; break; }; done
    if [[ -z $REL_PRODUCT ]]; then
      fail "Release $v has no Linux x86_64 .rpm under a known name." \
           "The naming changed again upstream. Linux packages in the release: $(grep -E '_linux_amd64\.(rpm|deb)$' <<<"$REL_ASSETS" | tr '\n' ' ')" \
           "Check https://github.com/$GH_REPO/releases/tag/$v - the script knows: ${PRODUCTS[*]}"
      return 1
    fi
    ok "Release $v: $(wc -l <<<"$REL_ASSETS") assets (read from the $REL_SOURCE), package $REL_PRODUCT"
    log "assets: $(tr '\n' ' ' <<<"$REL_ASSETS")"
  else
    warn "The release metadata is not readable (API and release page blocked?) - probing the download URLs instead"
    for p in "${PRODUCTS[@]}"; do
      probe_asset "$v" "${p}_${v}_linux_amd64.rpm"; rc=$?
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
  [[ $REL_PRERELEASE == yes ]] && warn "$v is a PRE-RELEASE - not for production unless the customer has approved it"
  [[ $REL_PRODUCT == bindplane-otel-collector ]] && info "$v is a v2 release: package 'bindplane-otel-collector' (OpAMP supervisor, configured by supervisor.yaml)"
  return 0
}
asset_listed() { (( ! REL_ASSETS_KNOWN )) || grep -qxF "$1" <<<"$REL_ASSETS"; }

# ---- release catalogue: "tag|pre-release yes/no|date" lines, newest first --------------------------
# Sources in order: GitHub API -> releases feed (github.com) -> releases page -> built-in list + probes.
release_catalogue() {
  local f="$RUN_TMP/catalogue" code
  if [[ -s $f ]]; then CATALOGUE=$(cat "$f"); CATALOGUE_SOURCE=$(cat "$f.src"); return 0; fi
  CATALOGUE=""; CATALOGUE_SOURCE=""
  info "Reading the collector release list from GitHub ..."
  code=$(gh_code "$GH_API/releases?per_page=60" "$RUN_TMP/rel.json" -H 'Accept: application/vnd.github+json')
  if [[ $code == 200 ]]; then
    CATALOGUE=$(jq -r '.[] | select(.draft | not) | "\(.tag_name)|\(if .prerelease then "yes" else "no" end)|\((.published_at // "")[0:10])"' "$RUN_TMP/rel.json" 2>/dev/null)
    [[ -n $CATALOGUE ]] && CATALOGUE_SOURCE="GitHub API"
  fi
  if [[ -z $CATALOGUE ]]; then
    code=$(gh_code "https://github.com/$GH_REPO/releases.atom" "$RUN_TMP/rel.atom")
    if [[ $code == 200 ]]; then
      CATALOGUE=$(awk '/<entry>/{t="";d=""} /releases\/tag\//{ if (match($0, /releases\/tag\/[^"<]+/)) t=substr($0, RSTART+13, RLENGTH-13) }
                       /<updated>/{ if (match($0, /<updated>[0-9-]+/)) d=substr($0, RSTART+9, 10) }
                       /<\/entry>/{ if (t != "") print t "|" (t ~ /-/ ? "yes" : "no") "|" d }' "$RUN_TMP/rel.atom")
      [[ -n $CATALOGUE ]] && CATALOGUE_SOURCE="GitHub release feed"
    fi
  fi
  if [[ -z $CATALOGUE ]]; then
    code=$(gh_code "https://github.com/$GH_REPO/releases" "$RUN_TMP/rel.html")
    if [[ $code == 200 ]]; then
      CATALOGUE=$(grep -oE "/$GH_REPO/releases/tag/[^\"?#]+" "$RUN_TMP/rel.html" | sed 's#.*/tag/##' | awk '!seen[$0]++' \
                  | awk '{print $0 "|" ($0 ~ /-/ ? "yes" : "no") "|"}')
      [[ -n $CATALOGUE ]] && CATALOGUE_SOURCE="GitHub releases page"
    fi
  fi
  if [[ -z $CATALOGUE ]]; then
    warn "GitHub's release listing is not reachable from here - using the built-in list and probing for newer releases"
    CATALOGUE=$( { printf '%s\n' $KNOWN_RELEASES; probe_newer_releases; } | awk '!seen[$0]++ {print $0 "|" ($0 ~ /-/ ? "yes" : "no") "|"}')
    CATALOGUE_SOURCE="built-in list + download probes; GitHub listing blocked"
    FAIL_WHAT="" FAIL_WHY="" FAIL_FIX=""
  fi
  CATALOGUE=$(grep -E '^v[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.]+)?\|' <<<"$CATALOGUE" | awk -F'|' '!seen[$1]++')
  printf '%s\n' "$CATALOGUE" >"$f"; printf '%s' "$CATALOGUE_SOURCE" >"$f.src"
  log "catalogue ($CATALOGUE_SOURCE): $(cut -d'|' -f1 <<<"$CATALOGUE" | paste -sd' ')"
}
# releases newer than KNOWN_RELEASES, found by probing the download URLs (both families)
probe_newer_releases() {
  local newest a b c n i cand found
  newest=$(printf '%s\n' $KNOWN_RELEASES | grep '^v1\.' | sort_tags | tail -n1)
  for i in 1 2 3 4 5 6; do
    IFS=. read -r a b c <<<"${newest#v}"; found=""
    for cand in "v$a.$((b+1)).0" "v$a.$b.$((c+1))" "v$a.$((b+2)).0"; do
      probe_asset "$cand" "${V1_PKG}_${cand}_linux_amd64.rpm" && { echo "$cand"; found=$cand; break; }
    done
    [[ -n $found ]] || break; newest=$found
  done
  newest=$(printf '%s\n' $KNOWN_RELEASES | grep '^v2\.' | sort_tags | tail -n1)
  if [[ $newest =~ ^(v[0-9]+\.[0-9]+\.[0-9]+)-beta\.([0-9]+)$ ]]; then
    a=${BASH_REMATCH[1]}; n=${BASH_REMATCH[2]}
    for i in 1 2 3 4 5 6; do
      cand="$a-beta.$((n+i))"
      probe_asset "$cand" "${V2_PKG}_${cand}_linux_amd64.rpm" && echo "$cand" || break
    done
    newest=$a
  fi
  IFS=. read -r a b c <<<"${newest#v}"
  for cand in "v$a.$b.$c" "v$a.$b.$((c+1))" "v$a.$((b+1)).0"; do
    probe_asset "$cand" "${V2_PKG}_${cand}_linux_amd64.rpm" && echo "$cand"
  done
  return 0
}
catalogue_tags() { # FAMILY [stable] -> tags of that family, newest first (catalogue + EXTRA tags)
  local fam=$1 only=${2:-} t pre
  { cut -d'|' -f1,2 <<<"$CATALOGUE"; for t in ${CAT_EXTRA:-}; do echo "$t|$(is_prerelease "$t" && echo yes || echo no)"; done; } \
    | awk -F'|' '!seen[$1]++' | while IFS='|' read -r t pre; do
        [[ -n $t && $(family_of_version "$t") == "$fam" ]] || continue
        [[ $only == stable && $pre == yes ]] && continue
        echo "$t"
      done | sort_tags | tac
}
catalogue_field() { awk -F'|' -v t="$1" -v n="$2" '$1==t {print $n; exit}' <<<"$CATALOGUE"; }
# default selection: the two newest v1 releases and the two newest v2 releases (stable preferred)
default_stage_selection() {
  local fam out="" t
  for fam in v1 v2; do
    t=$( { catalogue_tags "$fam" stable; catalogue_tags "$fam"; } | awk '!seen[$0]++' | head -n2)
    out+=" $(paste -sd' ' <<<"$t")"
  done
  out=$(trim "$out"); printf '%s' "$out"
}
# version_menu SELECTED STAGED [LIMIT] - numbered release list for both families; fills MENU_TAGS[1..n]
version_menu() {
  local sel=$1 staged=$2 limit=${3:-6} fam t n=0 shown mark flags d
  MENU_TAGS=()
  CAT_EXTRA="$sel $staged"
  for fam in v1 v2; do
    if [[ $fam == v1 ]]; then printf '     %sv1  observiq-otel-collector%s  - manager.yaml; the stable line the runbook describes\n' "$C_BLD" "$C_OFF"
    else printf '     %sv2  bindplane-otel-collector%s - OpAMP supervisor + supervisor.yaml\n' "$C_BLD" "$C_OFF"; fi
    shown=0
    while IFS= read -r t; do
      [[ -n $t ]] || continue
      if (( shown >= limit )) && ! contains_word "$sel $staged" "$t"; then continue; fi
      n=$((n+1)); shown=$((shown+1)); MENU_TAGS[n]=$t
      mark="[ ]"; contains_word "$sel" "$t" && mark="[x]"
      flags=""; is_prerelease "$t" && flags+=" pre-release"; contains_word "$staged" "$t" && flags+=" (staged)"
      [[ $t == "${BP_VERSION:-}" ]] && flags+=" (default)"
      d=$(catalogue_field "$t" 3)
      printf '       %s %2d) %-16s %-11s%s\n' "$mark" "$n" "$t" "${d:-}" "$flags"
    done < <(catalogue_tags "$fam")
    (( shown )) || printf '       (none listed)\n'
  done
}
# parse_selection INPUT -> release tags; accepts menu numbers, ranges (2-4), tags (v1.109.0), commas
parse_selection() {
  local in=${1//,/ } tok i out=""
  for tok in $in; do
    if [[ $tok =~ ^([0-9]+)-([0-9]+)$ ]]; then
      for ((i=BASH_REMATCH[1]; i<=BASH_REMATCH[2]; i++)); do [[ -n ${MENU_TAGS[i]-} ]] || return 1; out+=" ${MENU_TAGS[i]}"; done
    elif [[ $tok =~ ^[0-9]+$ ]]; then
      [[ -n ${MENU_TAGS[tok]-} ]] || return 1; out+=" ${MENU_TAGS[tok]}"
    else
      [[ $tok == v* ]] || tok="v$tok"
      v_version "$tok" >/dev/null || return 1; out+=" $tok"
    fi
  done
  printf '%s\n' $out | awk 'NF && !seen[$0]++' | paste -sd' '
}
v_selection() { [[ -z $1 ]] && return 0; parse_selection "$1" >/dev/null || { echo "Use numbers from the list (e.g. 1 2 7), ranges (1-3) or release tags (e.g. v1.109.0)."; return 1; }; }
# tags that are neither in the catalogue nor already staged must exist on GitHub (probe both names)
check_tags_exist() {
  local t rc bad=""
  for t in $1; do
    grep -q "^$t|" <<<"$CATALOGUE" && continue
    product_of_version "$t" >/dev/null 2>&1 && continue
    probe_asset "$t" "$(product_of_family "$(family_of_version "$t")")_${t}_linux_amd64.rpm"; rc=$?
    (( rc == 1 )) && bad+=" $t"
  done
  FAIL_WHAT="" FAIL_WHY="" FAIL_FIX=""
  [[ -z $bad ]] || echo "No such release on github.com/$GH_REPO:$bad"
}
# select_versions VAR PROMPT DEFAULT_TAGS STAGED [LIMIT] [ALLOW_NONE] - multi-select from the menu
select_versions() {
  local __v=$1 prompt=$2 def=$3 staged=$4 limit=${5:-6} none=${6:-0} reply sel defnums t i bad
  while :; do
    version_menu "$def" "$staged" "$limit"
    defnums=""
    for t in $def; do for i in "${!MENU_TAGS[@]}"; do [[ ${MENU_TAGS[i]} == "$t" ]] && defnums+="${defnums:+ }$i"; done; done
    ask reply "$prompt" "$defnums" v_selection "$none" || return 1
    sel=$(parse_selection "$reply")
    if [[ -z $sel && $none != 1 ]]; then warn "  Select at least one version."; { (( ASSUME_YES )) || [[ -z $TTY ]]; } && return 1; continue; fi
    bad=$(check_tags_exist "$sel")
    if [[ -n $bad ]]; then warn "  $bad"; { (( ASSUME_YES )) || [[ -z $TTY ]]; } && return 1; def=$sel; continue; fi
    printf -v "$__v" '%s' "$sel"; log "SELECTED $prompt = $sel"
    return 0
  done
}
# select_one VAR PROMPT DEFAULT CANDIDATES - pick one version from a short list
select_one() {
  local __v=$1 prompt=$2 def=$3 cands=$4 t n=0 reply defn=""
  local -a list=()
  for t in $cands; do
    n=$((n+1)); list[n]=$t; [[ $t == "$def" ]] && defn=$n
    printf '       %2d) %-16s %s\n' "$n" "$t" "$(family_label "$(family_of_version "$t")")$(is_prerelease "$t" && echo ', pre-release')"
  done
  while :; do
    ask reply "$prompt" "${defn:-1}" || return 1
    [[ $reply =~ ^[0-9]+$ && -n ${list[reply]-} ]] && reply=${list[reply]}
    [[ $reply == v* ]] || reply="v$reply"
    if contains_word "$cands" "$reply"; then printf -v "$__v" '%s' "$reply"; ok "  $prompt: $reply"; return 0; fi
    warn "  Choose a number from the list or one of: $cands"
    { (( ASSUME_YES )) || [[ -z $TTY ]]; } && return 1
  done
}

# product_of_version VERSION -> package name of a staged version
product_of_version() { # only the package name that belongs to the version's family counts
  local p
  p=$(product_of_family "$(family_of_version "$1")")
  # staged = its x86_64 .rpm is present (what RHEL gateways install); a .deb alone does not count
  [[ -f $REPO_ROOT/packages/${p}_${1}_linux_amd64.rpm ]] && { echo "$p"; return 0; }
  return 1
}
# files that carry a version under the other family's package name (e.g. a renamed download) - ignored
misnamed_files() {
  find "$REPO_ROOT/packages" "$REPO_ROOT/windows" -maxdepth 1 -type f \
       \( -name "${V1_PKG}_v[2-9]*" -o -name "${V1_PKG}-v[2-9]*-SHA256SUMS" -o -name "${V2_PKG}_v1.*" -o -name "${V2_PKG}-v1.*-SHA256SUMS" \) 2>/dev/null | sort
}
# staged_list -> "package version" lines, oldest first
staged_list() {
  local p v
  find "$REPO_ROOT/packages" -maxdepth 1 -name '*-otel-collector_v*_linux_amd64.rpm' -printf '%f\n' 2>/dev/null \
    | sed -nE 's/^(observiq-otel-collector|bindplane-otel-collector)_(v[^_]+)_linux_amd64\.rpm$/\1 \2/p' \
    | while read -r p v; do [[ $p == "$(product_of_family "$(family_of_version "$v")")" ]] && echo "$p $v"; done | sort -k2,2V
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
  case $rel in windows/*-otel-collector.msi|windows/*-otel-collector-arm64.msi|windows/install_windows.ps1|scripts/install_unix.sh) ;; *) return 0 ;; esac
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

get_windows_script() { # VERSION
  local v=$1 url rel
  rel=$(rel_for windows/install_windows.ps1 "$v")
  for url in "$GH_DL/$v/install_windows.ps1" "$BDOT_CDN/$v/install_windows.ps1"; do
    if [[ $url == "$GH_DL"* ]] && (( REL_ASSETS_KNOWN )) && ! grep -qxF install_windows.ps1 <<<"$REL_ASSETS"; then continue; fi
    get_artefact "$rel" "$url" ps1 install_windows.ps1 "$v" && return 0
  done
  FAIL_WHAT="" FAIL_WHY="" FAIL_FIX=""
  warn "Could not stage install_windows.ps1 - the MSI alone is sufficient (Stage 9.2 is a script-free install path)."
  hint "If you need the script, take the current URL from the console's Windows install command."
  return 1
}

os_field() { ( . /etc/os-release 2>/dev/null; eval "printf '%s' \"\${$1:-}\"" ); }

# vendor_gpgkey - file:// URL of the OS vendor's package-signing key, as this host's own repositories
# reference it. Every RHEL host already has it under /etc/pki/rpm-gpg, so the isolated hosts verify the
# staged OS packages with gpgcheck=1 without trusting anything delivered over the HTTP repository.
vendor_gpgkey() {
  local k f
  k=$(grep -hE '^[[:space:]]*gpgkey[[:space:]]*=' /etc/yum.repos.d/*.repo 2>/dev/null | grep -oE 'file:///etc/pki/rpm-gpg/[^[:space:],]+' | head -n1)
  if [[ -z $k ]]; then
    for f in /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release "/etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-$OS_MAJOR" \
             "/etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-$OS_MAJOR" /etc/pki/rpm-gpg/RPM-GPG-KEY-oracle; do
      [[ -f $f ]] && { k="file://$f"; break; }
    done
  fi
  printf '%s' "${k:-file:///etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release}"
}

# local_repo_file BASEURL [ID] - the .repo file the isolated hosts use for the staged OS packages
local_repo_file() {
  local url=$1 id=${2:-bindplane-local} keys signed=0
  keys=$(vendor_gpgkey)
  [[ ${SIGN_RPM_REPO:-no} == yes ]] && { keys+=" file:///etc/pki/rpm-gpg/RPM-GPG-KEY-bindplane-repo"; signed=1; }
  printf '%s\n' "[$id]" "name=NCINGA Bindplane offline repository ($(hostname -s))" "baseurl=$url" "enabled=1" \
    "gpgcheck=1" "gpgkey=$keys" "repo_gpgcheck=$signed" \
    "# RHEL 8: nginx is a modular package - lets it install from a repository without module metadata" \
    "module_hotfixes=1"
}

write_version_info() {
  local rpm_line="not built (Satellite / internal mirror used)"
  local apt_line="not built (RHEL origin host - build apt/ on an Ubuntu host of the target release)"
  if [[ ${BUILD_RPM_REPO:-no} == yes && -f $RPM_REPO_DIR/repodata/repomd.xml ]]; then
    rpm_line="el${OS_MAJOR}-${RPM_ARCH} ($(os_field PRETTY_NAME)) in $RPM_REPO_REL"
  fi
  [[ -f $REPO_ROOT/apt/Packages ]] && apt_line="present (imported - built on an Ubuntu host)"
  {
    echo "current_collector_version=$BP_VERSION"
    echo "current_package=$(product_of_version "$BP_VERSION" || echo unknown)"
    echo "current_v1=$(family_current v1 || true)"
    echo "current_v2=$(family_current v2 || true)"
    echo "staged_versions=$(staged_list | awk '{print $2}' | paste -sd' ')"
    echo "staged_packages=$(staged_list | awk '{print $1":"$2}' | paste -sd' ')"
    echo "package_format=rpm"
    echo "rpm_repo_built_for=$rpm_line"
    echo "rpm_repo_signed=${SIGN_RPM_REPO:-no}"
    echo "apt_repo_built_for=$apt_line"
    echo "origin_host=$(hostname -s) ($DMZ_GW_IP)"
    echo "updated=$(date -Is)"
  } >"$REPO_ROOT/VERSION-INFO"
  chmod 644 "$REPO_ROOT/VERSION-INFO"
}

write_repo_readme() {
  cat >"$REPO_ROOT/README.txt" <<EOF
NCINGA Bindplane - offline package origin ($(hostname -s), site: $SITE, $(os_field PRETTY_NAME))
Served by nginx on http://$DMZ_GW_IP:$REPO_PORT/ (runbook Stage 2). Managed by bp-dmz-setup-rhel.sh.

  packages/   collector .rpm (and .deb when staged) for every staged version + the publisher's SHA256SUMS
                v1  observiq-otel-collector_<tag>_linux_<arch>.rpm|deb   (manager.yaml)
                v2  bindplane-otel-collector_<tag>_linux_<arch>.rpm|deb  (supervisor.yaml)
                <package>-<tag>-SHA256SUMS      the publisher's checksums
                <package>-<tag>-gpg-keys.tar.gz the publisher's signing key (offline signature checks)
  scripts/    bp-agent-install-linux.sh  - NCINGA offline agent installer for Linux log sources (Stage 8)
              install_unix.sh of the default version, install_unix_<tag>.sh of the others
              (do NOT use them on isolated hosts - they need the internet, §6.4)
  windows/    bp-agent-install-windows.ps1 - NCINGA offline agent installer for Windows log sources (Stage 9)
              observiq-otel-collector.msi = current v1, bindplane-otel-collector.msi = current v2,
              <package>_<tag>.msi = other versions (-arm64 variants when ARM64 is staged);
              install_windows.ps1 (+ _<tag> copies)
  $RPM_REPO_REL/
              dnf repository: $RPM_REPO_PKGS${EXTRA_RPM_PKGS:+ $EXTRA_RPM_PKGS} + full dependency closure
              (RHEL $OS_MAJOR, $RPM_ARCH only - the isolated hosts must run the same major release)
  apt/        (empty on a RHEL origin - build Ubuntu repositories on an Ubuntu host of the target release)
  SHA256SUMS  checksums of every file above - verify after every transfer
  VERSION-INFO  default and current v1/v2 versions, staged versions, RHEL release of the dnf repository

Log sources (Stages 8/9) - from the gateway of their segment (this host for the DMZ segment):
  Linux:   curl -fsSO http://<gateway>:$REPO_PORT/scripts/bp-agent-install-linux.sh && sudo bash bp-agent-install-linux.sh
  Windows: Invoke-WebRequest http://<gateway>:$REPO_PORT/windows/bp-agent-install-windows.ps1 -OutFile bp-agent-install-windows.ps1 -UseBasicParsing
           powershell -ExecutionPolicy Bypass -File .\bp-agent-install-windows.ps1      (elevated)

LIVE gateway (RHEL $OS_MAJOR), §5.2 - /etc/yum.repos.d/bindplane-local.repo:
$(local_repo_file "http://$DMZ_GW_IP:$REPO_PORT/$RPM_REPO_REL/" | sed 's/^/    /')
  sudo dnf --disablerepo='*' --enablerepo=bindplane-local install -y nginx haproxy wget
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
    echo "## name resolution"; cat /etc/resolv.conf; nmcli dev show 2>/dev/null | grep -i dns
    echo "## SELinux"; getenforce 2>&1; sestatus 2>&1 | head -n 5
    echo "## firewalld"; firewall-cmd --state 2>&1; firewall-cmd --get-active-zones 2>&1
    echo "## dnf repositories"; timeout 120 dnf -q --color=never repolist --enabled 2>&1
  } >"$f" 2>&1
  check_os
  check_selinux
  check_repos
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
         "See the [FAIL] lines and hints above. Runbook gate §1.3: DNS, the perimeter-firewall rule set, TLS inspection or clock skew are resolved at this tier - no proxy hop will fix them." \
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
  # tar/binutils: read .deb control files without dpkg; dnf-plugins-core: 'dnf download'
  local pkgs=(curl ca-certificates jq wget openssl gzip tar iproute binutils dnf-plugins-core) c missing="" rc
  [[ ${BUILD_RPM_REPO:-no} == yes ]] && pkgs+=(createrepo_c)
  [[ ${SIGN_RPM_REPO:-no} == yes ]] && pkgs+=(gnupg2)
  selinux_enabled && pkgs+=(policycoreutils-python-utils)     # semanage
  local -a absent=()
  for c in "${pkgs[@]}"; do rpm -q --quiet "$c" || absent+=("$c"); done
  dnf_run "Refreshing repository metadata (dnf makecache)" makecache; rc=$?
  if (( rc != 0 )); then
    if (( ${#absent[@]} == 0 )) && [[ ${BUILD_RPM_REPO:-no} != yes ]]; then
      warn "dnf makecache failed, but every base package is already installed and no local dnf repository is built - continuing."
      FAIL_WHAT="" FAIL_WHY="" FAIL_FIX=""
    else
      return 1
    fi
  fi
  if grep -qE 'not registered (with an entitlement server|to Red Hat Subscription Management)' "$LAST_OUT"; then
    warn "dnf reports this host is not registered with Red Hat Subscription Management."
    hint "Packages only come from the other repositories configured in /etc/yum.repos.d (Satellite / internal mirror)."
  fi
  if (( ${#absent[@]} )); then
    # only missing packages are named: dnf install never upgrades packages that are already installed (change control)
    dnf_run "Installing missing base packages: ${absent[*]}" install --setopt=install_weak_deps=False "${absent[@]}" || return 1
  else
    ok "Base packages already installed (nothing upgraded): ${pkgs[*]}"
  fi
  for c in curl jq wget openssl sha256sum ss ar tar rpm; do command -v "$c" >/dev/null || missing+=" $c"; done
  [[ ${BUILD_RPM_REPO:-no} == yes ]] && ! command -v createrepo_c >/dev/null && missing+=" createrepo_c"
  [[ ${BUILD_RPM_REPO:-no} == yes ]] && ! dnf download --help >/dev/null 2>&1 && missing+=" dnf-download(dnf-plugins-core)"
  selinux_enabled && ! command -v semanage >/dev/null && missing+=" semanage"
  [[ ${SIGN_RPM_REPO:-no} == yes ]] && ! command -v gpg >/dev/null && missing+=" gpg"
  [[ -z $missing ]] || { fail "Required commands still missing:$missing" "The packages did not install correctly." "dnf reinstall ${pkgs[*]}"; return 1; }
  ok "All required tools are present"
}

step_repo_layout() {
  run "Creating $REPO_ROOT/{packages,scripts,windows,apt,rpm}" mkdir -p "$REPO_ROOT"/{packages,scripts,windows,apt,rpm} \
    || { fail "Could not create $REPO_ROOT." "The filesystem is read-only or full." "findmnt -T $REPO_ROOT ; df -h $REPO_ROOT"; return 1; }
  chmod 755 "$REPO_ROOT" "$REPO_ROOT"/{packages,scripts,windows,apt,rpm}
  write_repo_readme
  ok "Layout ready: $REPO_ROOT/{packages,scripts,windows,apt,rpm}"
}

# ---- SELinux (RHEL) ---------------------------------------------------------------------------------
# Default policy: httpd_t (nginx) may bind http_port_t and http_cache_port_t (8080 is http_cache_port_t);
# haproxy_t may bind http_port_t, http_cache_port_t and commplex_main_port_t and connect to http_port_t
# (443). tcp/3001 is ntop_port_t and tcp/8404 is unlabelled (unreserved_port_t), so both are labelled
# http_port_t. The repository is labelled httpd_sys_content_t (read-only web content).
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

# selinux_label_port PORT WHO - make tcp/PORT bindable for nginx/haproxy (http_port_t unless already allowed)
selinux_label_port() {
  local port=$1 who=$2 cur out="$RUN_TMP/semanage.out" mode
  cur=$(selinux_port_type "$port")
  if [[ $cur == http_port_t || $cur == http_cache_port_t ]]; then ok "tcp/$port is $cur - $who may bind it"; return 0; fi
  printf '    Labelling tcp/%s http_port_t (was %s) so %s may bind it ... ' "$port" "$cur" "$who"
  if semanage port -a -t http_port_t -p tcp "$port" >"$out" 2>&1; then mode=added
  elif semanage port -m -t http_port_t -p tcp "$port" >>"$out" 2>&1; then mode=modified
  else
    printf '%sFAILED%s
' "$C_RED" "$C_OFF"; show_tail "$out" 6; log_file "$out"
    fail "semanage could not label tcp/$port." "See the semanage output above." "Run by hand: semanage port -a -t http_port_t -p tcp $port   (or -m if it is already defined)"
    return 1
  fi
  printf '%sok%s
' "$C_GRN" "$C_OFF"; log_file "$out"
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
  command -v semanage >/dev/null || { fail "semanage is not installed." "policycoreutils-python-utils is missing (base_packages installs it when SELinux is enabled)." "dnf install policycoreutils-python-utils ; then choose [r]"; return 1; }
  info "SELinux is $(getenforce) - labelling what nginx and haproxy need (this takes a few seconds per change)"
  selinux_label_repo || return 1
  selinux_label_port "$REPO_PORT" nginx || return 1
  selinux_label_port "$OPAMP_PORT" haproxy || return 1
  selinux_label_port "$STATS_PORT" haproxy || return 1
  if [[ $(getsebool haproxy_connect_any 2>/dev/null) == *"--> on" ]]; then
    info "haproxy_connect_any is on (set outside this script) - this configuration does not need it"
  fi
  ok "SELinux labels in place; outbound haproxy -> $BP_CLOUD_HOST:443 (http_port_t) is allowed by the default policy"
}

# stage_collector_version VERSION - download and verify one release (either family). Packages are always
#   versioned; the MSI and install scripts stay where they are (unversioned when this version is current),
#   otherwise they are stored as *_vX.Y.Z - promote_currents() gives the current ones the plain names.
stage_collector_version() {
  local v=$1 p base item rel asset kind need
  local -a plan=()
  FETCH_VERSION=$v
  discover_release "$v" || return 1
  p=$REL_PRODUCT; EXPECT_PKG=$p; base="$GH_DL/$v"
  fetch_upstream_sums "$v" "$p"
  plan+=("packages/${p}_${v}_linux_amd64.rpm|${p}_${v}_linux_amd64.rpm|rpm-amd64|required")
  [[ $STAGE_DEB == yes ]]   && plan+=("packages/${p}_${v}_linux_amd64.deb|${p}_${v}_linux_amd64.deb|deb-amd64|wanted")
  [[ $STAGE_ARM64 == yes ]] && plan+=("packages/${p}_${v}_linux_arm64.rpm|${p}_${v}_linux_arm64.rpm|rpm-arm64|wanted")
  [[ $STAGE_ARM64 == yes && $STAGE_DEB == yes ]] && plan+=("packages/${p}_${v}_linux_arm64.deb|${p}_${v}_linux_arm64.deb|deb-arm64|wanted")
  # the publisher's signing key + revocations: lets the NCINGA agent installers verify package signatures offline
  plan+=("packages/${p}-${v}-gpg-keys.tar.gz|gpg-keys.tar.gz|gpgkeys|wanted")
  plan+=("$(rel_for scripts/install_unix.sh "$v")|install_unix.sh|sh|wanted")
  [[ $STAGE_WINDOWS == yes ]] && plan+=("$(rel_for "windows/${p}.msi" "$v")|${p}.msi|msi|wanted")
  [[ $STAGE_WINDOWS == yes && $STAGE_ARM64 == yes ]] && plan+=("$(rel_for "windows/${p}-arm64.msi" "$v")|${p}-arm64.msi|msi|wanted")
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
  [[ $STAGE_WINDOWS == yes ]] && { get_windows_script "$v" || true; }
  EXPECT_PKG=""; FETCH_VERSION=""
  return 0
}

# promote_current VERSION [msi] - give a staged version the unversioned "current" names (with 'msi':
# only its family's MSI - used for the current version of the family that is not the default)
promote_current() {
  local v=$1 mode=${2:-all} p pair vrel urel have sum
  local -a pairs=()
  p=$(product_of_version "$v") || { fail "$v is not staged in $REPO_ROOT/packages." "" "Stage it first."; return 1; }
  pairs=("windows/${p}_${v}.msi|windows/${p}.msi" "windows/${p}-arm64_${v}.msi|windows/${p}-arm64.msi")
  [[ $mode == msi ]] || pairs+=("scripts/install_unix_${v}.sh|scripts/install_unix.sh" "windows/install_windows_${v}.ps1|windows/install_windows.ps1")
  for pair in "${pairs[@]}"; do
    vrel=${pair%%|*}; urel=${pair#*|}
    [[ -f $REPO_ROOT/$vrel ]] || continue
    archive_previous "$urel" "$v"
    have=$(manifest_get "$vrel"); sum=${have#*|}; [[ -n $have ]] || sum=$(sha256 "$REPO_ROOT/$vrel")
    mv -f "$REPO_ROOT/$vrel" "$REPO_ROOT/$urel"
    manifest_set "$urel" "$v" "$sum"; manifest_del "$vrel"
    info "$urel now holds $v"
  done
  [[ $mode == msi ]] || BP_VERSION=$v
  return 0
}
# family_current FAMILY - that family's current version: the default (BP_VERSION) when it belongs to the
# family, otherwise the family's newest staged version (stable preferred)
family_current() {
  local fam=$1 list c
  list=$(staged_list | awk '{print $2}')
  if [[ -n ${BP_VERSION:-} && $(family_of_version "$BP_VERSION") == "$fam" ]] && grep -qxF "$BP_VERSION" <<<"$list"; then echo "$BP_VERSION"; return 0; fi
  c=$(while read -r x; do [[ -n $x && $(family_of_version "$x") == "$fam" ]] && echo "$x"; done <<<"$list")
  { grep -v -- - <<<"$c" | sort_tags | tail -n1; sort_tags <<<"$c" | tail -n1; } | grep . | head -n1
}
# promote_currents - plain names for each family's current version; the default version last, so the
# shared install scripts are the default's
promote_currents() {
  local def=$BP_VERSION other oc
  other=$([[ $(family_of_version "$def") == v1 ]] && echo v2 || echo v1)
  oc=$(family_current "$other")
  if [[ -n $oc ]]; then promote_current "$oc" msi || return 1; fi
  promote_current "$def" || return 1
  return 0
}

# The NCINGA agent installers for log sources are published in the repository when they sit next to
# this script (or in the directory it was started from): log sources then fetch them from their gateway.
AGENT_INSTALLERS=("bp-agent-install-linux.sh|scripts" "bp-agent-install-windows.ps1|windows")
agent_installer_version() { grep -m1 -oE "^(SCRIPT_VERSION=\"|\\\$ScriptVersion = ')[0-9][0-9.]*" "$1" 2>/dev/null | grep -oE '[0-9][0-9.]*$'; }
publish_agent_installers() {
  local item name dir src d rel n=0 why
  for item in "${AGENT_INSTALLERS[@]}"; do
    name=${item%%|*}; dir=${item#*|}; rel="$dir/$name"; src=""
    for d in "${SCRIPT_DIR:-}" "${LAUNCH_DIR:-}" "$STATE_DIR"; do [[ -n $d && -f $d/$name ]] && { src=$d/$name; break; }; done
    if [[ -z $src ]]; then
      [[ -f $REPO_ROOT/$rel ]] && { ok "$rel v$(agent_installer_version "$REPO_ROOT/$rel") - published earlier, kept"; n=$((n+1)); }
      continue
    fi
    if [[ -f $REPO_ROOT/$rel ]] && cmp -s "$src" "$REPO_ROOT/$rel"; then ok "$rel v$(agent_installer_version "$src") - already published"; n=$((n+1)); continue; fi
    why=""
    if [[ $name == *.sh ]]; then bash -n "$src" 2>/dev/null || why="it is not a valid bash script (bash -n failed)"
    else grep -q 'NCINGA' "$src" && grep -q 'msiexec' "$src" || why="it does not look like the NCINGA Windows agent installer"; fi
    head -c 300 "$src" | tr -d '\0' | grep -qiE '<html|<!doctype' && why="it is an HTML page, not the script"
    if [[ -n $why ]]; then warn "Not publishing $src: $why"; continue; fi
    mkdir -p "$REPO_ROOT/$dir"
    install -m "$([[ $name == *.sh ]] && echo 755 || echo 644)" "$src" "$REPO_ROOT/$rel" \
      || { warn "Could not copy $src to $REPO_ROOT/$rel"; continue; }
    ok "Published $rel v$(agent_installer_version "$src") (from $src)"; n=$((n+1))
  done
  (( n )) || hint "Place bp-agent-install-linux.sh and bp-agent-install-windows.ps1 next to this script and re-run '$0 --only collector_artefacts': log sources can then fetch them from their gateway."
  return 0
}

step_collector_artefacts() {
  local v n=0 total list
  contains_word "$STAGE_VERSIONS" "$BP_VERSION" || STAGE_VERSIONS=$(trim "$STAGE_VERSIONS $BP_VERSION")
  list=$(printf '%s\n' $STAGE_VERSIONS | sort_tags | paste -sd' ')
  total=$(wc -w <<<"$list")
  for v in $list; do
    n=$((n+1))
    section "Collector $v - $(family_label "$(family_of_version "$v")")  [$n of $total]"
    stage_collector_version "$v" || return 1
  done
  promote_currents || return 1
  write_version_info
  section "NCINGA agent installers for log sources"
  publish_agent_installers
  [[ $(state_get checksums) == "done" ]] && state_set checksums pending
  if [[ -n $(misnamed_files) ]]; then
    warn "These files carry a version under the other family's package name (renamed copies) and are ignored:"
    misnamed_files | sed "s#^$REPO_ROOT/#         #"
    hint "Remove them so LIVE gateways and log sources only see real names: rm -f $(misnamed_files | paste -sd' ')  ; then: $0 --only checksums"
  fi
  ok "Staged $total version(s) in $REPO_ROOT: $list"
  ok "Default $BP_VERSION; current v1: $(family_current v1 || true)${V2_PKG:+, current v2: $(family_current v2 || true)}"
  hint "Versions staged earlier and not selected now stay in place - to drop one, delete its files under $REPO_ROOT/packages (and windows/), then run: $0 --only checksums"
}
# configurations written before v2.0 have no STAGE_VERSIONS: keep what is staged, add nothing
migrate_config() {
  if [[ -z ${STAGE_VERSIONS:-} && -n ${BP_VERSION:-} ]]; then
    STAGE_VERSIONS=$(trim "$( { staged_list | awk '{print $2}'; echo "$BP_VERSION"; } | awk 'NF && !seen[$0]++' | sort_tags | paste -sd' ')")
    STAGE_MIGRATED=1
    info "Collector versions to keep staged: $STAGE_VERSIONS (to add v1/v2 releases: --choose-versions or --reconfigure)"
  fi
  return 0
}

# sign_rpm_repo - detached signature for repomd.xml (dnf repo_gpgcheck=1 on the isolated hosts). The packages
# themselves keep the vendor's signatures and are checked with gpgcheck=1 against the vendor key every RHEL
# host already has; this only adds integrity for the repository metadata.
sign_rpm_repo() {
  local md="$RPM_REPO_DIR/repodata/repomd.xml" fpr
  if [[ ${SIGN_RPM_REPO:-no} != yes ]]; then
    if [[ -e $md.asc ]]; then rm -f "$md.asc"; info "Removed the old repomd.xml signature (signing is disabled)"; fi
    return 0
  fi
  command -v gpg >/dev/null || { fail "gpg is not installed." "Signing was requested but gnupg2 is missing." "dnf install gnupg2 ; then retry"; return 1; }
  install -d -m 700 "$GNUPG_DIR"
  fpr=$(gpg --homedir "$GNUPG_DIR" --list-secret-keys --with-colons 2>/dev/null | awk -F: '/^fpr:/{print $10; exit}')
  if [[ -z $fpr ]]; then
    run "Generating a dedicated repository signing key (RSA 4096, 3-year expiry, stored in $GNUPG_DIR)" \
      gpg --batch --homedir "$GNUPG_DIR" --pinentry-mode loopback --passphrase '' \
          --quick-gen-key "NCINGA Bindplane Repo ($(hostname -s)) <bindplane-repo@$(hostname -s).invalid>" rsa4096 sign 3y \
      || { fail "GPG key generation failed." "See the gpg output above." "Check entropy/permissions on $GNUPG_DIR, or set signing to 'no' with --reconfigure."; return 1; }
    fpr=$(gpg --homedir "$GNUPG_DIR" --list-secret-keys --with-colons 2>/dev/null | awk -F: '/^fpr:/{print $10; exit}')
  fi
  run "Signing repomd.xml -> repomd.xml.asc" gpg --batch --yes --homedir "$GNUPG_DIR" --local-user "$fpr" --armor --detach-sign --output "$md.asc" "$md" \
    || { fail "Signing failed." "" "See the gpg output above."; return 1; }
  gpg --homedir "$GNUPG_DIR" --armor --export "$fpr" >"$RPM_REPO_KEY"
  chmod 644 "$RPM_REPO_KEY" "$md.asc"
  ok "Repository metadata signed with key $fpr"
  hint "Distribute $RPM_REPO_KEY to /etc/pki/rpm-gpg/RPM-GPG-KEY-bindplane-repo on the isolated hosts"
  hint "through your configuration-management channel (§5.4) - not over this HTTP repository."
}

# rpm_url_file URL -> local file name of a package URL (percent-decoded)
rpm_url_file() { local f=${1##*/}; printf '%b' "${f//%/\\x}"; }

step_os_repo() {
  if [[ ${BUILD_RPM_REPO:-no} != yes ]]; then
    info "Skipped by configuration: the customer's Satellite / internal RHEL mirror provides OS packages (runbook §2, 'Preferred alternative')."
    return 3
  fi
  local d=$RPM_REPO_DIR url fn n_total p sig_ok=0 out
  local -a pkgs need=() missing=() bad=() absent=()
  read -r -a pkgs <<<"$RPM_REPO_PKGS ${EXTRA_RPM_PKGS:-}"
  install -d -m 755 "$d" && cd "$d" || { fail "Cannot create or enter $d." "The repository layout is missing or the disk is full." "Run: $0 --from repo_layout"; return 1; }
  # --alldeps: the complete closure, including packages already installed HERE - the isolated hosts may be
  # more minimal than this one. --url lists the files without downloading (resume / verify, like apt --print-uris).
  run "Resolving the full dependency closure of: ${pkgs[*]}" \
      dnf -q --color=never "${DNF_PROXY_OPTS[@]}" download --resolve --alldeps --url "${pkgs[@]}" \
    || { explain_dnf_failure "$LAST_OUT"; return 1; }
  grep -E '^(https?|ftp|file)://[^[:space:]]+\.rpm$' "$LAST_OUT" | sort -u >"$RUN_TMP/rpm.urls"
  n_total=$(wc -l <"$RUN_TMP/rpm.urls")
  (( n_total )) || { fail "dnf resolved no package files." "$(head -n 3 "$LAST_OUT")" "Check: dnf repolist ; dnf download --url nginx"; return 1; }
  info "$n_total package files in the dependency closure (RHEL $OS_MAJOR, $RPM_ARCH)"
  while IFS= read -r url; do fn=$(rpm_url_file "$url"); [[ -s $fn ]] || need+=("$fn"); done <"$RUN_TMP/rpm.urls"
  info "$(( n_total - ${#need[@]} )) of $n_total package files already staged, ${#need[@]} to download"
  if (( ${#need[@]} )); then
    dnf_run "Downloading ${#need[@]} package file(s) into $d" download --resolve --alldeps --destdir "$d" "${pkgs[@]}" || return 1
  fi
  while IFS= read -r url; do fn=$(rpm_url_file "$url"); [[ -s $fn ]] || missing+=("$fn"); done <"$RUN_TMP/rpm.urls"
  if (( ${#missing[@]} )); then
    fail "${#missing[@]} package file(s) are missing after the download." "Interrupted transfer or a mirror problem: ${missing[*]:0:5}" "Choose [r] to retry - complete files are not downloaded again."
    return 1
  fi
  info "Verifying $n_total package files (digests, and signatures against the keys imported on this host)"
  while IFS= read -r url; do
    fn=$(rpm_url_file "$url")
    # a truncated or altered file is removed so that [r] downloads it again
    if ! rpm -K --nosignature "$fn" >/dev/null 2>&1; then bad+=("$fn"); rm -f "$fn"; continue; fi
    out=$(rpm -K "$fn" 2>&1); [[ $out == *"signatures OK"* ]] && sig_ok=$((sig_ok+1))
  done <"$RUN_TMP/rpm.urls"
  if (( ${#bad[@]} )); then
    fail "${#bad[@]} package file(s) failed the digest check and were removed: ${bad[*]:0:5}" \
         "Truncated transfer, or a content-rewriting proxy in the path." "Choose [r] to download them again."
    return 1
  fi
  ok "All $n_total package files are present and intact (rpm -K digests)"
  if (( sig_ok == n_total )); then ok "All $n_total packages carry a valid signature from a key imported on this host"
  else
    warn "$(( n_total - sig_ok )) of $n_total packages could not be signature-verified with the keys imported here (rpm -q gpg-pubkey)"
    hint "Packages from repositories other than the vendor's (e.g. EPEL) need that key added to gpgkey= on the isolated hosts."
  fi
  run "Building the repository metadata (createrepo_c)" createrepo_c --update "$d" \
    || { fail "createrepo_c failed." "A package in $d is corrupt, or the disk is full." "df -h $d ; then choose [r]"; return 1; }
  rpm -qp --nosignature --qf '%{NAME}\n' -- ./*.rpm 2>/dev/null | sort -u >"$RUN_TMP/rpm.names"
  for p in "${pkgs[@]}"; do grep -qxF "$p" "$RUN_TMP/rpm.names" || absent+=("$p"); done
  (( ${#absent[@]} )) && { fail "The repository does not contain: ${absent[*]}." "dnf resolved the name to a different package (a 'provides'), or the download failed." "Use the exact package name (dnf info <name>), then choose [r]."; return 1; }
  sign_rpm_repo || return 1
  write_version_info
  [[ $(state_get checksums) == "done" ]] && state_set checksums pending
  ok "dnf repository ready: $(wc -l <"$RUN_TMP/rpm.names") packages ($n_total files) in $d"
  warn "These RPMs are for RHEL $OS_MAJOR ($RPM_ARCH, $(os_field PRETTY_NAME)). The isolated hosts must run the SAME major release."
}

step_checksums() {
  local bad
  cd "$REPO_ROOT" || { fail "Cannot enter $REPO_ROOT." "" "Run: $0 --from repo_layout"; return 1; }
  bad=$(find . -type f \( -name '*%*' -o -name '*:*' -o -name '* *' -o -name '*#*' -o -name '*\?*' \) ! -name '*.part' | head -n 5)
  if [[ -n $bad ]]; then
    fail "File names that cannot be mirrored over HTTP were found: $(tr '\n' ' ' <<<"$bad")" \
         "Names containing % : space # or ? are mangled by URL encoding; wget mirroring (§6.1) would miss them and the LIVE-side checksum check would fail." \
         "Rename or remove them, then retry."
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
  if selinux_enabled; then   # files imported with tar/mv keep their old label - nginx would answer 403
    run "Resetting SELinux labels (restorecon -R $REPO_ROOT)" restorecon -R "$REPO_ROOT" || warn "restorecon failed - check: ls -Zd $REPO_ROOT ; $0 --only selinux"
  fi
  run "Self-check (sha256sum -c SHA256SUMS)" sha256sum -c --quiet SHA256SUMS \
    || { fail "A file changed while checksums were computed." "Another process is writing into $REPO_ROOT." "Choose [r] to retry."; return 1; }
  ok "$(wc -l <SHA256SUMS) files listed in SHA256SUMS, $(du -sh "$REPO_ROOT" | cut -f1) in total"
}

# conf_is_pristine FILE - 0 when FILE is exactly as its RPM shipped it (rpm -V reports no change)
conf_is_pristine() {
  local f=$1 pkg changes
  pkg=$(rpm -qf --qf '%{NAME}\n' "$f" 2>/dev/null | head -n1)
  [[ -n $pkg && $pkg != *" "* ]] || return 1          # "file ... is not owned by any package"
  changes=$(rpm -V "$pkg" 2>/dev/null)                # captured first: rpm -V exits 1 on changes (pipefail)
  # only content changes count (S = size, 5 = digest); a touched mtime alone does not
  ! awk -v f="$f" '$NF==f && ($1 ~ /[S5]/ || $1 == "missing") {found=1} END {exit !found}' <<<"$changes"
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
  if ! rpm -q --quiet nginx; then
    dnf_run "Installing nginx (RHEL packages never start or enable a service on install)" install --setopt=install_weak_deps=False nginx || return 1
  else ok "nginx already installed ($(rpm -q nginx))"; fi
  nginx_main_config || return 1
  others=$(grep -lE '^[[:space:]]*listen[[:space:]]' /etc/nginx/conf.d/*.conf 2>/dev/null | grep -vxF "$NGINX_SITE" | xargs -r -n1 basename | tr '\n' ' ')
  [[ -n $others ]] && warn "Other nginx server configurations in /etc/nginx/conf.d will keep running: $others(make sure none listens on a wildcard address)"
  render_nginx_site >"$RUN_TMP/nginx.site"
  install -m 644 -o root -g root "$RUN_TMP/nginx.site" "$NGINX_SITE"
  selinux_restore "$NGINX_SITE"
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
  [[ $code == 200 ]] || { fail "The repository index returned HTTP ${code:-no response}." "nginx is running but cannot serve $REPO_ROOT (403 on RHEL is usually the SELinux label)." \
                             "tail $NGINX_ERROR_LOG ; ls -ldZ $REPO_ROOT   (expect httpd_sys_content_t; fix: $0 --only selinux)"; return 1; }
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
  local v
  if rpm -q --quiet haproxy; then ok "haproxy already installed ($(rpm -q haproxy))"
  else
    dnf_run "Installing haproxy" install --setopt=install_weak_deps=False haproxy || return 1
  fi
  v=$(haproxy -v 2>/dev/null | head -n1)
  [[ -n $v ]] || { fail "haproxy -v printed nothing." "The haproxy binary is missing or broken." "dnf reinstall haproxy"; return 1; }
  detect_haproxy_mode
  if [[ -n $HAPROXY_VER ]] && (( ${HAPROXY_VER%%.*} == 1 && ${HAPROXY_VER#*.} < 8 )); then
    fail "$v is too old." "The hop 1 configuration needs HAProxy 1.8 or later (ssl-min-ver, init-addr)." "RHEL 8 ships 1.8 and RHEL 9 ships 2.4 - use the RHEL AppStream package."; return 1
  fi
  ok "$v"
  if (( HAPROXY_COMPAT18 )); then
    info "HAProxy $HAPROXY_VER (RHEL 8 AppStream): hop 1 is rendered in 1.8 compatibility mode -"
    hint "log /dev/log instead of stdout; DNS servers copied from /etc/resolv.conf instead of parse-resolv-conf;"
    hint "no server-side ALPN (1.8 sends none, so the cloud answers HTTP/1.1 - what the WebSocket upgrade needs)."
    hint "Upstream 1.8 is end-of-life; Red Hat maintains it for RHEL 8. RHEL 9 ships HAProxy 2.4."
  fi
}

step_haproxy_config() {
  local new="$RUN_TMP/haproxy.cfg.new" first
  is_local_ip "$DMZ_GW_IP" || { fail "$DMZ_GW_IP is not assigned to this host." "The address changed since configuration." "Re-run with --reconfigure."; return 1; }
  [[ -s $CA_FILE ]] || { fail "CA bundle $CA_FILE is missing." "ca-certificates is not installed." "dnf reinstall ca-certificates && update-ca-trust"; return 1; }
  detect_haproxy_mode
  if (( HAPROXY_COMPAT18 )) && [[ -z $(resolv_nameservers) ]]; then
    fail "No IPv4 nameserver in /etc/resolv.conf." "HAProxy 1.8 cannot read resolv.conf itself; the script copies its IPv4 nameservers into the resolvers section." \
         "Check: cat /etc/resolv.conf ; nmcli dev show | grep -i dns   (an IPv4 DNS server is required)"; return 1
  fi
  if compgen -G "$HAPROXY_CFGDIR/*.cfg" >/dev/null && [[ $(systemctl cat haproxy 2>/dev/null) == *CFGDIR* ]]; then
    warn "The haproxy unit also loads $HAPROXY_CFGDIR/*.cfg: $(cd "$HAPROXY_CFGDIR" && printf '%s ' ./*.cfg)"
    hint "They are validated together with hop 1 and keep running - make sure none binds a wildcard address."
  fi
  # RHEL's stock haproxy.cfg is a sample with 'frontend main *:5000' - it is replaced silently (kept as .orig)
  if [[ -f $HAPROXY_CFG ]] && ! grep -q "Managed by $SCRIPT_NAME" "$HAPROXY_CFG" && ! conf_is_pristine "$HAPROXY_CFG" \
     && grep -qE '^[[:space:]]*(frontend|listen)[[:space:]]' "$HAPROXY_CFG"; then
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
  if ! run "Validating the new configuration before installing it (haproxy -c)" haproxy_check "$new"; then
    first=$(grep -m1 -F '[ALERT]' "$LAST_OUT")
    fail "haproxy -c rejected the generated configuration." \
         "First alert: ${first:-see output}\nOnly the FIRST alert is real - later ones are the parser losing its place (§3.1)." \
         "The live configuration was NOT changed. Fix the cause, then choose [r]. The candidate file is $new."
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
  grep -q 'timeout tunnel  24h' "$HAPROXY_CFG" && ok "timeout tunnel 24h present (without it every OpAMP session drops within a minute)"
  if (( HAPROXY_COMPAT18 )); then
    ok "Hop 1 configuration installed (HAProxy 1.8 mode): $DMZ_GW_IP:$OPAMP_PORT -> $BP_CLOUD_HOST:443 (TLS, SNI, Host rewrite; no ALPN = HTTP/1.1)"
    hint "DNS servers were copied from /etc/resolv.conf: $(resolv_nameservers | awk '{print $3}' | paste -sd' ') - re-run '$0 --only haproxy_config' if they change."
  else
    ok "Hop 1 configuration installed: $DMZ_GW_IP:$OPAMP_PORT -> $BP_CLOUD_HOST:443 (TLS, SNI, Host rewrite, ALPN http/1.1)"
  fi
}

step_haproxy_limits() {
  install -d -m 755 "$HAPROXY_DROPIN_DIR"
  printf '# Managed by %s - runbook §3.5\n[Service]\nLimitNOFILE=65535\n' "$SCRIPT_NAME" >"$HAPROXY_DROPIN"
  chmod 644 "$HAPROXY_DROPIN"
  run "Reloading systemd units (daemon-reload)" systemctl daemon-reload || { fail "systemctl daemon-reload failed." "" "journalctl -n 20"; return 1; }
  ok "LimitNOFILE=65535 set for haproxy (maxconn $HAPROXY_MAXCONN: keep it >= 2x the projected agent count)"
}

firewalld_active() { command -v firewall-cmd >/dev/null && [[ $(firewall-cmd --state 2>/dev/null) == running ]]; }
# fw_zone - the zone that handles traffic arriving on DMZ_GW_IP's interface (else the default zone)
fw_zone() {
  local ifc z=""
  ifc=$(iface_of_ip "$DMZ_GW_IP")
  [[ -n $ifc ]] && z=$(firewall-cmd --get-zone-of-interface="$ifc" 2>/dev/null)
  [[ -n $z ]] || z=$(firewall-cmd --get-default-zone 2>/dev/null)
  printf '%s' "$z"
}
# fw_rule SRC DST PORT - the rich rule this script adds (also the key used to find and remove it)
fw_rule() { printf 'rule family="ipv4" source address="%s" destination address="%s" port port="%s" protocol="tcp" accept' "$1" "$2" "$3"; }
fw_port_label() {
  case $1 in "$OPAMP_PORT") echo "opamp hop1" ;; "$REPO_PORT") echo "package repo" ;; "$OTLP_PORT") echo "otlp" ;; *) echo "bindplane" ;; esac
}

step_host_firewall() {
  local src port zone rule changed=0 z srcs
  if firewalld_active; then
    zone=$(fw_zone)
    [[ -n $zone ]] || { fail "Could not determine the firewalld zone for $DMZ_GW_IP." "" "firewall-cmd --get-active-zones ; firewall-cmd --get-default-zone"; return 1; }
    info "firewalld is running - adding narrowly-scoped rich rules to zone '$zone' (sources -> $DMZ_GW_IP)"
    touch "$FW_RECORD"; chmod 600 "$FW_RECORD"
    # remove rules this script added earlier that no longer match the answers
    local osrc oport odst ozone keep="$RUN_TMP/fw.keep"
    : >"$keep"
    while read -r osrc oport odst ozone; do
      [[ -n $osrc ]] || continue; odst=${odst:-$DMZ_GW_IP}; ozone=${ozone:-$zone}
      if [[ $odst == "$DMZ_GW_IP" && $ozone == "$zone" ]] && contains_word "$FW_SOURCES" "$osrc" && contains_word "$FW_PORTS" "$oport"; then
        echo "$osrc $oport $odst $ozone" >>"$keep"
      else
        if run "remove old rule $osrc -> $odst tcp/$oport (zone $ozone)" firewall-cmd --permanent --zone="$ozone" --remove-rich-rule="$(fw_rule "$osrc" "$odst" "$oport")"; then changed=1
        else warn "Could not remove it - check: firewall-cmd --zone=$ozone --list-rich-rules"; fi
      fi
    done <"$FW_RECORD"
    cp -f "$keep" "$FW_RECORD"
    for src in $FW_SOURCES; do
      for port in $FW_PORTS; do
        rule=$(fw_rule "$src" "$DMZ_GW_IP" "$port")
        if firewall-cmd --permanent --zone="$zone" --query-rich-rule="$rule" >/dev/null 2>&1; then
          ok "allow $src -> $DMZ_GW_IP tcp/$port ($(fw_port_label "$port")) - already present"
        else
          run "allow $src -> $DMZ_GW_IP tcp/$port ($(fw_port_label "$port"))" firewall-cmd --permanent --zone="$zone" --add-rich-rule="$rule" \
            || { fail "firewalld refused the rule for $src tcp/$port." "See the firewall-cmd output above." "firewall-cmd --zone=$zone --list-all"; return 1; }
          changed=1
        fi
        grep -qxF "$src $port $DMZ_GW_IP $zone" "$FW_RECORD" || echo "$src $port $DMZ_GW_IP $zone" >>"$FW_RECORD"
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
      warn "The INPUT policy is DROP but firewalld is not managing it: allow tcp/${FW_PORTS// /,} from ${FW_SOURCES} to $DMZ_GW_IP in your firewall tooling"
    fi
  fi
  info "Perimeter rules are still needed (network team):"
  say  "        internal firewall : ${LIVE_GW_IP:-LIVE_GW} -> $DMZ_GW_IP  tcp/$OPAMP_PORT (OpAMP), tcp/$OTLP_PORT (OTLP), tcp/$REPO_PORT (packages)"
  say  "        perimeter firewall: $DMZ_GW_IP -> $BP_CLOUD_HOST tcp/443 (direct, no TLS inspection)"
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
  if [[ -n $(selinux_denials) ]]; then   # running, but something (e.g. the 1.8 /dev/log logging) was denied
    warn "SELinux denied haproxy something since it started (it is running):"; selinux_denials | cut -c1-200 | sed 's/^/         /'
    hint "Inspect: ausearch -m AVC -ts recent -c haproxy | audit2why . If only logging to /dev/log is denied (HAProxy 1.8),"
    hint "the relay works but writes no log lines: ausearch -m AVC -ts recent -c haproxy | audit2allow -M bp-haproxy-log && semodule -i bp-haproxy-log.pp"
  fi
  info "Waiting for the cloud backend health check (TCP + TLS to $BP_CLOUD_HOST:443) ..."
  for i in $(seq 1 30); do
    st=$(stats_field bindplane_cloud cloud status); cs=$(stats_field bindplane_cloud cloud check_status)
    [[ $st == UP* ]] && break
    [[ $st == DOWN* && $i -ge 8 ]] && break
    sleep 1
  done
  if [[ $st == UP* ]]; then ok "Backend bindplane_cloud/cloud is UP (check: ${cs:-?})"; return 0; fi
  if [[ $st == *resolution* ]]; then
    detect_haproxy_mode
    fail "Backend bindplane_cloud/cloud is ${st} - HAProxy's own resolver cannot resolve $BP_CLOUD_HOST." \
         "The nameservers HAProxy uses ($( (( HAPROXY_COMPAT18 )) && resolv_nameservers | awk '{print $3}' | paste -sd' ' || echo 'from /etc/resolv.conf')) do not answer for $BP_CLOUD_HOST from this host." \
         "Check: getent hosts $BP_CLOUD_HOST ; cat /etc/resolv.conf$( (( HAPROXY_COMPAT18 )) && echo " ; after a DNS change: $0 --only haproxy_config")\nThen: $0 --diagnose"
    return 1
  fi
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

hop_restore() { # put the direct collector config back after a §4.4 test
  [[ -f $HOP_MARKER ]] || { HOP_TEST_ACTIVE=0; return 0; }
  if [[ ! -f $COLLECTOR_CONF.direct ]]; then
    err "Cannot restore the direct connection: $COLLECTOR_CONF.direct is missing."
    hint "Set the endpoint in $COLLECTOR_CONF back to: $(cat "$HOP_MARKER") and restart $COLLECTOR_SVC"
    return 1
  fi
  cp -p "$COLLECTOR_CONF.direct" "$COLLECTOR_CONF"
  systemctl restart "$COLLECTOR_SVC" >/dev/null 2>&1 9>&-
  if [[ $(yaml_get endpoint) == "$(cat "$HOP_MARKER")" ]]; then
    ok "Direct connection restored (endpoint: $(yaml_get endpoint)) and collector restarted"
    rm -f "$HOP_MARKER"; HOP_TEST_ACTIVE=0; return 0
  fi
  err "$(basename "$COLLECTOR_CONF") endpoint is '$(yaml_get endpoint)' after restore - expected '$(cat "$HOP_MARKER")'"
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
  [[ -r $COLLECTOR_CONF ]] || { fail "$COLLECTOR_CONF not found." "The collector is not installed here." "Complete Stage 1 first."; return 1; }
  orig=$(yaml_get endpoint)
  [[ -n $orig ]] || { fail "$(basename "$COLLECTOR_CONF") has no endpoint line." "" "Check $COLLECTOR_CONF"; return 1; }
  if [[ $orig == ws://*:$OPAMP_PORT/* ]]; then
    fail "$(basename "$COLLECTOR_CONF") already points at a relay ($orig)." "A previous test was not restored." \
         "Restore the direct copy: cp -p $COLLECTOR_CONF.direct $COLLECTOR_CONF && systemctl restart $COLLECTOR_SVC"; return 1
  fi
  cp -p "$COLLECTOR_CONF" "$COLLECTOR_CONF.direct" || { fail "Could not back up $(basename "$COLLECTOR_CONF")." "" "df -h $COLLECTOR_HOME"; return 1; }
  printf '%s\n' "$orig" >"$HOP_MARKER"; chmod 600 "$HOP_MARKER"; HOP_TEST_ACTIVE=1
  collector_set_endpoint "$relay"
  [[ $(yaml_get endpoint) == "$relay" ]] || { hop_restore; fail "Could not rewrite the endpoint in $(basename "$COLLECTOR_CONF")." "" "Inspect $COLLECTOR_CONF"; return 1; }
  ok "$(basename "$COLLECTOR_CONF") now points at $relay (backup: $COLLECTOR_CONF.direct)"
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
    errs=$(tail -n +"$((before+1))" "$COLLECTOR_LOG" 2>/dev/null | grep -iE 'error|refused|denied|timeout|unauthor|forbidden|bad handshake|status=[45]' | grep -vE "$BENIGN_LOG_RE" | sed -E 's/"stacktrace":"[^"]*"//' | tail -n 8)
    [[ -n $errs ]] && { warn "Collector log lines since the restart:"; printf '%s\n' "$errs" | redact_stream | cut -c1-220 | sed 's/^/         /'; }
  fi
  if (( connected )); then
    ok "Live tunnel through hop 1: bindplane_cloud/cloud scur=$scur"
    tunnel_census
    say "  Check the Bindplane console now: Agents -> this agent ($(hostname -s), identity $(yaml_get agent_id))."
    if ask_yn "Is it shown as Connected?" y; then console=1; fi
  fi
  info "Restoring the direct connection"
  hop_restore || { fail "The direct connection could not be restored automatically." "See the messages above." "cp -p $COLLECTOR_CONF.direct $COLLECTOR_CONF && systemctl restart $COLLECTOR_SVC"; return 1; }
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
  if grep -qiE 'unauthor|401|status=403' <<<"${errs:-}"; then
    fail "No tunnel: the collector reported an authorisation error." "The secret key in $(basename "$COLLECTOR_CONF") is not accepted through the relay." "Compare secret_key with the console (Agents -> Install Agents) and retry."
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
  local live_name="bp-gw-live-01" site_label=primary repo_block
  [[ $SITE == dr ]] && { live_name="bp-gw-drlive-01"; site_label=dr; }
  if [[ ${BUILD_RPM_REPO:-no} == yes ]]; then
    repo_block="sudo tee /etc/yum.repos.d/bindplane-local.repo >/dev/null <<'REPO'
$(local_repo_file "http://$DMZ_GW_IP:$REPO_PORT/$RPM_REPO_REL/")
REPO
$( [[ ${SIGN_RPM_REPO:-no} == yes ]] && echo "# first install $RPM_REPO_KEY as /etc/pki/rpm-gpg/RPM-GPG-KEY-bindplane-repo (via config management)" )
sudo dnf --disablerepo='*' --enablerepo=bindplane-local makecache
sudo dnf --disablerepo='*' --enablerepo=bindplane-local install -y nginx haproxy wget policycoreutils-python-utils"
  else
    repo_block="# not built here: install nginx, haproxy, wget and policycoreutils-python-utils from the customer's Satellite / internal mirror"
  fi
  cat >"$NEXT_STEPS_FILE" <<EOF
# =============================================================================
# Hand-off for the LIVE gateway ($live_name) - runbook Stages 5 and 6
# Generated by $SCRIPT_NAME (RHEL edition) on $(hostname -s) at $(date -Is)   (NCINGA internal)
# DMZ side: repository http://$DMZ_GW_IP:$REPO_PORT/  relay ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp
# =============================================================================
export DMZ_GW_IP='$DMZ_GW_IP'
export LIVE_GW_IP='$LIVE_GW_IP'
export BP_VERSION='$BP_VERSION'
export BP_CLOUD_HOST='$BP_CLOUD_HOST'
export BP_SECRET='<paste from the console - never stored in this file>'

# 5.1 path to the DMZ repository (if this fails: internal-firewall rule $live_name -> $DMZ_GW_IP tcp/$REPO_PORT)
curl -s --max-time 5 http://$DMZ_GW_IP:$REPO_PORT/ | head -20

# 5.2 dnf from the DMZ repository only (RHEL $OS_MAJOR $RPM_ARCH - the LIVE host must run the same major release).
#     Packages keep the vendor's signatures: gpgcheck=1 against the key already on every RHEL host.
$repo_block

# 5.3 SELinux on the LIVE gateway (Enforcing): label the mirror and the relay port - do not disable SELinux
sudo semanage fcontext -a -t httpd_sys_content_t '/srv/bindplane(/.*)?'
sudo semanage port -a -t http_port_t -p tcp $OPAMP_PORT     # 3001 is ntop_port_t by default; haproxy may not bind it
sudo semanage port -a -t http_port_t -p tcp $STATS_PORT     # only if the LIVE HAProxy has a stats frontend here

# 6.1 mirror the repository
sudo mkdir -p /srv/bindplane && cd /srv/bindplane
sudo wget -r -np -nH -N -R 'index.html*' http://$DMZ_GW_IP:$REPO_PORT/
sudo sha256sum -c SHA256SUMS
sudo restorecon -R /srv/bindplane

# 6.3 hop 2 backend line (rewrites nothing; keep 'timeout tunnel 24h' there too)
#     server dmz $DMZ_GW_IP:$OPAMP_PORT check
#     On RHEL 8 (HAProxy 1.8) use 'log /dev/log local0' and explicit 'nameserver' lines - no 'log stdout' / parse-resolv-conf.

# 6.3 validate the chain from the LIVE host (expect 403 with 'Via: 1.1 google')
curl -i -sS --max-time 10 --http1.1 -H 'Connection: Upgrade' -H 'Upgrade: websocket' \\
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \\
  -H "Authorization: Secret-Key \${BP_SECRET}" http://\${LIVE_GW_IP}:$OPAMP_PORT/v1/opamp | head -20

# 6.4 collector on the LIVE gateway - staged now: $(staged_list | awk '{print $2}' | paste -sd' ')
#     (default $BP_VERSION; current v1 $(family_current v1 || true), current v2 $(family_current v2 || true))
#   by hand - the local .rpm, NOT install_unix.sh (it needs the internet):
#     v1: sudo dnf --disablerepo='*' install -y /srv/bindplane/packages/observiq-otel-collector_<v1 tag>_linux_$(pkg_arch).rpm   -> manager.yaml
#     v2: sudo dnf --disablerepo='*' install -y /srv/bindplane/packages/bindplane-otel-collector_<v2 tag>_linux_$(pkg_arch).rpm  -> supervisor.yaml
#   endpoint ws://$DMZ_GW_IP:$OPAMP_PORT/v1/opamp, labels "site=$site_label,segment=$( [[ $SITE == dr ]] && echo dr-live || echo prod-live ),role=gateway"

# Watch hop 1 from the DMZ host while you test:
#   journalctl -u haproxy -f        curl -s '$STATS_URL' | awk -F, '\$1=="bindplane_cloud"{print \$1,\$2,"status="\$18,"scur="\$5}'

# Stages 8/9 - log sources of the DMZ segment use THIS gateway (repository :$REPO_PORT, OpAMP :$OPAMP_PORT); LIVE-segment
# sources use the LIVE gateway. NCINGA offline agent installers:
$( if [[ -f $REPO_ROOT/scripts/bp-agent-install-linux.sh || -f $REPO_ROOT/windows/bp-agent-install-windows.ps1 ]]; then
     echo "#   Linux (root):   curl -fsSO http://$DMZ_GW_IP:$REPO_PORT/scripts/bp-agent-install-linux.sh && sudo bash bp-agent-install-linux.sh --gateway $DMZ_GW_IP"
     echo "#   Windows (elevated PowerShell):"
     echo "#     Invoke-WebRequest http://$DMZ_GW_IP:$REPO_PORT/windows/bp-agent-install-windows.ps1 -OutFile bp-agent-install-windows.ps1 -UseBasicParsing"
     echo "#     powershell -ExecutionPolicy Bypass -File .\\bp-agent-install-windows.ps1 -Gateway $DMZ_GW_IP"
   else
     echo "#   not published yet: put bp-agent-install-linux.sh / bp-agent-install-windows.ps1 next to this script and"
     echo "#   re-run: $0 --only collector_artefacts"
   fi )
EOF
  chmod 644 "$NEXT_STEPS_FILE"
}

step_evidence() {
  local d="$EVIDENCE_DIR/pack-$RUN_TS" tarball
  mkdir -p "$d"
  {
    echo "# Evidence pack - $(hostname -s) - $(date -Is) - $SCRIPT_NAME v$SCRIPT_VERSION"
    echo "## versions"; haproxy -v 2>&1 | head -n1; nginx -v 2>&1; echo "collector $(collector_version)"; rpm -q haproxy nginx 2>&1
    echo "## OS"; os_field PRETTY_NAME; echo; uname -r
    echo "## listeners"; ss -lntp 2>/dev/null | grep -E ":($OPAMP_PORT|$OTLP_PORT|5514|$REPO_PORT|$STATS_PORT) "
    echo "## established OpAMP/OTLP sessions"; ss -tn 2>/dev/null | grep -cE ":($OPAMP_PORT|$OTLP_PORT) "
    echo "## tunnel census"; tunnel_census
    echo "## haproxy -c"; haproxy_check "$HAPROXY_CFG" 2>&1
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
  cp -f "$REPO_ROOT/SHA256SUMS" "$REPO_ROOT/VERSION-INFO" "$d/" 2>/dev/null
  [[ -r $MANAGER_YAML ]] && sed -E 's/^(secret_key:).*/\1 ***REDACTED***/' "$MANAGER_YAML" >"$d/manager.yaml.redacted"
  [[ -r $SUP_YAML ]] && sed -E 's/(Secret-Key )[^"]*/\1***REDACTED***/' "$SUP_YAML" >"$d/supervisor.yaml.redacted"
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
  local svc a e first cs st sums code p t ctx
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
    detect_haproxy_mode
    (( HAPROXY_COMPAT18 )) && say "      HAProxy $HAPROXY_VER: configuration rendered in 1.8 compatibility mode (RHEL 8)"
    if haproxy_check "$HAPROXY_CFG" >"$RUN_TMP/hc.out" 2>&1; then c_ok "haproxy -c: configuration is valid"
    else first=$(grep -m1 -F '[ALERT]' "$RUN_TMP/hc.out"); c_fail "haproxy -c: ${first:-invalid}"; hint "Only the first alert is real (§3.1)."; fi
    grep -qE '^[[:space:]]*timeout[[:space:]]+tunnel' "$HAPROXY_CFG" && c_ok "timeout tunnel is set" \
      || { c_fail "timeout tunnel is missing - agents connect then drop every ~50s"; }
    grep -qE '\\[[:space:]]*$' "$HAPROXY_CFG" && c_fail "A line ends in '\\' - HAProxy has no line continuation (§3.1)"
    grep -q 'capture request header Authorization' "$HAPROXY_CFG" && c_warn "Temporary header capture is ON - turn it off before handover: $0 --proxy-debug off"
  else c_warn "$HAPROXY_CFG not present"; fi
  if command -v nginx >/dev/null; then
    nginx -t >"$RUN_TMP/nt.out" 2>&1 && c_ok "nginx -t: configuration is valid" || c_fail "nginx -t: $(grep -m1 -E 'emerg|error' "$RUN_TMP/nt.out")"
    if [[ -f $NGINX_MAIN ]] && ! grep -q "Managed by $SCRIPT_NAME" "$NGINX_MAIN" && grep -qE '^[[:space:]]*listen[[:space:]]+(\[::\]:)?80[[:space:];]' "$NGINX_MAIN"; then
      c_warn "$NGINX_MAIN still has the stock server{} on *:80 / [::]:80"; hint "Re-run: $0 --only nginx (replaces it; the original is kept as $NGINX_MAIN.orig)"
    fi
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
  if firewalld_active; then
    c_ok "firewalld running; rich rules to ${DMZ_GW_IP:-?} in zone $(fw_zone):"
    firewall-cmd --zone="$(fw_zone)" --list-rich-rules 2>/dev/null | grep -F "\"${DMZ_GW_IP:-none}\"" | sed 's/^/        /'
  else say "      firewalld not running"; fi
  if selinux_enabled; then
    if command -v semanage >/dev/null; then
      for p in "$REPO_PORT" "$OPAMP_PORT" "$STATS_PORT"; do
        t=$(selinux_port_type "$p")
        if [[ $t == http_port_t || $t == http_cache_port_t ]]; then c_ok "SELinux: tcp/$p is $t"
        else c_fail "SELinux: tcp/$p is $t - nginx/haproxy may not bind it"; hint "$0 --only selinux"; fi
      done
    else c_warn "semanage not installed - SELinux port labels not checked (dnf install policycoreutils-python-utils)"; fi
    ctx=$(stat -c %C "$REPO_ROOT" 2>/dev/null)
    if [[ -z $ctx ]]; then :
    elif [[ $ctx == *:httpd_sys_content_t:* ]]; then c_ok "SELinux: $REPO_ROOT is httpd_sys_content_t"
    else c_fail "SELinux: $REPO_ROOT is labelled $ctx - nginx answers 403"; hint "$0 --only selinux"; fi
    [[ -n $(selinux_denials) ]] && { c_warn "Recent SELinux denials for haproxy/nginx:"; selinux_denials | cut -c1-200 | sed 's/^/        /'; }
  else say "      SELinux disabled"; fi
  if systemctl cat haproxy >/dev/null 2>&1; then
    [[ $(systemctl show haproxy -p LimitNOFILE --value 2>/dev/null) == 65535 ]] && c_ok "haproxy LimitNOFILE=65535" || c_warn "haproxy LimitNOFILE is not 65535 (§3.5)"
  fi

  section "10. Recent HAProxy log"
  journalctl -u haproxy -n 300 --no-pager -o cat 2>/dev/null | grep -E ' opamp_in |\[ALERT\]|bindplane_cloud' | tail -n 8 | cut -c1-200 | sed 's/^/      /'

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
    "Collector versions to stage" "${STAGE_VERSIONS:-$BP_VERSION}" \
    "Default version" "$BP_VERSION ($(family_label "$(family_of_version "$BP_VERSION")"))" \
    "DMZ gateway IP (bind)" "$DMZ_GW_IP${DMZ_GW_IP:+ on $(iface_of_ip "$DMZ_GW_IP")}" \
    "LIVE gateway IP" "$LIVE_GW_IP" \
    "Host-firewall sources/ports" "${FW_SOURCES:-?} -> tcp ${FW_PORTS:-?} $(firewalld_active && echo '(firewalld running)' || echo '(firewalld not running: not applied)')" \
    "HAProxy maxconn" "$HAPROXY_MAXCONN" \
    "Stage DEB / ARM64 / Windows" "${STAGE_DEB:-?} / ${STAGE_ARM64:-?} / ${STAGE_WINDOWS:-?}   (x86_64 .rpm: always)" \
    "Local dnf repository" "${BUILD_RPM_REPO:-?}${EXTRA_RPM_PKGS:+ (+ $EXTRA_RPM_PKGS)}$( [[ $SIGN_RPM_REPO == yes ]] && echo ', repomd.xml signed')$( [[ $BUILD_RPM_REPO == yes ]] && echo " -> $RPM_REPO_REL")" \
    "Download proxy" "${DL_PROXY:-none (direct)}" \
    "Pause between steps" "${PAUSE_BETWEEN_STEPS:-no}"
}

action_status() {
  init_defaults
  if load_config; then migrate_config >/dev/null; banner_line "Saved configuration ($CONF_FILE)"; show_config; else warn "No saved configuration yet"; fi
  if [[ -f $REPO_ROOT/VERSION-INFO ]]; then banner_line "Repository ($REPO_ROOT/VERSION-INFO)"; grep -E '^(current_|staged_versions)' "$REPO_ROOT/VERSION-INFO" | sed 's/^/  /'; fi
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
  say "  Record this checksum at both ends. On the receiving DMZ host (same RHEL major release: $OS_MAJOR, $RPM_ARCH):"
  say "    sha256sum -c $name.sha256 && sudo tar -xzf $name -C $(dirname "$REPO_ROOT") && sudo chmod -R a+rX $REPO_ROOT"
  say "    cd $REPO_ROOT && sudo sha256sum -c SHA256SUMS"
  if [[ -f $RPM_REPO_DIR/repodata/repomd.xml ]]; then
    say "  If that host cannot reach a RHEL repository, install the proxy software from the imported repository first"
    say "  (packages are verified with the vendor key that host already has):"
    say "    sudo dnf --disablerepo='*' --repofrompath=bindplane-import,file://$RPM_REPO_DIR \\"
    say "         --setopt=bindplane-import.gpgcheck=1 --setopt=bindplane-import.gpgkey=$(vendor_gpgkey) \\"
    say "         --setopt=bindplane-import.module_hotfixes=1 install -y nginx haproxy policycoreutils-python-utils"
  else
    say "  No local dnf repository was built here - that host needs nginx and haproxy from its own Satellite / mirror."
  fi
  say "  Then run this script there (site 'dr'). Imported artefacts are verified against SHA256SUMS instead of"
  say "  being downloaded again; if the base_packages/os_repo steps cannot reach a mirror, choose [s] - the"
  say "  imported repository already contains their output."
}

upgrade_local_collector() {
  local arch pkgf aid0 aid1 v
  arch=$(pkg_arch)
  local p; p=$(product_of_version "$BP_VERSION") || { err "$BP_VERSION is not staged"; return 1; }
  if [[ $p != "$COLLECTOR_PKG" ]]; then
    err "$BP_VERSION is the '$p' package; this host runs '$COLLECTOR_PKG'. Installing it would add a SECOND collector, not upgrade this one."
    hint "Changing collector family (v1 <-> v2) is a migration: different package, service and config file. Plan it separately."
    return 1
  fi
  pkgf="$REPO_ROOT/packages/${p}_${BP_VERSION}_linux_${arch}.rpm"
  [[ -f $pkgf ]] || { err "$pkgf is not staged (ARM64 packages are only staged when that option is on)"; return 1; }
  aid0=$(yaml_get agent_id)
  # rpm -U upgrades in place (same version: --replacepkgs reinstalls); a downgrade needs --oldpackage
  run "Installing $pkgf" rpm -U --replacepkgs "$pkgf" || { err "rpm failed - the previous version is still installed"; hint "Downgrade? rpm -U --oldpackage $pkgf"; return 1; }
  # the package swaps the binary but does not restart a running service
  run "Restarting the collector so the new binary runs" systemctl restart "$COLLECTOR_SVC"
  sleep 5
  v=$(collector_version)
  [[ $v == "$BP_VERSION" ]] && ok "Collector now reports $v" || warn "Collector reports '${v:-?}' (expected $BP_VERSION)"
  systemctl is-active --quiet "$COLLECTOR_SVC" && ok "Collector is running" || err "Collector is not running - escalate to Bindplane if an upgrade leaves it stopped (§13.3)"
  aid1=$(yaml_get agent_id)
  if [[ $aid0 == "$aid1" ]]; then ok "agent_id unchanged ($aid1)"
  else err "agent_id CHANGED ($aid0 -> $aid1): the host re-registered as a new agent - escalate to Bindplane (§13.3)"; fi
}

# --choose-versions: pick the staged versions (both families) and the default, then stage them
action_choose_versions() {
  init_defaults; load_config || { err "No saved configuration - run the full build first."; exit 1; }
  migrate_config
  snapshot_config
  banner_line "Collector versions in $REPO_ROOT"
  choose_versions || { err "Nothing changed."; exit 1; }
  save_config
  invalidate_changed
  set_proxy_opts
  FORCED[collector_artefacts]=1; FORCED[checksums]=1
  run_steps collector_artefacts checksums
  ok "Repository: $(staged_list | awk '{print $2}' | paste -sd' ') - default $BP_VERSION"
  say "  Next, on the LIVE gateway: sudo /usr/local/bin/bp-mirror-sync   (pulls only the new files, §13.3)"
}

action_fetch_version() {
  local newv=$ACTION_ARG old msg
  init_defaults; load_config || { err "No saved configuration - run the full build first."; exit 1; }
  msg=$(v_version "$newv") || { err "$msg"; exit 2; }
  [[ $newv == v* ]] || newv="v$newv"
  set_proxy_opts
  old=$BP_VERSION
  banner_line "Stage collector $newv next to $old (runbook §13.3, DMZ part)"
  say "  This makes $newv the default version. To add versions without changing the default (or to"
  say "  pick several at once), use --choose-versions instead."
  migrate_config
  contains_word "$STAGE_VERSIONS" "$newv" || STAGE_VERSIONS=$(trim "$STAGE_VERSIONS $newv")
  BP_VERSION=$newv
  FORCE_ALL=1; ADHOC=1
  run_steps collector_artefacts checksums
  ADHOC=0
  save_config
  ok "$newv is now the default version in $REPO_ROOT (previous versions are kept for rollback, §13.4)"
  if ask_yn "Upgrade THIS host's collector to $newv now (DMZ gateways are upgraded first, §13.2)?" n; then
    upgrade_local_collector
    hint "Rollback if needed: rpm -U --oldpackage $REPO_ROOT/packages/$(product_of_version "$old" || echo observiq-otel-collector)_${old}_linux_$(pkg_arch).rpm"
  fi
  say "  Next, on the LIVE gateway: sudo /usr/local/bin/bp-mirror-sync   (pulls only the delta, §13.3)"
}

action_rollback() {
  local src port others dst zone kind key mode old reload=0
  init_defaults; load_config || true
  banner_line "Rollback - back out the changes made by this script"
  say "  This will:"
  say "    - restore the collector's direct connection if a §4.4 test is pending"
  say "    - restore $HAPROXY_CFG from $HAPROXY_CFG.orig, then stop and disable haproxy"
  say "    - remove $NGINX_SITE, restore $NGINX_MAIN from .orig (stop nginx if nothing else is configured)"
  say "    - remove $HAPROXY_DROPIN, the firewalld rich rules and the SELinux labels this script added"
  say "    - clear step progress (your answers are kept)"
  say "  Packages stay installed and $REPO_ROOT is kept unless you choose to delete it."
  ask_yn "Proceed with the rollback?" n || { info "Nothing changed"; return 0; }
  [[ -f $HOP_MARKER ]] && hop_restore
  if [[ -f $HAPROXY_CFG.orig ]]; then cp -p "$HAPROXY_CFG" "$HAPROXY_CFG.rolledback-$RUN_TS" 2>/dev/null; cp -p "$HAPROXY_CFG.orig" "$HAPROXY_CFG"; selinux_restore "$HAPROXY_CFG"; ok "haproxy.cfg restored (previous copy: $HAPROXY_CFG.rolledback-$RUN_TS)"; fi
  if systemctl cat haproxy >/dev/null 2>&1; then systemctl disable --now haproxy >/dev/null 2>&1 && ok "haproxy stopped and disabled"; fi
  rm -f "$HAPROXY_DROPIN" && rmdir "$HAPROXY_DROPIN_DIR" 2>/dev/null; systemctl daemon-reload 2>/dev/null; ok "LimitNOFILE drop-in removed"
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
      [[ -n $src ]] || continue; dst=${dst:-$DMZ_GW_IP}; zone=${zone:-$(fw_zone)}
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
  if ask_yn "Also DELETE the repository contents in $REPO_ROOT (downloads would have to be repeated)?" n; then
    rm -rf --one-file-system "${REPO_ROOT:?}"/{packages,scripts,windows,apt,rpm} "$REPO_ROOT"/{SHA256SUMS,VERSION-INFO,README.txt}
    rm -f "$MANIFEST"; ok "Repository contents deleted"
  fi
  rm -f "$STATE_FILE"; ok "Step progress cleared"
  hint "Packages left installed. To remove them: dnf remove haproxy nginx"
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
    ask sel "Internal-firewall-facing address for HAProxy :$OPAMP_PORT and the repository :$REPO_PORT (number or IP)" "$def" || return 1
    if [[ $sel =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#rows[@]} )); then sel=${rows[$((sel-1))]#* }; sel=${sel%/*}; fi
    if ! msg=$(v_local_ip "$sel"); then warn "  $msg"; { (( ASSUME_YES )) || [[ -z $TTY ]]; } && return 1; continue; fi
    if [[ $(iface_of_ip "$sel") == "$defif" ]]; then
      if (( ${#rows[@]} > 1 )); then
        warn "  $sel is on the default-route interface ($defif). The runbook binds to the internal-firewall-facing interface, never the internet-facing one."
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
    say "  Secret key found in $COLLECTOR_CONF: $(mask "$DET_SECRET")"
    if ask_yn "Use this key (the one the DMZ collector already authenticates with)?" y; then BP_SECRET=$DET_SECRET
    else ask_secret BP_SECRET "Bindplane secret key (console -> Agents -> Install Agents)" || return 1; fi
  else
    ask_secret BP_SECRET "Bindplane secret key (console -> Agents -> Install Agents)" || return 1
  fi
  [[ $BP_SECRET =~ ^[0-9A-HJKMNP-TV-Z]{26}$ ]] || warn "  The key is not a 26-character ULID - double-check it (an invalid key fails exactly like a wrong one)."
  [[ -n $DET_SECRET && $BP_SECRET != "$DET_SECRET" ]] && warn "  This key differs from the one in $COLLECTOR_CONF."
  choose_versions || return 1
  choose_dmz_ip || return 1
  live_name=$([[ $SITE == dr ]] && echo bp-gw-drlive-01 || echo bp-gw-live-01)
  ask LIVE_GW_IP "LIVE gateway address ($live_name, its LIVE-facing interface)" "$LIVE_GW_IP" v_remote_ip || return 1
  if firewalld_active; then
    say "  firewalld is running here: rich rules will allow only these sources to reach $DMZ_GW_IP."
    ask FW_SOURCES "Allowed sources (IPs/CIDRs: the LIVE gateway plus any DMZ-segment log-source subnets)" "${FW_SOURCES:-$LIVE_GW_IP}" v_sources || return 1
    ask FW_PORTS "TCP ports to allow from them" "${FW_PORTS:-$OPAMP_PORT $REPO_PORT $OTLP_PORT}" v_ports || return 1
  else
    FW_SOURCES=${FW_SOURCES:-$LIVE_GW_IP}; FW_PORTS=${FW_PORTS:-"$OPAMP_PORT $REPO_PORT $OTLP_PORT"}
  fi
  ask HAPROXY_MAXCONN "HAProxy maxconn (>= 2x projected agents; 20000 supports ~10,000)" "${HAPROXY_MAXCONN:-20000}" v_maxconn || return 1
  say "  Collector artefacts to stage (§2.2 - everything the estate needs; the Linux x86_64 .rpm is always staged):"
  ask_yn_var STAGE_DEB     "  .deb for Ubuntu/Debian log sources?" yes
  ask_yn_var STAGE_ARM64   "  ARM64 packages too (.rpm; .deb and .msi when those are staged)?" yes
  ask_yn_var STAGE_WINDOWS "  Windows MSI and install_windows.ps1?" yes
  say "  OS packages for the isolated hosts (§2.3). Answer n if the customer runs Satellite or an internal RHEL mirror reachable from the LIVE segment."
  ask_yn_var BUILD_RPM_REPO "  Build the local dnf repository ($RPM_REPO_PKGS + dependencies, RHEL $OS_MAJOR $RPM_ARCH)?" yes
  if [[ $BUILD_RPM_REPO == yes ]]; then
    ask EXTRA_RPM_PKGS "  Extra RHEL packages to include (space-separated, or 'none')" "$EXTRA_RPM_PKGS" v_pkgs 1 || return 1
    ask_yn_var SIGN_RPM_REPO "  GPG-sign the repository metadata (packages keep the vendor's signatures; only if the customer requires it, §5.4)?" no
  else SIGN_RPM_REPO=no; EXTRA_RPM_PKGS=""; fi
  if (( first )); then DL_PROXY=${DL_PROXY:-$DET_PROXY}; fi
  ask DL_PROXY "Outbound proxy for downloads from this host ('none' = direct)" "$DL_PROXY" v_proxy 1 || return 1
  ask_yn_var PAUSE_BETWEEN_STEPS "Pause for confirmation between steps?" no
  return 0
}

# choose_versions - which releases to stage (both families) and which one is the default
choose_versions() {
  local staged def msg
  set_proxy_opts
  release_catalogue
  staged=$(staged_list | awk '{print $2}' | paste -sd' ')
  say ""
  say "  Collector releases (from the $CATALOGUE_SOURCE). Stage several - the LIVE gateways and log sources"
  say "  can then install any staged version, of either family. Default: the two newest v1 and v2 releases."
  if [[ -n $ARG_VERSIONS ]]; then
    MENU_TAGS=(); STAGE_VERSIONS=$(parse_selection "$ARG_VERSIONS") || { err "--versions: '$ARG_VERSIONS' is not a list of release tags"; return 1; }
    msg=$(check_tags_exist "$STAGE_VERSIONS"); [[ -z $msg ]] || { err "$msg"; return 1; }
    info "  Versions to stage (--versions): $STAGE_VERSIONS"
  else
    # first choice (or answers from before v2.0): what is staged plus the two newest v1 and v2 releases
    if [[ -z $STAGE_VERSIONS ]] || (( STAGE_MIGRATED )); then def="$STAGE_VERSIONS $(default_stage_selection)"; else def=$STAGE_VERSIONS; fi
    [[ -n $DET_VERSION ]] && ! contains_word "$def" "$DET_VERSION" && (( STAGE_MIGRATED || ${#STAGE_VERSIONS} == 0 )) && def+=" $DET_VERSION"
    def=$(printf '%s\n' $def | awk 'NF && !seen[$0]++' | paste -sd' ')
    select_versions STAGE_VERSIONS "Versions to stage (numbers, ranges or tags)" "$def" "$staged" 6 0 || return 1
  fi
  STAGE_VERSIONS=$(order_tags "$STAGE_VERSIONS")
  def=${ARG_DEFAULT:-$BP_VERSION}; [[ -n $def && $def != v* ]] && def="v$def"
  contains_word "$STAGE_VERSIONS" "$def" || def=""
  [[ -z $def && -n $DET_VERSION ]] && contains_word "$STAGE_VERSIONS" "$DET_VERSION" && def=$DET_VERSION
  [[ -z $def ]] && def=$(printf '%s\n' $STAGE_VERSIONS | grep '^v1\.' | grep -v -- - | sort_tags | tail -n1)
  [[ -z $def ]] && def=${STAGE_VERSIONS%% *}
  say "  The default version is what VERSION-INFO, the plain-named install scripts and the LIVE gateways"
  say "  offer first. Each family's newest staged version also gets the plain MSI name."
  select_one BP_VERSION "Default version" "$def" "$STAGE_VERSIONS" || return 1
  is_prerelease "$BP_VERSION" && warn "  $BP_VERSION is a PRE-RELEASE - production use needs the customer's approval"
  [[ -n $DET_VERSION && $BP_VERSION != "$DET_VERSION" ]] && info "  This host's collector runs $DET_VERSION ($COLLECTOR_FAMILY) - runbook §1.3 keeps the estate on one version where possible."
  return 0
}

config_complete() {
  local k
  for k in SITE BP_CLOUD_HOST BP_SECRET BP_VERSION STAGE_VERSIONS DMZ_GW_IP LIVE_GW_IP FW_SOURCES FW_PORTS HAPROXY_MAXCONN STAGE_DEB STAGE_ARM64 STAGE_WINDOWS BUILD_RPM_REPO PAUSE_BETWEEN_STEPS; do
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
  [BP_VERSION]="collector_artefacts checksums evidence" [STAGE_VERSIONS]="collector_artefacts checksums evidence"
  [DMZ_GW_IP]="preflight repo_layout nginx haproxy_config host_firewall haproxy_start probe_hop1 collector_via_hop1 checksums evidence"
  [LIVE_GW_IP]="host_firewall evidence"
  [FW_SOURCES]="host_firewall" [FW_PORTS]="host_firewall"
  [HAPROXY_MAXCONN]="haproxy_config haproxy_start probe_hop1"
  [STAGE_DEB]="collector_artefacts checksums" [STAGE_ARM64]="collector_artefacts checksums" [STAGE_WINDOWS]="collector_artefacts checksums"
  [BUILD_RPM_REPO]="base_packages os_repo checksums" [EXTRA_RPM_PKGS]="os_repo checksums" [SIGN_RPM_REPO]="base_packages os_repo checksums"
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
  (( had )) && migrate_config
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
  if (( had && ! RECONFIGURE )) && [[ -n $ARG_VERSIONS || -n $ARG_DEFAULT ]]; then
    choose_versions || exit 1; save_config; ok "Versions saved: $STAGE_VERSIONS (default $BP_VERSION)"
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
$SCRIPT_NAME v$SCRIPT_VERSION - NCINGA internal: Bindplane DMZ gateway build (runbook Stages 2-4) for RHEL 8 / RHEL 9

Usage: sudo bash $0 [options]

Build (default): asks for the values it needs, then runs every pending step.
Re-running resumes at the first unfinished step; completed steps are skipped.
  --reconfigure        ask all questions again (previous answers are the defaults)
  --from STEP          re-run STEP and every step after it
  --only STEP          re-run just STEP (e.g. --only probe_hop1)
  --versions "LIST"    release tags to stage, both families (e.g. "v1.109.0 v1.108.1 v2.0.1-beta.6 v2.0.1-beta.5")
  --default TAG        the default version (VERSION-INFO, LIVE default, install scripts)
  --pause              pause for confirmation between steps
  -y, --yes            accept saved/default answers without prompting; quit on the first failure

Operations:
  --status             saved answers (secret masked), step progress and gate status
  --list-steps         list step names
  --diagnose           read-only health check of the whole DMZ side (troubleshooting reference)
  --choose-versions    pick the versions to stage (v1 and v2, from the GitHub release list) and the default
  --fetch-version VER  stage VER (v1 or v2) and make it the default (upgrade, §13.3); keeps old versions
  --export-repo [DIR]  tar up $REPO_ROOT for controlled transfer to the DR-DMZ host (§7.2; default /var/tmp)
  --proxy-debug on|off temporary HAProxy header capture for troubleshooting (remove before handover)
  --rollback           back out this script's changes (HAProxy/nginx config, firewalld rules, SELinux labels, drop-in)
  --reset              forget step progress (answers are kept)
  --no-color           plain output
  -h, --help           this help

Files: answers $CONF_FILE (0600) | progress $STATE_FILE | logs $LOG_DIR
Steps: ${STEPS[*]}
Collector packages: v1 observiq-otel-collector_<tag>_linux_<arch>.rpm|deb, v2 bindplane-otel-collector_<tag>_linux_<arch>.rpm|deb
Local dnf repository: $RPM_REPO_REL (RHEL $OS_MAJOR $RPM_ARCH). Add versions later with --choose-versions or --fetch-version.

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
      --versions)      need=1; ARG_VERSIONS=${2:-} ;;
      --versions=*)    ARG_VERSIONS=${1#*=} ;;
      --default)       need=1; ARG_DEFAULT=${2:-} ;;
      --default=*)     ARG_DEFAULT=${1#*=} ;;
      --status)        ACTION=status ;;
      --list-steps)    ACTION=list ;;
      --diagnose|--diag) ACTION=diagnose ;;
      --choose-versions) ACTION=choose ;;
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
  if (( HOP_TEST_ACTIVE )) || [[ -f $HOP_MARKER ]]; then warn "Restoring the collector's direct connection first ..."; hop_restore; fi
  [[ -n $CURRENT_STEP ]] && state_set "$CURRENT_STEP" interrupted
  info "Progress is saved. Re-run the script to resume${CURRENT_STEP:+ at: ${STEP_TITLE[$CURRENT_STEP]}}."
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
  [[ $ACTION == help ]] && { print_brand "$SCRIPT_NAME v$SCRIPT_VERSION - DMZ gateway build"; usage; exit 0; }
  (( EUID == 0 )) || { echo "This script must run as root:  sudo bash $0 $*" >&2; exit 1; }
  for c in systemctl journalctl ss ip awk sed grep flock sha256sum od stat df mktemp rpm; do command -v "$c" >/dev/null || miss+=" $c"; done
  [[ -z $miss ]] || { echo "Missing required commands:$miss (is this RHEL 8/9?)" >&2; exit 1; }
  case $(os_field ID) in
    ubuntu|debian) echo "This is the RHEL edition; on $(os_field PRETTY_NAME) use bp-dmz-setup.sh." >&2; exit 1 ;;
  esac

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

  print_brand "$SCRIPT_NAME v$SCRIPT_VERSION - DMZ gateway build (runbook Stages 2-4)"
  case $(installed_family) in v2) use_family v2 ;; *) use_family v1 ;; esac
  say "  Host: $(hostname -s)   Action: $ACTION   Collector here: $(family_label "$COLLECTOR_FAMILY") $(collector_version)   Log: $LOG_FILE"
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
    choose)     action_choose_versions ;;
    export)     action_export_repo ;;
    proxydebug) action_proxy_debug ;;
    rollback)   action_rollback ;;
    reset)      action_reset ;;
  esac
}

main "$@"

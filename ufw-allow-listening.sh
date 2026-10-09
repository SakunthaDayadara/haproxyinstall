#!/usr/bin/env bash
#
# ufw-allow-listening.sh
#
# Finds services listening on non-loopback interfaces and builds UFW rules for
# them. For each port you choose whether to allow it from anywhere, only from
# specific IPs/subnets, or not at all. Nothing changes until you confirm.
#
# Usage: sudo ./ufw-allow-listening.sh [-y|--yes] [-n|--dry-run] [-h|--help]

set -euo pipefail

ASSUME_YES=0
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: sudo ./ufw-allow-listening.sh [options]

Detects services listening on external interfaces and asks, port by port,
whether to allow them through UFW. Nothing is changed until you confirm.

Options:
  -y, --yes       Don't prompt; accept the default for every question
                  (allows every detected port except DHCP/mDNS client ports)
  -n, --dry-run   Ask the questions and show the plan, but change nothing
  -h, --help      Show this help
EOF
}

while (( $# > 0 )); do
  case $1 in
    -y|--yes)     ASSUME_YES=1 ;;
    -n|--dry-run) DRY_RUN=1 ;;
    -h|--help)    usage; exit 0 ;;
    *)            printf 'Unknown option: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

# ---------------------------------------------------------------------------
# Output and prompt helpers
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
  BOLD=$'\e[1m' YELLOW=$'\e[33m' RED=$'\e[31m' RESET=$'\e[0m'
else
  BOLD='' YELLOW='' RED='' RESET=''
fi

header() { printf '\n%s=== %s ===%s\n' "$BOLD" "$1" "$RESET"; }
warn()   { printf '%sWARNING:%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
die()    { printf '%sError:%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }

# ask PROMPT DEFAULT -> prints the reply (DEFAULT if empty, or always with --yes).
# Reads from /dev/tty so prompts still work inside loops that consume stdin.
ask() {
  local reply=''
  if (( ASSUME_YES )); then
    printf '%s%s\n' "$1" "$2" >&2
  else
    read -rp "$1" reply </dev/tty || true
  fi
  printf '%s\n' "${reply:-$2}"
}

# confirm QUESTION DEFAULT(y|n) -> succeeds on yes
confirm() {
  local hint='[y/N]' answer
  if [[ $2 == y ]]; then hint='[Y/n]'; fi
  answer=$(ask "$1 $hint " "$2")
  [[ ${answer,,} == y || ${answer,,} == yes ]]
}

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
RE_IPV4='^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$'
RE_IPV6='^[0-9A-Fa-f:]*:[0-9A-Fa-f:]*(/([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8]))?$'
RE_PORT='^([0-9]{1,5})(/(tcp|udp))?$'
RE_RANGE='^([0-9]{1,5}):([0-9]{1,5})/(tcp|udp)$'

valid_source() { [[ $1 =~ $RE_IPV4 || $1 =~ $RE_IPV6 ]]; }

# Accepts PORT, PORT/tcp, PORT/udp or START:END/tcp|udp
valid_port_spec() {
  local a b
  if [[ $1 =~ $RE_PORT ]]; then
    a=$((10#${BASH_REMATCH[1]}))
    (( a >= 1 && a <= 65535 ))
  elif [[ $1 =~ $RE_RANGE ]]; then
    a=$((10#${BASH_REMATCH[1]})) b=$((10#${BASH_REMATCH[2]}))
    (( a >= 1 && b <= 65535 && a < b ))
  else
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
(( EUID == 0 )) || die "Please run this script with sudo or as root."

for cmd in ufw ss awk; do
  command -v "$cmd" >/dev/null 2>&1 || die "'$cmd' not found. Install it first (sudo apt install ufw iproute2)."
done

if (( ! ASSUME_YES )) && ! { : </dev/tty; } 2>/dev/null; then
  die "No terminal available for prompts. Re-run with --yes to accept the defaults."
fi

UFW_STATUS=$(ufw status 2>/dev/null || true)
UFW_ADDED=$(ufw show added 2>/dev/null || true)
UFW_ACTIVE=0
if [[ $UFW_STATUS == *"Status: active"* ]]; then UFW_ACTIVE=1; fi

# Client-side ports whose replies UFW's built-in rules (before.rules) already accept
declare -A BUILTIN_HANDLED=(
  [68/udp]="DHCP client; UFW's built-in rules already allow DHCP replies"
  [546/udp]="DHCPv6 client; UFW's built-in rules already allow DHCPv6 replies"
  [5353/udp]="mDNS; UFW's built-in rules already allow multicast DNS"
)

# ---------------------------------------------------------------------------
# Detect listening sockets (loopback-only binds are ignored)
# ---------------------------------------------------------------------------
header "Detecting listening services"

declare -A PROCS=() ADDRS=()
KEYS=()   # "port/proto", in display order

while read -r proto port addr proc; do
  key="$port/$proto"
  if [[ -z ${PROCS[$key]+set} ]]; then
    KEYS+=("$key"); PROCS[$key]=''; ADDRS[$key]=''
  fi
  [[ ",${PROCS[$key]}," == *",$proc,"* ]] || PROCS[$key]+="${PROCS[$key]:+,}$proc"
  [[ ",${ADDRS[$key]}," == *",$addr,"* ]] || ADDRS[$key]+="${ADDRS[$key]:+,}$addr"
done < <(
  ss -tulnp | awk 'NR > 1 {
    proto = $1; laddr = $5
    port = laddr; sub(/.*:/, "", port)
    addr = laddr; sub(/:[^:]*$/, "", addr)
    if (port !~ /^[0-9]+$/) next
    if (addr ~ /^127\./ || addr ~ /^\[::1\]$/ || addr ~ /^\[::ffff:127\./ || addr ~ /%lo$/) next
    proc = "-"
    i = index($0, "users:((\"")
    if (i) { proc = substr($0, i + 9); sub(/".*/, "", proc) }
    print proto, port, addr, proc
  }' | sort -k1,1 -k2,2n
)

if (( ${#KEYS[@]} == 0 )); then
  echo "No services are listening on external interfaces. Nothing to do."
  exit 0
fi

printf '\n  %-14s %-28s %s\n' "PORT/PROTO" "PROCESS" "LISTENING ON"
for key in "${KEYS[@]}"; do
  printf '  %-14s %-28s %s\n' "$key" "${PROCS[$key]}" "${ADDRS[$key]//,/, }"
done
echo

# SSH ports: sshd's effective config (covers socket activation on newer Ubuntu,
# where the listener is owned by systemd) plus any port owned by an sshd process.
declare -A SSH_PORTS=()
if command -v sshd >/dev/null 2>&1; then
  while read -r p; do
    if [[ $p =~ ^[0-9]+$ ]]; then SSH_PORTS[$p]=1; fi
  done < <(sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }')
fi
for key in "${KEYS[@]}"; do
  if [[ $key == */tcp && ",${PROCS[$key]}," == *,sshd,* ]]; then SSH_PORTS[${key%/*}]=1; fi
done

if [[ ${PROCS[*]} == *docker-proxy* ]]; then
  warn "Docker publishes container ports through its own iptables rules, which bypass UFW. UFW rules won't restrict those ports."
fi
if grep -qs '^IPV6=no' /etc/default/ufw && [[ ${ADDRS[*]} == *'['* ]]; then
  warn "IPV6=no in /etc/default/ufw, but some services listen on IPv6. UFW won't filter that traffic."
fi

# ---------------------------------------------------------------------------
# Decide on rules
# ---------------------------------------------------------------------------
RULE_TARGET=() RULE_FROM=() RULE_COMMENT=()
add_rule() { RULE_TARGET+=("$1"); RULE_FROM+=("$2"); RULE_COMMENT+=("$3"); }

# choose_rule TARGET COMMENT DEFAULT(a|n) IS_SSH
choose_rule() {
  local target=$1 comment=$2 default=$3 is_ssh=$4 choice sources src bad
  local -a list
  while :; do
    choice=$(ask "  Allow? (a)nywhere / (s)pecific IPs or subnets / (n)o [$default]: " "$default")
    case ${choice,,} in
      a|anywhere)
        add_rule "$target" any "$comment"
        return 0 ;;
      s|specific)
        sources=$(ask "  IPs/subnets, separated by spaces or commas (e.g. 192.168.1.0/24): " "")
        read -ra list <<<"${sources//,/ }"
        if (( ${#list[@]} == 0 )); then echo "  Nothing entered."; continue; fi
        bad=''
        for src in "${list[@]}"; do
          valid_source "$src" || bad+=" $src"
        done
        if [[ -n $bad ]]; then echo "  Not a valid IP or subnet:$bad"; continue; fi
        for src in "${list[@]}"; do add_rule "$target" "$src" "$comment"; done
        if (( is_ssh )); then
          warn "Make sure the address you connect from is in that list, or you'll lose SSH access."
        fi
        return 0 ;;
      n|no)
        if (( is_ssh )) && ! confirm "  ${RED}Leave SSH port ${target%/*} closed? You may lock yourself out.${RESET}" n; then
          continue
        fi
        return 0 ;;
      *)
        echo "  Please answer a, s or n." ;;
    esac
  done
}

header "Choose what to allow"
echo "Nothing is changed until you confirm the plan at the end."

for key in "${KEYS[@]}"; do
  port=${key%/*} proto=${key#*/} procs=${PROCS[$key]}
  is_ssh=0 default=a note=''

  if [[ $proto == tcp && -n ${SSH_PORTS[$port]+set} ]]; then
    is_ssh=1; note="SSH; closing this can lock you out"
  elif [[ -n ${BUILTIN_HANDLED[$key]+set} ]]; then
    default=n; note=${BUILTIN_HANDLED[$key]}
  fi
  if [[ $procs == *docker-proxy* ]]; then
    note="published by Docker, which bypasses UFW (see warning above)"
  fi

  printf '\n%s%s%s  %s on %s\n' "$BOLD" "$key" "$RESET" "$procs" "${ADDRS[$key]//,/, }"

  if grep -Eq "^ufw allow (${port}|${key})( |\$)" <<<"$UFW_ADDED"; then
    echo "  Already allowed from anywhere; skipping."
    continue
  fi
  if [[ -n $note ]]; then echo "  Note: $note"; fi
  if grep -Eq " port ${port} proto ${proto}( |\$)" <<<"$UFW_ADDED"; then
    echo "  Note: UFW already has source-restricted rules for this port."
  fi

  comment=${procs//[^A-Za-z0-9,._-]/}
  if [[ $comment == - ]]; then comment=''; fi
  choose_rule "$key" "$comment" "$default" "$is_ssh"
done

if (( ! ASSUME_YES )); then
  header "Extra ports"
  if (( ${#SSH_PORTS[@]} == 0 )); then
    warn "No SSH server was detected. If you manage this machine remotely, add the port you connect on here."
  fi
  echo "Add ports for services that aren't running yet, e.g. 443/tcp or 6000:6010/udp."
  while :; do
    extra=$(ask "  Port to add (Enter to finish): " "")
    if [[ -z $extra ]]; then break; fi
    if ! valid_port_spec "$extra"; then
      echo "  Use PORT, PORT/tcp, PORT/udp or START:END/tcp|udp (1-65535)."
      continue
    fi
    choose_rule "$extra" "manual" a 0
  done
fi

header "Default policy"
in_policy=$(awk -F= '$1 == "DEFAULT_INPUT_POLICY" { gsub(/"/, "", $2); print $2 }' /etc/default/ufw 2>/dev/null || true)
SET_DENY=0
case $in_policy in
  DROP|REJECT)
    echo "Incoming connections are denied by default ($in_policy). Good." ;;
  *)
    echo "Default incoming policy is '${in_policy:-unknown}', so allow rules alone won't block anything."
    if confirm "Set the default incoming policy to deny?" y; then SET_DENY=1; fi ;;
esac

# ---------------------------------------------------------------------------
# Show the plan
# ---------------------------------------------------------------------------
# build_cmd INDEX -> fills CMD with the ufw arguments for that planned rule
build_cmd() {
  local target=${RULE_TARGET[$1]} from=${RULE_FROM[$1]} comment=${RULE_COMMENT[$1]}
  local port=$target proto=''
  if [[ $target == */* ]]; then port=${target%/*}; proto=${target#*/}; fi
  if [[ $from == any ]]; then
    CMD=(allow "$target")
  else
    CMD=(allow from "$from" to any port "$port")
    if [[ -n $proto ]]; then CMD+=(proto "$proto"); fi
  fi
  if [[ -n $comment ]]; then CMD+=(comment "$comment"); fi
}

# Succeeds if a planned or existing rule lets SSH in
ssh_allowed() {
  local p i
  for p in "${!SSH_PORTS[@]}"; do
    for i in "${!RULE_TARGET[@]}"; do
      if [[ ${RULE_TARGET[$i]} == "$p/tcp" || ${RULE_TARGET[$i]} == "$p" ]]; then return 0; fi
    done
    if grep -Eq "^ufw allow (${p}|${p}/tcp|OpenSSH)( |\$)| port ${p}( proto tcp)?( |\$)" <<<"$UFW_ADDED"; then
      return 0
    fi
  done
  return 1
}

header "Plan"
planned=0
for i in "${!RULE_TARGET[@]}"; do
  build_cmd "$i"
  printf '  ufw'; printf ' %q' "${CMD[@]}"; printf '\n'
  planned=1
done
if (( SET_DENY )); then echo "  ufw default deny incoming"; planned=1; fi
if (( ! UFW_ACTIVE )); then echo "  ufw --force enable"; planned=1; fi

if (( ! planned )); then
  echo "  Nothing to change."
  exit 0
fi

if (( ${#SSH_PORTS[@]} > 0 )) && ! ssh_allowed; then
  warn "No rule allows SSH (port ${!SSH_PORTS[*]}). With UFW active, new SSH connections will be blocked."
fi

if (( DRY_RUN )); then
  echo
  echo "Dry run: nothing was changed."
  exit 0
fi

if (( ! ASSUME_YES )) && ! confirm "Apply these changes?" n; then
  echo "Aborted. Nothing was changed."
  exit 0
fi

# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------
header "Applying"
backup_dir="/root/ufw-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$backup_dir"
cp -a /etc/ufw/user.rules /etc/ufw/user6.rules /etc/default/ufw "$backup_dir"/ 2>/dev/null || true
echo "Backed up the current UFW config to $backup_dir"

failed=0
for i in "${!RULE_TARGET[@]}"; do
  build_cmd "$i"
  if ! ufw "${CMD[@]}"; then
    warn "Rule failed: ufw ${CMD[*]}"
    failed=1
  fi
done

if (( SET_DENY )); then ufw default deny incoming; fi

if (( UFW_ACTIVE )); then
  echo "UFW was already active; the new rules are live."
else
  enable=1
  if (( failed )); then
    enable=0
    if (( ! ASSUME_YES )) && confirm "Some rules failed. Enable UFW anyway?" n; then enable=1; fi
  fi
  if (( enable )); then
    ufw --force enable
  else
    warn "UFW was left disabled. Fix the failed rules, then run: sudo ufw enable"
  fi
fi

header "Current UFW status"
ufw status verbose
echo
echo "To roll back: copy user.rules and user6.rules from $backup_dir to /etc/ufw/"
echo "(and 'ufw' to /etc/default/), then run: sudo ufw reload"

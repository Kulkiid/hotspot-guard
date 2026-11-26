#!/usr/bin/env bash
# ============================================================
#  🔥 HOTSPOT GUARD v3.0 - Who Is On My Hotspot?
#  Works on: Windows (Git Bash), Linux, macOS
#  Only scan networks you own (like your own phone hotspot).
# ============================================================
set -u

VERSION="3.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${HOTSPOT_GUARD_DIR:-$SCRIPT_DIR}"
KNOWN_FILE="$DATA_DIR/hotspot-known.txt"      # trusted devices: "mac  name"
HISTORY_FILE="$DATA_DIR/hotspot-history.txt"  # one line per scan
REPORT_FILE="$DATA_DIR/hotspot-report.txt"    # last scan, readable
LAST_FILE="$DATA_DIR/.hotspot-last.txt"       # MACs seen on previous scan
SEEN_FILE="$DATA_DIR/hotspot-seen.tsv"        # every device ever seen
NAMES_FILE="$DATA_DIR/.hotspot-names.cache"   # mac -> hostname cache
VENDOR_FILE="$DATA_DIR/.hotspot-vendors.cache" # oui -> vendor cache

# ---------- defaults ----------
SPEED=0; WATCH=0; TRUST=0; TRUSTALL=0; DEEP=0; CHECKPASS=1
NOTIFY=0; LOOKUP=1; REFRESH=0; LIST_DEVICES=0; RENAME=0; INCLUDE_SILENT=0
INTERVAL=30; MAXDEV=0; EXPORT=""
FORCE_SUBNET=""
USE_COLOR=1
SHOW_PROGRESS=0; [[ -t 1 ]] && SHOW_PROGRESS=1

usage() {
  cat <<EOF
Hotspot Guard v$VERSION

Usage: ./hotspot-guard.sh [options]

Scanning
  -w, --watch          Live mode: rescan repeatedly and alert on changes
  -i, --interval N     Seconds between scans in watch mode (default 30)
  -d, --deep           Scan twice (finds sleepy phones that miss one ping)
      --include-silent Also count devices that don't answer ping (may be stale!)
      --subnet A.B.C   Scan this /24 instead of auto-detecting (e.g. 192.168.43)

Names & trust
  -t, --trust          Name your devices one by one (saved as trusted)
  -T, --trust-all      Trust everything connected right now (auto-named)
      --no-vendor      Don't look up manufacturers online
      --refresh        Forget cached device names and look them up again
      --devices        Show every device ever seen (no scan)
      --rename         Menu to rename / trust / remove devices (no scan)

Alerts & output
  -n, --notify         Desktop popup when an unknown device joins / limit passed
      --max N          Warn if more than N devices are connected
  -e, --export TYPE    Save this scan as csv or json
  -s, --speed          Speed test + link quality to your phone
      --no-pass        Skip the password strength check
      --no-color       Plain output
  -h, --help           Show this help

Files are kept in: $DATA_DIR
EOF
}

# ---------- argument parsing ----------
need_val() { [[ -n "${2:-}" ]] || { echo "Option $1 needs a value (try --help)"; exit 1; }; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    -s|--speed)     SPEED=1 ;;
    -w|--watch)     WATCH=1 ;;
    -t|--trust)     TRUST=1 ;;
    -T|--trust-all) TRUSTALL=1 ;;
    -d|--deep)      DEEP=1 ;;
    --include-silent) INCLUDE_SILENT=1 ;;
    -n|--notify)    NOTIFY=1 ;;
    --no-vendor)    LOOKUP=0 ;;
    --refresh)      REFRESH=1 ;;
    --devices)      LIST_DEVICES=1 ;;
    --rename|--manage) RENAME=1 ;;
    --no-pass)      CHECKPASS=0 ;;
    --no-color)     USE_COLOR=0 ;;
    -i|--interval)  need_val "$1" "${2:-}"; INTERVAL="$2"; shift ;;
    --max)          need_val "$1" "${2:-}"; MAXDEV="$2"; shift ;;
    -e|--export)    need_val "$1" "${2:-}"; EXPORT="$2"; shift ;;
    --subnet)       need_val "$1" "${2:-}"; FORCE_SUBNET="$2"; shift ;;
    -h|--help)      usage; exit 0 ;;
    *) echo "Unknown option: $1 (try --help)"; exit 1 ;;
  esac
  shift
done

[[ "$INTERVAL" =~ ^[0-9]+$ ]] && (( INTERVAL >= 5 )) || { echo "Interval must be a number >= 5"; exit 1; }
[[ "$MAXDEV" =~ ^[0-9]+$ ]] || { echo "--max must be a number"; exit 1; }
[[ -z "$EXPORT" || "$EXPORT" == "csv" || "$EXPORT" == "json" ]] || { echo "--export must be csv or json"; exit 1; }
[[ -t 1 && -z "${NO_COLOR:-}" ]] || USE_COLOR=0

if (( USE_COLOR )); then
  GREEN=$'\033[0;32m'; RED=$'\033[0;31m'; YELLOW=$'\033[1;33m'
  CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; NC=$'\033[0m'
else
  GREEN=""; RED=""; YELLOW=""; CYAN=""; BOLD=""; NC=""
fi

# ---------- temp files, cleaned up on exit ----------
TMP="$(mktemp -d 2>/dev/null || mktemp -d -t hotspotguard)"
trap 'rm -rf "$TMP"' EXIT
CUR="$TMP/cur.txt"              # "ip mac" for devices in this scan
DEVICES="$TMP/devices.tsv"      # ip mac host vendor (tab separated)
ROWS="$TMP/rows.tsv"            # final rows for export
CUR_MACS="$TMP/cur_macs.txt"
PREV_MACS="$TMP/prev_macs.txt"
SESS_MACS="$TMP/sess_macs.txt"
REPLIED="$TMP/replied.txt"      # IPs that answered ping this scan
SILENT="$TMP/silent.txt"        # in ARP table but did NOT answer
HAVE_PREV=0; HAVE_SEEN=0
: > "$CUR"; : > "$DEVICES"; : > "$ROWS"; : > "$SESS_MACS"; : > "$REPLIED"; : > "$SILENT"
touch "$NAMES_FILE" "$VENDOR_FILE" 2>/dev/null

# ---------- OS detection ----------
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
  Darwin)               OS="mac" ;;
  Linux)                OS="linux" ;;
  *)                    OS="unknown" ;;
esac

say()  { printf '%s\n' "$*"; }
line() { say "${CYAN}-----------------------------------------------------------------------------------------${NC}"; }
TAB=$'\t'
if ( : </dev/tty ) 2>/dev/null; then TTY_IN=/dev/tty; else TTY_IN=/dev/stdin; fi

# ============================================================
#  NETWORK DETECTION
# ============================================================
detect_network() {
  MY_IP=""; GATEWAY=""

  if [[ -n "$FORCE_SUBNET" ]]; then
    BASE="$FORCE_SUBNET"
    MY_IP="${BASE}.0"; GATEWAY="${BASE}.1"
    return 0
  fi

  case "$OS" in
    windows)
      local pairs
      pairs=$(ipconfig 2>/dev/null | tr -d '\r' | awk '
        function flush() { if (ip != "") print ip, (gw == "" ? "-" : gw); ip=""; gw=""; ingw=0 }
        /^[^ ]/ { flush() }
        /IPv4/ { if (match($0, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) ip = substr($0, RSTART, RLENGTH) }
        /Default Gateway/ { ingw=1; if (match($0, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) gw = substr($0, RSTART, RLENGTH); next }
        ingw && $0 !~ /\. :/ { if (match($0, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) gw = substr($0, RSTART, RLENGTH); next }
        { ingw=0 }
        END { flush() }' | grep -Ev '^(169\.254|127\.)')
      pick_adapter "$pairs"
      ;;
    linux)
      local dev
      if command -v ip >/dev/null 2>&1; then
        GATEWAY=$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')
        dev=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')
        [[ -n "$dev" ]] && MY_IP=$(ip -4 -o addr show dev "$dev" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n 1)
      fi
      [[ -z "$MY_IP" ]] && MY_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
      ;;
    mac)
      local iface
      GATEWAY=$(route -n get default 2>/dev/null | awk '/gateway/{print $2}')
      iface=$(route -n get default 2>/dev/null | awk '/interface/{print $2}')
      [[ -n "$iface" ]] && MY_IP=$(ipconfig getifaddr "$iface" 2>/dev/null)
      ;;
  esac

  if [[ -z "$MY_IP" ]]; then
    say "${RED}❌ Not connected to a network. Connect your laptop to the phone hotspot first!${NC}"
    exit 1
  fi
  BASE="${MY_IP%.*}"
  [[ -z "$GATEWAY" || "$GATEWAY" == "-" ]] && GATEWAY="$BASE.1"
}

pick_adapter() {
  local pairs="$1" count choice n=0 best="" ip gw
  count=$(printf '%s\n' "$pairs" | grep -c .)
  if (( count == 0 )); then MY_IP=""; return; fi

  best=$(printf '%s\n' "$pairs" | grep -E '^(192\.168\.43\.|172\.20\.10\.|192\.168\.137\.)' | head -n 1)
  if [[ -z "$best" && $count -eq 1 ]]; then best="$pairs"; fi

  if [[ -z "$best" ]]; then
    say "${YELLOW}Several networks found. Which one is your hotspot?${NC}"
    while read -r ip gw; do n=$((n+1)); say "  [$n] $ip  (gateway: $gw)"; done <<<"$pairs"
    read -r -p "Choose number [1]: " choice
    choice=${choice:-1}
    best=$(printf '%s\n' "$pairs" | sed -n "${choice}p")
    [[ -z "$best" ]] && best=$(printf '%s\n' "$pairs" | head -n 1)
  fi
  MY_IP=$(awk '{print $1}' <<<"$best")
  GATEWAY=$(awk '{print $2}' <<<"$best")
}

# ============================================================
#  PASSWORD CHECKER (never saved, never sent anywhere)
# ============================================================
check_password() {
  say "${YELLOW}--- [1] HOTSPOT PASSWORD CHECK ---${NC}"
  local pass len lower pool=0 classes=0 bits unique rating color tips=""
  read -rs -p "Type your hotspot password to check it (NOT saved; Enter to skip): " pass
  echo ""
  if [[ -z "$pass" ]]; then say "Skipped."; echo ""; return; fi

  len=${#pass}
  lower=$(printf '%s' "$pass" | tr 'A-Z' 'a-z')

  [[ "$pass" =~ [a-z] ]]        && { classes=$((classes+1)); pool=$((pool+26)); }
  [[ "$pass" =~ [A-Z] ]]        && { classes=$((classes+1)); pool=$((pool+26)); }
  [[ "$pass" =~ [0-9] ]]        && { classes=$((classes+1)); pool=$((pool+10)); }
  [[ "$pass" =~ [^a-zA-Z0-9] ]] && { classes=$((classes+1)); pool=$((pool+33)); }
  (( pool < 1 )) && pool=1

  bits=$(awk -v l="$len" -v p="$pool" 'BEGIN{printf "%d", l*log(p)/log(2)}')
  unique=$(printf '%s' "$pass" | fold -w1 | sort -u | wc -l | tr -d ' ')

  case "$lower" in
    12345678|123456789|1234567890|password|password1|qwertyuiop|11111111|00000000|87654321|iloveyou|admin123|letmein|qwerty123|abcd1234|12341234)
      bits=0; tips+=$'\n  • This is one of the most common passwords in the world.' ;;
  esac
  (( unique <= 2 )) && { bits=$((bits/4)); tips+=$'\n  • Too many repeated characters.'; }
  case "$lower" in
    *12345*|*abcde*|*qwert*|*asdf*|*0000*|*1111*) bits=$((bits/2)); tips+=$'\n  • Contains an easy sequence (12345, qwerty, 1111...).' ;;
  esac
  case "$lower" in
    *hotspot*|*wifi*|*password*|*admin*) bits=$((bits/2)); tips+=$'\n  • Contains a guessable word (wifi, hotspot, password...).' ;;
  esac

  if   (( len < 8 ));  then rating="INVALID (WPA2/WPA3 needs at least 8 characters)"; color=$RED
  elif (( len > 63 )); then rating="INVALID (WPA2/WPA3 allows at most 63 characters)"; color=$RED
  elif (( bits < 28 )); then rating="VERY WEAK - change it now!"; color=$RED
  elif (( bits < 36 )); then rating="WEAK"; color=$RED
  elif (( bits < 50 )); then rating="FAIR"; color=$YELLOW
  elif (( bits < 64 )); then rating="STRONG"; color=$GREEN
  else                       rating="EXCELLENT"; color=$GREEN
  fi

  say "${color}Result: $rating${NC}  (length $len, ~${bits} bits)"
  (( len >= 8 && len < 12 )) && tips+=$'\n  • Go to 12+ characters.'
  (( classes < 3 )) && tips+=$'\n  • Mix upper/lower case, numbers and symbols.'
  [[ -n "$tips" ]] && say "Tips:$tips"
  say "  Best idea: 3-4 random unrelated words + a number, e.g. teapot-river-moon-47"
  pass=""; unset pass
  echo ""
}

# ============================================================
#  SCANNING
# ============================================================
ping_once() {
  local t="${2:-fast}"
  case "$OS" in
    windows) if [[ "$t" == slow ]]; then ping -n 1 -w 1500 "$1"; else ping -n 1 -w 300 "$1"; fi ;;
    mac)     if [[ "$t" == slow ]]; then ping -c 1 -W 1500 "$1"; else ping -c 1 -W 400 "$1"; fi ;;
    *)       if [[ "$t" == slow ]]; then ping -c 1 -W 2 "$1"; else ping -c 1 -W 1 "$1"; fi ;;
  esac
}

# A real reply contains "TTL=". (Windows ping can exit 0 even for
# "Destination host unreachable", so the exit code can't be trusted.)
ping_ok() { ping_once "$1" "${2:-fast}" 2>/dev/null | grep -qi 'ttl='; }

sweep() {
  local i
  for i in $(seq 1 254); do
    { ping_ok "$BASE.$i" && echo "$BASE.$i" >> "$REPLIED"; } >/dev/null 2>&1 &
    while (( $(jobs -r | wc -l) >= 60 )); do sleep 0.05; done
    if (( SHOW_PROGRESS && i % 10 == 0 )); then
      printf '\r%s  Scanning %s.x ... %3d%%%s' "$CYAN" "$BASE" $(( i * 100 / 254 )) "$NC"
    fi
  done
  wait
  (( SHOW_PROGRESS )) && printf '\r\033[K'
  return 0
}

normalize_mac() {
  local m o out="" first=1
  m=$(printf '%s' "$1" | tr 'A-F-' 'a-f:')
  local IFS=:
  for o in $m; do
    (( ${#o} == 1 )) && o="0$o"
    if (( first )); then out="$o"; first=0; else out="$out:$o"; fi
  done
  printf '%s' "$out"
}

collect() {
  local out l ip mac last
  if [[ "$OS" == "linux" ]] && command -v ip >/dev/null 2>&1; then
    out=$(ip -4 neigh show 2>/dev/null)
  else
    out=$(arp -a 2>/dev/null)
  fi
  while IFS= read -r l; do
    l=${l//$'\r'/}
    [[ "$l" =~ ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) ]] || continue
    ip=${BASH_REMATCH[1]}
    [[ "$l" =~ ([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2} ]] || continue
    mac=$(normalize_mac "${BASH_REMATCH[0]}")
    [[ "$ip" == "$BASE".* ]] || continue
    last=${ip##*.}
    (( last == 0 || last == 255 )) && continue
    [[ "$ip" == "$MY_IP" ]] && continue
    [[ "$mac" == "ff:ff:ff:ff:ff:ff" ]] && continue
    printf '%s %s\n' "$ip" "$mac"
  done <<<"$out" | sort -t. -k4 -n -u
}

# Keep only devices that really answer. The ARP table also remembers
# phones that already left, so retry silent ones, then split the list.
confirm_devices() {
  local ip mac
  while read -r ip mac; do
    [[ -z "$ip" ]] && continue
    grep -qx "$ip" "$REPLIED" && continue
    [[ "$ip" == "$GATEWAY" ]] && continue
    ( for _ in 1 2 3; do ping_ok "$ip" slow && { echo "$ip" >> "$REPLIED"; break; }; done ) >/dev/null 2>&1 &
  done < "$CUR"
  wait
  local ok="$TMP/confirmed.txt"
  : > "$ok"; : > "$SILENT"
  while read -r ip mac; do
    [[ -z "$ip" ]] && continue
    if [[ "$ip" == "$GATEWAY" ]] || grep -qx "$ip" "$REPLIED"; then
      echo "$ip $mac" >> "$ok"
    else
      echo "$ip $mac" >> "$SILENT"
    fi
  done < "$CUR"
  if (( INCLUDE_SILENT )); then cat "$SILENT" >> "$ok"; fi
  sort -t. -k4 -n -u "$ok" > "$CUR"
}

print_silent() {
  [[ -s "$SILENT" ]] || return 0
  (( INCLUDE_SILENT )) && return 0
  local ip mac name
  say "${YELLOW}Not answering ping (NOT counted) - asleep, firewalled, or just disconnected:${NC}"
  while read -r ip mac; do
    if ! name=$(known_name "$mac"); then name=$(cached_host "$mac") || name="-"; fi
    printf '   %-15s %-17s %s\n' "$ip" "$mac" "$name"
  done < "$SILENT"
  say "${YELLOW}  Old entries vanish after ~1-2 min. Use --include-silent to count them anyway.${NC}"
}

# ============================================================
#  DEVICE NAMES  (hostname + manufacturer + type guess)
# ============================================================

# Phones use random "private" MACs: 2nd hex digit of 1st byte is 2, 6, a or e
is_private_mac() { local c=${1:1:1}; [[ "$c" == [26ae] ]]; }

cached_host() {
  awk -F'\t' -v m="$1" '$1 == m { print $2; f = 1; exit } END { exit !f }' "$NAMES_FILE"
}

# Try several ways to learn a device's real name. Prints the name or nothing.
resolve_host() {
  local ip="$1" out n=""
  case "$OS" in
    windows)
      out=$(ping -a -n 1 -w 500 "$ip" 2>/dev/null | tr -d '\r' | head -n 3)
      n=$(sed -n 's/^Pinging \([^ ]*\) \[.*/\1/p' <<<"$out" | head -n 1)
      if [[ -z "$n" ]]; then
        n=$(nbtstat -A "$ip" 2>/dev/null | tr -d '\r' | awk '/<00>/ && /UNIQUE/ && $1 !~ /__MSBROWSE__/ {print $1; exit}')
      fi
      ;;
    linux)
      n=$(getent hosts "$ip" 2>/dev/null | awk '{print $2; exit}')
      if [[ -z "$n" ]] && command -v avahi-resolve >/dev/null 2>&1; then
        n=$(avahi-resolve -a "$ip" 2>/dev/null | awk '{print $2; exit}')
      fi
      ;;
  esac
  # Ask the phone's own DNS (it often knows the names devices gave it via DHCP)
  if [[ -z "$n" ]] && command -v nslookup >/dev/null 2>&1; then
    out=$(nslookup -timeout=2 -retry=1 "$ip" "$GATEWAY" 2>/dev/null | tr -d '\r')
    n=$(awk '/name = /{print $NF; exit} /^Name:/{print $2; exit}' <<<"$out")
  fi
  n=${n%.}; n=${n%%.*}
  case "$n" in ""|"$ip"|UnKnown|unknown|\**) return 0 ;; esac
  printf '%s' "$n"
}

# Manufacturer from the MAC prefix (cached; one online lookup per new prefix)
vendor_of() {
  local mac="$1" oui v
  if is_private_mac "$mac"; then echo "Private/random MAC"; return; fi
  oui=${mac:0:8}
  v=$(awk -F'\t' -v o="$oui" '$1 == o { print $2; exit }' "$VENDOR_FILE")
  if [[ -n "$v" ]]; then echo "$v"; return; fi
  (( LOOKUP )) || return 0
  command -v curl >/dev/null 2>&1 || return 0
  v=$(curl -s --max-time 4 "https://api.macvendors.com/${oui}" 2>/dev/null | tr -d '\r')
  sleep 1.1   # the free service allows about 1 request per second
  case "$v" in
    "")           return 0 ;;
    *'Not Found'*) printf '%s\tUnknown vendor\n' "$oui" >> "$VENDOR_FILE"; echo "Unknown vendor" ;;
    "{"*|"<"*)    return 0 ;;     # error / rate limit: don't cache
    *)            printf '%s\t%s\n' "$oui" "$v" >> "$VENDOR_FILE"; echo "$v" ;;
  esac
}

short_vendor() {
  local v="${1%%,*}"
  v=$(awk '{printf "%s%s%s", $1, (NF > 1 ? " " : ""), $2}' <<<"$v")
  printf '%s' "${v:0:18}"
}

# Best-effort icon from the name/vendor. This is a GUESS, not a fact.
guess_icon() {
  local s
  s=$(printf '%s %s' "$1" "$2" | tr 'A-Z' 'a-z')
  case "$s" in
    *iphone*|*ipad*)                                   echo "📱" ;;
    *macbook*|*imac*|*mac-mini*|*desktop-*|*laptop-*)  echo "💻" ;;
    *android*|*galaxy*|*pixel*|*redmi*|*xiaomi*|*huawei*|*honor*|*oppo*|*vivo*|*tecno*|*infinix*|*itel*|*oneplus*|*realme*|*samsung*|*motorola*|*nokia*) echo "📱" ;;
    *apple*)                                           echo "🍎" ;;
    *dell*|*lenovo*|*hewlett*|*asustek*|*acer*|*microsoft*|*intel*|*liteon*|*chicony*|*azurewave*|*realtek*) echo "💻" ;;
    *-tv*|*roku*|*chromecast*|*firestick*|*bravia*)    echo "📺" ;;
    *playstation*|*xbox*|*nintendo*)                   echo "🎮" ;;
    *printer*|*epson*|*canon*|*brother*)               echo "🖨" ;;
    *)                                                 echo "❔" ;;
  esac
}

# Fill $DEVICES with: ip <tab> mac <tab> hostname|- <tab> vendor|-
enrich() {
  : > "$DEVICES"
  local ip mac host vendor
  (( REFRESH )) && : > "$NAMES_FILE"
  REFRESH=0

  # look up hostnames for unknown devices in parallel
  while read -r ip mac; do
    [[ -z "$ip" ]] && continue
    [[ "$ip" == "$GATEWAY" ]] && continue
    cached_host "$mac" >/dev/null && continue
    ( resolve_host "$ip" > "$TMP/host.$ip" 2>/dev/null ) &
  done < "$CUR"
  wait

  while read -r ip mac; do
    [[ -z "$ip" ]] && continue
    host=$(cached_host "$mac") || host=""
    if [[ -z "$host" && -s "$TMP/host.$ip" ]]; then
      host=$(cat "$TMP/host.$ip")
      printf '%s\t%s\n' "$mac" "$host" >> "$NAMES_FILE"
    fi
    vendor=$(vendor_of "$mac")
    printf '%s\t%s\t%s\t%s\n' "$ip" "$mac" "${host:--}" "${vendor:--}" >> "$DEVICES"
  done < "$CUR"
}

# ============================================================
#  KNOWN / TRUSTED DEVICES
# ============================================================
known_count() { [[ -f "$KNOWN_FILE" ]] && grep -Evc '^[[:space:]]*(#|$)' "$KNOWN_FILE" || echo 0; }

known_name() {
  [[ -f "$KNOWN_FILE" ]] || return 1
  awk -v m="$1" '
    /^[[:space:]]*#/ || NF == 0 { next }
    { k = tolower($1); gsub("-", ":", k)
      if (k == m) { $1 = ""; sub(/^ +/, ""); print ($0 == "" ? "trusted" : $0); found = 1; exit } }
    END { exit !found }' "$KNOWN_FILE"
}

# Best human label for a MAC: trusted name > hostname > vendor > unknown
label_for() {
  local m="$1" n h v
  if n=$(known_name "$m"); then echo "$n"; return; fi
  h=$(awk -F'\t' -v m="$m" '$2 == m && $3 != "-" { print $3; exit }' "$DEVICES")
  v=$(awk -F'\t' -v m="$m" '$2 == m && $4 != "-" { print $4; exit }' "$DEVICES")
  if [[ -z "$h" && -s "$SEEN_FILE" ]]; then
    h=$(awk -F'\t' -v m="$m" '$1 == m && $5 != "-" { print $5; exit }' "$SEEN_FILE")
    v=$(awk -F'\t' -v m="$m" '$1 == m && $6 != "-" { print $6; exit }' "$SEEN_FILE")
  fi
  if [[ -n "$h" ]]; then echo "$h"
  elif [[ -n "$v" && "$v" != Private* && "$v" != Unknown* ]]; then echo "$(short_vendor "$v") device"
  else echo "unknown device"; fi
}

trust_devices() {
  local auto="$1"
  if [[ "$auto" == "1" ]]; then
    say "${YELLOW}--- TRUST ALL: saving everything connected right now ---${NC}"
  else
    say "${YELLOW}--- TRUST MODE: name your devices ---${NC}"
    say "Enter = accept the suggestion, ${BOLD}-${NC} = skip this one, ${BOLD}s${NC} = stop."
  fi
  [[ -f "$KNOWN_FILE" ]] || printf '# Hotspot Guard trusted devices\n# format: mac  name\n' > "$KNOWN_FILE"

  local ip mac host vendor suggest name added=0
  while IFS=$'\t' read -r ip mac host vendor; do
    [[ -z "$ip" || "$ip" == "$GATEWAY" ]] && continue
    known_name "$mac" >/dev/null && continue
    if [[ "$host" != "-" ]]; then suggest="$host"
    elif [[ "$vendor" != "-" && "$vendor" != Private* && "$vendor" != Unknown* ]]; then suggest="$(short_vendor "$vendor") device"
    else suggest="device-$(printf '%s' "${mac: -5}" | tr ':' '-')"; fi

    if [[ "$auto" == "1" ]]; then
      name="$suggest"
    else
      read -r -p "  $ip  $mac  name [$suggest]: " name <"$TTY_IN"
      [[ "$name" == "s" ]] && break
      [[ "$name" == "-" ]] && continue
      [[ -z "$name" ]] && name="$suggest"
    fi
    printf '%s  %s\n' "$mac" "$name" >> "$KNOWN_FILE"
    say "  ${GREEN}✅ saved${NC} $mac  $name"
    added=$((added+1))
  done < "$DEVICES"
  say "${GREEN}$added device(s) added to $KNOWN_FILE${NC}"
  echo ""
}

# ============================================================
#  OUTPUT
# ============================================================
TOTAL=0; UNKNOWN=0; NEWCNT=0; JOINED=0; LEFT=0; UJOINED=0
SELF_NAME="$(hostname 2>/dev/null || echo laptop)"

print_table() {
  local ip mac host vendor name vshort icon tag status kc lowinfo=0
  TOTAL=0; UNKNOWN=0; NEWCNT=0
  : > "$ROWS"
  kc=$(known_count)
  line
  say "${CYAN}${BOLD}$(printf '   %-15s %-22s %-18s %-17s %s' IP NAME MANUFACTURER MAC STATUS)${NC}"
  line
  printf '💻 %-15s %-22s %-18s %-17s %s\n' "$MY_IP" "${SELF_NAME:0:22}" "-" "-" "You"

  while IFS=$'\t' read -r ip mac host vendor; do
    [[ -z "$ip" ]] && continue
    vshort="-"; [[ "$vendor" != "-" && "$vendor" != Private* ]] && vshort=$(short_vendor "$vendor")

    if [[ "$ip" == "$GATEWAY" ]]; then
      printf '📱 %-15s %-22s %-18s %-17s %s\n' "$ip" "Hotspot phone" "$vshort" "$mac" "(your phone)"
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$ip" "$mac" "Hotspot phone" "$host" "$vendor" "gateway" >> "$ROWS"
      continue
    fi

    TOTAL=$((TOTAL+1))
    status="listed"
    if name=$(known_name "$mac"); then
      tag="${GREEN}✅ trusted${NC}"; status="trusted"
    else
      if [[ "$host" != "-" ]]; then name="$host"
      elif [[ "$vendor" != "-" && "$vendor" != Private* && "$vendor" != Unknown* ]]; then name="$vshort device"
      else name="Unknown device"; lowinfo=1; fi
      if (( kc > 0 )); then tag="${RED}❓ UNKNOWN${NC}"; UNKNOWN=$((UNKNOWN+1)); status="unknown"; else tag="•"; fi
    fi
    if (( HAVE_SEEN )) && ! grep -q "^$mac" "$SEEN_FILE" 2>/dev/null; then
      tag="$tag ${YELLOW}🆕 NEW${NC}"; NEWCNT=$((NEWCNT+1)); status="$status,new"
    fi
    is_private_mac "$mac" && tag="$tag ${CYAN}(private MAC)${NC}"

    icon=$(guess_icon "$name $host" "$vendor")
    printf '%s %-15s %-22s %-18s %-17s %s\n' "$icon" "$ip" "${name:0:22}" "$vshort" "$mac" "$tag"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$ip" "$mac" "$name" "$host" "$vendor" "$status" >> "$ROWS"
  done < "$DEVICES"

  line
  say "Devices connected (besides you): ${BOLD}$TOTAL${NC}   Unknown: ${BOLD}$UNKNOWN${NC}   New: ${BOLD}$NEWCNT${NC}"
  (( kc == 0 )) && say "${YELLOW}Tip: run with --trust (or --trust-all) to save your own devices, then strangers stand out.${NC}"
  if (( lowinfo )); then
    say "${YELLOW}Tip: 'Unknown device' = the phone hides its name and uses a private MAC.${NC}"
    say "${YELLOW}     Name it once with --trust, or turn off 'Private Wi-Fi address' on that device.${NC}"
  fi
}

report_changes() {
  JOINED=0; LEFT=0; UJOINED=0
  (( HAVE_PREV )) || return 0
  local m ip lbl kc; kc=$(known_count)
  while read -r m; do
    [[ -z "$m" ]] && continue
    ip=$(awk -v m="$m" '$2 == m {print $1}' "$CUR")
    lbl=$(label_for "$m")
    JOINED=$((JOINED+1))
    if known_name "$m" >/dev/null; then
      say "${GREEN}➕ JOINED: $lbl  ($ip, $m)${NC}"
    else
      say "${RED}➕ JOINED: $lbl  ($ip, $m)  - not on your trusted list${NC}"
      if (( kc > 0 )); then
        UJOINED=$((UJOINED+1)); printf '\a'
        notify "Hotspot Guard: unknown device" "$lbl joined ($ip)"
      fi
    fi
  done < <(comm -13 "$PREV_MACS" "$CUR_MACS")
  while read -r m; do
    [[ -z "$m" ]] && continue
    LEFT=$((LEFT+1))
    say "${YELLOW}➖ LEFT:   $(label_for "$m")  ($m)${NC}"
  done < <(comm -23 "$PREV_MACS" "$CUR_MACS")
}

check_max() {
  (( MAXDEV > 0 && TOTAL > MAXDEV )) || return 0
  say "${RED}⚠️  $TOTAL devices connected - your limit is $MAXDEV. Someone may be using your data!${NC}"
  printf '\a'
  notify "Hotspot Guard: device limit" "$TOTAL devices connected (limit $MAXDEV)"
}

notify() {
  (( NOTIFY )) || return 0
  local title="${1//[\'\"]/}" msg="${2//[\'\"]/}"
  case "$OS" in
    windows)
      powershell.exe -NoProfile -Command "Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; \$n = New-Object System.Windows.Forms.NotifyIcon; \$n.Icon = [System.Drawing.SystemIcons]::Warning; \$n.Visible = \$true; \$n.ShowBalloonTip(6000, '$title', '$msg', [System.Windows.Forms.ToolTipIcon]::Warning); Start-Sleep 7; \$n.Dispose()" >/dev/null 2>&1 &
      disown 2>/dev/null ;;
    linux) command -v notify-send >/dev/null 2>&1 && notify-send "$title" "$msg" ;;
    mac)   osascript -e "display notification \"$msg\" with title \"$title\"" >/dev/null 2>&1 ;;
  esac
  return 0
}

# ============================================================
#  DEVICE HISTORY (everything ever seen)
# ============================================================
update_seen() {
  local now; now=$(date '+%Y-%m-%d %H:%M:%S')
  [[ -f "$SEEN_FILE" ]] || : > "$SEEN_FILE"
  awk -F'\t' -v OFS='\t' -v now="$now" '
    FILENAME == ARGV[1] { first[$1]=$2; last[$1]=$3; n[$1]=$4; host[$1]=$5; ven[$1]=$6; order[++k]=$1; next }
    { m=$2
      if (!(m in first)) { first[m]=now; n[m]=0; order[++k]=m }
      last[m]=now; n[m]++
      if ($3 != "-") host[m]=$3
      if ($4 != "-") ven[m]=$4 }
    END { for (i=1; i<=k; i++) { m=order[i]
            print m, first[m], last[m], n[m], (host[m]==""?"-":host[m]), (ven[m]==""?"-":ven[m]) } }
  ' "$SEEN_FILE" "$DEVICES" > "$SEEN_FILE.tmp" && mv "$SEEN_FILE.tmp" "$SEEN_FILE"
}

list_devices() {
  if [[ ! -s "$SEEN_FILE" ]]; then say "No devices recorded yet. Run a scan first."; return; fi
  line
  say "${CYAN}${BOLD}$(printf '%-17s %-22s %-19s %-19s %s' MAC NAME 'FIRST SEEN' 'LAST SEEN' SCANS)${NC}"
  line
  local mac first last n host vendor name tag
  : > "$DEVICES"
  while IFS=$'\t' read -r mac first last n host vendor; do
    if name=$(known_name "$mac"); then tag="✅"
    else
      if [[ "$host" != "-" ]]; then name="$host"
      elif [[ "$vendor" != "-" && "$vendor" != Private* && "$vendor" != Unknown* ]]; then name="$(short_vendor "$vendor") device"
      else name="Unknown device"; fi
      tag="  "
    fi
    printf '%-17s %-22s %-19s %-19s %s %s\n' "$mac" "${name:0:22}" "$first" "$last" "$n" "$tag"
  done < <(sort -t "$TAB" -k3,3r "$SEEN_FILE")
  line
  say "$(wc -l < "$SEEN_FILE" | tr -d ' ') device(s) recorded in $SEEN_FILE"
}

# ============================================================
#  EXPORT / SAVE
# ============================================================
csvq()  { local s="${1//\"/\"\"}"; printf '"%s"' "$s"; }
jsonq() { local s="${1//\\/\\\\}"; s="${s//\"/\\\"}"; printf '"%s"' "$s"; }

export_scan() {
  local f ip mac name host vendor status first=1
  f="$DATA_DIR/hotspot-export-$(date +%Y%m%d-%H%M%S).$EXPORT"
  if [[ "$EXPORT" == "csv" ]]; then
    {
      echo "ip,mac,name,hostname,manufacturer,status"
      while IFS=$'\t' read -r ip mac name host vendor status; do
        [[ "$host" == "-" ]] && host=""; [[ "$vendor" == "-" ]] && vendor=""
        printf '%s,%s,%s,%s,%s,%s\n' "$(csvq "$ip")" "$(csvq "$mac")" "$(csvq "$name")" "$(csvq "$host")" "$(csvq "$vendor")" "$(csvq "$status")"
      done < "$ROWS"
    } > "$f"
  else
    {
      printf '{\n  "scanned_at": %s,\n  "devices": [' "$(jsonq "$(date '+%Y-%m-%d %H:%M:%S')")"
      while IFS=$'\t' read -r ip mac name host vendor status; do
        [[ "$host" == "-" ]] && host=""; [[ "$vendor" == "-" ]] && vendor=""
        (( first )) || printf ','
        first=0
        printf '\n    {"ip": %s, "mac": %s, "name": %s, "hostname": %s, "manufacturer": %s, "status": %s}' \
          "$(jsonq "$ip")" "$(jsonq "$mac")" "$(jsonq "$name")" "$(jsonq "$host")" "$(jsonq "$vendor")" "$(jsonq "$status")"
      done < "$ROWS"
      printf '\n  ]\n}\n'
    } > "$f"
  fi
  say "${CYAN}[Exported to $(basename "$f")]${NC}"
}

save_outputs() {
  printf '%s - Total: %s - Unknown: %s - New: %s - Joined: %s - Left: %s\n' \
    "$(date '+%Y-%m-%d %H:%M:%S')" "$TOTAL" "$UNKNOWN" "$NEWCNT" "$JOINED" "$LEFT" >> "$HISTORY_FILE"
  {
    echo "Hotspot Guard report - $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Laptop: $MY_IP   Phone/Gateway: $GATEWAY"
    sed $'s/\033\\[[0-9;]*m//g' "$TMP/table.out"
  } > "$REPORT_FILE"
  cp "$CUR_MACS" "$LAST_FILE"
  update_seen
}

# ============================================================
#  SPEED + LINK QUALITY
# ============================================================
link_quality() {
  local out loss avg
  case "$OS" in
    windows)
      out=$(ping -n 5 "$GATEWAY" 2>/dev/null | tr -d '\r')
      loss=$(grep -oE '[0-9]+% loss' <<<"$out" | head -n 1 | grep -oE '^[0-9]+')
      avg=$(grep -oE 'Average = [0-9]+ms' <<<"$out" | grep -oE '[0-9]+') ;;
    *)
      out=$(ping -c 5 "$GATEWAY" 2>/dev/null)
      loss=$(grep -oE '[0-9.]+% packet loss' <<<"$out" | head -n 1 | grep -oE '^[0-9.]+')
      avg=$(awk -F'/' '/min\/avg\/max/ {print $5}' <<<"$out") ;;
  esac
  if [[ -z "$avg" ]]; then say "Link to phone:    no reply from $GATEWAY"; return; fi
  say "Link to phone:    ${avg} ms average, ${loss:-0}% packet loss  (weak signal = high ms / loss)"
}

speed_test() {
  say "${YELLOW}--- [Speed Test] ---${NC}"
  link_quality
  if ! command -v curl >/dev/null 2>&1; then say "${RED}curl not found - skipping download test.${NC}"; return; fi
  local res
  res=$(curl -s -o /dev/null --max-time 20 \
        -w '%{time_connect} %{speed_download} %{size_download}' \
        "https://speed.cloudflare.com/__down?bytes=10000000" 2>/dev/null)
  if [[ -z "$res" ]] || [[ "$(awk '{print $3}' <<<"$res")" == "0" ]]; then
    say "${RED}Speed test failed (no internet or blocked).${NC}"; return
  fi
  awk -v r="$res" 'BEGIN{
    split(r, a, " ")
    printf "Internet latency: %.0f ms\nDownload speed:   %.1f Mbps\n", a[1]*1000, a[2]*8/1000000 }'
  echo ""
}

# ============================================================
#  RENAME / MANAGE DEVICES (no sed needed)
# ============================================================
# Save or replace the trusted name for one MAC
set_trusted_name() {
  local mac="$1" name="$2" tmp="$KNOWN_FILE.tmp"
  [[ -f "$KNOWN_FILE" ]] || printf '# Hotspot Guard trusted devices\n# format: mac  name\n' > "$KNOWN_FILE"
  awk -v m="$mac" '
    /^[[:space:]]*#/ || NF == 0 { print; next }
    { k = tolower($1); gsub("-", ":", k); if (k != m) print }' "$KNOWN_FILE" > "$tmp"
  printf '%s  %s\n' "$mac" "$name" >> "$tmp"
  mv "$tmp" "$KNOWN_FILE"
}

remove_trusted() {
  local mac="$1" tmp="$KNOWN_FILE.tmp"
  [[ -f "$KNOWN_FILE" ]] || return 0
  awk -v m="$mac" '
    /^[[:space:]]*#/ || NF == 0 { print; next }
    { k = tolower($1); gsub("-", ":", k); if (k != m) print }' "$KNOWN_FILE" > "$tmp"
  mv "$tmp" "$KNOWN_FILE"
}

manage_devices() {
  local list="$TMP/manage.txt" ans n mac cur_name last trusted new i
  : > "$DEVICES"
  while true; do
    # every device ever seen (newest first), then trusted ones never seen
    : > "$list"
    [[ -s "$SEEN_FILE" ]] && sort -t "$TAB" -k3,3r "$SEEN_FILE" | cut -f1 >> "$list"
    if [[ -f "$KNOWN_FILE" ]]; then
      awk '/^[[:space:]]*#/ || NF == 0 { next } { k = tolower($1); gsub("-", ":", k); print k }' "$KNOWN_FILE" |
        while read -r mac; do grep -qx "$mac" "$list" || echo "$mac" >> "$list"; done
    fi
    if [[ ! -s "$list" ]]; then say "No devices yet. Run a scan first (bash hotspot-guard.sh)."; return; fi

    line
    say "${CYAN}${BOLD}$(printf '%-4s %-17s %-24s %-10s %s' '#' MAC NAME STATUS 'LAST SEEN')${NC}"
    line
    i=0
    while read -r mac; do
      i=$((i+1))
      if cur_name=$(known_name "$mac"); then trusted="${GREEN}✅ trusted${NC}"
      else cur_name=$(label_for "$mac"); trusted="not trusted"; fi
      last=$(awk -F'\t' -v m="$mac" '$1 == m { print $3; exit }' "$SEEN_FILE" 2>/dev/null)
      printf '%-4s %-17s %-24s %-10s %s\n' "[$i]" "$mac" "${cur_name:0:24}" "$trusted" "${last:--}"
    done < "$list"
    line
    say "Type a ${BOLD}number${NC} to rename/trust it, ${BOLD}d<number>${NC} to remove it from trusted (e.g. d2), ${BOLD}q${NC} to quit."
    read -r -p "> " ans <"$TTY_IN" || return
    case "$ans" in
      ""|q|Q) say "${GREEN}Done.${NC}"; return ;;
      d[0-9]*|D[0-9]*)
        n=${ans:1}; mac=$(sed -n "${n}p" "$list")
        if [[ -z "$mac" ]]; then say "${RED}No device #$n${NC}"; continue; fi
        remove_trusted "$mac"; say "${YELLOW}Removed $mac from trusted list.${NC}" ;;
      [0-9]*)
        mac=$(sed -n "${ans}p" "$list")
        if [[ -z "$mac" ]]; then say "${RED}No device #$ans${NC}"; continue; fi
        cur_name=$(known_name "$mac" || label_for "$mac")
        read -r -p "New name for $mac [$cur_name]: " new <"$TTY_IN"
        new=${new:-$cur_name}
        if [[ -z "$new" ]]; then continue; fi
        set_trusted_name "$mac" "$new"
        say "${GREEN}✅ Saved: $mac = $new${NC}" ;;
      *) say "${RED}Not understood.${NC}" ;;
    esac
  done
}

# ============================================================
#  MAIN
# ============================================================
if [[ "${HG_SOURCE_ONLY:-}" == "1" ]]; then return 0 2>/dev/null || exit 0; fi

if (( LIST_DEVICES )); then list_devices; exit 0; fi
if (( RENAME )); then manage_devices; exit 0; fi

detect_network

say "${CYAN}=========================================================${NC}"
say "${CYAN}  🔥 HOTSPOT GUARD v$VERSION - Who Is On My Hotspot?${NC}"
say "${CYAN}=========================================================${NC}"
say "${GREEN}Your laptop:     $MY_IP  ($SELF_NAME)${NC}"
say "${GREEN}Hotspot (phone): $GATEWAY   Scanning: $BASE.1 - $BASE.254${NC}"
echo ""

(( CHECKPASS && ! WATCH )) && check_password

[[ -f "$LAST_FILE" ]] && { cp "$LAST_FILE" "$PREV_MACS"; HAVE_PREV=1; }
[[ -s "$SEEN_FILE" ]] && HAVE_SEEN=1

# one full scan + report cycle
do_scan() {
  : > "$REPLIED"
  sweep
  (( DEEP )) && sweep
  collect > "$CUR"
  confirm_devices
  awk '{print $2}' "$CUR" | sort -u > "$CUR_MACS"
  (( SHOW_PROGRESS )) && printf '%s  Looking up device names...%s' "$CYAN" "$NC"
  enrich
  (( SHOW_PROGRESS )) && printf '\r\033[K'
  { print_table; print_silent; } > "$TMP/table.out"
}

say "${YELLOW}--- [2] DEVICE SCAN ---${NC}"
do_scan
cat "$TMP/table.out"
report_changes
check_max
save_outputs
[[ -n "$EXPORT" ]] && export_scan
say "${CYAN}[Saved: $(basename "$HISTORY_FILE"), $(basename "$REPORT_FILE"), $(basename "$SEEN_FILE")]${NC}"
echo ""

if (( TRUSTALL )); then trust_devices 1
elif (( TRUST )); then trust_devices 0; fi
(( SPEED )) && speed_test

if (( WATCH )); then
  say "${YELLOW}🔴 LIVE WATCH MODE - rescanning every ${INTERVAL}s. Press Ctrl+C to stop.${NC}"
  SCANS=1; SESS_JOINS=0; SESS_LEFT=0; SESS_ALERTS=0
  cp "$CUR_MACS" "$SESS_MACS"
  trap 'echo; say "${CYAN}Session summary: $SCANS scans, $(sort -u "$SESS_MACS" | wc -l | tr -d " ") different device(s) seen, $SESS_JOINS joined, $SESS_LEFT left, $SESS_ALERTS unknown-device alert(s). Stay safe! 🔒${NC}"; exit 0' INT
  while true; do
    sleep "$INTERVAL"
    cp "$CUR_MACS" "$PREV_MACS"; HAVE_PREV=1
    [[ -s "$SEEN_FILE" ]] && HAVE_SEEN=1
    SHOW_PROGRESS=0
    do_scan
    SCANS=$((SCANS+1))
    report_changes
    SESS_JOINS=$((SESS_JOINS+JOINED)); SESS_LEFT=$((SESS_LEFT+LEFT)); SESS_ALERTS=$((SESS_ALERTS+UJOINED))
    cat "$CUR_MACS" >> "$SESS_MACS"
    if (( JOINED + LEFT > 0 )); then cat "$TMP/table.out"
    else say "$(date +%H:%M:%S) - $TOTAL device(s), no changes"; fi
    check_max
    save_outputs
    [[ -n "$EXPORT" ]] && export_scan
  done
fi

say "${CYAN}Done! ✅${NC}"

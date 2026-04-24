#!/bin/bash
# RawonGuard Anti-Backdoor Cleaner v2
# Usage: bash <(curl -fsSL https://raw.githubusercontent.com/bssn1337/clean/main/service.sh)

[ -f "$0" ] && sed -i 's/\r$//' "$0" 2>/dev/null || true
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
info() { echo -e "${CYAN}    →${NC} $*"; }
err()  { echo -e "${RED}[x]${NC} $*"; }

# ── Hardcoded known targets ───────────────────────────────────────────────────
REMOVE_SERVICES=(defunct gs-dbus)
REMOVE_BINARIES=(/usr/bin/defunct /usr/bin/gs-dbus)
REMOVE_FILES=(/lib/systemd/system/defunct.dat)

# ── Dynamic detection ─────────────────────────────────────────────────────────
log "Scanning for suspicious systemd services..."

while IFS= read -r svc_file; do
  [ -f "$svc_file" ] || continue

  # Detect by: GS_ARGS, GS_HOST, atau exec -a dengan nama kernel thread/service palsu
  if grep -qE 'GS_ARGS=|GS_HOST=|exec -a '"'"'\[' "$svc_file" 2>/dev/null; then
    svc_name=$(basename "$svc_file" .service)
    warn "Suspicious service: ${svc_name} (${svc_file})"

    # Skip jika sudah ada di list
    already=0
    for s in "${REMOVE_SERVICES[@]}"; do [ "$s" = "$svc_name" ] && already=1 && break; done
    [ "$already" -eq 1 ] && continue

    REMOVE_SERVICES+=("$svc_name")

    # Ekstrak path binary: cari '/usr/bin/...' atau '/usr/local/bin/...' terakhir di ExecStart
    bin=$(grep -m1 'ExecStart' "$svc_file" \
          | grep -oP "'(/usr(?:/local)?/bin/[^']+)'" \
          | tail -1 | tr -d "'" 2>/dev/null || true)
    if [ -n "$bin" ]; then
      info "Binary: $bin"
      REMOVE_BINARIES+=("$bin")
    fi

    # Ekstrak path -k dat/log dari GS_ARGS
    dat=$(grep -m1 'ExecStart' "$svc_file" \
          | grep -oP '(?<=-k )[^ "'"'"']+' | head -1 2>/dev/null || true)
    if [ -n "$dat" ]; then
      info "Data file: $dat"
      REMOVE_FILES+=("$dat")
    fi
  fi
done < <(find /etc/systemd/system /lib/systemd/system -maxdepth 2 -name "*.service" 2>/dev/null || true)

echo ""
log "Targets:"
info "Services : ${REMOVE_SERVICES[*]}"
info "Binaries : ${REMOVE_BINARIES[*]}"
info "Files    : ${REMOVE_FILES[*]}"
echo ""

# ── Kill proses yang sedang berjalan ──────────────────────────────────────────
log "Killing running backdoor processes..."

for bin in "${REMOVE_BINARIES[@]}"; do
  [ -z "$bin" ] && continue
  base=$(basename "$bin")

  # Kill via pkill (by name)
  pkill -9 -f "$base" 2>/dev/null && info "Killed by name: $base" || true

  # Kill via /proc/*/exe (tangkap proses yang pakai exec -a untuk ganti nama)
  for exe_link in /proc/*/exe; do
    real_bin=$(readlink "$exe_link" 2>/dev/null || true)
    if [ "$real_bin" = "$bin" ]; then
      pid=$(echo "$exe_link" | grep -oP '(?<=/proc/)\d+')
      kill -9 "$pid" 2>/dev/null && info "Killed PID $pid ($bin via exec -a)" || true
    fi
  done
done

# ── Stop & remove services ────────────────────────────────────────────────────
log "Stopping and removing backdoor services..."

for svc in "${REMOVE_SERVICES[@]}"; do
  [ -z "$svc" ] && continue
  systemctl stop  "${svc}.service" 2>/dev/null && info "Stopped: $svc" || true
  systemctl disable "${svc}.service" 2>/dev/null || true
  rm -f "/etc/systemd/system/${svc}.service"
  rm -f "/lib/systemd/system/${svc}.service"
  rm -f "/etc/systemd/system/multi-user.target.wants/${svc}.service"
  rm -f "/lib/systemd/system/multi-user.target.wants/${svc}.service"
  info "Removed: ${svc}.service"
done

# ── Remove binaries & data files ──────────────────────────────────────────────
log "Removing binaries and data files..."

for f in "${REMOVE_BINARIES[@]}" "${REMOVE_FILES[@]}"; do
  [ -z "$f" ] && continue
  if [ -e "$f" ]; then
    rm -f "$f" && info "Removed: $f" || err "Failed to remove: $f"
  fi
done

# ── Fix dbus ──────────────────────────────────────────────────────────────────
log "Fixing dbus..."
systemctl unmask dbus.service 2>/dev/null || true
systemctl unmask dbus.socket  2>/dev/null || true
systemctl daemon-reexec
systemctl daemon-reload
systemctl restart dbus.service 2>/dev/null || true

# ── Setup path guard ──────────────────────────────────────────────────────────
log "Setting up anti-backdoor path guard..."

# Gabungkan semua file yang perlu dipantau (tanpa duplikat)
declare -A _seen
ALL_WATCH=()
for f in "${REMOVE_BINARIES[@]}" "${REMOVE_FILES[@]}"; do
  [ -z "$f" ] && continue
  [ "${_seen[$f]+set}" ] && continue
  _seen[$f]=1
  ALL_WATCH+=("$f")
done

# Stop guard lama jika ada
systemctl stop  anti-backdoor.path    2>/dev/null || true
systemctl disable anti-backdoor.path  2>/dev/null || true
systemctl stop  anti-backdoor.service 2>/dev/null || true

# Build cleanup command
CLEANUP_CMD="rm -f $(printf '%q ' "${ALL_WATCH[@]}")"

cat > /etc/systemd/system/anti-backdoor.service << EOF
[Unit]
Description=Anti Backdoor Cleanup

[Service]
Type=oneshot
ExecStart=/bin/bash -c "${CLEANUP_CMD}"
EOF

{
  echo "[Unit]"
  echo "Description=Watch for backdoor file re-creation"
  echo ""
  echo "[Path]"
  for f in "${ALL_WATCH[@]}"; do
    echo "PathExists=${f}"
  done
  echo ""
  echo "[Install]"
  echo "WantedBy=multi-user.target"
} > /etc/systemd/system/anti-backdoor.path

systemctl daemon-reload
systemctl enable anti-backdoor.path
systemctl start  anti-backdoor.path

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}  DONE — SYSTEM CLEAN & PROTECTED         ${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo ""
printf "Services removed (%d):\n" "${#REMOVE_SERVICES[@]}"
printf '  - %s\n' "${REMOVE_SERVICES[@]}"
echo ""
printf "Binaries removed (%d):\n" "${#REMOVE_BINARIES[@]}"
printf '  - %s\n' "${REMOVE_BINARIES[@]}"
echo ""
printf "Path guard watching (%d files):\n" "${#ALL_WATCH[@]}"
printf '  - %s\n' "${ALL_WATCH[@]}"
echo ""
echo "Path guard status:"
systemctl is-active anti-backdoor.path 2>/dev/null && \
  echo -e "  ${GREEN}anti-backdoor.path is ACTIVE${NC}" || \
  echo -e "  ${RED}anti-backdoor.path is NOT active${NC}"

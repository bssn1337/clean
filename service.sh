#!/bin/bash
# RawonGuard Anti-Backdoor Cleaner v4
# Covers: systemd services, user home dirs, crontabs, rc.local, deleted-binary procs
# Usage: bash <(curl -fsSL https://raw.githubusercontent.com/bssn1337/clean/main/service.sh)

[ -f "$0" ] && sed -i 's/\r$//' "$0" 2>/dev/null || true

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
info() { echo -e "${CYAN}    →${NC} $*"; }
err()  { echo -e "${RED}[x]${NC} $*"; }

# ── Hardcoded known targets ───────────────────────────────────────────────────
REMOVE_SERVICES=(defunct gs-dbus)
REMOVE_BINARIES=(/usr/bin/defunct /usr/bin/gs-dbus)
REMOVE_FILES=(/lib/systemd/system/defunct.dat /etc/defunct.dat)
REMOVE_CRON_PATTERNS="defunct|gs-dbus|base64.*bash|GS_ARGS|\.config/htop"

# ── Dynamic detection: systemd services ──────────────────────────────────────
log "Scanning suspicious systemd services..."

while IFS= read -r svc_file; do
    [ -f "$svc_file" ] || continue
    if grep -qE 'GS_ARGS=|GS_HOST=|exec -a '"'"'\[' "$svc_file" 2>/dev/null; then
        svc_name=$(basename "$svc_file" .service)
        warn "Suspicious service: ${svc_name}"
        already=0
        for s in "${REMOVE_SERVICES[@]}"; do [ "$s" = "$svc_name" ] && already=1 && break; done
        [ "$already" -eq 1 ] && continue
        REMOVE_SERVICES+=("$svc_name")
        bin=$(grep -m1 'ExecStart' "$svc_file" \
              | grep -oP "'(/usr(?:/local)?/bin/[^']+)'" \
              | tail -1 | tr -d "'" 2>/dev/null || true)
        [ -n "$bin" ] && REMOVE_BINARIES+=("$bin") && info "Binary: $bin"
        dat=$(grep -m1 'ExecStart' "$svc_file" \
              | grep -oP '(?<=-k )[^ "'"'"']+' | head -1 2>/dev/null || true)
        [ -n "$dat" ] && REMOVE_FILES+=("$dat") && info "Data file: $dat"
    fi
done < <(find /etc/systemd/system /lib/systemd/system -maxdepth 2 -name "*.service" 2>/dev/null || true)

# ── Dynamic detection: user home directories ─────────────────────────────────
log "Scanning user home directories for hidden malware..."

while IFS= read -r home_dir; do
    [ -d "$home_dir" ] || continue
    username=$(basename "$home_dir")
    while IFS= read -r suspicious_file; do
        [ -f "$suspicious_file" ] || continue
        # Only match actual ELF binaries — PHP/shell scripts are "executable" too but not malware
        if file "$suspicious_file" 2>/dev/null | grep -q 'ELF'; then
            warn "Suspicious binary: $suspicious_file (user: $username)"
            REMOVE_BINARIES+=("$suspicious_file")
            dat_dir=$(dirname "$suspicious_file")
            for dat_file in "$dat_dir"/*.dat "$dat_dir"/*.json "$dat_dir"/*.conf; do
                [ -f "$dat_file" ] && REMOVE_FILES+=("$dat_file") && info "Config: $dat_file"
            done
        fi
    done < <(find "$home_dir" -maxdepth 5 -type f \
              \( -path "*/.config/*" -o -path "*/.local/*" -o -path "*/.[a-z]*/*" \) \
              -not -path "*/.git/*" \
              -not -path "*/.npm/*" \
              -not -path "*/.composer/*" \
              -not -path "*/.cache/*" \
              -not -path "*/node_modules/*" \
              -not -path "*/.nvm/*" \
              -not -path "*/.rbenv/*" \
              -not -path "*/.pyenv/*" \
              -not -path "*/.trash/*" \
              -not -path "*/vendor/*" \
              -not -path "*/debug/*" \
              2>/dev/null | grep -vE '\.(py|php|rb|pl|sh|txt|log|jpg|png|css|js|html|gz|zip|tar|so|a|o)$' || true)
done < <(awk -F: '$3 >= 500 && $3 < 65534 {print $6}' /etc/passwd 2>/dev/null | grep -v '^/$' | sort -u)

# ── Print targets ─────────────────────────────────────────────────────────────
echo ""
log "Targets:"
info "Services : ${REMOVE_SERVICES[*]}"
info "Binaries : ${REMOVE_BINARIES[*]}"
info "Files    : ${REMOVE_FILES[*]}"
echo ""

# ── Kill proses aktif ─────────────────────────────────────────────────────────
log "Killing backdoor processes..."

for bin in "${REMOVE_BINARIES[@]}"; do
    [ -z "$bin" ] && continue
    base=$(basename "$bin")
    # pkill by name ONLY for known malware — avoid killing legitimate processes like artisan/spark
    case "$base" in
        defunct|gs-dbus|gs-netcat|libglib-2.0.so.0)
            pkill -9 -f "$base" 2>/dev/null && info "Killed by name: $base" || true
            ;;
    esac
    for exe_link in /proc/*/exe; do
        real_bin=$(readlink "$exe_link" 2>/dev/null | sed 's/ (deleted)$//' || true)
        if [ "$real_bin" = "$bin" ]; then
            pid=$(echo "$exe_link" | grep -oP '(?<=/proc/)\d+')
            kill -9 "$pid" 2>/dev/null && info "Killed PID $pid ($bin)" || true
        fi
    done
done

# Kill proses dengan binary (deleted) yang mencurigakan
log "Killing processes with deleted binaries..."
for exe_link in /proc/*/exe; do
    real_bin=$(readlink "$exe_link" 2>/dev/null || true)
    if echo "$real_bin" | grep -qE '(deleted)|defunct|gs-dbus|\.config/htop'; then
        pid=$(echo "$exe_link" | grep -oP '(?<=/proc/)\d+')
        kill -9 "$pid" 2>/dev/null && info "Killed PID $pid (deleted binary)" || true
    fi
done

# Kill jailshell proses yang spawn miner (cPanel users)
log "Killing jailshell miner processes..."
while IFS= read -r line; do
    pid=$(echo "$line" | awk '{print $2}')
    kill -9 "$pid" 2>/dev/null && info "Killed jailshell miner PID $pid" || true
done < <(ps aux 2>/dev/null | grep -E 'base64.*bash|defunct|\.config/htop' | grep -v grep || true)

# ── Stop & remove systemd services ───────────────────────────────────────────
log "Stopping and removing backdoor services..."

for svc in "${REMOVE_SERVICES[@]}"; do
    [ -z "$svc" ] && continue
    systemctl stop    "${svc}.service" 2>/dev/null || true
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
    [ -e "$f" ] && rm -f "$f" && info "Removed: $f" || true
done

# ── Bersihkan crontab (root + semua user) ─────────────────────────────────────
log "Cleaning malicious crontabs..."

# Root crontab
if crontab -l 2>/dev/null | grep -qE "$REMOVE_CRON_PATTERNS"; then
    crontab -l 2>/dev/null | grep -vE "$REMOVE_CRON_PATTERNS" | crontab -
    info "Root crontab cleaned"
else
    info "Root crontab clean"
fi

# /etc/cron.d/ dan system cron dirs
for cron_dir in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly; do
    [ -d "$cron_dir" ] || continue
    while IFS= read -r cron_file; do
        if grep -qE "$REMOVE_CRON_PATTERNS" "$cron_file" 2>/dev/null; then
            grep -vE "$REMOVE_CRON_PATTERNS" "$cron_file" > "${cron_file}.tmp" && \
                mv "${cron_file}.tmp" "$cron_file"
            info "Cleaned: $cron_file"
        fi
    done < <(find "$cron_dir" -type f 2>/dev/null || true)
done

# Semua user crontab via /var/spool/cron
for spool in /var/spool/cron /var/spool/cron/crontabs; do
    [ -d "$spool" ] || continue
    for cron_file in "$spool"/*; do
        [ -f "$cron_file" ] || continue
        uname=$(basename "$cron_file")
        if grep -qE "$REMOVE_CRON_PATTERNS" "$cron_file" 2>/dev/null; then
            grep -vE "$REMOVE_CRON_PATTERNS" "$cron_file" > "${cron_file}.tmp" && \
                mv "${cron_file}.tmp" "$cron_file"
            info "User crontab cleaned: $uname"
        fi
    done
done

# ── Bersihkan /etc/rc.local ───────────────────────────────────────────────────
log "Cleaning /etc/rc.local..."

if [ -f /etc/rc.local ] && grep -qE "$REMOVE_CRON_PATTERNS" /etc/rc.local 2>/dev/null; then
    grep -vE "$REMOVE_CRON_PATTERNS" /etc/rc.local > /etc/rc.local.tmp && \
        mv /etc/rc.local.tmp /etc/rc.local
    chmod +x /etc/rc.local
    info "rc.local cleaned"
else
    info "rc.local clean"
fi

# ── Fix dbus ──────────────────────────────────────────────────────────────────
log "Fixing dbus..."
systemctl unmask dbus.service  2>/dev/null || true
systemctl unmask dbus.socket   2>/dev/null || true
systemctl daemon-reexec        2>/dev/null || true
systemctl daemon-reload        2>/dev/null || true
systemctl restart dbus.service 2>/dev/null || true

# ── Setup path guard ──────────────────────────────────────────────────────────
log "Setting up anti-backdoor path guard..."

declare -A _seen
ALL_WATCH=()
for f in "${REMOVE_BINARIES[@]}" "${REMOVE_FILES[@]}"; do
    [ -z "$f" ] && continue
    echo "$f" | grep -qE '^/(usr|home|etc|lib|var|tmp|dev)' || continue
    [ "${_seen[$f]+set}" ] && continue
    _seen[$f]=1
    ALL_WATCH+=("$f")
done

CLEANUP_CMD="rm -f $(printf '%q ' "${ALL_WATCH[@]}")"
GUARD_OK=0

# Coba systemd dulu
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop    anti-backdoor.path    2>/dev/null || true
    systemctl disable anti-backdoor.path   2>/dev/null || true
    systemctl stop    anti-backdoor.service 2>/dev/null || true

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
    systemctl enable anti-backdoor.path 2>/dev/null && \
    systemctl start  anti-backdoor.path 2>/dev/null && GUARD_OK=1

    if [ "$GUARD_OK" -eq 1 ]; then
        info "Path guard aktif via systemd"
    fi
fi

# Fallback: cron guard untuk server non-systemd (CentOS 6, container, dll)
if [ "$GUARD_OK" -eq 0 ]; then
    warn "systemd tidak tersedia — menggunakan cron guard sebagai fallback"

    # Buat script guard
    GUARD_SCRIPT=/usr/local/bin/anti-backdoor-guard.sh
    cat > "$GUARD_SCRIPT" << GUARDEOF
#!/bin/bash
# Anti-backdoor guard — auto-generated by RawonGuard Cleaner v3
$CLEANUP_CMD
# Kill proses yang menggunakan binary tersebut jika muncul lagi
for bin in ${ALL_WATCH[*]}; do
    [ -z "\$bin" ] && continue
    base=\$(basename "\$bin")
    pkill -9 -f "\$base" 2>/dev/null || true
done
GUARDEOF
    chmod +x "$GUARD_SCRIPT"
    info "Guard script: $GUARD_SCRIPT"

    # Tambah ke crontab root (setiap menit)
    CRON_LINE="* * * * * /usr/local/bin/anti-backdoor-guard.sh >/dev/null 2>&1"
    # Hapus entry lama jika ada
    crontab -l 2>/dev/null | grep -v "anti-backdoor-guard" | crontab - 2>/dev/null || true
    # Tambah entry baru
    ( crontab -l 2>/dev/null; echo "$CRON_LINE" ) | crontab -
    info "Cron guard aktif: setiap menit cek & hapus backdoor files"
    GUARD_OK=1
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}  DONE — SYSTEM CLEAN & PROTECTED  v3     ${NC}"
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
if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active anti-backdoor.path 2>/dev/null && \
        echo -e "  ${GREEN}systemd path guard ACTIVE${NC}" || \
        echo -e "  ${YELLOW}systemd path guard not active — cron fallback used${NC}"
else
    crontab -l 2>/dev/null | grep -q "anti-backdoor-guard" && \
        echo -e "  ${GREEN}cron guard ACTIVE (setiap menit)${NC}" || \
        echo -e "  ${RED}guard NOT active${NC}"
fi
echo ""
log "Recheck — remaining suspicious processes:"
REMAINING=$(ps aux 2>/dev/null | grep -E 'defunct|gs-dbus|xmrig|node-helper|\.config/htop|\.local/bin' \
            | grep -v grep | grep -v ' Z ' || true)
if [ -n "$REMAINING" ]; then
    warn "Masih ada proses mencurigakan:"
    echo "$REMAINING"
else
    echo -e "  ${GREEN}✓ Tidak ada proses mencurigakan tersisa${NC}"
fi

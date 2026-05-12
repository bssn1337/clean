#!/bin/bash
# RawonGuard Scanner v1 — Rawon Hunter™
# Smart multi-signal backdoor scanner: web-root aware, zero false positive
# Usage: bash <(curl -fsSL https://raw.githubusercontent.com/bssn1337/clean/main/scanner.sh) [--clean] [--json] [--verbose]

# ── Args ──────────────────────────────────────────────────────────────────────
MODE_CLEAN=0; MODE_JSON=0; MODE_VERBOSE=0
for arg in "$@"; do
    case "$arg" in --clean) MODE_CLEAN=1 ;; --json) MODE_JSON=1 ;; --verbose) MODE_VERBOSE=1 ;; esac
done

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
log()     { [ "$MODE_JSON" -eq 0 ] && echo -e "${GREEN}[+]${NC} $*"; }
warn()    { [ "$MODE_JSON" -eq 0 ] && echo -e "${YELLOW}[!]${NC} $*"; }
info()    { [ "$MODE_JSON" -eq 0 ] && echo -e "${CYAN}    →${NC} $*"; }
section() { [ "$MODE_JSON" -eq 0 ] && echo -e "\n${BOLD}${BLUE}══ $* ══${NC}"; }

# ── Known Malware DB ──────────────────────────────────────────────────────────
KNOWN_BINARY_NAMES=("gs-dbus" "defunct" "gs-netcat" "xmrig")
KNOWN_BINARY_STRINGS=("GS_ARGS=" "GS_HOST=" "GS_KNOCK_PORT=" ".config/htop")
KNOWN_WEBSHELL_SIGS=(
    "FilesMan" "c99shell" "r57shell" "WSO Shell" "b374k" "AntiSec"
    "Predator" "alfa-team" "IndoXploit" "r3dny" "Milw0rm"
    "priv8shell" "symlink shell" "cpanel cracker"
)

# ── Findings storage ──────────────────────────────────────────────────────────
declare -a F_PATH F_SCORE F_REASON F_ACTION F_DOMAIN
F_COUNT=0

add_finding() {
    local path="$1" score="$2" reason="$3" action="$4" domain="${5:-}"
    F_PATH[$F_COUNT]="$path"
    F_SCORE[$F_COUNT]="$score"
    F_REASON[$F_COUNT]="$reason"
    F_ACTION[$F_COUNT]="$action"
    F_DOMAIN[$F_COUNT]="$domain"
    ((F_COUNT++))
}

score_level() {
    local s=$1
    if   [ "$s" -ge 10 ]; then echo "MALWARE"
    elif [ "$s" -ge 7  ]; then echo "LIKELY"
    elif [ "$s" -ge 4  ]; then echo "SUSPICIOUS"
    else echo "CLEAN"; fi
}

# ── Package manager helper ────────────────────────────────────────────────────
PKG_CMD=""
is_owned_by_pkg() {
    case "$PKG_CMD" in
        rpm)  rpm  -qf "$1" >/dev/null 2>&1 ;;
        dpkg) dpkg -S  "$1" >/dev/null 2>&1 ;;
        *)    return 1 ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 0: Environment & Panel Detection
# ═══════════════════════════════════════════════════════════════════════════════
IS_CPANEL=0; IS_PLESK=0; IS_DIRECTADMIN=0
IS_APACHE=0; IS_NGINX=0; IS_LITESPEED=0
PANEL="Manual"; WEB_SERVER="Unknown"

detect_environment() {
    [ -d /usr/local/cpanel ]                           && IS_CPANEL=1      && PANEL="cPanel"
    [ -d /usr/local/psa ]                              && IS_PLESK=1       && PANEL="Plesk"
    [ -f /usr/local/directadmin/directadmin ]          && IS_DIRECTADMIN=1 && PANEL="DirectAdmin"
    [ -f /usr/local/lsws/bin/lswsctrl ]               && IS_LITESPEED=1   && WEB_SERVER="LiteSpeed"
    command -v apache2 >/dev/null 2>&1                 && IS_APACHE=1      && WEB_SERVER="Apache"
    command -v httpd   >/dev/null 2>&1                 && IS_APACHE=1      && WEB_SERVER="Apache"
    command -v nginx   >/dev/null 2>&1                 && IS_NGINX=1       && [ "$WEB_SERVER" = "Unknown" ] && WEB_SERVER="Nginx"
    [ -f /etc/debian_version ] && PKG_CMD="dpkg"
    [ -f /etc/redhat-release ] && PKG_CMD="rpm"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 1: Web Root Enumeration
# Hanya scan dir yang memang web root aktif — tidak brutal
# ═══════════════════════════════════════════════════════════════════════════════
declare -a WEB_ROOTS      # format: "domain:path"
declare -a EXTRA_SCAN_DIRS

enumerate_web_roots() {
    section "Web Root Enumeration"
    declare -A seen

    _add_root() {
        local domain="$1" root="$2"
        root=$(realpath "$root" 2>/dev/null || echo "$root")
        [ -d "$root" ] || return
        [ "${seen[$root]+x}" ] && return
        seen[$root]=1
        WEB_ROOTS+=("$domain:$root")
        info "$domain → $root"
    }

    # cPanel: /etc/userdomains
    if [ "$IS_CPANEL" -eq 1 ] && [ -f /etc/userdomains ]; then
        while IFS=: read -r domain user; do
            domain=$(echo "$domain" | xargs)
            user=$(echo "$user"     | xargs)
            [ -z "$user" ] && continue
            _add_root "$domain" "/home/$user/public_html"
            # Addon domains
            for addon in "/home/$user/domains"/*/public_html; do
                [ -d "$addon" ] || continue
                local adom
                adom=$(echo "$addon" | awk -F/ '{print $(NF-1)}')
                _add_root "$adom" "$addon"
            done
        done < /etc/userdomains 2>/dev/null
    fi

    # Plesk: /var/www/vhosts/*/httpdocs
    if [ "$IS_PLESK" -eq 1 ]; then
        for vhost in /var/www/vhosts/*/httpdocs; do
            [ -d "$vhost" ] || continue
            local dom
            dom=$(echo "$vhost" | awk -F/ '{print $(NF-1)}')
            _add_root "$dom" "$vhost"
        done
    fi

    # DirectAdmin: /home/*/domains/*/public_html
    if [ "$IS_DIRECTADMIN" -eq 1 ]; then
        for pub in /home/*/domains/*/public_html; do
            [ -d "$pub" ] || continue
            local dom
            dom=$(echo "$pub" | awk -F/ '{print $(NF-1)}')
            _add_root "$dom" "$pub"
        done
    fi

    # Apache: parse DocumentRoot dari config aktif
    for conf_dir in /etc/apache2/sites-enabled /etc/httpd/conf.d \
                    /usr/local/apache/conf/vhosts /etc/apache2/conf.d; do
        [ -d "$conf_dir" ] || continue
        while IFS= read -r root; do
            root=$(echo "$root" | tr -d '"'"'")
            [ -d "$root" ] || continue
            _add_root "apache-vhost" "$root"
        done < <(grep -rh "DocumentRoot" "$conf_dir" 2>/dev/null | grep -v '#' | awk '{print $2}')
    done

    # Nginx: parse root directive
    for conf_dir in /etc/nginx/sites-enabled /etc/nginx/conf.d; do
        [ -d "$conf_dir" ] || continue
        while IFS= read -r root; do
            root=$(echo "$root" | tr -d '";'"'")
            [ -d "$root" ] || continue
            _add_root "nginx-vhost" "$root"
        done < <(grep -rh "^\s*root " "$conf_dir" 2>/dev/null | grep -v '#' | awk '{print $2}' | tr -d ';')
    done

    # Fallback: /home/*/public_html
    for pub in /home/*/public_html; do
        [ -d "$pub" ] || continue
        local user
        user=$(echo "$pub" | cut -d/ -f3)
        _add_root "$user" "$pub"
    done

    log "Web roots found: ${#WEB_ROOTS[@]}"

    # Extra vulnerable dirs — selalu di-scan walau bukan web root
    for d in /tmp /var/tmp /dev/shm; do
        [ -d "$d" ] && EXTRA_SCAN_DIRS+=("$d")
    done
}

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 2: PHP Backdoor Scanner
# Zero false positive — hanya flag pattern yang tidak pernah ada di kode legit
# ═══════════════════════════════════════════════════════════════════════════════

# CMS detection untuk context-aware whitelist
CMS="unknown"
detect_cms() {
    local root="$1"
    CMS="unknown"
    [ -f "$root/wp-config.php"     ] && CMS="wordpress"   && return
    [ -f "$root/artisan"           ] && CMS="laravel"      && return
    [ -f "$root/configuration.php" ] && grep -q "JConfig" "$root/configuration.php" 2>/dev/null \
                                      && CMS="joomla"      && return
    [ -f "$root/index.php"         ] && grep -q "CodeIgniter" "$root/index.php" 2>/dev/null \
                                      && CMS="codeigniter" && return
}

is_php_whitelisted() {
    local file="$1"
    # Framework/CMS core dirs — jangan pernah scan
    [[ "$file" == */vendor/* ]]                    && return 0
    [[ "$file" == */node_modules/* ]]              && return 0
    [[ "$file" == */.git/* ]]                      && return 0
    [[ "$file" == */storage/framework/views/* ]]   && return 0  # Laravel Blade cache
    [[ "$file" == */bootstrap/cache/* ]]           && return 0  # Laravel bootstrap cache
    [[ "$file" == */var/cache/* ]]                 && return 0  # Symfony cache
    [[ "$file" == */cache/smarty/* ]]              && return 0  # Smarty cache
    [[ "$file" == */wp-includes/* ]]               && return 0  # WordPress core
    [[ "$file" == */wp-admin/* ]]                  && return 0  # WordPress admin
    [[ "$file" == */autoload_real.php ]]           && return 0  # Composer autoload
    [[ "$file" == */autoload_static.php ]]         && return 0  # Composer autoload
    # ionCube / Zend Guard encoded files (legitimate obfuscation)
    timeout 1 head -c 100 "$file" 2>/dev/null | grep -qE 'ionCube|Zend Guard|Zend Loader' && return 0
    return 1
}

scan_php_file() {
    local file="$1" domain="$2" root="$3"
    is_php_whitelisted "$file" && return

    local score=0
    local -a reasons

    # ── TIER 1: Zero False Positive (score 10) ─────────────────────────────
    # Pattern ini TIDAK PERNAH ada di kode legit manapun

    # eval/assert dengan direct user input
    if grep -qP '(eval|assert)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\b' "$file" 2>/dev/null; then
        score=$((score+10)); reasons+=("eval/assert(user_input)")
    fi

    # shell function dengan direct user input — tanpa variabel perantara
    if grep -qP '(system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\b' "$file" 2>/dev/null; then
        score=$((score+10)); reasons+=("shell_exec(user_input)")
    fi

    # preg_replace /e modifier + user input (code injection via regex)
    if grep -qP "preg_replace\s*\(\s*(['\"]).*\/e\1\s*,.*\\\$_(GET|POST|REQUEST|COOKIE)" "$file" 2>/dev/null; then
        score=$((score+10)); reasons+=("preg_replace /e + user_input")
    fi

    # create_function dengan user input (sama dengan eval)
    if grep -qP 'create_function\s*\([^,]*,\s*\$_(GET|POST|REQUEST|COOKIE)' "$file" 2>/dev/null; then
        score=$((score+10)); reasons+=("create_function(user_input)")
    fi

    # Known webshell signatures — string unik yang tidak pernah ada di kode legit
    for sig in "${KNOWN_WEBSHELL_SIGS[@]}"; do
        if grep -qi "$sig" "$file" 2>/dev/null; then
            score=$((score+10)); reasons+=("webshell signature: $sig"); break
        fi
    done

    # ── TIER 2: High Confidence (score 7-8) ───────────────────────────────
    # Sangat jarang false positive, tapi perlu kombinasi

    # Multi-layer obfuscation + eval (gzip+base64+rot13) — tidak ada use legit
    if grep -qP 'eval\s*\(\s*(gzinflate|gzuncompress|str_rot13|gzdecode)\s*\(\s*(base64_decode|str_rot13)\s*\(' "$file" 2>/dev/null; then
        score=$((score+8)); reasons+=("multi-layer obfuscation eval(gzip/rot13(base64()))")
    fi

    # Hardcoded base64 panjang >500 char di dalam eval
    if grep -qP "eval\s*\(\s*base64_decode\s*\(\s*['\"][A-Za-z0-9+/=]{500,}['\"]" "$file" 2>/dev/null; then
        score=$((score+8)); reasons+=("eval(base64_decode(hardcoded_500+chars))")
    fi

    # @eval — error suppression untuk sembunyikan trace
    if grep -qP '@eval\s*\(' "$file" 2>/dev/null; then
        score=$((score+6)); reasons+=("@eval error suppression")
    fi

    # PHP file di uploads/ — seharusnya tidak boleh ada
    if [[ "$file" == */uploads/*.php* ]] || [[ "$file" == */upload/*.php* ]]; then
        score=$((score+7)); reasons+=("PHP file in uploads dir")
    fi

    # PHP file di /tmp, /var/tmp, /dev/shm
    if [[ "$file" == /tmp/* ]] || [[ "$file" == /var/tmp/* ]] || [[ "$file" == /dev/shm/* ]]; then
        score=$((score+7)); reasons+=("PHP file in temp dir")
    fi

    # .htaccess yang register PHP handler ke extension non-php (bypass)
    # (handled separately)

    # ── TIER 3: Suspicious (score 4) — butuh signal lain untuk confirm ────
    # Hanya flag kalau belum ada signal lain

    if [ "$score" -eq 0 ]; then
        # eval(base64_decode()) tanpa hardcoded string panjang — bisa jadi plugin obfuscated
        if grep -qP 'eval\s*\(\s*base64_decode\s*\(' "$file" 2>/dev/null; then
            score=$((score+4)); reasons+=("eval(base64_decode()) — verify manually")
        fi
    fi

    [ "$score" -lt 4 ] && return

    local reason_str
    reason_str=$(IFS='; '; echo "${reasons[*]}")
    local action="warn"
    [ "$score" -ge 10 ] && action="quarantine"

    add_finding "PHP:$file" "$score" "$reason_str" "$action" "$domain"
}

scan_htaccess() {
    local file="$1" domain="$2"
    # .htaccess yang bisa execute PHP via extension lain (gambar, dll)
    if grep -qE '(AddHandler|SetHandler).*(application/x-httpd-php|php-script)' "$file" 2>/dev/null; then
        # Cek kalau ini untuk extension non-php (itu yang bahaya)
        if grep -qE '(AddHandler|SetHandler).*\.(jpg|jpeg|png|gif|bmp|svg|txt|log).*php' "$file" 2>/dev/null; then
            add_finding "HTACCESS:$file" "9" "PHP handler on non-PHP extension (image/txt bypass)" "warn" "$domain"
            return
        fi
    fi
    # auto_prepend_file via htaccess (inject PHP ke semua request)
    if grep -qE 'php_value\s+auto_prepend_file' "$file" 2>/dev/null; then
        add_finding "HTACCESS:$file" "8" "auto_prepend_file in .htaccess" "warn" "$domain"
    fi
}

scan_php_backdoors() {
    section "PHP Backdoor Scanner"

    local find_excludes=(
        -not -path "*/vendor/*"
        -not -path "*/node_modules/*"
        -not -path "*/.git/*"
        -not -path "*/storage/framework/views/*"
        -not -path "*/bootstrap/cache/*"
        -not -path "*/var/cache/*"
        -not -path "*/wp-includes/*"
        -not -path "*/wp-admin/*"
        -size -2M
    )

    # Pre-filter pattern: minimal string yang bisa jadi backdoor — 1x pass per dir
    local PREFILTER='eval|assert|base64_decode|gzinflate|gzuncompress|str_rot13|gzdecode|shell_exec|passthru|proc_open|popen|create_function|preg_replace|FilesMan|c99shell|r57shell|WSO Shell|b374k|AntiSec|IndoXploit|alfa-team'

    _scan_dir_php() {
        local domain="$1" root="$2"
        [ -d "$root" ] || return

        detect_cms "$root"
        local total_files
        total_files=$(find "$root" -type f \( -name "*.php" -o -name "*.php7" -o -name "*.phtml" \) \
                      "${find_excludes[@]}" 2>/dev/null | wc -l)
        log "Scanning PHP: $domain ($root) [$CMS] — ${total_files} files"

        # Pass 1: grep -lP untuk pre-filter kandidat saja (jauh lebih cepat)
        local candidates
        candidates=$(find "$root" -type f \( -name "*.php" -o -name "*.php7" -o -name "*.phtml" \) \
                      "${find_excludes[@]}" 2>/dev/null \
                      -exec grep -lP "$PREFILTER" {} + 2>/dev/null)

        local cnt=0
        while IFS= read -r f; do
            [ -f "$f" ] || continue
            scan_php_file "$f" "$domain" "$root"
            ((cnt++))
        done <<< "$candidates"

        [ "$MODE_VERBOSE" -eq 1 ] && info "$domain: $cnt candidate files analyzed (of $total_files total)"

        # Scan .htaccess
        while IFS= read -r f; do
            scan_htaccess "$f" "$domain"
        done < <(find "$root" -name ".htaccess" 2>/dev/null)
    }

    for entry in "${WEB_ROOTS[@]}"; do
        _scan_dir_php "${entry%%:*}" "${entry#*:}"
    done

    # Extra dirs: /tmp, /var/tmp, /dev/shm
    for extra in "${EXTRA_SCAN_DIRS[@]}"; do
        log "Scanning temp dir: $extra"
        while IFS= read -r f; do
            scan_php_file "$f" "SYSTEM-TEMP" "$extra"
        done < <(find "$extra" -maxdepth 3 -type f -name "*.php" -size -2M 2>/dev/null \
                  -exec grep -lP "$PREFILTER" {} + 2>/dev/null)
    done
}

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 3: Binary/ELF Backdoor Scanner
# Hanya scan hidden dirs di user home — tidak brutal scan system dirs
# ═══════════════════════════════════════════════════════════════════════════════
scan_binary_backdoors() {
    section "Binary Backdoor Scanner"

    while IFS= read -r home_dir; do
        [ -d "$home_dir" ] || continue
        [ "$home_dir" = "/" ] && continue  # skip jika home = root system

        local username
        username=$(basename "$home_dir")

        while IFS= read -r f; do
            [ -f "$f" ] || continue
            # Wajib ELF binary — skip PHP/shell script yang "executable"
            file "$f" 2>/dev/null | grep -q '\bELF\b' || continue

            local score=0; local -a reasons
            local name
            name=$(basename "$f")

            score=$((score+2)); reasons+=("ELF binary in hidden user dir")

            for mname in "${KNOWN_BINARY_NAMES[@]}"; do
                [ "$name" = "$mname" ] && score=$((score+8)) && reasons+=("known malware: $mname")
            done

            for mstr in "${KNOWN_BINARY_STRINGS[@]}"; do
                strings "$f" 2>/dev/null | grep -q "$mstr" && \
                    score=$((score+6)) && reasons+=("contains: $mstr")
            done

            ! is_owned_by_pkg "$f" 2>/dev/null && \
                score=$((score+2)) && reasons+=("not in package manager")

            # Disguised as system process?
            case "$name" in
                dbus-daemon|systemd-logind|polkitd|sshd)
                    score=$((score+4)); reasons+=("disguised as system binary: $name")
                    ;;
            esac

            [ "$score" -lt 4 ] && continue

            local reason_str
            reason_str=$(IFS='; '; echo "${reasons[*]}")
            add_finding "BINARY:$f" "$score" "$reason_str" "$([ $score -ge 10 ] && echo 'remove' || echo 'warn')" ""

        done < <(find "$home_dir" -maxdepth 5 -type f \
                  \( -path "*/.config/*" -o -path "*/.local/lib/*" -o -path "*/.dbus/*" \) \
                  -not -path "*/.trash/*" \
                  -not -path "*/vendor/*" \
                  -not -path "*/debug/.dwz/*" \
                  2>/dev/null)

    done < <(awk -F: '$3>=500 && $3<65534 {print $6}' /etc/passwd 2>/dev/null | grep -v '^/$' | sort -u)
}

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 4: Systemd Service Scanner
# ═══════════════════════════════════════════════════════════════════════════════
scan_services() {
    section "Service Scanner"

    while IFS= read -r svc_file; do
        [ -f "$svc_file" ] || continue
        local score=0; local -a reasons
        local svc_name
        svc_name=$(basename "$svc_file" .service)

        grep -qE 'GS_ARGS=|GS_HOST='  "$svc_file" 2>/dev/null && score=$((score+8)) && reasons+=("gsocket env vars")
        grep -q "exec -a"              "$svc_file" 2>/dev/null && score=$((score+4)) && reasons+=("process name disguise")
        for mname in "${KNOWN_BINARY_NAMES[@]}"; do
            [ "$svc_name" = "$mname" ] && score=$((score+8)) && reasons+=("known malware service: $mname")
        done

        [ "$score" -lt 4 ] && continue
        local reason_str
        reason_str=$(IFS='; '; echo "${reasons[*]}")
        add_finding "SERVICE:$svc_name" "$score" "$reason_str" "remove_service" ""

    done < <(find /etc/systemd/system /lib/systemd/system -maxdepth 2 -name "*.service" 2>/dev/null)
}

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 5: Process Scanner
# ═══════════════════════════════════════════════════════════════════════════════
scan_processes() {
    section "Process Scanner"

    for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
        [ -d "/proc/$pid" ] || continue
        local exe
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
        local exe_clean="${exe% (deleted)}"
        local name
        name=$(basename "$exe_clean")
        local cmdline
        cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
        local score=0; local -a reasons

        [[ "$exe" == *"(deleted)"* ]] && score=$((score+4)) && reasons+=("running from deleted binary")

        for mname in "${KNOWN_BINARY_NAMES[@]}"; do
            [[ "$name" == "$mname" ]] && score=$((score+8)) && reasons+=("known malware process: $mname")
        done

        for mstr in "${KNOWN_BINARY_STRINGS[@]}"; do
            echo "$cmdline" | grep -q "$mstr" && score=$((score+6)) && reasons+=("malware pattern in cmdline: $mstr")
        done

        # Disguised system binary — path tidak sesuai
        case "$name" in
            dbus-daemon)
                [[ "$exe_clean" != /usr/bin/dbus-daemon ]] && \
                    score=$((score+6)) && reasons+=("fake dbus-daemon — path: $exe_clean")
                ;;
        esac

        [ "$score" -lt 4 ] && continue
        local reason_str
        reason_str=$(IFS='; '; echo "${reasons[*]}")
        add_finding "PROCESS:PID-$pid ($exe_clean)" "$score" "$reason_str" "kill" ""
    done
}

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 6: Crontab & RC Scanner
# ═══════════════════════════════════════════════════════════════════════════════
scan_crontabs() {
    section "Crontab & RC Scanner"

    local PAT="defunct|gs-dbus|gs-netcat|GS_ARGS|\.config/htop|curl\b.*\|\s*bash|wget\b.*\|\s*bash"

    crontab -l 2>/dev/null | grep -qE "$PAT" && \
        add_finding "CRONTAB:root" "8" "Malware pattern in root crontab" "clean_cron" ""

    for spool in /var/spool/cron /var/spool/cron/crontabs; do
        [ -d "$spool" ] || continue
        for f in "$spool"/*; do
            [ -f "$f" ] || continue
            grep -qE "$PAT" "$f" 2>/dev/null && \
                add_finding "CRONTAB:$(basename "$f")" "8" "Malware pattern in user crontab" "clean_cron" ""
        done
    done

    for cron_dir in /etc/cron.d /etc/cron.hourly /etc/cron.daily; do
        [ -d "$cron_dir" ] || continue
        for f in "$cron_dir"/*; do
            [ -f "$f" ] || continue
            grep -qE "$PAT" "$f" 2>/dev/null && \
                add_finding "CRON.D:$f" "8" "Malware pattern in system cron" "clean_cron" ""
        done
    done

    [ -f /etc/rc.local ] && grep -qE "$PAT" /etc/rc.local 2>/dev/null && \
        add_finding "RC_LOCAL:/etc/rc.local" "7" "Malware pattern in rc.local" "warn" ""
}

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 7: Rootkit Detection
# ═══════════════════════════════════════════════════════════════════════════════
scan_rootkit() {
    section "Rootkit Detection"

    # ld.so.preload — inject library ke semua proses
    if [ -s /etc/ld.so.preload ]; then
        local preload_content
        preload_content=$(cat /etc/ld.so.preload)
        add_finding "ROOTKIT:/etc/ld.so.preload" "9" "ld.so.preload: $preload_content" "warn" ""
    fi

    # Fake system library di user home
    while IFS= read -r lib; do
        [[ "$lib" == /usr/lib/* ]] && continue
        local score=7; local -a reasons
        reasons+=("fake system library in user home: $lib")
        # Lebih bahaya kalau sudah di-load oleh proses
        if grep -rl "$lib" /proc/*/maps 2>/dev/null | grep -q .; then
            score=$((score+3)); reasons+=("actively loaded by running process")
        fi
        local reason_str
        reason_str=$(IFS='; '; echo "${reasons[*]}")
        add_finding "ROOTKIT:$lib" "$score" "$reason_str" "warn" ""
    done < <(find /home -maxdepth 5 -type f -name "lib*.so*" \
              \( -path "*/.local/lib/*" -o -path "*/.config/*" \) 2>/dev/null)
}

# ═══════════════════════════════════════════════════════════════════════════════
# ACTION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════
do_action() {
    local i="$1"
    local level
    level=$(score_level "${F_SCORE[$i]}")
    [ "$level" != "MALWARE" ] && return

    case "${F_ACTION[$i]}" in
        quarantine|remove)
            local fpath="${F_PATH[$i]}"
            fpath="${fpath#PHP:}"; fpath="${fpath#BINARY:}"
            if [ -f "$fpath" ]; then
                mkdir -p /var/quarantine/rawonguard
                mv "$fpath" /var/quarantine/rawonguard/ 2>/dev/null && \
                    echo -e "  ${GREEN}→ Quarantined: $fpath${NC}"
            fi
            ;;
        kill)
            local pid
            pid=$(echo "${F_PATH[$i]}" | grep -oP 'PID-\K[0-9]+')
            [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null && \
                echo -e "  ${GREEN}→ Killed PID $pid${NC}"
            ;;
        remove_service)
            local svc="${F_PATH[$i]#SERVICE:}"
            systemctl stop    "$svc.service" 2>/dev/null
            systemctl disable "$svc.service" 2>/dev/null
            rm -f "/etc/systemd/system/$svc.service" "/lib/systemd/system/$svc.service"
            systemctl daemon-reload 2>/dev/null
            echo -e "  ${GREEN}→ Removed service: $svc${NC}"
            ;;
        clean_cron)
            local target="${F_PATH[$i]}"
            if [[ "$target" == CRONTAB:root ]]; then
                crontab -l 2>/dev/null | grep -vE "$PAT" | crontab -
                echo -e "  ${GREEN}→ Root crontab cleaned${NC}"
            fi
            ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════════════════
# REPORT
# ═══════════════════════════════════════════════════════════════════════════════
print_report() {
    echo ""
    echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  RawonGuard Scanner v1 — $(hostname)${NC}"
    echo -e "${BOLD}  $(date '+%Y-%m-%d %H:%M:%S') | Panel: $PANEL | Web: $WEB_SERVER${NC}"
    echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
    echo ""

    local cnt_m=0 cnt_l=0 cnt_s=0

    for i in $(seq 0 $((F_COUNT-1))); do
        local level
        level=$(score_level "${F_SCORE[$i]}")
        local tag=""
        [ -n "${F_DOMAIN[$i]}" ] && tag=" [${F_DOMAIN[$i]}]"

        case "$level" in
            MALWARE)    echo -e "${RED}[MALWARE  |${F_SCORE[$i]}]${NC}$tag ${F_PATH[$i]}"; ((cnt_m++)) ;;
            LIKELY)     echo -e "${YELLOW}[LIKELY   |${F_SCORE[$i]}]${NC}$tag ${F_PATH[$i]}"; ((cnt_l++)) ;;
            SUSPICIOUS) echo -e "${CYAN}[SUSPECT  |${F_SCORE[$i]}]${NC}$tag ${F_PATH[$i]}"; ((cnt_s++)) ;;
        esac

        [ "$MODE_VERBOSE" -eq 1 ] && echo -e "          ${F_REASON[$i]}"

        [ "$MODE_CLEAN" -eq 1 ] && do_action "$i"
    done

    echo ""
    if [ "$F_COUNT" -eq 0 ]; then
        echo -e "  ${GREEN}✓ No threats detected${NC}"
    else
        echo -e "  ${RED}$cnt_m MALWARE${NC} | ${YELLOW}$cnt_l LIKELY${NC} | ${CYAN}$cnt_s SUSPICIOUS${NC}"
        echo -e "  Web roots scanned: ${#WEB_ROOTS[@]}"
        if [ "$MODE_CLEAN" -eq 0 ] && [ $((cnt_m+cnt_l)) -gt 0 ]; then
            echo ""
            echo -e "  ${YELLOW}Run with --clean to quarantine MALWARE findings${NC}"
            echo -e "  ${YELLOW}Quarantine dir: /var/quarantine/rawonguard/${NC}"
        fi
    fi
    echo ""
}

print_json() {
    printf '{"host":"%s","ip":"%s","time":"%s","panel":"%s","web_server":"%s","web_roots":%d,"findings":[' \
        "$(hostname)" "$(hostname -I | awk '{print $1}')" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "$PANEL" "$WEB_SERVER" "${#WEB_ROOTS[@]}"
    for i in $(seq 0 $((F_COUNT-1))); do
        [ "$i" -gt 0 ] && printf ','
        printf '{"path":"%s","score":%d,"level":"%s","reason":"%s","domain":"%s"}' \
            "${F_PATH[$i]}" "${F_SCORE[$i]}" "$(score_level "${F_SCORE[$i]}")" \
            "${F_REASON[$i]}" "${F_DOMAIN[$i]}"
    done
    printf ']}\n'
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
[ "$MODE_JSON" -eq 0 ] && {
    echo -e "${BOLD}RawonGuard Scanner v1 — Rawon Hunter™${NC}"
    echo -e "Host: $(hostname) | IP: $(hostname -I | awk '{print $1}') | $(date)"
    echo ""
}

detect_environment
[ "$MODE_JSON" -eq 0 ] && log "Panel: $PANEL | Web: $WEB_SERVER | PKG: ${PKG_CMD:-none}"

enumerate_web_roots
scan_php_backdoors
scan_binary_backdoors
scan_services
scan_processes
scan_crontabs
scan_rootkit

[ "$MODE_JSON" -eq 1 ] && print_json || print_report

#!/usr/bin/env bash
# Linux Vulnerable Lab Security Audit Script - Comprehensive Read-Only Version
# Purpose: Audit (ONLY) a deliberately vulnerable Linux system and provide detailed remediation advice
# Features: Users, sudo, file perms, SSH, firewall, sysctl, mounts, SUID, suspicious/malicious files, etc.
# Author: Wifi-assisted comprehensive checklist (2025/2026 best practices)
# Version: 1.1 - added malicious file patterns
# Usage:   sudo ./linux-lab-audit.sh | tee audit-report-$(date +%Y%m%d).txt
#          (run as root for maximum coverage)

set -u
PATH="/usr/sbin:/usr/bin:/sbin:/bin"

# ────────────────────────────────────────────────
# Colors & output helpers
# ────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_header() {
    echo -e "\n${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE} $1 ${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}\n"
}

pass()    { echo -e "[${GREEN}PASS${NC}] $1"; }
warn()    { echo -e "[${YELLOW}WARN${NC}] $1"; }
fail()    { echo -e "[${RED}FAIL${NC}] $1"; }
info()    { echo -e "[${CYAN}INFO${NC}] $1"; }
rec()     { echo -e "   → Recommendation: $1"; }

is_command() { command -v "$1" >/dev/null 2>&1; }

# ────────────────────────────────────────────────
# 0. Basic environment
# ────────────────────────────────────────────────
print_header "SYSTEM INFORMATION"

info "Hostname     : $(hostname)"
info "Kernel       : $(uname -r)"
info "OS Release   : $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || echo "unknown")"
info "Uptime       : $(uptime -p)"
info "Current user : $(whoami) (effective UID: $EUID)"
if (( EUID != 0 )); then
    fail "Script not running as root → many checks will be incomplete or false negatives"
    rec  "Re-run with sudo"
fi

# ────────────────────────────────────────────────
# 1. Users & Groups
# ────────────────────────────────────────────────
print_header "USER & GROUP AUDIT"

# Passwordless / empty password accounts
info "Checking for accounts with empty or weak password field..."
awk -F: '$2 == "" || $2 == "!" || $2 == "*" {print $1}' /etc/shadow | while read -r u; do
    if [[ "$u" != "root" && "$u" != "" ]]; then
        fail "Account '$u' has empty password field in /etc/shadow"
        rec  "passwd -l $u   or set a strong password"
    fi
done

# UID 0 accounts besides root
info "Non-root UID=0 accounts"
awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd | while read -r u; do
    fail "Extra UID 0 account → $u"
    rec  "Investigate & remove or change UID"
done

# Users with no password aging
info "Accounts with password never expires / no aging"
awk -F: '$2 !~ /^[*!]/ && $5 == "" && $1 !~ /^(root|sync|halt|shutdown)$/ {print $1}' /etc/shadow | while read -r u; do
    warn "User $u has no password aging configured"
    rec  "chage -M 90 -W 7 $u    (max age 90 days, warn 7 days before)"
done

# ────────────────────────────────────────────────
# 2. Sudo / Privilege Escalation
# ────────────────────────────────────────────────
print_header "SUDO & PRIVILEGE ESCALATION"

if [[ -f /etc/sudoers ]]; then
    if grep -Eq 'ALL\s+ALL=\(ALL:ALL\)\s+ALL|ALL\s+ALL=\(ALL\)\s+NOPASSWD:' /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
        fail "Dangerous wildcard sudo rule found (ALL ALL = ALL or NOPASSWD)"
        rec  "Use specific commands/users — never ALL ALL or NOPASSWD:ALL"
    fi
fi

if is_command sudo; then
    sudo -l 2>/dev/null | grep -iq NOPASSWD && warn "Some commands can be run via sudo without password"
fi

# ────────────────────────────────────────────────
# 3. Critical file permissions
# ────────────────────────────────────────────────
print_header "CRITICAL FILE PERMISSIONS"

declare -A critical_files=(
    ["/etc/passwd"]         "644"
    ["/etc/shadow"]         "640 or 600"
    ["/etc/group"]          "644"
    ["/etc/gshadow"]        "640 or 600"
    ["/etc/sudoers"]        "440"
    ["/etc/ssh/sshd_config"] "600"
)

for file in "${!critical_files[@]}"; do
    if [[ -f "$file" ]]; then
        perms=$(stat -c %a "$file" 2>/dev/null)
        owner=$(stat -c %U:%G "$file" 2>/dev/null)
        expected="${critical_files[$file]}"
        if [[ "$perms" != "${expected%% *}"* ]]; then
            fail "$file has insecure permissions: $perms (should be ~$expected)"
            rec  "chmod ${expected%% *} $file"
        fi
        if [[ "$owner" != "root:root" && "$owner" != "root:shadow" ]]; then
            warn "$file owned by $owner instead of root/root:shadow"
            rec  "chown root:root $file   (or root:shadow for shadow files)"
        fi
    else
        info "$file does not exist"
    fi
done

# World-writable files (very common in labs)
info "Looking for world-writable regular files (excluding /proc, /sys, /dev)..."
find / -xdev -type f -perm -0002 -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" 2>/dev/null | head -n 15 | while read -r f; do
    fail "World-writable file: $f"
    rec  "chmod o-w \"$f\""
done

# ────────────────────────────────────────────────
# 4. SSH Configuration
# ────────────────────────────────────────────────
print_header "SSH SECURITY"

sshd_config="/etc/ssh/sshd_config"
if [[ ! -f "$sshd_config" ]]; then
    warn "sshd_config not found — SSH may not be installed or using non-standard location"
else
    checks=(
        "PermitRootLogin.*yes"                               "FAIL"  "PermitRootLogin no (or prohibit-password)"
        "PasswordAuthentication.*yes"                        "WARN"  "PasswordAuthentication no → prefer keys only"
        "PubkeyAuthentication.*no"                           "FAIL"  "PubkeyAuthentication yes"
        "PermitEmptyPasswords.*yes"                          "FAIL"  "PermitEmptyPasswords no"
        "ChallengeResponseAuthentication.*yes"               "WARN"  "ChallengeResponseAuthentication no (unless needed)"
        "UsePAM.*no"                                         "WARN"  "UsePAM yes (usually better)"
        "X11Forwarding.*yes"                                 "WARN"  "X11Forwarding no (unless required)"
        "AllowTcpForwarding.*yes"                            "WARN"  "AllowTcpForwarding no (or limited)"
        "MaxAuthTries.*[6-9][0-9]*"                          "WARN"  "MaxAuthTries ≤ 4"
    )

    for line in "${checks[@]}"; do
        pattern=$(echo "$line" | awk '{print $1}')
        level=$(echo "$line" | awk '{print $2}')
        rec_msg=$(echo "$line" | cut -d' ' -f3-)
        if grep -Eq "^\s*${pattern}" "$sshd_config" 2>/dev/null; then
            $level "Found dangerous SSH setting: $pattern"
            rec  "$rec_msg"
        fi
    done
fi

# ────────────────────────────────────────────────
# 5. Firewall & Network
# ────────────────────────────────────────────────
print_header "FIREWALL & NETWORK"

if is_command ufw; then
    ufw status | grep -q "Status: active" || fail "UFW is not active"
fi

if is_command firewall-cmd; then
    firewall-cmd --state >/dev/null 2>&1 || fail "firewalld is not running"
fi

if is_command iptables; then
    iptables -nL | grep -q "Chain INPUT.*policy ACCEPT" && warn "iptables INPUT policy is ACCEPT"
fi

info "Listening ports (non-loopback):"
ss -tuln 2>/dev/null | grep -v "127.0.0.1\|::1" | grep LISTEN || info "(none found)"

# ────────────────────────────────────────────────
# 6. Kernel & Sysctl Hardening
# ────────────────────────────────────────────────
print_header "KERNEL HARDENING (sysctl)"

common_hardening=(
    "net.ipv4.ip_forward=0"
    "net.ipv4.conf.all.accept_redirects=0"
    "net.ipv4.conf.all.send_redirects=0"
    "net.ipv4.conf.all.accept_source_route=0"
    "net.ipv4.icmp_echo_ignore_broadcasts=1"
    "net.ipv4.icmp_ignore_bogus_error_responses=1"
    "kernel.kptr_restrict=2"
    "kernel.dmesg_restrict=1"
    "kernel.randomize_va_space=2"
    "kernel.sysrq=0"
    "kernel.yama.ptrace_scope=1"
)

for setting in "${common_hardening[@]}"; do
    key="${setting%%=*}"
    val="${setting#*=}"
    current=$(sysctl -n "$key" 2>/dev/null || echo "not set")
    if [[ "$current" != "$val" ]]; then
        warn "$key = $current  (expected $val)"
        rec  "echo '$setting' >> /etc/sysctl.d/99-hardening.conf && sysctl -p"
    fi
done

# ────────────────────────────────────────────────
# 7. Filesystem & Mount Options
# ────────────────────────────────────────────────
print_header "FILESYSTEM MOUNT OPTIONS"

mount | grep -E '\s(/tmp|/var|/var/tmp|/dev/shm)\s' | while read -r line; do
    if ! echo "$line" | grep -q "nodev"; then warn "/tmp-like mount missing nodev: $line"; fi
    if ! echo "$line" | grep -q "nosuid"; then warn "/tmp-like mount missing nosuid: $line"; fi
    if ! echo "$line" | grep -q "noexec"; then warn "/tmp-like mount missing noexec: $line"; fi
done

# ────────────────────────────────────────────────
# 8. SUID/SGID Binaries
# ────────────────────────────────────────────────
print_header "SUID / SGID BINARIES"

info "Listing SUID/SGID binaries (review for unexpected ones)"
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -not -path "/snap/*" 2>/dev/null | sort | head -n 40

# ────────────────────────────────────────────────
# 9. MALICIOUS / SUSPICIOUS FILE PATTERNS
# ────────────────────────────────────────────────
print_header "MALICIOUS / SUSPICIOUS FILE PATTERNS"

info "Scanning common writeable locations for suspicious filenames/patterns..."
info "(Heuristic scan — many hits expected in vulnerable labs/CTFs)"

suspect_dirs=(
    "/tmp" "/var/tmp" "/dev/shm"
    "/var/www/html" "/var/www" "/usr/share/nginx/html" "/var/lib/php/sessions"
    "/home" "/root" "/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly"
)

# Webshell / backdoor patterns
webshell_patterns=(
    "shell.php" "webshell.php" "backdoor.php" "cmd.php" "php-reverse-shell.php"
    "c99.php" "r57.php" "wso.php" "sym.php" "indoxploit.php" "alfa.php"
    ".php." ".php " ".php.jpg" ".php.gif" ".php%00" ".php.bak" ".php.old"
)

miner_patterns=(
    "xmrig" "kinsing" "kthreaddi" "kswapd0" "kpsmoused" "khugepageds"
    "xm" "miner" "monero" "crypto" "pool.mine" "stratum+tcp"
)

backdoor_patterns=(
    "rshell" "revshell" "shell.py" "shell.sh" "reverse.sh" "back.sh"
    "nc.sh" "socat" "netcat" "bash -i" "python -c" "perl -e"
    "run.sh" "start.sh" "update.sh" "install.sh" ".sh" ".py.bak"
)

all_patterns=("${webshell_patterns[@]}" "${miner_patterns[@]}" "${backdoor_patterns[@]}")

echo -e "${YELLOW}→ Webshell / backdoor name matches:${NC}"
for dir in "${suspect_dirs[@]}"; do
    [[ -d "$dir" ]] || continue
    find "$dir" -type f \( -iname "*.php*" -o -iname "*.phtml*" -o -iname "*.jsp*" -o -iname "*.asp*" \) 2>/dev/null |
    grep -Ei "$(IFS="|"; echo "${all_patterns[*]}")" 2>/dev/null |
    head -n 12 | while read -r f; do
        fail "Suspicious file: $f"
        rec  "Review contents → rm if malicious (backup first!)"
    done
done

echo -e "\n${YELLOW}→ Miner / common malware droppers:${NC}"
for dir in "${suspect_dirs[@]}"; do
    [[ -d "$dir" ]] || continue
    find "$dir" -type f \( -iname "*xmrig*" -o -iname "*kinsing*" -o -iname "*kthreaddi*" -o -iname "*mine*" \) 2>/dev/null |
    head -n 10 | while read -r f; do
        fail "Possible miner / dropper: $f"
        rec  "Check: ps auxf | grep -i $(basename "$f")"
        rec  "strings \"$f\" | grep -i pool"
    done
done

echo -e "\n${YELLOW}→ Executables / scripts in suspicious locations:${NC}"
for dir in "${suspect_dirs[@]}"; do
    [[ -d "$dir" ]] || continue
    find "$dir" -type f \( -perm -100 -o -name "*.sh" -o -name "*.py" -o -name "*.pl" \) 2>/dev/null |
    grep -vE "/snap/|/vendor/|/node_modules/" | head -n 15 | while read -r f; do
        warn "Executable/script in odd location: $f"
        rec  "ls -la \"$f\"; file \"$f\"; head -n 10 \"$f\""
    done
done

echo -e "\n${YELLOW}→ Hidden files with suspicious extensions:${NC}"
for dir in "${suspect_dirs[@]}"; do
    [[ -d "$dir" ]] || continue
    find "$dir" -type f -name ".*" 2>/dev/null |
    grep -Ei "\.(sh|py|pl|elf|bin|so|php|jpg|png|gif|rar|zip)$" |
    head -n 10 | while read -r f; do
        warn "Hidden suspicious file: $f"
        rec  "file \"$f\"; head -n 15 \"$f\""
    done
done

echo -e "\n${YELLOW}→ Recently modified files in volatile dirs (last 7 days):${NC}"
for dir in /tmp /var/tmp /dev/shm; do
    [[ -d "$dir" ]] || continue
    find "$dir" -type f -mtime -7 -ls 2>/dev/null | head -n 15
    info "(review any unfamiliar recent files)"
done

# ────────────────────────────────────────────────
# 10. SUMMARY & NEXT STEPS
# ────────────────────────────────────────────────
print_header "SUMMARY & NEXT STEPS"

info "This script is intentionally noisy — many [WARN]/[FAIL] messages are expected in a vulnerable lab."
info "Top remediation priorities usually are:"

cat << 'EOF'
  1. Disable root SSH login → PermitRootLogin no + use key-based auth only
  2. Fix permissions on /etc/shadow, /etc/passwd, /etc/sudoers
  3. Remove or lock accounts with empty/no password
  4. Apply sysctl hardening settings
  5. Activate & properly configure a firewall (ufw/firewalld/iptables)
  6. Review and remove suspicious files in /tmp, /dev/shm, web roots
  7. Audit SUID/SGID binaries and world-writable files
EOF

echo -e "\n${GREEN}Audit complete. Review carefully and harden step-by-step.${NC}"
echo "Additional tools to consider (if installed):"
echo "  • lynis audit system"
echo "  • rkhunter --check"
echo "  • clamscan -r /tmp /var/tmp /dev/shm"
echo "  • debsums -c   (on Debian/Ubuntu) or rpm -Va (on RPM-based)"

echo -e "\n${CYAN}Happy (ethical) hacking & good luck with your lab assessment!${NC}"

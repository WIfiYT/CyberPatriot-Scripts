#!/bin/bash
# CyberPatriot Linux Quick Audit Script
# Checks for common permission issues, scripts, services, and other hardening items
# Run with sudo for best results
# Usage: sudo bash audit.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

section() {
    echo -e "\n${CYAN}========== $1 ==========${NC}\n"
}

warn() {
    echo -e "${YELLOW}[!] $1${NC}"
}

good() {
    echo -e "${GREEN}[+] $1${NC}"
}

bad() {
    echo -e "${RED}[-] $1${NC}"
}

section "1. WORLD-WRITABLE FILES (dangerous, especially outside /tmp)"
# Find world-writable files, exclude common temporary locations
find / -type f -perm -0002 -not -path "/tmp/*" -not -path "/var/tmp/*" -not -path "/dev/*" -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | head -50 | while read -r f; do
    bad "World-writable: $f"
done
good "World-writable check complete (showing first 50)"

section "2. SUID / SGID BINARIES (potential privilege escalation)"
find / -type f \( -perm -4000 -o -perm -2000 \) -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | head -40 | while read -r f; do
    ls -l "$f" 2>/dev/null
done
good "SUID/SGID check complete"

section "3. ALL SCRIPTS ON SYSTEM"
# Common script extensions + shebang detection
warn "Executable scripts (.sh, .py, .pl, .rb) and files with shebang:"
find / -type f \( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.rb" -o -name "*.bash" \) -executable 2>/dev/null | head -30
echo
warn "Files with shebang in /usr/local, /opt, /home, /var:"
find /usr/local /opt /home /var -type f -executable -exec grep -l '^#!' {} \; 2>/dev/null | head -30
good "Script listing complete (limited output)"

section "4. SYSTEMD SERVICE UNIT FILES WITH BAD PERMISSIONS"
# Check for world-writable or group-writable unit files
find /etc/systemd /lib/systemd /usr/lib/systemd -type f -name "*.service" \( -perm -0002 -o -perm -0020 \) 2>/dev/null | while read -r f; do
    bad "Writable service file: $f"
    ls -l "$f"
done
good "Service unit permission check complete"

section "5. RUNNING SERVICES AND THEIR EXECUTABLES"
echo -e "${CYAN}Active services and their main executable:${NC}"
systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print $1}' | while read -r svc; do
    echo -e "\n${YELLOW}Service: $svc${NC}"
    systemctl show "$svc" -p ExecStart -p User -p Group --no-pager 2>/dev/null | sed 's/^/  /'
    # Try to extract binary path
    binary=$(systemctl show "$svc" -p ExecStart --value 2>/dev/null | grep -oE '/[^ ]+' | head -1)
    if [[ -n "$binary" && -f "$binary" ]]; then
        echo "  Binary: $binary"
        ls -l "$binary" 2>/dev/null | sed 's/^/  /'
    fi
done
good "Running services listed"

section "6. ADDITIONAL COMMON CYBERPATRIOT CHECKS"

warn "World-readable sensitive files:"
ls -l /etc/shadow /etc/gshadow /etc/passwd /etc/group 2>/dev/null | grep -E '^-r..r' && bad "Shadow or group files are world-readable!" || good "Shadow/group permissions look OK"

warn "Users with empty passwords:"
awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null | while read -r u; do
    bad "Empty password: $u"
done

warn "Sudoers with NOPASSWD:"
grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#' && bad "Found NOPASSWD entries" || good "No obvious NOPASSWD"

warn "Cron jobs (system and user):"
ls -la /etc/cron.* /var/spool/cron 2>/dev/null | head -20
echo "--- User crontabs ---"
for u in $(cut -f1 -d: /etc/passwd); do
    crontab -l -u "$u" 2>/dev/null | grep -v '^#' && echo "User $u has crontab"
done

warn "Authorized SSH keys:"
find /home /root -name "authorized_keys" -type f 2>/dev/null | while read -r k; do
    echo "Found: $k"
    ls -l "$k"
    wc -l "$k"
done

warn "Listening network services (common ports):"
ss -tulpn 2>/dev/null | head -30 || netstat -tulpn 2>/dev/null | head -30

warn "Recently modified files in critical directories (last 7 days):"
find /etc /usr/bin /usr/sbin /bin /sbin -type f -mtime -7 2>/dev/null | head -20

section "AUDIT COMPLETE"
echo -e "${GREEN}Review the output above carefully.${NC}"
echo "Tip: Save this output with: sudo bash $0 | tee audit_$(date +%Y%m%d_%H%M).txt"
echo "Common fixes:"
echo "  - chmod 644 or 755 on world-writable files"
echo "  - Remove unnecessary SUID bits (chmod u-s)"
echo "  - Lock accounts: passwd -l username"
echo "  - systemctl disable --now service"
echo "  - Review and clean cron jobs / authorized_keys"

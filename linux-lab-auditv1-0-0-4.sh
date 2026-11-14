#!/usr/bin/env bash
# ============================================================
# CyberPatriot Linux Security Audit + Optional Hardening
# Credit: WifiStudios
# Head Coders: unknownentity57, Suo644
# Version: 2.1 (Interactive)
# ============================================================
# Does more than v1.0.0.3 and asks before making changes.
# If you say no to one action, it offers a different one.

set -u
PATH="/usr/sbin:/usr/bin:/sbin:/bin"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

print_header() { echo -e "\n${BLUE}════════════════════════════════════════════════${NC}\n${BLUE} $1 ${NC}\n${BLUE}════════════════════════════════════════════════${NC}\n"; }
pass() { echo -e "[${GREEN}PASS${NC}] $1"; }
warn() { echo -e "[${YELLOW}WARN${NC}] $1"; }
fail() { echo -e "[${RED}FAIL${NC}] $1"; }
info() { echo -e "[${CYAN}INFO${NC}] $1"; }
rec()  { echo -e "   → $1"; }

ask() {
    local prompt="$1"
    local default="${2:-n}"
    read -rp "$prompt [y/N]: " reply
    reply=${reply:-$default}
    [[ "$reply" =~ ^[Yy] ]] && return 0 || return 1
}

print_header "SYSTEM INFORMATION"
info "Hostname : $(hostname)"
info "OS       : $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || echo unknown)"
info "Kernel   : $(uname -r)"
if [[ $EUID -ne 0 ]]; then
    fail "Not running as root"
    echo "Please re-run with: sudo bash \"$0\""
    exit 1
fi

# ==================== USERS ====================
print_header "USER & PASSWORD AUDIT"
info "Scanning for empty-password and extra UID 0 accounts..."
empty_users=$(awk -F: '($2 == "" || $2 == "!" || $2 == "*") && $1 != "root" {print $1}' /etc/shadow 2>/dev/null)
uid0_users=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)

if [[ -n "$empty_users" ]]; then
    fail "Empty/locked password accounts found: $empty_users"
    if ask "Lock these accounts now?"; then
        for u in $empty_users; do passwd -l "$u" && info "Locked $u"; done
    else
        if ask "Show detailed password aging info instead?"; then
            for u in $empty_users; do chage -l "$u"; done
        fi
    fi
else
    pass "No empty-password accounts found"
fi

if [[ -n "$uid0_users" ]]; then
    fail "Extra UID 0 accounts: $uid0_users"
    if ask "Remove these extra UID 0 accounts?"; then
        for u in $uid0_users; do userdel -r "$u" 2>/dev/null && info "Removed $u"; done
    else
        if ask "Just list their groups and home directories instead?"; then
            for u in $uid0_users; do id "$u"; ls -ld /home/"$u" 2>/dev/null; done
        fi
    fi
fi

# ==================== SSH ====================
print_header "SSH HARDENING"
sshd="/etc/ssh/sshd_config"
if [[ -f "$sshd" ]]; then
    if grep -Eq '^PermitRootLogin\s+yes' "$sshd"; then
        fail "PermitRootLogin is yes"
        if ask "Disable root SSH login now?"; then
            sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$sshd"
            info "Set PermitRootLogin no (restart SSH later to apply)"
        else
            if ask "Show current SSH config highlights instead?"; then
                grep -E '^(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|X11Forwarding)' "$sshd"
            fi
        fi
    else
        pass "Root SSH login already restricted"
    fi
fi

# ==================== FIREWALL ====================
print_header "FIREWALL"
if command -v ufw >/dev/null; then
    if ! ufw status | grep -q "Status: active"; then
        fail "UFW is inactive"
        if ask "Enable UFW now (default deny incoming)?"; then
            ufw --force enable
            ufw default deny incoming
            ufw default allow outgoing
            info "UFW enabled"
        else
            if ask "Show current listening ports instead?"; then
                ss -tuln | grep LISTEN
            fi
        fi
    else
        pass "UFW is active"
    fi
fi

# ==================== SYSCTL ====================
print_header "KERNEL HARDENING"
if ask "Apply recommended sysctl hardening settings?"; then
    cat > /etc/sysctl.d/99-cyberpatriot.conf << 'EOF'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
EOF
    sysctl -p /etc/sysctl.d/99-cyberpatriot.conf
    info "Sysctl hardening applied"
else
    if ask "Just show current values of key sysctl settings?"; then
        sysctl net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects kernel.randomize_va_space 2>/dev/null
    fi
fi

# ==================== SUSPICIOUS FILES ====================
print_header "SUSPICIOUS FILES"
info "Scanning common locations..."
suspicious=$(find /tmp /var/tmp /dev/shm /var/www -type f \( -iname "*shell*" -o -iname "*backdoor*" -o -iname "*xmrig*" -o -iname "*miner*" \) 2>/dev/null | head -n 15)
if [[ -n "$suspicious" ]]; then
    fail "Suspicious files found:"
    echo "$suspicious"
    if ask "Delete these suspicious files?"; then
        echo "$suspicious" | xargs -r rm -f
        info "Deleted listed files"
    else
        if ask "Show file types and first few lines instead?"; then
            echo "$suspicious" | while read -r f; do
                echo "=== $f ==="
                file "$f"
                head -n 5 "$f" 2>/dev/null
                echo
            done
        fi
    fi
else
    pass "No obvious suspicious files in scanned directories"
fi

# ==================== PROCESSES ====================
print_header "RUNNING PROCESSES"
deleted=$(ls -l /proc/*/exe 2>/dev/null | grep '(deleted)' || true)
if [[ -n "$deleted" ]]; then
    fail "Processes with deleted executables found"
    echo "$deleted"
    if ask "Kill these processes?"; then
        echo "$deleted" | awk -F/ '{print $3}' | xargs -r kill -9
        info "Killed processes"
    else
        if ask "Show full process details instead?"; then
            echo "$deleted" | awk -F/ '{print $3}' | while read -r pid; do ps -p "$pid" -f; done
        fi
    fi
else
    pass "No processes with deleted executables"
fi

# ==================== CRON ====================
print_header "CRON AUDIT"
if ask "Show all user and system cron jobs?"; then
    for user in $(getent passwd | cut -d: -f1); do
        crontab -u "$user" -l 2>/dev/null | grep -v '^#' | grep -q . && {
            info "Crontab for $user:"
            crontab -u "$user" -l 2>/dev/null
        }
    done
    ls /etc/cron.* /etc/crontab 2>/dev/null
fi

print_header "AUDIT COMPLETE"
echo -e "${GREEN}Finished. Credit: WifiStudios${NC}"
echo "You can re-run this script anytime. All changes were optional."

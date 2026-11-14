#!/bin/bash
# =============================================================================
# CyberPatriot Linux Hardening Script
# Inspired by and credits: https://github.com/BiermanM/CyberPatriot-Scripts
# Created for team use - WifiStudios / CyberPatriot Round 1 preparation
# Target: Ubuntu / Debian-based systems
# =============================================================================
# WARNING: This script makes significant system changes. Always review the
# README for the competition image first. Run only after forensic questions.
# Test on practice images. Use at your own risk.
# =============================================================================

set -u
# set -e is disabled for more resilient execution during competition

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_DIR="/root/cyberpatriot_logs"
BACKUP_DIR="/root/cyberpatriot_backups"
COMPARATIVE_DIR="/root/cyberpatriot_comparative_${TIMESTAMP}"
LOGFILE="${LOG_DIR}/hardening_${TIMESTAMP}.log"

mkdir -p "$LOG_DIR" "$BACKUP_DIR" "$COMPARATIVE_DIR"
touch "$LOGFILE"
chmod 600 "$LOGFILE" "$LOG_DIR" "$BACKUP_DIR" "$COMPARATIVE_DIR" 2>/dev/null || true

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
log() {
    local msg="$1"
    local ts
    ts=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[${ts}] ${msg}" | tee -a "$LOGFILE"
}

log_section() {
    echo "" | tee -a "$LOGFILE"
    echo "========== $1 ==========" | tee -a "$LOGFILE"
}

# -----------------------------------------------------------------------------
# Root Check
# -----------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root."
    exit 1
fi
log "Script started as root. Log: $LOGFILE"

# -----------------------------------------------------------------------------
# Backup Critical Files
# -----------------------------------------------------------------------------
backup_critical() {
    log_section "Backing up critical files"
    local files=(
        /etc/passwd /etc/shadow /etc/group /etc/gshadow
        /etc/sudoers /etc/sudoers.d
        /etc/ssh/sshd_config
        /etc/hosts /etc/host.conf
        /etc/sysctl.conf
        /etc/login.defs
        /etc/pam.d/common-auth /etc/pam.d/common-password /etc/pam.d/common-account
        /etc/lightdm/lightdm.conf
        /etc/crontab /etc/cron.allow /etc/cron.deny
        /etc/rc.local
        /etc/apt/sources.list
        /etc/default/irqbalance
    )
    for f in "${files[@]}"; do
        if [[ -f "$f" ]]; then
            cp -a "$f" "$BACKUP_DIR/" 2>/dev/null && log "Backed up $f"
            cp -a "$f" "$COMPARATIVE_DIR/" 2>/dev/null
        fi
    done
    # Additional system state for comparative
    ps aux > "$COMPARATIVE_DIR/processes.txt" 2>/dev/null
    ss -tulpn > "$COMPARATIVE_DIR/listening_ports.txt" 2>/dev/null || netstat -tulpn > "$COMPARATIVE_DIR/listening_ports.txt" 2>/dev/null
    dpkg -l > "$COMPARATIVE_DIR/packages.txt" 2>/dev/null
    systemctl list-unit-files --type=service > "$COMPARATIVE_DIR/services.txt" 2>/dev/null
    crontab -l > "$COMPARATIVE_DIR/root_crontab.txt" 2>/dev/null
    log "Critical files and system state backed up to $BACKUP_DIR and $COMPARATIVE_DIR"
}

# -----------------------------------------------------------------------------
# User Management
# -----------------------------------------------------------------------------
manage_users() {
    log_section "User Management"
    echo "Current users (UID >= 1000):"
    awk -F: '$3 >= 1000 && $3 < 65534 {print $1, $3}' /etc/passwd
    echo ""
    echo "1) Add user"
    echo "2) Remove user (and home)"
    echo "3) Modify privileges (add/remove from sudo/admin)"
    echo "4) Change user password"
    echo "5) List all users with details"
    echo "0) Back"
    read -rp "Choice: " choice
    case $choice in
        1)
            read -rp "New username: " uname
            if [[ -n "$uname" ]]; then
                adduser "$uname"
                read -rp "Make admin (sudo)? [y/N]: " admin
                if [[ "$admin" =~ ^[Yy]$ ]]; then
                    usermod -aG sudo "$uname" 2>/dev/null || usermod -aG admin "$uname"
                    log "Added user $uname and made admin"
                else
                    log "Added user $uname"
                fi
            fi
            ;;
        2)
            read -rp "Username to remove: " uname
            if [[ -n "$uname" && "$uname" != "root" ]]; then
                userdel -r "$uname" 2>/dev/null && log "Removed user $uname and home" || log "Failed to remove $uname"
            fi
            ;;
        3)
            read -rp "Username: " uname
            echo "1) Add to sudo  2) Remove from sudo"
            read -rp "Choice: " p
            if [[ "$p" == "1" ]]; then
                usermod -aG sudo "$uname" && log "Added $uname to sudo"
            elif [[ "$p" == "2" ]]; then
                gpasswd -d "$uname" sudo 2>/dev/null; gpasswd -d "$uname" admin 2>/dev/null
                log "Removed $uname from sudo/admin"
            fi
            ;;
        4)
            read -rp "Username to change password: " uname
            passwd "$uname"
            log "Password changed for $uname"
            ;;
        5)
            getent passwd | awk -F: '$3 >= 1000 {print}'
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Remove Aliases
# -----------------------------------------------------------------------------
remove_aliases() {
    log_section "Removing aliases"
    # Common places for malicious aliases
    for file in /root/.bashrc /root/.bash_aliases /etc/bash.bashrc /etc/profile; do
        if [[ -f "$file" ]]; then
            sed -i '/^alias /d' "$file" 2>/dev/null
            log "Cleared aliases in $file"
        fi
    done
    # Check all users
    for home in /home/* /root; do
        [[ -d "$home" ]] || continue
        for f in "$home/.bashrc" "$home/.bash_aliases" "$home/.profile"; do
            [[ -f "$f" ]] && sed -i '/^alias /d' "$f" 2>/dev/null && log "Cleared aliases in $f"
        done
    done
    unalias -a 2>/dev/null || true
    log "Alias removal complete"
}

# -----------------------------------------------------------------------------
# Lock root & Shadow permissions
# -----------------------------------------------------------------------------
lock_root_and_shadow() {
    log_section "Locking root and securing shadow"
    usermod -L root 2>/dev/null && log "Root account locked (usermod -L)"
    passwd -l root 2>/dev/null
    chmod 640 /etc/shadow 2>/dev/null || chmod 600 /etc/shadow
    chown root:shadow /etc/shadow 2>/dev/null || chown root:root /etc/shadow
    chmod 640 /etc/gshadow 2>/dev/null
    log "Shadow permissions set (640 recommended)"
}

# -----------------------------------------------------------------------------
# Remove unnecessary home directories
# -----------------------------------------------------------------------------
clean_home_dirs() {
    log_section "Cleaning unnecessary /home directories"
    echo "Current /home contents:"
    ls -la /home/
    read -rp "Enter usernames (space separated) whose homes to KEEP, or 'none' to review manually: " keep
    if [[ "$keep" != "none" ]]; then
        for dir in /home/*; do
            [[ -d "$dir" ]] || continue
            user=$(basename "$dir")
            if ! echo "$keep" | grep -qw "$user"; then
                read -rp "Remove home directory for $user? [y/N]: " yn
                if [[ "$yn" =~ ^[Yy]$ ]]; then
                    rm -rf "$dir" && log "Removed /home/$user"
                fi
            fi
        done
    fi
}

# -----------------------------------------------------------------------------
# Firewall
# -----------------------------------------------------------------------------
enable_firewall() {
    log_section "Enabling firewall (ufw)"
    apt-get update -qq
    apt-get install -y ufw iptables 2>/dev/null
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    # Allow common necessary if prompted later
    ufw enable
    ufw status verbose | tee -a "$LOGFILE"
    log "UFW enabled with default deny incoming"
}

# -----------------------------------------------------------------------------
# Shellshock fix
# -----------------------------------------------------------------------------
fix_shellshock() {
    log_section "Fixing Shellshock (Bash vulnerability)"
    apt-get update -qq
    apt-get install --only-upgrade bash -y
    # Test
    env x='() { :;}; echo vulnerable' bash -c "echo" 2>&1 | grep -q vulnerable && log "WARNING: Still vulnerable?" || log "Bash appears patched"
    bash --version | head -1 | tee -a "$LOGFILE"
}

# -----------------------------------------------------------------------------
# Hosts file defaults
# -----------------------------------------------------------------------------
reset_hosts() {
    log_section "Resetting /etc/hosts to defaults"
    cp /etc/hosts "$BACKUP_DIR/hosts.bak" 2>/dev/null
    cat > /etc/hosts << 'EOF'
127.0.0.1   localhost
127.0.1.1   $(hostname)
::1         localhost ip6-localhost ip6-loopback
fe00::0     ip6-localnet
ff00::0     ip6-mcastprefix
ff02::1     ip6-allnodes
ff02::2     ip6-allrouters
EOF
    # Expand hostname
    sed -i "s/\$(hostname)/$(hostname)/" /etc/hosts
    chmod 644 /etc/hosts
    log "/etc/hosts reset to defaults"
}

# -----------------------------------------------------------------------------
# Secure LightDM
# -----------------------------------------------------------------------------
secure_lightdm() {
    log_section "Securing LightDM"
    local conf="/etc/lightdm/lightdm.conf"
    mkdir -p /etc/lightdm
    if [[ ! -f "$conf" ]]; then
        touch "$conf"
    fi
    cp "$conf" "$BACKUP_DIR/" 2>/dev/null
    # Ensure [Seat:*] or [SeatDefaults]
    grep -q "allow-guest=false" "$conf" || echo -e "\n[Seat:*]\nallow-guest=false\ngreeter-hide-users=true\ngreeter-show-manual-login=true" >> "$conf"
    chmod 644 "$conf"
    log "LightDM secured (guest disabled, hide users)"
}

# -----------------------------------------------------------------------------
# Remove scripts in /bin (careful - only suspicious)
# -----------------------------------------------------------------------------
clean_bin_scripts() {
    log_section "Checking /bin and /usr/bin for suspicious scripts"
    echo "Listing non-standard or recently modified files in /bin /usr/bin (review carefully):"
    find /bin /usr/bin -type f -mtime -30 -ls 2>/dev/null | head -50
    log "Review complete. Manually remove any unauthorized scripts."
}

# -----------------------------------------------------------------------------
# Disable IRQ Balance
# -----------------------------------------------------------------------------
disable_irqbalance() {
    log_section "Disabling IRQ Balance"
    if [[ -f /etc/default/irqbalance ]]; then
        sed -i 's/ENABLED=.*/ENABLED="0"/' /etc/default/irqbalance
        systemctl stop irqbalance 2>/dev/null
        systemctl disable irqbalance 2>/dev/null
        log "IRQ Balance disabled"
    else
        log "irqbalance config not found"
    fi
}

# -----------------------------------------------------------------------------
# Configure sysctl
# -----------------------------------------------------------------------------
configure_sysctl() {
    log_section "Configuring sysctl hardening"
    cp /etc/sysctl.conf "$BACKUP_DIR/" 2>/dev/null
    cat >> /etc/sysctl.conf << 'EOF'

# CyberPatriot hardening
net.ipv4.ip_forward = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.icmp_echo_ignore_all = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
fs.suid_dumpable = 0
EOF
    sysctl -p 2>/dev/null || true
    log "sysctl hardening applied"
}

# -----------------------------------------------------------------------------
# IPv6 enable/disable
# -----------------------------------------------------------------------------
toggle_ipv6() {
    log_section "IPv6 Configuration"
    echo "1) Disable IPv6  2) Enable IPv6  3) Skip"
    read -rp "Choice: " c
    case $c in
        1)
            sysctl -w net.ipv6.conf.all.disable_ipv6=1
            sysctl -w net.ipv6.conf.default.disable_ipv6=1
            echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
            echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
            log "IPv6 disabled"
            ;;
        2)
            sysctl -w net.ipv6.conf.all.disable_ipv6=0
            sysctl -w net.ipv6.conf.default.disable_ipv6=0
            sed -i '/disable_ipv6/d' /etc/sysctl.conf
            log "IPv6 enabled"
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Service management (generic)
# -----------------------------------------------------------------------------
manage_service() {
    local svc="$1"
    local pkg="$2"
    local port="$3"
    log_section "Managing $svc"
    echo "1) Install and configure $svc"
    echo "2) Remove/purge $svc"
    echo "0) Skip"
    read -rp "Choice: " c
    case $c in
        1)
            apt-get install -y "$pkg"
            systemctl enable "$svc" 2>/dev/null
            systemctl start "$svc" 2>/dev/null
            if [[ -n "$port" ]]; then
                ufw allow "$port" 2>/dev/null
            fi
            log "$svc installed and enabled (port $port allowed)"
            # Basic config notes
            echo "NOTE: Manually review config for $svc after install."
            ;;
        2)
            systemctl stop "$svc" 2>/dev/null
            systemctl disable "$svc" 2>/dev/null
            apt-get purge -y "$pkg" 2>/dev/null
            apt-get autoremove -y
            if [[ -n "$port" ]]; then
                ufw deny "$port" 2>/dev/null
            fi
            log "$svc removed and port $port denied"
            ;;
    esac
}

# Specific services
manage_samba() { manage_service "smbd" "samba" "139,445"; }
manage_ftp() { manage_service "vsftpd" "vsftpd" "21"; }
manage_ssh() {
    manage_service "ssh" "openssh-server" "22"
    if systemctl is-active --quiet ssh 2>/dev/null; then
        # Basic secure config
        sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
        sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
        sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
        systemctl restart ssh
        log "SSH basic hardening applied (no root login)"
    fi
}
manage_telnet() { manage_service "inetd" "telnetd" "23"; }
manage_mail() { manage_service "postfix" "postfix" "25"; }
manage_printing() { manage_service "cups" "cups" "631"; }
manage_mysql() { manage_service "mysql" "mysql-server" "3306"; }
manage_web() { manage_service "apache2" "apache2" "80,443"; }
manage_dns() { manage_service "bind9" "bind9" "53"; }

# -----------------------------------------------------------------------------
# Remove media files
# -----------------------------------------------------------------------------
remove_media() {
    log_section "Removing media files"
    local exts="mp3 mp4 avi mov wmv mkv flv jpg jpeg png gif bmp wav wma aac m4a"
    for ext in $exts; do
        find /home /root /tmp /var/tmp -type f -iname "*.$ext" -delete 2>/dev/null
    done
    log "Media files (common extensions) removed from home/tmp"
}

# -----------------------------------------------------------------------------
# List files with 700-777 and PHP files
# -----------------------------------------------------------------------------
list_perms_and_php() {
    log_section "Listing high permission files and PHP files"
    echo "Files with permissions 700-777 (world/group writable or executable suspicious):"
    find / -type f -perm -700 -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" 2>/dev/null | head -100 | tee -a "$LOGFILE"
    echo ""
    echo "PHP files:"
    find / -type f -name "*.php" 2>/dev/null | head -50 | tee -a "$LOGFILE"
    log "Listing complete (truncated to 100/50 for performance)"
}

# -----------------------------------------------------------------------------
# Remove hacking tools
# -----------------------------------------------------------------------------
remove_hacking_tools() {
    log_section "Removing known hacking tools"
    local packages=(
        netcat netcat-openbsd netcat-traditional ncat
        john john-data hydra hydra-gtk
        aircrack-ng fcrackzip lcrack ophcrack ophcrack-cli
        pdfcrack pyrit rarcrack sipcrack irpas
        logkeys zeitgeist zeitgeist-core zeitgeist-datahub
        nfs-common nfs-kernel-server
        nginx nginx-common
        openbsd-inetd inetutils-inetd
        vnc4server tightvncserver xtightvncviewer
        snmp snmpd
    )
    for pkg in "${packages[@]}"; do
        apt-get purge -y "$pkg" 2>/dev/null && log "Purged $pkg" || true
    done
    # Force remove nc binary if present
    rm -f /usr/bin/nc /bin/nc 2>/dev/null
    apt-get autoremove -y
    log "Hacking tools purge complete"
}

# -----------------------------------------------------------------------------
# Password policies
# -----------------------------------------------------------------------------
set_password_policies() {
    log_section "Setting login.defs and PAM password policies"
    # login.defs
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs
    grep -q "^PASS_MIN_LEN" /etc/login.defs || echo "PASS_MIN_LEN 12" >> /etc/login.defs
    log "login.defs updated (max 90, min 7, warn 14)"

    # PAM
    apt-get install -y libpam-pwquality libpam-cracklib 2>/dev/null
    # Backup
    cp /etc/pam.d/common-password "$BACKUP_DIR/" 2>/dev/null
    # Ensure complexity (modern systems use pwquality)
    if grep -q "pam_pwquality" /etc/pam.d/common-password; then
        sed -i 's/pam_pwquality.so.*/pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password
    else
        echo "password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1" >> /etc/pam.d/common-password
    fi
    # Account lockout
    if ! grep -q "pam_tally2" /etc/pam.d/common-auth && ! grep -q "pam_faillock" /etc/pam.d/common-auth; then
        sed -i '1i auth required pam_tally2.so deny=5 unlock_time=1800 onerr=fail audit even_deny_root' /etc/pam.d/common-auth
    fi
    log "PAM password complexity and lockout configured"
}

# -----------------------------------------------------------------------------
# Deny false loopback packets
# -----------------------------------------------------------------------------
deny_false_loopback() {
    log_section "Denying false loopback packets"
    iptables -A INPUT -i eth0 -s 127.0.0.0/8 -j DROP 2>/dev/null
    iptables -A INPUT -i ens* -s 127.0.0.0/8 -j DROP 2>/dev/null || true
    # Persist if possible
    if command -v iptables-persistent >/dev/null; then
        apt-get install -y iptables-persistent
        netfilter-persistent save 2>/dev/null
    fi
    log "Rules added to drop packets from loopback on external interfaces"
}

# -----------------------------------------------------------------------------
# Disable Ctrl-Alt-Del
# -----------------------------------------------------------------------------
disable_ctrl_alt_del() {
    log_section "Disabling Ctrl-Alt-Del reboot"
    systemctl mask ctrl-alt-del.target 2>/dev/null
    systemctl daemon-reload
    # Legacy
    if [[ -f /etc/init/control-alt-delete.conf ]]; then
        echo "exec true" > /etc/init/control-alt-delete.conf
    fi
    log "Ctrl-Alt-Del disabled"
}

# -----------------------------------------------------------------------------
# Install AppArmor
# -----------------------------------------------------------------------------
install_apparmor() {
    log_section "Installing and enabling AppArmor"
    apt-get install -y apparmor apparmor-utils
    systemctl enable apparmor
    systemctl start apparmor
    aa-status 2>/dev/null | head -20 | tee -a "$LOGFILE"
    log "AppArmor installed and enabled"
}

# -----------------------------------------------------------------------------
# Crontab cleanup
# -----------------------------------------------------------------------------
clean_crontab() {
    log_section "Cleaning crontab and restricting to root"
    # Backup
    crontab -l > "$BACKUP_DIR/root_crontab.bak" 2>/dev/null
    # Remove user crontabs except root
    for user in $(cut -d: -f1 /etc/passwd); do
        if [[ "$user" != "root" ]]; then
            crontab -u "$user" -r 2>/dev/null && log "Cleared crontab for $user"
        fi
    done
    # Restrict
    echo "root" > /etc/cron.allow
    rm -f /etc/cron.deny
    chmod 644 /etc/cron.allow
    log "Only root allowed in cron; other user crontabs cleared"
}

# -----------------------------------------------------------------------------
# APT repositories and updates
# -----------------------------------------------------------------------------
update_system() {
    log_section "Updating system and managing packages"
    # Basic secure sources (Ubuntu/Debian generic - user should verify)
    cp /etc/apt/sources.list "$BACKUP_DIR/" 2>/dev/null
    apt-get update
    apt-get upgrade -y
    apt-get dist-upgrade -y
    apt-get autoremove -y
    apt-get autoclean
    log "System updated and unused packages removed"
}

# -----------------------------------------------------------------------------
# OpenSSL Heartbleed fix
# -----------------------------------------------------------------------------
fix_heartbleed() {
    log_section "Fixing OpenSSL Heartbleed"
    apt-get update -qq
    apt-get install --only-upgrade openssl libssl1.0.0 libssl1.1 libssl3 -y 2>/dev/null || apt-get install --only-upgrade openssl -y
    openssl version | tee -a "$LOGFILE"
    log "OpenSSL updated"
}

# -----------------------------------------------------------------------------
# Set UID 0 only to root
# -----------------------------------------------------------------------------
fix_uid0() {
    log_section "Ensuring only root has UID 0"
    awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd | while read -r user; do
        if [[ -n "$user" ]]; then
            usermod -u 1000 "$user" 2>/dev/null || userdel -r "$user" 2>/dev/null
            log "Fixed/removed non-root UID 0 user: $user"
        fi
    done
    log "UID 0 check complete"
}

# -----------------------------------------------------------------------------
# Remove startup scripts / tasks
# -----------------------------------------------------------------------------
clean_startup() {
    log_section "Cleaning startup scripts"
    # rc.local
    if [[ -f /etc/rc.local ]]; then
        cp /etc/rc.local "$BACKUP_DIR/"
        echo "#!/bin/sh -e" > /etc/rc.local
        echo "exit 0" >> /etc/rc.local
        chmod +x /etc/rc.local
        log "/etc/rc.local cleared"
    fi
    # Check systemd user units, etc. - log for review
    systemctl list-unit-files --state=enabled | tee -a "$LOGFILE"
    log "Startup review logged. Manually disable unauthorized services."
}

# -----------------------------------------------------------------------------
# Main Menu
# -----------------------------------------------------------------------------
main_menu() {
    while true; do
        clear
        echo "=============================================="
        echo " CyberPatriot Linux Hardening Script"
        echo " Credit: Inspired by BiermanM/CyberPatriot-Scripts"
        echo " Log: $LOGFILE"
        echo "=============================================="
        echo "1)  Backup critical files & create comparative snapshot"
        echo "2)  Manage users (add/remove/privileges/passwords)"
        echo "3)  Remove aliases"
        echo "4)  Lock root & set shadow permissions"
        echo "5)  Clean unnecessary /home directories"
        echo "6)  Enable firewall (UFW)"
        echo "7)  Fix Shellshock (update bash)"
        echo "8)  Reset hosts file to defaults"
        echo "9)  Secure LightDM"
        echo "10) Check/remove suspicious scripts in /bin"
        echo "11) Disable IRQ Balance"
        echo "12) Configure sysctl hardening"
        echo "13) Enable/Disable IPv6"
        echo "14) Manage Samba"
        echo "15) Manage FTP (vsftpd)"
        echo "16) Manage SSH"
        echo "17) Manage Telnet"
        echo "18) Manage Mail (Postfix)"
        echo "19) Manage Printing (CUPS)"
        echo "20) Manage MySQL"
        echo "21) Manage Web Server (Apache)"
        echo "22) Manage DNS (Bind)"
        echo "23) Remove media files"
        echo "24) List high-perm files (700-777) and PHP files"
        echo "25) Remove hacking tools (netcat, john, hydra, etc.)"
        echo "26) Set password policies (login.defs + PAM)"
        echo "27) Deny false loopback packets"
        echo "28) Disable Ctrl-Alt-Del reboot"
        echo "29) Install AppArmor"
        echo "30) Clean crontab & allow only root"
        echo "31) Update system & remove unused packages"
        echo "32) Fix OpenSSL Heartbleed"
        echo "33) Ensure only root has UID 0"
        echo "34) Clean startup scripts (rc.local etc.)"
        echo "99) Run recommended full hardening sequence (interactive)"
        echo "0)  Exit"
        echo "=============================================="
        read -rp "Select option: " opt

        # Validate and confirm (except for exit)
        case $opt in
            0)
                log "Script exited by user"
                exit 0
                ;;
            1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33|34|99)
                read -rp "Are you sure you want to run task $opt? (y/n): " confirm
                if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                    echo "Cancelled. Returning to menu."
                    sleep 1
                    continue
                fi
                ;;
            *)
                echo "Invalid option. Please enter a valid number."
                sleep 1
                continue
                ;;
        esac

        # Execute the confirmed task
        case $opt in
            1) backup_critical ;;
            2) manage_users ;;
            3) remove_aliases ;;
            4) lock_root_and_shadow ;;
            5) clean_home_dirs ;;
            6) enable_firewall ;;
            7) fix_shellshock ;;
            8) reset_hosts ;;
            9) secure_lightdm ;;
            10) clean_bin_scripts ;;
            11) disable_irqbalance ;;
            12) configure_sysctl ;;
            13) toggle_ipv6 ;;
            14) manage_samba ;;
            15) manage_ftp ;;
            16) manage_ssh ;;
            17) manage_telnet ;;
            18) manage_mail ;;
            19) manage_printing ;;
            20) manage_mysql ;;
            21) manage_web ;;
            22) manage_dns ;;
            23) remove_media ;;
            24) list_perms_and_php ;;
            25) remove_hacking_tools ;;
            26) set_password_policies ;;
            27) deny_false_loopback ;;
            28) disable_ctrl_alt_del ;;
            29) install_apparmor ;;
            30) clean_crontab ;;
            31) update_system ;;
            32) fix_heartbleed ;;
            33) fix_uid0 ;;
            34) clean_startup ;;
            99)
                log "Starting full recommended sequence"
                backup_critical
                remove_aliases
                lock_root_and_shadow
                enable_firewall
                fix_shellshock
                reset_hosts
                secure_lightdm
                disable_irqbalance
                configure_sysctl
                remove_hacking_tools
                set_password_policies
                deny_false_loopback
                disable_ctrl_alt_del
                install_apparmor
                clean_crontab
                fix_heartbleed
                fix_uid0
                clean_startup
                update_system
                log "Full sequence complete. Review logs and manually handle users/services per README."
                ;;
        esac
        read -rp "Press Enter to continue..."
    done
}

# -----------------------------------------------------------------------------
# Start
# -----------------------------------------------------------------------------
log "CyberPatriot Hardening Script initialized"
backup_critical
main_menu

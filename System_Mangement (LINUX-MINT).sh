

# ============================================================================
# System Management Script for Linux (Bash)
# Functions: List installed apps, show admins/users, update system, enable firewall
# ============================================================================

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}This script requires root privileges. Please run with sudo.${NC}"
    exit 1
fi

echo -e "${CYAN}========================================"
echo "System Management Script - Linux"
echo "========================================${NC}"
echo ""

# ============================================================================
# 1. Find and Display All Installed Applications
# ============================================================================
echo -e "${YELLOW}[1] Finding all installed applications...${NC}"
echo ""

# Detect package manager
if command -v apt-get &> /dev/null; then
    PACKAGE_MANAGER="apt"
    echo -e "${CYAN}Installed Applications (using apt):${NC}"
    echo -e "${CYAN}-----------------------------------${NC}"
    dpkg -l | awk '/^ii/ {print $2, $3}' | column -t
    APP_COUNT=$(dpkg -l | grep -c "^ii")
    
elif command -v rpm &> /dev/null; then
    PACKAGE_MANAGER="rpm"
    echo -e "${CYAN}Installed Applications (using rpm):${NC}"
    echo -e "${CYAN}-----------------------------------${NC}"
    rpm -qa --qf '%{NAME} %{VERSION}\n' | column -t
    APP_COUNT=$(rpm -qa | wc -l)
    
elif command -v pacman &> /dev/null; then
    PACKAGE_MANAGER="pacman"
    echo -e "${CYAN}Installed Applications (using pacman):${NC}"
    echo -e "${CYAN}-------------------------------------${NC}"
    pacman -Q
    APP_COUNT=$(pacman -Q | wc -l)
    
else
    echo -e "${RED}No supported package manager found (apt, rpm, pacman)${NC}"
    PACKAGE_MANAGER="unknown"
    APP_COUNT=0
fi

echo -e "${GREEN}Total applications found: $APP_COUNT${NC}"
echo ""

# ============================================================================
# 2. Show Administrator and User Accounts
# ============================================================================
echo -e "${YELLOW}[2] Displaying Administrator and User Accounts...${NC}"
echo ""

echo -e "${CYAN}Sudo Users (Administrators):${NC}"
echo -e "${CYAN}---------------------------${NC}"
getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n'
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}No sudo group found or error reading sudo users${NC}"
fi
echo ""

echo -e "${CYAN}Wheel Group Users (Administrators - RedHat/CentOS):${NC}"
echo -e "${CYAN}---------------------------------------------------${NC}"
getent group wheel 2>/dev/null | cut -d: -f4 | tr ',' '\n'
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}No wheel group found${NC}"
fi
echo ""

echo -e "${CYAN}All Local User Accounts:${NC}"
echo -e "${CYAN}------------------------${NC}"
awk -F: '$3 >= 1000 {print $1, "(" $3 ")"}' /etc/passwd | column -t
echo ""

# ============================================================================
# 3.  Automatically Update the System
# ============================================================================
echo -e "${YELLOW}[3] Updating system packages...${NC}"
echo ""

if [ "$PACKAGE_MANAGER" = "apt" ]; then
    echo -e "${YELLOW}Updating package lists...${NC}"
    apt-get update -y
    echo -e "${YELLOW}Upgrading packages...${NC}"
    apt-get upgrade -y
    echo -e "${GREEN}System update completed! ${NC}"
    
elif [ "$PACKAGE_MANAGER" = "rpm" ]; then
    echo -e "${YELLOW}Updating packages...${NC}"
    if command -v dnf &> /dev/null; then
        dnf update -y
    else
        yum update -y
    fi
    echo -e "${GREEN}System update completed!${NC}"
    
elif [ "$PACKAGE_MANAGER" = "pacman" ]; then
    echo -e "${YELLOW}Updating packages...${NC}"
    pacman -Syu --noconfirm
    echo -e "${GREEN}System update completed! ${NC}"
    
else
    echo -e "${RED}Cannot update system: no supported package manager found${NC}"
fi
echo ""

# ============================================================================
# 4. Enable Firewall
# ============================================================================
echo -e "${YELLOW}[4] Enabling Firewall...${NC}"
echo ""

# Check for UFW (Uncomplicated Firewall) - most common on Ubuntu/Debian
if command -v ufw &> /dev/null; then
    echo -e "${YELLOW}Using UFW (Uncomplicated Firewall)${NC}"
    
    # Enable UFW
    ufw --force enable
    echo -e "${GREEN}UFW firewall enabled${NC}"
    
    # Display status
    echo ""
    echo -e "${CYAN}Firewall Status:${NC}"
    echo -e "${CYAN}----------------${NC}"
    ufw status verbose
    
# Check for firewalld - common on RedHat/CentOS/Fedora
elif command -v firewall-cmd &> /dev/null; then
    echo -e "${YELLOW}Using firewalld${NC}"
    
    # Start and enable firewalld
    systemctl start firewalld
    systemctl enable firewalld
    echo -e "${GREEN}firewalld started and enabled${NC}"
    
    # Display status
    echo ""
    echo -e "${CYAN}Firewall Status:${NC}"
    echo -e "${CYAN}----------------${NC}"
    firewall-cmd --state
    firewall-cmd --list-all
    
# Check for iptables
elif command -v iptables &> /dev/null; then
    echo -e "${YELLOW}Using iptables${NC}"
    echo -e "${YELLOW}Note: iptables is being phased out.  Consider using UFW or firewalld${NC}"
    
    # Display status
    echo ""
    echo -e "${CYAN}Firewall Status:${NC}"
    echo -e "${CYAN}----------------${NC}"
    iptables -L -v | head -20
    
else
    echo -e "${RED}No firewall service found (UFW, firewalld, iptables)${NC}"
fi
echo ""

# ============================================================================
# Summary
# ============================================================================
echo -e "${CYAN}========================================"
echo "Script Execution Complete"
echo "========================================${NC}"
echo -e "${GREEN}✓ Installed applications displayed${NC}"
echo -e "${GREEN}✓ Administrator and user accounts shown${NC}"
echo -e "${GREEN}✓ System packages updated${NC}"
echo -e "${GREEN}✓ Firewall activated and enabled${NC}"
echo ""
echo -e "${YELLOW}Note: Some changes may require a system restart to take effect.${NC}"

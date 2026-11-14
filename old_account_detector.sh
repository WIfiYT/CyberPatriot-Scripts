#!/bin/bash
#
# old_account_detector.sh
# Detects local user accounts that are inactive (old / unused).
#
# Usage:
#   ./old_account_detector.sh              # default: 90 days
#   ./old_account_detector.sh 180          # custom threshold in days
#   ./old_account_detector.sh 90 --all     # also show system accounts (UID < 1000)
#
# Requires: lastlog, date, /etc/passwd
# Run as root for complete lastlog data on some systems.

set -euo pipefail

THRESHOLD_DAYS="${1:-90}"
SHOW_SYSTEM="${2:-}"

# Validate threshold
if ! [[ "$THRESHOLD_DAYS" =~ ^[0-9]+$ ]]; then
    echo "Error: Threshold must be a positive integer (days)."
    echo "Usage: $0 [days] [--all]"
    exit 1
fi

CURRENT_EPOCH=$(date +%s)
THRESHOLD_SECONDS=$((THRESHOLD_DAYS * 86400))

echo "=============================================="
echo "  Old / Inactive Account Detector"
echo "  Threshold: accounts inactive > $THRESHOLD_DAYS days"
echo "  Current time: $(date)"
echo "=============================================="
echo

# Header
printf "%-16s %-6s %-12s %-10s %s\n" "USERNAME" "UID" "STATUS" "DAYS_IDLE" "HOME / NOTES"
printf "%-16s %-6s %-12s %-10s %s\n" "--------" "---" "------" "--------" "------------"

found_any=0

while IFS=: read -r user _ uid _ _ home shell; do
    # Skip invalid lines
    [[ -z "$user" || -z "$uid" ]] && continue

    # Filter system accounts unless --all is given
    if [[ "$SHOW_SYSTEM" != "--all" ]]; then
        if (( uid < 1000 || uid >= 65534 )); then
            continue
        fi
        # Skip common non-login shells
        case "$shell" in
            */nologin|*/false|*/sync|*/halt|*/shutdown)
                continue
                ;;
        esac
    fi

    # Get lastlog line (skip header)
    lastlog_line=$(lastlog -u "$user" 2>/dev/null | tail -n 1 || true)

    status="UNKNOWN"
    days_idle="N/A"
    notes=""

    if [[ -z "$lastlog_line" ]]; then
        status="NO_DATA"
        notes="lastlog unavailable"
    elif echo "$lastlog_line" | grep -q "Never logged in"; then
        status="NEVER"
        days_idle="∞"
        notes="Never logged in"
    else
        # Extract the "Latest" date portion
        # Typical format: ... Latest Thu Nov 13 19:02:00 +0000 2026
        date_str=$(echo "$lastlog_line" | sed -E 's/.*[[:space:]]Latest[[:space:]]*//; s/[[:space:]]+$//')

        if [[ -n "$date_str" && "$date_str" != "**Never logged in**" ]]; then
            # Try to parse the date
            login_epoch=$(date -d "$date_str" +%s 2>/dev/null || echo "")
            if [[ -n "$login_epoch" && "$login_epoch" =~ ^[0-9]+$ ]]; then
                idle_seconds=$((CURRENT_EPOCH - login_epoch))
                days_idle=$((idle_seconds / 86400))
                if (( days_idle > THRESHOLD_DAYS )); then
                    status="INACTIVE"
                else
                    status="ACTIVE"
                fi
            else
                status="PARSE_FAIL"
                notes="Could not parse date: $date_str"
            fi
        else
            status="NEVER"
            days_idle="∞"
        fi
    fi

    # Only show inactive / never / problematic accounts by default
    # (or all if you want everything — remove the if below)
    if [[ "$status" == "INACTIVE" || "$status" == "NEVER" || "$status" == "PARSE_FAIL" || "$status" == "NO_DATA" ]]; then
        printf "%-16s %-6s %-12s %-10s %s\n" \
            "$user" "$uid" "$status" "$days_idle" "$home ${notes:+($notes)}"
        found_any=1
    fi

done < /etc/passwd

echo
if (( found_any == 0 )); then
    echo "No old/inactive accounts found (threshold: $THRESHOLD_DAYS days)."
else
    echo "Tip: Review the accounts above. Consider locking or removing unused ones:"
    echo "  sudo passwd -l <username>     # lock account"
    echo "  sudo usermod -L <username>    # lock"
    echo "  sudo userdel -r <username>    # delete (careful with -r)"
fi

echo
echo "Done. Threshold was $THRESHOLD_DAYS days."
echo "Run as root if lastlog data looks incomplete."

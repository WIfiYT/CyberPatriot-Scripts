# ============================================================================
# System Management Script for Windows (PowerShell)
# Functions: List installed apps, show admins/users, update system, enable firewall
# ============================================================================

# Requires Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security. Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires Administrator privileges. Please run as Administrator." -ForegroundColor Red
    exit 1
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "System Management Script - Windows" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================================
# 1. Find and Display All Installed Applications
# ============================================================================
Write-Host "[1] Finding all installed applications..." -ForegroundColor Yellow

function Get-InstalledApps {
    $apps = @()
    
    # Check 64-bit registry
    $regPath64 = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $apps += Get-ItemProperty $regPath64 -ErrorAction SilentlyContinue | 
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
        Where-Object { $_. DisplayName -ne $null }
    
    # Check 32-bit registry
    $regPath32 = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $apps += Get-ItemProperty $regPath32 -ErrorAction SilentlyContinue | 
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
        Where-Object { $_.DisplayName -ne $null }
    
    # Remove duplicates and sort
    $apps = $apps | Sort-Object DisplayName -Unique
    return $apps
}

$installedApps = Get-InstalledApps
Write-Host "Total applications found: $($installedApps.Count)" -ForegroundColor Green
Write-Host ""
Write-Host "Installed Applications:" -ForegroundColor Cyan
Write-Host "----------------------" -ForegroundColor Cyan
$installedApps | Format-Table -AutoSize -Property DisplayName, DisplayVersion, Publisher
Write-Host ""

# ============================================================================
# 2. Show Administrator and User Accounts
# ============================================================================
Write-Host "[2] Displaying Administrator and User Accounts..." -ForegroundColor Yellow
Write-Host ""

Write-Host "Local Administrators:" -ForegroundColor Cyan
Write-Host "-------------------" -ForegroundColor Cyan
try {
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | 
        Select-Object Name, ObjectClass, PrincipalSource
    if ($admins) {
        $admins | Format-Table -AutoSize
    } else {
        Write-Host "No administrators found" -ForegroundColor Yellow
    }
} catch {
    Write-Host "Error retrieving administrators: $_" -ForegroundColor Red
}
Write-Host ""

Write-Host "Local User Accounts:" -ForegroundColor Cyan
Write-Host "-------------------" -ForegroundColor Cyan
try {
    $users = Get-LocalUser -ErrorAction SilentlyContinue | 
        Select-Object Name, Enabled, LastLogon, Description
    if ($users) {
        $users | Format-Table -AutoSize
    } else {
        Write-Host "No users found" -ForegroundColor Yellow
    }
} catch {
    Write-Host "Error retrieving users: $_" -ForegroundColor Red
}
Write-Host ""

# ============================================================================
# 3.  Automatically Update the System
# ============================================================================
Write-Host "[3] Updating Windows system..." -ForegroundColor Yellow

try {
    # Check if Windows Update service is running
    $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    
    if ($wuService) {
        if ($wuService.Status -ne "Running") {
            Write-Host "Starting Windows Update service..." -ForegroundColor Yellow
            Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        
        Write-Host "Checking for and installing updates..." -ForegroundColor Yellow
        # Using PSWindowsUpdate module if available, otherwise use direct method
        if (Get-Command Get-WindowsUpdate -ErrorAction SilentlyContinue) {
            Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot
            Write-Host "Updates completed!" -ForegroundColor Green
        } else {
            Write-Host "Installing updates using Windows Update service..." -ForegroundColor Yellow
            # Trigger Windows Update scan
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            Write-Host "Searching for updates..." -ForegroundColor Yellow
            $searchResults = $updateSearcher.Search("IsInstalled=0")
            
            if ($searchResults.Updates.Count -gt 0) {
                Write-Host "Found $($searchResults.Updates.Count) update(s) available." -ForegroundColor Green
                $updateInstaller = $updateSession.CreateUpdateInstaller()
                $updateInstaller.Updates = $searchResults.Updates
                Write-Host "Installing updates..." -ForegroundColor Yellow
                $installationResult = $updateInstaller.Install()
                Write-Host "Update installation result: $($installationResult.ResultCode)" -ForegroundColor Green
            } else {
                Write-Host "No updates available.  System is up to date." -ForegroundColor Green
            }
        }
    } else {
        Write-Host "Windows Update service not found." -ForegroundColor Red
    }
} catch {
    Write-Host "Error during system update: $_" -ForegroundColor Red
}
Write-Host ""

# ============================================================================
# 4. Activate/Enable Windows Firewall
# ============================================================================
Write-Host "[4] Enabling Windows Firewall..." -ForegroundColor Yellow

try {
    $fwProfiles = @("Domain", "Private", "Public")
    
    foreach ($profile in $fwProfiles) {
        $fwStatus = Get-NetFirewallProfile -Name $profile -ErrorAction SilentlyContinue
        if ($fwStatus. Enabled -eq $false) {
            Write-Host "Enabling $profile firewall profile..." -ForegroundColor Yellow
            Set-NetFirewallProfile -Name $profile -Enabled $true -ErrorAction SilentlyContinue
            Write-Host "$profile firewall profile enabled." -ForegroundColor Green
        } else {
            Write-Host "$profile firewall profile is already enabled." -ForegroundColor Green
        }
    }
} catch {
    Write-Host "Error enabling firewall: $_" -ForegroundColor Red
}
Write-Host ""

Write-Host "Current Firewall Status:" -ForegroundColor Cyan
Write-Host "------------------------" -ForegroundColor Cyan
Get-NetFirewallProfile -ErrorAction SilentlyContinue | 
    Select-Object Name, Enabled | Format-Table -AutoSize
Write-Host ""

# ============================================================================
# Summary
# ============================================================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Script Execution Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "✓ Installed applications displayed" -ForegroundColor Green
Write-Host "✓ Administrator and user accounts shown" -ForegroundColor Green
Write-Host "✓ System updates checked and applied" -ForegroundColor Green
Write-Host "✓ Windows Firewall activated" -ForegroundColor Green
Write-Host ""
Write-Host "Note: A system restart may be required for updates to take effect." -ForegroundColor Yellow

Owner: 
WifiStudios
Head Coders:
unknownentity57,
Suo644

Rules:
Do not copy these and claim they are yours.
It is not recommended to use these outside of CyberPatriot competitions, as it might get you into trouble when executing them on random computers. However, if you are authorized by a CyberPatriot host, you may proceed with executing these files.
This was partially made with Grok. CyberPatriot 19 bans the use of AI during competition sessions, but you may create scripts using AI ahead of time. So, executing this repository is allowed. Do not use these on systems or machines you are not authorized to access.

--------------------------------------------------------------------------------------------------------------

What the scripts do:

SEMI-FINAL SCRIPT v1.0.0.1 / .2 / .3 — Read-only Linux security audits. Checks users, permissions, sudo, SSH, firewall, sysctl, mounts, SUID, world-writable files, and suspicious files. Later versions refine or extend these checks.

semifinalscriptv1-0-0-4.sh — Newer version of the semi-final Linux audit. Interactive and does more than v1.0.0.3 (audit + optional hardening elements).

Semi-Final Script v1.0.0.3 WIN32 Edit — Windows 11 lab audit script (PowerShell). Read-only checks for common vulnerable-lab issues with colored output and remediation advice.

cyberpatriot_audit.sh — Quick Linux audit. Looks for world-writable files, SUID/SGID binaries, and other basic hardening problems.

cyberpatriot_linux_editing.sh — Full Linux hardening script (~750 lines). Makes changes (users, services, permissions, firewall, etc.), includes logging, backups, and comparative snapshots. Inspired by common Linux hardening workflows.

Malware Scan LINUX — Automates rkhunter: installs it if missing, updates the databases, and then runs a scan.

old_account_detector.sh — Finds inactive local user accounts (default: idle > 90 days). Optional custom threshold and system-account mode.

oldaccountscript-setup(check-code).txt — Short notes on how to make the old account detector executable and run it.

System_Management (WIN32) — PowerShell script that lists installed apps, shows users/admins, updates the system, and enables the firewall.

System_Management (LINUX-MINT) — Bash equivalent of the above for Linux (list packages, users/admins, update, enable firewall).

helpfulcmds.txt — Cheat sheet of basic useful commands (rm, ufw, chmod, apt, etc.) with short tips.

creditsandrules.txt — Owner (WifiStudios), head coders, and simple usage rules (don’t claim as yours; use carefully outside authorized CyberPatriot environments).

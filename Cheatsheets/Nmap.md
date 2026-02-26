# Nmap Cheatsheet

## What is Nmap?

Nmap (Network Mapper) is an open-source tool for network discovery and security auditing. It discovers hosts, open ports, running services, OS fingerprints, and vulnerabilities.

---

## Scan Types

| Flag | Scan Type | Notes |
|---|---|---|
| `-sS` | SYN (Stealth) scan | Half-open, faster, less logged. **Default with root.** |
| `-sT` | TCP Connect scan | Full 3-way handshake. Default without root. |
| `-sU` | UDP scan | Slower, unreliable. Combine with `-sS` |
| `-sV` | Version detection | Detect service and version |
| `-sC` | Default scripts | Run default NSE scripts |
| `-sN` | Null scan | No flags set — FW evasion |
| `-sF` | FIN scan | FIN flag only |
| `-sX` | Xmas scan | FIN+PSH+URG flags |
| `-sA` | ACK scan | Check if port is filtered |
| `-sI` | Idle/Zombie scan | Use zombie host to hide attacker |
| `-O` | OS detection | Guess target OS |
| `-A` | Aggressive | `-O -sV -sC --traceroute` combined |

---

## Target Specification

```bash
# Single host
nmap 192.168.1.1

# CIDR range
nmap 192.168.1.0/24

# Multiple IPs
nmap 192.168.1.1 192.168.1.5

# IP range
nmap 192.168.1.1-50

# Hostname
nmap example.com

# From file
nmap -iL targets.txt

# Exclude hosts
nmap 192.168.1.0/24 --exclude 192.168.1.1
```

---

## Port Specification

```bash
# Specific ports
nmap -p 22,80,443 target

# Port range
nmap -p 1-1024 target

# All 65535 ports
nmap -p- target

# Top N most common ports
nmap --top-ports 100 target

# All ports, fast
nmap -p- --min-rate 5000 target

# UDP ports
nmap -sU -p 53,161,500 target
```

---

## Common Scan Recipes

```bash
# Quick recon (top 1000 ports)
nmap -sV -sC target

# Full port scan with version detection
nmap -p- -sV -sC target

# Fast scan (no DNS, no ping, top 1000 ports)
nmap -n -Pn -F target

# Aggressive scan
nmap -A target

# Stealth SYN scan with version
sudo nmap -sS -sV -p- target

# UDP + TCP
sudo nmap -sS -sU -p- target

# OS detection
sudo nmap -O target
```

---

## Host Discovery

```bash
# Ping scan (no port scan)
nmap -sn 192.168.1.0/24

# Disable ping (scan even if host doesn't respond to ping)
nmap -Pn target

# ARP ping (local network only)
nmap -PR 192.168.1.0/24

# Traceroute
nmap --traceroute target
```

---

## Output Formats

```bash
# Normal output
nmap target -oN output.txt

# XML output
nmap target -oX output.xml

# Grepable output
nmap target -oG output.gnmap

# All formats at once
nmap target -oA output_base_name

# Verbose
nmap -v target
nmap -vv target
```

---

## NSE Scripts (Nmap Scripting Engine)

```bash
# Run default scripts
nmap -sC target

# Specific script
nmap --script=http-title target
nmap --script=smb-vuln-ms17-010 target

# Script category
nmap --script=vuln target
nmap --script=discovery target
nmap --script=auth target
nmap --script=exploit target

# Multiple scripts
nmap --script="http-*" target
nmap --script=http-headers,http-title target

# List all scripts
ls /usr/share/nmap/scripts/
```

### Useful Scripts

```bash
# Web
nmap --script=http-title,http-headers,http-methods target -p 80,443
nmap --script=http-enum target -p 80,443

# SMB
nmap --script=smb-enum-shares,smb-enum-users target -p 445
nmap --script=smb-vuln-* target -p 445

# FTP
nmap --script=ftp-anon,ftp-bounce target -p 21

# DNS
nmap --script=dns-zone-transfer target -p 53

# SSL/TLS
nmap --script=ssl-enum-ciphers target -p 443

# Vulnerability scan
nmap --script=vuln target
```

---

## Timing and Performance

| Template | Flag | Speed | Use Case |
|---|---|---|---|
| Paranoid | `-T0` | Slowest | IDS evasion |
| Sneaky | `-T1` | Very slow | IDS evasion |
| Polite | `-T2` | Slow | Reduce bandwidth |
| Normal | `-T3` | Default | Standard |
| Aggressive | `-T4` | Fast | Lab/CTF |
| Insane | `-T5` | Fastest | Unreliable |

```bash
# Control rate manually
nmap --min-rate 1000 --max-rate 3000 target

# Parallel host scanning
nmap --min-hostgroup 64 target

# Max retries (reduce for speed)
nmap --max-retries 1 target
```

---

## Firewall Evasion

```bash
# Fragment packets
nmap -f target

# Specify MTU for fragments
nmap --mtu 16 target

# Use decoys (appear to come from many IPs)
nmap -D RND:10 target
nmap -D 10.0.0.1,10.0.0.2,ME target

# Specify source port (appear as DNS/HTTP)
nmap --source-port 53 target
nmap -g 80 target

# Randomize host order
nmap --randomize-hosts 192.168.1.0/24

# Add random data to packets
nmap --data-length 25 target

# Slow scan
nmap -T1 target
```

---

## Interpreting Port States

| State | Meaning |
|---|---|
| `open` | Application is listening and accepting connections |
| `closed` | Port accessible but no application listening |
| `filtered` | Firewall/filter blocking — nmap can't determine state |
| `unfiltered` | Accessible but nmap can't determine open/closed |
| `open\|filtered` | Nmap can't determine (UDP, FIN/Null/Xmas scans) |

---

## References

- [Nmap Official Docs](https://nmap.org/book/man.html)
- [Nmap Cheat Sheet by StationX](https://www.stationx.net/nmap-cheat-sheet/)
- [NSE Script Reference](https://nmap.org/nsedoc/)

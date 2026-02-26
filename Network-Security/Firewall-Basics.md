# Firewall Basics

## What is a Firewall?

A firewall is a network security device (hardware or software) that monitors and controls incoming/outgoing network traffic based on defined security rules. It creates a barrier between trusted internal networks and untrusted external networks.

---

## Types of Firewalls

### 1. Packet Filter (Stateless)
- Inspects individual packets in isolation
- Checks: source/dest IP, source/dest port, protocol
- Fast, but no awareness of connection state
- Can't detect attacks split across multiple packets
- **Example:** Early iptables rules, ACLs on routers

### 2. Stateful Inspection Firewall
- Tracks the state of active connections (connection table)
- Only allows packets that match an established session
- Understands TCP handshake — can detect unsolicited packets
- **Example:** Most modern firewalls, iptables with conntrack

### 3. Application Layer Firewall (Layer 7 / NGFW)
- Deep Packet Inspection (DPI) — understands application protocols
- Can block specific apps, not just ports (e.g., block BitTorrent on port 80)
- Can inspect HTTP, DNS, TLS (with SSL inspection)
- **Example:** Palo Alto, Fortinet, pfSense with Snort/Suricata

### 4. Web Application Firewall (WAF)
- Specifically protects web apps (HTTP/HTTPS)
- Detects and blocks OWASP Top 10 attacks (SQLi, XSS, etc.)
- Operates at Layer 7
- **Example:** ModSecurity, Cloudflare WAF, AWS WAF

### 5. Next-Generation Firewall (NGFW)
- Combines stateful inspection + DPI + application awareness
- User identity tracking, IPS, SSL inspection, threat intelligence
- **Example:** Palo Alto PA series, Cisco Firepower

---

## iptables (Linux Firewall)

iptables is the traditional Linux packet filtering tool. `nftables` is its modern replacement but iptables is still widely used.

### Chains
- **INPUT** — packets destined for the local system
- **OUTPUT** — packets originating from the local system
- **FORWARD** — packets being routed through the system

### Basic Syntax
```bash
iptables -[A/I/D] <chain> -[options] -j <target>
```

| Target | Meaning |
|---|---|
| `ACCEPT` | Allow the packet |
| `DROP` | Silently discard |
| `REJECT` | Discard and send error |
| `LOG` | Log the packet |

### Common Commands

```bash
# View current rules (with line numbers)
iptables -L -v -n --line-numbers

# Allow established/related connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (port 22)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTP and HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Drop all other inbound traffic (default deny)
iptables -A INPUT -j DROP

# Block specific IP
iptables -A INPUT -s 10.10.10.10 -j DROP

# Rate limit (brute force protection)
iptables -A INPUT -p tcp --dport 22 -m limit --limit 3/min -j ACCEPT

# Save rules (Debian/Ubuntu)
iptables-save > /etc/iptables/rules.v4

# Flush (delete) all rules
iptables -F
```

---

## UFW (Uncomplicated Firewall)

UFW is a simpler frontend for iptables, common on Ubuntu.

```bash
# Enable/disable
ufw enable
ufw disable

# Default policies
ufw default deny incoming
ufw default allow outgoing

# Allow by port/protocol
ufw allow 22/tcp
ufw allow 80
ufw allow 443

# Allow from specific IP
ufw allow from 192.168.1.100 to any port 22

# Deny a port
ufw deny 23

# Check status
ufw status verbose

# Delete a rule
ufw delete allow 80
```

---

## Firewall Evasion Techniques

| Technique | Description |
|---|---|
| Port scanning with allowed ports | Use ports 80, 443 to tunnel traffic |
| Fragmentation | Split packets to confuse stateless filters |
| Source port manipulation | Use trusted source ports (e.g., 53, 80) |
| Tunneling | DNS tunneling, ICMP tunneling, HTTP tunneling |
| Decoy scanning (Nmap -D) | Send packets from many spoofed IPs |
| Idle scan (Nmap -sI) | Use zombie host to mask attacker's IP |
| Protocol abuse | Use allowed protocols for unexpected purposes |

### Nmap Firewall Evasion
```bash
# Fragment packets
nmap -f target.com

# Use decoys
nmap -D RND:10 target.com

# Specify source port (appear as DNS)
nmap --source-port 53 target.com

# Slow scan (evade rate-based detection)
nmap -T1 target.com

# Idle/zombie scan
nmap -sI zombie_ip target.com
```

---

## DMZ (Demilitarized Zone)

A DMZ is a network segment between the internet and internal network, hosting public-facing services (web servers, mail, DNS).

```
Internet → [Firewall] → DMZ (web server, mail) → [Firewall] → Internal Network
```

- If a DMZ server is compromised, attackers still can't directly reach internal systems
- Internal firewall provides second layer of defense

---

## Common Firewall Rules Checklist

- [ ] Default deny inbound (allowlist, not blocklist)
- [ ] Allow only required ports for each service
- [ ] Allow established/related traffic for stateful filtering
- [ ] Block RFC 1918 addresses from external interfaces (anti-spoofing)
- [ ] Rate limit SSH and other management interfaces
- [ ] Log dropped traffic for analysis
- [ ] Block outbound traffic from servers to unexpected destinations

---

## References

- [iptables Man Page](https://linux.die.net/man/8/iptables)
- [UFW Docs](https://help.ubuntu.com/community/UFW)
- [Cloudflare — What is a Firewall?](https://www.cloudflare.com/learning/security/what-is-a-firewall/)

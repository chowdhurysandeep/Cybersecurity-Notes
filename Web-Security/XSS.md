# Cross-Site Scripting (XSS)

## Definition
Cross-Site Scripting (XSS) is a client-side injection vulnerability where an attacker injects malicious JavaScript into a web application that executes in other users' browsers.

---

## Types of XSS

### 1. Reflected XSS
- Payload is reflected immediately in response.
- Common in search fields or query parameters.

Example:
```
https://example.com/search?q=<script>alert(1)</script>
```
---

### 2. Stored XSS
- Payload is stored in database.
- Executes whenever a user views the affected page.

Common targets:
- Comment sections
- User profiles
- Forums

---

### 3. DOM-Based XSS
- Happens entirely in browser.
- Vulnerability exists in client-side JavaScript.

Example:
```
document.write(location.hash)
```
---

## Impact
- Session hijacking
- Cookie theft
- Keylogging
- Phishing attacks
- Account takeover

---

## Basic Payloads

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
```

---

## Filter Bypass Techniques

- Case manipulation: <ScRiPt>
- Event handlers: onmouseover=
- Encoding: %3Cscript%3E
- Using backticks: alert`1`

---

## Prevention

- Output encoding
- Content Security Policy (CSP)
- HttpOnly cookies
- Proper input validation
- Avoid innerHTML in JS


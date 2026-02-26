# Server-Side Request Forgery (SSRF)

## Definition
SSRF allows attackers to force the server to send HTTP requests to internal or unintended resources.

---

## Common Scenario

Application fetches URL from user input:
```
http://example.com/fetch?url=http://target.com
```
Attacker supplies:
```
http://127.0.0.1:80
```
---

## Internal Targets

- 127.0.0.1
- 0.0.0.0
- 169.254.169.254 (Cloud metadata)
- Internal admin panels

---

## Cloud Metadata Attack

AWS:
```
http://169.254.169.254/latest/meta-data/
```
Possible impact:
- Retrieve IAM credentials
- Privilege escalation

---

## Bypass Techniques

- Decimal IP: http://2130706433
- IPv6 format
- DNS rebinding
- URL encoding

---

## Prevention

- Strict allow list
- Block internal IP ranges
- Validate URL parsing
- Disable unnecessary outbound requests


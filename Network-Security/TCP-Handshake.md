# TCP Three-Way Handshake

## Overview

TCP (Transmission Control Protocol) is a connection-oriented protocol that guarantees reliable, ordered delivery of data. Before any data is exchanged, a connection must be established via the **three-way handshake**.

---

## The Three-Way Handshake

```
Client                        Server
  |                              |
  |------- SYN (seq=x) -------->|   Step 1: Client initiates
  |                              |
  |<-- SYN-ACK (seq=y, ack=x+1)-|   Step 2: Server acknowledges
  |                              |
  |------- ACK (ack=y+1) ------>|   Step 3: Client confirms
  |                              |
  |<===== Data Transfer ========>|
```

### Step 1 — SYN
- Client sends a SYN (synchronize) segment
- Includes a random Initial Sequence Number (ISN): `seq=x`
- Client state: `SYN_SENT`

### Step 2 — SYN-ACK
- Server responds with SYN-ACK
- Acknowledges client's SYN: `ack=x+1`
- Includes server's own ISN: `seq=y`
- Server state: `SYN_RECEIVED`

### Step 3 — ACK
- Client sends ACK acknowledging server's SYN: `ack=y+1`
- Connection is now **ESTABLISHED** on both sides
- Data transfer can begin

---

## TCP Connection Termination (4-Way)

```
Client                        Server
  |                              |
  |-------- FIN --------------->|   Client done sending
  |<-------- ACK ---------------|   Server acknowledges
  |<-------- FIN ---------------|   Server done sending
  |-------- ACK --------------->|   Client acknowledges
  |                              |
  (Client waits in TIME_WAIT state ~2xMSL before closing)
```

---

## TCP Flags

| Flag | Hex | Meaning |
|---|---|---|
| SYN | 0x02 | Synchronize — initiate connection |
| ACK | 0x10 | Acknowledge received data |
| FIN | 0x01 | Finish — no more data to send |
| RST | 0x04 | Reset — abruptly close connection |
| PSH | 0x08 | Push — send data immediately |
| URG | 0x20 | Urgent data |

---

## Sequence Numbers

- Each byte of data has a sequence number
- Receiver sends ACK = (last received seq + bytes received)
- Ensures ordered, reliable delivery
- Detects lost packets (retransmission if no ACK)

---

## Security Implications

### SYN Flood (DoS)
- Attacker sends many SYN packets with spoofed source IPs
- Server allocates resources and waits for ACK that never comes
- Fills the SYN backlog queue → legitimate connections refused
- **Defense:** SYN cookies, rate limiting, firewalls

### TCP Session Hijacking
- Attacker predicts or sniffs sequence numbers
- Injects forged packets with correct seq/ack numbers
- Can take over an established session
- **Defense:** Encrypted sessions (TLS), strong random ISNs

### TCP RST Attack
- Attacker sends a RST packet with correct seq number
- Forces the connection to close
- Used to terminate sessions or disrupt communication

### Half-Open Scan (Nmap -sS)
- Send SYN, wait for SYN-ACK (port open) or RST (port closed)
- Never send final ACK — connection never fully established
- Stealthier than full connect scan (may not be logged)

---

## TCP States

| State | Description |
|---|---|
| `LISTEN` | Waiting for incoming connections |
| `SYN_SENT` | SYN sent, waiting for SYN-ACK |
| `SYN_RECEIVED` | SYN-ACK sent, waiting for ACK |
| `ESTABLISHED` | Connection open, data transfer active |
| `FIN_WAIT_1` | FIN sent, waiting for ACK |
| `FIN_WAIT_2` | ACK received, waiting for FIN |
| `TIME_WAIT` | Waiting to ensure remote FIN received |
| `CLOSE_WAIT` | FIN received, waiting for app to close |
| `CLOSED` | No connection |

---

## Useful Commands

```bash
# View current TCP connections and states
ss -tan
netstat -an

# Capture handshake in Wireshark filter
tcp.flags.syn == 1

# Capture full 3-way handshake
tcp.flags.syn == 1 or tcp.flags.ack == 1

# Send SYN with hping3
hping3 -S -p 80 target.com

# SYN flood test (lab only)
hping3 -S --flood -p 80 target.com
```

---

## References

- [RFC 793 — TCP](https://www.rfc-editor.org/rfc/rfc793)
- [Cloudflare — What is a SYN flood?](https://www.cloudflare.com/learning/ddos/syn-flood-ddos-attack/)

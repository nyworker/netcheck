# netcheck

A lightweight, single-port network bandwidth tester — like `iperf3` but with no dependencies beyond Python's stdlib.

## Features

- **TCP and UDP** modes
- **Reverse direction** — server sends, client receives (`-R`)
- **Single port** — all traffic (control + data) uses one port (default 5201), TCP and UDP share the same port number
- **Per-second intervals** — live transfer and bandwidth during the test
- **TCP diagnostics** sampled each second via `getsockopt(TCP_INFO)`:
  - Congestion window (`cwnd`) min–max range
  - Receive window (`rwnd`) min–max range
  - Retransmit count (delta from `/proc/net/snmp`)
- **UDP diagnostics** — packet loss %, jitter (RFC 1889), paced sending at a target bandwidth

## Usage

Start the server on one host:

```
python3 netcheck-server.py
```

Run tests from another host:

```bash
# TCP forward (client → server), 10 s
python3 netcheck-client.py 10.0.0.1

# TCP reverse (server → client)
python3 netcheck-client.py 10.0.0.1 -R

# UDP forward at 100 Mbit/s
python3 netcheck-client.py 10.0.0.1 -u -b 100M

# UDP reverse at 1 Gbit/s
python3 netcheck-client.py 10.0.0.1 -u -R -b 1G

# 30-second run on a custom port
python3 netcheck-client.py 10.0.0.1 -t 30 -p 9000
```

## Options

**Server**

| Flag | Default | Description |
|------|---------|-------------|
| `-p PORT` | 5201 | Port to listen on (TCP + UDP) |

**Client**

| Flag | Default | Description |
|------|---------|-------------|
| `-p PORT` | 5201 | Server port |
| `-u` | off | UDP mode (default is TCP) |
| `-R` | off | Reverse: server sends, client receives |
| `-t SECS` | 10 | Test duration in seconds |
| `-b BW` | 10M | UDP target bandwidth — e.g. `10M`, `500M`, `1G` |

## Example output

```
Connecting to 10.0.0.1:5201  [TCP  client→server]
Server ready.  Running TCP test for 10 s ...

      Interval      Transfer        Bandwidth
  [  0.0-  1.0 s]    112 MBytes    938.42 Mbits/sec
  [  1.0-  2.0 s]    113 MBytes    947.11 Mbits/sec
  ...

================================================================
  RESULTS
  Sender   (client):   1.10 GBytes    941.35 Mbits/sec  retrans=2  cwnd=256K–512K
  Receiver (server):   1.10 GBytes    940.98 Mbits/sec  retrans=2  rwnd=256K–512K
================================================================
```

## Notes

- `cwnd` (congestion window) appears on the **sender** line — it shows how much unacknowledged data TCP allows in flight.
- `rwnd` (receive window) appears on the **receiver** line — it reflects the receiver's socket buffer space.
- Both window fields show `min–max` across all 1-second samples, or a single value if constant.
- Retransmit counts are system-wide (all sockets), not per-connection. They're a reliable signal when no other TCP traffic is present.
- Window tracking and retransmit counts require Linux (`/proc/net/snmp` and `TCP_INFO`). On other platforms those fields are silently omitted.

## Requirements

Python 3.10+ — no third-party packages.

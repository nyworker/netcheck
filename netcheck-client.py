#!/usr/bin/env python3
"""netcheck-client: iperf3-like network tester — single port, both directions

Usage:
    python3 netcheck-client.py <host> [options]

Examples:
    python3 netcheck-client.py 10.0.0.1              # TCP forward, 10 s
    python3 netcheck-client.py 10.0.0.1 -R           # TCP reverse
    python3 netcheck-client.py 10.0.0.1 -u           # UDP forward, 10M target
    python3 netcheck-client.py 10.0.0.1 -u -R -b 100M  # UDP reverse, 100 Mbit/s
"""

import socket
import json
import time
import struct
import argparse
import sys

PKT_SIZE = 1400
TCP_CHUNK = b'N' * 131072    # fill byte 0x4E
TCP_SENTINEL = b'\xff\xff\xff\xff'
UDP_SENTINEL = 0xFFFFFFFF


# ── buffered socket reader ────────────────────────────────────────────────────
# Needed because in TCP-reverse mode the server sends {"ready":true}\n and data
# in rapid succession; a single recv() can return both, so we must buffer.

class CtrlSock:
    """Thin wrapper that keeps a read buffer so JSON lines and raw binary can
    coexist on the same TCP connection without losing bytes."""

    def __init__(self, sock: socket.socket):
        self._s = sock
        self._buf = b''

    # ── pass-through ──
    def sendall(self, data: bytes): self._s.sendall(data)
    def shutdown(self, how: int):   self._s.shutdown(how)
    def settimeout(self, t):        self._s.settimeout(t)
    def close(self):                self._s.close()

    @property
    def raw(self) -> socket.socket:
        return self._s

    # ── buffered recv ──
    def recv(self, n: int) -> bytes:
        if self._buf:
            out, self._buf = self._buf[:n], self._buf[n:]
            return out
        return self._s.recv(n)

    def read_json_line(self) -> dict:
        while b'\n' not in self._buf:
            chunk = self._s.recv(4096)
            if not chunk:
                raise ConnectionError('connection closed')
            self._buf += chunk
        idx = self._buf.index(b'\n')
        line, self._buf = self._buf[:idx], self._buf[idx + 1:]
        return json.loads(line)


# ── formatting ────────────────────────────────────────────────────────────────

def _parse_bw(s: str) -> float:
    s = s.upper().strip()
    if s.endswith('G'): return float(s[:-1]) * 1000
    if s.endswith('M'): return float(s[:-1])
    if s.endswith('K'): return float(s[:-1]) / 1000
    return float(s) / 1e6


def _human(n: int) -> str:
    if n >= 1 << 30: return f'{n/(1<<30):.2f} GBytes'
    if n >= 1 << 20: return f'{n/(1<<20):.2f} MBytes'
    return f'{n/(1<<10):.2f} KBytes'


def _row(t0: float, t1: float, n_bytes: int, extra: str = ''):
    dt = t1 - t0
    mbps = n_bytes * 8 / dt / 1e6 if dt > 0 else 0
    print(f"  [{t0:5.1f}-{t1:5.1f} s]  {_human(n_bytes):>12}  {mbps:8.2f} Mbits/sec{extra}")


def _hdr_tcp():
    print(f"  {'Interval':>12}  {'Transfer':>12}  {'Bandwidth':>15}")


def _hdr_udp():
    print(f"  {'Interval':>12}  {'Transfer':>12}  {'Bandwidth':>15}  {'Pkts':>8}")


# ── helpers ───────────────────────────────────────────────────────────────────

def _tcp_retrans() -> int:
    """Return global TCP RetransSegs from /proc/net/snmp, or -1 if unavailable."""
    try:
        with open('/proc/net/snmp') as f:
            lines = f.read().splitlines()
        for i in range(len(lines) - 1):
            if lines[i].startswith('Tcp:') and lines[i + 1].startswith('Tcp:'):
                keys = lines[i].split()
                vals = lines[i + 1].split()
                return int(vals[keys.index('RetransSegs')])
    except Exception:
        pass
    return -1


# TCP_INFO struct layout (Linux): 8 uint8s + 24 uint32s = 104 bytes
# Field indices after unpack('8B24I'):
#   [10] snd_mss  [23] rtt_us  [26] snd_cwnd (segments)  [30] rcv_space (bytes)
_TI_FMT = '8B24I'
_TI_SZ = struct.calcsize(_TI_FMT)


def _tcp_info(sock: socket.socket) -> dict | None:
    try:
        raw = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, _TI_SZ)
        f = struct.unpack_from(_TI_FMT, raw)
        return {
            'cwnd': f[26] * f[10],   # congestion window in bytes (segments × MSS)
            'rwnd': f[30],            # receive-space advertised by peer
            'rtt_ms': f[23] / 1000,  # smoothed RTT in ms
        }
    except Exception:
        return None


def _udp_recv_loop(udp_sock: socket.socket, duration: float) -> dict:
    """Receive UDP packets; return stats dict and send them on ctrl after return."""
    seqs: dict[int, int] = {}
    jitter_acc = []
    last_arrival = last_send_ts = None
    udp_sock.settimeout(0.5)
    t0 = time.monotonic()
    deadline = t0 + duration + 2
    interval_bytes = interval_pkts = 0
    last_report = t0

    _hdr_udp()
    while time.monotonic() < deadline:
        try:
            data, _ = udp_sock.recvfrom(65536)
        except socket.timeout:
            continue
        if len(data) < 12:
            continue
        seq = struct.unpack_from('!I', data, 0)[0]
        if seq == UDP_SENTINEL:
            break
        send_ts = struct.unpack_from('!d', data, 4)[0]
        arrival = time.monotonic()
        seqs[seq] = len(data)
        interval_bytes += len(data)
        interval_pkts += 1
        if last_arrival is not None:
            jitter_acc.append(abs((arrival - last_arrival) - (send_ts - last_send_ts)) * 1000)
        last_arrival, last_send_ts = arrival, send_ts

        now = time.monotonic()
        if now - last_report >= 1.0:
            _row(now - 1.0 - t0, now - t0, interval_bytes, f"  {interval_pkts:5d} pkts")
            interval_bytes = interval_pkts = 0
            last_report = now

    elapsed = time.monotonic() - t0
    if not seqs:
        return {'error': 'no UDP packets received'}
    total = sum(seqs.values())
    received = len(seqs)
    expected = max(seqs) - min(seqs) + 1
    lost = expected - received
    loss_pct = lost / expected * 100 if expected else 0
    jitter = sum(jitter_acc) / len(jitter_acc) if jitter_acc else 0
    mbps = total * 8 / elapsed / 1e6 if elapsed > 0 else 0
    return {
        'bytes': total, 'elapsed': round(elapsed, 3), 'mbps': round(mbps, 2),
        'packets_received': received, 'packets_lost': lost,
        'loss_pct': round(loss_pct, 2), 'jitter_ms': round(jitter, 3),
    }


# ── TCP modes ─────────────────────────────────────────────────────────────────

def run_tcp_forward(ctrl: CtrlSock, duration: float):
    """Client sends on the control connection; shutdown signals end."""
    _hdr_tcp()
    total = 0
    t0 = time.monotonic()
    r0 = _tcp_retrans()
    deadline = t0 + duration
    interval_bytes = 0
    last_report = t0
    cwnd_samples: list[int] = []

    while time.monotonic() < deadline:
        ctrl.sendall(TCP_CHUNK)
        total += len(TCP_CHUNK)
        interval_bytes += len(TCP_CHUNK)
        now = time.monotonic()
        if now - last_report >= 1.0:
            _row(now - 1.0 - t0, now - t0, interval_bytes)
            interval_bytes = 0
            last_report = now
            info = _tcp_info(ctrl.raw)
            if info:
                cwnd_samples.append(info['cwnd'])

    try:
        ctrl.shutdown(socket.SHUT_WR)   # signal EOF; server reads until here
    except OSError:
        pass

    elapsed = time.monotonic() - t0
    local = {'bytes': total, 'elapsed': elapsed}
    r1 = _tcp_retrans()
    if r0 >= 0 and r1 >= 0:
        local['retrans'] = r1 - r0
    if cwnd_samples:
        local['cwnd_min'] = min(cwnd_samples)
        local['cwnd_max'] = max(cwnd_samples)
    print()
    server = ctrl.read_json_line()
    return local, server


def run_tcp_reverse(ctrl: CtrlSock, duration: float):
    """Server sends on the control connection; sentinel \\xff x4 signals end.

    CtrlSock buffers any data bytes that arrived alongside {"ready":true},
    so recv() here correctly drains them before going to the socket.
    """
    _hdr_tcp()
    total = 0
    t0 = time.monotonic()
    r0 = _tcp_retrans()
    interval_bytes = 0
    last_report = t0
    rwnd_samples: list[int] = []
    ctrl.settimeout(duration + 10)

    try:
        while True:
            chunk = ctrl.recv(65536)
            if not chunk:
                break
            # Fill byte is 0x4E so 0xFF never appears in data — sentinel is safe.
            if TCP_SENTINEL in chunk:
                idx = chunk.index(TCP_SENTINEL)
                total += idx
                interval_bytes += idx
                break
            total += len(chunk)
            interval_bytes += len(chunk)
            now = time.monotonic()
            if now - last_report >= 1.0:
                _row(now - 1.0 - t0, now - t0, interval_bytes)
                interval_bytes = 0
                last_report = now
                info = _tcp_info(ctrl.raw)
                if info:
                    rwnd_samples.append(info['rwnd'])
    except socket.timeout:
        pass

    elapsed = time.monotonic() - t0
    mbps = total * 8 / elapsed / 1e6 if elapsed > 0 else 0
    recv_result = {'bytes': total, 'elapsed': round(elapsed, 3), 'mbps': round(mbps, 2)}
    r1 = _tcp_retrans()
    if r0 >= 0 and r1 >= 0:
        recv_result['retrans'] = r1 - r0
    if rwnd_samples:
        recv_result['rwnd_min'] = min(rwnd_samples)
        recv_result['rwnd_max'] = max(rwnd_samples)

    print()
    ctrl.sendall(json.dumps(recv_result).encode() + b'\n')
    server = ctrl.read_json_line()
    return recv_result, server


# ── UDP modes ─────────────────────────────────────────────────────────────────

def run_udp_forward(ctrl: CtrlSock, host: str, port: int,
                    duration: float, bw_mbps: float):
    """Client sends UDP to server:port; server measures; results over ctrl."""
    pkt_size = PKT_SIZE
    pps = bw_mbps * 1e6 / 8 / pkt_size
    inter_pkt = 1.0 / pps if pps > 0 else 0
    padding = b'U' * (pkt_size - 12)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target = (host, port)

    _hdr_udp()
    seq = 0
    total = 0
    t0 = time.monotonic()
    deadline = t0 + duration
    interval_bytes = interval_pkts = 0
    last_report = t0

    while time.monotonic() < deadline:
        ts = time.monotonic()
        pkt = struct.pack('!Id', seq, ts) + padding
        sock.sendto(pkt, target)
        total += len(pkt)
        interval_bytes += len(pkt)
        interval_pkts += 1
        seq += 1
        if inter_pkt > 0:
            wait = t0 + seq * inter_pkt - time.monotonic()
            if wait > 0:
                time.sleep(wait)
        now = time.monotonic()
        if now - last_report >= 1.0:
            _row(now - 1.0 - t0, now - t0, interval_bytes, f"  {interval_pkts:5d} pkts")
            interval_bytes = interval_pkts = 0
            last_report = now

    term = struct.pack('!Id', UDP_SENTINEL, 0.0)
    for _ in range(5):
        sock.sendto(term, target)
        time.sleep(0.01)
    sock.close()

    elapsed = time.monotonic() - t0
    print()
    server = ctrl.read_json_line()
    return {'bytes': total, 'packets_sent': seq, 'elapsed': elapsed}, server


def run_udp_reverse(ctrl: CtrlSock, udp_sock: socket.socket, duration: float):
    """Server sends UDP to our pre-opened udp_sock; we measure and report."""
    recv_result = _udp_recv_loop(udp_sock, duration)
    udp_sock.close()
    print()
    ctrl.sendall(json.dumps(recv_result).encode() + b'\n')
    server = ctrl.read_json_line()
    return recv_result, server


# ── summary ───────────────────────────────────────────────────────────────────

def _retrans_tag(d: dict) -> str:
    r = d.get('retrans')
    return f'  retrans={r}' if r is not None else ''


def _win_tag(d: dict, key: str) -> str:
    lo = d.get(f'{key}_min')
    hi = d.get(f'{key}_max')
    if lo is None:
        return ''
    def kb(n): return f'{n>>20}M' if n >= 1<<20 else f'{n>>10}K'
    return f'  {key}={kb(lo)}' if lo == hi else f'  {key}={kb(lo)}–{kb(hi)}'


def _summary(mode: str, reverse: bool, local: dict, server: dict):
    w = 64
    print('=' * w)
    print('  RESULTS')
    if mode == 'tcp':
        if not reverse:
            lmbps = local['bytes'] * 8 / local['elapsed'] / 1e6
            print(f"  Sender   (client):  {_human(local['bytes']):>12}  {lmbps:8.2f} Mbits/sec{_retrans_tag(local)}{_win_tag(local,'cwnd')}")
            print(f"  Receiver (server):  {_human(server['bytes']):>12}  {server.get('mbps',0):8.2f} Mbits/sec{_retrans_tag(server)}{_win_tag(server,'rwnd')}")
        else:
            print(f"  Sender   (server):  {_human(server['bytes']):>12}  {server.get('mbps',0):8.2f} Mbits/sec{_retrans_tag(server)}{_win_tag(server,'cwnd')}")
            print(f"  Receiver (client):  {_human(local['bytes']):>12}  {local.get('mbps',0):8.2f} Mbits/sec{_retrans_tag(local)}{_win_tag(local,'rwnd')}")
    else:
        if not reverse:
            sent = local['packets_sent']
            recv = server.get('packets_received', 0)
            lost = server.get('packets_lost', 0)
            lmbps = local['bytes'] * 8 / local['elapsed'] / 1e6
            print(f"  Sender   (client):  {_human(local['bytes']):>12}  {lmbps:8.2f} Mbits/sec  {sent} pkts")
            print(f"  Receiver (server):  {_human(server.get('bytes',0)):>12}  {server.get('mbps',0):8.2f} Mbits/sec  {recv} pkts")
            print(f"  Packet loss:  {lost}/{sent} ({server.get('loss_pct',0):.1f}%)")
            print(f"  Jitter:       {server.get('jitter_ms',0):.3f} ms")
        else:
            sent = server.get('packets_sent', 0)
            recv = local.get('packets_received', 0)
            lost = local.get('packets_lost', 0)
            print(f"  Sender   (server):  {_human(server.get('bytes',0)):>12}  {server.get('mbps',0):8.2f} Mbits/sec  {sent} pkts")
            print(f"  Receiver (client):  {_human(local.get('bytes',0)):>12}  {local.get('mbps',0):8.2f} Mbits/sec  {recv} pkts")
            print(f"  Packet loss:  {lost}/{sent} ({local.get('loss_pct',0):.1f}%)")
            print(f"  Jitter:       {local.get('jitter_ms',0):.3f} ms")
    print('=' * w)


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='netcheck client — single port, iperf3-like',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument('host')
    ap.add_argument('-p', '--port', type=int, default=5201)
    ap.add_argument('-u', '--udp', action='store_true', help='UDP mode (default TCP)')
    ap.add_argument('-R', '--reverse', action='store_true',
                    help='reverse: server sends, client receives')
    ap.add_argument('-t', '--time', type=float, default=10, dest='duration',
                    help='duration in seconds (default 10)')
    ap.add_argument('-b', '--bandwidth', default='10M',
                    help='UDP target bandwidth e.g. 10M 100M 1G (default 10M)')
    args = ap.parse_args()

    mode = 'udp' if args.udp else 'tcp'
    bw_mbps = _parse_bw(args.bandwidth)
    direction = 'server→client' if args.reverse else 'client→server'
    bw_tag = f'  @ {bw_mbps:.0f} Mbits/sec target' if mode == 'udp' else ''
    print(f"Connecting to {args.host}:{args.port}  [{mode.upper()}  {direction}]{bw_tag}")

    # For UDP reverse, open the local UDP socket now so we have the port for params.
    udp_sock = None
    local_udp_port = 0
    if mode == 'udp' and args.reverse:
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.bind(('', 0))
        local_udp_port = udp_sock.getsockname()[1]
        print(f"Local UDP receive port: {local_udp_port}")

    ctrl = CtrlSock(socket.create_connection((args.host, args.port), timeout=10))
    ctrl.settimeout(args.duration + 30)

    params = {
        'mode': mode, 'duration': args.duration, 'reverse': args.reverse,
        'bandwidth_mbps': bw_mbps, 'client_udp_port': local_udp_port,
    }
    ctrl.sendall(json.dumps(params).encode() + b'\n')

    resp = ctrl.read_json_line()
    if 'error' in resp:
        print(f"Server error: {resp['error']}", file=sys.stderr)
        sys.exit(1)

    print(f"Server ready.  Running {mode.upper()} test for {args.duration:.0f} s ...\n")

    if mode == 'tcp':
        local, server = (run_tcp_reverse if args.reverse else run_tcp_forward)(ctrl, args.duration)
    else:
        if not args.reverse:
            local, server = run_udp_forward(ctrl, args.host, args.port, args.duration, bw_mbps)
        else:
            local, server = run_udp_reverse(ctrl, udp_sock, args.duration)

    ctrl.close()

    if 'error' in server:
        print(f"Server error: {server['error']}", file=sys.stderr)
        sys.exit(1)

    _summary(mode, args.reverse, local, server)


if __name__ == '__main__':
    main()

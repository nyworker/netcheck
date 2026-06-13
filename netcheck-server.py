#!/usr/bin/env python3
"""netcheck-server: iperf3-like network tester — single port, both directions

Usage:
    python3 netcheck-server.py [-p PORT]
"""

import socket
import json
import time
import struct
import threading
import queue
import argparse

PORT = 5201
TCP_CHUNK = b'N' * 131072   # fill byte 0x4E — never confused with sentinel 0xFF
UDP_SENTINEL = 0xFFFFFFFF
TCP_SENTINEL = b'\xff\xff\xff\xff'


# ── UDP listener (persistent background thread on the fixed port) ─────────────

class UDPListener:
    def __init__(self, port: int):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('', port))
        self._q: queue.Queue = queue.Queue(maxsize=100_000)
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                self._q.put(self.sock.recvfrom(65536))
            except Exception:
                pass

    def flush(self):
        while not self._q.empty():
            try:
                self._q.get_nowait()
            except queue.Empty:
                break

    def get(self, timeout=0.5):
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            return None, None


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


def _recv_line(sock: socket.socket) -> str:
    buf = b''
    while b'\n' not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError('connection closed')
        buf += chunk
    return buf.decode().strip()


def _udp_stats(seqs: dict, jitter_acc: list, elapsed: float) -> dict:
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


def _udp_recv_loop(source: UDPListener, duration: float) -> dict:
    """Drain the UDP queue for `duration` seconds, return stats."""
    seqs: dict[int, int] = {}
    jitter_acc = []
    last_arrival = last_send_ts = None
    t0 = time.monotonic()
    deadline = t0 + duration + 2

    while time.monotonic() < deadline:
        data, _ = source.get(0.5)
        if data is None:
            continue
        if len(data) < 12:
            continue
        seq = struct.unpack_from('!I', data, 0)[0]
        if seq == UDP_SENTINEL:
            break
        send_ts = struct.unpack_from('!d', data, 4)[0]
        arrival = time.monotonic()
        seqs[seq] = len(data)
        if last_arrival is not None:
            jitter_acc.append(abs((arrival - last_arrival) - (send_ts - last_send_ts)) * 1000)
        last_arrival, last_send_ts = arrival, send_ts

    return _udp_stats(seqs, jitter_acc, time.monotonic() - t0)


def _udp_send_loop(target: tuple, duration: float, bw_mbps: float) -> dict:
    """Send UDP packets at `bw_mbps` for `duration` seconds, return stats."""
    pkt_size = 1400
    bps = bw_mbps * 1e6 / 8
    pps = bps / pkt_size
    inter_pkt = 1.0 / pps if pps > 0 else 0
    padding = b'U' * (pkt_size - 12)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 0
    total = 0
    t0 = time.monotonic()
    deadline = t0 + duration

    while time.monotonic() < deadline:
        ts = time.monotonic()
        pkt = struct.pack('!Id', seq, ts) + padding
        sock.sendto(pkt, target)
        total += len(pkt)
        seq += 1
        if inter_pkt > 0:
            wait = t0 + seq * inter_pkt - time.monotonic()
            if wait > 0:
                time.sleep(wait)

    term = struct.pack('!Id', UDP_SENTINEL, 0.0)
    for _ in range(5):
        sock.sendto(term, target)
        time.sleep(0.01)
    sock.close()

    elapsed = time.monotonic() - t0
    mbps = total * 8 / elapsed / 1e6 if elapsed > 0 else 0
    return {'bytes': total, 'elapsed': round(elapsed, 3), 'mbps': round(mbps, 2),
            'packets_sent': seq}


# ── per-connection handlers ───────────────────────────────────────────────────

def handle_tcp_forward(ctrl: socket.socket, duration: float):
    """Client → server on the control connection."""
    ctrl.sendall(b'{"ready":true}\n')
    total = 0
    t0 = time.monotonic()
    r0 = _tcp_retrans()
    ctrl.settimeout(duration + 5)
    rwnd_samples: list[int] = []
    last_sample = t0
    try:
        while True:
            chunk = ctrl.recv(65536)
            if not chunk:
                break
            total += len(chunk)
            now = time.monotonic()
            if now - last_sample >= 1.0:
                info = _tcp_info(ctrl)
                if info:
                    rwnd_samples.append(info['rwnd'])
                last_sample = now
    except socket.timeout:
        pass
    elapsed = time.monotonic() - t0
    mbps = total * 8 / elapsed / 1e6 if elapsed > 0 else 0
    result = {'bytes': total, 'elapsed': round(elapsed, 3), 'mbps': round(mbps, 2)}
    r1 = _tcp_retrans()
    if r0 >= 0 and r1 >= 0:
        result['retrans'] = r1 - r0
    if rwnd_samples:
        result['rwnd_min'] = min(rwnd_samples)
        result['rwnd_max'] = max(rwnd_samples)
    ctrl.sendall(json.dumps(result).encode() + b'\n')


def handle_tcp_reverse(ctrl: socket.socket, duration: float):
    """Server → client on the control connection.

    After data, server sends TCP_SENTINEL (\xff x4) so both sides can
    still exchange result JSON on the same connection.
    """
    ctrl.sendall(b'{"ready":true}\n')
    total = 0
    t0 = time.monotonic()
    r0 = _tcp_retrans()
    deadline = t0 + duration
    cwnd_samples: list[int] = []
    last_sample = t0
    try:
        while time.monotonic() < deadline:
            ctrl.sendall(TCP_CHUNK)
            total += len(TCP_CHUNK)
            now = time.monotonic()
            if now - last_sample >= 1.0:
                info = _tcp_info(ctrl)
                if info:
                    cwnd_samples.append(info['cwnd'])
                last_sample = now
    except (BrokenPipeError, ConnectionResetError):
        pass
    ctrl.sendall(TCP_SENTINEL)   # signals end of data

    elapsed = time.monotonic() - t0
    mbps = total * 8 / elapsed / 1e6 if elapsed > 0 else 0
    sender_result = {'bytes': total, 'elapsed': round(elapsed, 3), 'mbps': round(mbps, 2)}
    r1 = _tcp_retrans()
    if r0 >= 0 and r1 >= 0:
        sender_result['retrans'] = r1 - r0
    if cwnd_samples:
        sender_result['cwnd_min'] = min(cwnd_samples)
        sender_result['cwnd_max'] = max(cwnd_samples)

    # Read client's receiver stats, then send ours
    _recv_line(ctrl)
    ctrl.sendall(json.dumps(sender_result).encode() + b'\n')


def handle_udp_forward(ctrl: socket.socket, udp: UDPListener, duration: float):
    """Client sends UDP → server receives."""
    udp.flush()
    ctrl.sendall(b'{"ready":true}\n')
    result = _udp_recv_loop(udp, duration)
    ctrl.sendall(json.dumps(result).encode() + b'\n')


def handle_udp_reverse(ctrl: socket.socket, client_addr: str, client_udp_port: int,
                        duration: float, bw_mbps: float):
    """Server sends UDP → client receives."""
    ctrl.sendall(b'{"ready":true}\n')
    target = (client_addr, client_udp_port)
    sender_result = _udp_send_loop(target, duration, bw_mbps)

    # Read client's receiver stats, then send ours
    _recv_line(ctrl)
    ctrl.sendall(json.dumps(sender_result).encode() + b'\n')


# ── main connection dispatcher ────────────────────────────────────────────────

def handle_client(ctrl: socket.socket, addr, udp: UDPListener):
    peer = f"{addr[0]}:{addr[1]}"
    print(f"[+] {peer} connected")
    try:
        params = json.loads(_recv_line(ctrl))
        mode = params.get('mode', 'tcp')
        duration = float(params.get('duration', 10))
        reverse = bool(params.get('reverse', False))
        bw_mbps = float(params.get('bandwidth_mbps', 10))
        client_udp_port = int(params.get('client_udp_port', 0))

        print(f"[+] {peer}  {mode.upper()}  {'reverse' if reverse else 'forward'}  {duration}s")

        if mode == 'tcp':
            if not reverse:
                handle_tcp_forward(ctrl, duration)
            else:
                handle_tcp_reverse(ctrl, duration)
        elif mode == 'udp':
            if not reverse:
                handle_udp_forward(ctrl, udp, duration)
            else:
                if not client_udp_port:
                    ctrl.sendall(json.dumps({'error': 'client_udp_port required for UDP reverse'}).encode() + b'\n')
                    return
                handle_udp_reverse(ctrl, addr[0], client_udp_port, duration, bw_mbps)
        else:
            ctrl.sendall(json.dumps({'error': f'unknown mode: {mode}'}).encode() + b'\n')

        print(f"[+] {peer}  done")
    except Exception as exc:
        print(f"[!] {peer}  {exc}")
        try:
            ctrl.sendall(json.dumps({'error': str(exc)}).encode() + b'\n')
        except Exception:
            pass
    finally:
        try:
            ctrl.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser(description='netcheck server — single port, iperf3-like')
    ap.add_argument('-p', '--port', type=int, default=PORT)
    args = ap.parse_args()

    udp = UDPListener(args.port)

    tcp_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_srv.bind(('', args.port))
    tcp_srv.listen(10)
    print(f"netcheck server  TCP+UDP :{args.port}  (ctrl+c to stop)")

    while True:
        conn, addr = tcp_srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr, udp), daemon=True).start()


if __name__ == '__main__':
    main()

# Production-hardened Scapy-based Traffic Monitor
import sys
import os
import ctypes

if os.name == 'nt':
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Requesting Administrator privileges...")
        script_path = os.path.abspath(sys.argv[0])
        args = f'"{script_path}"'
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, args, None, 1)
        sys.exit(0)

import threading
import time
import math
import random
import logging
from typing import Dict, Any, List

logger = logging.getLogger("phantom.traffic_monitor")

# Thread-safety lock
stats_lock = threading.Lock()

# Data structures to store metrics
# Rolling window of traffic snapshots (bytes-per-second, packets-per-second)
history_bps: List[float] = []
history_pps: List[float] = []

# Current interval totals (reset every interval)
current_bytes = 0
current_packets = 0
current_ports: Dict[str, set] = {}       # src_ip -> set of destination ports
current_ip_bytes: Dict[str, int] = {}    # src_ip -> bytes this interval
current_ip_packets: Dict[str, int] = {}  # src_ip -> packets this interval
current_ip_proto: Dict[str, Dict[str, int]] = {}  # src_ip -> {TCP:n, UDP:n, ICMP:n}

# Per-IP rolling history for z-score anomaly (30-sample window per IP)
ip_history_bps: Dict[str, List[float]] = {}
ip_history_pps: Dict[str, List[float]] = {}

# Sniffing & simulation flags
is_simulated = False
sniffer_thread = None

# Cumulative stats
total_bytes_captured = 0
total_packets_captured = 0

def packet_callback(pkt):
    global current_bytes, current_packets, current_ports
    global total_bytes_captured, total_packets_captured
    global current_ip_bytes, current_ip_packets, current_ip_proto
    try:
        pkt_len = len(pkt)
        with stats_lock:
            current_bytes += pkt_len
            current_packets += 1
            total_bytes_captured += pkt_len
            total_packets_captured += 1

            if pkt.haslayer('IP'):
                ip_src = pkt['IP'].src

                # Per-IP byte/packet tracking
                current_ip_bytes[ip_src] = current_ip_bytes.get(ip_src, 0) + pkt_len
                current_ip_packets[ip_src] = current_ip_packets.get(ip_src, 0) + 1

                # Per-IP protocol tracking
                if ip_src not in current_ip_proto:
                    current_ip_proto[ip_src] = {}

                if pkt.haslayer('TCP'):
                    proto = 'TCP'
                    dport = pkt['TCP'].dport
                elif pkt.haslayer('UDP'):
                    proto = 'UDP'
                    dport = pkt['UDP'].dport
                elif pkt.haslayer('ICMP'):
                    proto = 'ICMP'
                    dport = 0
                else:
                    proto = 'OTHER'
                    dport = 0

                current_ip_proto[ip_src][proto] = current_ip_proto[ip_src].get(proto, 0) + 1

                # Per-IP port tracking
                if dport:
                    if ip_src not in current_ports:
                        current_ports[ip_src] = set()
                    current_ports[ip_src].add(dport)

    except Exception:
        pass

def start_sniffer(interface: str = None):
    global sniffer_thread, is_simulated
    try:
        from scapy.all import sniff
        sniff(iface=interface, count=1, timeout=0.5)

        def run():
            logger.info(f"Starting Scapy sniffer on interface: {interface or 'default'}")
            try:
                sniff(iface=interface, prn=packet_callback, store=0)
            except Exception as ex:
                logger.error(f"Scapy sniffer runtime error: {ex}. Falling back to simulation.")
                run_simulation_loop()

        sniffer_thread = threading.Thread(target=run, daemon=True)
        sniffer_thread.start()
        is_simulated = False
    except Exception as e:
        logger.warning(
            f"Failed to initialize raw socket capture (Reason: {e}). "
            "Falling back to high-fidelity traffic simulation."
        )
        is_simulated = True
        sniffer_thread = threading.Thread(target=run_simulation_loop, daemon=True)
        sniffer_thread.start()

def run_simulation_loop():
    global current_bytes, current_packets, current_ports
    global total_bytes_captured, total_packets_captured
    global current_ip_bytes, current_ip_packets, current_ip_proto

    logger.info("Traffic simulation loop started.")

    # Realistic simulated host pool
    SIM_HOSTS = [
        {"ip": "192.168.1.10", "label": "workstation"},
        {"ip": "192.168.1.20", "label": "server"},
        {"ip": "10.0.0.4",    "label": "gateway"},
        {"ip": "172.16.0.22", "label": "vpn-peer"},
        {"ip": "8.8.8.8",     "label": "dns"},
        {"ip": "1.1.1.1",     "label": "cdn"},
    ]
    PROTO_MIX = [('TCP', 80), ('TCP', 443), ('UDP', 53), ('TCP', 22), ('TCP', 8080), ('ICMP', 0)]

    while True:
        try:
            pkts = random.randint(2, 10)
            bytes_size = sum(random.randint(64, 1500) for _ in range(pkts))

            with stats_lock:
                current_bytes += bytes_size
                current_packets += pkts
                total_bytes_captured += bytes_size
                total_packets_captured += pkts

                for _ in range(pkts):
                    host = random.choice(SIM_HOSTS)
                    src = host["ip"]
                    proto, port = random.choice(PROTO_MIX)
                    pkt_sz = random.randint(64, 1500)

                    current_ip_bytes[src] = current_ip_bytes.get(src, 0) + pkt_sz
                    current_ip_packets[src] = current_ip_packets.get(src, 0) + 1
                    if src not in current_ip_proto:
                        current_ip_proto[src] = {}
                    current_ip_proto[src][proto] = current_ip_proto[src].get(proto, 0) + 1
                    if port:
                        if src not in current_ports:
                            current_ports[src] = set()
                        current_ports[src].add(port)

            # Anomaly injection (1.5% chance per 100ms tick)
            if random.random() < 0.015:
                anomaly_type = random.choice(["ddos", "spike", "portscan"])
                if anomaly_type == "ddos":
                    burst_pkts = random.randint(300, 700)
                    burst_bytes = burst_pkts * random.randint(64, 128)
                    ddos_ip = "203.0.113.99"
                    with stats_lock:
                        current_packets += burst_pkts
                        current_bytes += burst_bytes
                        total_bytes_captured += burst_bytes
                        total_packets_captured += burst_pkts
                        current_ip_bytes[ddos_ip] = current_ip_bytes.get(ddos_ip, 0) + burst_bytes
                        current_ip_packets[ddos_ip] = current_ip_packets.get(ddos_ip, 0) + burst_pkts
                        if ddos_ip not in current_ip_proto:
                            current_ip_proto[ddos_ip] = {}
                        current_ip_proto[ddos_ip]['UDP'] = current_ip_proto[ddos_ip].get('UDP', 0) + burst_pkts
                elif anomaly_type == "spike":
                    burst_pkts = random.randint(50, 100)
                    burst_bytes = burst_pkts * random.randint(1400, 1500)
                    spike_ip = random.choice(SIM_HOSTS)["ip"]
                    with stats_lock:
                        current_packets += burst_pkts
                        current_bytes += burst_bytes
                        total_bytes_captured += burst_bytes
                        total_packets_captured += burst_pkts
                        current_ip_bytes[spike_ip] = current_ip_bytes.get(spike_ip, 0) + burst_bytes
                        current_ip_packets[spike_ip] = current_ip_packets.get(spike_ip, 0) + burst_pkts
                elif anomaly_type == "portscan":
                    scanner_ip = "192.168.1.189"
                    with stats_lock:
                        if scanner_ip not in current_ports:
                            current_ports[scanner_ip] = set()
                        for _ in range(random.randint(20, 40)):
                            current_ports[scanner_ip].add(random.randint(1024, 65535))
                        scan_pkts = random.randint(20, 40)
                        current_packets += scan_pkts
                        current_bytes += scan_pkts * 60
                        total_bytes_captured += scan_pkts * 60
                        total_packets_captured += scan_pkts
                        current_ip_packets[scanner_ip] = current_ip_packets.get(scanner_ip, 0) + scan_pkts
                        current_ip_bytes[scanner_ip] = current_ip_bytes.get(scanner_ip, 0) + scan_pkts * 60
                        if scanner_ip not in current_ip_proto:
                            current_ip_proto[scanner_ip] = {}
                        current_ip_proto[scanner_ip]['TCP'] = current_ip_proto[scanner_ip].get('TCP', 0) + scan_pkts

            time.sleep(0.1)
        except Exception:
            pass

# History rolling window size (e.g. 30 samples of 2 seconds each)
ROLLING_WINDOW_SIZE = 30
IP_ROLLING_WINDOW = 30
interval_duration = 2.0

# Start statistics collector thread on module load
last_collection_time = time.monotonic()

def _ip_anomaly(ip: str, ip_pps: float, ip_bps: float, ports_set: set) -> dict:
    """Compute per-IP z-score anomaly classification."""
    h_bps = ip_history_bps.setdefault(ip, [])
    h_pps = ip_history_pps.setdefault(ip, [])

    status = "learning"
    z_score = 0.0
    unique_ports = len(ports_set)

    if len(h_bps) >= 5:
        mean_b = sum(h_bps) / len(h_bps)
        std_b = math.sqrt(sum((x - mean_b) ** 2 for x in h_bps) / len(h_bps)) or 0.001
        mean_p = sum(h_pps) / len(h_pps)
        std_p = math.sqrt(sum((x - mean_p) ** 2 for x in h_pps) / len(h_pps)) or 0.001

        z_b = (ip_bps - mean_b) / std_b
        z_p = (ip_pps - mean_p) / std_p
        z_score = round(0.6 * z_p + 0.4 * z_b, 2)

        if unique_ports > 15:
            status = "PORT_SCAN"
        elif z_p > 5.0 and ip_pps > mean_p + 50:
            status = "DDOS_SUSPECTED"
        elif z_b > 3.0 or z_p > 3.0:
            status = "TRAFFIC_SPIKE"
        elif z_b > 1.5 or z_p > 1.5:
            status = "ELEVATED_TRAFFIC"
        elif z_p < -2.0 and mean_p > 5:
            status = "TRAFFIC_DROP"
        else:
            status = "normal"

    # Update IP rolling history
    h_bps.append(ip_bps)
    h_pps.append(ip_pps)
    if len(h_bps) > IP_ROLLING_WINDOW:
        h_bps.pop(0)
        h_pps.pop(0)

    return {
        "status": status,
        "z_score": z_score,
        "unique_ports": unique_ports,
        "top_ports": sorted(list(ports_set))[:10],
    }

import ipaddress as _ipaddress

def _is_private(ip: str) -> bool:
    try:
        return _ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def collect_interval_stats() -> dict:
    global current_bytes, current_packets, current_ports, last_collection_time
    global history_bps, history_pps
    global current_ip_bytes, current_ip_packets, current_ip_proto

    now = time.monotonic()
    dt = now - last_collection_time
    if dt <= 0:
        dt = interval_duration

    with stats_lock:
        bytes_in_interval = current_bytes
        packets_in_interval = current_packets
        ports_in_interval = {k: set(v) for k, v in current_ports.items()}
        ip_bytes_snap = dict(current_ip_bytes)
        ip_pkts_snap = dict(current_ip_packets)
        ip_proto_snap = {k: dict(v) for k, v in current_ip_proto.items()}

        # Reset all interval counters
        current_bytes = 0
        current_packets = 0
        current_ports.clear()
        current_ip_bytes.clear()
        current_ip_packets.clear()
        current_ip_proto.clear()

    last_collection_time = now

    bps = bytes_in_interval / dt
    pps = packets_in_interval / dt

    # Global rolling window stats
    mean_bps = 0.0
    std_bps = 0.0
    mean_pps = 0.0
    std_pps = 0.0

    if len(history_bps) >= 5:
        mean_bps = sum(history_bps) / len(history_bps)
        variance_bps = sum((x - mean_bps) ** 2 for x in history_bps) / len(history_bps)
        std_bps = math.sqrt(variance_bps)
        mean_pps = sum(history_pps) / len(history_pps)
        variance_pps = sum((x - mean_pps) ** 2 for x in history_pps) / len(history_pps)
        std_pps = math.sqrt(variance_pps)

    z_bps = ((bps - mean_bps) / std_bps) if std_bps > 0 else 0.0
    z_pps = ((pps - mean_pps) / std_pps) if std_pps > 0 else 0.0

    # Global anomaly classification
    status = "normal"
    z_score = max(abs(z_bps), abs(z_pps))

    max_ports_scanned = 0
    scanner_ip = None
    for ip, ports in ports_in_interval.items():
        if len(ports) > max_ports_scanned:
            max_ports_scanned = len(ports)
            scanner_ip = ip

    if len(history_bps) < 5:
        status = "learning"
    elif max_ports_scanned > 15:
        status = "PORT_SCAN"
    elif z_pps > 3.0 and pps > mean_pps + 50:
        status = "DDOS_SUSPECTED"
    elif z_bps > 3.0:
        status = "TRAFFIC_SPIKE"
    elif z_pps > 1.5 or z_bps > 1.5:
        status = "ELEVATED_TRAFFIC"
    elif pps < mean_pps - 2.0 * std_pps and mean_pps > 10:
        status = "TRAFFIC_DROP"
    elif pps < 2 and mean_pps > 5:
        status = "LOW_TRAFFIC"

    history_bps.append(bps)
    history_pps.append(pps)
    if len(history_bps) > ROLLING_WINDOW_SIZE:
        history_bps.pop(0)
        history_pps.pop(0)

    # ── Build per-IP table ─────────────────────────────────────────────────
    all_ips = set(list(ip_bytes_snap.keys()) + list(ip_pkts_snap.keys()))
    per_ip_rows = []
    for ip in all_ips:
        ip_b = ip_bytes_snap.get(ip, 0)
        ip_p = ip_pkts_snap.get(ip, 0)
        ip_bps_val = ip_b / dt
        ip_pps_val = ip_p / dt
        ip_kbs_val = round(ip_bps_val / 1024, 2)
        proto_map = ip_proto_snap.get(ip, {})
        top_proto = max(proto_map, key=proto_map.get) if proto_map else "UNK"
        anomaly = _ip_anomaly(ip, ip_pps_val, ip_bps_val, ports_in_interval.get(ip, set()))
        per_ip_rows.append({
            "ip": ip,
            "pps": round(ip_pps_val, 1),
            "bps": round(ip_bps_val, 1),
            "kbs": ip_kbs_val,
            "protocols": proto_map,
            "top_proto": top_proto,
            "private": _is_private(ip),
            "unique_ports": anomaly["unique_ports"],
            "top_ports": anomaly["top_ports"],
            "anomaly": anomaly["status"],
            "z_score": anomaly["z_score"],
        })

    # Sort by PPS descending, cap at 50 IPs
    per_ip_rows.sort(key=lambda r: r["pps"], reverse=True)
    per_ip_rows = per_ip_rows[:50]

    return {
        "interface": "default",
        "bytes_per_second": round(bps, 2),
        "packets_per_second": round(pps, 2),
        "z_score": round(z_score, 2),
        "status": status,
        "is_simulated": is_simulated,
        "total_bytes": total_bytes_captured,
        "total_packets": total_packets_captured,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "per_ip": per_ip_rows,
        "details": {
            "mean_bps": round(mean_bps, 2),
            "std_bps": round(std_bps, 2),
            "mean_pps": round(mean_pps, 2),
            "std_pps": round(std_pps, 2),
            "max_ports_scanned": max_ports_scanned,
            "scanner_ip": scanner_ip,
        }
    }


def run_collection_scheduler():
    global last_collection_time
    last_collection_time = time.monotonic()
    # Initialize packet sniffer/simulation
    start_sniffer()
    
    while True:
        time.sleep(interval_duration)
        try:
            # Regularly update rolling queues
            collect_interval_stats()
        except Exception:
            pass

# Start background collection scheduler automatically on module load
collection_thread = threading.Thread(target=run_collection_scheduler, daemon=True)
collection_thread.start()

def get_traffic_snapshot(interface: str = "eth0") -> dict:
    stats = collect_interval_stats()
    stats["interface"] = interface
    return stats

import socket
import json
import threading
import time

import tempfile

IPC_SOCKET_PATH = os.path.join(tempfile.gettempdir(), 'phantom_scapy_bridge.sock')
IPC_HOST = '127.0.0.1'
IPC_PORT = 19999

def run_ipc_server():
    if hasattr(socket, 'AF_UNIX'):
        import os
        if os.path.exists(IPC_SOCKET_PATH):
            os.remove(IPC_SOCKET_PATH)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(IPC_SOCKET_PATH)
        os.chmod(IPC_SOCKET_PATH, 0o600)
        print(f"Daemon listening on Unix Domain Socket: {IPC_SOCKET_PATH}")
    else:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((IPC_HOST, IPC_PORT))
        print(f"Daemon listening on TCP Socket: {IPC_HOST}:{IPC_PORT} (AF_UNIX unsupported)")

    server.listen(5)
    
    while True:
        try:
            conn, _ = server.accept()
            try:
                # Read full request (small command packet, 1024 is enough)
                data = conn.recv(1024)
                if not data:
                    continue

                req = json.loads(data.decode())
                if req.get('command') == 'get_snapshot':
                    interface = req.get('interface', 'eth0')
                    snapshot = get_traffic_snapshot(interface)
                    payload = json.dumps(snapshot).encode()
                    conn.sendall(payload)
                    conn.shutdown(socket.SHUT_WR)  # Signal EOF so client recv loop exits
            finally:
                conn.close()
        except Exception as e:
            print(f"IPC Server Error: {e}")


ipc_thread = threading.Thread(target=run_ipc_server, daemon=True)
ipc_thread.start()

if __name__ == "__main__":
    try:
        print("Phantom Traffic Daemon Started.")
        while True:
            time.sleep(1)
    except Exception as e:
        with open(r'C:\Users\kesha\.gemini\antigravity-ide\brain\b6ef5ae5-4b2f-4186-96f8-51bcac465bb9\scratch\daemon_error.log', 'a') as log:
            log.write(str(e) + '\n')

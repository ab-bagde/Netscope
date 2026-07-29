from collections import deque
import time
alerts = []
port_history = {}
syn_counter = {}
icmp_counter = {}
THRESHOLDS = {
    "pps": 500,
    "upload": 20 * 1024 * 1024,
    "download": 50 * 1024 * 1024,
    "port_scan": 20,
    "syn_flood": 100,
    "icmp_flood": 100,
    "window_size":1
}

def detect_threats(packet_speed, upload_speed, download_speed, parsed_data):
    alerts.clear()
    if packet_speed > THRESHOLDS["pps"]:
        alerts.append(
            f"🚨 High Packet Rate ({packet_speed} PPS)"
        )

    if upload_speed > THRESHOLDS["upload"]:
        alerts.append(
            f"🚨 Upload spike ({upload_speed/(1024*1024):.2f} MB/s)"
        )

    if download_speed > THRESHOLDS["download"]:
            alerts.append(
                f"🚨 Download spike ({download_speed/(1024*1024):.2f} MB/s)"
            )
    if parsed_data is not None and parsed_data["protocol"] == "TCP":
        src_ip = parsed_data["src_ip"]
        dst_ip = parsed_data["dst_ip"]
        timestamp = parsed_data["timestamp"]
        dst_port = parsed_data["dst_port"]

        if (src_ip, dst_ip) not in port_history:
            port_history[(src_ip, dst_ip) ] = deque()

        history = port_history[(src_ip, dst_ip)]
        unique_ports = set()
        history.append((timestamp, dst_port))
        while history and timestamp - history[0][0] > THRESHOLDS["window_size"]:
            history.popleft()

        for _, port in history:
            unique_ports.add(port)
        if not history:
            del port_history[(src_ip, dst_ip)]
        elif len(unique_ports) >= THRESHOLDS["port_scan"]:
            alerts.append(
                f"🚨 Port scan ({src_ip} - {dst_ip} : {len(unique_ports)}) unique ports"
            )

        flag = parsed_data["flags"]
        if flag == "S":
            if (src_ip, dst_ip) not in syn_counter:
                syn_counter[(src_ip, dst_ip)] = deque()
            syn_history = syn_counter[(src_ip, dst_ip)]
            syn_history.append(timestamp)
            while syn_history and timestamp - syn_history[0] > THRESHOLDS["window_size"]:
                syn_history.popleft()

            if not syn_history:
                del syn_counter[(src_ip, dst_ip)]
            elif len(syn_history) >= THRESHOLDS["syn_flood"]:
                alerts.append(
                    f"🚨 Possible SYN Flood ({src_ip} - {dst_ip} : {len(syn_history)}) SYN packets"
                )

    if parsed_data is not None:
        if parsed_data["protocol"] == "ICMP":
            src_ip = parsed_data["src_ip"]
            dst_ip = parsed_data["dst_ip"]
            timestamp = parsed_data["timestamp"]
            if (src_ip, dst_ip) not in icmp_counter:
                icmp_counter[(src_ip, dst_ip)] = deque()
            icmp_history = icmp_counter[(src_ip, dst_ip)]
            icmp_history.append(timestamp)

            while icmp_history and timestamp - icmp_history[0] > THRESHOLDS["window_size"]:
                icmp_history.popleft()

            if not icmp_history:
                del icmp_counter[(src_ip, dst_ip)]
            elif len(icmp_history) >= THRESHOLDS["icmp_flood"]:
                alerts.append(
                    f"🚨 Possible ICMP Flood ({src_ip} - {dst_ip} : {len(icmp_history)}) ICMP packets"
                )

def print_alerts():
    print("=" * 50)
    print("Threat Detection")
    print("=" * 50)
    if alerts:
        for alert in alerts:
            print(alert)
    else:
        print("✅ No Threats Detected")

    print("=" * 50)
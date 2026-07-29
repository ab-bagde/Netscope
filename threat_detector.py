from collections import deque
import time
alerts = []
port_history = {}
syn_counter = {}
icmp_counter = {}
ICMP_THRESHOLD = 100
PPS_THRESHOLD = 500
UPLOAD_THRESHOLD = 20 * 1024 *1024
DOWNLOAD_THRESHOLD = 50 * 1024* 1024
PORT_SCAN_THRESHOLD = 20
SYN_THRESHOLD = 100

def detect_threats(packet_speed, upload_speed, download_speed, parsed_data):
    alerts.clear()
    if packet_speed > PPS_THRESHOLD:
        alerts.append(
            f"🚨 High Packet Rate ({packet_speed} PPS)"
        )

    if upload_speed > UPLOAD_THRESHOLD:
        alerts.append(
            f"🚨 Upload spike ({upload_speed/(1024*1024):.2f} MB/s)"
        )

    if download_speed > DOWNLOAD_THRESHOLD:
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
        while history and timestamp - history[0][0] > 1:
            history.popleft()

        for _, port in history:
            unique_ports.add(port)
         
        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            alerts.append(
                f"🚨 Port scan ({src_ip} - {dst_ip} : {len(unique_ports)}) unique ports"
            )

        flag = parsed_data["flags"]
        if flag == "S":
            if (src_ip, dst_ip) not in syn_counter:
                syn_counter[(src_ip, dst_ip)] = deque()
            syn_history = syn_counter[(src_ip, dst_ip)]
            syn_history.append(timestamp)
            while syn_history and timestamp - syn_history[0] > 1:
                syn_history.popleft()

            if not syn_history:
                del syn_counter[(src_ip, dst_ip)]
            elif len(syn_history) >= SYN_THRESHOLD:
                alerts.append(
                    f"🚨 Possible SYN Flood ({src_ip} - {dst_ip} : {len(syn_history)}) SYN packets"
                )

    if parsed_data is not None:
        if parsed_data["protocol"] == "ICMP":
            src_ip = parsed_data["src_ip"]
            if src_ip not in icmp_counter:
                icmp_counter[src_ip] = 0
            icmp_counter[src_ip] += 1

    for ip, count in icmp_counter.items():
        if count >= ICMP_THRESHOLD:
            alerts.append(
            f"🚨 Possible ICMP Flood ({ip}) - {count} ICMP packets"
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
from collections import deque
from alert_logger import alerts_logger
alerts = []
active_alerts = set()
port_history = {}
syn_counter = {}
icmp_counter = {}
dns_counter = {}
THRESHOLDS = {
    "pps": 120,
    "upload": 20 * 1024 * 1024,
    "download": 50 * 1024 * 1024,
    "port_scan": 5,
    "syn_flood": 100,
    "icmp_flood": 100,
    "dns_flood":75,
    "window_size":1,
    "dns_len" : 90
}

def detect_threats(packet_speed, upload_speed, download_speed, parsed_data):
    alerts.clear()
    if parsed_data is not None:
        src_id = parsed_data['src_ip']
        dst_id = parsed_data['dst_ip']
    else:
        src_id = "System"
        dst_id = "System"
    key = ("High Packet Rate",)
    if packet_speed > THRESHOLDS["pps"]:
        alerts.append(
            f"🚨 High Packet Rate ({packet_speed} PPS)"
        )
        if key not in active_alerts:
            active_alerts.add(key)
            alerts_logger("High Packet Rate", src_id, dst_id, f"{packet_speed} PPS", "Started")
    elif key in active_alerts:
        active_alerts.remove(key)
        alerts_logger("High Packet Rate", src_id, dst_id, "Normal", "Ended")

    key = ("Upload spike",)
    if upload_speed > THRESHOLDS["upload"]:
        alerts.append(
            f"🚨 Upload spike ({upload_speed/(1024*1024):.2f} MB/s)"
        )
        if key not in active_alerts:
            active_alerts.add(key)
            alerts_logger("Upload spike", src_id, dst_id, f"{upload_speed/(1024*1024):.2f} MB/s", "Started")
    elif key in active_alerts:
         active_alerts.remove(key)
         alerts_logger("Upload spike", src_id, dst_id, "Normal", "Ended")

    key = ("Download spike",)
    if download_speed > THRESHOLDS["download"]:
            alerts.append(
                f"🚨 Download spike ({download_speed/(1024*1024):.2f} MB/s)"
            )
            if key not in active_alerts:
                      active_alerts.add(key)
                      alerts_logger("Download spike", src_id, dst_id, f"{download_speed/(1024*1024):.2f} MB/s", "Started")
    elif key in active_alerts:
        active_alerts.remove(key)
        alerts_logger("Download spike", src_id, dst_id, "Normal", "Ended")


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
        key = ("Port scan", src_ip, dst_ip)
        if not history:
            del port_history[(src_ip, dst_ip)]
            if key in active_alerts:
                active_alerts.remove(key)
                alerts_logger(
                "Port scan",
                src_ip,
                dst_ip,
                "Normal",
                "Ended"
                )
        elif len(unique_ports) >= THRESHOLDS["port_scan"]:
            alerts.append(
                f"🚨 Port scan ({src_ip} - {dst_ip} : {len(unique_ports)}) unique ports"
            )
            if key not in active_alerts:
                active_alerts.add(key)
                alerts_logger("Port scan", src_ip, dst_ip, f"{len(unique_ports)}) unique ports", "Started")
        elif key in active_alerts:
            active_alerts.remove(key)
            alerts_logger("Port scan", src_ip, dst_ip, "Normal", "Ended")


        flag = parsed_data["flags"]
        if flag == "S":
            if (src_ip, dst_ip) not in syn_counter:
                syn_counter[(src_ip, dst_ip)] = deque()
            syn_history = syn_counter[(src_ip, dst_ip)]
            syn_history.append(timestamp)
            while syn_history and timestamp - syn_history[0] > THRESHOLDS["window_size"]:
                syn_history.popleft()
            key = ("SYN Flood", src_ip, dst_ip)
            if not syn_history:
                del syn_counter[(src_ip, dst_ip)]
                if key in active_alerts:
                    active_alerts.remove(key)
                    alerts_logger(
                    "SYN Flood",
                    src_ip,
                     dst_ip,
                    "Normal",
                    "Ended"
                    )
            elif len(syn_history) >= THRESHOLDS["syn_flood"]:
                alerts.append(
                    f"🚨 Possible SYN Flood ({src_ip} - {dst_ip} : {len(syn_history)}) SYN packets"
                )
                if key not in active_alerts:
                        active_alerts.add(key)
                        alerts_logger("SYN Flood", src_ip, dst_ip, f"{len(syn_history)}) SYN packets", "Started")
            elif key in active_alerts:
                active_alerts.remove(key)
                alerts_logger("SYN Flood", src_ip, dst_ip, "Normal", "Ended")


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
            key = ("ICMP Flood", src_ip, dst_ip)
            if not icmp_history:
                del icmp_counter[(src_ip, dst_ip)]
                if key in active_alerts:
                                    active_alerts.remove(key)
                                    alerts_logger(
                                    "ICMP Flood",
                                    src_ip,
                                    dst_ip,
                                    "Normal",
                                    "Ended"
                                    )
            elif len(icmp_history) >= THRESHOLDS["icmp_flood"]:
                alerts.append(
                    f"🚨 Possible ICMP Flood ({src_ip} - {dst_ip} : {len(icmp_history)}) ICMP packets"
                )
                if key not in active_alerts:
                    active_alerts.add(key)
                    alerts_logger("ICMP Flood", src_ip, dst_ip, f"{len(icmp_history)}) ICMP packets", "Started")
            elif key in active_alerts:
                    active_alerts.remove(key)
                    alerts_logger("ICMP Flood", src_ip, dst_ip, "Normal", "Ended")

    if parsed_data is not None and parsed_data["service"] == "DNS":
        timestamp = parsed_data["timestamp"]
        src_ip = parsed_data["src_ip"]
        dst_ip = parsed_data["dst_ip"]
        key = ("DNS Flood", src_ip, dst_ip)
       
        if (src_ip, dst_ip) not in dns_counter:
             dns_counter[(src_ip, dst_ip)] = deque()
        dns_history = dns_counter[(src_ip, dst_ip)]
        dns_history.append(timestamp)
        while dns_history and timestamp - dns_history[0] > THRESHOLDS["window_size"]:
             dns_history.popleft()
        if not dns_history:
             del dns_counter[(src_ip, dst_ip)]
             if key in active_alerts:
                  active_alerts.remove(key)
                  alerts_logger("DNS Flood",src_ip, dst_ip, "Normal","Ended")
        elif len(dns_history) >= THRESHOLDS["dns_flood"]:
             alerts.append(
                   f"🚨 Possible DNS Flood ({src_ip} - {dst_ip} : {len(dns_history)}) DNS requests"
             )
             if key not in active_alerts:
                   active_alerts.add(key)
                   alerts_logger("DNS Flood",src_ip, dst_ip, f"{len(dns_history)} DNS requests","Started")
        elif key in active_alerts:
             active_alerts.remove(key)
             alerts_logger("DNS Flood",src_ip, dst_ip, "Normal","Ended")
    if parsed_data is not None and parsed_data["domain"] is not None:
        src_ip = parsed_data["src_ip"]
        dst_ip = parsed_data["dst_ip"]
        domain_name = parsed_data["domain"]
        domain_len = parsed_data["domain_length"]

        key = ("Long DNS Query", src_ip, dst_ip, domain_name)

        if domain_len >= THRESHOLDS["dns_len"]:
            alerts.append(
                f"🚨 Suspicious Long DNS Query ({domain_name})"
            )
            if key not in active_alerts:
                active_alerts.add(key)
                alerts_logger(
                "Long DNS Query",
                src_ip,
                dst_ip,
                domain_name,
                "Started"
            )
        elif key in active_alerts:
            active_alerts.remove(key)
            alerts_logger(
            "Long DNS Query",
            src_ip,
             dst_ip,
            "Normal",
            "Ended"
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


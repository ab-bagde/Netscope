from collections import deque
from alert_logger import alerts_logger
from malicious_ip_loader import load_malicious_ip
malicious_ip_dataset = load_malicious_ip()

alerts = []
active_alerts = set()
port_history = {}
syn_counter = {}
icmp_counter = {}
dns_counter = {}
domain_counter = {}
mac_table = {}
dhcp_history = deque()
THRESHOLDS = {
    "pps": 150,
    "upload": 20 * 1024 * 1024,
    "download": 50 * 1024 * 1024,
    "port_scan": 5,
    "syn_flood": 100,
    "icmp_flood": 100,
    "dns_flood":75,
    "window_size":1,
    "dns_len" : 90,
    "unique_dns" : 20,
    "dhcp_window_size" : 10,
    "dhcp_mac_threshold" : 35 
}
def detect_threats(packet_speed, upload_speed, download_speed, parsed_data):
    alerts.clear()
    if parsed_data is not None:
        src_id = parsed_data.get("src_ip", parsed_data.get("sender_ip", parsed_data.get("src_mac", "Unknown")))
        dst_id = parsed_data.get("dst_ip", parsed_data.get("target_ip", "Unknown"))
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
                alerts_logger("Port scan", src_ip, dst_ip, "Normal", "Ended")
        elif len(unique_ports) >= THRESHOLDS["port_scan"]:
            alerts.append(
                f"🚨 Port scan ({src_ip} - {dst_ip} : {len(unique_ports)}) unique ports"
            )
            if key not in active_alerts:
                active_alerts.add(key)
                alerts_logger("Port scan", src_ip, dst_ip, f"{len(unique_ports)} unique ports", "Started")
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
                    alerts_logger("SYN Flood", src_ip, dst_ip, "Normal", "Ended")
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
                    alerts_logger("ICMP Flood", src_ip, dst_ip, "Normal", "Ended")
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

    if parsed_data is not None and parsed_data.get("service")== "DNS":
        timestamp = parsed_data["timestamp"]
        src_ip = parsed_data["src_ip"]
        dst_ip = parsed_data["dst_ip"]
        domain_name = parsed_data["domain"]
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

    if parsed_data is not None and parsed_data.get("domain") is not None:
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
                alerts_logger("Long DNS Query", src_ip, dst_ip, domain_name, "Started")
        elif key in active_alerts:
            active_alerts.remove(key)
            alerts_logger("Long DNS Query", src_ip, dst_ip, "Normal", "Ended")

    if parsed_data is not None and parsed_data.get("service") == "DNS":
        timestamp = parsed_data["timestamp"]
        src_ip = parsed_data["src_ip"]
        dst_ip = parsed_data["dst_ip"]
        domain_name = parsed_data["domain"]

        if src_ip not in domain_counter:
            domain_counter[src_ip] = deque()
        domain_history = domain_counter[src_ip]
        domain_history.append((timestamp, domain_name))

        while domain_history and timestamp - domain_history[0][0] > THRESHOLDS["window_size"]:
            domain_history.popleft()

        unique_domain = set()
        for _, domain in domain_history:
             unique_domain.add(domain)

        key = ("Unique DNS", src_ip)
        if not domain_history:
            del domain_counter[src_ip]
            if key in active_alerts:
                        active_alerts.remove(key)
                        alerts_logger("Suspicious DNS Activity", src_ip, dst_ip, "Normal", "Ended")
        elif len(unique_domain) >= THRESHOLDS["unique_dns"]:
                    alerts.append(
                    f"🚨 Suspicious DNS Activity ({src_ip} queried {len(unique_domain)} unique domains)"
                    )
                    if key not in active_alerts:
                        active_alerts.add(key)
                        alerts_logger("Suspicious DNS Activity", src_ip, dst_ip, f"{len(unique_domain)} unique domains","Started")
        elif key in active_alerts:
                    active_alerts.remove(key)
                    alerts_logger("Suspicious DNS Activity", src_ip, dst_ip, "Normal", "Ended")

    if parsed_data is not None and parsed_data.get("operation") == 2:
        sender_ip = parsed_data["sender_ip"]
        sender_mac = parsed_data["sender_mac"]
        dest_ip = parsed_data["target_ip"]
        key = ("ARP spoofing", sender_ip)
        if sender_ip in mac_table:
            if sender_mac != mac_table[sender_ip]:
                alerts.append(
                        f"🚨 Possible ARP Spoofing ({sender_ip} changed MAC from {mac_table[sender_ip]} To {sender_mac})"
                )
                if key not in active_alerts:
                    active_alerts.add(key)
                    alerts_logger("ARP Spoofing", sender_ip, dest_ip, f"changed MAC from {mac_table[sender_ip]} To {sender_mac}", "Started")
            elif sender_mac == mac_table[sender_ip]:
                if key in active_alerts:
                    active_alerts.remove(key)
                    alerts_logger("ARP Spoofing", sender_ip, dest_ip, "Normal", "Ended")
        elif sender_ip not in mac_table:
            mac_table[sender_ip] = sender_mac


    if parsed_data is not None and parsed_data.get("protocol") == "DHCP" and parsed_data.get("message_type")== 1:
            src_mac = parsed_data["src_mac"]
            timestamp = parsed_data["timestamp"]
            unique_mac_address = set()
            dhcp_history.append((timestamp, src_mac))
            while dhcp_history and timestamp - dhcp_history[0][0] > THRESHOLDS["dhcp_window_size"]:
                dhcp_history.popleft()
    
            for _, mac in dhcp_history:
                unique_mac_address.add(mac)
            key = ("DHCP Starvation",)
            if not dhcp_history:
                if key in active_alerts:
                    active_alerts.remove(key)
                    alerts_logger("DHCP Starvation Possible", src_mac, "DHCP Server", "Normal", "Ended")
            elif len(unique_mac_address) >= THRESHOLDS["dhcp_mac_threshold"]:
                alerts.append(
                     f"🚨 Possible DHCP Starvation ({len(unique_mac_address)} unique MAC addresses)"
                )
                if key not in active_alerts:
                    active_alerts.add(key)
                    alerts_logger("DHCP Starvation Possible", src_mac, "DHCP Server", f"{len(unique_mac_address)} unique MACs", "Started")
            elif key in active_alerts:
                active_alerts.remove(key)
                alerts_logger("DHCP Starvation Possible", src_mac, "DHCP Server", "Normal", "Ended")

    if parsed_data is not None:
         src_ip = parsed_data.get("src_ip")

         if src_ip in malicious_ip_dataset:
            info = malicious_ip_dataset[src_ip]
            alerts.append(
                    f"🚨 Malicious IP ({src_ip}) [{info['severity']}] - {info['threat']}"
                )
            alerts_logger(
                "Malicious IP",src_ip, parsed_data["dst_ip"],f"{info['threat']} | {info['severity']} | {info['source']}","Detected"
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


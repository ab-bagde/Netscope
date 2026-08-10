from collections import deque

recent_activity = deque(maxlen=5)


def track_recent_activity(parsed_data):
    global recent_activity
    if parsed_data is None:
        return

    protocol = parsed_data.get("protocol")

    if protocol == "ARP":
        activity = (
            f"ARP: {parsed_data['sender_ip']} "
            f"→ {parsed_data['target_ip']}"
        )

    elif protocol == "DHCP":
        activity = (
            f"DHCP: {parsed_data.get('src_mac', 'Unknown')}"
        )

    else:
        src_ip = parsed_data.get("src_ip", "Unknown")
        dst_ip = parsed_data.get("dst_ip", "Unknown")
        service = parsed_data.get("service", protocol)

        activity = f"{src_ip} → {dst_ip} | {service}"

    recent_activity.appendleft(activity)
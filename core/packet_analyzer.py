def analyze_packet(parsed_packet):

    if parsed_packet is None:
        return

    print("=" * 50)
    print(f"Source IP        : {parsed_packet['src_ip']}")
    print(f"Destination IP   : {parsed_packet['dst_ip']}")
    print(f"Protocol         : {parsed_packet['protocol']}")
    if parsed_packet["src_port"] is not None:
        print(f"Source Port      : {parsed_packet['src_port']}")
    if parsed_packet["dst_port"] is not None:
        print(f"Destination Port : {parsed_packet['dst_port']}")
    print(f"Service          : {parsed_packet['service']}")

    status = "Unknown Traffic"
    if parsed_packet["service"] == "HTTPS":
       status = "🔒 Secure Web Traffic"
    elif parsed_packet["service"] == "HTTP":
        status = "🌍 Web Traffic"
    elif parsed_packet["service"] == "DNS":
        status = "🌐 Domain Name Lookup"
    elif parsed_packet["service"] == "SSH":
        status = "🔐 Secure Remote Login"
    elif parsed_packet["service"] == "FTP":
        status = "📁 File Transfer"
    elif parsed_packet["service"] == "SMTP":
        status = "📧 Sending Email"
    elif parsed_packet["service"] == "POP3":
        status = "📥 Receiving Email"
    elif parsed_packet["service"] == "IMAP":
        status = "📨 Email Synchronization"
    elif parsed_packet["service"] == "Telnet":
        status = "🖥️ Remote Terminal"
    elif parsed_packet["service"] == "DHCP Server":
        status = "📡 DHCP Server Communication"
    elif parsed_packet["service"] == "DHCP Client":
        status = "📡 DHCP Client Communication"
    elif parsed_packet["protocol"] == "ICMP":
        status = "📶 Ping / Network Control"
    print(f"Status           : {status}")

    direction = "Unknown"
    if parsed_packet["service"] != "Unknown":
        if parsed_packet["dst_port"] in [80, 443, 53, 22]:
            direction = "Outgoing"
        elif parsed_packet["src_port"] in [80, 443, 53, 22]:
            direction = "Incoming"
    print(f"Direction        : {direction}")
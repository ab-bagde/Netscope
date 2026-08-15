ALLOWED_SERVICES = [
    "HTTP",
    "HTTPS",
    "DNS",
    "SSH",
    "FTP",
    "mDNS",
    "ICMP"
]
def filter_packets(parsed_packet):
    if parsed_packet is None:
        return False

    if parsed_packet.get("service") in ALLOWED_SERVICES:
        return True

    return False
   
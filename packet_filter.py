ALLOWED_SERVICES = [
    "HTTP",
    "HTTPS",
    "DNS",
    "SSH",
    "FTP",
    "mDNS"
]
def filter_packets(parsed_packet):
    if parsed_packet is None:
        return False

    if parsed_packet["service"] in ALLOWED_SERVICES:
        return True

    return False
stats = {
    "total_packets": 0,
    "HTTP_packets": 0,
    "HTTPS_packets": 0,
    "TCP_packets": 0,
    "UDP_packets": 0,
    "DNS_packets": 0,
    "SSH_packets": 0,
    "FTP_packets": 0,
    "mDNS_packets": 0,
}
def packet_statistics(parsed_packet):
    global stats
    if parsed_packet is None:
        return
    stats["total_packets"]+=1

    protocol = parsed_packet["protocol"]
    key1 = f"{protocol}_packets"
    if key1 in stats.keys():
        stats[key1] += 1
    service = parsed_packet["service"]
    key2 = f"{service}_packets"
    if key2 in stats.keys():
        stats[key2] += 1
    

def print_statistics():
    print("=" * 50)
    print("Packet Statistics:")
    print("=" * 50)
    print()
    print(f"Total Packets     : {stats['total_packets']}")
    print("")
    print("Protocols")
    print("-" * 20)
    print("")
    print(f"TCP Packets       : {stats['TCP_packets']}")
    print(f"UDP Packets       : {stats['UDP_packets']}")
    print("")
    print("Services")
    print("-" * 20)
    print("")
    print(f"HTTP Packets      : {stats['HTTP_packets']}")
    print(f"HTTPS Packets     : {stats['HTTPS_packets']}")
    print(f"DNS Packets       : {stats['DNS_packets']}")
    print(f"SSH Packets       : {stats['SSH_packets']}")
    print(f"FTP Packets       : {stats['FTP_packets']}")
    print(f"mDNS Packets      : {stats['mDNS_packets']}")
    print("=" * 50)
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import ARP
import time
PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}
PORTS = {
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    53 : "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    25: "SMTP",
    143: "IMAP",
    21: "FTP",
    110: "POP3",
    5353: "mDNS"
}
def parse_packet(packet):
    if ARP in packet:
        return {
            "protocol": "ARP",
            "sender_ip": packet[ARP].psrc,
            "sender_mac": packet[ARP].hwsrc,
            "target_ip": packet[ARP].pdst,
            "target_mac": packet[ARP].hwdst,
            "timestamp": time.time(),
            "operation":packet[ARP].op,
            "size": len(packet)
        }
    if IP not in packet:
        return None

    protocol = PROTOCOLS.get(packet[IP].proto, "Unknown")

    src_port = None
    dst_port = None
    flag = None
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flag = packet[TCP].flags

    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    
    service = PORTS.get(dst_port)
    if service is None:
        service = PORTS.get(src_port, "Unknown")
    domain = None
    domain_length = 0
    if DNS in packet and DNSQR in packet:
        domain = packet[DNSQR].qname.decode().rstrip(".")
        domain_length = len(domain)

    return {
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "service": service,
        "size": len(packet),
        "flags" : str(flag),
        "timestamp" : time.time(),
        "domain": domain,
        "domain_length": domain_length,
    }
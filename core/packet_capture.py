from scapy.all import sniff

def capture_packets():
    packets = sniff(count=500)  
    return packets

def live_capture(callback):
    sniff(
        prn = callback,
        store = False
    )
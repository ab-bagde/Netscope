bandwidth = {
    "total_bytes": 0,
    "upload_bytes" : 0,
    "download_bytes" : 0,
    "total_packets": 0,
    "largest_packet_size": 0,
    "smallest_packet_size": float('inf'),
}

previous_packets = 0
packet_speed = 0
previous_download = 0
previous_upload = 0
current_download_speed = 0
current_upload_speed = 0


def update_live_speed():
    global previous_download
    global previous_upload
    global current_download_speed
    global current_upload_speed
    global previous_packets
    global packet_speed

    current_download_speed = bandwidth["download_bytes"] - previous_download
    current_upload_speed = bandwidth["upload_bytes"] - previous_upload
    packet_speed = bandwidth["total_packets"] - previous_packets
    previous_upload = bandwidth["upload_bytes"] 
    previous_download = bandwidth["download_bytes"]
    previous_packets = bandwidth["total_packets"]

def update_bandwidth(parsed_packet):
    if parsed_packet is None:
        return
    print("PACKET SIZE:", parsed_packet["size"])
    bandwidth["total_bytes"] += parsed_packet["size"]
    bandwidth["total_packets"] += 1

    if parsed_packet["direction"] == "Outgoing" :
        bandwidth["upload_bytes"] += parsed_packet["size"]
    elif parsed_packet["direction"] == "Incoming" :
        bandwidth["download_bytes"] += parsed_packet["size"]

    if parsed_packet["size"] > bandwidth["largest_packet_size"]:
        bandwidth["largest_packet_size"] = parsed_packet["size"]
    if parsed_packet["size"] < bandwidth["smallest_packet_size"]:
        bandwidth["smallest_packet_size"] = parsed_packet["size"]  
        

def format_speed(speed):
    if speed < 1024:
        return f"{speed:.2f} B/s"
    elif speed < 1024 * 1024:
        return f"{speed/1024:.2f} KB/s"
    else:
        return f"{speed/(1024 * 1024):.2f} MB/s"

def format_data(data):
        if data < 1024:
            return f"{data} B"
        elif data < 1024 * 1024:
            return f"{data/1024:.2f} KB"
        else:
            return f"{data/(1024*1024):.2f} MB"


def calculate_speed(elapsed_speed):
    if elapsed_speed <= 0:
        return "0 B/s"
    data = bandwidth['total_bytes']
    speed = data / elapsed_speed
    return format_speed(speed)

def calculate_upload_speed(elapsed_speed):
    if elapsed_speed <= 0:
        return "0 B/s"
    data = bandwidth['upload_bytes']
    speed = data / elapsed_speed
    return format_speed(speed)

def calculate_download_speed(elapsed_speed):
    if elapsed_speed <= 0:
        return "0 B/s"
    data = bandwidth['download_bytes']
    speed = data / elapsed_speed
    return format_speed(speed)

def get_live_stats():
    return (
        packet_speed,
        current_upload_speed,
        current_download_speed
    )
def print_bandwidth():
    print("=" * 50)
    print("Bandwidth Monitor:")
    print("=" * 50)
    print()
    print(f"Total Bytes       : {bandwidth['total_bytes']} ({bandwidth['total_bytes'] / 1024:.2f} KB)")
    print(f"Uplaod Bytes       : {bandwidth['upload_bytes']} ({bandwidth['upload_bytes'] / 1024:.2f} KB)")
    print(f"Download Bytes       : {bandwidth['download_bytes']} ({bandwidth['download_bytes'] / 1024:.2f} KB)")
    print(f"Total Packets     : {bandwidth['total_packets']}")
    print(f"Largest Packet Size: {bandwidth['largest_packet_size']} ({bandwidth['largest_packet_size'] / 1024:.2f} KB)")
    print(f"Smallest Packet Size: {bandwidth['smallest_packet_size']} ({bandwidth['smallest_packet_size'] / 1024:.2f} KB)")
    print("=" * 50)

def print_speed(elapsed_time):
    average_speed = calculate_speed(elapsed_time)
    average_upload_speed = calculate_upload_speed(elapsed_time)
    average_download_speed = calculate_download_speed(elapsed_time)
    live_upload_speed = format_speed(current_upload_speed)
    live_download_speed = format_speed(current_download_speed)
    print("=" * 50)
    print("Live Network Speed")
    print("=" * 50)
    print("")
    print(f"Capture duration        :       {elapsed_time:.2f} s")
    print(f"Total traffic           :       {bandwidth['total_bytes']/1024:.2f} KB")
    print(f"Average speed           :       {average_speed}")
    print(f"Average upload speed    :       {average_upload_speed}")
    print(f"Average download speed  :       {average_download_speed}")
    print(f"Packet speed (Live)     :       {packet_speed} PPS")
    print(f"Download speed (Live)   :       {live_download_speed}")
    print(f"Upload speed (Live)     :       {live_upload_speed}")


    print("=" * 50)

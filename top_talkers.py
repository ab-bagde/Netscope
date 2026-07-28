top_talkers = {}
def track_top_talkers(parsed_data):
    if parsed_data is None:
        return 
    if parsed_data["direction"] == "Outgoing":
        ip = parsed_data["dst_ip"]
    else:
        ip = parsed_data["src_ip"]

    if ip not in top_talkers:
        top_talkers[ip] = 0

    top_talkers[ip] += parsed_data["size"]
    
def format_bytes(byte):
    if byte < 1024:
        return f"{byte} Bytes"
    elif byte < 1024*1024:
        return f"{byte/1024:.2f} KB"
    else:
        return f"{byte/(1024 * 1024):.2f} MB"
    
def print_top_talkers():
    sorted_talkers = sorted(
        top_talkers.items(),
        key = lambda x : x[1],
        reverse = True
    )
    top3 = sorted_talkers[:3]
    print("=" * 50)
    print("Top Talkers")
    print("=" * 50)
    for ip, size in top3:
        formated_size = format_bytes(size)
        print(f"{ip:<20} : {formated_size}")

    print("=" * 50)
connections = {}
def track_connections(parsed_packet):
    if parsed_packet is None:
        return


    endpoint1 = (parsed_packet["src_ip"], parsed_packet["src_port"])
    endpoint2 = (parsed_packet["dst_ip"], parsed_packet["dst_port"])

    if(endpoint1 < endpoint2):
        connection_key = (
            endpoint1,
            endpoint2,
            parsed_packet["protocol"]
     )
    else:
        connection_key = (
            endpoint2,
            endpoint1,
            parsed_packet["protocol"]
        )
    if connection_key not in connections:
        connections[connection_key] = 1
    else:
        connections[connection_key] += 1

def print_connections():
    print("=" * 50)
    print("Connection Tracker:")
    print("=" * 50)
    print()
    for connection, count in connections.items():
        endpoint1, endpoint2, protocol = connection
        src_ip, src_port = endpoint1
        dst_ip, dst_port = endpoint2

        print("-" * 50)
        print(f"Protocol: {protocol}")
        print(f"Endpoint 1: {src_ip}:{src_port}")
        print(f"Endpoint 2: {dst_ip}:{dst_port}")
        print(f"Packet Count: {count}")
    
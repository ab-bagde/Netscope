def detect_direction(parsed_data, myIP):
    if parsed_data is None:
        return None

    if parsed_data["src_ip"] == myIP:
        parsed_data["direction"] = "Outgoing"

    elif parsed_data["dst_ip"] == myIP:
        parsed_data["direction"] = "Incoming"

    else:
        parsed_data["direction"] = "Unknown"

    return parsed_data
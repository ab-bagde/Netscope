import csv
import time
file = None
writer = None

def initialize_logger():
    global file
    global writer

    file = open("capture.csv", "w", newline="")
    writer = csv.writer(file)
    writer.writerow([
    "Timestamp",
    "Source IP",
    "Destination IP",
    "Protocol",
    "Size",
    "Direction"
])

def log_packet(parsed_data):
    if parsed_data is None:
        return
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    writer.writerow([
        timestamp,
        parsed_data['src_ip'],
        parsed_data['dst_ip'],
        parsed_data['protocol'],
        parsed_data['size'],
        parsed_data['direction'],

    ])
    

def close_logger():
    file.close()
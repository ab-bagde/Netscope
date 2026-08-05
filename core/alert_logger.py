import csv
import time
import os
file = None
writer = None

def initialize_alert_logger():
    global file, writer

    file = open("logs/alert.csv", "w", newline="")
    writer = csv.writer(file)

    writer.writerow([
        "Timestamp",
        "Type",
        "Source_IP",
        "Destination_IP",
        "Details",
        "Status"
    ])

    
def alerts_logger(alert_type, src_id, dst_id, details, status):
    print(f"Logging: {alert_type} ({status})")
    if writer is None:
        return

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    writer.writerow([
        timestamp,
        alert_type,
        src_id,
        dst_id,
        details,
        status
    ])
    file.flush()
    os.fsync(file.fileno())


def close_alert_logger():
    global file

    if file:
        file.close()
from datetime import datetime
from core.bandwidth_monitor import bandwidth
from core.threat_detector import threat_records
from core.top_talkers import top_talkers
from core.connection_tracker import connections
from core.packet_statistics import stats
import json
import os

def collect_report_data(time_range, capture_duration):
    time_ranges = {
        "Last 5 Minutes": 5 * 60,
        "Last 30 Minutes": 30 * 60,
        "Last 1 Hour": 60 * 60,
        "Last 2 Hours": 2 * 60 * 60
    }

    selected_duration = time_ranges.get(time_range, capture_duration)

    if selected_duration > capture_duration:
        selected_duration = capture_duration

    report_start = capture_duration - selected_duration
    report_data = {
        "report_info": {
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "time_range": time_range,
            "capture_duration": capture_duration,
            "selected_duration": selected_duration,
            "report_start": report_start,
            "report_end": capture_duration
        },

        "packet_statistics": stats.copy(),
        "bandwidth": bandwidth.copy(),
        "top_talkers": top_talkers.copy(),
        "threats": threat_records.copy(),
        "connections": [
            {
                "endpoint1": f"{endpoint1[0]}:{endpoint1[1]}",
                "endpoint2": f"{endpoint2[0]}:{endpoint2[1]}",
                "protocol": protocol,
                "packets": details["packets"],
                "data": details["data"]
            }
            for(endpoint1, endpoint2, protocol), details in connections.items()
        ]       
    }

    return report_data

def generate_json_report(report_data, filename):
    report_folder = os.path.join(
        os.path.dirname(__file__),
        "generated"
    )
    os.makedirs(report_folder, exist_ok=True)

    file_path = os.path.join(
        report_folder,
        filename
    )
    with open(file_path, "w") as file:
        json.dump(
            report_data,
            file,
            indent=4
        )

    return file_path
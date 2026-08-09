import time
# from core.packet_capture import capture_packets
from PySide6.QtCore import QThread
from PySide6.QtWidgets import QApplication
from gui.app import NetScopeWindow
from core.packet_parser import parse_packet
from core.packet_analyzer import analyze_packet
from core.packet_statistics import packet_statistics, print_statistics
from core.packet_filter import filter_packets
from core.connection_tracker import track_connections, print_connections
from core.bandwidth_monitor import update_bandwidth, print_bandwidth, calculate_speed, print_speed
from core.utils import get_myIP
from core.direction_detector import detect_direction
from core.packet_capture import live_capture
from gui.dashboard import refresh_dashboard
from core.bandwidth_monitor import update_live_speed
from core.top_talkers import track_top_talkers
from core.packet_logger import log_packet, initialize_logger, close_logger
from core.threat_detector import detect_threats
from core.bandwidth_monitor import get_live_stats
from core.alert_logger import initialize_alert_logger, close_alert_logger
my_ip = get_myIP()

# start_time = time.time()
# packets = capture_packets()
# end_time = time.time()
# elapsed_speed = end_time - start_time
last_refresh = time.time()
capture_start_time = time.time()

def process_packet(packet):
    global last_refresh
    parsed_data = parse_packet(packet)

    if parsed_data is None:
     return

    if parsed_data.get("protocol") not in ("ARP", "DHCP"):
        parsed_data = detect_direction(parsed_data, my_ip)

    if filter_packets(parsed_data):
        packet_statistics(parsed_data)
        track_connections(parsed_data)
        update_bandwidth(parsed_data)
        track_top_talkers(parsed_data) 
        log_packet(parsed_data)

    current_time = time.time()
    if current_time - last_refresh >= 1:
        elapsed_time = current_time - capture_start_time
        update_live_speed()
        pps, upload, download = get_live_stats()
        detect_threats(pps, upload, download, parsed_data)
        refresh_dashboard(elapsed_time)
        last_refresh = current_time
class CaptureThread(QThread):
    def run(self):
        live_capture(process_packet)

if __name__ == "__main__":
    initialize_logger()
    initialize_alert_logger()

    capture_thread = CaptureThread()
    capture_thread.start()

    try:
        app = QApplication([])

        window = NetScopeWindow()
        window.show()

        app.exec()

    finally:
        capture_thread.quit()
        capture_thread.wait()

        close_alert_logger()
        close_logger()
#Static Network Dashboard

# for packet in packets:
#     parsed_data = parse_packet(packet)
#     parsed_data = detect_direction(parsed_data, my_ip)
#     if filter_packets(parsed_data):
#         # analyze_packet(parsed_data)
#         packet_statistics(parsed_data)
#         track_connections(parsed_data)
#         update_bandwidth(parsed_data)

# print_statistics()
# print_connections()
# print_bandwidth()
# calculate_speed(elapsed_speed)
# print_speed(elapsed_speed)

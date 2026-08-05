import os
from core.packet_statistics import print_statistics
from core.connection_tracker import print_connections
from core.bandwidth_monitor import print_bandwidth, print_speed
from core.top_talkers import print_top_talkers
from core.threat_detector import print_alerts

def refresh_dashboard(elapsed_time):
    os.system("cls")
    print("=" * 60)
    print("           NETSCOPE LIVE MONITOR")
    print("=" * 60)

    print_statistics()
    print()
    print_bandwidth()
    print()
    # print_connections()
    # print()
    print_speed(elapsed_time)
    print()
    print_top_talkers()
    print()
    print_alerts()
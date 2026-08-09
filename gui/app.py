from PySide6.QtWidgets import QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QLabel, QPushButton, QStackedWidget
from core.bandwidth_monitor import bandwidth
from PySide6.QtCore import Qt, QTimer
from core.bandwidth_monitor import get_live_stats, format_speed
class NetScopeWindow(QMainWindow):
    def update_packet(self):
        self.packet_value.setText(
            str(bandwidth['total_packets'])
        )

        self.pps_value.setText(
            f"{get_live_stats()[0]} packets/s"
        )
        
        self.upload_value.setText(
            format_speed(get_live_stats()[1])
        )

        self.download_value.setText(
            format_speed(get_live_stats()[2])
        )

    def __init__(self):
        super().__init__()

        self.setWindowTitle("NetScope - Network Monitoring & IDS")
        self.resize(1200, 700)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.main_layout = QHBoxLayout()
        self.central_widget.setLayout(self.main_layout)

        self.sidebar = QWidget()
        self.sidebar.setFixedWidth(250)
        self.sidebar_layout = QVBoxLayout()
        self.sidebar.setLayout(self.sidebar_layout)

        self.logo = QLabel("NetScope")
        self.logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.logo.setStyleSheet("""
            color: white;
            font-size: 22px;
            font-weight: bold;
            padding: 15px;
            """)
        
        self.sidebar_layout.addWidget(self.logo)
        self.dashboard_button = QPushButton("Dashboard")
        self.packets_button = QPushButton("Packets")
        self.threats_button = QPushButton("Threats")
        self.statistics_button = QPushButton("Statistics")
        self.top_talkers_button = QPushButton("Top Talkers")
        self.logs_button = QPushButton("Logs")
        self.settings_button = QPushButton("Settings")


        self.sidebar_layout.addWidget(self.dashboard_button)
        self.sidebar_layout.addWidget(self.packets_button)
        self.sidebar_layout.addWidget(self.threats_button)
        self.sidebar_layout.addWidget(self.statistics_button)
        self.sidebar_layout.addWidget(self.top_talkers_button)
        self.sidebar_layout.addWidget(self.logs_button)
        self.sidebar_layout.addWidget(self.settings_button)

        self.sidebar.setStyleSheet("""
             QWidget {
                background-color: #1E1E2F;
            }
            QPushButton {
                color: white;
                background-color: #2B2B3C;
                border: none;
                padding: 12px;
                text-align: left;
            }

            QPushButton:hover {
             background-color: #3A3A4F;
            }
        """)

        self.main_layout.addWidget(self.sidebar)
        self.pages = QStackedWidget()

        self.dashboard_page = QWidget()
        self.dashboard_layout = QVBoxLayout()
        self.dashboard_page.setLayout(self.dashboard_layout)

        self.dashboard_header = QLabel("Network Dashboard")
        self.dashboard_header.setStyleSheet("""
            color: white;
            font-size: 28px;
            font-weight: bold;
            """)
        self.dashboard_layout.addWidget(self.dashboard_header)
        self.status_section = QWidget()
        self.status_layout = QHBoxLayout()
        self.status_section.setLayout(self.status_layout)
        self.dashboard_layout.addWidget(self.status_section)
        self.status_label = QLabel("● Monitoring Status: Active")
        self.status_layout.addWidget(self.status_label)

        self.status_section.setStyleSheet("""
            background-color: #1E1E2F;
            border-radius: 10px;
        """)

        self.status_label.setStyleSheet("""
            color: #00FF88;
            font-size: 16px;
            font-weight: bold;
            padding: 10px;
        """)



        self.metrics_section = QWidget()
        self.metrics_layout = QHBoxLayout()
        self.metrics_section.setLayout(self.metrics_layout)
        self.dashboard_layout.addWidget(self.metrics_section)

        self.packet_card = QWidget()
        self.pps_card = QWidget()
        self.upload_card = QWidget()
        self.download_card = QWidget()

        self.packet_layout = QVBoxLayout()
        self.packet_card.setLayout(self.packet_layout)
        self.packet_title = QLabel("Total Packets")
        self.packet_value = QLabel("0")
        self.packet_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.packet_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.packet_title.setStyleSheet("""
            color: #A6A6B8;
            font-size: 14px;
            font-weight: bold;
        """)
        self.packet_value.setStyleSheet("""
            color: white;
            font-size: 28px;
            font-weight: bold;
        """)
        self.packet_layout.addWidget(self.packet_title)
        self.packet_layout.addWidget(self.packet_value)

        self.pps_layout = QVBoxLayout()
        self.pps_card.setLayout(self.pps_layout)
        self.pps_title = QLabel("Packets/sec")
        self.pps_value = QLabel("0")
        self.pps_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.pps_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.pps_title.setStyleSheet("""
            color: #A6A6B8;
            font-size: 14px;
            font-weight: bold;
        """)
        self.pps_value.setStyleSheet("""
            color: white;
            font-size: 28px;
            font-weight: bold;
        """)
        self.pps_layout.addWidget(self.pps_title)
        self.pps_layout.addWidget(self.pps_value)


        self.upload_layout = QVBoxLayout()
        self.upload_card.setLayout(self.upload_layout)
        self.upload_title = QLabel("Upload Speed")
        self.upload_value = QLabel("0 B/s")
        self.upload_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.upload_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.upload_title.setStyleSheet("""
            color: #A6A6B8;
            font-size: 14px;
            font-weight: bold;
        """)
        self.upload_value.setStyleSheet("""
            color: white;
            font-size: 28px;
            font-weight: bold;
        """)
        self.upload_layout.addWidget(self.upload_title)
        self.upload_layout.addWidget(self.upload_value)
        

        
        self.download_layout = QVBoxLayout()
        self.download_card.setLayout(self.download_layout)
        self.download_title = QLabel("Download Speed")
        self.download_value = QLabel("0 B/s")
        self.download_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.download_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.download_title.setStyleSheet("""
                    color: #A6A6B8;
                    font-size: 14px;
                    font-weight: bold;
                """)
        self.download_value.setStyleSheet("""
                    color: white;
                    font-size: 28px;
                    font-weight: bold;
                """)
        self.download_layout.addWidget(self.download_title)
        self.download_layout.addWidget(self.download_value)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_packet)
        self.timer.start(1000)

        self.metrics_layout.addWidget(self.packet_card)
        self.metrics_layout.addWidget(self.pps_card)
        self.metrics_layout.addWidget(self.upload_card)
        self.metrics_layout.addWidget(self.download_card)
   

        self.packet_card.setObjectName("metricCard")
        self.pps_card.setObjectName("metricCard")
        self.upload_card.setObjectName("metricCard")
        self.download_card.setObjectName("metricCard")



        self.metrics_section.setStyleSheet("""
            QWidget#metricCard {
            background-color: #1E1E2F;
            border-radius: 10px;
            padding: 10px;
            }
        """)

        self.main_content = QWidget()
        self.main_content_layout = QHBoxLayout()
        self.main_content.setLayout(self.main_content_layout)
        self.dashboard_layout.addWidget(self.main_content)
      
        self.traffic_overview = QWidget()
        self.traffic_layout = QVBoxLayout()
        self.traffic_overview.setLayout(self.traffic_layout)

        self.traffic_title = QLabel("Traffic Overview")
        self.traffic_title.setStyleSheet("""
            color: white;
            font-size: 18px;
            font-weight: bold;
        """)
        self.traffic_layout.addWidget(self.traffic_title)

        self.traffic_graph = QLabel("Traffic Graph")
        self.traffic_graph.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.traffic_layout.addWidget(self.traffic_graph)
        self.traffic_graph.setStyleSheet("""
            color: #A6A6B8;
            font-size: 16px;
        """)

        self.threat_monitoring = QWidget()
        self.threat_layout = QVBoxLayout()
        self.threat_monitoring.setLayout(self.threat_layout)

        self.threat_monitoring_title = QLabel("Threat Monitoring")
        self.threat_monitoring_title.setStyleSheet("""
                color: white;
                font-size: 18px;
                font-weight: bold;
            """)
        self.threat_layout.addWidget(self.threat_monitoring_title)
        self.threat_monitoring_graph = QLabel("No threat detected")
        self.threat_monitoring_graph.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.threat_layout.addWidget(self.threat_monitoring_graph)
        self.threat_monitoring_graph.setStyleSheet("""
                color: #A6A6B8;
                font-size: 16px;
            """)

        
        self.main_content_layout.addWidget(self.traffic_overview)
        self.main_content_layout.addWidget(self.threat_monitoring)

       
        self.threat_monitoring.setObjectName("main")
        self.traffic_overview.setObjectName("main")


        self.main_content.setStyleSheet("""
            QWidget#main {
            background-color: #1E1E2F;
            border-radius: 10px;
            padding: 10px;
            }
        """)

        self.bottom_content = QWidget()
        self.bottom_content_layout = QHBoxLayout()
        self.bottom_content.setLayout(self.bottom_content_layout)
        self.dashboard_layout.addWidget(self.bottom_content)
                      
        self.top_talkers = QWidget()
        self.top_talkers_layout = QVBoxLayout()
        self.top_talkers.setLayout(self.top_talkers_layout)

        self.top_talkers_title = QLabel("Top Talkers")
        self.top_talkers_title.setStyleSheet("""
            color: white;
            font-size: 18px;
            font-weight: bold;
        """)
        self.top_talkers_layout.addWidget(self.top_talkers_title)
        self.top_talkers_content = QLabel("No traffic data")
        self.top_talkers_content.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.top_talkers_layout.addWidget(self.top_talkers_content)
        self.top_talkers_content.setStyleSheet("""
            color: #A6A6B8;
            font-size: 16px;
        """)


        self.recent_activity = QWidget()
        self.recent_activity_layout = QVBoxLayout()
        self.recent_activity.setLayout(self.recent_activity_layout)



        self.recent_activity_title = QLabel("Recent Activity")
        self.recent_activity_title.setStyleSheet("""
            color: white;
            font-size: 18px;
            font-weight: bold;
        """)
        self.recent_activity_content = QLabel("No recent activity")
        self.recent_activity_content.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.recent_activity_content.setStyleSheet("""
            color: #A6A6B8;
            font-size: 16px;
        """)

        self.recent_activity_layout.addWidget(self.recent_activity_title)
        self.recent_activity_layout.addWidget(self.recent_activity_content)
        self.bottom_content_layout.addWidget(self.top_talkers)
        self.bottom_content_layout.addWidget(self.recent_activity)
                       
        self.top_talkers.setObjectName("bottom")
        self.recent_activity.setObjectName("bottom")
                
                
        self.bottom_content.setStyleSheet("""
            QWidget#bottom {
                background-color: #1E1E2F;
                border-radius: 10px;
                padding: 10px;
            }
        """)

        self.dashboard_layout.setStretch(0, 1)
        self.dashboard_layout.setStretch(1, 1)
        self.dashboard_layout.setStretch(2, 2)
        self.dashboard_layout.setStretch(3, 4)
        self.dashboard_layout.setStretch(4, 3)

        self.main_content_layout.setStretch(0, 2)
        self.main_content_layout.setStretch(1, 1)

        self.bottom_content_layout.setStretch(0, 1)
        self.bottom_content_layout.setStretch(1, 1)

        self.pages.addWidget(self.dashboard_page)





        self.packets_page = QWidget()
        self.pages.addWidget(self.packets_page)

        self.threats_page = QWidget()
        self.pages.addWidget(self.threats_page)

        self.statistics_page = QWidget()
        self.pages.addWidget(self.statistics_page)

        self.top_talkers_page = QWidget()
        self.pages.addWidget(self.top_talkers_page)

        self.logs_page = QWidget()
        self.pages.addWidget(self.logs_page)

        self.settings_page = QWidget()
        self.pages.addWidget(self.settings_page)

        self.main_layout.addWidget(self.pages)

        self.dashboard_button.clicked.connect(
            lambda: self.pages.setCurrentWidget(self.dashboard_page)
        )

        self.packets_button.clicked.connect(
            lambda: self.pages.setCurrentWidget(self.packets_page)
        )

        self.threats_button.clicked.connect(
            lambda: self.pages.setCurrentWidget(self.threats_page)
        )

        self.statistics_button.clicked.connect(
            lambda: self.pages.setCurrentWidget(self.statistics_page)
        )

        self.top_talkers_button.clicked.connect(
            lambda: self.pages.setCurrentWidget(self.top_talkers_page)
        )

        self.logs_button.clicked.connect(
            lambda: self.pages.setCurrentWidget(self.logs_page)
        )

        self.settings_button.clicked.connect(
            lambda: self.pages.setCurrentWidget(self.settings_page)
        )
      
        self.pages.setStyleSheet("""
            QWidget {
                background-color: #181825;
            }
        """)

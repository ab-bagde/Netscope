from PySide6.QtWidgets import QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QLabel, QPushButton, QStackedWidget, QLineEdit,QComboBox, QTableWidget, QHeaderView, QTableWidgetItem
from core.bandwidth_monitor import bandwidth
from PySide6.QtCore import Qt, QTimer
from core.bandwidth_monitor import get_live_stats, format_speed
from pyqtgraph import PlotWidget
from core.threat_detector import alerts, threat_records
from core.top_talkers import top_talkers, format_bytes
from core.recent_activity import recent_activity
from datetime import datetime
import time
import pyqtgraph as pg

MAX_POINTS = 30
MAX_PACKET_ROWS = 100
MAX_THREAT_RECORDS = 100
class SpeedAxis(pg.AxisItem):
    def tickStrings(self, values, scale, spacing):
        return [
            format_speed(value)
            for value in values
        ]
class NetScopeWindow(QMainWindow):

    def format_time_ago(self, timestamp):
            elapsed = int(time.time() - timestamp)
    
            if elapsed < 60:
                return f"{elapsed} sec ago"
    
            minutes = elapsed // 60
    
            if minutes < 60:
                return f"{minutes} min ago"
    
            hours = minutes // 60
    
            if hours < 24:
                return f"{hours} hr ago"
    
            days = hours // 24
            return f"{days} day ago" if days == 1 else f"{days} days ago"   
        
    def update_packet(self):
        self.packet_value.setText(
            str(bandwidth['total_packets'])
        )
        pps, upload, download = get_live_stats()
        self.pps_value.setText(
            f"{pps} packets/s"
        )
        
        self.upload_value.setText(
            format_speed(upload)
        )

        self.download_value.setText(
            format_speed(download)
        )
        self.elapsed_time += 1;
        self.time_data.append(self.elapsed_time)
        self.upload_data.append(upload)
        self.download_data.append(download)

        if len(self.time_data) > MAX_POINTS:
            self.upload_data.pop(0)
            self.download_data.pop(0)


        self.time_data = list(range(len(self.upload_data)))
        self.upload_plot.setData(
        self.time_data,
        self.upload_data
        )

        self.download_plot.setData(
        self.time_data,
        self.download_data
        )

        if self.upload_data:
            self.plot_item.vb.setYRange(
            0,
            max(self.upload_data) * 1.1 + 1
        )

        if self.download_data:
            self.download_view.setYRange(
            0,
            max(self.download_data) * 1.1 + 1
        )

        self.traffic_graph.setXRange(
            0,
            MAX_POINTS - 1
        )

        if alerts:
            self.threat_monitoring_graph.setText(
            "\n".join(alerts)
        )
        else:
            self.threat_monitoring_graph.setText(
            "✅ No threats detected"
        )

        sorted_talkers = sorted(
        top_talkers.items(),
        key=lambda x: x[1],
        reverse=True
        )

        top3 = sorted_talkers[:3]

        if top3:
            text = "\n".join(
            f"{ip} : {format_bytes(size)}"
            for ip, size in top3
            )
            self.top_talkers_content.setText(text)
        else:
            self.top_talkers_content.setText("No traffic data")

        if recent_activity:
            self.recent_activity_content.setText(
            "\n".join(recent_activity)
        )
        else:
            self.recent_activity_content.setText(
            "No recent activity"
        )

        self.total_threats_value.setText(
            f"{len(alerts)}"
        )

        self.total_threat_value.setText(
            f"{len(threat_records)}"
        )
        
        critical = sum(
            1 for threat in threat_records
            if threat["severity"] == "Critical"
        )

        high = sum(
            1 for threat in threat_records
            if threat["severity"] == "High"
        )

        self.critical_threats_value.setText(str(critical))
        self.high_threats_value.setText(str(high))

        if threat_records:
            last_threat = threat_records[-1]
            self.last_threat_value.setText(
                self.format_time_ago(last_threat["timestamp"])
            )
        else:
            self.last_threat_value.setText("None")

        self.update_threat_table()


    def add_packet(self, parsed_data):
        if parsed_data is None:
            return

        if self.packet_table.rowCount() > MAX_PACKET_ROWS -  1:
            self.packet_table.removeRow(0)

        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)

       

        timestamp = datetime.fromtimestamp(
            parsed_data.get("timestamp", 0)
        ).strftime("%H:%M:%S")

        values = [
            timestamp,
            parsed_data.get("src_ip", parsed_data.get("sender_ip", "")),
            parsed_data.get("dst_ip", parsed_data.get("target_ip", "")),
            parsed_data.get("protocol", ""),
            parsed_data.get("src_port", ""),
            parsed_data.get("dst_port", ""),
            parsed_data.get("service", ""),
            format_bytes(parsed_data.get("size", 0))
        ]

        for column, value in enumerate(values):
            item = QTableWidgetItem(str(value))
            self.packet_table.setItem(row, column, item)

        self.apply_filters()
    # def search_packets(self, text):
    #     text = text.lower().strip()
    #     for row in range(self.packet_table.rowCount()):
    #         match = False
    #         for column in range(self.packet_table.columnCount()):
    #             item = self.packet_table.item(row, column)
    #             if item and text in item.text().lower():
    #                 match = True
    #                 break
    #         self.packet_table.setRowHidden(row, not match)

    def apply_filters(self):
        search_text = self.packet_search.text().lower().strip()
        proto = self.protocol_filter.currentText()
        service = self.service_filter.currentText()

        for row in range(self.packet_table.rowCount()):
            row_protocol = self.packet_table.item(row, 3).text()
            row_service = self.packet_table.item(row, 6).text()

            search_match = False
            for column in range(self.packet_table.columnCount()):
                item = self.packet_table.item(row, column)
                if item and search_text in item.text().lower():
                    search_match = True
                    break
            proto_match = (
                proto == "All Protocols" or proto == row_protocol
            )

            service_match = (
                service == "All Services" or service == row_service
            )

            show = search_match and proto_match and service_match
            self.packet_table.setRowHidden(row, not show)

    def update_threat_table(self):
        self.threat_table.setRowCount(0)

        for threat in threat_records[-MAX_THREAT_RECORDS:]:
            row = self.threat_table.rowCount()
            self.threat_table.insertRow(row)

            timestamp = datetime.fromtimestamp(
                threat["timestamp"]
            ).strftime("%H:%M:%S")

            values = [
                timestamp,
                threat["type"],
                threat["source_ip"],
                threat["destination_ip"],
                threat["severity"],
                threat["description"]
            ]

            for column, value in enumerate(values):
                self.threat_table.setItem(
                    row,
                    column,
                    QTableWidgetItem(str(value))
                )
        
    def show_details(self, row, col):
        details = []
        for col in range(self.packet_table.columnCount()):
            header = self.packet_table.horizontalHeaderItem(col).text()
            item = self.packet_table.item(row,col)

            value = item.text() if item else " "
            details.append(f"{header} : {value}")

        self.packet_details_content.setText(
            "\n".join(details)
        )

    def show_threat_details(self, row, col):
        details = []
        for col in range(self.threat_table.columnCount()):
            header = self.threat_table.horizontalHeaderItem(col).text()
            item = self.threat_table.item(row,col)
        
            value = item.text() if item else " "
            details.append(f"{header} : {value}")
    
        self.Threat_details_content.setText(
            "\n".join(details)
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

            QPushButton:pressed {
            background-color: #30304A;
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

        self.time_data = []
        self.upload_data = []
        self.download_data = []
        self.elapsed_time = 0;

        self.upload_axis = SpeedAxis(orientation="left")
        self.download_axis = SpeedAxis(orientation="right")
        self.plot_item = pg.PlotItem(
            axisItems = {
                "left" : self.upload_axis,
                "right" : self.download_axis
            }
        )
        self.plot_item.showAxis("right")
        self.traffic_graph = pg.PlotWidget(
            plotItem = self.plot_item
        )

        self.download_view = pg.ViewBox()
        self.plot_item.scene().addItem(self.download_view)
        self.download_axis.linkToView(self.download_view)
        self.download_view.setXLink(self.plot_item.vb)

        def update_views():
            self.download_view.setGeometry(
            self.plot_item.vb.sceneBoundingRect()
        )

        self.plot_item.vb.sigResized.connect(update_views)
        update_views()

        self.traffic_graph.setTitle("Network Traffic")
        self.upload_axis.setLabel(
            "Upload Speed",
            units="B/s"
        )

        self.download_axis.setLabel(
            "Download Speed",
            units="B/s"
        )
        self.traffic_graph.showGrid(x=True, y=True, alpha=0.3)
        self.traffic_graph.addLegend()
        self.legend = self.traffic_graph.plotItem.legend

        self.legend.anchor(
            itemPos=(1, 0),
            parentPos=(1, 0),
            offset=(2, 2)
        )
        self.upload_plot = self.traffic_graph.plot(
            pen=pg.mkPen("#00FF88", width=2),
            name="Upload"
        )

        self.download_plot = self.traffic_graph.plot(
            pen=pg.mkPen("#4DA6FF", width=2),
            name="Download"
        )
        self.download_view.addItem(self.download_plot)
        self.traffic_layout.addWidget(self.traffic_graph)
        self.traffic_graph.setAlignment(Qt.AlignmentFlag.AlignCenter)
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

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_packet)
        self.timer.start(1000)


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
        self.packet_page_layout = QVBoxLayout()
        self.packets_page.setLayout(self.packet_page_layout)

        self.packets_header = QLabel("Network Packets")
        self.packets_header.setStyleSheet("""
            color: white;
            font-size: 28px;
            font-weight: bold;
            padding: 10px;
        """)
        self.packet_page_layout.addWidget(self.packets_header)
        self.packets_subtitle = QLabel(
            "Live network traffic captured by NetScope"
            )
        self.packets_subtitle.setStyleSheet("""
            color: #A6A6B8;
            font-size: 14px;
            padding-left: 10px;
            padding-bottom: 10px;
        """)
        self.packet_page_layout.addWidget(self.packets_subtitle)
        self.packet_filter_layout = QHBoxLayout()

        self.packet_filter_widget = QWidget()
        self.packet_filter_layout = QHBoxLayout()
        self.packet_filter_widget.setLayout(self.packet_filter_layout)
        self.packet_page_layout.addWidget(self.packet_filter_widget)

        self.packet_search = QLineEdit()
        self.packet_search.setPlaceholderText(
            "Search IP, protocol, service..."
        )

        self.protocol_filter = QComboBox()
        self.protocol_filter.addItems([
            "All Protocols",
            "TCP",
            "UDP",
            "ICMP",
            "ARP",
            "DHCP"
        ])

        self.service_filter = QComboBox()
        self.service_filter.addItems([
            "All Services",
            "HTTP",
            "HTTPS",
            "DNS",
            "SSH",
            "FTP",
            "Telnet",
            "SMTP",
            "IMAP",
            "POP3",
            "mDNS"
        ])

        self.packet_search.textChanged.connect(
            self.apply_filters
        )
        
        self.protocol_filter.currentTextChanged.connect(
            self.apply_filters
        )
        
        self.service_filter.currentTextChanged.connect(
            self.apply_filters
        )
        self.packet_filter_layout.addWidget(self.packet_search)
        self.packet_filter_layout.addWidget(self.protocol_filter)
        self.packet_filter_layout.addWidget(self.service_filter)

        self.packet_filter_widget.setStyleSheet("""
            QWidget {
                background-color: #1E1E2F;
                border-radius: 10px;
            }
        """)

        self.packet_table = QTableWidget()

        self.packet_table.setColumnCount(8)

        self.packet_table.setHorizontalHeaderLabels([
            "Time",
            "Source IP",
            "Destination IP",
            "Protocol",
            "Source Port",
            "Destination Port",
            "Service",
            "Size"
            ])

        self.packet_page_layout.addWidget(self.packet_table)
        self.packet_table.setAlternatingRowColors(True)

        self.packet_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )

        self.packet_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )

        self.packet_table.setSortingEnabled(True)
        header = self.packet_table.horizontalHeader()

        header.setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.packet_table.setStyleSheet("""
            QTableWidget {
                background-color: #1E1E2F;
                color: white;
                gridline-color: #3A3A4F;
                border: none;
                border-radius: 10px;
                font-size: 13px;
            }

            QTableWidget::item:selected {
                background-color: #3A3A4F;
            }

            QHeaderView::section {
                background-color: #2B2B3C;
                color: #A6A6B8;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
        """)

        self.packet_details = QWidget()
        self.packet_details_layout = QVBoxLayout()
        self.packet_details.setLayout(self.packet_details_layout)

        self.packet_details_title = QLabel("Packet Details")
        self.packet_details_title.setStyleSheet("""
            color: white;
            font-size: 18px;
            font-weight: bold;
        """)

        self.packet_details_content = QLabel("Select a packet to view details")
        self.packet_details_content.setStyleSheet("""
            color: #A6A6B8;
            font-size: 14px;
        """)

        self.packet_details_layout.addWidget(
            self.packet_details_title
        )
        self.packet_details_layout.addWidget(
            self.packet_details_content
        )

        self.packet_page_layout.addWidget(
            self.packet_details
        )

        self.packet_table.cellClicked.connect(
            self.show_details
        )

        self.pages.addWidget(self.packets_page)


        self.threats_page = QWidget()
        self.threats_page_layout = QVBoxLayout()
        self.threats_page.setLayout(self.threats_page_layout)
        
        self.threats_header = QLabel("Threat Monitoring")
        self.threats_header.setStyleSheet("""
            color: white;
            font-size: 28px;
            font-weight: bold;
            padding: 10px;
        """)
        self.threats_page_layout.addWidget(self.threats_header)
        self.threats_subtitle = QLabel(
            "Detected network threats and security alerts"
            )
        self.threats_subtitle.setStyleSheet("""
            color: #A6A6B8;
            font-size: 14px;
            padding-left: 10px;
            padding-bottom: 10px;
            """)
        self.threats_page_layout.addWidget(self.threats_subtitle)
        self.threats_card = QWidget()
        self.threats_card_layout = QHBoxLayout()
        self.threats_card.setLayout(self.threats_card_layout)

        self.total_threats = QWidget()
        self.total_threats_layout = QVBoxLayout()
        self.total_threats.setLayout(self.total_threats_layout)

        self.total_threats_title = QLabel("Active Threats")
        self.total_threats_value = QLabel("0")

        self.total_threats_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.total_threats_value.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.total_threats_title.setStyleSheet("""
            color: #A6A6B8;
            font-size: 14px;
            font-weight: bold;
        """)

        self.total_threats_value.setStyleSheet("""
            color: white;
            font-size: 28px;
            font-weight: bold;
        """)

        self.total_threats_layout.addWidget(self.total_threats_title)
        self.total_threats_layout.addWidget(self.total_threats_value)

        self.total_threat = QWidget()
        self.total_threat_layout = QVBoxLayout()
        self.total_threat.setLayout(self.total_threat_layout)
        
        self.total_threat_title = QLabel("Total Threats")
        self.total_threat_value = QLabel("0")
        
        self.total_threat_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.total_threat_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.total_threat_title.setStyleSheet("""
            color: #A6A6B8;
            font-size: 14px;
            font-weight: bold;
        """)
        
        self.total_threat_value.setStyleSheet("""
            color: white;
            font-size: 28px;
            font-weight: bold;
        """)
        
        self.total_threat_layout.addWidget(self.total_threat_title)
        self.total_threat_layout.addWidget(self.total_threat_value)

        self.critical_threats = QWidget()
        self.critical_threats_layout = QVBoxLayout()
        self.critical_threats.setLayout(self.critical_threats_layout)

        self.critical_threats_title = QLabel("Critical Threats")
        self.critical_threats_value = QLabel("0")

        self.critical_threats_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.critical_threats_value.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.critical_threats_title.setStyleSheet("""
            color: #A6A6B8;
            font-size: 14px;
            font-weight: bold;
        """)

        self.critical_threats_value.setStyleSheet("""
            color: white;
            font-size: 28px;
            font-weight: bold;
        """)

        self.critical_threats_layout.addWidget(self.critical_threats_title)
        self.critical_threats_layout.addWidget(self.critical_threats_value)

        self.high_threats = QWidget()
        self.high_threats_layout = QVBoxLayout()
        self.high_threats.setLayout(self.high_threats_layout)

        self.high_threats_title = QLabel("High Threats")
        self.high_threats_value = QLabel("0")
        
        self.high_threats_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.high_threats_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.high_threats_title.setStyleSheet("""
            color: #A6A6B8;
            font-size: 14px;
            font-weight: bold;
        """)
        
        self.high_threats_value.setStyleSheet("""
            color: white;
            font-size: 28px;
            font-weight: bold;
        """)
        
        self.high_threats_layout.addWidget(self.high_threats_title)
        self.high_threats_layout.addWidget(self.high_threats_value)
        
    
        self.last_threat = QWidget()
        self.last_threat_layout = QVBoxLayout()
        self.last_threat.setLayout(self.last_threat_layout)

        self.last_threat_title = QLabel("Last Threat")
        self.last_threat_value = QLabel("0")
                
        self.last_threat_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.last_threat_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
                
        self.last_threat_title.setStyleSheet("""
            color: #A6A6B8;
            font-size: 14px;
            font-weight: bold;
        """)
                
        self.last_threat_value.setStyleSheet("""
            color: white;
            font-size: 28px;
            font-weight: bold;
        """)
                
        self.last_threat_layout.addWidget(self.last_threat_title)
        self.last_threat_layout.addWidget(self.last_threat_value)

        self.threats_card_layout.addWidget(self.total_threats)
        self.threats_card_layout.addWidget(self.total_threat)
        self.threats_card_layout.addWidget(self.critical_threats)
        self.threats_card_layout.addWidget(self.high_threats)
        self.threats_card_layout.addWidget(self.last_threat)

        self.threats_page_layout.addWidget(self.threats_card)

        self.total_threats.setObjectName("metricCard")
        self.total_threat.setObjectName("metricCard")
        self.critical_threats.setObjectName("metricCard")
        self.high_threats.setObjectName("metricCard")
        self.last_threat.setObjectName("metricCard")
        
        self.threats_card.setStyleSheet("""
            QWidget#metricCard {
            background-color: #1E1E2F;
            border-radius: 10px;
            padding: 10px;
            }
        """)

        self.threat_table = QTableWidget()
        self.threat_table.setColumnCount(6)
        self.threat_table.setHorizontalHeaderLabels(
            [
                "Time",
                "Threat",
                "Source IP",
                "Destination IP",
                "Severity",
                "Description"
            ]
        )
        self.threats_page_layout.addWidget(self.threat_table)
        self.threat_table.setAlternatingRowColors(True)

        self.threat_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )


        self.threat_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        
        self.threat_table.setSortingEnabled(True)
        header = self.threat_table.horizontalHeader()
        
        header.setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.threat_table.setStyleSheet("""
            QTableWidget {
                background-color: #1E1E2F;
                color: white;
                gridline-color: #3A3A4F;
                border: none;
                border-radius: 10px;
                font-size: 13px;
            }
        
            QTableWidget::item:selected {
                background-color: #3A3A4F;
            }
        
            QHeaderView::section {
                background-color: #2B2B3C;
                color: #A6A6B8;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
        """)

        self.Threat_details = QWidget()
        self.Threat_details_layout = QVBoxLayout()
        self.Threat_details.setLayout(self.Threat_details_layout)
    
        self.Threat_details_title = QLabel("Threat Details")
        self.Threat_details_title.setStyleSheet("""
            color: white;
            font-size: 18px;
            font-weight: bold;
        """)
    
        self.Threat_details_content = QLabel("Select a packet to view details")
        self.Threat_details_content.setStyleSheet("""
            color: #A6A6B8;
            font-size: 14px;
        """)
        self.Threat_details_layout.addWidget(self.Threat_details_title)
        self.Threat_details_layout.addWidget(self.Threat_details_content)
        self.threats_page_layout.addWidget(self.Threat_details)
        self.threat_table.cellClicked.connect(
            self.show_threat_details
        )
    
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

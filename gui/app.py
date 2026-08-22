from PySide6.QtWidgets import QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QLabel, QPushButton, QStackedWidget, QLineEdit,QComboBox,QGridLayout, QTableWidget, QHeaderView, QTableWidgetItem, QFileDialog, QMessageBox
from core.bandwidth_monitor import bandwidth
from PySide6.QtCore import Qt, QTimer
from core.bandwidth_monitor import get_live_stats, format_speed, format_data
from pyqtgraph import PlotWidget
from core.connection_tracker import connections
from core.threat_detector import alerts, threat_records
from core.top_talkers import top_talkers, format_bytes
from core.recent_activity import recent_activity
from datetime import datetime
from core.packet_statistics import stats
from reports.report import collect_report_data, generate_json_report, generate_csv_report, generate_pdf_report
from reports.report_history import add_recent_report, load_recent_reports, clear_list
import time
import os
import pyqtgraph as pg
import json
import subprocess

MAX_POINTS = 30
MAX_PACKET_ROWS = 100
MAX_THREAT_RECORDS = 100
MAX_CONNECTION_RECORDS = 100
class SpeedAxis(pg.AxisItem):
    def tickStrings(self, values, scale, spacing):
        return [
            format_speed(value)
            for value in values
        ]
class ProtocolAxis(pg.AxisItem):
    def __init__(self, protocols, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.protocols = protocols

        self.setPen(pg.mkPen("#F9F9F5"))
        self.setTextPen(pg.mkPen("#F9F9F5"))

    def tickStrings(self, values, scale, spacing):
        return [
            self.protocols[int(value)]
            if 0 <= int(value) < len(self.protocols)
            else ""
            for value in values
        ]

class EditAxis(pg.AxisItem):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.setPen(pg.mkPen("#F9F9F5"))
        self.setTextPen(pg.mkPen("#F9F9F5"))
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

        self.tpacket_value.setText(
            str(bandwidth['total_packets'])
        )
        self.stat_data_value.setText(
            format_data(bandwidth['total_bytes'])
        )
        self.upload_data_value.setText(
            format_data(bandwidth['upload_bytes'])
        )
        self.download_data_value.setText(
            format_data(bandwidth['download_bytes'])
        )
        self.smallest_value.setText(
            format_data(bandwidth['smallest_packet_size'])
        )
        self.largest_value.setText(
            format_data(bandwidth['largest_packet_size'])
        )
        self.update_threat_table()
     

        self.protocol_values = [
            stats.get("TCP_packets", 0),
            stats.get("UDP_packets", 0),
            stats.get("ICMP_packets", 0),
            stats.get("DNS_packets", 0),
            stats.get("mDNS_packets", 0),
            
        ]

        self.protocol_bar.setOpts(
            height = self.protocol_values
        )
        for i, label in enumerate(self.proto_labels):
            label.setText(str(self.protocol_values[i]))
            label.setPos(i, self.protocol_values[i] + 2)


        self.protocol_graph.setYRange(
            0,
            max(self.protocol_values) * 1.2
        )

        self.service_values = [
            stats.get("HTTP_packets", 0),
            stats.get("HTTPS_packets", 0),
            stats.get("DNS_packets", 0),
            stats.get("SSH_packets", 0),
            stats.get("FTP_packets", 0)
        ]

        self.service_bar.setOpts(
            height=self.service_values
        )

        for i, label in enumerate(self.service_labels):
            label.setText(str(self.service_values[i]))
            label.setPos(i, self.service_values[i] + 2)
                
        self.service_graph.setYRange(
            0,
            max(self.service_values) * 1.2
            )
        self.host_value.setText(
            str(len(top_talkers))
        )

        total_data = sum(top_talkers.values())

        self.data_value.setText(
            format_bytes(total_data)
        )

        if top_talkers:
            top_ip = max(
            top_talkers,
            key=top_talkers.get
        )

            self.top_value.setText(top_ip)
        else:
            self.top_value.setText("None")


        top10 = sorted_talkers[:10]
        for i in range(10):
            if i < len(top10):
                ip, data = top10[i]

                self.top_ip[9-i] = ip
                self.data_values[9-i] = data

            else:
                self.top_ip[i] = f"IP{i + 1}"
                self.data_values[i] = 0
        x = [value / 2 for value in self.data_values]
        self.top_bar.setOpts(
            x=x,
            width=self.data_values
        )
        max_data = max(self.data_values) if self.data_values else 1
        left_margin = max_data * 0.2

        self.top_graph.setXRange(
            -left_margin,
            max_data * 1.10,
            padding=0
        )

        for i, label in enumerate(self.top_value_labels):
            label.setText(format_data(self.data_values[i]))
            label.setPos(self.data_values[i] + 2, i)

        for i, label in enumerate(self.top_ip_labels):
            label.setText(self.top_ip[i])
            label.setPos(-left_margin * 0.05, 9 - i)

        recent_exports = load_recent_reports()

        self.update_connection_table()

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

    def open_report(self, report):
        path = report["path"]
        file_format = report["format"]

        if file_format == "JSON":
            subprocess.Popen(["notepad.exe", path])
        else:
            os.startfile(path)

    def clear_all_reports(self):
        reply = QMessageBox.question(
            self,
            "Clear All Reports",
            "Are you sure you want to premanently delete all reports?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        reports = load_recent_reports()

        for report in reports:
            path = report["path"]
            if os.path.exists(path):
                os.remove(path)

        while self.recent_reports_layout.count():
            item = self.recent_reports_layout.takeAt(0)

            widget = item.widget()

            if widget is not None:
                widget.deleteLater()

        clear_list()
        self.update_recent_reports()

    def update_recent_reports(self):

        while self.recent_reports_layout.count():
            item = self.recent_reports_layout.takeAt(0)

            widget = item.widget()

            if widget is not None:
                widget.deleteLater()

        reports = load_recent_reports()
        if not reports:
            no_reports_label = QLabel(
                "No reports generated yet"
            )

            no_reports_label.setAlignment(
                Qt.AlignmentFlag.AlignCenter
            )

            no_reports_label.setStyleSheet("""
                color: #9ca3af;
                font-size: 14px;
                padding: 30px;
            """)

            self.recent_reports_layout.addWidget(
                no_reports_label
            )
            return
        for report in reports:

            report_row = QWidget()
            report_row.setObjectName("reportRow")

            report_row_layout = QHBoxLayout()
            report_row_layout.setContentsMargins(12, 10, 12, 10)
            report_row_layout.setSpacing(10)

            report_row.setLayout(report_row_layout)

            details_widget = QWidget()
            details_layout = QVBoxLayout()
            details_layout.setContentsMargins(0, 0, 0, 0)
            details_layout.setSpacing(4)

            details_widget.setLayout(details_layout)

            filename_label = QLabel(
                report["filename"]
            )
            filename_label.setStyleSheet("""
                color: white;
                font-size: 14px;
                font-weight: bold;
            """)

            metadata_label = QLabel(
                f'{report["format"]} • '
                f'{report["time_range"]} • '
                f'{report["generated_at"]}'
            )
            metadata_label.setStyleSheet("""
                color: #9ca3af;
                font-size: 12px;
            """)

            details_layout.addWidget(filename_label)
            details_layout.addWidget(metadata_label)

            report_row_layout.addWidget(details_widget)
            report_row_layout.addStretch()

            open_button = QPushButton("Open")
            open_button.setStyleSheet("""
                QPushButton {
                    background-color: #4DA6FF;
                    color: white;
                    border: none;
                    border-radius: 7px;
                    padding: 7px 14px;
                    font-size: 10px;
                    font-weight: bold;
                }
    
                QPushButton:hover {
                    background-color: #3B8FE6;
                }
    
                QPushButton:pressed {
                    background-color: #2878CC;
                }
            """)

            report_row_layout.addWidget(open_button)
            open_button.clicked.connect(
              lambda _, report=report: self.open_report(report)
            )
            self.recent_reports_layout.addWidget(
                report_row
            )

            report_row.setStyleSheet("""
                QWidget#reportRow {
                    background-color: #1E1E2F;
                    border: 1px solid #2B2B3C;
                    border-radius: 8px;
                }

                QWidget#reportRow:hover {
                    border: 1px solid #3A3A4F;
                }
            """)

    def generate_report(self):
        time_range = self.time_range_combo.currentText()
        report_format = self.format_combo.currentText()
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        time_now = time.time()

        print("Format:", report_format)
        print("Current directory:", os.getcwd())

        data = collect_report_data(
            time_range,
            self.elapsed_time
        )

        if report_format == "JSON":
            default_name = f"Netscope_report_{timestamp}.json"

            file_path, _ = QFileDialog.getSaveFileName(
               self,
               "Save Netscope Report",
               default_name,
               "JSON Files (*.json)"
            )

            if not file_path:
                return

            generate_json_report(
                data,
                file_path
            )

            print("JSON report generated")
            print("Saved At:", file_path)
            extension = os.path.splitext(file_path)[1]
            report = {
                "filename": os.path.basename(file_path),
                "path": file_path,
                "format": extension.replace(".", "").upper(),
                "time_range": time_range,
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            add_recent_report(report)
            self.update_recent_reports()

        if report_format == "CSV":
            default_name = f"Netscope_report_{timestamp}.csv"
           
            file_path, _ = QFileDialog.getSaveFileName(
               self,
               "Save Netscope Report",
               default_name,
               "CSV Files (*.csv)"
            )

            if not file_path:
                return

            generate_csv_report(
                data,
                file_path
            )

            print("CSV report generated")
            print("Saved At:", file_path)

            extension = os.path.splitext(file_path)[1]
            report = {
                "filename": os.path.basename(file_path),
                "path": file_path,
                "format": extension.replace(".", "").upper(),
                "time_range": time_range,
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            add_recent_report(report)
            self.update_recent_reports()

        elif report_format == "PDF":
            default_name = f"Netscope_report_{timestamp}.pdf"
            
            file_path, _ = QFileDialog.getSaveFileName(
               self,
               "Save Netscope Report",
               default_name,
               "PDF Files (*.pdf)"
            )

            if not file_path:
                return

            generate_pdf_report(
                data,
                file_path
            )

            print("PDF report generated")
            print("Saved at:", file_path)

            extension = os.path.splitext(file_path)[1]
            report = {
                "filename": os.path.basename(file_path),
                "path": file_path,
                "format": extension.replace(".", "").upper(),
                "time_range": time_range,
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            add_recent_report(report)
            self.update_recent_reports()

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
    def update_connection_table(self):
        self.connection_table.setRowCount(0)
        recent_connections = list(connections.items())[-MAX_CONNECTION_RECORDS:]
        for connection, dict in recent_connections:
            row = self.connection_table.rowCount()
            self.connection_table.insertRow(row)
            endpoint1, endpoint2, protocol = connection
            src_ip, src_port = endpoint1
            dst_ip, dst_port = endpoint2
        
            values = [
                f"{src_ip}:{src_port}",
                f"{dst_ip}:{dst_port}",
                protocol,
                f"{dict['packets']}",
                f"{format_data(dict['data'])}"
            ]
            for column, value in enumerate(values):
                self.connection_table.setItem(
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
        self.elapsed_time = 0

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
        self.threat_monitoring_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
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
        self.top_talkers_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
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
        self.recent_activity_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
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
        self.statistics_page_layout = QVBoxLayout()
        self.statistics_page.setLayout(self.statistics_page_layout)
        
        self.statistics_header = QLabel("Statistics")
        self.statistics_header.setStyleSheet("""
            color: white;
            font-size: 28px;
            font-weight: bold;
            padding: 10px;
        """)
        self.statistics_page_layout.addWidget(self.statistics_header)
        self.statistics_subtitle = QLabel(
            "Network traffic, protocol and threat analysis"
            )
        self.statistics_subtitle.setStyleSheet("""
            color: #A6A6B8;
            font-size: 14px;
            padding-left: 10px;
            padding-bottom: 10px;
            """)
        self.statistics_page_layout.addWidget(self.statistics_subtitle)

        self.info_section = QWidget()
        self.info_layout = QGridLayout()
        self.info_section.setLayout(self.info_layout)
        self.statistics_page_layout.addWidget(self.info_section)

        self.tpacket_card = QWidget()
        self.data_card = QWidget()
        self.upload_data_card = QWidget()
        self.download_data_card = QWidget()
        self.smallest_card = QWidget()
        self.largest_card = QWidget()

        self.tpacket_layout = QVBoxLayout()
        self.tpacket_card.setLayout(self.tpacket_layout)
        self.tpacket_title = QLabel("Total Packets")
        self.tpacket_value = QLabel("0")
        self.tpacket_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.tpacket_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.tpacket_title.setStyleSheet("""
            color: #A6A6B8;
            font-size: 14px;
            font-weight: bold;
        """)
        self.tpacket_value.setStyleSheet("""
            color: white;
            font-size: 28px;
            font-weight: bold;
        """)
        self.tpacket_layout.addWidget(self.tpacket_title)
        self.tpacket_layout.addWidget(self.tpacket_value)

        self.data_layout = QVBoxLayout()
        self.data_card.setLayout(self.data_layout)
        self.data_title = QLabel("Total Data")
        self.stat_data_value = QLabel("0 B")
        self.data_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.stat_data_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.data_title.setStyleSheet("""
            color: #A6A6B8;
            font-size: 14px;
            font-weight: bold;
        """)
        self.stat_data_value.setStyleSheet("""
            color: white;
            font-size: 28px;
            font-weight: bold;
        """)
        self.data_layout.addWidget(self.data_title)
        self.data_layout.addWidget(self.stat_data_value)

        self.upload_data_layout = QVBoxLayout()
        self.upload_data_card.setLayout(self.upload_data_layout)
        self.upload_data_title = QLabel("Uploaded")
        self.upload_data_value = QLabel("0 B")
        self.upload_data_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.upload_data_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.upload_data_title.setStyleSheet("""
            color: #A6A6B8;
            font-size: 14px;
            font-weight: bold;
        """)
        self.upload_data_value.setStyleSheet("""
            color: white;
            font-size: 28px;
            font-weight: bold;
        """)
        self.upload_data_layout.addWidget(self.upload_data_title)
        self.upload_data_layout.addWidget(self.upload_data_value)
        
        self.download_data_layout = QVBoxLayout()
        self.download_data_card.setLayout(self.download_data_layout)
        self.download_data_title = QLabel("Downloaded")
        self.download_data_value = QLabel("0 B")
        self.download_data_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.download_data_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.download_data_title.setStyleSheet("""
                    color: #A6A6B8;
                    font-size: 14px;
                    font-weight: bold;
                """)
        self.download_data_value.setStyleSheet("""
                    color: white;
                    font-size: 28px;
                    font-weight: bold;
                """)
        self.download_data_layout.addWidget(self.download_data_title)
        self.download_data_layout.addWidget(self.download_data_value)
        
        self.smallest_layout = QVBoxLayout()
        self.smallest_card.setLayout(self.smallest_layout)
        self.smallest_title = QLabel("Smallest")
        self.smallest_value = QLabel("0 B")
        self.smallest_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.smallest_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.smallest_title.setStyleSheet("""
            color: #A6A6B8;
            font-size: 14px;
            font-weight: bold;
        """)
        self.smallest_value.setStyleSheet("""
            color: white;
            font-size: 28px;
            font-weight: bold;
        """)
        self.smallest_layout.addWidget(self.smallest_title)
        self.smallest_layout.addWidget(self.smallest_value)

        self.largest_layout = QVBoxLayout()
        self.largest_card.setLayout(self.largest_layout)
        self.largest_title = QLabel("Longest")
        self.largest_value = QLabel("0 B")
        self.largest_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.largest_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.largest_title.setStyleSheet("""
            color: #A6A6B8;
            font-size: 14px;
            font-weight: bold;
        """)
        self.largest_value.setStyleSheet("""
            color: white;
            font-size: 24px;
            font-weight: bold;
        """)
        self.largest_layout.addWidget(self.largest_title)
        self.largest_layout.addWidget(self.largest_value)

        self.info_layout.addWidget(self.tpacket_card, 0, 0)
        self.info_layout.addWidget(self.data_card, 0, 1)
        self.info_layout.addWidget(self.upload_data_card, 0, 2)
        self.info_layout.addWidget(self.download_data_card, 1, 0)
        self.info_layout.addWidget(self.smallest_card, 1, 1)
        self.info_layout.addWidget(self.largest_card, 1, 2)

        self.info_layout.setHorizontalSpacing(12)
        self.info_layout.setVerticalSpacing(12)
        self.info_layout.setContentsMargins(0, 5, 0, 10)

        self.tpacket_card.setObjectName("metricCard")
        self.data_card.setObjectName("metricCard")
        self.upload_data_card.setObjectName("metricCard")
        self.download_data_card.setObjectName("metricCard")
        self.smallest_card.setObjectName("metricCard")
        self.largest_card.setObjectName("metricCard")

        self.info_section.setStyleSheet("""
            QWidget#metricCard {
            background-color: #1E1E2F;
            border-radius: 10px;
            padding: 10px;
            }
        """)

        self.main_field = QWidget()
        self.main_field_layout = QHBoxLayout()
        self.main_field.setLayout(self.main_field_layout)

        self.proto_overview = QWidget()
        self.proto_layout = QVBoxLayout()
        self.proto_overview.setLayout(self.proto_layout)
        self.proto_title = QLabel("Protocol Distribution")
        self.proto_title.setStyleSheet("""
            color: white;
            font-size: 18px;
            font-weight: bold;
        """)
        self.proto_layout.addWidget(self.proto_title)

        self.service_overview = QWidget()
        self.service_layout = QVBoxLayout()
        self.service_overview.setLayout(self.service_layout)
        self.service_title = QLabel("Service Distribution")
        self.service_title.setStyleSheet("""
            color: white;
            font-size: 18px;
            font-weight: bold;
        """)
        self.service_layout.addWidget(self.service_title)
        
        protocols = ["TCP", "UDP", "ICMP", "DNS", "mDNS"]
        self.proto_axis = ProtocolAxis(
            protocols,
            orientation = "bottom"
        )

        self.proto_y_axis = EditAxis(
            orientation = "left"
        )
        self.proto_axis.setLabel(
            "Protocol"
        )
        self.proto_y_axis.setLabel(
            "Packet count"
        )
        self.protocol_graph = pg.PlotWidget(
            axisItems = {
                "bottom":self.proto_axis,
                "left" : self.proto_y_axis
            }
        )
        self.protocol_graph.setTitle("Packets by Protocol")
        self.protocol_graph.showGrid(x=True, y=True, alpha=0.3)
       
       
        self.protocol_values = [0, 0, 0, 0, 0]
        x = list(range(len(protocols)))
        self.protocol_bar = pg.BarGraphItem(
            x = x,
            height=self.protocol_values,
            width = 0.4,
            brush="#4DA6FF"
        )
        self.protocol_graph.addItem(self.protocol_bar)
        self.proto_labels = []
        for i, protocol in enumerate(protocols):
            label = pg.TextItem(
                text = "0",
                color="#F9F9F5",
                anchor=(0.5, 1)
            )
            self.proto_labels.append(label)
            self.protocol_graph.addItem(label)
            label.setPos(i, self.protocol_values[i] + 2)

        services = ["HTTP", "HTTPS", "DNS", "SSH", "FTP"]
        self.service_axis = ProtocolAxis(
            services,
            orientation = "bottom"
        )
        
        self.service_y_axis = EditAxis(
            orientation = "left"
        )
        self.service_axis.setLabel(
            "Service"
        )
        self.service_y_axis.setLabel(
            "Packet count"
        )
        self.service_graph = pg.PlotWidget(
             axisItems = {
                "bottom":self.service_axis,
                "left" : self.service_y_axis
            }
        )
        self.service_graph.setTitle("Packets by Service")
        self.service_graph.showGrid(x=True, y=True, alpha=0.3)

        self.service_values = [0, 0, 0, 0, 0]
        self.service_bar = pg.BarGraphItem(
            x = list(range(len(services))),
            height=self.service_values,
            width = 0.4,
            brush="#4DA6FF"
        )
        self.service_graph.addItem(self.service_bar)
        self.service_labels = []
        for i, service in enumerate(services):
            label = pg.TextItem(
                text = "0",
                color="#F9F9F5",
                anchor=(0.5, 1)
            )
            self.service_labels.append(label)
            self.service_graph.addItem(label)
            label.setPos(i, self.service_values[i] + 2)

        self.proto_layout.addWidget(self.protocol_graph)
        self.main_field_layout.addWidget(self.proto_overview)

        self.service_layout.addWidget(self.service_graph)
        self.main_field_layout.addWidget(self.service_overview)

        self.statistics_page_layout.addWidget(self.main_field)
        self.pages.addWidget(self.statistics_page)

        self.top_talkers_page = QWidget()
        self.top_talkers_page_layout = QVBoxLayout()
        self.top_talkers_page.setLayout(self.top_talkers_page_layout)
        
        self.top_talkers_header = QLabel("Top Talkers")
        self.top_talkers_header.setStyleSheet("""
            color: white;
            font-size: 28px;
            font-weight: bold;
            padding: 10px;
        """)
        self.top_talkers_page_layout.addWidget(self.top_talkers_header)
        self.top_talkers_subtitle = QLabel(
            "Devices/IPs generating the most network traffic "
            )
        self.top_talkers_subtitle.setStyleSheet("""
            color: #A6A6B8;
            font-size: 14px;
            padding-left: 10px;
            padding-bottom: 10px;
            """)
        self.top_talkers_page_layout.addWidget(self.top_talkers_subtitle)

        self.tt_section = QWidget()
        self.tt_layout = QHBoxLayout()
        self.tt_section.setLayout(self.tt_layout)
    
        self.host_card = QWidget()
        self.data_card = QWidget()
        self.top_card = QWidget()

        self.host_layout = QVBoxLayout()
        self.host_card.setLayout(self.host_layout)
        self.host_title = QLabel("Total Hosts")
        self.host_value = QLabel("0")
        self.host_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.host_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.host_title.setStyleSheet("""
            color: #A6A6B8;
            font-size: 14px;
            font-weight: bold;
        """)
        self.host_value.setStyleSheet("""
            color: white;
            font-size: 28px;
            font-weight: bold;
        """)
        self.host_layout.addWidget(self.host_title)
        self.host_layout.addWidget(self.host_value)

        self.data_layout = QVBoxLayout()
        self.data_card.setLayout(self.data_layout)
        self.data_title = QLabel("Total data")
        self.data_value = QLabel("0 B")
        self.data_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.data_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.data_title.setStyleSheet("""
            color: #A6A6B8;
            font-size: 14px;
            font-weight: bold;
        """)
        self.data_value.setStyleSheet("""
            color: white;
            font-size: 28px;
            font-weight: bold;
        """)
        self.data_layout.addWidget(self.data_title)
        self.data_layout.addWidget(self.data_value)

        self.top_layout = QVBoxLayout()
        self.top_card.setLayout(self.top_layout)
        self.top_title = QLabel("Top Talker")
        self.top_value = QLabel("None")
        self.top_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.top_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.top_title.setStyleSheet("""
            color: #A6A6B8;
            font-size: 14px;
            font-weight: bold;
        """)
        self.top_value.setStyleSheet("""
            color: white;
            font-size: 28px;
            font-weight: bold;
        """)
        self.top_layout.addWidget(self.top_title)
        self.top_layout.addWidget(self.top_value)
    
        self.host_card.setObjectName("metricCard")
        self.top_card.setObjectName("metricCard")
        self.data_card.setObjectName("metricCard")
    
        self.tt_section.setStyleSheet("""
            QWidget#metricCard {
            background-color: #1E1E2F;
            border-radius: 10px;
            padding: 10px;
            }
        """)
        self.tt_layout.addWidget(self.host_card)
        self.tt_layout.addWidget(self.data_card)
        self.tt_layout.addWidget(self.top_card)

        self.top_talkers_page_layout.addWidget(self.tt_section)
        self.top_talker_graph = QWidget()
        self.top_talker_graph_layout = QVBoxLayout()
        self.top_talker_graph.setLayout(self.top_talker_graph_layout)

        self.top_ip = ["IP1","IP2","IP3","IP4","IP5","IP6","IP7","IP8","IP9","IP10"]
        self.data_values = [0, 0, 0, 0, 0, 0, 0, 0, 0 , 0]
        self.top_graph = pg.PlotWidget()
        self.top_graph.setTitle("Top Talkers")
        self.top_bar = pg.BarGraphItem(
            x = [value / 2 for value in self.data_values],
            y = list(range(len(self.top_ip))),
            width = self.data_values,
            height = 0.4,
            brush="#4DA6FF"
        )
        self.top_graph.addItem(self.top_bar)
        self.top_value_labels = []
        for i, val in enumerate(self.top_ip):
            label = pg.TextItem(
                text = "0",
                color="#F9F9F5",
                anchor=(0, 0.5)
            )
            self.top_value_labels.append(label)
            self.top_graph.addItem(label)
            label.setPos(self.data_values[i] + 1, i)

        self.top_ip_labels = []
        for i, ip in enumerate(self.top_ip):
            label = pg.TextItem(
                text = self.top_ip[i],
                color="#F9F9F5",
                anchor=(1, 0.5)
            )
            self.top_ip_labels.append(label)
            self.top_graph.addItem(label)
            label.setPos(-2, 9-i)

        self.top_graph.hideAxis("left")
        self.top_graph.hideAxis("bottom")

        self.top_talker_graph_layout.addWidget(self.top_graph)
        self.top_talkers_page_layout.addWidget(self.top_talker_graph)

        self.connection_details = QWidget()
        self.connection_details_layout = QVBoxLayout()
        self.connection_details.setLayout(self.connection_details_layout)
        self.connection_details_title = QLabel("Active Connections")
        self.connection_details_title.setStyleSheet("""
            color: white;
            font-size: 18px;
            font-weight: bold;
        """)


        self.connection_details_layout.addWidget(
            self.connection_details_title
        )
        self.top_talkers_page_layout.addWidget(self.connection_details)
        self.connection_table = QTableWidget()

        self.connection_table.setColumnCount(5)
        self.connection_table.setHorizontalHeaderLabels([
            "Endpoint 1",
            "Endpoint 2",
            "Protocol",
            "Packets",
            "Size"
            ])

        self.top_talkers_page_layout.addWidget(self.connection_table)
        self.connection_table.setAlternatingRowColors(True)

        self.connection_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )

        self.connection_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )

        self.connection_table.setSortingEnabled(True)
        header = self.connection_table.horizontalHeader()

        header.setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.connection_table.setStyleSheet("""
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
        self.top_talker_graph.setMinimumHeight(250)
        self.top_talker_graph.setMaximumHeight(300)

        self.top_talkers_page_layout.setStretch(0, 0)
        self.top_talkers_page_layout.setStretch(1, 0)
        self.top_talkers_page_layout.setStretch(2, 1)
        self.top_talkers_page_layout.setStretch(3, 0)
        self.top_talkers_page_layout.setStretch(4, 1)
  
        self.pages.addWidget(self.top_talkers_page)




        self.logs_page = QWidget()
        self.logs_page_layout = QVBoxLayout()
        self.logs_page.setLayout(self.logs_page_layout)

        self.logs_header = QLabel("Logs")
        self.logs_header.setStyleSheet("""
            color: white;
            font-size: 28px;
            font-weight: bold;
            padding: 10px 0px 0px 5px;
        """)

        self.logs_subheader = QLabel("Network reports & system activity")
        self.logs_subheader.setStyleSheet("""
            color: #9ca3af;
            font-size: 14px;
            padding-left: 5px;
            padding-bottom: 10px;
        """)

        self.logs_page_layout.addWidget(self.logs_header)
        self.logs_page_layout.addWidget(self.logs_subheader)

        self.export_section = QWidget()
        self.export_section_layout = QVBoxLayout()
        self.export_section.setLayout(self.export_section_layout)
        self.logs_page_layout.addWidget(self.export_section)

        self.export_title = QLabel("Export Report")
        self.export_title.setStyleSheet("""
            color: white;
            font-size: 20px;
            font-weight: bold;
        """)
        self.export_section_layout.addWidget(self.export_title)

        self.export_description = QLabel(
            "Generate a report from NetScope's collected analysis"
        )
        self.export_description.setStyleSheet("""
            color: #9ca3af;
            font-size: 13px;
        """)
        self.export_section_layout.addWidget(self.export_description)
        self.export_section.setObjectName("exportSection")
        self.export_section.setStyleSheet("""
            QWidget#exportSection {
            background-color: #1E1E2F;
            border-radius: 10px;
            }   
        """)
        self.export_description.setStyleSheet("""
            color: #A6A6B8;
            font-size: 14px;
            padding-top: 2px;
            padding-bottom: 10px;
        """)
        self.export_controls_layout = QHBoxLayout()
        self.export_section_layout.addLayout(self.export_controls_layout)

        combo_style = """
            QComboBox {
                background-color: #2B2B3C;
                color: white;
                border: 1px solid #3A3A4F;
                border-radius: 6px;
                padding: 8px 12px;
                min-width: 150px;
            }

            QComboBox:hover {
                border: 1px solid #4DA6FF;
            }

            QComboBox::drop-down {
                border: none;
                width: 25px;
            }

            QComboBox QAbstractItemView {
                background-color: #2B2B3C;
                color: white;
                selection-background-color: #3A3A4F;
            }
        """     
        self.time_range_layout = QVBoxLayout()
        self.time_range_label = QLabel("Time Range")
        self.time_range_label.setStyleSheet("""
            color: #9ca3af;
            font-size: 13px;
        """)

        self.time_range_layout.addWidget(
            self.time_range_label
        )
        self.time_range_combo = QComboBox()
        self.time_range_combo.addItems([
            "Last 5 Minutes",
            "Last 30 Minutes",
            "Last 1 Hour",
            "Last 2 Hours"
        ])

        self.time_range_layout.addWidget(
            self.time_range_combo
        )
        self.export_controls_layout.addLayout(
            self.time_range_layout
        )


        self.format_layout = QVBoxLayout()
        self.format_label = QLabel("Format")
        self.format_label.setStyleSheet("""
            color: #9ca3af;
            font-size: 13px;
        """)

        self.format_layout.addWidget(
            self.format_label
        )
        self.format_combo = QComboBox()
        self.format_combo.addItems([
            "PDF",
            "CSV",
            "JSON"
        ])

        self.format_layout.addWidget(
            self.format_combo
        )

        self.export_controls_layout.addLayout(
            self.format_layout
        )
        self.time_range_combo.setStyleSheet(combo_style)
        self.format_combo.setStyleSheet(combo_style)

        self.export_controls_layout.addStretch()

        self.generate_report_button = QPushButton(
            "Generate Report"
        )

        self.generate_report_button.setStyleSheet("""
            QPushButton {
                background-color: #4DA6FF;
                color: white;
                border: none;
                border-radius: 7px;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
            }

            QPushButton:hover {
                background-color: #3B8FE6;
            }

            QPushButton:pressed {
                background-color: #2878CC;
            }
        """)

        self.export_controls_layout.addWidget(
            self.generate_report_button
        )

        self.generate_report_button.clicked.connect(
            self.generate_report
        )

        self.recent_exports_section = QWidget()
        self.recent_exports_layout = QVBoxLayout()
        self.recent_exports_section.setLayout(
            self.recent_exports_layout
        )

        self.logs_page_layout.addWidget(
            self.recent_exports_section
        )
        self.recent_exports_title = QLabel("Recent Exports")
        self.recent_exports_title.setStyleSheet("""
            color: white;
            font-size: 20px;
            font-weight: bold;
        """)
        self.recent_exports_layout.addWidget(
            self.recent_exports_title
        )

        self.recent_exports_section.setObjectName("recentExportsSection")

        self.recent_exports_section.setStyleSheet("""
            QWidget#recentExportsSection {
                background-color: #1E1E2F;
                border-radius: 10px;
            }
        """)

        self.recent_exports_title.setStyleSheet("""
            color: white;
            font-size: 20px;
            font-weight: bold;
            padding-bottom: 5px;
        """)

        self.recent_reports_container = QWidget()
        self.recent_reports_layout = QVBoxLayout()
        self.recent_reports_container.setLayout(
            self.recent_reports_layout
        )

        self.recent_exports_layout.addWidget(
            self.recent_reports_container
        )


        self.logs_page_layout.setContentsMargins(
            10, 10, 10, 10
        )

        self.logs_page_layout.setSpacing(12)
        self.export_controls_layout.setSpacing(15)
        self.recent_exports_layout.addStretch()
        self.update_recent_reports()


        self.clear_reports = QPushButton(
            "Clear All"
        )
        
        self.clear_reports.setStyleSheet("""
            QPushButton {
                background-color: #4DA6FF;
                color: white;
                border: none;
                border-radius: 7px;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
            }

            QPushButton:hover {
                background-color: #3B8FE6;
            }

            QPushButton:pressed {
                background-color: #2878CC;
            }
        """)
        self.recent_exports_layout.addWidget(self.clear_reports)

        self.clear_reports.clicked.connect(
            self.clear_all_reports
        )
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

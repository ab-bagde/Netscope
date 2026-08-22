from datetime import datetime
from core.bandwidth_monitor import bandwidth
from core.threat_detector import threat_records
from core.top_talkers import top_talkers
from core.connection_tracker import connections
from core.packet_statistics import stats
from reportlab.platypus import SimpleDocTemplate
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib import colors


import json
import os
import csv

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

def generate_json_report(report_data, file_path):
    with open(file_path, "w") as file:
        json.dump(
            report_data,
            file,
            indent=4
        )

    return file_path


def generate_csv_report(report_data, file_path):
    # report_folder = os.path.join(
    #     os.path.dirname(__file__),
    #     "generated"
    # )
    # os.makedirs(report_folder, exist_ok=True)
    # file_path = os.path.join(
    #     report_folder,
    #     filename
    # )

    with open(file_path, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([
            "Section",
            "Metric",
            "Value"
        ])

        for key, value in report_data["report_info"].items():
            writer.writerow([
                "Report Information",
                key,
                value
            ])
    
        for key, value in report_data["packet_statistics"].items():
            writer.writerow([
                "Packet Statistics Information",
                key,
                value
            ])
    
        for key, value in report_data["bandwidth"].items():
            writer.writerow([
                "Bandwidth Information",
                key,
                value
            ])
    
        for key, value in report_data["top_talkers"].items():
            writer.writerow([
                "Top Talkers Information",
                key,
                value
            ])
    
        writer.writerow([])
        writer.writerow([
            "Threats",
            "Type",
            "Source IP",
            "Destination IP",
            "Severity",
            "Description",
            "Timestamp"
        ])
    
        for threat in report_data["threats"]:
            writer.writerow([
                "Threat",
                threat["type"],
                threat["source_ip"],
                threat["destination_ip"],
                threat["severity"],
                threat["description"],
                threat["timestamp"]
            ])
    
    
        writer.writerow([])
        writer.writerow([
            "Connections",
            "Endpoint 1",
            "Endpoint 2",
            "Protocol",
            "Packets",
            "Data"
        ])
    
        for connection in report_data["connections"]:
            writer.writerow([
                "Connection",
                connection["endpoint1"],
                connection["endpoint2"],
                connection["protocol"],
                connection["packets"],
                connection["data"]
            ])

    return file_path

def generate_pdf_report(report_data, file_path):
    # report_folder = os.path.join(
    # os.path.dirname(__file__),
    # "generated"
    # )

    # os.makedirs(report_folder, exist_ok=True)
    # file_path = os.path.join(
    #     report_folder,
    #     filename
    # )

    doc = SimpleDocTemplate(
        file_path
    )
    elements = []

    title_style = ParagraphStyle(
        "Title",
        fontSize=24,
        leading=28,
        alignment=TA_CENTER,
        textColor=colors.black
    )
    
    title = Paragraph(
        "NetScope",
        title_style
    )
    
    elements.append(title)
    
    subtitle_style = ParagraphStyle(
        "Subtitle",
        fontSize=14,
        leading=18,
        alignment=TA_CENTER,
        textColor=colors.grey
    )

    heading_style = ParagraphStyle(
        "Heading",
        fontSize=16,
        leading=20,
        spaceBefore=10,
        spaceAfter=8,
        textColor=colors.black
    )
    
    subtitle = Paragraph(
        "Network Analysis Report",
        subtitle_style
    )

    table_style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2B2B3C")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ])
    
    elements.append(subtitle)

    elements.append(
            Spacer(1, 15)
    )

    report_info = report_data["report_info"]

    report_info_data = [
        ["Generated At", report_info["generated_at"]],
        ["Time Range", report_info["time_range"]],
        ["Capture Duration", f"{report_info['capture_duration']} sec"],
        ["Selected Duration", f"{report_info['selected_duration']} sec"],
        ["Report Start", f"{report_info['report_start']} sec"],
        ["Report End", f"{report_info['report_end']} sec"]
    ]

    elements.append(
        Paragraph("Report Information", heading_style)
    )

    report_info_table = Table(report_info_data)
    report_info_table.setStyle(table_style)
    elements.append(report_info_table)

    elements.append(
        Spacer(1, 15)
    )

    packet_stats_data = [
        ["Metric", "Count"]
    ]

    for key, value in report_data["packet_statistics"].items():
        packet_stats_data.append([
            key,
            value
        ])

    elements.append(
        Paragraph("Packet Statistics", heading_style)
    )

    packet_info_table = Table(packet_stats_data)
    packet_info_table.setStyle(table_style)
    elements.append(packet_info_table)

    elements.append(
            Spacer(1, 15)
    )
    
    bandwidth_data = [
            ["Metric", "Count"]
    ]
    
    for key, value in report_data["bandwidth"].items():
        bandwidth_data.append([
            key,
            value
        ])

    elements.append(
        Paragraph("Bandwidth Information", heading_style)
    )

    band_info_table = Table(bandwidth_data)
    band_info_table.setStyle(table_style)
    elements.append(band_info_table)

    elements.append(
        Spacer(1, 15)
    )


    top_data = [
                ["Metric", "Count"]
    ]
        
    for key, value in report_data["top_talkers"].items():
        top_data.append([
            key,
            value
        ])

    elements.append(
        Paragraph("Top Talkers Information", heading_style)
    )

    top_info_table = Table(top_data)
    top_info_table.setStyle(table_style)
    elements.append(top_info_table)

    elements.append(
        Spacer(1, 15)
    )

    threat_data = [
        [ "Threats","Type","Source IP","Destination IP","Severity","Description","Timestamp"]
    ]

    for threat in report_data["threats"]:
        threat_data.append([
            "Threat",
            threat["type"],
            threat["source_ip"],
            threat["destination_ip"],
            threat["severity"],
            threat["description"],
            threat["timestamp"]
        ])

    
    elements.append(
        Paragraph("Threats Information", heading_style)
    )

    threat_info_table = Table(threat_data, colWidths=[45,70,75,75,55,150,85])
    threat_info_table.setStyle(table_style)
    elements.append(threat_info_table)

    elements.append(
        Spacer(1, 15)
    )

    connections_data = [
        [ "Connections", "Endpoint 1","Endpoint 2","Protocol","Packets","Data"]
    ]

    for connection in report_data["connections"]:
        connections_data.append([
            "Connection",
            connection["endpoint1"],
            connection["endpoint2"],
            connection["protocol"],
            connection["packets"],
            connection["data"]
        ])

    elements.append(
            Paragraph("Connections Information", heading_style)
        )
    
    connect_info_table = Table(connections_data, colWidths=[55,110,110,55,50,60])
    connect_info_table.setStyle(table_style)
    elements.append(connect_info_table)

    doc.build(elements)
    return file_path

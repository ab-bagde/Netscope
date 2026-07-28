# NetScope

### A Modular Network Monitoring & Intrusion Detection System (IDS)

**Author:** Bagde Abhay Dipakkumar

---

## Overview

NetScope is a modular Network Monitoring and Intrusion Detection System (IDS) built using Python and Scapy. It captures live network traffic, analyzes packets in real time, monitors network activity, tracks active connections, identifies high bandwidth consumers, logs packet information, and detects common network threats through rule-based analysis.

The project is designed with a modular architecture where each component performs a single responsibility, making the system maintainable, scalable, and easy to extend with future security capabilities.

---

## Features

### Live Network Monitoring

- Live packet capture using Scapy
- IPv4 packet parsing
- TCP and UDP packet analysis
- Protocol identification
- Service identification using well-known ports
- Incoming and outgoing traffic detection

### Network Analytics

- Real-time packet statistics
- Active connection tracking
- Upload and download bandwidth monitoring
- Live network speed calculation
- Top Talkers analysis

### Threat Detection

- High Packet Rate Detection
- Upload Traffic Spike Detection
- Download Traffic Spike Detection
- TCP Port Scan Detection
- TCP SYN Flood Detection
- ICMP Flood Detection

### Logging

- Packet logging to CSV
- Timestamped packet records
- Source and destination IP logging
- Protocol and packet size logging
- Traffic direction logging

---

## Project Architecture

```text
Live Packet Capture
        │
        ▼
Packet Parser
        │
        ▼
Direction Detector
        │
        ▼
Packet Filter
        │
        ▼
 ┌──────────────────────────────────────────────┐
 │                                              │
 │  Packet Statistics                           │
 │  Connection Tracker                          │
 │  Bandwidth Monitor                           │
 │  Top Talkers                                 │
 │  Threat Detector                             │
 │  Packet Logger                               │
 │                                              │
 └──────────────────────────────────────────────┘
        │
        ▼
Live Monitoring Dashboard
```

---

## Technologies Used

- Python
- Scapy
- CSV Module
- Socket Programming
- Computer Networking Fundamentals

---

## Threat Detection Techniques

NetScope currently implements rule-based detection mechanisms for:

- High Packet Rate
- Upload Bandwidth Spike
- Download Bandwidth Spike
- TCP Port Scan
- TCP SYN Flood
- ICMP Flood

---

## Project Structure

```text
NetScope/
│
├── main.py
├── packet_capture.py
├── packet_parser.py
├── packet_filter.py
├── direction_detector.py
├── packet_statistics.py
├── connection_tracker.py
├── bandwidth_monitor.py
├── top_talkers.py
├── threat_detector.py
├── packet_logger.py
├── dashboard.py
├── utils.py
├── requirements.txt
└── README.md
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/ab-bagde/NetScope.git
cd NetScope
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the project:

```bash
python main.py
```

---

## Current Capabilities

- Live packet capture
- Modular packet processing pipeline
- Real-time traffic monitoring
- Network bandwidth analysis
- Active connection monitoring
- Top Talkers identification
- Rule-based intrusion detection
- Packet logging

---

## Future Enhancements

- Time-window based threat detection
- Professional GUI Dashboard
- Configuration file support
- Alert logging
- DNS anomaly detection
- ARP spoofing detection
- Threat intelligence integration
- Interactive traffic visualization

---

## Learning Outcomes

Through this project, I strengthened my understanding of:

- TCP/IP Networking
- Packet Capture and Analysis
- Intrusion Detection Systems (IDS)
- Network Traffic Monitoring
- Rule-Based Threat Detection
- Modular Software Design
- Python Programming
- Scapy Framework

---

## License

This project is intended for educational and research purposes.

---

**Developed with dedication by Bagde Abhay Dipakkumar**

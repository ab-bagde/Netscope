# NetScope

### A Modular Network Monitoring & Intrusion Detection System (IDS)

**Author:** Bagde Abhay Dipakkumar

---

# Overview

NetScope is a modular Network Monitoring and Intrusion Detection System (IDS) built using Python and Scapy. It captures live network traffic, analyzes packets in real time, monitors network activity, tracks active connections, identifies high bandwidth consumers, logs packet information, and detects common network threats through rule-based analysis.

The project follows a modular architecture where each component performs a single responsibility, making the system maintainable, scalable, and easy to extend with future security capabilities.

---

# Features

## Live Network Monitoring

- Live packet capture using Scapy
- IPv4 packet parsing
- TCP and UDP packet analysis
- Protocol identification
- Service identification using well-known ports
- Incoming and outgoing traffic detection

---

## Network Analytics

- Real-time packet statistics
- Active connection tracking
- Upload and download bandwidth monitoring
- Live upload/download speed calculation
- Packets Per Second (PPS) monitoring
- Top Talkers analysis

---

## Threat Detection

- High Packet Rate Detection (Packets Per Second)
- Upload Traffic Spike Detection
- Download Traffic Spike Detection
- TCP Port Scan Detection
- TCP SYN Flood Detection
- ICMP Flood Detection
- Sliding Time Window based detection
- Configurable detection thresholds
- Real-time threat monitoring

---

## Logging

### Packet Logger

- Packet logging to CSV
- Timestamped packet records
- Source IP logging
- Destination IP logging
- Protocol logging
- Packet size logging
- Traffic direction logging

### Alert Logger

- Threat event logging
- Timestamped alerts
- Source & Destination IP logging
- Threat details logging
- Alert lifecycle tracking
- Threat Started / Ended logging

---

# Project Architecture

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
 ┌────────────────────────────────────────────────────────────┐
 │                                                            │
 │  Packet Statistics                                         │
 │  Connection Tracker                                        │
 │  Bandwidth Monitor                                         │
 │  Top Talkers                                               │
 │  Threat Detector                                           │
 │  Packet Logger                                             │
 │  Alert Logger                                              │
 │                                                            │
 └────────────────────────────────────────────────────────────┘
                              │
                              ▼
                 Live Monitoring Dashboard
```

---

# Technologies Used

- Python
- Scapy
- CSV Module
- Socket Programming
- Computer Networking Fundamentals

---

# Threat Detection Techniques

NetScope currently implements **rule-based intrusion detection** using configurable thresholds and sliding time-window analysis.

Current detections include:

- High Packet Rate Detection (Packets Per Second)
- Upload Bandwidth Spike Detection
- Download Bandwidth Spike Detection
- TCP Port Scan Detection (Unique destination ports within a configurable time window)
- TCP SYN Flood Detection (Large number of SYN packets within a configurable time window)
- ICMP Flood Detection (Large number of ICMP packets within a configurable time window)

Detection parameters are centralized inside the `THRESHOLDS` dictionary, making the IDS easy to tune for different network environments.

---

# Project Structure

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
├── alert_logger.py
├── dashboard.py
├── utils.py
├── requirements.txt
└── README.md
```

---

# Installation

Clone the repository

```bash
git clone https://github.com/ab-bagde/NetScope.git
cd NetScope
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run NetScope

```bash
python main.py
```

---

# Current Capabilities

- Live packet capture
- Modular packet processing pipeline
- Real-time packet parsing
- Real-time traffic monitoring
- Active connection monitoring
- Network bandwidth analysis
- Upload & download speed calculation
- Packets Per Second (PPS) monitoring
- Top Talkers identification
- Rule-based intrusion detection
- Sliding time-window based threat detection
- Configurable detection thresholds
- Packet logging
- Alert logging with threat start/end events

---

# Future Enhancements

- Professional GUI Dashboard
- Configuration file support (JSON/YAML)
- DNS anomaly detection
- ARP Spoofing Detection
- DHCP Starvation Detection
- MAC Spoofing Detection
- Threat Intelligence Integration
- Interactive Traffic Visualization
- Machine Learning based Anomaly Detection
- Email/Desktop Alert Notifications
- Automatic IP Blocking
- Firewall Integration

---

# Learning Outcomes

Through this project, I strengthened my understanding of:

- TCP/IP Networking
- Packet Capture and Analysis
- Intrusion Detection Systems (IDS)
- Network Traffic Monitoring
- Rule-Based Threat Detection
- Sliding Window Algorithms
- Real-time Event Logging
- Bandwidth Analysis
- Python Programming
- Scapy Framework
- Modular Software Design

---

# License

This project is intended for educational and research purposes.

---

## Developed with dedication by Bagde Abhay Dipakkumar

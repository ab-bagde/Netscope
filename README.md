# NetScope

# Modular Network Monitoring & Intrusion Detection System (IDS)

**Author:** Bagde Abhay Dipakkumar

---

# Overview

NetScope is a modular **Network Monitoring & Intrusion Detection System (IDS)** developed using **Python** and **Scapy**. It captures live network traffic, analyzes packets in real time, monitors bandwidth usage, tracks active network connections, identifies top network communicators, logs packet activity, and detects suspicious behavior using rule-based intrusion detection techniques.

The project follows a modular architecture where every component performs a dedicated responsibility, making the system scalable, maintainable, and easy to extend with future security features.

---

# Features

## Live Network Monitoring

- Live packet capture using Scapy
- IPv4 packet parsing
- TCP, UDP, ICMP, ARP and DHCP packet inspection
- DNS query extraction and analysis
- Protocol identification
- Service identification using well-known ports
- Incoming & outgoing traffic detection
- Real-time packet processing pipeline

---

## Network Analytics

- Real-time packet statistics
- Active connection tracking
- Upload & download bandwidth monitoring
- Live upload/download speed calculation
- Packet Rate (Packets Per Second)
- Top Talkers identification
- Protocol-wise traffic analysis
- Packet size monitoring

---

## Threat Detection

NetScope currently detects:

- High Packet Rate (PPS)
- Upload Traffic Spike
- Download Traffic Spike
- TCP Port Scan
- TCP SYN Flood
- ICMP Flood
- DNS Flood
- Suspicious Long DNS Queries
- High Unique DNS Query Activity
- ARP Spoofing
- DHCP Starvation
- Malicious IP Reputation Detection

All detections are configurable using centralized threshold values and sliding time-window analysis.

---

## Logging

### Packet Logger

- CSV-based packet logging
- Timestamp
- Source & Destination IP
- Protocol
- Service
- Packet Size
- Traffic Direction
- DNS Query (when available)

### Alert Logger

- Threat logging
- Timestamped events
- Source & Destination
- Threat details
- Alert lifecycle
- Started / Ended / Detected events

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
 ┌──────────────────────────────────────────────────────┐
 │                                                      │
 │ Packet Statistics                                    │
 │ Connection Tracker                                   │
 │ Bandwidth Monitor                                    │
 │ Top Talkers                                          │
 │ Threat Detector                                      │
 │ Packet Logger                                        │
 │ Alert Logger                                         │
 │ Malicious IP Reputation                              │
 │                                                      │
 └──────────────────────────────────────────────────────┘
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
- Computer Networking
- Git & GitHub

---

# Threat Detection Methodology

NetScope implements a **rule-based IDS** using packet inspection, malicious IP intelligence, configurable thresholds, and sliding time-window algorithms.

Current threat detection techniques include:

- Packet Rate Monitoring
- Bandwidth Spike Detection
- Port Scan Detection
- SYN Flood Detection
- ICMP Flood Detection
- DNS Flood Detection
- Long DNS Query Detection
- High Unique DNS Query Detection
- ARP Spoofing Detection
- DHCP Starvation Detection
- Malicious IP Reputation Detection

Detection parameters are centralized inside the `THRESHOLDS` dictionary, allowing quick tuning for different network environments.

The malicious IP reputation engine loads a local threat intelligence database and flags communication originating from known malicious IP addresses.

---

# Project Structure

```text
NetScope/
│
├── main.py
├── README.md
├── requirements.txt
├── .gitignore
│
├── core/
│   ├── alert_logger.py
│   ├── analyze_packet.py
│   ├── bandwidth_monitor.py
│   ├── connection_tracker.py
│   ├── direction_detector.py
│   ├── malicious_ip_loader.py
│   ├── packet_capture.py
│   ├── packet_filter.py
│   ├── packet_logger.py
│   ├── packet_parser.py
│   ├── packet_statistics.py
│   ├── threat_detector.py
│   ├── top_talkers.py
│   └── utils.py
│
├── gui/
│   └── dashboard.py
│
├── database/
│   └── Malicious_IP_Database.txt
│
└── logs/
    ├── packet_logs.csv
    └── alerts.csv
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
- Real-time packet parsing
- TCP, UDP, ICMP, ARP & DHCP inspection
- DNS query analysis
- Active connection tracking
- Upload & download bandwidth monitoring
- Packet Rate (PPS) monitoring
- Top Talkers analysis
- Rule-based intrusion detection
- Sliding time-window threat detection
- Malicious IP reputation checking
- Packet logging
- Threat event logging
- Modular architecture

---

# Future Enhancements

- Professional GUI
- Configuration File Support (JSON/YAML)
- Threat Intelligence APIs (AbuseIPDB, AlienVault OTX, VirusTotal)
- Geo-IP Mapping
- Interactive Network Topology
- Machine Learning Based Anomaly Detection
- Windows Background Service
- Email/Desktop Notifications
- Automatic IP Blocking
- Firewall Integration
- Web-based Dashboard
- SIEM Integration

---

# Learning Outcomes

Through this project, I strengthened my understanding of:

- Computer Networking
- TCP/IP Protocol Suite
- Packet Capture & Analysis
- Network Monitoring
- Intrusion Detection Systems (IDS)
- Threat Intelligence
- Sliding Window Algorithms
- Bandwidth Analysis
- Event Logging
- Python Programming
- Scapy Framework
- Modular Software Design
- Network Security Concepts

---

# License

This project is intended for educational and research purposes.

---

## Developed by

**Bagde Abhay Dipakkumar**

# Network Traffic Analysis and Anomaly Detection System

### Created by Maxine Jones  
Graduate Software Engineering Final Project | Chicago State University  
Advisor: Dr. Salam

---

## Project Description

This Python-based system captures and analyzes live network traffic to detect anomalies such as:

- TCP SYN Flood Attacks  
- Oversized UDP Packets (potential DoS)  
- ICMP Ping Sweeps

It uses Scapy and Npcap for packet sniffing, and logs events in a SQLite database. The project includes attack simulation scripts to validate detection and provides a query interface for log review.

---

## Features

- Real-time packet capture and classification (TCP, UDP, ICMP)
- Alert generation for suspicious activity
- Packet and alert logging in SQLite (`network_logs.db`)
- Query viewer for searching, filtering, and exporting logs
- Built-in attack simulation (SYN flood, UDP flood, Ping sweep)
- Memory usage monitoring with `psutil`

---

## Project Structure

Cptr 4950/
├── capstone.py # Main sniffer and analyzer
├── syn_flood.py # TCP SYN flood attack simulator
├── oversized_udp.py # UDP attack simulator
├── ping_sweep.py # ICMP ping sweep simulator
├── query_viewer.py # Menu-based log viewer + CSV export
├── logs.py # Log diagnostics helper
├── network_logs.db # SQLite3 database (auto-created)
└── README.md

yaml
Copy
Edit

---

## Setup Instructions

1. Install Python 3.8 or higher  
2. Install required Python packages:
   ```bash
   pip install scapy psutil
Install Npcap for Windows users if not already installed

How to Run
Run the main detection system:

bash
Copy
Edit
python capstone.py
This will:

Start sniffing packets

Launch attack simulations

Record all relevant logs to the database

View and export logs using:

bash
Copy
Edit
python query_viewer.py
Query Viewer Features
View recent alerts or packets

Filter logs by protocol/type, keyword, or timestamp

Export alerts and packets to CSV files

Auto-open CSV files after export (on Windows)

Sample Alert Types Logged
SYN_FLOOD: Unusual volume of SYN packets

UDP_ATTACK: Oversized UDP packets detected

ICMP_SWEEP: ICMP Echo requests from ping sweeps

Final Status
Completed all functional requirements

Database logging and query system integrated

Attack detection confirmed through simulated tests

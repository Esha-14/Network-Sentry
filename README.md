# NetworkSentry

## Network Sniffer & Packet Analyzer

NetworkSentry is a Python-based network packet capture and analysis
tool developed for educational and authorized laboratory environments.

## Features

- Captures network packets
- Identifies IPv4 packets
- Detects TCP, UDP and ICMP protocols
- Extracts source and destination IP addresses
- Extracts TCP and UDP port numbers
- Records packet timestamps and lengths
- Saves raw packets in PCAP format
- Generates CSV metadata reports
- Supports verification using Wireshark

## Technologies

- Python
- Scapy
- Npcap
- Wireshark
- Visual Studio Code

## Project Structure

NetworkSentry/
   src/
     main.py
     config.py
     capture.py
     analyzer.py
     reporter.py
   captures/
   reports/
   requirements.txt

## Installation

Install dependencies:

    python -m pip install -r requirements.txt

Windows users should install Npcap before capturing packets.

## Running the Application

Run the application from the project root:

    python src/main.py

Administrator privileges may be required.

## Output

The application generates:

- PCAP files in the captures folder
- CSV reports in the reports folder

The PCAP file can be opened in Wireshark for detailed packet inspection.

## Ethical Use

This project should only be used on networks and systems where
authorization has been obtained.

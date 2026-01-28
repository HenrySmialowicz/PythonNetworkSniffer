# PythonNetworkSniffer

A low-level network analysis tool built with Python to intercept and decode IPv4 packets. Project includes the TCP/IP stack, raw sockets, and binary data parsing.

Features
Packet Interception: Utilizes SOCK_RAW to capture traffic at the network layer, bypassing the standard application-layer stack.

IP Header Parsing: Manually unpacks the 20-byte IPv4 header to extract TTL, Protocol IDs, and Source/Destination addresses.

ASCII Data Dump: Includes a data-viewing mode to inspect the payload of ICMP and TCP packets in a human-readable format.

Usage
Note: Raw sockets require administrative privileges. Run as Root (Linux/macOS) or Administrator (Windows).

Bash

# Sniff ICMP traffic on a specific interface

sudo python3 sniffer.py --ip 192.168.1.XX --proto icmp --data

# Sniff TCP traffic

sudo python3 sniffer.py --ip 192.168.1.XX --proto tcp

Technical Implementation
struct.unpack: Used to translate raw binary wire-data into Python variables using Network Byte Order (!).

ipaddress: Leveraged for robust IP object handling and validation.

Disclaimer
This tool is for educational purposes only. It was developed to explore network protocol structures and should only be used on networks where you have explicit permission to monitor traffic.

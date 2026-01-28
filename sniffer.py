#!/usr/bin/env python3

import ipaddress
import socket
import struct
import sys
import argparse
import os

parser = argparse.ArgumentParser(description='Network packet sniffer')
parser.add_argument('--ip', help='IP address to sniff on', required=True)
parser.add_argument(
    '--proto', help='Protocol to sniff (TCP/ICMP)', required=True)
parser.add_argument('--data', help='Display Data', action='store_true')
opts = parser.parse_args()


class Packet:
    def __init__(self, data):
        self.packet = data
        header = struct.unpack('!BBHHHBBH4s4s', self.packet[0:20])
        self.ver = header[0] >> 4  # Version - First 4 bits
        self.ihl = header[0] & 0xF  # Header Length - Next 4 bits
        self.tos = header[1]  # Type of Service
        self.len = header[2]  # Packet Length
        self.id = header[3]  # Fragment ID
        self.off = header[4]  # Fragment Identifier
        self.ttl = header[5]  # Time to Live
        self.pro = header[6]  # Protocol Num
        self.num = header[7]  # Header Check Sum
        self.src = header[8]  # Source IP
        self.dst = header[9]  # Destination IP

        # Takes in raw address strings and converts to IPv6 or IPv4 Address Objects
        self.src_addr = ipaddress.ip_address(self.src)
        self.dst_addr = ipaddress.ip_address(self.dst)

        # Creates a map to label protocols
        self.protocol_map = {1: "ICMP", 6: "TCP"}

        # Error Handling for new protocols
        try:
            self.protocol = self.protocol_map[self.pro]
        except Exception as e:
            print(f'{e} No protocol for {self.pro}')
            self.protocol = str(self.pro)

    def print_header_short(self):
        print(
            f'Protocol: {self.protocol} {self.src_addr} -> {self.dst_addr}')

    def print_data(self):
        data = self.packet[20:]
        print('*'*10 + 'ASCII START' + '*'*10)
        for b in data:
            if b < 128:
                print(chr(b), end='')
            else:
                print('.', end='')
        print('*'*10 + 'ASCII END' + '*'*10)


def sniff(host):

    # Check Protocol
    if opts.proto == 'tcp':
        socket_protocol = socket.IPPROTO_TCP
    else:
        # Listen to ICMP
        socket_protocol = socket.IPPROTO_ICMP

    # Raw Socket allows for packet headers
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

    # Anchors sniffer to specific network
    sniffer.bind((host, 0))

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    # Self provided header
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    print(f"[*] Sniffer active on {host}. Waiting for {opts.proto.upper()}...")

    try:
        while True:
            raw_data = sniffer.recv(65535)
            packet = Packet(raw_data)
            packet.print_header_short()
            if opts.data:
                packet.print_data()
    except KeyboardInterrupt:
        sys.exit(1)


if __name__ == '__main__':
    sniff(opts.ip)

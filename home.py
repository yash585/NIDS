import os
import threading

from scapy.all import *
from collections import defaultdict
from scapy.layers.inet import TCP,IP
import time

THRESHOLD_SYN_PACKETS = 10  
SCAN_THRESHOLD = 100
MONITOR_DURATION = 60

syn_packets = defaultdict(int)
port_scan_records = defaultdict(set)

def detect_syn_flood(packet):
    """Detects SYN flood attacks based on a threshold of SYN packets."""
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':
        src_ip = packet[IP].src
        syn_packets[src_ip] += 1

        if syn_packets[src_ip] > THRESHOLD_SYN_PACKETS:
            print(f"[ALERT] Potential SYN flood attack detected from IP: {src_ip}")

def detect_port_scan(packet):
    """Detects port scanning based on the number of distinct ports accessed by a source IP."""
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        port_scan_records[src_ip].add(dst_port)

        if len(port_scan_records[src_ip]) > SCAN_THRESHOLD:
            print(f"[ALERT] Port scanning detected from IP: {src_ip}")

def packet_handler_dos(packet):
    """Processes each packet and applies IDS rules."""
    if packet.haslayer(IP):
        detect_syn_flood(packet)

def packet_handler_nmap(packet):
    """Processes each packet and applies IDS rules."""
    if packet.haslayer(IP):  # Check if the packet has an IP layer
        detect_port_scan(packet)  # Call the function to detect port scanning

def start_dos(interface='wlan0'):
    """Starts the IDS on a specified network interface."""
    print(f"Starting IDS on interface {interface}. Monitoring for SYN flood...")
    
    while True:
        sniff(iface=interface, prn=packet_handler_dos, timeout=MONITOR_DURATION)
        syn_packets.clear()

def start_nmap(interface='wlan0'):
    """Starts the IDS on a specified network interface."""
    print(f"Starting IDS on interface {interface}. Monitoring for port scans...")

    while True:
        sniff(iface=interface, prn=packet_handler_nmap, timeout=MONITOR_DURATION)
        port_scan_records.clear()

os.system('clear')

nids="""
========================================================
  ____     __   __________  ________        ______ 
|     \   |  | |___    ___|  |   __  \    /  _____|
|  |\  \  |  |     |  |      |  |  \  \  |  |_____ 
|  | \  \ |  |     |  |      |  |   |  | |______  |
|  |  \  \|  |  ___|  |___   |  |__/  /   _____|  |
|__|   \____ | |__________| _|______ /   |_______/ 

========================================================

    v1.0-cli"""

    
fn="""

 :: DOS Attack detectio
 :: PORT scanning
 :: Failed SSH login attempts
 
"""

print(nids)
print(fn)

thread1=threading.Thread(target=start_dos)
thread2=threading.Thread(target=start_nmap)

thread1.start()
thread2.start()

thread1.join()
thread2.join()
from scapy.all import *
from collections import defaultdict
from scapy.layers.inet import TCP,IP

SCAN_THRESHOLD = 100
MONITOR_DURATION = 60

port_scan_records = defaultdict(set)

def detect_port_scan(packet):
    """Detects port scanning based on the number of distinct ports accessed by a source IP."""
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        port_scan_records[src_ip].add(dst_port)

        if len(port_scan_records[src_ip]) > SCAN_THRESHOLD:
            print(f"[ALERT] Port scanning detected from IP: {src_ip}")
            wrpcap("Logs/nmap_packets.pcap",[packet], append=True)

def packet_handler_nmap(packet):
    """Processes each packet and applies IDS rules."""
    if packet.haslayer(IP):  # Check if the packet has an IP layer
        detect_port_scan(packet)  # Call the function to detect port scanning


def start_nmap(interface='wlan0'):
    """Starts the IDS on a specified network interface."""
    print(f"Starting IDS on interface {interface}. Monitoring for port scans...")

    while True:
        sniff(iface=interface, prn=packet_handler_nmap, timeout=MONITOR_DURATION)
        port_scan_records.clear()


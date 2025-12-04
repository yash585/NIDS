
from scapy.all import *
from collections import defaultdict
from scapy.layers.inet import TCP,IP

THRESHOLD_SYN_PACKETS = 10  
MONITOR_DURATION = 60

syn_packets = defaultdict(int)

def detect_syn_flood(packet):
    """Detects SYN flood attacks based on a threshold of SYN packets."""
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':
        src_ip = packet[IP].src
        syn_packets[src_ip] += 1

        if syn_packets[src_ip] > THRESHOLD_SYN_PACKETS:
            print(f"[ALERT] Potential SYN flood attack detected from IP: {src_ip}")
            wrpcap("Logs/dos_packets.pcap",[packet], append=True)

def packet_handler_dos(packet):
    """Processes each packet and applies IDS rules."""
    if packet.haslayer(IP):
        detect_syn_flood(packet)


def start_dos(interface='wlan0'):
    """Starts the IDS on a specified network interface."""
    print(f"Starting IDS on interface {interface}. Monitoring for SYN flood...")
    
    while True:
        sniff(iface=interface, prn=packet_handler_dos, timeout=MONITOR_DURATION)
        syn_packets.clear()

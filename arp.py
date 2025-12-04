from scapy.all import *
from scapy.all import sniff, ARP

# Dictionary to track IP-MAC mappings
arp_table = {}

def detect_arp_spoof(packet):
    if packet.haslayer(ARP) and packet.op == 2:  # ARP Reply
        src_ip = packet.psrc  # IP Address in ARP response
        src_mac = packet.hwsrc  # MAC Address in ARP response

        # Check if IP already exists with a different MAC address
        if src_ip in arp_table and arp_table[src_ip] != src_mac:
            print(f"[ALERT] ARP Spoofing Detected! {src_ip} is now mapping to {src_mac} (was {arp_table[src_ip]})")
            wrpcap("Logs/sql_packets.pcap",[packet], append=True)

        # Update ARP table
        arp_table[src_ip] = src_mac

def start_arp(interface="wlan0"):
    print(f"Starting IDS on interface {interface}. Monitoring for ARP Spoofing")

    while True:
        sniff(iface=interface, filter="arp", prn=detect_arp_spoof, store=0)

#!/usr/bin/env python3

from scapy.all import sniff, ARP, IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Display basic information about each packet
    if packet.haslayer(ARP):
        print(f"ARP Packet: {packet.summary()}")
    elif packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"IP Packet: {ip_layer.src} -> {ip_layer.dst}")
        
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            print(f"TCP Packet: {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")
        
        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            print(f"UDP Packet: {ip_layer.src}:{udp_layer.sport} -> {ip_layer.dst}:{udp_layer.dport}")
        
        elif packet.haslayer(ICMP):
            print(f"ICMP Packet: {ip_layer.src} -> {ip_layer.dst}")

def main():
    # Start sniffing the network traffic
    print("Starting network sniffer...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3

from scapy.all import ARP, Ether, srp
import sys

def scan(ip_range):
    # Create an ARP request packet
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send the packet and capture the response
    result = srp(packet, timeout=2, verbose=False)[0]

    # Parse the response
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    # Print the list of discovered devices
    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")
    for client in clients:
        print("{:16}    {}".format(client['ip'], client['mac']))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: sudo python3 network_scan.py <ip_range>")
        print("Example: sudo python3 network_scan.py 192.168.1.1/24")
        sys.exit(1)

    ip_range = sys.argv[1]
    scan(ip_range)

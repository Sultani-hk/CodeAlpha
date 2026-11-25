#!/usr/bin/env python3
"""
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
This is one Simple Packet Sniffer with Scapy 
A basic network packet sniffing tool with scapy by Rahmatullah 'Sultani '

>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
"""
from scapy.all import * 
import sys
from datetime import datetime 


packet_count = 0 

def packet_callback(packet):
    global packet_count 
    packet_count += 1  

    print(f"/n[Packet #{packet_count}]")
    print(f"Time: {datetime.now().strftime('%H:%M:%S.%f')[:-3]}")

    # It is For chacking if packet has the IP layer (Layer 3 )

    if packet.haslayer(IP):
        ip_src = packet[IP].src 
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        print(f"Source IP : {ip_src }")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags 

            print(f"TCP Source Port : {src_port}")
            print(f"TCP Destination Port : {dst_port} ")
            print(f"TCP Flags : {flags}")

        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            print(f"UDP Source Port: {src_port}")
            print(f"UDP Destination Port:{dst_port}")

        elif packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code

            print(f"ICMP Type : {icmp_type}")
            print(f"ICMP Type : {icmp_code}")

        print(f"Summary : {packet.summary()}")
        print("." * 60)


def sniff_all_packets(count=0):
    print ("\n [*] Start Packet capture .....")
    print ("[*] Press ctrl+c to stop Capturing \n")

    try:
        sniff(prn=packet_callback,count=count,store=False) 
    except KeyboardInterrupt:
        print(f"\n\n[*] Capture stopped by user ")
        print(f"[*] Total packets captured : {packet_count }")

def main():
    """
    Main function with menu interface 
    """

    global packet_count

    if os.getuid() != 0 : 
        print ("[!] This script required root privileges ")
        print("[!] Please run with sudo : sudo python3 NetSniffer.py")
        sys.exit(1)

    print ("=" * 60 )
    print("PYTHON PACKET SNIFFER WITH SCAPY ")
    print("Network Traffic Analysis Tool ")
    print("=" * 60 )
    print("\n[!] WARNING: Packet sniffing requires root privileges ")
    print("[!] only sniff networks you own or have permission to monitor ")

    while True: 
        packet_count = 0 

        print("\n" + "=" * 60 )
        print("Options : ")
        print("1. Sniffing Packets ")
        print("2. Exit ")
        print ("=" * 60 )

        choice = input ("\n Select option (1-2): ")

        if choice == "1":
            sniff_all_packets()
        elif choice =="2":
            print("\n [*] Exiting Packet Sniffer ")
            sys.exit(0)

        else:
            print("[!] Invalid option . Please select 1-2 . ")

if __name__ == "__main__":
    import os 

    try :
        main()
    except KeyboardInterrupt:
        print("\n\n [*] Sniffer interrupted bu user ")
        print("[*] Exiting ... ")
        sys.exit(0)
    except Exception as e :
        print(f"\n [!] Error : {e}")
        sys.exit(1)




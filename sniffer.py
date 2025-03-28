from scapy.all import sniff
from datetime import datetime

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}

#function definition to process each packet
def packet_handler(packet):
    if packet.haslayer('IP'): #IP layer? packet?
        ip_src = packet['IP'].src
        ip_dst = packet['IP'].dst
        protocol = packet['IP'].proto
        proto_name = PROTOCOLS.get(protocol, f"Unknown ({protocol})")
        timestamp = datetime.now().strftime ("%Y-%m-%d %H:%M:%S")
        if packet.haslayer('TCP'):
            port_src = packet['TCP'].sport
            port_dst = packet['TCP'].dport
            log = f"[{timestamp}] Source: {ip_src}:{port_src} -> Dest: {ip_dst}:{port_dst} | {proto_name}"
        elif packet.haslayer('UDP'):
            port_src = packet['UDP'].sport
            port_dst = packet['UDP'].dport
            log = f"[{timestamp}] Source: {ip_src}:{port_src} -> Dest: {ip_dst}:{port_dst} | {proto_name}"
        else:
            log = f"[{timestamp}] Source: {ip_src} -> Dest: {ip_dst} | {proto_name}"
        print(log)
        with open("packet_log.txt", "a") as f:
            f.write(log + "\n")
            
#sniffing starts
print("Starting packet sniffer... Press Ctrl+C to stop.")
sniff(prn=packet_handler, count=50) #for an indefinite run , its literally just to remove the count         
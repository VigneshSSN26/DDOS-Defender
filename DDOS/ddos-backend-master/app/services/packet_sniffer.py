from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw, conf
import logging

class PacketSniffer:
    def __init__(self, packet_handler):
        self.packet_handler = packet_handler
        conf.verb = 0
        
    def start(self):
        logging.info("Starting packet sniffer...")
        sniff(prn=self.packet_handler, store=0, filter="tcp or udp or icmp")
        
    def stop(self):
        # Scapy doesn't have a direct stop method, we'll handle this via threading
        pass
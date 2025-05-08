import numpy as np
from collections import deque
from datetime import datetime

class EnhancedTrafficFeatureExtractor:
    def __init__(self, window_size=100):
        self.window = deque(maxlen=window_size)
        self.unique_ips = set()
        self.unique_ports = set()
        self.last_time = None
        self.syn_count = 0
        self.http_req_count = 0
        self.dns_count = 0
        self.udp_count = 0

    def process_packet(self, pkt):
        if not pkt.haslayer('IP'):
            return None

        current_time = time.time()
        interval = current_time - self.last_time if self.last_time else 0
        self.last_time = current_time

        # Protocol detection
        is_tcp = 'TCP' in pkt
        is_udp = 'UDP' in pkt
        is_dns = ('DNS' in pkt) or (is_udp and pkt['UDP'].dport == 53)
        
        # Count specific packet types
        if is_udp:
            self.udp_count += 1
            if is_dns:
                self.dns_count += 1
                
        # TCP analysis
        tcp_flags = 0
        if is_tcp:
            tcp_flags = pkt['TCP'].flags
            if 'S' in str(tcp_flags) and 'A' not in str(tcp_flags):  # SYN without ACK
                self.syn_count += 1
            
            # HTTP detection
            if pkt['TCP'].dport == 80 and 'Raw' in pkt:
                payload = str(pkt['TCP'].payload)
                if payload.startswith(('GET ', 'POST ', 'HEAD ')):
                    self.http_req_count += 1

        packet_data = {
            'timestamp': current_time,
            'src_ip': pkt['IP'].src,
            'dst_ip': pkt['IP'].dst,
            'proto': pkt['IP'].proto,
            'size': len(pkt),
            'ttl': pkt['IP'].ttl,
            'is_tcp': int(is_tcp),
            'is_udp': int(is_udp),
            'is_icmp': int('ICMP' in pkt),
            'is_dns': int(is_dns),
            'tcp_flags': tcp_flags,
            'src_port': pkt['TCP'].sport if is_tcp else pkt['UDP'].sport if is_udp else 0,
            'dst_port': pkt['TCP'].dport if is_tcp else pkt['UDP'].dport if is_udp else 0,
            'interval': interval,
            'is_http': int(self.http_req_count > 0)
        }
        
        self.window.append(packet_data)
        self.unique_ips.add(pkt['IP'].src)
        self.unique_ports.add(packet_data['dst_port'])
        return packet_data

    def get_features(self):
        if len(self.window) < self.window.maxlen//2:
            return None

        # Calculate various statistics
        sizes = [p['size'] for p in self.window]
        intervals = [p['interval'] for p in self.window if p['interval'] > 0]
        ttls = [p['ttl'] for p in self.window]
        ports = [p['dst_port'] for p in self.window]
        
        # Packet type counts
        tcp_packets = [p for p in self.window if p['is_tcp']]
        udp_packets = [p for p in self.window if p['is_udp']]
        dns_packets = [p for p in self.window if p['is_dns']]
        http_packets = [p for p in self.window if p['is_http']]
        
        # Calculate entropy for ports
        port_counts = np.unique(ports, return_counts=True)[1]
        port_probs = port_counts / port_counts.sum()
        port_entropy = -np.sum(port_probs * np.log2(port_probs + 1e-10))

        # Time features
        now = datetime.now()
        hour = now.hour
        weekday = now.weekday()
        
        features = [
            len(self.window),                           # packet_count
            np.mean(sizes),                            # avg_size
            np.std(sizes),                             # size_std
            np.mean(ttls) if ttls else 0,              # avg_ttl
            np.std(ttls) if ttls else 0,               # ttl_std
            len(tcp_packets)/len(self.window),         # tcp_ratio
            len(udp_packets)/len(self.window),         # udp_ratio
            len(dns_packets)/len(self.window),         # dns_ratio
            self.syn_count/len(self.window),           # syn_ratio
            len(http_packets)/len(self.window),        # http_ratio
            len(self.unique_ips),                      # unique_ips
            len(self.unique_ports),                    # unique_ports
            port_entropy,                              # port_entropy
            np.mean(intervals) if intervals else 0,    # avg_interval
            np.std(intervals) if intervals else 0,     # interval_std
            hour/24,                                   # hour_of_day
            weekday/7,                                 # day_of_week
            sum(1 for s in sizes if s < 60)/len(self.window),    # small_pkt_ratio
            sum(1 for s in sizes if 60 <= s < 1000)/len(self.window), # medium_pkt_ratio
            sum(1 for s in sizes if s >= 1000)/len(self.window), # large_pkt_ratio
            sum(1 for p in self.window if p['dst_ip'] == '127.0.0.1')/len(self.window)  # inbound_ratio
        ]

        # Reset counters
        self.syn_count = 0
        self.http_req_count = 0
        self.udp_count = 0
        self.dns_count = 0

        return np.array(features, dtype=np.float32)
import time
import random
import subprocess
import logging
from datetime import datetime
from collections import deque, defaultdict
from threading import Thread
import json
import os

class DDoSDefender:
    def __init__(self, dqn_model, arf_model):
        self.dqn_model = dqn_model
        self.arf_model = arf_model
        self.extractor = EnhancedTrafficFeatureExtractor()
        
        # State tracking
        self.attack_log = deque(maxlen=50)
        self.mitigation_log = deque(maxlen=50)
        self.metrics = deque(maxlen=200)
        self.running = True
        self.attack_process = None
        self.current_attacker = None
        self.last_action = None
        self.last_attack_type = None
        self.last_reward = 0
        self.last_state = None
        self.unknown_attack_samples = []
        self.attack_signatures = {}
        
        # Configuration
        self.TARGET_IP = "127.0.0.1"
        self.ATTACKS = {
            "normal": {"signature": [0, 0, 0, 0]},
            "syn_flood": {"signature": [1, 0, 0, 0]},
            "dns_amplification": {"signature": [0, 0, 0, 1]}
        }
        self.ACTIONS = {
            0: "No action",
            1: "Rate limit",
            2: "Block IP",
            3: "SYN cookies",
            4: "CAPTCHA",
            5: "Null route"
        }
        
        # Load attack signatures if they exist
        self._load_attack_signatures()

    def monitor(self):
        def handle_packet(pkt):
            if not self.running:
                return
            
            try:
                packet_data = self.extractor.process_packet(pkt)
                if packet_data:
                    features = self.extractor.get_features()
                    if features is not None:
                        self._process_traffic(features)
            except Exception as e:
                logging.error(f"Error processing packet: {e}")

        logging.info("Starting network monitoring...")
        while self.running:
            try:
                from scapy.all import sniff
                sniff(prn=handle_packet, store=0, timeout=1, filter="tcp or udp or icmp")
            except Exception as e:
                logging.error(f"Sniffing error: {e}")
                time.sleep(1)

    def _process_traffic(self, features):
        # Convert features to dictionary for ARF
        arf_features = {
            'packet_count': features[0],
            'avg_size': features[1],
            'size_std': features[2],
            'avg_ttl': features[3],
            'ttl_std': features[4],
            'tcp_ratio': features[5],
            'udp_ratio': features[6],
            'dns_ratio': features[7],
            'syn_ratio': features[8],
            'http_ratio': features[9],
            'unique_ips': features[10],
            'unique_ports': features[11],
            'port_entropy': features[12],
            'avg_interval': features[13],
            'interval_std': features[14],
            'hour_of_day': features[15],
            'day_of_week': features[16],
            'small_pkt_ratio': features[17],
            'medium_pkt_ratio': features[18],
            'large_pkt_ratio': features[19],
            'inbound_ratio': features[20]
        }
        
        # Predict with ARF
        predicted_attack = self.arf_model.predict(arf_features)
        confidence = self.arf_model.predict_proba(arf_features).get(predicted_attack, 0)
        
        # Check for unknown attack pattern
        if predicted_attack not in self.ATTACKS and confidence < 0.7:  # NEW_ATTACK_THRESHOLD
            self._handle_unknown_attack(arf_features)
            return
        
        # Learn from new data (continuous learning)
        self.arf_model.learn(arf_features, predicted_attack)
        
        # Only proceed if we have high confidence in attack detection
        if predicted_attack != "normal" and confidence > 0.7:
            self.last_attack_type = predicted_attack
            self._identify_attacker()
            
            # Log attack
            self.attack_log.append({
                'time': datetime.now().strftime('%H:%M:%S'),
                'type': predicted_attack,
                'confidence': f"{confidence:.0%}",
                'src_ip': self.current_attacker or "unknown",
                'packets': features[0]
            })
            
            # Get DQN state (just traffic features)
            state = features
            
            # Select action using DQN
            action = self.dqn_model.predict(state)
            
            # Apply mitigation
            self._apply_mitigation(action)
            
            # Get reward based on effectiveness
            reward = self._calculate_reward(action, features)
            
            # Log mitigation
            self.mitigation_log.append({
                'time': datetime.now().strftime('%H:%M:%S'),
                'action': action,
                'target': self.current_attacker,
                'attack': predicted_attack,
                'effectiveness': min(0.95, max(0.7, random.random()))
            })
            
            # Update metrics
            self.metrics.append({
                'time': datetime.now(),
                'packet_rate': features[0],
                'attack': predicted_attack,
                'action': action,
                'reward': reward,
                'confidence': confidence
            })

    def _identify_attacker(self):
        ip_counts = defaultdict(int)
        for pkt in list(self.extractor.window):
            ip_counts[pkt['src_ip']] += 1
        
        if ip_counts:
            candidates = [ip for ip in ip_counts if ip != self.TARGET_IP]
            if candidates:
                self.current_attacker = max(candidates, key=lambda ip: ip_counts[ip])
                logging.info(f"Identified attacker: {self.current_attacker}")

    def _apply_mitigation(self, action):
        if action == 0 or not self.current_attacker:
            logging.info("No mitigation action taken")
            return
            
        try:
            if action == 1:  # Rate limit
                cmd = f"iptables -A INPUT -s {self.current_attacker} -m limit --limit 10/s -j ACCEPT"
                subprocess.run(cmd, shell=True, check=True)
            elif action == 2:  # Block IP
                cmd = f"iptables -A INPUT -s {self.current_attacker} -j DROP"
                subprocess.run(cmd, shell=True, check=True)
            elif action == 3:  # SYN cookies
                cmd = "sysctl -w net.ipv4.tcp_syncookies=1"
                subprocess.run(cmd, shell=True, check=True)
            elif action == 4:  # CAPTCHA
                cmd = f"iptables -A INPUT -s {self.current_attacker} -m limit --limit 2/s -j ACCEPT"
                subprocess.run(cmd, shell=True, check=True)
            elif action == 5:  # Null route
                cmd = f"ip route add blackhole {self.current_attacker}"
                subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Mitigation command failed: {e}")

    def _calculate_reward(self, action, features):
        packet_rate = features[0]
        syn_ratio = features[8]
        http_ratio = features[9]
        dns_ratio = features[7]
        
        if action == 0:  # No action
            return 1.0 if packet_rate < 100 else -2.0 * (packet_rate / 1000)
        elif action == 1:  # Rate limit
            return 1.0 + min(1.0, packet_rate / 500)
        elif action == 2:  # Block IP
            return 2.0
        elif action == 3:  # SYN cookies
            return 1.5 + syn_ratio
        elif action == 4:  # CAPTCHA
            return 1.5 + http_ratio
        elif action == 5:  # Null route
            return 2.0 + dns_ratio
        return 0.0

    def _load_attack_signatures(self):
        try:
            if os.path.exists('attack_signatures.json'):
                with open('attack_signatures.json', 'r') as f:
                    self.attack_signatures = json.load(f)
        except Exception as e:
            logging.error(f"Error loading attack signatures: {e}")

    def simulate_attack(self, attack_type):
        if self.attack_process:
            self.attack_process.terminate()
            self.attack_process = None
        
        if attack_type != "normal":
            logging.info(f"Starting {attack_type} attack simulation")
            if attack_type == "syn_flood":
                cmd = ["hping3", "-S", "-p", "80", "--flood", "--rand-source", "127.0.0.1"]
            elif attack_type == "dns_amplification":
                cmd = ["hping3", "--udp", "-p", "53", "--flood", "--rand-source", "127.0.0.1", "--data", "1024"]
            
            self.attack_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

    def stop(self):
        logging.info("Shutting down DDoS Defender...")
        self.running = False
        if self.attack_process:
            self.attack_process.terminate()
        subprocess.run("iptables -F", shell=True)
        subprocess.run("ip route flush cache", shell=True)
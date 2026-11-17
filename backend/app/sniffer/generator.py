import random
import time
from datetime import datetime, timezone
from typing import Dict, Any, List

SAMPLE_HOSTS = [
    ("192.168.1.10", "3c:22:fb:1a:2b:3c", "Apple Inc."),
    ("192.168.1.25", "dc:a6:32:44:55:66", "Raspberry Pi Foundation"),
    ("192.168.1.42", "b8:27:eb:77:88:99", "Samsung Electronics"),
    ("192.168.1.100", "00:1a:2b:aa:bb:cc", "Intel Corporate"),
    ("192.168.1.105", "50:c7:bf:11:22:33", "TP-Link Technologies")
]

PUBLIC_SERVERS = [
    ("142.250.190.46", 443, "HTTPS", "TCP"),
    ("1.1.1.1", 53, "DNS", "UDP"),
    ("8.8.8.8", 53, "DNS", "UDP"),
    ("151.101.1.140", 443, "HTTPS", "TCP"),
    ("13.107.42.14", 80, "HTTP", "TCP"),
    ("192.168.1.1", 80, "HTTP", "TCP"), # Router gateway
    ("216.58.214.206", 443, "HTTPS", "TCP")
]

class SyntheticTrafficGenerator:
    """
    Generates realistic background Wi-Fi network traffic and controlled test scenarios
    for defensive testing, demonstration, and offline lab evaluation.
    """
    
    @staticmethod
    def generate_normal_packet() -> Dict[str, Any]:
        """Generate a realistic normal packet metadata dictionary."""
        src_ip, src_mac, vendor = random.choice(SAMPLE_HOSTS)
        dst_ip, dst_port, service, protocol = random.choice(PUBLIC_SERVERS)
        
        src_port = random.randint(49152, 65535)
        packet_size = random.choice([64, 128, 512, 1024, 1420, 1514])
        tcp_flags = ["ACK"] if protocol == "TCP" else []
        if protocol == "TCP" and random.random() < 0.1:
            tcp_flags = ["SYN"]
            
        return {
            "timestamp": datetime.now(timezone.utc),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_mac": src_mac,
            "dst_mac": "c0:25:e9:12:34:56", # Gateway MAC
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "packet_size": packet_size,
            "tcp_flags": tcp_flags,
            "service": service,
            "ttl": random.choice([64, 128]),
            "info": f"Synthetic {protocol} Traffic"
        }

    @staticmethod
    def generate_port_scan_burst(attacker_ip: str = "192.168.1.199", target_ip: str = "192.168.1.1", port_count: int = 25) -> List[Dict[str, Any]]:
        """Simulate an active SYN port scan attack burst."""
        packets = []
        mac = "de:ad:be:ef:00:01"
        target_ports = random.sample(range(20, 1024), min(port_count, 100))
        
        for port in target_ports:
            packets.append({
                "timestamp": datetime.now(timezone.utc),
                "src_ip": attacker_ip,
                "dst_ip": target_ip,
                "src_mac": mac,
                "dst_mac": "c0:25:e9:12:34:56",
                "protocol": "TCP",
                "src_port": random.randint(50000, 60000),
                "dst_port": port,
                "packet_size": 60,
                "tcp_flags": ["SYN"],
                "service": "Unknown",
                "ttl": 64,
                "info": f"SYN Scan target port {port}"
            })
        return packets

    @staticmethod
    def generate_spike_burst(source_ip: str = "192.168.1.188", packet_count: int = 80) -> List[Dict[str, Any]]:
        """Simulate an unexpected sudden connection rate surge / packet flood."""
        packets = []
        for _ in range(packet_count):
            packets.append({
                "timestamp": datetime.now(timezone.utc),
                "src_ip": source_ip,
                "dst_ip": "192.168.1.1",
                "src_mac": "aa:bb:cc:11:22:33",
                "dst_mac": "c0:25:e9:12:34:56",
                "protocol": "UDP",
                "src_port": random.randint(40000, 65000),
                "dst_port": 53,
                "packet_size": random.randint(128, 512),
                "tcp_flags": [],
                "service": "DNS",
                "ttl": 64,
                "info": "Connection Rate Spike burst"
            })
        return packets

    @staticmethod
    def generate_bandwidth_surge(source_ip: str = "192.168.1.177") -> List[Dict[str, Any]]:
        """Simulate an unusual massive bandwidth transfer anomaly."""
        packets = []
        for _ in range(50):
            packets.append({
                "timestamp": datetime.now(timezone.utc),
                "src_ip": source_ip,
                "dst_ip": "104.244.42.1",
                "src_mac": "70:85:c2:99:88:77",
                "dst_mac": "c0:25:e9:12:34:56",
                "protocol": "TCP",
                "src_port": 55120,
                "dst_port": 443,
                "packet_size": 1514, # Maximum MTU frame
                "tcp_flags": ["ACK", "PSH"],
                "service": "HTTPS",
                "ttl": 64,
                "info": "Heavy Bandwidth Streaming Burst"
            })
        return packets

    @staticmethod
    def generate_unknown_device_packet() -> Dict[str, Any]:
        """Simulate a new, unregistered rogue device transmitting on the network."""
        unregistered_mac = f"02:00:00:{random.randint(10, 99)}:{random.randint(10, 99)}:{random.randint(10, 99)}"
        new_ip = f"192.168.1.{random.randint(200, 240)}"
        return {
            "timestamp": datetime.now(timezone.utc),
            "src_ip": new_ip,
            "dst_ip": "192.168.1.1",
            "src_mac": unregistered_mac,
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "protocol": "ARP",
            "src_port": None,
            "dst_port": None,
            "packet_size": 42,
            "tcp_flags": [],
            "service": "ARP",
            "ttl": None,
            "info": "New device discovery broadcast"
        }

from collections import defaultdict
from datetime import datetime, timezone
import time
from typing import Dict, Any, List

class FeatureExtractor:
    """
    Maintains a rolling sliding window of packets to compute behavioral
    feature vectors per IP address and globally.
    """
    def __init__(self, window_seconds: int = 5):
        self.window_seconds = window_seconds
        # ip -> list of (timestamp, packet_dict)
        self.ip_windows = defaultdict(list)
        self.last_cleanup = time.time()

    def add_packet(self, packet: Dict[str, Any]):
        """Record packet in the rolling window."""
        src_ip = packet.get("src_ip")
        if not src_ip:
            return
        
        now = time.time()
        self.ip_windows[src_ip].append((now, packet))
        
        # Periodic cleanup of old entries
        if now - self.last_cleanup > 2.0:
            self._cleanup_windows(now)

    def _cleanup_windows(self, now: float):
        cutoff = now - self.window_seconds
        for ip in list(self.ip_windows.keys()):
            self.ip_windows[ip] = [item for item in self.ip_windows[ip] if item[0] >= cutoff]
            if not self.ip_windows[ip]:
                del self.ip_windows[ip]
        self.last_cleanup = now

    def extract_features_for_ip(self, ip: str) -> Dict[str, float]:
        """
        Compute standard feature vector for a given IP over the active window.
        Returns:
            - packet_rate (packets/sec)
            - byte_rate (bytes/sec)
            - unique_dst_ports
            - unique_dst_ips
            - syn_ratio
            - udp_ratio
            - avg_packet_size
        """
        now = time.time()
        cutoff = now - self.window_seconds
        packets = [p for (t, p) in self.ip_windows.get(ip, []) if t >= cutoff]
        
        total_packets = len(packets)
        if total_packets == 0:
            return {
                "packet_rate": 0.0,
                "byte_rate": 0.0,
                "unique_dst_ports": 0,
                "unique_dst_ips": 0,
                "syn_ratio": 0.0,
                "udp_ratio": 0.0,
                "avg_packet_size": 0.0
            }

        total_bytes = sum(p.get("packet_size", 0) for p in packets)
        dst_ports = set(p.get("dst_port") for p in packets if p.get("dst_port") is not None)
        dst_ips = set(p.get("dst_ip") for p in packets if p.get("dst_ip") is not None)
        
        syn_count = sum(1 for p in packets if "SYN" in p.get("tcp_flags", []))
        udp_count = sum(1 for p in packets if p.get("protocol") == "UDP")

        duration = max(self.window_seconds, 1.0)
        
        return {
            "packet_rate": round(total_packets / duration, 2),
            "byte_rate": round(total_bytes / duration, 2),
            "unique_dst_ports": len(dst_ports),
            "unique_dst_ips": len(dst_ips),
            "syn_ratio": round(syn_count / total_packets, 3),
            "udp_ratio": round(udp_count / total_packets, 3),
            "avg_packet_size": round(total_bytes / total_packets, 1)
        }

    def get_active_ips(self) -> List[str]:
        return list(self.ip_windows.keys())

feature_extractor = FeatureExtractor(window_seconds=5)

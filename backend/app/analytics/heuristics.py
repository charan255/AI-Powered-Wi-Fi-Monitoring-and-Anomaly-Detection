import time
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from app.config import settings
from app.database import db_manager

logger = logging.getLogger("wifi_monitor.heuristics")

class HeuristicDetector:
    """
    Defensive rule-based anomaly & attack signature detection:
    - SYN / Port Scanning
    - Connection Rate / Packet Surges
    - High Bandwidth Surges
    - Unknown Device / Unauthorized MAC Address
    """
    def __init__(self):
        # Cool-down tracker to prevent alert storms: (src_ip, alert_type) -> last_alert_time
        self.alert_cooldowns: Dict[tuple, float] = {}
        self.cooldown_period_seconds: float = 12.0
        
        # MAC cache for known devices
        self.known_macs: set = set()

    def _can_alert(self, ip: str, alert_type: str) -> bool:
        now = time.time()
        key = (ip, alert_type)
        if key in self.alert_cooldowns:
            if now - self.alert_cooldowns[key] < self.cooldown_period_seconds:
                return False
        self.alert_cooldowns[key] = now
        return True

    def check_heuristics(self, src_ip: str, features: Dict[str, Any], raw_packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Evaluate traffic features and raw packet for heuristic signatures."""
        timestamp = datetime.now(timezone.utc)
        
        # 1. Port Scan Detection (High number of distinct ports with SYN/connection attempts)
        if features["unique_dst_ports"] >= settings.PORT_SCAN_PORT_THRESHOLD:
            if self._can_alert(src_ip, "PORT_SCAN"):
                alert = {
                    "timestamp": timestamp,
                    "alert_type": "PORT_SCAN",
                    "severity": "CRITICAL",
                    "source_ip": src_ip,
                    "target_ip": raw_packet.get("dst_ip", "Multiple"),
                    "details": (
                        f"Detected port scanning activity from {src_ip}: "
                        f"{features['unique_dst_ports']} distinct ports probed within "
                        f"{settings.WINDOW_SECONDS}s window (SYN ratio: {features['syn_ratio']:.0%})."
                    ),
                    "status": "ACTIVE"
                }
                db_manager.insert_alert(alert)
                logger.warning(f"[DEFENSIVE ALERT] Port scan detected: {alert['details']}")
                return alert

        # 2. Connection Spike / Packet Surge
        if features["packet_rate"] >= 50.0:  # Threshold for local Wi-Fi client rate
            if self._can_alert(src_ip, "CONNECTION_SPIKE"):
                alert = {
                    "timestamp": timestamp,
                    "alert_type": "CONNECTION_SPIKE",
                    "severity": "HIGH",
                    "source_ip": src_ip,
                    "target_ip": raw_packet.get("dst_ip", "Gateway"),
                    "details": (
                        f"Abnormal packet surge from {src_ip}: {features['packet_rate']} pkts/sec "
                        f"exceeds standard threshold."
                    ),
                    "status": "ACTIVE"
                }
                db_manager.insert_alert(alert)
                logger.warning(f"[DEFENSIVE ALERT] Connection spike detected: {alert['details']}")
                return alert

        # 3. High Bandwidth Surge
        if features["byte_rate"] >= settings.BANDWIDTH_BURST_THRESHOLD_BYTES / settings.WINDOW_SECONDS:
            if self._can_alert(src_ip, "BANDWIDTH_SURGE"):
                kbps = round((features["byte_rate"] * 8) / 1024, 1)
                alert = {
                    "timestamp": timestamp,
                    "alert_type": "BANDWIDTH_SURGE",
                    "severity": "MEDIUM",
                    "source_ip": src_ip,
                    "target_ip": raw_packet.get("dst_ip", "Internet"),
                    "details": f"Unusual sustained throughput burst from {src_ip}: ~{kbps} Kbps.",
                    "status": "ACTIVE"
                }
                db_manager.insert_alert(alert)
                logger.info(f"[DEFENSIVE ALERT] Bandwidth burst: {alert['details']}")
                return alert

        # 4. Unknown / Rogue Device Detection
        src_mac = raw_packet.get("src_mac")
        if src_mac and src_mac != "00:00:00:00:00:00":
            if src_mac not in self.known_macs:
                # Check if it's in DB
                existing_devices = {d["mac_address"] for d in db_manager.get_devices()}
                if src_mac not in existing_devices and len(existing_devices) > 0:
                    if self._can_alert(src_ip, "UNKNOWN_DEVICE"):
                        alert = {
                            "timestamp": timestamp,
                            "alert_type": "UNKNOWN_DEVICE",
                            "severity": "MEDIUM",
                            "source_ip": src_ip,
                            "target_ip": "Network",
                            "details": f"New unauthorized MAC address detected on subnet: {src_mac} (assigned IP: {src_ip}).",
                            "status": "ACTIVE"
                        }
                        db_manager.insert_alert(alert)
                        logger.warning(f"[DEFENSIVE ALERT] Unknown device detected: {alert['details']}")
                        self.known_macs.add(src_mac)
                        return alert
                self.known_macs.add(src_mac)

        return None

heuristic_detector = HeuristicDetector()

import threading
import time
import queue
import logging
from typing import Optional, List, Dict, Any

from app.config import settings
from app.database import db_manager
from app.sniffer.parser import parse_packet
from app.sniffer.generator import SyntheticTrafficGenerator

logger = logging.getLogger("wifi_monitor.capture")

class PacketCaptureEngine:
    def __init__(self):
        self.is_running: bool = False
        self.simulation_mode: bool = settings.SIMULATION_MODE
        self.thread: Optional[threading.Thread] = None
        self.packet_queue: queue.Queue = queue.Queue(maxsize=5000)
        self.pipeline_callbacks = []
        self._stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "start_time": time.time(),
            "packets_per_sec": 0.0,
            "bytes_per_sec": 0.0
        }
        self._recent_packet_count = 0
        self._recent_byte_count = 0
        self._last_rate_calc = time.time()

    def register_pipeline_callback(self, callback):
        """Register processing callback (e.g. anomaly detection, WebSocket broadcaster)."""
        self.pipeline_callbacks.append(callback)

    def start(self):
        """Start packet capture in a non-blocking background thread."""
        if self.is_running:
            logger.info("Sniffer already running.")
            return

        self.is_running = True
        self.thread = threading.Thread(target=self._capture_worker, daemon=True)
        self.thread.start()
        logger.info(f"Packet Capture Engine started (Simulation Mode: {self.simulation_mode}).")

    def stop(self):
        """Stop packet capture."""
        self.is_running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)
        logger.info("Packet Capture Engine stopped.")

    def set_simulation_mode(self, enabled: bool):
        self.simulation_mode = enabled
        logger.info(f"Simulation mode set to {enabled}")

    def inject_packets(self, packets: List[Dict[str, Any]]):
        """Inject synthetic packet frames directly for live attack/anomaly demonstration."""
        for p in packets:
            self._handle_processed_packet(p)

    def _handle_processed_packet(self, packet_dict: Dict[str, Any]):
        """Central ingestion pipeline for parsed packets."""
        self._stats["total_packets"] += 1
        self._stats["total_bytes"] += packet_dict["packet_size"]
        self._recent_packet_count += 1
        self._recent_byte_count += packet_dict["packet_size"]

        # Track device
        if packet_dict.get("src_mac") and packet_dict.get("src_ip"):
            db_manager.upsert_device(
                mac_address=packet_dict["src_mac"],
                ip_address=packet_dict["src_ip"],
                packet_size=packet_dict["packet_size"]
            )

        # Buffer for database batching
        db_manager.insert_traffic_packet(packet_dict)

        # Notify registered analysis & WebSocket pipelines
        for cb in self.pipeline_callbacks:
            try:
                cb(packet_dict)
            except Exception as e:
                logger.error(f"Error in pipeline callback: {e}")

    def _update_rates(self):
        now = time.time()
        delta = now - self._last_rate_calc
        if delta >= 1.0:
            self._stats["packets_per_sec"] = round(self._recent_packet_count / delta, 1)
            self._stats["bytes_per_sec"] = round(self._recent_byte_count / delta, 1)
            self._recent_packet_count = 0
            self._recent_byte_count = 0
            self._last_rate_calc = now

    def get_stats(self) -> Dict[str, Any]:
        self._update_rates()
        uptime = round(time.time() - self._stats["start_time"], 1)
        return {
            "is_running": self.is_running,
            "simulation_mode": self.simulation_mode,
            "total_packets": self._stats["total_packets"],
            "total_bytes": self._stats["total_bytes"],
            "packets_per_sec": self._stats["packets_per_sec"],
            "bytes_per_sec": self._stats["bytes_per_sec"],
            "uptime_seconds": uptime
        }

    def _capture_worker(self):
        """Worker thread executing either Scapy live sniff or synthetic stream."""
        if not self.simulation_mode:
            try:
                import scapy.all as scapy
                def scapy_callback(pkt):
                    if not self.is_running:
                        return True
                    parsed = parse_packet(pkt)
                    if parsed:
                        self._handle_processed_packet(parsed)

                iface = settings.CAPTURE_INTERFACE if settings.CAPTURE_INTERFACE else None
                logger.info(f"Initiating Scapy live sniff on interface: {iface or 'DEFAULT'}...")
                # Sniff with store=False for zero memory leak
                scapy.sniff(
                    iface=iface,
                    prn=scapy_callback,
                    store=False,
                    stop_filter=lambda _: not self.is_running
                )
                return
            except Exception as e:
                logger.warning(
                    f"Live Scapy capture failed or Npcap not detected ({e}). "
                    "Auto-switching to Synthetic Traffic Generation mode."
                )
                self.simulation_mode = True

        # Simulation Mode loop
        while self.is_running:
            synthetic_pkt = SyntheticTrafficGenerator.generate_normal_packet()
            self._handle_processed_packet(synthetic_pkt)
            self._update_rates()
            # Random sleep to mimic natural network inter-arrival intervals
            time.sleep(0.05 + 0.15 * (1.0 / (1.0 + (self._stats["total_packets"] % 10))))

capture_engine = PacketCaptureEngine()

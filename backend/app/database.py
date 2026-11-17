import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import pymongo
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

from app.config import settings

logger = logging.getLogger("wifi_monitor.database")

class DatabaseManager:
    def __init__(self):
        self.client: Optional[MongoClient] = None
        self.db = None
        self.is_connected: bool = False
        
        # In-memory fallbacks when MongoDB is offline
        self._mem_traffic: List[Dict[str, Any]] = []
        self._mem_anomalies: List[Dict[str, Any]] = []
        self._mem_alerts: List[Dict[str, Any]] = []
        self._mem_devices: Dict[str, Dict[str, Any]] = {}
        self._max_mem_records: int = 2000

    def connect(self):
        """Establish connection to MongoDB with timeout and setup indexes."""
        try:
            logger.info(f"Connecting to MongoDB at {settings.MONGO_URI}...")
            self.client = MongoClient(
                settings.MONGO_URI,
                serverSelectionTimeoutMS=2000,
                connectTimeoutMS=2000
            )
            # Ping to verify active connection
            self.client.admin.command('ping')
            self.db = self.client[settings.DB_NAME]
            self.is_connected = True
            logger.info(f"Successfully connected to MongoDB database: {settings.DB_NAME}")
            self._ensure_indexes()
        except (ConnectionFailure, ServerSelectionTimeoutError, Exception) as err:
            self.is_connected = False
            logger.warning(
                f"Could not connect to MongoDB ({err}). "
                "Running in resilient in-memory mode until MongoDB is available."
            )

    def _ensure_indexes(self):
        """Build optimized indexes on MongoDB collections."""
        if not self.is_connected or self.db is None:
            return
        try:
            # traffic_logs indexes
            self.db.traffic_logs.create_index([("timestamp", DESCENDING)])
            self.db.traffic_logs.create_index([("src_ip", ASCENDING)])
            self.db.traffic_logs.create_index([("dst_ip", ASCENDING)])
            self.db.traffic_logs.create_index([("protocol", ASCENDING)])
            
            # anomalies indexes
            self.db.anomalies.create_index([("timestamp", DESCENDING)])
            self.db.anomalies.create_index([("ip_target", ASCENDING)])
            
            # alerts indexes
            self.db.alerts.create_index([("timestamp", DESCENDING)])
            self.db.alerts.create_index([("alert_type", ASCENDING)])
            
            # devices indexes
            self.db.devices.create_index([("mac_address", ASCENDING)], unique=True)
            self.db.devices.create_index([("ip_address", ASCENDING)])
            logger.info("MongoDB collection indexes initialized.")
        except Exception as e:
            logger.error(f"Error creating indexes: {e}")

    def insert_traffic_packet(self, packet_data: Dict[str, Any]):
        """Store a parsed network packet log."""
        if self.is_connected and self.db is not None:
            try:
                self.db.traffic_logs.insert_one(packet_data)
                return
            except Exception as e:
                logger.error(f"Failed to insert traffic log into MongoDB: {e}")
        
        # Fallback to in-memory ring buffer
        self._mem_traffic.append(packet_data)
        if len(self._mem_traffic) > self._max_mem_records:
            self._mem_traffic.pop(0)

    def insert_traffic_batch(self, packets: List[Dict[str, Any]]):
        """Batch insert parsed network logs for maximum ingestion throughput."""
        if not packets:
            return
        if self.is_connected and self.db is not None:
            try:
                self.db.traffic_logs.insert_many(packets, ordered=False)
                return
            except Exception as e:
                logger.error(f"Failed batch insert to MongoDB: {e}")
        
        self._mem_traffic.extend(packets)
        if len(self._mem_traffic) > self._max_mem_records:
            self._mem_traffic = self._mem_traffic[-self._max_mem_records:]

    def insert_anomaly(self, anomaly: Dict[str, Any]):
        """Store an ML-detected anomaly."""
        if self.is_connected and self.db is not None:
            try:
                self.db.anomalies.insert_one(anomaly)
                return
            except Exception as e:
                logger.error(f"Failed to insert anomaly: {e}")
        
        self._mem_anomalies.append(anomaly)
        if len(self._mem_anomalies) > 500:
            self._mem_anomalies.pop(0)

    def insert_alert(self, alert: Dict[str, Any]):
        """Store a heuristic rule-based alert."""
        if self.is_connected and self.db is not None:
            try:
                self.db.alerts.insert_one(alert)
                return
            except Exception as e:
                logger.error(f"Failed to insert alert: {e}")
                
        self._mem_alerts.append(alert)
        if len(self._mem_alerts) > 500:
            self._mem_alerts.pop(0)

    def upsert_device(self, mac_address: str, ip_address: str, packet_size: int, vendor: str = "Unknown"):
        """Track and update device network presence and telemetry."""
        now = datetime.now(timezone.utc)
        if self.is_connected and self.db is not None:
            try:
                self.db.devices.update_one(
                    {"mac_address": mac_address},
                    {
                        "$set": {
                            "ip_address": ip_address,
                            "last_seen": now,
                            "vendor": vendor
                        },
                        "$setOnInsert": {
                            "first_seen": now,
                            "is_trusted": False
                        },
                        "$inc": {
                            "packet_count": 1,
                            "bytes_transferred": packet_size
                        }
                    },
                    upsert=True
                )
                return
            except Exception as e:
                logger.error(f"Failed to upsert device: {e}")
                
        # In-memory update
        if mac_address not in self._mem_devices:
            self._mem_devices[mac_address] = {
                "mac_address": mac_address,
                "ip_address": ip_address,
                "vendor": vendor,
                "first_seen": now,
                "last_seen": now,
                "packet_count": 1,
                "bytes_transferred": packet_size,
                "is_trusted": False
            }
        else:
            dev = self._mem_devices[mac_address]
            dev["ip_address"] = ip_address
            dev["last_seen"] = now
            dev["packet_count"] += 1
            dev["bytes_transferred"] += packet_size

    def get_recent_traffic(self, limit: int = 100, protocol: Optional[str] = None, ip: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve recent packet logs with optional protocol or IP filters."""
        if self.is_connected and self.db is not None:
            try:
                query: Dict[str, Any] = {}
                if protocol:
                    query["protocol"] = protocol.upper()
                if ip:
                    query["$or"] = [{"src_ip": ip}, {"dst_ip": ip}]
                cursor = self.db.traffic_logs.find(query).sort("timestamp", DESCENDING).limit(limit)
                results = list(cursor)
                for r in results:
                    r["_id"] = str(r["_id"])
                return results
            except Exception as e:
                logger.error(f"Failed to get recent traffic from MongoDB: {e}")
                
        # Filter in-memory
        logs = list(self._mem_traffic)
        if protocol:
            logs = [x for x in logs if x.get("protocol") == protocol.upper()]
        if ip:
            logs = [x for x in logs if x.get("src_ip") == ip or x.get("dst_ip") == ip]
        return logs[-limit:][::-1]

    def get_anomalies(self, limit: int = 50) -> List[Dict[str, Any]]:
        if self.is_connected and self.db is not None:
            try:
                cursor = self.db.anomalies.find().sort("timestamp", DESCENDING).limit(limit)
                results = list(cursor)
                for r in results:
                    r["_id"] = str(r["_id"])
                return results
            except Exception as e:
                logger.error(f"Failed to fetch anomalies from MongoDB: {e}")
        return self._mem_anomalies[-limit:][::-1]

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        if self.is_connected and self.db is not None:
            try:
                cursor = self.db.alerts.find().sort("timestamp", DESCENDING).limit(limit)
                results = list(cursor)
                for r in results:
                    r["_id"] = str(r["_id"])
                return results
            except Exception as e:
                logger.error(f"Failed to fetch alerts from MongoDB: {e}")
        return self._mem_alerts[-limit:][::-1]

    def get_devices(self) -> List[Dict[str, Any]]:
        if self.is_connected and self.db is not None:
            try:
                cursor = self.db.devices.find().sort("last_seen", DESCENDING)
                results = list(cursor)
                for r in results:
                    r["_id"] = str(r["_id"])
                return results
            except Exception as e:
                logger.error(f"Failed to fetch devices: {e}")
        return list(self._mem_devices.values())

    def update_device_trust(self, mac_address: str, is_trusted: bool):
        if self.is_connected and self.db is not None:
            try:
                self.db.devices.update_one({"mac_address": mac_address}, {"$set": {"is_trusted": is_trusted}})
                return True
            except Exception as e:
                logger.error(f"Failed to update device trust: {e}")
        if mac_address in self._mem_devices:
            self._mem_devices[mac_address]["is_trusted"] = is_trusted
            return True
        return False

    def close(self):
        if self.client:
            self.client.close()
            logger.info("Closed MongoDB connection.")

db_manager = DatabaseManager()

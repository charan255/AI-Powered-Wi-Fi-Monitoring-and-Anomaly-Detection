import os
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseModel):
    PROJECT_NAME: str = "AI-Powered Wi-Fi Network Monitoring & Anomaly Detection System"
    VERSION: str = "1.0.0"
    API_PREFIX: str = "/api"
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # MongoDB Configuration
    MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    DB_NAME: str = os.getenv("DB_NAME", "wifi_monitor_db")
    
    # Packet Sniffer Configuration
    CAPTURE_INTERFACE: str = os.getenv("CAPTURE_INTERFACE", "")  # Empty string defaults to Scapy conf.iface
    BUFFER_SIZE: int = int(os.getenv("BUFFER_SIZE", "1000"))
    SIMULATION_MODE: bool = os.getenv("SIMULATION_MODE", "true").lower() in ("true", "1", "yes")
    
    # Detection Thresholds
    WINDOW_SECONDS: int = int(os.getenv("WINDOW_SECONDS", "5"))
    PORT_SCAN_PORT_THRESHOLD: int = int(os.getenv("PORT_SCAN_PORT_THRESHOLD", "15"))
    PORT_SCAN_TIME_WINDOW: int = int(os.getenv("PORT_SCAN_TIME_WINDOW", "5"))
    PACKET_SPIKE_FACTOR: float = float(os.getenv("PACKET_SPIKE_FACTOR", "3.5"))
    BANDWIDTH_BURST_THRESHOLD_BYTES: int = int(os.getenv("BANDWIDTH_BURST_THRESHOLD_BYTES", "5000000"))  # 5 MB in window
    
    # Machine Learning Settings
    ML_CONTAMINATION: float = float(os.getenv("ML_CONTAMINATION", "0.05"))
    ML_MODEL_PATH: str = os.getenv("ML_MODEL_PATH", "isolation_forest.joblib")
    RETRAIN_INTERVAL_MINUTES: int = int(os.getenv("RETRAIN_INTERVAL_MINUTES", "60"))

settings = Settings()

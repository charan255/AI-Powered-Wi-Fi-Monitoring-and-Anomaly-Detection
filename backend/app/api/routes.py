from collections import Counter
from typing import Optional
from fastapi import APIRouter, Query, HTTPException, Body
from pydantic import BaseModel

from app.config import settings
from app.database import db_manager
from app.sniffer.capture import capture_engine
from app.sniffer.generator import SyntheticTrafficGenerator
from app.analytics.ml_detector import ml_detector

router = APIRouter()

class TrustUpdatePayload(BaseModel):
    is_trusted: bool

@router.get("/status")
def get_system_status():
    """Retrieve full defensive engine telemetry and health state."""
    capture_stats = capture_engine.get_stats()
    return {
        "status": "healthy",
        "project": settings.PROJECT_NAME,
        "database": {
            "is_connected": db_manager.is_connected,
            "type": "MongoDB" if db_manager.is_connected else "In-Memory Buffer (MongoDB Offline)"
        },
        "capture": capture_stats,
        "ml_model": {
            "is_trained": ml_detector.is_trained,
            "last_trained": ml_detector.last_trained_time
        }
    }

@router.get("/traffic/live")
def get_live_traffic(
    limit: int = Query(default=100, le=500),
    protocol: Optional[str] = None,
    ip: Optional[str] = None
):
    """Fetch recent packet metadata logs."""
    logs = db_manager.get_recent_traffic(limit=limit, protocol=protocol, ip=ip)
    return {"count": len(logs), "packets": logs}

@router.get("/traffic/stats")
def get_traffic_stats():
    """Compute protocol breakdowns and top communicating host IPs."""
    recent_packets = db_manager.get_recent_traffic(limit=300)
    
    # Protocol distribution
    protocols = Counter(p.get("protocol", "Other") for p in recent_packets)
    protocol_distribution = [{"name": k, "value": v} for k, v in protocols.items()]

    # Top talkers
    src_talkers = Counter(p.get("src_ip") for p in recent_packets if p.get("src_ip"))
    top_talkers = [{"ip": k, "packets": v} for k, v in src_talkers.most_common(5)]

    # Services
    services = Counter(p.get("service", "Unknown") for p in recent_packets)
    top_services = [{"name": k, "count": v} for k, v in services.most_common(6)]

    return {
        "protocol_distribution": protocol_distribution,
        "top_talkers": top_talkers,
        "top_services": top_services,
        "sample_size": len(recent_packets)
    }

@router.get("/anomalies")
def get_anomalies(limit: int = Query(default=50, le=200)):
    """Retrieve unsupervised Isolation Forest anomaly records."""
    records = db_manager.get_anomalies(limit=limit)
    return {"count": len(records), "anomalies": records}

@router.get("/alerts")
def get_alerts(limit: int = Query(default=50, le=200)):
    """Retrieve rule-based heuristic security alerts."""
    records = db_manager.get_alerts(limit=limit)
    return {"count": len(records), "alerts": records}

@router.get("/devices")
def get_devices():
    """List all network endpoints observed on the Wi-Fi segment."""
    devices = db_manager.get_devices()
    return {"count": len(devices), "devices": devices}

@router.post("/devices/{mac}/trust")
def set_device_trust(mac: str, payload: TrustUpdatePayload):
    """Mark a device as trusted or untrusted."""
    success = db_manager.update_device_trust(mac, payload.is_trusted)
    if not success:
        raise HTTPException(status_code=404, detail="Device not found")
    return {"mac": mac, "is_trusted": payload.is_trusted}

@router.post("/capture/start")
def start_capture():
    capture_engine.start()
    return {"status": "started", "stats": capture_engine.get_stats()}

@router.post("/capture/stop")
def stop_capture():
    capture_engine.stop()
    return {"status": "stopped", "stats": capture_engine.get_stats()}

@router.post("/capture/mode")
def toggle_mode(simulation: bool = Query(...)):
    capture_engine.set_simulation_mode(simulation)
    return {"simulation_mode": simulation}

@router.post("/simulate/{scenario}")
def trigger_simulation_scenario(scenario: str):
    """
    Inject synthetic attack patterns for live defense evaluation and project presentation:
    - port_scan: Injects SYN probes across 25 destination ports
    - spike: Injects sudden rate surge
    - bandwidth: Injects high data volume stream
    - unknown_device: Injects frame from unregistered MAC
    """
    scenario = scenario.lower()
    if scenario == "port_scan":
        burst = SyntheticTrafficGenerator.generate_port_scan_burst()
        capture_engine.inject_packets(burst)
        return {"scenario": "port_scan", "injected_packets": len(burst)}
        
    elif scenario == "spike":
        burst = SyntheticTrafficGenerator.generate_spike_burst()
        capture_engine.inject_packets(burst)
        return {"scenario": "spike", "injected_packets": len(burst)}
        
    elif scenario == "bandwidth":
        burst = SyntheticTrafficGenerator.generate_bandwidth_surge()
        capture_engine.inject_packets(burst)
        return {"scenario": "bandwidth", "injected_packets": len(burst)}
        
    elif scenario == "unknown_device":
        pkt = SyntheticTrafficGenerator.generate_unknown_device_packet()
        capture_engine.inject_packets([pkt])
        return {"scenario": "unknown_device", "injected_packets": 1}
        
    else:
        raise HTTPException(status_code=400, detail=f"Unknown scenario '{scenario}'. Allowed: port_scan, spike, bandwidth, unknown_device")

@router.post("/ml/retrain")
def retrain_ml():
    """Trigger retraining of the Isolation Forest model."""
    ml_detector.train()
    return {
        "status": "trained",
        "last_trained": ml_detector.last_trained_time
    }

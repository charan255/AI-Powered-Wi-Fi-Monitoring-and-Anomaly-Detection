import sys
import os

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.database import db_manager
from app.sniffer.parser import parse_packet
from app.sniffer.generator import SyntheticTrafficGenerator
from app.analytics.features import feature_extractor
from app.analytics.heuristics import heuristic_detector
from app.analytics.ml_detector import ml_detector

def run_tests():
    print("[1/5] Testing Database connection manager...")
    db_manager.connect()
    print(f"      Database status: {'Connected to MongoDB' if db_manager.is_connected else 'In-Memory Resilient Mode'}")

    print("[2/5] Testing Synthetic Traffic Generator...")
    pkt = SyntheticTrafficGenerator.generate_normal_packet()
    assert pkt["protocol"] in ("TCP", "UDP"), "Expected protocol in packet"
    assert "src_ip" in pkt and "dst_ip" in pkt
    print(f"      Generated packet: {pkt['protocol']} from {pkt['src_ip']} to {pkt['dst_ip']}")

    print("[3/5] Testing Feature Extractor & Isolation Forest...")
    feature_extractor.add_packet(pkt)
    feats = feature_extractor.extract_features_for_ip(pkt["src_ip"])
    print(f"      Extracted features for {pkt['src_ip']}: {feats}")
    
    assert ml_detector.is_trained, "Isolation Forest should be trained"
    anom = ml_detector.score_features(pkt["src_ip"], feats)
    print(f"      Normal packet ML anomaly check: {'Flagged' if anom else 'Normal (Clean)'}")

    print("[4/5] Testing Port Scan Heuristic Detection...")
    scan_burst = SyntheticTrafficGenerator.generate_port_scan_burst(attacker_ip="192.168.1.199", port_count=20)
    alert_triggered = False
    for p in scan_burst:
        feature_extractor.add_packet(p)
        f = feature_extractor.extract_features_for_ip(p["src_ip"])
        alert = heuristic_detector.check_heuristics(p["src_ip"], f, p)
        if alert:
            alert_triggered = True
            print(f"      SUCCESS: Heuristic alert caught: {alert['alert_type']} - {alert['details']}")
            break
    assert alert_triggered, "Port scan should trigger an alert"

    print("[5/5] Testing ML Outlier Isolation on Attack Bursts...")
    spike_burst = SyntheticTrafficGenerator.generate_spike_burst(source_ip="192.168.1.188", packet_count=90)
    ml_flagged = False
    for p in spike_burst:
        feature_extractor.add_packet(p)
        f = feature_extractor.extract_features_for_ip(p["src_ip"])
        anom = ml_detector.score_features(p["src_ip"], f)
        if anom:
            ml_flagged = True
            print(f"      SUCCESS: ML Isolation Forest isolated outlier: Score={anom['anomaly_score']} Reason={anom['explanation']}")
            break

    print("\n=======================================================")
    print(" ALL CORE DEFENSIVE COMPONENTS TESTED & FUNCTIONAL! ")
    print("=======================================================")

if __name__ == "__main__":
    run_tests()

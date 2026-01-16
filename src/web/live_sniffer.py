import json
import os
import requests
import time
import socket
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

# config
LOG_FILE = "live_alerts.json"
STATE_FILE = "stats.json"
LOCKDOWN_FILE = "lockdown_status.json"

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

MY_IP = get_local_ip()

def extract_meaningful_features(pkt):
    """
    Extract flow-approximated features for the LSTM model.
    Schema: [Dest Port, Duration, Fwd Pkts, Bwd Pkts, Bytes/s, Pkts/s, IAT, Len Mean, Active, Idle]
    """
    if IP in pkt:
        dest_port = float(pkt.dport) if (TCP in pkt or UDP in pkt) else 80.0
        pkt_len = float(len(pkt))
        
        # single-packet approximations (real flow stats would need state tracking)
        return [
            dest_port,  # 1. Destination Port
            0.1,        # 2. Flow Duration (Low for single packet)
            1.0,        # 3. Total Fwd Packets
            0.0,        # 4. Total Backward Packets
            pkt_len,    # 5. Flow Bytes/s (Instantaneous)
            1.0,        # 6. Flow Packets/s (Instantaneous)
            0.0,        # 7. Flow IAT Mean
            pkt_len,    # 8. Packet Length Mean
            0.0,        # 9. Active Mean
            0.0         # 10. Idle Mean
        ]
    return None

def save_to_log(data):
    """Safely appends to log and updates a global counter."""
    try:
        logs = []
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                logs = json.load(f)
        
        logs.append(data)
        # Keep a sliding window of 100 for better trend analysis
        with open(LOG_FILE, "w") as f:
            json.dump(logs[-100:], f)

        # Update Running Total for the Dashboard
        stats = {"total": 0}
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, "r") as f:
                stats = json.load(f)
        stats["total"] += 1
        with open(STATE_FILE, "w") as f:
            json.dump(stats, f)
    except Exception as e:
        print(f"Logging error: {e}")

def process_packet(pkt):
    # Ignore self-traffic to avoid infinite feedback loops
    if IP in pkt and pkt[IP].src == MY_IP:
        return 

    # Check Lockdown Status
    is_locked = False
    if os.path.exists(LOCKDOWN_FILE):
        try:
            with open(LOCKDOWN_FILE, "r") as f:
                is_locked = json.load(f).get("locked", False)
        except: pass

    features = extract_meaningful_features(pkt)
    if features:
        try:
            # query inference API
            res = requests.post("http://127.0.0.1:8000/predict", json={"features": features}, timeout=0.1)
            result = res.json()
            
            status = result["status"]
            if is_locked and status == "ATTACK":
                status = "BLOCKED"

            # log packet data
            dport = 0
            if TCP in pkt: 
                dport = pkt[TCP].dport
            elif UDP in pkt: 
                dport = pkt[UDP].dport

            save_to_log({
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "unix_time": time.time(),
                "src": pkt[IP].src,
                "dst": pkt[IP].dst,
                "dst_port": dport,
                "proto": "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other",
                "status": status,
                "confidence": result["confidence"],
                "lockdown_active": is_locked
            })
            
            log_msg = f"[{datetime.now().strftime('%H:%M:%S')}] Analyzed: {status} ({result['confidence']})"
            if is_locked: log_msg += " [LOCKDOWN]"
            print(log_msg)
        except Exception as e:
            # print(f"Error processing packet: {e}")
            pass

if __name__ == "__main__":
    print(f"🕵️  Sniffer V2: Predictive Mode Active. Monitoring {MY_IP}...")
    sniff(prn=process_packet, store=False)
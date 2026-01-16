import time
import random
import socket
import sys
import logging

# Suppress Scapy 'Using broadcast' warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import IP, TCP, UDP, send, Raw

def get_target_ip():
    """Auto-detect local IP to send traffic to itself."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

TARGET_IP = get_target_ip()

def banner():
    print(f"""
    ⚔️  Guardian AI : Attack Simulator
    ==================================
    Target: {TARGET_IP}
    
    Select Mode:
    [1] 🌊 Velocity Surge (UDP Flood) -> Triggers 'High Velocity' Alarm
    [2] 🕷️ Port Scan Simulation       -> Generates 'Forensics' entries
    [3] 🛑 Stop
    """)

def udp_flood():
    print("\n🚀 Starting High-Velocity Flood (Ctrl+C to stop)...")
    print("   Watch the 'Traffic Velocity' metric on the dashboard!")
    count = 0
    # Spoof a fake external attacker IP
    fake_src = "192.168.1.66" 
    try:
        while True:
            # Random port to avoid OS caching/blocking issues
            dport = random.randint(1024, 65535)
            # Create a packet with some payload and SPOOFED SOURCE
            pkt = IP(src=fake_src, dst=TARGET_IP)/UDP(dport=dport)/Raw(load="BenignTestPayload"*10)
            send(pkt, verbose=False)
            count += 1
            if count % 50 == 0:
                print(f"   -> Sent {count} packets...", end="\r")
            time.sleep(0.01) # fast but not crashing-the-system fast
    except KeyboardInterrupt:
        print("\n🛑 Flood stopped.")

def port_scan():
    print("\n🕵️  Starting Port Scan Simulation...")
    print("   Watch the 'Target Port Analysis' graph update!")
    common_ports = [80, 443, 21, 22, 25, 3306, 8080]
    fake_src = "10.0.0.99" # Different attacker
    try:
        for i in range(50):
            # Mix specific ports and random ones
            if i % 5 == 0:
                dport = random.choice(common_ports)
            else:
                dport = random.randint(20, 1000)
            
            pkt = IP(src=fake_src, dst=TARGET_IP)/TCP(dport=dport, flags="S")
            send(pkt, verbose=False)
            print(f"   -> Probing port {dport}...", end="\r")
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    print("\n✅ Simulation complete.")

if __name__ == "__main__":
    while True:
        banner()
        choice = input("Enter choice: ")
        
        if choice == "1":
            udp_flood()
        elif choice == "2":
            port_scan()
        elif choice == "3":
            sys.exit()
        else:
            print("Invalid choice.")

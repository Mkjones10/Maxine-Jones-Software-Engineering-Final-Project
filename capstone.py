import os
import sqlite3
import threading
import time
import psutil
import subprocess
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list

MEMORY_THRESHOLD_MB = 100
DB_FILE = 'network_logs.db'

# ---------------- DB Setup ----------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        dest_ip TEXT,
        protocol TEXT,
        details TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        type TEXT,
        message TEXT
    )''')
    conn.commit()
    conn.close()

def insert_packet(timestamp, src_ip, dest_ip, protocol, details):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO packets (timestamp, src_ip, dest_ip, protocol, details) VALUES (?, ?, ?, ?, ?)",
              (timestamp, src_ip, dest_ip, protocol, details))
    conn.commit()
    conn.close()

def insert_alert(timestamp, alert_type, message):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO alerts (timestamp, type, message) VALUES (?, ?, ?)",
              (timestamp, alert_type, message))
    conn.commit()
    conn.close()

# ---------------- Memory Monitor ----------------
def monitor_memory():
    print("[INFO] Memory monitoring started...")
    while True:
        memory_info = psutil.Process().memory_info()
        rss_memory_mb = memory_info.rss / (1024 * 1024)
        if rss_memory_mb > MEMORY_THRESHOLD_MB:
            msg = f"High memory usage: {rss_memory_mb:.2f} MB"
            print(f"[WARNING] {msg}")
            insert_alert(time.strftime('%Y-%m-%d %H:%M:%S'), "MEMORY", msg)
        time.sleep(1)

# ---------------- Packet Analysis ----------------
def analyze_packet(packet):
    packet_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))

    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        if packet.haslayer(TCP):
            tcp_flags = packet[TCP].flags
            if tcp_flags == 'S':
                msg = f"SYN Packet from {ip_src} to {ip_dst} at {packet_time}"
                print(f"[ALERT] {msg}")
                insert_packet(packet_time, ip_src, ip_dst, "TCP", "SYN Packet")
                insert_alert(packet_time, "SYN_FLOOD", msg)

        elif packet.haslayer(UDP):
            udp_len = packet[UDP].len
            if udp_len > 1500:
                msg = f"Oversized UDP Packet from {ip_src} to {ip_dst} at {packet_time}"
                print(f"[ALERT] {msg}")
                insert_packet(packet_time, ip_src, ip_dst, "UDP", "Oversized UDP Packet")
                insert_alert(packet_time, "UDP_ATTACK", msg)

        elif packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type
            if icmp_type == 8:
                msg = f"ICMP Echo Request from {ip_src} to {ip_dst} at {packet_time}"
                print(f"[INFO] {msg}")
                insert_packet(packet_time, ip_src, ip_dst, "ICMP", "Ping Sweep")
                insert_alert(packet_time, "ICMP_SWEEP", msg)

# ---------------- Sniffer ----------------
def start_sniffing():
    print("[INFO] Packet sniffing started...")

    # Auto-select first available interface (customize if needed)
    interfaces = get_if_list()
    print("\n[DEBUG] Available Interfaces:")
    for i, iface in enumerate(interfaces):
        print(f" - {iface}")
    print()

    sniff(prn=analyze_packet, store=False, filter="ip")  # Remove iface= to use default

# ---------------- Attack Script Launcher ----------------
def run_attacks():
    print("[INFO] Launching simulated attack scripts...")

    base_dir = os.path.dirname(os.path.abspath(__file__))

    scripts = [
        "syn_flood.py",
        "oversized_udp.py",
        "ping_sweep.py"
    ]

    for script in scripts:
        script_path = os.path.join(base_dir, script)
        if os.path.exists(script_path):
            subprocess.run(["python", script_path])
        else:
            print(f"[ERROR] {script} not found at {script_path}")

# ---------------- Main ----------------
if __name__ == "__main__":
    init_db()

    # Start memory monitor thread
    threading.Thread(target=monitor_memory, daemon=True).start()

    # Start packet sniffer thread
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.start()

    # Run attack scripts
    run_attacks()

    # Wait for sniffer to finish (manual stop)
    sniff_thread.join()

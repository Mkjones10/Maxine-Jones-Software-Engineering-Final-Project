from scapy.all import IP, UDP, Raw, send
import os
import time

# Ensure the 'logs' directory exists
os.makedirs("logs", exist_ok=True)

# Function to log events to a file and print to console
def log_event(message):
    with open("logs/udp_log.txt", "a") as log_file:
        log_file.write(f"{message}\n")
    print(message)

# Function to send oversized UDP packets
def send_large_udp(target_ip, target_port, size=1600, packet_count=5):
    log_event(f"Sending {packet_count} oversized UDP packets to {target_ip}:{target_port} at {time.strftime('%Y-%m-%d %H:%M:%S')}...")
    payload = "A" * size  # Large payload
    for i in range(packet_count):
        packet = IP(dst=target_ip) / UDP(sport=12345 + i, dport=target_port) / Raw(load=payload)
        send(packet, verbose=False)
        log_event(f"Packet sent during UDP attack: {packet.summary()}")
    log_event(f"Oversized UDP packets sent at {time.strftime('%Y-%m-%d %H:%M:%S')}.")

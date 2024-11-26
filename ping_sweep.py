from scapy.all import IP, ICMP, send
import os
import time

# Ensure the 'logs' directory exists
os.makedirs("logs", exist_ok=True)

# Function to log events to a file and print to console
def log_event(message):
    with open("logs/ping_sweep_log.txt", "a") as log_file:
        log_file.write(f"{message}\n")
    print(message)

# Function to perform an ICMP ping sweep
def icmp_ping_sweep(network_prefix, start_range=1, end_range=254):
    log_event(f"Starting ICMP ping sweep on {network_prefix}.{start_range}-{end_range} at {time.strftime('%Y-%m-%d %H:%M:%S')}...")
    for i in range(start_range, end_range + 1):
        packet = IP(dst=f"{network_prefix}.{i}") / ICMP()
        send(packet, verbose=False)
        log_event(f"Packet sent during ICMP ping sweep: {packet.summary()}")
    log_event(f"Ping sweep completed at {time.strftime('%Y-%m-%d %H:%M:%S')}.")

from scapy.all import sniff, IP, TCP, UDP, ICMP
import time
import threading
import psutil  # For monitoring memory
import syn_flood
import oversized_udp
import ping_sweep
import os

# Ensure the 'logs' directory exists
os.makedirs("logs", exist_ok=True)

# Log files
sniffing_log_file = "logs/sniffing_log.txt"
memory_log_file = "logs/memory_log.txt"

# Memory usage threshold in MB
MEMORY_THRESHOLD_MB = 100  # Adjust to your system's capacity

# Function to monitor memory usage
def monitor_memory():
    with open(memory_log_file, "a") as log_file:
        log_file.write(f"Memory monitoring started at {time.strftime('%Y-%m-%d %H:%M:%S')}...\n")
    print("Memory monitoring started...")

    while True:
        # Get current memory usage in MB
        memory_info = psutil.Process().memory_info()
        rss_memory_mb = memory_info.rss / (1024 * 1024)

        if rss_memory_mb > MEMORY_THRESHOLD_MB:
            with open(memory_log_file, "a") as log_file:
                log_file.write(
                    f"[WARNING] High memory usage detected: {rss_memory_mb:.2f} MB at {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                )
            print(f"[WARNING] High memory usage detected: {rss_memory_mb:.2f} MB")
        
        # Check every second
        time.sleep(1)

# Function to analyze packets
def analyze_packet(packet):
    packet_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))
    
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        if packet.haslayer(TCP):
            tcp_flags = packet[TCP].flags
            if tcp_flags == 'S':  # SYN flag
                message = f"[ALERT] SYN Packet detected from {ip_src} to {ip_dst} at {packet_time}"
                log_event(sniffing_log_file, message, packet)
                
        elif packet.haslayer(UDP):
            udp_len = packet[UDP].len
            if udp_len > 1500:  # Unusually large UDP packet
                message = f"[ALERT] Large UDP Packet detected from {ip_src} to {ip_dst} at {packet_time}"
                log_event(sniffing_log_file, message, packet)
                
        elif packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type
            if icmp_type == 8:  # Echo Request (Ping)
                message = f"[INFO] ICMP Echo Request detected from {ip_src} to {ip_dst} at {packet_time}"
                log_event(sniffing_log_file, message, packet)

# Log events to a file
def log_event(filename, message, packet=None):
    with open(filename, "a") as log_file:
        log_file.write(f"{message}\n")
        if packet:
            log_file.write(f"Packet Data: {packet.summary()}\n")
    print(message)
    if packet:
        print(f"Packet Data: {packet.summary()}")

# Run all scenarios sequentially
def run_all_scenarios():
    # SYN Flood Attack with higher packet count
    syn_flood.syn_flood("192.168.1.1", 80, packet_count=5000)

    # Oversized UDP Packets with large payload
    oversized_udp.send_large_udp("192.168.1.1", 53, size=65000, packet_count=500)

    # ICMP Ping Sweep over a large subnet
    ping_sweep.icmp_ping_sweep("192.168.1", start_range=1, end_range=254)

# Sniffing packets
def start_sniffing():
    print("Starting packet sniffing...")
    sniff(prn=analyze_packet, store=False, filter="ip", iface="Wi-Fi")

if __name__ == "__main__":
    # Start sniffing in one thread
    sniffing_thread = threading.Thread(target=start_sniffing)
    sniffing_thread.start()

    # Start memory monitoring in another thread
    memory_thread = threading.Thread(target=monitor_memory, daemon=True)
    memory_thread.start()

    # Run attack scenarios
    run_all_scenarios()

    # Wait for sniffing thread to finish
    sniffing_thread.join()

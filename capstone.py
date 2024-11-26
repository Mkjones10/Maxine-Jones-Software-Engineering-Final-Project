from scapy.all import sniff, IP, TCP, UDP, ICMP
import time
import threading
import syn_flood
import oversized_udp
import ping_sweep
import os

# Define the path for the 'logs' directory inside the CPTR 4950 folder
base_dir = os.path.dirname(os.path.abspath(__file__))  # Get the directory of the current script
logs_dir = os.path.join(base_dir, "CPTR 4950", "logs")  # Create the path to the logs directory

# Ensure the 'logs' directory exists
os.makedirs(logs_dir, exist_ok=True)

# Initialize counters for analysis
packet_count = {"TCP": 0, "UDP": 0, "ICMP": 0}

# Log sniffing events to a text file
sniffing_log_file = os.path.join(logs_dir, "sniffing_log.txt")  # Path to sniffing_log.txt

# Function to analyze packets
def analyze_packet(packet):
    global packet_count
    packet_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))
    
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        if packet.haslayer(TCP):
            packet_count["TCP"] += 1
            tcp_flags = packet[TCP].flags
            if tcp_flags == 'S':  # SYN flag
                message = f"[ALERT] SYN Packet detected from {ip_src} to {ip_dst} at {packet_time}"
                log_event(sniffing_log_file, message, packet)
                
        elif packet.haslayer(UDP):
            packet_count["UDP"] += 1
            udp_len = packet[UDP].len
            if udp_len > 1500:  # Unusually large UDP packet
                message = f"[ALERT] Large UDP Packet detected from {ip_src} to {ip_dst} at {packet_time}"
                log_event(sniffing_log_file, message, packet)
                
        elif packet.haslayer(ICMP):
            packet_count["ICMP"] += 1
            icmp_type = packet[ICMP].type
            if icmp_type == 8:  # Echo Request (Ping)
                message = f"[INFO] ICMP Echo Request detected from {ip_src} to {ip_dst} at {packet_time}"
                log_event(sniffing_log_file, message, packet)
    
    # Packet count stats are for console output only and not logged
    if int(time.time()) % 10 == 0:
        stats_message = f"[STATS] TCP: {packet_count['TCP']} UDP: {packet_count['UDP']} ICMP: {packet_count['ICMP']}"
        print(stats_message)

# Log events to a file
def log_event(filename, message, packet=None):
    with open(filename, "a") as log_file:
        log_file.write(f"{message}\n")
        if packet:
            log_file.write(f"Packet Data: {packet.summary()}\n")
    print(message)  # Print to console for real-time feedback
    if packet:
        print(f"Packet Data: {packet.summary()}")

# Run all scenarios sequentially
def run_all_scenarios():
    syn_flood.syn_flood("192.168.1.1", 80, packet_count=50)  # Logs handled in `syn_flood.py`
    oversized_udp.send_large_udp("192.168.1.1", 53, size=1600, packet_count=5)  # Logs handled in `oversized_udp.py`
    ping_sweep.icmp_ping_sweep("192.168.1", start_range=1, end_range=10)  # Logs handled in `ping_sweep.py`

# Sniffing packets
def start_sniffing():
    print("Starting packet sniffing...")
    sniff(prn=analyze_packet, store=False, filter="ip", iface="Wi-Fi")

if __name__ == "__main__":
    sniffing_thread = threading.Thread(target=start_sniffing)
    sniffing_thread.start()
    run_all_scenarios()
    sniffing_thread.join()

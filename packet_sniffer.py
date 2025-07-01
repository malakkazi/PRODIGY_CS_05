from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import logging

# Set the log file name
log_file = "packets_log.txt"

# Configure logging
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# Function to handle and log each packet
def packet_handler(packet):
    try:
        # Extract IP layer
        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = "Other"
            port_info = ""

            # Check for TCP
            if TCP in packet:
                protocol = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                port_info = f"Ports: {sport} → {dport}"

            # Check for UDP
            elif UDP in packet:
                protocol = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                port_info = f"Ports: {sport} → {dport}"

            # Final log line
            log_line = f"{src_ip} → {dst_ip} | Protocol: {protocol} | {port_info}"
            print(log_line)
            logging.info(log_line)

    except Exception as e:
        print(f"[Error] {e}")
        logging.error(f"Error processing packet: {e}")

# Start sniffing (requires admin privileges)
print("🛡️  Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=packet_handler, store=0)

import os
import subprocess
import scapy.all as scapy
from scapy.packet import Raw
from scapy.utils import rdpcap
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import time
import threading
import watchdog.events
import watchdog.observers
import cv2
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage

# Function to capture traffic using tshark and save it to a PCAP file
def capture_traffic():
    command = "tshark -i Wi-Fi -a duration:2 -w capture.pcap"
    subprocess.run(command, shell=True)

# Function to analyze the PCAP file and detect threats
def analyze_pcap():
    # Load the PCAP file
    packets = rdpcap("capture.pcap")

    # Define the list of known malicious IP addresses
    malicious_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    # Define the list of suspicious ports
    suspicious_ports = [80, 443, 445, 1433, 3306]

    # Define the list of suspicious file types
    suspicious_file_types = [".exe", ".dll", ".bat", ".scr", ".jar", ".com"]

    # Define the dataset
    dataset = []

    # Loop through each packet in the PCAP file
    for packet in packets:
        # Check if the packet has a TCP or UDP layer
        if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
            # Get the source and destination IP addresses and ports
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            src_port = packet.getlayer(scapy.TCP).sport if packet.haslayer(scapy.TCP) else packet.getlayer(scapy.UDP).sport
            dst_port = packet.getlayer(scapy.TCP).dport if packet.haslayer(scapy.TCP) else packet.getlayer(scapy.UDP).dport

            # Check if the source or destination IP address is malicious
            if src_ip in malicious_ips or dst_ip in malicious_ips:
                dataset.append((src_ip, dst_ip, src_port, packet.haslayer(scapy.TCP), dst_port))

            # Check if the destination port is suspicious
            elif dst_port in suspicious_ports:
                dataset.append((src_ip, dst_ip, src_port, packet.haslayer(scapy.TCP), dst_port))

        # Check if the packet has a Raw layer
        elif packet.haslayer(scapy.Raw):
            # Get the payload and check if it has a suspicious file type
            payload = str(packet[scapy.Raw])
            for file_type in suspicious_file_types:
                if file_type in payload:
                    dataset.append((src_ip, dst_ip, src_port, packet.haslayer(scapy.TCP), dst_port))

    # Define the function to check if a packet is a network threat
    def is_threat(packet):
        src_ip, dst_ip, src_port, is_tcp, dst_port = packet
        if src_ip in malicious_ips or dst_ip in malicious_ips:
            return True
        if is_tcp and dst_port in suspicious_ports:
            return True
        return False

    # Check if any of the packets are network threats
    threats = [packet for packet in dataset if is_threat(packet)]
    return threats

# Function to read the pcap file using pyshark and convert it to a pandas DataFrame
def read_pcap(file_path):
    cap = pyshark.FileCapture(file_path)
    packets = []

    for packet in cap:
        try:
            packet_dict = {
                'src_ip': packet.ip.src if hasattr(packet, 'ip') else None,
                'dst_ip': packet.ip.dst if hasattr(packet, 'ip') else None,
                'protocol': packet.highest_layer,
                'packet_size': int(packet.length),
                'duration': float(packet.sniff_time.timestamp()),
                'src_port': int(packet[packet.transport_layer].srcport) if hasattr(packet, 'transport_layer') and packet.transport_layer else None,
                'dst_port': int(packet[packet.transport_layer].dstport) if hasattr(packet, 'transport_layer') and packet.transport_layer else None,
            }
            packets.append(packet_dict)
        except AttributeError:
            # Skip packets that do not have the required attributes
            continue

    return pd.DataFrame(packets)

class AdvancedThreatDetector:
    def __init__(self, packets):
        self.packets = packets

    def detect_anomalies(self):
        # Implement anomaly detection algorithms (e.g., clustering, statistical analysis)
        pass

    def detect_zero_day_attacks(self):
        zero_day_attacks = self.packets[(self.packets['protocol'] == 'unknown') & (self.packets['duration'] > 100)]
        return zero_day_attacks

    def detect_malware(self):
        malware = self.packets[(self.packets['packet_size'] > 10000) & (self.packets['duration'] < 10)]
        return malware

    def detect_sql_injection(self):
        sql_injection = self.packets[(self.packets['src_ip'] == '192.168.1.100') & (self.packets['dst_port'] == 1433)]
        return sql_injection

    def detect_https_threats(self):
        https_threats = self.packets[self.packets['dst_port'] == 443]
        return https_threats

class IncidentResponse:
    def __init__(self, alerts):
        self.alerts = alerts

    def automate_response(self):
        https_solution_given = False

        if self.alerts.empty:
            print("No threats detected.")
        else:
            for _, alert in self.alerts.iterrows():
                if alert['type'] == 'zero_day_attack':
                    print("Detected zero-day attack.")
                    print("Solution for zero-day attack: Isolate affected devices and gather data for analysis.")
                elif alert['type'] == 'malware':
                    print("Detected malware.")
                    print("Solution for malware: Quarantine affected devices and remove malware.")
                elif alert['type'] == 'sql_injection':
                    print("Detected SQL injection.")
                    print("Solution for SQL injection: Patch vulnerabilities and strengthen input validation.")
                elif alert['type'] == 'https_threat' and not https_solution_given:
                    print("Detected HTTPS threat.")
                    print("Solution for HTTPS threats: Implement SSL/TLS best practices and monitor certificates.")
                    https_solution_given = True

# Capture traffic for a specified duration
capture_traffic()

# Analyze the PCAP file for basic threats
threats = analyze_pcap()
threats_found = bool(threats)

if threats_found:
    print("Threats Found: Yes")
    print("The threats found are as follows: ")
else:
    print("Threats Found: No")

# Read the pcap file using pyshark for advanced threat detection
file_path = "capture.pcap"
packets_df = read_pcap(file_path)

# Initialize the AdvancedThreatDetector
advanced_threat_detector = AdvancedThreatDetector(packets_df)

# Detect threats
zero_day_attacks = advanced_threat_detector.detect_zero_day_attacks()
malware = advanced_threat_detector.detect_malware()
sql_injection = advanced_threat_detector.detect_sql_injection()
https_threats = advanced_threat_detector.detect_https_threats()

# Combine detected threats into a single DataFrame
alerts = pd.concat([zero_day_attacks, malware, sql_injection, https_threats], ignore_index=True)

# Add threat types to the alerts DataFrame
alerts['type'] = ['zero_day_attack'] * len(zero_day_attacks) + \
                 ['malware'] * len(malware) + \
                 ['sql_injection'] * len(sql_injection) + \
                 ['https_threat'] * len(https_threats)

# Display the table of detected threats
print("Detected Threats:")
print(alerts)

# Initialize IncidentResponse and automate responses
incident_response = IncidentResponse(alerts)
incident_response.automate_response()

# Generate a histogram of packet lengths using pyshark and matplotlib
def generate_packet_length_histogram(file_path, output_path):
    cap = pyshark.FileCapture(file_path)
    packet_lengths = [int(packet.length) for packet in cap]

    plt.hist(packet_lengths, bins=100)
    plt.title('Packet Length Distribution')
    plt.xlabel('Packet Length (bytes)')
    plt.ylabel('Frequency')
    plt.xscale('log')
    plt.savefig(output_path)
    plt.close()

# Path to save the histogram
output_path = "C:\\Users\\Pratik\\PratikProjects\\Major_Project1\\Network_Traffic_Graph.png"

# Generate and save the histogram
generate_packet_length_histogram(file_path, output_path)

# Folder monitoring functionality
# Email settings
FROM_EMAIL = "kirmadaaaaa@gmail.com"
TO_EMAIL = "pranvatsinghr@gmail.com"
PASSWORD = "uuhyrwxhzrftrkdx"

# Folder path to monitor
FOLDER_PATH = 'E:\\CEH_LABS_NOTES_SELF_MADE'

# Set the timeout to 5 minutes
timeout = 300  # 5 minutes in seconds

# Create a thread to monitor the folder
class FolderMonitor(watchdog.events.PatternMatchingEventHandler):
    def __init__(self, folder_path):
        watchdog.events.PatternMatchingEventHandler.__init__(self, patterns=['*'], ignore_directories=True)
        self.folder_path = folder_path
        self.picture_taken = False

    def on_modified(self, event):
        if not event.is_directory and not self.picture_taken:
            self.picture_taken = True
            # Take a picture
            cap = cv2.VideoCapture(0)
            ret, frame = cap.read()
            cv2.imwrite('picture.jpg', frame)
            cap.release()
            cv2.destroyAllWindows()

            # Compose the email
            msg = MIMEMultipart()
            msg['From'] = FROM_EMAIL
            msg['To'] = TO_EMAIL
            msg['Subject'] = "Intruder Alert"
            message = f"ALERT! Someone is trying to access the file named '{os.path.basename(event.src_path)}'\n"
            msg.attach(MIMEText(message, 'plain'))

            # Attach the picture to the email
            with open('picture.jpg', 'rb') as f:
                img = MIMEImage(f.read())
                img.add_header('Content-Disposition', 'attachment', filename='picture.jpg')
                msg.attach(img)

            # Send the email
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(FROM_EMAIL, PASSWORD)
            server.sendmail(FROM_EMAIL, TO_EMAIL, msg.as_string())
            server.quit() 

            print("Email sent with picture:", event.src_path)

# Create and start the observer
observer = watchdog.observers.Observer()
observer.schedule(FolderMonitor(FOLDER_PATH), FOLDER_PATH, recursive=False)
observer.start()

# Wait for 5 minutes or until manually stopped
try:
    time.sleep(timeout)
except KeyboardInterrupt:
    print("Monitoring stopped manually")

# Stop the observer
observer.stop()
observer.join()

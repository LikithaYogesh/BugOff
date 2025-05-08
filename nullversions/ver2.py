import os
import hashlib
import yara
import psutil
import time
import argparse
import requests
import logging
from scapy.all import sniff, IP
from tqdm import tqdm

# Configuration
MALWARE_DB_FILE = "malware_db.txt"
YARA_RULES_FILE = "malware_rules.yar"
LOG_FILE = "av_log.txt"
THREAT_FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_online/"  # Replace with a real threat intelligence feed

# Set up logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

# Load malware database
def load_malware_db():
    if os.path.exists(MALWARE_DB_FILE):
        with open(MALWARE_DB_FILE, "r") as f:
            return set(line.strip() for line in f)
    return set()

# Load YARA rules
def load_yara_rules():
    if os.path.exists(YARA_RULES_FILE):
        return yara.compile(filepath=YARA_RULES_FILE)
    return None

# Update malware database from threat feed
def update_malware_db():
    try:
        response = requests.get(THREAT_FEED_URL)
        if response.status_code == 200:
            with open(MALWARE_DB_FILE, "w") as f:
                f.write(response.text)
            print("[*] Malware database updated.")
        else:
            print("[!] Failed to update malware database.")
    except Exception as e:
        print(f"[!] Error updating malware database: {e}")

# Calculate file hash
def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Scan a file for malware
def scan_file(file_path, malware_db, yara_rules):
    # Signature-based detection
    file_hash = calculate_hash(file_path)
    if file_hash in malware_db:
        logging.warning(f"Malware detected: {file_path} (Hash: {file_hash})")
        print(f"[!] Malware detected: {file_path} (Hash: {file_hash})")
        return True

    # YARA rule-based detection
    if yara_rules:
        matches = yara_rules.match(file_path)
        if matches:
            logging.warning(f"YARA rule match: {file_path} (Rule: {matches})")
            print(f"[!] YARA rule match: {file_path} (Rule: {matches})")
            return True

    return False

# Monitor processes for suspicious behavior
def monitor_processes():
    suspicious_processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            # Example: Detect processes with suspicious names
            if "malware" in proc.info['name'].lower():
                logging.warning(f"Suspicious process detected: {proc.info['name']} (PID: {proc.info['pid']})")
                print(f"[!] Suspicious process detected: {proc.info['name']} (PID: {proc.info['pid']})")
                suspicious_processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return suspicious_processes

# Monitor network traffic for suspicious connections
def monitor_network():
    def packet_callback(packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            # Example: Detect connections to known malicious IPs
            if dst_ip in ["1.2.3.4", "5.6.7.8"]:  # Replace with a real blacklist
                logging.warning(f"Suspicious network connection: {src_ip} -> {dst_ip}")
                print(f"[!] Suspicious network connection: {src_ip} -> {dst_ip}")

    sniff(prn=packet_callback, count=10)  # Monitor 10 packets (adjust as needed)

# Inotify event handler for real-time monitoring
class EventHandler(pyinotify.ProcessEvent):
    def __init__(self, malware_db, yara_rules):
        self.malware_db = malware_db
        self.yara_rules = yara_rules

    def process_default(self, event):
        if event.maskname in ["IN_CREATE", "IN_MODIFY"]:
            print(f"[*] File created/modified: {event.pathname}")
            if scan_file(event.pathname, self.malware_db, self.yara_rules):
                print(f"[!] Threat detected in file: {event.pathname}")

# Start real-time monitoring
def start_monitoring(path_to_watch, malware_db, yara_rules):
    print(f"[*] Starting real-time monitoring on: {path_to_watch}")
    watch_manager = pyinotify.WatchManager()
    event_handler = EventHandler(malware_db, yara_rules)
    notifier = pyinotify.Notifier(watch_manager, event_handler)
    watch_manager.add_watch(path_to_watch, pyinotify.IN_CREATE | pyinotify.IN_MODIFY)

    while True:
        try:
            notifier.process_events()
            if notifier.check_events():
                notifier.read_events()
            monitor_processes()
            monitor_network()
            time.sleep(1)  # Reduce CPU usage
        except KeyboardInterrupt:
            print("\n[*] Stopping monitoring...")
            break

# Full system scan with anomaly detection
def anomaly_based_scan():
    print("[*] Starting anomaly-based system scan...")

    # Define suspicious file extensions
    SUSPICIOUS_EXTENSIONS = [".exe", ".dll", ".bat", ".sh", ".py", ".js"]
    # Define suspicious directories
    SUSPICIOUS_DIRECTORIES = ["/tmp", "/var/tmp", "/dev/shm"]
    # Define known malicious IPs (example)
    MALICIOUS_IPS = ["1.2.3.4", "5.6.7.8"]

    # Function to check for file anomalies
    def check_file_anomalies(file_path):
        # Check for suspicious extensions
        if any(file_path.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
            logging.warning(f"Suspicious file extension: {file_path}")
            print(f"[!] Suspicious file extension: {file_path}")

        # Check for files in suspicious directories
        if any(file_path.startswith(dir) for dir in SUSPICIOUS_DIRECTORIES):
            logging.warning(f"File in suspicious directory: {file_path}")
            print(f"[!] File in suspicious directory: {file_path}")

    # Function to check for process anomalies
    def check_process_anomalies():
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                # Check for processes running from suspicious directories
                if any(proc.info['exe'].startswith(dir) for dir in SUSPICIOUS_DIRECTORIES):
                    logging.warning(f"Suspicious process: {proc.info['name']} (PID: {proc.info['pid']})")
                    print(f"[!] Suspicious process: {proc.info['name']} (PID: {proc.info['pid']})")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

    # Function to check for network anomalies
    def check_network_anomalies():
        for conn in psutil.net_connections():
            if conn.status == psutil.CONN_ESTABLISHED:
                ip = conn.raddr.ip
                if ip in MALICIOUS_IPS:
                    logging.warning(f"Suspicious network connection: {ip}")
                    print(f"[!] Suspicious network connection: {ip}")

    # Count total files for progress bar
    total_files = 0
    for root, _, files in os.walk("/"):
        total_files += len(files)

    # Scan files with progress bar
    scanned_files = 0
    with tqdm(total=total_files, desc="Scanning files", unit="file") as pbar:
        for root, _, files in os.walk("/"):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    # Check for file anomalies
                    check_file_anomalies(file_path)
                except (PermissionError, FileNotFoundError, OSError) as e:
                    logging.warning(f"Skipped file: {file_path} (Error: {e})")
                    continue
                scanned_files += 1
                pbar.update(1)  # Update progress bar

    # Check for process and network anomalies
    check_process_anomalies()
    check_network_anomalies()

    print(f"[*] Anomaly-based system scan completed. Scanned {scanned_files} files.")

# Main function
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Custom Anti-Virus Tool")
    parser.add_argument("--scan", help="Scan a directory", type=str)
    parser.add_argument("--monitor", help="Monitor a directory in real-time", type=str)
    parser.add_argument("--update", help="Update malware database", action="store_true")
    parser.add_argument("--full-scan", help="Perform a full system scan", action="store_true")
    parser.add_argument("--anomaly-scan", help="Perform an anomaly-based system scan", action="store_true")
    args = parser.parse_args()

    malware_db = load_malware_db()
    yara_rules = load_yara_rules()

    if args.update:
        update_malware_db()
    elif args.scan:
        for root, _, files in os.walk(args.scan):
            for file in files:
                file_path = os.path.join(root, file)
                scan_file(file_path, malware_db, yara_rules)
    elif args.monitor:
        start_monitoring(args.monitor, malware_db, yara_rules)
    elif args.full_scan:
        full_system_scan(malware_db, yara_rules)
    elif args.anomaly_scan:
        anomaly_based_scan()
    else:
        print("Please specify an action (--scan, --monitor, --update, --full-scan, or --anomaly-scan).")
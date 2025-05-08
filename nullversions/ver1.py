import os
import hashlib
import yara
import psutil
import time
import argparse
import requests
import logging
import pyinotify
from scapy.all import sniff, IP
from tqdm import tqdm

# Configuration
MALWARE_DB_FILE = "malware_db.txt"
YARA_RULES_FILE = "malware_rules.yar"
LOG_FILE = "av_log.txt"
THREAT_FEED_URL = "https://example.com/threat-feed"  # Replace with a real threat intelligence feed

# Set up logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

# Load malware database
def load_malware_db():
    if os.path.exists(MALWARE_DB_FILE):
        with open(MALWARE_DB_FILE, "r") as f:
            db = set(line.strip() for line in f)
        print(f"[+] Loaded malware database with {len(db)} signatures")
        return db
    print("[!] Malware database not found, starting with empty database")
    return set()

# Load YARA rules
def load_yara_rules():
    if os.path.exists(YARA_RULES_FILE):
        rules = yara.compile(filepath=YARA_RULES_FILE)
        print(f"[+] Loaded YARA rules from {YARA_RULES_FILE}")
        return rules
    print("[!] YARA rules file not found")
    return None

# Update malware database from threat feed
def update_malware_db():
    try:
        print("[*] Contacting threat intelligence feed...")
        response = requests.get(THREAT_FEED_URL)
        if response.status_code == 200:
            signature_count = len(response.text.splitlines())
            with open(MALWARE_DB_FILE, "w") as f:
                f.write(response.text)
            print(f"[+] Malware database updated successfully with {signature_count} signatures")
            logging.info(f"Malware database updated with {signature_count} signatures")
            return True
        else:
            print(f"[!] Failed to update malware database. Server returned status code: {response.status_code}")
            logging.error(f"Failed to update malware database. Status code: {response.status_code}")
            return False
    except Exception as e:
        print(f"[!] Error updating malware database: {e}")
        logging.error(f"Error updating malware database: {e}")
        return False

# Calculate file hash
def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Scan a file for malware
def scan_file(file_path, malware_db, yara_rules):
    try:
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
    except Exception as e:
        logging.error(f"Error scanning file {file_path}: {e}")
        print(f"[!] Error scanning file {file_path}: {e}")
        return False

# Monitor processes for suspicious behavior
def monitor_processes():
    print("[*] Monitoring processes for suspicious behavior...")
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
    
    if not suspicious_processes:
        print("[+] No suspicious processes detected during this scan")
    else:
        print(f"[!] Found {len(suspicious_processes)} suspicious processes")
    
    return suspicious_processes

# Load malicious IPs
def load_malicious_ips():
    # This could be implemented to load from a file or database
    malicious_ips = ["1.2.3.4", "5.6.7.8"]  # Example IPs
    print(f"[+] Loaded {len(malicious_ips)} malicious IP addresses for network monitoring")
    return malicious_ips

# Monitor network traffic for suspicious connections
def monitor_network(malicious_ips=None):
    if malicious_ips is None:
        malicious_ips = load_malicious_ips()
    
    print("[*] Starting network traffic monitoring...")
    suspicious_connections = []
    
    def packet_callback(packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            # Check against loaded malicious IPs
            if dst_ip in malicious_ips:
                logging.warning(f"Suspicious network connection: {src_ip} -> {dst_ip}")
                print(f"[!] Suspicious network connection: {src_ip} -> {dst_ip}")
                suspicious_connections.append((src_ip, dst_ip))

    try:
        sniff(prn=packet_callback, count=10, timeout=5)  # Monitor 10 packets or 5 seconds
        if not suspicious_connections:
            print("[+] No suspicious network traffic detected during this scan")
        else:
            print(f"[!] Found {len(suspicious_connections)} suspicious network connections")
    except Exception as e:
        print(f"[!] Error monitoring network: {e}")
        logging.error(f"Error monitoring network: {e}")

# Inotify event handler for real-time monitoring
class EventHandler(pyinotify.ProcessEvent):
    def __init__(self, malware_db, yara_rules):
        self.malware_db = malware_db
        self.yara_rules = yara_rules
        self.events_processed = 0
        self.threats_detected = 0

    def process_default(self, event):
        self.events_processed += 1
        if event.maskname in ["IN_CREATE", "IN_MODIFY"]:
            print(f"[*] File created/modified: {event.pathname}")
            try:
                if scan_file(event.pathname, self.malware_db, self.yara_rules):
                    self.threats_detected += 1
                    print(f"[!] Threat detected in file: {event.pathname}")
                else:
                    print(f"[+] File scanned: {event.pathname} - No threats detected")
            except Exception as e:
                print(f"[!] Error scanning file {event.pathname}: {e}")
        
        # Print periodic status updates
        if self.events_processed % 10 == 0:
            print(f"[+] Monitoring status: Processed {self.events_processed} events, detected {self.threats_detected} threats")

# Start real-time monitoring
def start_monitoring(path_to_watch, malware_db, yara_rules):
    if not os.path.exists(path_to_watch):
        print(f"[!] Path not found: {path_to_watch}")
        return
    
    print(f"[*] Starting real-time monitoring on: {path_to_watch}")
    print("[*] Press Ctrl+C to stop monitoring")
    
    watch_manager = pyinotify.WatchManager()
    event_handler = EventHandler(malware_db, yara_rules)
    notifier = pyinotify.Notifier(watch_manager, event_handler)
    watch_descriptor = watch_manager.add_watch(path_to_watch, pyinotify.IN_CREATE | pyinotify.IN_MODIFY)
    
    if watch_descriptor[path_to_watch] > 0:
        print(f"[+] Successfully set up watch for: {path_to_watch}")
    else:
        print(f"[!] Failed to set up watch for: {path_to_watch}")
        return

    malicious_ips = load_malicious_ips()  # Load once at startup
    
    monitoring_start_time = time.time()
    last_status_update = monitoring_start_time
    
    try:
        while True:
            notifier.process_events()
            if notifier.check_events():
                notifier.read_events()
            
            # Run process and network monitoring periodically (every 30 seconds)
            current_time = time.time()
            if current_time - last_status_update >= 30:
                elapsed_time = current_time - monitoring_start_time
                print(f"[+] Monitoring active for {elapsed_time:.1f} seconds")
                monitor_processes()
                monitor_network(malicious_ips)
                last_status_update = current_time
            
            time.sleep(1)  # Reduce CPU usage
    except KeyboardInterrupt:
        print("\n[*] Stopping monitoring...")
        elapsed_time = time.time() - monitoring_start_time
        print(f"[+] Monitoring stopped after {elapsed_time:.1f} seconds")
        print(f"[+] Processed {event_handler.events_processed} file events")
        print(f"[+] Detected {event_handler.threats_detected} threats")
        watch_manager.rm_watch(watch_descriptor.values())
        print("[+] Watches removed")

# Full system scan
def full_system_scan(malware_db, yara_rules):
    print("[*] Starting full system scan...")
    start_time = time.time()
    excluded_dirs = ["/proc", "/sys", "/dev"]  # Directories to exclude

    # Count total files for progress bar
    print("[*] Counting files to scan (this may take a while)...")
    total_files = 0
    for root, _, files in os.walk("/"):
        if any(root.startswith(excluded) for excluded in excluded_dirs):
            continue
        total_files += len(files)

    print(f"[+] Found {total_files} files to scan")

    # Scan files with progress bar
    scanned_files = 0
    threats_found = 0
    skipped_files = 0
    
    with tqdm(total=total_files, desc="Scanning files", unit="file") as pbar:
        for root, _, files in os.walk("/"):
            if any(root.startswith(excluded) for excluded in excluded_dirs):
                continue
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    if scan_file(file_path, malware_db, yara_rules):
                        threats_found += 1
                except (PermissionError, FileNotFoundError, OSError):
                    skipped_files += 1
                    pass  # Skip files with permission issues or not found
                scanned_files += 1
                pbar.update(1)  # Update progress bar
                
                # Print periodic updates
                if scanned_files % 1000 == 0:
                    elapsed_time = time.time() - start_time
                    print(f"[+] Progress update: Scanned {scanned_files}/{total_files} files, found {threats_found} threats, elapsed time: {elapsed_time:.1f} seconds")

    elapsed_time = time.time() - start_time
    print(f"[+] Full system scan completed in {elapsed_time:.1f} seconds")
    print(f"[+] Scanned {scanned_files} files")
    print(f"[+] Skipped {skipped_files} files due to permissions or errors")
    print(f"[+] Found {threats_found} threats")
    
    if threats_found > 0:
        print("[!] Threats were detected during the scan. Check the log file for details.")
    else:
        print("[+] No threats were detected during the scan.")
    
    return threats_found

# Full system scan with anomaly detection
def anomaly_based_scan():
    print("[*] Starting anomaly-based system scan...")
    start_time = time.time()

    # Define suspicious file extensions
    SUSPICIOUS_EXTENSIONS = [".exe", ".dll", ".bat", ".sh", ".py", ".js"]
    # Define suspicious directories
    SUSPICIOUS_DIRECTORIES = ["/tmp", "/var/tmp", "/dev/shm"]
    # Define known malicious IPs (example)
    MALICIOUS_IPS = ["1.2.3.4", "5.6.7.8"]

    # Function to check for file anomalies
    def check_file_anomalies(file_path):
        anomalies = []
        
        # Check for suspicious extensions
        if any(file_path.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
            anomaly = f"Suspicious file extension: {file_path}"
            logging.warning(anomaly)
            print(f"[!] {anomaly}")
            anomalies.append(anomaly)

        # Check for files in suspicious directories
        if any(file_path.startswith(dir) for dir in SUSPICIOUS_DIRECTORIES):
            anomaly = f"File in suspicious directory: {file_path}"
            logging.warning(anomaly)
            print(f"[!] {anomaly}")
            anomalies.append(anomaly)
            
        return anomalies

    # Function to check for process anomalies
    def check_process_anomalies():
        anomalies = []
        
        print("[*] Checking for process anomalies...")
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                # Check for processes running from suspicious directories
                if proc.info['exe'] and any(proc.info['exe'].startswith(dir) for dir in SUSPICIOUS_DIRECTORIES):
                    anomaly = f"Suspicious process: {proc.info['name']} (PID: {proc.info['pid']}, Path: {proc.info['exe']})"
                    logging.warning(anomaly)
                    print(f"[!] {anomaly}")
                    anomalies.append(anomaly)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, AttributeError):
                pass
                
        if anomalies:
            print(f"[!] Found {len(anomalies)} process anomalies")
        else:
            print("[+] No process anomalies detected")
        
        return anomalies

    # Function to check for network anomalies
    def check_network_anomalies():
        anomalies = []
        
        print("[*] Checking for network anomalies...")
        for conn in psutil.net_connections():
            if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                ip = conn.raddr.ip
                if ip in MALICIOUS_IPS:
                    anomaly = f"Suspicious network connection: {ip} from PID {conn.pid}"
                    logging.warning(anomaly)
                    print(f"[!] {anomaly}")
                    anomalies.append(anomaly)
        
        if anomalies:
            print(f"[!] Found {len(anomalies)} network anomalies")
        else:
            print("[+] No network anomalies detected")
        
        return anomalies

    # Count total files for progress bar (limiting to common directories for speed)
    print("[*] Counting files for scanning...")
    total_files = 0
    common_dirs = ["/home", "/usr", "/var", "/opt", "/tmp"]
    excluded_dirs = ["/proc", "/sys", "/dev"]
    
    for base_dir in common_dirs:
        if os.path.exists(base_dir):
            for root, _, files in os.walk(base_dir):
                if any(root.startswith(excluded) for excluded in excluded_dirs):
                    continue
                total_files += len(files)

    print(f"[+] Found approximately {total_files} files to scan")

    # Scan files with progress bar
    scanned_files = 0
    file_anomalies = []
    skipped_files = 0
    
    print("[*] Scanning files for anomalies...")
    with tqdm(total=total_files, desc="Scanning files", unit="file") as pbar:
        for base_dir in common_dirs:
            if os.path.exists(base_dir):
                for root, _, files in os.walk(base_dir):
                    if any(root.startswith(excluded) for excluded in excluded_dirs):
                        continue
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            # Check for file anomalies
                            anomalies = check_file_anomalies(file_path)
                            if anomalies:
                                file_anomalies.extend(anomalies)
                        except (PermissionError, FileNotFoundError, OSError):
                            skipped_files += 1
                        scanned_files += 1
                        pbar.update(1)  # Update progress bar
                        
                        # Print periodic updates
                        if scanned_files % 1000 == 0:
                            print(f"[+] Progress update: Scanned {scanned_files}/{total_files} files, found {len(file_anomalies)} anomalies")

    process_anomalies = check_process_anomalies()
    network_anomalies = check_network_anomalies()
    
    total_anomalies = len(file_anomalies) + len(process_anomalies) + len(network_anomalies)
    
    elapsed_time = time.time() - start_time
    print(f"[+] Anomaly-based system scan completed in {elapsed_time:.1f} seconds")
    print(f"[+] Scanned {scanned_files} files, skipped {skipped_files} files due to errors")
    print(f"[+] Found {total_anomalies} total anomalies:")
    print(f"  - {len(file_anomalies)} file anomalies")
    print(f"  - {len(process_anomalies)} process anomalies")
    print(f"  - {len(network_anomalies)} network anomalies")
    
    if total_anomalies > 0:
        print("[!] Anomalies were detected. Check the log file for details.")
    else:
        print("[+] No anomalies were detected during the scan.")
    
    return total_anomalies

# Main function
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Custom Anti-Virus Tool")
    parser.add_argument("--scan", help="Scan a directory", type=str)
    parser.add_argument("--monitor", help="Monitor a directory in real-time", type=str)
    parser.add_argument("--update", help="Update malware database", action="store_true")
    parser.add_argument("--full-scan", help="Perform a full system scan", action="store_true")
    parser.add_argument("--anomaly-scan", help="Perform an anomaly-based system scan", action="store_true")
    args = parser.parse_args()

    print("=" * 60)
    print(" Custom Anti-Virus Tool")
    print("=" * 60)
    
    start_time = time.time()
    
    print("[*] Loading malware signatures and YARA rules...")
    malware_db = load_malware_db()
    yara_rules = load_yara_rules()
    print(f"[+] Initialization complete")

    if args.update:
        print("[*] Running database update...")
        result = update_malware_db()
        if result:
            print("[+] Database update completed successfully")
        else:
            print("[!] Database update failed")
    elif args.scan:
        if not os.path.exists(args.scan):
            print(f"[!] Path not found: {args.scan}")
        else:
            print(f"[*] Scanning directory: {args.scan}")
            scanned_files = 0
            detected_threats = 0
            
            for root, _, files in os.walk(args.scan):
                for file in files:
                    file_path = os.path.join(root, file)
                    scanned_files += 1
                    try:
                        if scan_file(file_path, malware_db, yara_rules):
                            detected_threats += 1
                    except (PermissionError, FileNotFoundError, OSError) as e:
                        print(f"[!] Error scanning {file_path}: {e}")
            
            print(f"[+] Scan completed")
            print(f"[+] Scanned {scanned_files} files")
            print(f"[+] Detected {detected_threats} threats")
            
            if detected_threats > 0:
                print("[!] Threats were detected during the scan. Check the log file for details.")
            else:
                print("[+] No threats were detected during the scan.")
    elif args.monitor:
        start_monitoring(args.monitor, malware_db, yara_rules)
    elif args.full_scan:
        full_system_scan(malware_db, yara_rules)
    elif args.anomaly_scan:
        anomaly_based_scan()
    else:
        print("[!] Please specify an action (--scan, --monitor, --update, --full-scan, or --anomaly-scan).")
        parser.print_help()
    
    elapsed_time = time.time() - start_time
    print(f"[+] Total execution time: {elapsed_time:.2f} seconds")
    print("=" * 60)
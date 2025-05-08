#!/usr/bin/env python3
import os
import hashlib
import yara
import psutil
import time
import argparse
import requests
import logging
import csv
from scapy.all import sniff, IP
from tqdm import tqdm
import pyinotify

# ===== CONFIGURATION =====
MALWARE_DB_FILE = "malware_db.txt"
YARA_RULES_FILE = "malware_rules.yar"
LOG_FILE = "av.log"
THREAT_FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_online/"
SCAN_EXCLUSIONS = ["/proc", "/sys", "/dev", "/run"]  # Directories to exclude
SUSPICIOUS_EXTENSIONS = [".exe", ".dll", ".bat", ".sh", ".py", ".js"]
SUSPICIOUS_DIRECTORIES = ["/tmp", "/var/tmp", "/dev/shm"]
MALICIOUS_IPS = ["1.2.3.4", "5.6.7.8"]  # Replace with real threat intel
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

# ===== LOGGING SETUP =====
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ===== DATABASE FUNCTIONS =====
def load_malware_db():
    """Load malware hashes from database file"""
    try:
        if os.path.exists(MALWARE_DB_FILE):
            with open(MALWARE_DB_FILE, "r") as f:
                db = set(line.strip() for line in f if line.strip())
            print(f"[+] Successfully loaded {len(db)} malware signatures")
            return db
        print("[-] Malware database not found. Use --update to create it.")
        return set()
    except Exception as e:
        logger.error(f"Error loading malware DB: {str(e)}")
        print(f"[!] Error loading malware database: {str(e)}")
        return set()

def load_yara_rules():
    """Load YARA rules with error handling"""
    try:
        if os.path.exists(YARA_RULES_FILE):
            rules = yara.compile(filepath=YARA_RULES_FILE)
            print(f"[+] Successfully loaded YARA rules from {YARA_RULES_FILE}")
            return rules
        print("[-] YARA rules file not found")
        return None
    except yara.Error as e:
        logger.error(f"YARA rules error: {str(e)}")
        print(f"[!] Error loading YARA rules: {str(e)}")
        return None

def update_malware_db():
    """Update malware database from threat feed"""
    try:
        print("[*] Starting malware database update...")
        logger.info("Starting malware database update")
        response = requests.get(THREAT_FEED_URL, timeout=30)
        if response.status_code == 200:
            csv_reader = csv.DictReader(response.text.splitlines())
            hashes = set()
            
            for row in csv_reader:
                if 'sha256_hash' in row and row['sha256_hash']:
                    hashes.add(row['sha256_hash'].strip())
            
            with open(MALWARE_DB_FILE, "w") as f:
                f.write("\n".join(hashes))
            
            logger.info(f"Updated malware DB with {len(hashes)} hashes")
            print(f"[+] Malware database updated successfully: {len(hashes)} signatures downloaded")
            return True
            
        logger.error(f"Failed to fetch threat feed: HTTP {response.status_code}")
        print(f"[-] Database update failed: HTTP {response.status_code}")
        return False
    except Exception as e:
        logger.error(f"Error updating malware DB: {str(e)}")
        print(f"[!] Database update error: {str(e)}")
        return False

# ===== SCANNING FUNCTIONS =====
def calculate_hash(file_path):
    """Calculate file hash with error handling"""
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (IOError, OSError) as e:
        logger.debug(f"Could not hash {file_path}: {str(e)}")
        return None

def scan_file(file_path, malware_db, yara_rules):
    """Scan individual file for threats"""
    try:
        # Skip directories and special files
        if not os.path.isfile(file_path):
            return False
            
        # Skip large files
        if os.path.getsize(file_path) > MAX_FILE_SIZE:
            logger.debug(f"Skipping large file: {file_path}")
            return False
            
        # Signature check
        if file_hash := calculate_hash(file_path):
            if file_hash in malware_db:
                logger.warning(f"Malware detected: {file_path} (Hash: {file_hash})")
                print(f"[!] Malware detected: {file_path}")
                print(f"    - Threat detected by hash signature match")
                return True
                
        # YARA check
        if yara_rules:
            try:
                if matches := yara_rules.match(file_path):
                    logger.warning(f"YARA match: {file_path} (Rule: {matches})")
                    print(f"[!] YARA rule match: {file_path}")
                    print(f"    - Matched rules: {', '.join(match.rule for match in matches)}")
                    return True
            except yara.Error as e:
                logger.debug(f"YARA error on {file_path}: {str(e)}")
                
        return False
    except Exception as e:
        logger.error(f"Scan error on {file_path}: {str(e)}")
        print(f"[!] Error scanning {file_path}: {str(e)}")
        return False

def directory_scan(path, malware_db, yara_rules):
    """Scan a specific directory"""
    if not os.path.isdir(path):
        logger.error(f"Invalid directory: {path}")
        print(f"[-] Error: {path} is not a valid directory")
        return
        
    print(f"[*] Scanning directory: {path}")
    files_scanned = 0
    threats_found = 0
    
    try:
        for root, _, files in os.walk(path):
            # Skip excluded directories
            if any(root.startswith(excl) for excl in SCAN_EXCLUSIONS):
                continue
                
            for file in files:
                file_path = os.path.join(root, file)
                files_scanned += 1
                if files_scanned % 100 == 0:
                    print(f"[*] Progress: {files_scanned} files scanned...")
                
                if scan_file(file_path, malware_db, yara_rules):
                    threats_found += 1
                    
        print(f"[+] Scan complete: {files_scanned} files scanned, {threats_found} threats detected")
        logger.info(f"Directory scan completed on {path}: {files_scanned} files, {threats_found} threats")
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        print(f"[!] Scan error: {str(e)}")

# ===== ANOMALY DETECTION =====
def detect_file_anomalies(file_path):
    """Check for suspicious file characteristics"""
    try:
        anomalies = []
        
        # Check extensions
        if any(file_path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
            logger.warning(f"Suspicious extension: {file_path}")
            anomalies.append("suspicious extension")
            
        # Check locations
        if any(file_path.startswith(dir) for dir in SUSPICIOUS_DIRECTORIES):
            logger.warning(f"Suspicious location: {file_path}")
            anomalies.append("suspicious location")
            
        if anomalies:
            print(f"[!] Anomaly detected: {file_path}")
            print(f"    - Reasons: {', '.join(anomalies)}")
            return True
            
        return False
    except Exception as e:
        logger.error(f"Anomaly check error: {str(e)}")
        return False

def detect_process_anomalies():
    """Check for suspicious processes"""
    anomalies_found = 0
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            process_anomalies = []
            
            # Check suspicious locations
            if proc.info['exe'] and any(proc.info['exe'].startswith(dir) for dir in SUSPICIOUS_DIRECTORIES):
                logger.warning(f"Suspicious process: {proc.info['name']} (PID: {proc.info['pid']})")
                process_anomalies.append("running from suspicious location")
                
            # Check suspicious command lines
            if proc.info['cmdline'] and any("malware" in cmd.lower() for cmd in proc.info['cmdline']):
                logger.warning(f"Suspicious command line: {proc.info['cmdline']}")
                process_anomalies.append("suspicious command line parameters")
                
            if process_anomalies:
                print(f"[!] Suspicious process: {proc.info['name']} (PID: {proc.info['pid']})")
                print(f"    - Reasons: {', '.join(process_anomalies)}")
                anomalies_found += 1
                
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
            
    return anomalies_found

def detect_network_anomalies():
    """Check for suspicious network activity"""
    try:
        anomalies_found = 0
        for conn in psutil.net_connections():
            if conn.status == psutil.CONN_ESTABLISHED and hasattr(conn.raddr, 'ip'):
                if conn.raddr.ip in MALICIOUS_IPS:
                    logger.warning(f"Suspicious connection to {conn.raddr.ip}")
                    print(f"[!] Suspicious connection detected:")
                    print(f"    - Local:  {conn.laddr.ip}:{conn.laddr.port}")
                    print(f"    - Remote: {conn.raddr.ip}:{conn.raddr.port} (KNOWN MALICIOUS)")
                    if conn.pid:
                        try:
                            process = psutil.Process(conn.pid)
                            print(f"    - Process: {process.name()} (PID: {conn.pid})")
                        except psutil.NoSuchProcess:
                            print(f"    - Process: Unknown (PID: {conn.pid})")
                    anomalies_found += 1
        return anomalies_found
    except Exception as e:
        logger.error(f"Network check error: {str(e)}")
        print(f"[!] Network check error: {str(e)}")
        return 0

def anomaly_scan():
    """Perform comprehensive anomaly detection"""
    print("[*] Starting anomaly scan...")
    
    file_anomalies = 0
    total_files_checked = 0
    
    # File system anomalies
    print("[*] Scanning for file system anomalies...")
    for root, _, files in os.walk("/"):
        if any(root.startswith(excl) for excl in SCAN_EXCLUSIONS):
            continue
            
        for file in files:
            total_files_checked += 1
            file_path = os.path.join(root, file)
            if detect_file_anomalies(file_path):
                file_anomalies += 1
                
            if total_files_checked % 1000 == 0:
                print(f"[*] Checked {total_files_checked} files...")
    
    # Process anomalies
    print("[*] Scanning for process anomalies...")
    process_anomalies = detect_process_anomalies()
    
    # Network anomalies
    print("[*] Scanning for network anomalies...")
    network_anomalies = detect_network_anomalies()
    
    # Report results
    print("\n[+] Anomaly scan completed")
    print(f"    - Files checked: {total_files_checked}")
    print(f"    - File anomalies: {file_anomalies}")
    print(f"    - Process anomalies: {process_anomalies}")
    print(f"    - Network anomalies: {network_anomalies}")
    print(f"    - Total anomalies: {file_anomalies + process_anomalies + network_anomalies}")
    
    logger.info(f"Anomaly scan completed: {file_anomalies} file, {process_anomalies} process, {network_anomalies} network anomalies")

# ===== REAL-TIME MONITORING =====
class FileEventHandler(pyinotify.ProcessEvent):
    """Handler for real-time file system events"""
    def __init__(self, malware_db, yara_rules):
        self.malware_db = malware_db
        self.yara_rules = yara_rules
        self.events_processed = 0
        self.threats_detected = 0

    def process_IN_CREATE(self, event):
        self.process_file_event(event, "created")

    def process_IN_MODIFY(self, event):
        self.process_file_event(event, "modified")

    def process_file_event(self, event, action):
        file_path = event.pathname
        self.events_processed += 1
        print(f"[*] File {action}: {file_path}")
        if scan_file(file_path, self.malware_db, self.yara_rules):
            self.threats_detected += 1
            print(f"[!] Threat detected in {action} file: {file_path}")
        
        # Periodically report statistics
        if self.events_processed % 10 == 0:
            print(f"[*] Monitoring status: {self.events_processed} events processed, {self.threats_detected} threats detected")

def start_monitoring(path_to_watch):
    """Start real-time file monitoring"""
    if not os.path.isdir(path_to_watch):
        print(f"[-] Error: {path_to_watch} is not a valid directory")
        return
        
    print(f"[*] Starting real-time monitoring on: {path_to_watch}")
    
    malware_db = load_malware_db()
    yara_rules = load_yara_rules()
    
    # Initialize watcher
    watch_manager = pyinotify.WatchManager()
    event_handler = FileEventHandler(malware_db, yara_rules)
    notifier = pyinotify.Notifier(watch_manager, event_handler)
    
    try:
        # Add watch
        mask = pyinotify.IN_CREATE | pyinotify.IN_MODIFY
        watch_descriptor = watch_manager.add_watch(path_to_watch, mask, rec=True)
        
        if watch_descriptor[path_to_watch] > 0:
            print(f"[+] Successfully established watch on {path_to_watch}")
        else:
            print(f"[-] Failed to establish watch on {path_to_watch}")
            return
            
        # Report monitoring started
        print("[+] Real-time monitoring active")
        print("    - Press Ctrl+C to stop monitoring")
        
        # Start monitoring loop
        network_check_counter = 0
        process_check_counter = 0
        
        while True:
            notifier.process_events()
            if notifier.check_events():
                notifier.read_events()
            
            # Also check for process/network anomalies periodically
            network_check_counter += 1
            process_check_counter += 1
            
            if process_check_counter >= 60:  # Check processes every minute
                process_check_counter = 0
                anomalies = detect_process_anomalies()
                if anomalies > 0:
                    print(f"[!] Detected {anomalies} suspicious processes during periodic check")
                    
            if network_check_counter >= 300:  # Check network every 5 minutes
                network_check_counter = 0
                anomalies = detect_network_anomalies()
                if anomalies > 0:
                    print(f"[!] Detected {anomalies} suspicious network connections during periodic check")
            
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Monitoring stopped by user")
        print(f"    - Events processed: {event_handler.events_processed}")
        print(f"    - Threats detected: {event_handler.threats_detected}")
    except Exception as e:
        logger.error(f"Monitoring error: {str(e)}")
        print(f"[!] Monitoring error: {str(e)}")

# ===== MAIN FUNCTION =====
def main():
    parser = argparse.ArgumentParser(
        description="Custom Anti-Virus System",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--scan",
        help="Scan a specific directory",
        metavar="DIRECTORY"
    )
    parser.add_argument(
        "--monitor",
        help="Monitor a directory in real-time",
        metavar="DIRECTORY"
    )
    parser.add_argument(
        "--update",
        help="Update malware signatures database",
        action="store_true"
    )
    parser.add_argument(
        "--full-scan",
        help="Perform full system scan",
        action="store_true"
    )
    parser.add_argument(
        "--anomaly-scan",
        help="Perform anomaly detection scan",
        action="store_true"
    )
    
    args = parser.parse_args()
    
    # Print banner
    print("=" * 60)
    print("Custom Anti-Virus System")
    print("=" * 60)
    
    try:
        if args.update:
            if update_malware_db():
                print("[+] Database update completed successfully")
            else:
                print("[-] Database update failed")
                
        elif args.scan:
            print(f"[*] Initializing scan of {args.scan}")
            malware_db = load_malware_db()
            yara_rules = load_yara_rules()
            directory_scan(args.scan, malware_db, yara_rules)
            print("[+] Scan completed")
            
        elif args.monitor:
            start_monitoring(args.monitor)
            
        elif args.full_scan:
            print("[*] Starting full system scan (this may take a while)...")
            malware_db = load_malware_db()
            yara_rules = load_yara_rules()
            directory_scan("/", malware_db, yara_rules)
            print("[+] Full system scan completed")
            
        elif args.anomaly_scan:
            anomaly_scan()
            
        else:
            parser.print_help()
            print("\n[*] No action specified. Use one of the options above.")
            
    except KeyboardInterrupt:
        print("\n[!] Operation interrupted by user")
    except Exception as e:
        logger.critical(f"Fatal error: {str(e)}")
        print(f"[!] Fatal error: {str(e)}")
        raise

if __name__ == "__main__":
    main()
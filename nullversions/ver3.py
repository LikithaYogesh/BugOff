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
MALWARE_DB_FILE = "/opt/custom_av/malware_db.txt"
YARA_RULES_FILE = "/opt/custom_av/malware_rules.yar"
LOG_FILE = "/var/log/custom_av.log"
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
                return set(line.strip() for line in f if line.strip())
        return set()
    except Exception as e:
        logger.error(f"Error loading malware DB: {str(e)}")
        return set()

def load_yara_rules():
    """Load YARA rules with error handling"""
    try:
        if os.path.exists(YARA_RULES_FILE):
            return yara.compile(filepath=YARA_RULES_FILE)
        return None
    except yara.Error as e:
        logger.error(f"YARA rules error: {str(e)}")
        return None

def update_malware_db():
    """Update malware database from threat feed"""
    try:
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
            print(f"[*] Malware database updated with {len(hashes)} signatures")
            return True
            
        logger.error(f"Failed to fetch threat feed: HTTP {response.status_code}")
        return False
    except Exception as e:
        logger.error(f"Error updating malware DB: {str(e)}")
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
                return True
                
        # YARA check
        if yara_rules:
            try:
                if matches := yara_rules.match(file_path):
                    logger.warning(f"YARA match: {file_path} (Rule: {matches})")
                    print(f"[!] YARA rule match: {file_path}")
                    return True
            except yara.Error as e:
                logger.debug(f"YARA error on {file_path}: {str(e)}")
                
        return False
    except Exception as e:
        logger.error(f"Scan error on {file_path}: {str(e)}")
        return False

def directory_scan(path, malware_db, yara_rules):
    """Scan a specific directory"""
    if not os.path.isdir(path):
        logger.error(f"Invalid directory: {path}")
        return
        
    print(f"[*] Scanning directory: {path}")
    for root, _, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            scan_file(file_path, malware_db, yara_rules)

# ===== ANOMALY DETECTION =====
def detect_file_anomalies(file_path):
    """Check for suspicious file characteristics"""
    try:
        # Check extensions
        if any(file_path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
            logger.warning(f"Suspicious extension: {file_path}")
            print(f"[!] Suspicious extension: {file_path}")
            
        # Check locations
        if any(file_path.startswith(dir) for dir in SUSPICIOUS_DIRECTORIES):
            logger.warning(f"Suspicious location: {file_path}")
            print(f"[!] Suspicious location: {file_path}")
            
    except Exception as e:
        logger.error(f"Anomaly check error: {str(e)}")

def detect_process_anomalies():
    """Check for suspicious processes"""
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            # Check suspicious locations
            if proc.info['exe'] and any(proc.info['exe'].startswith(dir) for dir in SUSPICIOUS_DIRECTORIES):
                logger.warning(f"Suspicious process: {proc.info['name']} (PID: {proc.info['pid']})")
                print(f"[!] Suspicious process: {proc.info['name']}")
                
            # Check suspicious command lines
            if proc.info['cmdline'] and any("malware" in cmd.lower() for cmd in proc.info['cmdline']):
                logger.warning(f"Suspicious command line: {proc.info['cmdline']}")
                print(f"[!] Suspicious command line: {' '.join(proc.info['cmdline'])}")
                
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def detect_network_anomalies():
    """Check for suspicious network activity"""
    try:
        for conn in psutil.net_connections():
            if conn.status == psutil.CONN_ESTABLISHED and hasattr(conn.raddr, 'ip'):
                if conn.raddr.ip in MALICIOUS_IPS:
                    logger.warning(f"Suspicious connection to {conn.raddr.ip}")
                    print(f"[!] Suspicious connection to {conn.raddr.ip}")
    except Exception as e:
        logger.error(f"Network check error: {str(e)}")

def anomaly_scan():
    """Perform comprehensive anomaly detection"""
    print("[*] Starting anomaly scan...")
    
    # File system anomalies
    for root, _, files in os.walk("/"):
        if any(root.startswith(excl) for excl in SCAN_EXCLUSIONS):
            continue
            
        for file in files:
            file_path = os.path.join(root, file)
            detect_file_anomalies(file_path)
    
    # Process anomalies
    detect_process_anomalies()
    
    # Network anomalies
    detect_network_anomalies()
    
    print("[*] Anomaly scan completed")

# ===== REAL-TIME MONITORING =====
class FileEventHandler(pyinotify.ProcessEvent):
    """Handler for real-time file system events"""
    def __init__(self, malware_db, yara_rules):
        self.malware_db = malware_db
        self.yara_rules = yara_rules

    def process_IN_CREATE(self, event):
        self.process_file_event(event, "created")

    def process_IN_MODIFY(self, event):
        self.process_file_event(event, "modified")

    def process_file_event(self, event, action):
        file_path = event.pathname
        print(f"[*] File {action}: {file_path}")
        if scan_file(file_path, self.malware_db, self.yara_rules):
            print(f"[!] Threat detected in {action} file: {file_path}")

def start_monitoring(path_to_watch):
    """Start real-time file monitoring"""
    print(f"[*] Starting real-time monitoring on: {path_to_watch}")
    
    malware_db = load_malware_db()
    yara_rules = load_yara_rules()
    
    # Initialize watcher
    watch_manager = pyinotify.WatchManager()
    event_handler = FileEventHandler(malware_db, yara_rules)
    notifier = pyinotify.Notifier(watch_manager, event_handler)
    
    # Add watch
    watch_manager.add_watch(
        path_to_watch,
        pyinotify.IN_CREATE | pyinotify.IN_MODIFY,
        rec=True
    )
    
    # Start monitoring loop
    try:
        while True:
            notifier.process_events()
            if notifier.check_events():
                notifier.read_events()
            
            # Also check for process/network anomalies periodically
            detect_process_anomalies()
            detect_network_anomalies()
            
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping monitoring...")
    except Exception as e:
        logger.error(f"Monitoring error: {str(e)}")

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
    
    try:
        malware_db = load_malware_db()
        yara_rules = load_yara_rules()
        
        if args.update:
            update_malware_db()
        elif args.scan:
            directory_scan(args.scan, malware_db, yara_rules)
        elif args.monitor:
            start_monitoring(args.monitor)
        elif args.full_scan:
            print("[*] Starting full system scan (this may take a while)...")
            directory_scan("/", malware_db, yara_rules)
        elif args.anomaly_scan:
            anomaly_scan()
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        logger.critical(f"Fatal error: {str(e)}")
        raise

if __name__ == "__main__":
    main()
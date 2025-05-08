import os
import psutil
import logging
from tqdm import tqdm

# Set up logging
logging.basicConfig(filename="anomaly_scan.log", level=logging.INFO, format="%(asctime)s - %(message)s")

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

# Full system scan with anomaly detection
def full_system_scan():
    print("[*] Starting full system scan with anomaly detection...")

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

    print(f"[*] Full system scan completed. Scanned {scanned_files} files.")

# Main function
if __name__ == "__main__":
    full_system_scan()
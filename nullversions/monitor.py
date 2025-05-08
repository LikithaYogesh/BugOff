import pyinotify
import os
import hashlib
import yara
import psutil
import time

# Load YARA rules
RULES = yara.compile(filepath="malware_rules.yar")

# Database of known malware hashes
MALWARE_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # Example hash (empty file)
}

# Function to calculate SHA-256 hash of a file
def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Function to scan a file for malware
def scan_file(file_path):
    # Signature-based detection
    file_hash = calculate_hash(file_path)
    if file_hash in MALWARE_HASHES:
        print(f"[!] Malware detected: {file_path} (Hash: {file_hash})")
        return True

    # YARA rule-based detection
    matches = RULES.match(file_path)
    if matches:
        print(f"[!] YARA rule match: {file_path} (Rule: {matches})")
        return True

    return False

# Function to monitor processes for suspicious behavior
def monitor_processes():
    suspicious_processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            # Example: Detect processes with suspicious names
            if "malware" in proc.info['name'].lower():
                print(f"[!] Suspicious process detected: {proc.info['name']} (PID: {proc.info['pid']})")
                suspicious_processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return suspicious_processes

# Inotify event handler
class EventHandler(pyinotify.ProcessEvent):
    def process_default(self, event):
        if event.maskname == "IN_CREATE" or event.maskname == "IN_MODIFY":
            print(f"[*] File created/modified: {event.pathname}")
            if scan_file(event.pathname):
                print(f"[!] Threat detected in file: {event.pathname}")

# Start real-time monitoring
def start_monitoring(path_to_watch):
    print(f"[*] Starting real-time monitoring on: {path_to_watch}")
    watch_manager = pyinotify.WatchManager()
    event_handler = EventHandler()
    notifier = pyinotify.Notifier(watch_manager, event_handler)
    watch_manager.add_watch(path_to_watch, pyinotify.IN_CREATE | pyinotify.IN_MODIFY)

    while True:
        try:
            notifier.process_events()
            if notifier.check_events():
                notifier.read_events()
            monitor_processes()
            time.sleep(1)  # Reduce CPU usage
        except KeyboardInterrupt:
            print("\n[*] Stopping monitoring...")
            break

# Main function
if __name__ == "__main__":
    path_to_watch = input("Enter the directory to monitor: ")
    if os.path.isdir(path_to_watch):
        start_monitoring(path_to_watch)
    else:
        print("Invalid directory path.")
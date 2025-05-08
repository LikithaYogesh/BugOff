import os
import hashlib

# Database of known malware hashes (SHA-256)
MALWARE_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # Example hash (empty file)
    # Add more malware hashes here
}

# Function to calculate SHA-256 hash of a file
def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b"":
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Function to scan a directory for malware
def scan_directory(directory):
    infected_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = calculate_hash(file_path)
            if file_hash in MALWARE_HASHES:
                print(f"Malware detected: {file_path} (Hash: {file_hash})")
                infected_files.append(file_path)
    return infected_files

# Main function
if __name__ == "__main__":
    directory_to_scan = input("Enter the directory to scan: ")
    if os.path.isdir(directory_to_scan):
        print(f"Scanning directory: {directory_to_scan}")
        infected_files = scan_directory(directory_to_scan)
        if not infected_files:
            print("No malware detected.")
    else:
        print("Invalid directory path.")
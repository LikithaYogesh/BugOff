import os
import json
import time
import hashlib
import docker
from datetime import datetime
import tempfile
import shutil
import logging
import sys
import re

# Configuration
SANDBOX_TIMEOUT = 60  # seconds
SANDBOX_REPORT_DIR = "sandbox_reports"
SANDBOX_IMAGE = "sandbox-image:latest"
NETWORK_MONITORING = True
FILE_QUARANTINE = True

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('sandbox.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SandboxAnalyzer")

class SandboxAnalyzer:
    def __init__(self, timeout=60, network_monitoring=True):
        self.timeout = timeout
        self.network_monitoring = network_monitoring
        try:
            self.client = docker.from_env()
            self.client.ping()
        except Exception as e:
            logger.error(f"Docker connection failed: {str(e)}")
            raise
        self.activities = []
        self.start_time = None
        self.end_time = None
        self.temp_dir = None
        self.container = None
        
        # Enhanced detection patterns
        self.malicious_patterns = {
            'reverse_shell': [
                r'/dev/tcp/',
                r'/bin/bash -i',
                r'/bin/sh -i',
                r'nc -e /bin/sh',
                r'nc -e /bin/bash',
                r'meterpreter',
                r'payload'
            ],
            'privilege_escalation': [
                r'sudo',
                r'su ',
                r'chmod \d{3,4}',
                r'chown \w+:\w+',
                r'passwd'
            ],
            'persistence': [
                r'crontab -e',
                r'systemctl enable',
                r'/etc/init.d/',
                r'/etc/rc.local',
                r'~/.bashrc',
                r'~/.profile'
            ],
            'reconnaissance': [
                r'uname -a',
                r'whoami',
                r'ifconfig',
                r'ip a',
                r'netstat',
                r'ps -aux',
                r'ls -la /'
            ],
            'data_exfiltration': [
                r'curl.*http',
                r'wget.*http',
                r'nc.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
                r'scp',
                r'ftp'
            ]
        }
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        
    def analyze(self, file_path):
        try:
            self.start_time = datetime.now()
            
            # Validate and prepare file
            file_info = self._validate_and_prepare_file(file_path)
            logger.info(f"File prepared for analysis: {file_info}")
            
            # Create isolated environment
            self._setup_sandbox_environment(file_info)
            
            # Execute and monitor
            execution_result = self._execute_and_monitor(file_info)
            
            # Collect and analyze results
            report = self._generate_report(file_path, file_info, execution_result)
            
            # Save report
            report_path = self._save_report(report)
            report['report_path'] = report_path
            
            return report
            
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}", exc_info=True)
            return {
                'file': file_path,
                'error': str(e),
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        finally:
            self.cleanup()
    
    def _validate_and_prepare_file(self, file_path):
        if not os.path.isfile(file_path):
            raise ValueError(f"File not found: {file_path}")
            
        self.temp_dir = tempfile.mkdtemp(prefix="sandbox_")
        sandbox_path = os.path.join(self.temp_dir, os.path.basename(file_path))
        
        try:
            shutil.copy2(file_path, sandbox_path)
            os.chmod(sandbox_path, 0o755)
        except Exception as e:
            raise ValueError(f"Failed to prepare file: {str(e)}")
        
        file_stats = os.stat(file_path)
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
            
        return {
            'original_path': file_path,
            'sandbox_path': sandbox_path,
            'filename': os.path.basename(file_path),
            'size': file_stats.st_size,
            'sha256': file_hash,
            'created': datetime.fromtimestamp(file_stats.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
            'modified': datetime.fromtimestamp(file_stats.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            'extension': os.path.splitext(file_path)[1].lower()
        }
    
    def _setup_sandbox_environment(self, file_info):
        logger.info("Setting up sandbox environment")
        
        try:
            # Create container with proper configuration
            self.container = self.client.containers.run(
                image=SANDBOX_IMAGE,
                command=f"tail -f /dev/null",  # Keep container running
                volumes={
                    os.path.dirname(file_info['sandbox_path']): {'bind': '/sandbox', 'mode': 'rw'}
                },
                network_mode='bridge' if self.network_monitoring else 'none',
                cap_add=['NET_RAW', 'NET_ADMIN'],
                security_opt=['no-new-privileges'],
                mem_limit='512m',
                cpu_quota=50000,
                detach=True,
                auto_remove=False,
                environment={
                    'FILE_TO_ANALYZE': file_info['filename'],
                    'TIMEOUT': str(self.timeout - 5)
                }
            )
            
            # Wait for container to initialize
            time.sleep(3)
            self.container.reload()
            if self.container.status != 'running':
                logs = self.container.logs().decode('utf-8')
                raise RuntimeError(f"Container failed to start. Logs:\n{logs}")
                
        except Exception as e:
            logger.error(f"Failed to setup sandbox: {str(e)}")
            raise
        
    def _execute_and_monitor(self, file_info):
        logger.info("Starting execution monitoring")
        
        try:
            # Make file executable inside container
            exit_code, output = self.container.exec_run(
                cmd=f"chmod +x /sandbox/{file_info['filename']}",
                demux=True
            )
            if exit_code != 0:
                raise RuntimeError(f"Failed to make file executable: {output}")
            
            # Start monitoring script
            exec_id = self.container.exec_run(
                cmd="/bin/bash /monitor.sh",
                detach=True,
                tty=True
            )
            
            # Execute the file with timeout
            exec_result = self.container.exec_run(
                cmd=f"timeout {self.timeout-5} /sandbox/{file_info['filename']}",
                demux=True
            )
            
            # Handle output properly (it's a tuple of (stdout, stderr))
            stdout, stderr = exec_result.output
            exec_output = ""
            if stdout:
                exec_output += stdout.decode('utf-8')
            if stderr:
                exec_output += "\nSTDERR:\n" + stderr.decode('utf-8')
            
            # Give time for monitoring to capture activities
            time.sleep(2)
            
            # Get logs
            logs = self.container.logs().decode('utf-8')
            
            print("\nExecution Output:")
            print(exec_output if exec_output else "<No output>")
            
            self._parse_logs(logs)
            
            return {
                'exit_code': exec_result.exit_code,
                'logs': logs,
                'execution_output': exec_output,
                'duration': time.time() - self.start_time.timestamp()
            }
            
        except Exception as e:
            logger.error(f"Monitoring failed: {str(e)}")
            # Still try to get logs if possible
            try:
                logs = self.container.logs().decode('utf-8') if self.container else ""
                self._parse_logs(logs)
                return {
                    'exit_code': -1,
                    'logs': logs,
                    'execution_output': str(e),
                    'duration': time.time() - self.start_time.timestamp()
                }
            except Exception as e2:
                logger.error(f"Failed to get logs: {str(e2)}")
                raise e
    
    def _parse_logs(self, logs):
        for line in logs.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            try:
                if line.startswith('[') and ']' in line:
                    timestamp_end = line.index(']')
                    timestamp = line[1:timestamp_end]
                    remaining = line[timestamp_end+1:].strip()
                    if ':' in remaining:
                        event_type, message = remaining.split(':', 1)
                        self.activities.append((event_type.strip(), message.strip(), timestamp))
                else:
                    self.activities.append(('log', line, datetime.now().strftime('%H:%M:%S')))
            except Exception as e:
                logger.warning(f"Failed to parse log line: {line} - {str(e)}")
    
    def _generate_report(self, original_path, file_info, execution_result):
        self.end_time = datetime.now()
        
        behavior_analysis = self._analyze_behavior()
        
        return {
            'file': original_path,
            'file_info': file_info,
            'timestamp': self.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            'end_time': self.end_time.strftime("%Y-%m-%d %H:%M:%S"),
            'duration': str(self.end_time - self.start_time),
            'malicious': behavior_analysis['is_malicious'],
            'confidence': behavior_analysis['confidence'],
            'behavior_analysis': behavior_analysis,
            'execution_result': execution_result,
            'monitored_activities': self.activities,
            'environment': {
                'sandbox_image': SANDBOX_IMAGE,
                'timeout': self.timeout,
                'network_monitoring': self.network_monitoring,
                'isolation': 'container'
            }
        }
    
    def _analyze_behavior(self):
        suspicious_activities = []
        command_history = []
        network_connections = []
        file_modifications = []
        process_tree = []
        detected_patterns = []
        confidence = 0
        
        for activity in self.activities:
            # Track all commands executed
            if activity[0] == 'process':
                command = activity[1].split(':', 1)[-1].strip() if ':' in activity[1] else activity[1]
                command_history.append(command)
                
                # Build process tree
                if 'fork' in activity[1] or 'exec' in activity[1]:
                    process_tree.append(activity[1])
            
            # Track network connections
            elif activity[0] == 'network':
                network_connections.append(activity[1])
            
            # Track file modifications
            elif activity[0] == 'file':
                file_modifications.append(activity[1])
            
            # Check against detection patterns
            for category, patterns in self.malicious_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, activity[1], re.IGNORECASE):
                        detected_patterns.append({
                            'category': category,
                            'pattern': pattern,
                            'activity': activity[1]
                        })
                        confidence += 10  # Increase confidence for each detected pattern
        
        # Additional analysis
        if len(network_connections) > 2:
            confidence += 20
        if len(process_tree) > 1:
            confidence += 15
        if len(file_modifications) > 3:
            confidence += 15
            
        # Check for common meterpreter patterns in command history
        meterpreter_patterns = [
            'getuid', 'sysinfo', 'cd /', 'ls', 'upload', 'download',
            'shell', 'execute', 'migrate', 'ps', 'kill'
        ]
        if any(cmd in ' '.join(command_history).lower() for cmd in meterpreter_patterns):
            detected_patterns.append({
                'category': 'meterpreter',
                'pattern': 'meterpreter_commands',
                'activity': 'Found meterpreter commands in execution history'
            })
            confidence += 30
        
        # Generate suspicious activities report
        for pattern in detected_patterns:
            suspicious_activities.append({
                'type': 'pattern',
                'description': f"Detected {pattern['category'].replace('_', ' ')}",
                'details': pattern['activity'],
                'timestamp': 'N/A'
            })
        
        # Determine if malicious
        is_malicious = confidence >= 50 or len(detected_patterns) > 0
        
        return {
            'is_malicious': is_malicious,
            'confidence': min(confidence, 100),  # Cap at 100%
            'suspicious_activities': suspicious_activities,
            'detected_patterns': detected_patterns,
            'command_history': command_history,
            'network_connections': network_connections,
            'file_modifications': file_modifications,
            'process_tree': process_tree
        }
    
    def _save_report(self, report):
        os.makedirs(SANDBOX_REPORT_DIR, exist_ok=True)
        base_name = os.path.basename(report['file'])
        report_file = f"{base_name}_{self.start_time.strftime('%Y%m%d_%H%M%S')}.json"
        report_path = os.path.join(SANDBOX_REPORT_DIR, report_file)
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=4, default=str)
            
        return report_path
    
    def cleanup(self):
        logger.info("Cleaning up sandbox resources")
        
        if self.container:
            try:
                self.container.stop(timeout=1)
                self.container.remove(v=True, force=True)
            except Exception as e:
                logger.warning(f"Error cleaning up container: {str(e)}")
        
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                if FILE_QUARANTINE and any(self.activities):
                    quarantine_dir = os.path.join(SANDBOX_REPORT_DIR, "quarantine")
                    os.makedirs(quarantine_dir, exist_ok=True)
                    shutil.move(self.temp_dir, os.path.join(quarantine_dir, os.path.basename(self.temp_dir)))
                else:
                    shutil.rmtree(self.temp_dir)
            except Exception as e:
                logger.warning(f"Error cleaning up temp directory: {str(e)}")


def print_report(report):
    """Pretty print the analysis report"""
    if not report:
        print("[-] No report generated")
        return
        
    print("\n" + "="*60)
    print("SANDBOX ANALYSIS REPORT".center(60))
    print("="*60)
    
    if 'error' in report:
        print(f"\n[!] Analysis failed: {report['error']}")
        return
    
    print(f"\n[+] File Information:")
    print(f"    - Path: {report['file']}")
    print(f"    - SHA256: {report['file_info']['sha256']}")
    print(f"    - Size: {report['file_info']['size']} bytes")
    print(f"    - Type: {report['file_info']['extension']}")
    
    print(f"\n[+] Analysis Details:")
    print(f"    - Started: {report['timestamp']}")
    print(f"    - Duration: {report['duration']}")
    print(f"    - Sandbox Image: {report['environment']['sandbox_image']}")
    
    print(f"\n[+] Verdict:")
    if report['malicious']:
        print(f"    - MALICIOUS (Confidence: {report['confidence']}%)")
    else:
        print(f"    - CLEAN (Confidence: {100 - report['confidence']}%)")
    
    if report['malicious'] and report['suspicious_activities']:
        print("\n[!] Suspicious Activities Detected:")
        for i, activity in enumerate(report['suspicious_activities'], 1):
            print(f"    {i}. [{activity['type']}] {activity['description']}")
            print(f"        Details: {activity['details']}")
    
    if report['behavior_analysis'].get('detected_patterns'):
        print("\n[!] Detected Malicious Patterns:")
        for i, pattern in enumerate(report['behavior_analysis']['detected_patterns'], 1):
            print(f"    {i}. {pattern['category'].replace('_', ' ')}")
            print(f"        Example: {pattern['activity']}")
    
    if report['execution_result'].get('execution_output'):
        print("\n[+] Execution Output:")
        print(report['execution_result']['execution_output'])
    
    print(f"\n[+] Report saved to: {report['report_path']}")
    print("="*60 + "\n")


def sandbox_analyze(file_path):
    """Analyze a file in an isolated sandbox environment"""
    if not os.path.isfile(file_path):
        print(f"[-] Error: {file_path} is not a valid file")
        return None
        
    print(f"[*] Starting isolated sandbox analysis of: {file_path}")
    print(f"    - Timeout: {SANDBOX_TIMEOUT} seconds")
    print(f"    - Sandbox image: {SANDBOX_IMAGE}")
    print("    - Monitoring capabilities:")
    print("        * Process creation and execution")
    print("        * File system modifications")
    print("        * Network activity")
    print("        * Known attack patterns detection")
    print("    - Isolation: Container-based with restricted privileges")
    
    try:
        with SandboxAnalyzer(timeout=SANDBOX_TIMEOUT, network_monitoring=NETWORK_MONITORING) as sandbox:
                    report = sandbox.analyze(file_path)
        
        print_report(report)
        return report
        
    except Exception as e:
        print(f"[-] Analysis failed: {str(e)}")
        return None


if __name__ == "__main__":
    if len(sys.argv) > 1:
        sandbox_analyze(sys.argv[1])
    else:
        print("Usage: python sandbox.py <file_to_analyze>")
        print("\nRequirements:")
        print("1. Docker installed and running")
        print("2. Pre-built sandbox image with monitoring tools")
        print("3. Appropriate permissions to run containers")
#!/usr/bin/env python3

import subprocess
import time
import re
from datetime import datetime

def capture_apparmor_events():
    """Monitor and capture AppArmor events to a local file"""
    log_file = "/home/yns/Desktop/honeypoy-ssh/apparmor_audit.log"
    
    # Command to follow kernel logs for AppArmor events
    cmd = ["journalctl", "-f", "-k"]
    
    print(f"Starting AppArmor event capture at {datetime.now()}")
    print(f"Logging to {log_file}")
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1
        )
        
        with open(log_file, 'a') as f:
            f.write(f"\n--- AppArmor Event Capture Started: {datetime.now()} ---\n")
            
        print("Monitoring for AppArmor events containing 'ssh_honeypot'...")
        
        while True:
            output = process.stdout.readline()
            if output:
                # Look for AppArmor events related to our honeypot
                if "apparmor" in output.lower() and "ssh_honeypot" in output:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    log_entry = f"[{timestamp}] {output.strip()}\n"
                    
                    with open(log_file, 'a') as f:
                        f.write(log_entry)
                    
                    print(f"Logged: {log_entry.strip()}")
            
            if process.poll() is not None:
                break
                
    except KeyboardInterrupt:
        print("\nStopping AppArmor event capture...")
        with open(log_file, 'a') as f:
            f.write(f"\n--- AppArmor Event Capture Stopped: {datetime.now()} ---\n")
    except Exception as e:
        print(f"Error occurred: {e}")

if __name__ == "__main__":
    capture_apparmor_events()

#!/bin/bash

# Simple AppArmor event logger for the SSH honeypot
LOG_FILE="/home/yns/Desktop/honeypoy-ssh/apparmor_audit.log"

# Function to continuously monitor AppArmor events
log_apparmor_events() {
    echo "Starting AppArmor monitoring at $(date)" >> "$LOG_FILE"
    # Monitor kernel logs for AppArmor events related to our profile
    journalctl -f -k | grep --line-buffered apparmor | grep --line-buffered ssh_honeypot >> "$LOG_FILE" &
    JOURNALCTL_PID=$!
    
    # Also monitor the traditional log files if they exist
    if [ -f /var/log/kern.log ]; then
        tail -f /var/log/kern.log 2>/dev/null | grep --line-buffered apparmor | grep --line-buffered ssh_honeypot >> "$LOG_FILE" &
        TAIL_KERN_PID=$!
    fi
    
    # Set up a cleanup trap
    trap "kill $JOURNALCTL_PID $TAIL_KERN_PID 2>/dev/null; exit" EXIT INT TERM
    
    # Keep the script running
    while true; do
        sleep 1
    done
}

# Run the monitoring function in background
log_apparmor_events &
echo $! > /tmp/apparmor_monitor.pid
echo "AppArmor monitoring started. PID saved to /tmp/apparmor_monitor.pid"
echo "Logs will be written to $LOG_FILE"

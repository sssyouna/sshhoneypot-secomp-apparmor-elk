#!/bin/bash

# Monitor AppArmor logs and write relevant entries to local audit log
LOG_FILE="/home/yns/Desktop/honeypoy-ssh/apparmor_audit.log"

# Function to monitor logs in the background
monitor_logs() {
    # Watch for AppArmor messages in various log locations
    {
        journalctl -f -k | grep -i apparmor &
        tail -f /var/log/kern.log 2>/dev/null | grep -i apparmor &
        tail -f /var/log/syslog 2>/dev/null | grep -i apparmor &
        tail -f /var/log/messages 2>/dev/null | grep -i apparmor &
    } | while read line; do
        if [[ "$line" =~ "ssh_honeypot" ]] || [[ "$line" =~ "python3" ]]; then
            echo "$(date): $line" >> "$LOG_FILE"
        fi
    done
}

# Start monitoring
monitor_logs &
echo "AppArmor monitoring started. Logs will be written to $LOG_FILE"

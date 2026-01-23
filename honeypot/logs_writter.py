from datetime import datetime
import threading

LOG_FILE = "/logs/ssh_logs.log"
_log_lock = threading.Lock()

log_fd = open(LOG_FILE, "a", buffering=1)

def write_logs(event_type, message, client_addr=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    source = "SSH_HONEYPOT"
    
    if client_addr:
        log_line = f"{timestamp} [{event_type}] [{source}] {client_addr[0]}:{client_addr[1]} - {message}\n"
    else:
        log_line = f"{timestamp} [{event_type}] [{source}] {message}\n"

    with _log_lock:
        log_fd.write(log_line)

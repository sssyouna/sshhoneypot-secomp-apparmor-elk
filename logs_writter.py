from datetime import datetime
import threading

LOG_FILE = "ssh_logs.log"
_log_lock = threading.Lock()


def write_logs(event_type, message, client_addr=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if client_addr:
        log_line = f"[{timestamp}] [{event_type}] {client_addr[0]}:{client_addr[1]} - {message}\n"
    else:
        log_line = f"[{timestamp}] [{event_type}] {message}\n"

    with _log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_line)

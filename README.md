# 🐝 SSH Honeypot with Docker, AppArmor, Seccomp and ELK Stack

## 📌 Project Overview

This project is a **secure SSH honeypot** designed to **attract, observe, and log malicious SSH activity** such as:
- brute-force attacks
- credential harvesting
- automated scanners

The honeypot intentionally exposes a **fake SSH service** while ensuring:
- no real system access is possible
- attackers are fully sandboxed
- all actions are logged for analysis

The project integrates **multiple security layers**:
- Python-based SSH server (Paramiko)
- Linux kernel hardening (Seccomp, no_new_privs)
- Mandatory Access Control (AppArmor)
- Centralized log analysis (ELK stack via Docker)

This makes the project suitable for:
- cybersecurity labs
- blue-team / SOC training
- academic projects
- attack behavior analysis

---

## 🎯 Project Objectives

- Simulate a realistic SSH service
- Capture attacker behavior safely
- Prevent system compromise even if the honeypot is abused
- Demonstrate defense-in-depth security architecture
- Provide centralized log visualization (ELK)
- Keep the honeypot logic minimal and non-blocking

---

## 🧠 Architecture Overview

Attacker
|
v
Fake SSH Server (Paramiko)
|
v
Local Log Files
|
v
Filebeat (Docker)
|
v
Elasticsearch <--> Kibana

yaml
Copy code

### Security Layers
| Layer | Purpose |
|-----|-------|
| Docker | Container isolation |
| no_new_privs | Prevent privilege escalation |
| Seccomp | Restrict kernel syscalls |
| AppArmor | Restrict filesystem & process access |
| Fake SSH shell | No real command execution |
| File-based logging | No network dependency |

---

## 📁 Project Structure

HONEYPOT_SSH/
├── docker-compose.yml # Orchestrates all services
├── README.md # Project documentation
├── .gitignore
│
├── honeypot/ # SSH honeypot implementation
│ ├── dockerfile
│ ├── main.py # Fake SSH server logic
│ ├── logs_writter.py # Thread-safe logging
│ ├── seccomp_filter.py # Syscall sandbox
│ ├── capture_apparmor_events.py
│
├── apparmorprofile/
│ └── apparmor_profile_ssh_honeypot
│
├── filebeat/
│ └── filebeat.yml # Log shipper config
│
├── elasticsearch/
│ └── elasticsearch.yml
│
├── kibana/
│ └── kibana.yml
│
└── logs/
├── ssh_logs.log # Honeypot logs
└── apparmor_audit.log # AppArmor denials

markdown
Copy code

---

## 🔐 Security Design

### 1️⃣ Fake SSH Service
- Implemented using `paramiko`
- Accepts connections on a non-standard port
- No real shell or OS command execution
- Credentials are logged, not validated

### 2️⃣ Seccomp (Syscall Filtering)
- Restricts the Python process to a minimal syscall set
- Blocks dangerous syscalls such as:
  - `execve`
  - `ptrace`
  - `mount`
- Prevents container escape and kernel abuse

### 3️⃣ no_new_privs
- Ensures the process can **never gain new privileges**
- Even if exploited, escalation is impossible

### 4️⃣ AppArmor
- Enforces filesystem and process access rules
- Limits:
  - executable paths
  - writable locations
  - device access
- Captures denied actions for forensic analysis

### 5️⃣ Logging Strategy
- Honeypot writes logs locally only
- Logging is:
  - thread-safe
  - non-blocking
  - crash-safe
- Filebeat ships logs asynchronously

---

## 📊 ELK Stack Role

### Elasticsearch
- Stores all honeypot logs
- Enables fast searching and aggregation

### Kibana
- Visualizes attack activity
- Useful for:
  - brute-force timelines
  - IP analysis
  - credential reuse detection

### Filebeat
- Reads log files
- Ships them securely to Elasticsearch
- Does not interfere with honeypot execution

---

## 🚀 How to Run the Project

### ✅ Requirements
- Linux (recommended: Ubuntu / Debian)
- Docker
- Docker Compose
- AppArmor enabled on host

---

### 1️⃣ Clone the repository
```bash
git clone <repo-url>
cd HONEYPOT_SSH
2️⃣ Start the full stack
bash
Copy code
docker compose up -d --build
Check running containers:

bash
Copy code
docker ps
3️⃣ Access the honeypot
bash
Copy code
ssh -p 2121 test@localhost
Any credentials entered will be logged.

4️⃣ Access Kibana
Open your browser:

arduino
Copy code
http://localhost:5601
Create index pattern:

Copy code
filebeat-*
Filter logs:

nginx
Copy code
service : "ssh-honeypot"
🧪 Logs Location
Honeypot logs:

bash
Copy code
logs/ssh_logs.log
AppArmor audit logs:

bash
Copy code
logs/apparmor_audit.log
⚠️ Important Notes
Do NOT expose Elasticsearch or Kibana to the internet

This honeypot is for observation only

Never reuse real SSH credentials

Keep the honeypot isolated from production systems

📚 Educational Value
This project demonstrates:

Secure service emulation

Kernel-level hardening

Defense-in-depth design

SOC-style log analysis

Real-world honeypot architecture

🧠 Future Improvements
GeoIP enrichment

Attack correlation

Dashboard automation

Log rotation

Systemd deployment

Alerting (offline analysis)

👤 Author
Developed as a cybersecurity learning and research project.

yaml
Copy code

---


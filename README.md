# SSH Honeypot with AppArmor and Seccomp

This repository contains a secure SSH honeypot implementation with AppArmor and seccomp-bpf sandboxing.

## Features

- SSH honeypot using Paramiko
- AppArmor profile for restricting system access
- Seccomp-bpf filters for additional security
- Brute-force protection
- Audit logging

## AppArmor Profile

The profile `/etc/apparmor.d/usr.bin.ssh_honeypot` restricts the Python process to only access necessary files and system resources.

### Setup AppArmor Profile

```bash
sudo cp apparmor_profile_ssh_honeypot /etc/apparmor.d/usr.bin.ssh_honeypot
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.ssh_honeypot
sudo aa-enforce /etc/apparmor.d/usr.bin.ssh_honeypot
```

### Monitoring AppArmor Events

Use the monitoring script to capture AppArmor denials:

```bash
sudo python3 capture_apparmor_events.py
```

Audit logs are written to `apparmor_audit.log`.

## Running the Honeypot

```bash
sudo aa-exec -p ssh_honeypot -- python3 main.py
```

The honeypot listens on port 2121.

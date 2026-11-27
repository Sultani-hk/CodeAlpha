"""
respond.py - Simple automatic response for Suricata alerts.

Reads Suricata's eve.json in real time. When an alert with a signature ID
listed in BLOCK_SIDS appears, the source IP is blocked with iptables and
the action is written to a log file.

Run (needs root):  sudo python3 respond.py
Use only on your own network or VMs.
"""
import ipaddress
import json
import subprocess
import time
from datetime import datetime

EVE_LOG = "/var/log/suricata/eve.json"
ACTION_LOG = "response_actions.log"

# Only block for these rules (1000002 = port scan rule from local.rules).
# The ping rule (1000001) is left out so a simple ping does not block anyone.
BLOCK_SIDS = {1000002}

# Never block these addresses (add your own Kali IP, gateway and so on).
WHITELIST = {"127.0.0.1","10.0.0.10"}

# True = only log what would happen. Set to False to really block.
DRY_RUN = False

blocked = set()


def log_action(message):
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S} {message}"
    print(line)
    with open(ACTION_LOG, "a") as f:
        f.write(line + "\n")


def block_ip(ip, signature):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return
    if ip in blocked or ip in WHITELIST:
        return

    cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    if DRY_RUN:
        log_action(f"[DRY RUN] Would block {ip} for: {signature}")
    else:
        try:
            subprocess.run(cmd, check=True)
            log_action(f"[BLOCKED] {ip} for: {signature}")
        except (subprocess.CalledProcessError, FileNotFoundError) as err:
            log_action(f"[ERROR] Could not block {ip}: {err}")
            return
    blocked.add(ip)


def follow(path):
    """Yield new lines as they are added to the file (like tail -f)."""
    with open(path, "r") as f:
        f.seek(0, 2)  # start at the end, ignore old events
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def main():
    log_action(f"Monitoring {EVE_LOG} (dry run: {DRY_RUN})")
    try:
        for line in follow(EVE_LOG):
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") != "alert":
                continue
            alert = event.get("alert", {})
            sid = alert.get("signature_id")
            src = event.get("src_ip", "")
            log_action(f"[ALERT] {alert.get('signature')} from {src}")
            if sid in BLOCK_SIDS:
                block_ip(src, alert.get("signature"))
    except FileNotFoundError:
        print(f"{EVE_LOG} not found. Is Suricata running?")
    except PermissionError:
        print("Permission denied. Run with sudo.")
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()

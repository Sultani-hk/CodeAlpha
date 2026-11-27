"""
chart.py - Visualize Suricata alerts from eve.json.

Creates alerts_summary.png with three charts:
  1. Alerts by type (signature)
  2. Top source IPs
  3. Alerts over time (per minute)

Install:  sudo apt install python3-matplotlib
Run:      sudo python3 chart.py
"""
import json
from collections import Counter

import matplotlib
matplotlib.use("Agg")  # save to file, no display needed
import matplotlib.pyplot as plt

EVE_LOG = "/var/log/suricata/eve.json"
OUTPUT = "alerts_summary.png"

by_signature = Counter()
by_source = Counter()
by_minute = Counter()

try:
    with open(EVE_LOG) as f:
        for line in f:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") != "alert":
                continue
            by_signature[event["alert"].get("signature", "unknown")] += 1
            by_source[event.get("src_ip", "unknown")] += 1
            by_minute[event.get("timestamp", "")[:16]] += 1  # YYYY-MM-DDTHH:MM
except FileNotFoundError:
    raise SystemExit(f"{EVE_LOG} not found. Is Suricata installed and running?")
except PermissionError:
    raise SystemExit("Permission denied. Run with sudo.")

if not by_signature:
    raise SystemExit("No alerts found yet. Generate some traffic first (ping, nmap).")

fig, axes = plt.subplots(3, 1, figsize=(10, 12))

# 1. Alerts by type
sigs = by_signature.most_common(8)
axes[0].barh([s[:45] for s, _ in sigs], [c for _, c in sigs], color="#2A9D8F")
axes[0].set_title("Alerts by type")
axes[0].invert_yaxis()

# 2. Top source IPs
srcs = by_source.most_common(8)
axes[1].bar([s for s, _ in srcs], [c for _, c in srcs], color="#FCA311")
axes[1].set_title("Top source IPs")
axes[1].tick_params(axis="x", rotation=30)

# 3. Alerts over time
times = sorted(by_minute)
axes[2].plot(times, [by_minute[t] for t in times], marker="o", color="#14213D")
axes[2].set_title("Alerts over time (per minute)")
axes[2].tick_params(axis="x", rotation=45)

plt.tight_layout()
plt.savefig(OUTPUT, dpi=150)
print(f"Saved {OUTPUT} ({sum(by_signature.values())} alerts)")

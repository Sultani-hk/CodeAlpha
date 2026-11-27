# CodeAlpha Cybersecurity Tasks

Cybersecurity internship tasks covering network analysis, awareness training, secure coding and intrusion detection.

> **Disclaimer:** This project is for learning only. Run everything on your own network or virtual machines. `app.py` in Task 3 is intentionally vulnerable and must never be used in production.

## Tasks

| Task | Folder | Description |
|---|---|---|
| 1 | `Task-1` | Basic network sniffer in Python using Scapy |
| 2 | `Task-2` | Phishing awareness training presentation |
| 3 | `Task-3` | Secure coding review of a sample app using Bandit |
| 4 | `Task-4` | Network intrusion detection system with Suricata |

## Task 4: Network Intrusion Detection System

A Suricata-based IDS on Kali Linux that detects suspicious traffic, responds automatically and shows the results on a dashboard.

### Files

| File | Purpose |
|---|---|
| `local.rules` | Custom Suricata rules (ICMP ping and port scan detection) |
| `respond.py` | Reads `eve.json` and blocks scanning IPs with `iptables` |
| `chart.py` | Creates `alerts_summary.png` with alert charts |
| `dashboard.py` | Live web dashboard at `http://127.0.0.1:8000` |

### Custom rules

```
alert icmp any any -> $HOME_NET any (msg:"ICMP ping detected"; sid:1000001; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"Possible port scan"; flags:S; detection_filter:track by_src, count 20, seconds 10; sid:1000002; rev:1;)
```

### Requirements

- Kali Linux (or any Linux) with Suricata installed: `sudo apt install suricata`
- Python 3
- matplotlib for the chart: `sudo apt install python3-matplotlib`

### How to run

1. Copy `local.rules` to `/var/lib/suricata/rules/` and add `local.rules` under `rule-files:` in `/etc/suricata/suricata.yaml`.
2. Test the configuration:
   ```
   sudo suricata -T -c /etc/suricata/suricata.yaml -v
   ```
3. Terminal 1, start Suricata (replace `eth1` with your interface):
   ```
   sudo suricata -c /etc/suricata/suricata.yaml -i eth1
   ```
4. Terminal 2, start the response script:
   ```
   sudo python3 respond.py
   ```
   Keep `DRY_RUN = True` while testing, and add your own IP to `WHITELIST`.
5. Terminal 3, start the dashboard and open `http://127.0.0.1:8000`:
   ```
   sudo python3 dashboard.py
   ```
6. From another machine on your own network, generate traffic:
   ```
   ping <kali-ip>
   nmap -sS <kali-ip>
   ```
7. Create the chart:
   ```
   sudo python3 chart.py
   ```

### Results

Add your screenshots here:

- Suricata alerts in `fast.log`
- Response log (`response_actions.log`)
- `alerts_summary.png`
- The dashboard

## Tools used

Python, Scapy, Bandit, Suricata, iptables, Kali Linux, VirtualBox

## Author

**Rahmatullah Sultani **

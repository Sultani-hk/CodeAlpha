"""
dashboard.py - Live web dashboard for Suricata alerts.

Reads /var/log/suricata/eve.json and response_actions.log (written by
respond.py) and shows them at http://127.0.0.1:8000, refreshing every 5 s.
Uses only the Python standard library, so nothing extra to install.

Run (from the folder where respond.py runs):  sudo python3 dashboard.py
Then open Firefox on Kali:                    http://127.0.0.1:8000
Stop with Ctrl+C.
"""
import html
import json
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

EVE_LOG = "/var/log/suricata/eve.json"
ACTION_LOG = "response_actions.log"
HOST, PORT = "127.0.0.1", 8000


def read_alerts():
    by_sig, by_src = Counter(), Counter()
    recent = deque(maxlen=15)
    total = 0
    try:
        with open(EVE_LOG) as f:
            for line in f:
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if e.get("event_type") != "alert":
                    continue
                total += 1
                sig = e["alert"].get("signature", "unknown")
                src = e.get("src_ip", "unknown")
                by_sig[sig] += 1
                by_src[src] += 1
                recent.append((e.get("timestamp", "")[:19], src,
                               e.get("dest_ip", ""), sig))
    except (FileNotFoundError, PermissionError):
        pass
    return total, by_sig, by_src, list(reversed(recent))


def read_blocks():
    rows = []
    try:
        with open(ACTION_LOG) as f:
            for line in f:
                if "[BLOCKED]" in line or "[DRY RUN]" in line:
                    rows.append(line.strip())
    except FileNotFoundError:
        pass
    return rows[-10:][::-1]


def bars(counter, color):
    if not counter:
        return "<p class='muted'>No data yet</p>"
    top = counter.most_common(6)
    biggest = top[0][1]
    out = []
    for name, count in top:
        width = max(4, int(count / biggest * 100))
        out.append(
            f"<div class='row'><div class='label'>{html.escape(name)}</div>"
            f"<div class='bar' style='width:{width}%;background:{color}'>"
            f"{count}</div></div>")
    return "".join(out)


def page():
    total, by_sig, by_src, recent = read_alerts()
    blocks = read_blocks()

    recent_rows = "".join(
        f"<tr><td>{html.escape(t)}</td><td>{html.escape(s)}</td>"
        f"<td>{html.escape(d)}</td><td>{html.escape(sig)}</td></tr>"
        for t, s, d, sig in recent) or "<tr><td colspan=4>No alerts yet</td></tr>"
    block_rows = "".join(f"<li>{html.escape(b)}</li>" for b in blocks) \
        or "<li class='muted'>No response actions yet</li>"

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta http-equiv="refresh" content="5">
<title>Suricata IDS Dashboard</title>
<style>
body{{font-family:Arial,sans-serif;background:#14213D;color:#F4F1EA;margin:0;padding:24px}}
h1{{margin:0 0 4px}} .muted{{color:#9aa5b8}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px}}
.card{{background:#1F3159;border-radius:10px;padding:16px}}
.big{{font-size:56px;font-weight:bold;color:#FCA311}}
.row{{margin:8px 0}} .label{{font-size:13px;margin-bottom:2px}}
.bar{{color:#14213D;font-weight:bold;padding:3px 8px;border-radius:4px;min-width:30px;box-sizing:border-box}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
td,th{{text-align:left;padding:6px;border-bottom:1px solid #2d4373}}
ul{{padding-left:18px;font-size:13px}}
@media(max-width:800px){{.grid{{grid-template-columns:1fr}}}}
</style></head><body>
<h1>Suricata IDS Dashboard</h1>
<div class="muted">Auto-refreshes every 5 seconds</div>
<div class="grid">
  <div class="card"><div class="muted">Total alerts</div><div class="big">{total}</div></div>
  <div class="card"><h3>Response actions</h3><ul>{block_rows}</ul></div>
  <div class="card"><h3>Alerts by type</h3>{bars(by_sig, "#2A9D8F")}</div>
  <div class="card"><h3>Top source IPs</h3>{bars(by_src, "#FCA311")}</div>
</div>
<div class="card" style="margin-top:16px"><h3>Recent alerts</h3>
<table><tr><th>Time</th><th>Source</th><th>Destination</th><th>Alert</th></tr>
{recent_rows}</table></div>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = page().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # keep the terminal quiet


if __name__ == "__main__":
    print(f"Dashboard running at http://{HOST}:{PORT}  (Ctrl+C to stop)")
    try:
        ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")

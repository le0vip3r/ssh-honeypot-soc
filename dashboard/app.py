
from collections import Counter
from datetime import datetime
from pathlib import Path
import json

from flask import Flask, render_template_string

app = Flask(__name__)

BASE = Path.home() / "ssh-honeypot"
ALERT_LOG = BASE / "var/alerts/alerts.log"
COWRIE_LOG = BASE / "var/log/cowrie/cowrie.json"

HTML = """
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="10">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SSH Honeypot SOC Dashboard</title>
<style>
body {
    margin: 0; padding: 28px;
    background: #10151f; color: #e7edf7;
    font-family: system-ui, sans-serif;
}
h1 { margin-bottom: 4px; }
.muted { color: #9baac0; }
.cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px; margin: 24px 0;
}
.card, section {
    background: #1a2332; border: 1px solid #303d50;
    border-radius: 12px; padding: 18px; margin-bottom: 18px;
}
.metric { font-size: 30px; font-weight: 700; margin-top: 8px; }
table { width: 100%; border-collapse: collapse; }
th, td {
    text-align: left; padding: 10px;
    border-bottom: 1px solid #303d50;
    overflow-wrap: anywhere;
}
.alert { color: #ff8d8d; }
.ok { color: #85e0b2; }
.scroll { overflow-x: auto; }
</style>

</head>
<body>
<h1>SSH Honeypot SOC</h1>
<div class="muted">Cowrie monitoring · Auto-refresh every 10 seconds</div>

<div class="cards">
  <div class="card">Recorded events<div class="metric">{{ total }}</div></div>
  <div class="card">Failed logins<div class="metric alert">{{ failed }}</div></div>
  <div class="card">Successful logins<div class="metric">{{ success }}</div></div>
  <div class="card">Unique source IPs<div class="metric">{{ sources }}</div></div>
  <div class="card">Recorded alerts<div class="metric alert">{{ alert_count }}</div></div>
</div>

<section>
<h2>Top source IPs</h2>
{% if top_ips %}
<div class="scroll"><table>
<tr><th>Source IP</th><th>Failed logins</th></tr>
{% for ip, count in top_ips %}
<tr><td>{{ ip }}</td><td>{{ count }}</td></tr>
{% endfor %}
</table></div>
{% else %}
<p class="muted">No failed-login events found in the current log.</p>
{% endif %}
</section>

<section>
<h2>Login activity over time</h2>
<canvas id="loginChart" height="100"></canvas>
</section>

<section>
<h2>Recent alerts</h2>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
const labels = {{ chart_labels | tojson }};
const failed = {{ chart_failed | tojson }};
const successful = {{ chart_success | tojson }};

new Chart(document.getElementById("loginChart"), {
  type: "line",
  data: {
    labels: labels,
    datasets: [
      {
        label: "Failed logins",
        data: failed,
        borderColor: "#ff8585",
        tension: 0.25
      },
      {
        label: "Successful logins",
        data: successful,
        borderColor: "#85e0b2",
        tension: 0.25
      }
    ]
  },
  options: {
    responsive: true,
    animation: false,
    scales: {
      y: { beginAtZero: true, ticks: { precision: 0 } }
    }
  }
});
</script>

{% if alerts %}
{% for alert in alerts %}
{% if "192.0.2.10" in alert %}
<p class="alert"><strong>[TEST]</strong> {{ alert }}</p>
{% elif "172.17.0.1" in alert %}
<p class="alert"><strong>[LAB]</strong> {{ alert }}</p>
{% else %}
<p class="alert"><strong>[REVIEW]</strong> {{ alert }}</p>
{% endif %}
{% endfor %}
{% else %}
<p class="ok">No alerts recorded yet.</p>
{% endif %}
</section>

<section>
<h2>Recent Cowrie events</h2>
{% if recent %}
<div class="scroll"><table>
<tr><th>Timestamp</th><th>Event</th><th>Username</th><th>Source IP</th></tr>
{% for e in recent %}
<tr>
<td>{{ e.timestamp }}</td>
<td>{{ e.eventid }}</td>
<td>{{ e.username }}</td>
<td>{{ e.src_ip }}</td>
</tr>
{% endfor %}
</table></div>
{% else %}
<p class="muted">Cowrie log not found or contains no readable events.</p>
{% endif %}
</section>

<p class="muted">Local lab dashboard · Data refreshes automatically.</p>
</body>
</html>
"""



def read_events():
    import subprocess

    command = [
        "sudo", "docker", "exec", "cowrie-honeypot",
        "/cowrie/cowrie-env/bin/python3",
        "-c",
        """
import json
p = "/cowrie/cowrie-git/var/log/cowrie/cowrie.json"
with open(p, encoding="utf-8") as f:
    for line in f:
        try:
            e = json.loads(line)
            print(json.dumps({
                "timestamp": e.get("timestamp", ""),
                "eventid": e.get("eventid", ""),
                "username": e.get("username", "-"),
                "src_ip": e.get("src_ip", "-"),
            }))
        except (json.JSONDecodeError, TypeError):
            continue
"""
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        events = []
        for line in result.stdout.splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events
    except (subprocess.SubprocessError, OSError):
        return []


@app.route("/")
def index():
    events = read_events()
    failed_events = [
        e for e in events if e["eventid"] == "cowrie.login.failed"
    ]
    successful_events = [
        e for e in events if e["eventid"] == "cowrie.login.success"
    ]

    counts = Counter(
        e["src_ip"] for e in failed_events if e["src_ip"] != "-"
    )

    # Group login events by minute for the chart
    from collections import defaultdict
    from datetime import datetime

    minute_counts = defaultdict(lambda: {"failed": 0, "success": 0})

    for event in events:
        event_id = event["eventid"]
        if event_id not in ("cowrie.login.failed", "cowrie.login.success"):
            continue

        timestamp = event.get("timestamp", "")
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            minute = parsed.strftime("%H:%M")
        except (ValueError, TypeError):
            continue

        if event_id == "cowrie.login.failed":
            minute_counts[minute]["failed"] += 1
        else:
            minute_counts[minute]["success"] += 1

    chart_labels = sorted(minute_counts.keys())
    chart_failed = [minute_counts[m]["failed"] for m in chart_labels]
    chart_success = [minute_counts[m]["success"] for m in chart_labels]


    try:
        alerts = ALERT_LOG.read_text(encoding="utf-8").splitlines()
    except OSError:
        alerts = []

    return render_template_string(
        HTML,
        total=len(events),
        failed=len(failed_events),
        success=len(successful_events),
        sources=len(counts),
        alert_count=len(alerts),
        top_ips=counts.most_common(10),
        alerts=list(reversed(alerts[-10:])),
        recent=list(reversed(events[-20:])),
        chart_labels=chart_labels,
        chart_failed=chart_failed,
        chart_success=chart_success,
 )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

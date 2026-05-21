#!/usr/bin/env python3
"""
DShield Honeypot — Threat Intelligence Dashboard
Parses /var/log/dshield.log and /srv/cowrie/var/log/cowrie/cowrie.json
"""

import re
import json
import gzip
import glob
import configparser
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

DSHIELD_LOG  = "/var/log/dshield.log"
COWRIE_LOG   = "/srv/cowrie/var/log/cowrie/cowrie.json"
COWRIE_GLOB  = "/srv/cowrie/var/log/cowrie/cowrie.json*"
DSHIELD_INI  = "/etc/dshield.ini"

PORT_NAMES = {
    "22": "SSH", "23": "Telnet", "80": "HTTP",
    "443": "HTTPS", "3389": "RDP", "8080": "HTTP-alt",
    "8443": "HTTPS-alt", "2222": "SSH-alt", "2223": "Telnet-alt",
    "7547": "TR-069", "5555": "ADB", "9000": "misc",
}

EXCLUDE_PORTS = {"8888", "12222"}


def load_admin_ips():
    """Read admin IPs from dshield.ini — never hardcoded in source."""
    ips = set()
    try:
        cfg = configparser.ConfigParser()
        cfg.read(DSHIELD_INI)
        raw = cfg.get("DShield", "nofwlog", fallback="")
        for token in raw.split():
            ip = token.split("/")[0]
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                ips.add(ip)
    except Exception:
        pass
    env = os.environ.get("ADMIN_IPS", "")
    if env:
        ips.update(env.split(","))
    return ips


def parse_dshield():
    entries = []
    admin_ips = load_admin_ips()
    pat_src   = re.compile(r"SRC=(\S+)")
    pat_dpt   = re.compile(r"DPT=(\d+)")
    pat_proto = re.compile(r"PROTO=(\w+)")
    try:
        with open(DSHIELD_LOG) as f:
            for line in f:
                ms = pat_src.search(line)
                md = pat_dpt.search(line)
                mp = pat_proto.search(line)
                if ms and md and mp:
                    src = ms.group(1)
                    dpt = md.group(1)
                    if src in admin_ips or dpt in EXCLUDE_PORTS:
                        continue
                    entries.append({
                        "src":   src,
                        "dpt":   dpt,
                        "proto": mp.group(1),
                    })
    except FileNotFoundError:
        pass
    return entries


def parse_cowrie():
    events = []
    files = sorted(glob.glob(COWRIE_GLOB))
    for path in files:
        opener = gzip.open if path.endswith(".gz") else open
        try:
            with opener(path, "rt") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except (FileNotFoundError, OSError):
            pass
    return events


def build_stats():
    fw   = parse_dshield()
    cow  = parse_cowrie()

    # --- firewall stats ---
    port_counts  = Counter(e["dpt"] for e in fw)
    ip_counts_fw = Counter(e["src"] for e in fw)

    top_ports = [
        {"port": p, "name": PORT_NAMES.get(p, "unknown"), "count": c}
        for p, c in port_counts.most_common(10)
    ]
    top_ips_fw = [
        {"ip": ip, "count": c}
        for ip, c in ip_counts_fw.most_common(10)
    ]

    # --- cowrie stats ---
    sessions   = [e for e in cow if e.get("eventid") == "cowrie.session.connect"]
    logins     = [e for e in cow if e.get("eventid") == "cowrie.login.success"]
    login_fail = [e for e in cow if e.get("eventid") == "cowrie.login.failed"]
    commands   = [e for e in cow if e.get("eventid") == "cowrie.command.input"]
    downloads  = [e for e in cow if e.get("eventid") in (
        "cowrie.session.file_download", "cowrie.session.file_download.failed"
    )]

    ip_counts_cow = Counter(e.get("src_ip", "") for e in sessions)
    top_ips_cow   = [{"ip": ip, "count": c} for ip, c in ip_counts_cow.most_common(10)]

    user_counts = Counter(
        e.get("username", "") for e in login_fail if e.get("username")
    )
    pass_counts = Counter(
        e.get("password", "") for e in login_fail if e.get("password")
    )
    cmd_counts  = Counter(
        e.get("input", "") for e in commands if e.get("input")
    )

    top_users    = [{"value": u, "count": c} for u, c in user_counts.most_common(10)]
    top_passwords = [{"value": p, "count": c} for p, c in pass_counts.most_common(10)]
    top_commands = [{"value": cmd, "count": c} for cmd, c in cmd_counts.most_common(10)]

    # --- timeline (last 24h by hour) ---
    hourly = defaultdict(int)
    for e in sessions:
        ts = e.get("timestamp", "")
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                hourly[dt.strftime("%H:00")] += 1
            except ValueError:
                pass

    timeline = [{"hour": h, "count": hourly[h]} for h in sorted(hourly)]

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "totals": {
            "fw_events":    len(fw),
            "sessions":     len(sessions),
            "login_fails":  len(login_fail),
            "login_success": len(logins),
            "commands":     len(commands),
            "downloads":    len(downloads),
        },
        "top_ports":     top_ports,
        "top_ips_fw":    top_ips_fw,
        "top_ips_cowrie": top_ips_cow,
        "top_usernames": top_users,
        "top_passwords": top_passwords,
        "top_commands":  top_commands,
        "timeline":      timeline,
    }


HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DShield — Threat Intel Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #8b949e; --accent: #58a6ff;
    --danger: #f85149; --warning: #d29922; --success: #3fb950;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'SF Mono', 'Fira Code', monospace; font-size: 13px; }
  header { padding: 16px 24px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
  header h1 { font-size: 15px; font-weight: 600; color: var(--accent); letter-spacing: .05em; }
  .ts { font-size: 11px; color: var(--muted); }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; padding: 16px 24px; }
  .stat { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; }
  .stat .label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; margin-bottom: 6px; }
  .stat .value { font-size: 26px; font-weight: 700; color: var(--accent); }
  .panels { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; padding: 0 24px 24px; }
  .panel { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
  .panel h2 { font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; padding: 12px 16px; border-bottom: 1px solid var(--border); }
  .chart-wrap { padding: 16px; }
  table { width: 100%; border-collapse: collapse; }
  td { padding: 7px 16px; border-bottom: 1px solid var(--border); }
  td:last-child { text-align: right; color: var(--accent); font-weight: 600; }
  tr:last-child td { border-bottom: none; }
  .bar-row { display: flex; align-items: center; gap: 8px; padding: 6px 16px; }
  .bar-label { min-width: 80px; color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .bar-track { flex: 1; height: 6px; background: var(--border); border-radius: 3px; }
  .bar-fill { height: 100%; border-radius: 3px; background: var(--accent); }
  .bar-count { min-width: 36px; text-align: right; color: var(--muted); font-size: 11px; }
  .panel-wide { grid-column: 1 / -1; }
  .tag { display: inline-block; background: rgba(88,166,255,.12); color: var(--accent); border-radius: 4px; padding: 1px 6px; font-size: 11px; }
  .danger { color: var(--danger); }
  .success { color: var(--success); }
</style>
</head>
<body>
<header>
  <h1>DShield Honeypot — Threat Intelligence</h1>
  <span class="ts" id="ts">Loading...</span>
</header>

<div class="grid" id="stats"></div>

<div class="panels">
  <div class="panel panel-wide">
    <h2>Session timeline (by hour)</h2>
    <div class="chart-wrap" style="height:140px">
      <canvas id="timeline"></canvas>
    </div>
  </div>

  <div class="panel">
    <h2>Top targeted ports</h2>
    <div id="ports"></div>
  </div>

  <div class="panel">
    <h2>Top source IPs (firewall)</h2>
    <table id="ips-fw"></table>
  </div>

  <div class="panel">
    <h2>Top source IPs (cowrie)</h2>
    <table id="ips-cow"></table>
  </div>

  <div class="panel">
    <h2>Top usernames tried</h2>
    <div id="users"></div>
  </div>

  <div class="panel">
    <h2>Top passwords tried</h2>
    <div id="passwords"></div>
  </div>

  <div class="panel panel-wide">
    <h2>Top commands executed</h2>
    <table id="commands"></table>
  </div>
</div>

<script>
let tlChart = null;

function bar(items, maxCount) {
  return items.map(i => {
    const pct = Math.round((i.count / maxCount) * 100);
    return `<div class="bar-row">
      <span class="bar-label" title="${i.value||i.port}">${i.value||i.port} <span class="tag">${i.name||''}</span></span>
      <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
      <span class="bar-count">${i.count}</span>
    </div>`;
  }).join('');
}

function table(rows, key) {
  return rows.map(r =>
    `<tr><td>${r[key]}</td><td>${r.count}</td></tr>`
  ).join('');
}

async function refresh() {
  const d = await fetch('/api/stats').then(r => r.json());

  document.getElementById('ts').textContent = 'Updated ' + d.generated_at + ' · auto-refresh 30s';

  document.getElementById('stats').innerHTML = [
    ['FW events',    d.totals.fw_events,     ''],
    ['Sessions',     d.totals.sessions,      ''],
    ['Login fails',  d.totals.login_fails,   'danger'],
    ['Login success',d.totals.login_success, 'success'],
    ['Commands',     d.totals.commands,      ''],
    ['Downloads',    d.totals.downloads,     'danger'],
  ].map(([l, v, cls]) =>
    `<div class="stat"><div class="label">${l}</div><div class="value ${cls}">${v}</div></div>`
  ).join('');

  const mx_p = d.top_ports[0]?.count || 1;
  document.getElementById('ports').innerHTML = bar(d.top_ports, mx_p);

  document.getElementById('ips-fw').innerHTML  = table(d.top_ips_fw,    'ip');
  document.getElementById('ips-cow').innerHTML = table(d.top_ips_cowrie, 'ip');

  const mx_u = d.top_usernames[0]?.count || 1;
  const mx_pw = d.top_passwords[0]?.count || 1;
  document.getElementById('users').innerHTML     = bar(d.top_usernames, mx_u);
  document.getElementById('passwords').innerHTML = bar(d.top_passwords, mx_pw);

  document.getElementById('commands').innerHTML = d.top_commands.map(c =>
    `<tr><td style="font-family:monospace;color:#79c0ff">${c.value}</td><td>${c.count}</td></tr>`
  ).join('');

  const labels = d.timeline.map(t => t.hour);
  const values = d.timeline.map(t => t.count);
  if (tlChart) {
    tlChart.data.labels = labels;
    tlChart.data.datasets[0].data = values;
    tlChart.update();
  } else {
    tlChart = new Chart(document.getElementById('timeline'), {
      type: 'bar',
      data: {
        labels,
        datasets: [{ data: values, backgroundColor: 'rgba(88,166,255,.5)', borderColor: '#58a6ff', borderWidth: 1 }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#8b949e', font: { size: 10 } }, grid: { color: '#30363d' } },
          y: { ticks: { color: '#8b949e', font: { size: 10 } }, grid: { color: '#30363d' } }
        }
      }
    });
  }
}

refresh();
setInterval(refresh, 30000);
</script>
</body>
</html>"""


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/api/stats")
def api_stats():
    return jsonify(build_stats())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888, debug=False)
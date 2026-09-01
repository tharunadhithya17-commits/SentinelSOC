#!/usr/bin/env python3
"""
SentinelSOC Lightweight Security Agent
Collects system telemetry and ships it to your SOC dashboard.
"""

import json
import os
import platform
import socket
import sys
import time
import uuid
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path

try:
    import psutil
    import requests
except ImportError:
    print("[ERROR] Missing dependencies. Run: pip install psutil requests")
    sys.exit(1)

# ── Configuration ──────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).parent.resolve()
CONFIG_FILE = SCRIPT_DIR / "agent_config.json"
LOG_FILE    = SCRIPT_DIR / "agent.log"

DEFAULT_SERVER = os.environ.get("SOC_SERVER", "http://localhost:4000")
POLL_INTERVAL  = int(os.environ.get("POLL_INTERVAL", "30"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger("sentinel-agent")

# ── Helpers ────────────────────────────────────────────────────────────────

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def short_id(prefix=""):
    return f"{prefix}{uuid.uuid4().hex[:12].upper()}"

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

# ── Registration ───────────────────────────────────────────────────────────

def load_config():
    return None

def save_config(cfg):
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

def register(server_url):
    """Register this agent with the SOC server and get credentials."""
    payload = {
        "hostname":   socket.gethostname() + "-2",
        "ip":         get_local_ip(),
        "os":         platform.system(),
        "os_version": platform.version()[:80],
        "arch":       platform.machine(),
    }
    log.info(f"Registering with SOC server at {server_url} ...")
    try:
        r = requests.post(f"{server_url}/api/agents/register", json=payload, timeout=10)
        r.raise_for_status()
        data = r.json()
        cfg = {
            "server_url": server_url,
            "agent_id":   data["agent_id"],
            "api_key":    data["api_key"],
        }
        save_config(cfg)
        log.info(f"Registered! agent_id={cfg['agent_id']}")
        return cfg
    except Exception as e:
        log.error(f"Registration failed: {e}")
        sys.exit(1)

# ── Collectors ─────────────────────────────────────────────────────────────

def collect_system_metrics():
    return {
        "cpu":  psutil.cpu_percent(interval=1),
        "mem":  psutil.virtual_memory().percent,
        "disk": psutil.disk_usage("/").percent if platform.system() != "Windows"
                else psutil.disk_usage("C:\\").percent,
    }

def collect_processes():
    events = []
    try:
        for proc in psutil.process_iter(["pid", "name", "username", "cmdline", "cpu_percent"]):
            try:
                info = proc.info
                name = info.get("name", "")
                # Flag suspicious process names
                suspicious = any(s in name.lower() for s in [
                    "powershell", "cmd", "wscript", "cscript", "mshta",
                    "regsvr32", "rundll32", "certutil", "bitsadmin", "psexec",
                    "mimikatz", "nc.exe", "ncat", "netcat"
                ])
                if suspicious:
                    events.append({
                        "id":         f"EVT-{short_id()}",
                        "timestamp":  now_iso(),
                        "event_type": "suspicious_process",
                        "process":    name,
                        "username":   info.get("username", ""),
                        "severity":   "HIGH",
                        "raw":        {"pid": info["pid"], "cmdline": " ".join(info.get("cmdline") or [])[:200]},
                    })
                else:
                    events.append({
                        "id":         f"EVT-{short_id()}",
                        "timestamp":  now_iso(),
                        "event_type": "process_snapshot",
                        "process":    name,
                        "username":   info.get("username", ""),
                        "severity":   "LOW",
                        "raw":        {"pid": info["pid"]},
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        log.warning(f"Process collection error: {e}")
    return events[:50]   # cap to 50 per cycle

def collect_network_connections():
    events = []
    try:
        conns = psutil.net_connections(kind="inet")
        for c in conns:
            if c.status == "ESTABLISHED" and c.raddr:
                rip = c.raddr.ip
                rport = c.raddr.port
                # Flag known suspicious ports
                suspicious_ports = {22, 23, 445, 1433, 3306, 3389, 4444, 5900, 6666, 8080}
                sev = "MEDIUM" if rport in suspicious_ports else "LOW"
                events.append({
                    "id":          f"EVT-{short_id()}",
                    "timestamp":   now_iso(),
                    "event_type":  "network_connection",
                    "source_ip":   c.laddr.ip if c.laddr else "",
                    "destination": f"{rip}:{rport}",
                    "severity":    sev,
                })
    except Exception as e:
        log.warning(f"Network collection error: {e}")
    return events[:30]

def collect_failed_logins_windows():
    """Read Windows Security Event Log (Event ID 4625) via PowerShell."""
    events = []
    if platform.system() != "Windows":
        return events
    try:
        ps_cmd = (
            "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddSeconds(-35)} "
            "-ErrorAction SilentlyContinue | "
            "Select-Object -First 20 | "
            "ForEach-Object { "
            "  $xml=[xml]$_.ToXml(); "
            "  $data=$xml.Event.EventData.Data; "
            "  $user=($data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'; "
            "  $ip=($data | Where-Object {$_.Name -eq 'IpAddress'}).'#text'; "
            "  Write-Output \"$user|$ip|$($_.TimeCreated)\" "
            "}"
        )
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split("|")
            if len(parts) >= 2:
                user = parts[0].strip() or "UNKNOWN"
                src_ip = parts[1].strip() or "-"
                events.append({
                    "id":         f"EVT-{short_id()}",
                    "timestamp":  now_iso(),
                    "event_type": "failed_login",
                    "username":   user,
                    "source_ip":  src_ip,
                    "severity":   "MEDIUM",
                    "raw":        {"event_id": 4625},
                })
    except Exception as e:
        log.warning(f"Windows Event Log error: {e}")
    return events

def collect_failed_logins_linux():
    """Read /var/log/auth.log for recent failures."""
    events = []
    auth_log = Path("/var/log/auth.log")
    if not auth_log.exists():
        auth_log = Path("/var/log/secure")
    if not auth_log.exists():
        return events
    try:
        result = subprocess.run(
            ["tail", "-n", "50", str(auth_log)],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if "Failed password" in line or "authentication failure" in line:
                # Basic parse
                parts = line.split()
                user = "unknown"
                src_ip = "-"
                for i, p in enumerate(parts):
                    if p == "user" and i + 1 < len(parts):
                        user = parts[i + 1]
                    if p == "from" and i + 1 < len(parts):
                        src_ip = parts[i + 1]
                events.append({
                    "id":         f"EVT-{short_id()}",
                    "timestamp":  now_iso(),
                    "event_type": "failed_login",
                    "username":   user,
                    "source_ip":  src_ip,
                    "severity":   "MEDIUM",
                })
    except Exception as e:
        log.warning(f"Linux auth log error: {e}")
    return events

def collect_failed_logins():
    if platform.system() == "Windows":
        return collect_failed_logins_windows()
    else:
        return collect_failed_logins_linux()

# ── Local Detection Rules ──────────────────────────────────────────────────

def run_detection_rules(events, counters):
    alerts = []

    # Rule 1: Brute force — 5+ failed logins in one cycle
    failed = [e for e in events if e["event_type"] == "failed_login"]
    counters["failed_logins"] = counters.get("failed_logins", 0) + len(failed)

    if len(failed) >= 5:
        alerts.append({
            "id":        f"ALR-{short_id()}",
            "timestamp": now_iso(),
            "name":      "Possible Brute Force",
            "severity":  "HIGH",
            "technique": "T1110",
            "source_ip": failed[0].get("source_ip", "-"),
            "username":  failed[0].get("username", "-"),
        })
    elif len(failed) >= 2:
        alerts.append({
            "id":        f"ALR-{short_id()}",
            "timestamp": now_iso(),
            "name":      "Multiple Failed Logins",
            "severity":  "MEDIUM",
            "technique": "T1110",
            "source_ip": failed[0].get("source_ip", "-"),
            "username":  failed[0].get("username", "-"),
        })

    # Rule 2: Suspicious processes
    susp_procs = [e for e in events if e["event_type"] == "suspicious_process"]
    for sp in susp_procs:
        alerts.append({
            "id":        f"ALR-{short_id()}",
            "timestamp": now_iso(),
            "name":      "Suspicious PowerShell" if "powershell" in sp["process"].lower() else "Suspicious Process",
            "severity":  "HIGH",
            "technique": "T1059.001" if "powershell" in sp["process"].lower() else "T1059",
            "username":  sp.get("username", "-"),
        })

    # Rule 3: Suspicious network connections
    susp_net = [e for e in events if e["event_type"] == "network_connection" and e["severity"] == "MEDIUM"]
    for sn in susp_net[:3]:
        alerts.append({
            "id":        f"ALR-{short_id()}",
            "timestamp": now_iso(),
            "name":      "Suspicious Network Connection",
            "severity":  "MEDIUM",
            "technique": "T1041",
            "destination": sn.get("destination", "-"),
        })

    return alerts

# ── Main Agent Loop ────────────────────────────────────────────────────────

def send(server_url, agent_id, api_key, endpoint, payload):
    headers = {"x-agent-id": agent_id, "x-api-key": api_key, "Content-Type": "application/json"}
    try:
        r = requests.post(f"{server_url}{endpoint}", json=payload, headers=headers, timeout=15)
        r.raise_for_status()
        return True
    except Exception as e:
        log.warning(f"Send to {endpoint} failed: {e}")
        return False

def run_agent(cfg):
    server_url = cfg["server_url"]
    agent_id   = cfg["agent_id"]
    api_key    = cfg["api_key"]
    counters   = {}
    cycle      = 0

    log.info(f"Agent started | id={agent_id} | server={server_url} | interval={POLL_INTERVAL}s")
    log.info("Press Ctrl+C to stop.")

    while True:
        cycle += 1
        log.info(f"── Cycle {cycle} ──────────────────────")

        # Collect telemetry
        metrics   = collect_system_metrics()
        logins    = collect_failed_logins()
        processes = collect_processes()
        network   = collect_network_connections()

        all_events = logins + processes + network
        log.info(f"Collected: {len(logins)} login events, {len(processes)} processes, {len(network)} network connections")

        # Send heartbeat with system metrics
        send(server_url, agent_id, api_key, "/api/agents/heartbeat", metrics)

        # Ship events
        if all_events:
            ok = send(server_url, agent_id, api_key, "/api/ingest/events", {"events": all_events})
            if ok:
                log.info(f"Shipped {len(all_events)} events")

        # Run detection rules and ship alerts
        alerts = run_detection_rules(all_events, counters)
        if alerts:
            ok = send(server_url, agent_id, api_key, "/api/ingest/alerts", {"alerts": alerts})
            if ok:
                log.info(f"Shipped {len(alerts)} alerts")

        log.info(f"Cycle complete | CPU={metrics['cpu']}% MEM={metrics['mem']}% DISK={metrics['disk']}%")
        log.info(f"Next cycle in {POLL_INTERVAL}s ...")
        time.sleep(POLL_INTERVAL)

# ── Entry Point ────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  SentinelSOC Security Agent")
    print("=" * 60)

    cfg = load_config()
    if cfg:
        log.info(f"Loaded existing config: agent_id={cfg['agent_id']}, server={cfg['server_url']}")
        # Re-register to update IP/status on server
        payload = {
            "hostname":   socket.gethostname() + "-2",
            "ip":         get_local_ip(),
            "os":         platform.system(),
            "os_version": platform.version()[:80],
            "arch":       platform.machine(),
        }
        try:
            headers = {"Content-Type": "application/json"}
            r = requests.post(f"{cfg['server_url']}/api/agents/register", json=payload, headers=headers, timeout=10)
            r.raise_for_status()
        except Exception:
            log.warning("Could not re-register, continuing with saved credentials.")
    else:
        server_url = input(f"SOC Server URL [{DEFAULT_SERVER}]: ").strip() or DEFAULT_SERVER
        cfg = register(server_url)

    try:
        run_agent(cfg)
    except KeyboardInterrupt:
        log.info("Agent stopped by user.")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
SentinelSOC Enhanced Security Agent  v2.0
Collects REAL system telemetry from this machine and ships it to your SOC.

Collects:
  - All network connections with process name, PID, username
  - Listening ports (attack surface map)
  - Windows Security Event Log: 4625 failed logon, 4624 successful logon,
    4648 explicit credential logon
  - Linux: auth.log / journalctl / syslog
  - Running processes (suspicious LOLBins + high-CPU/memory)
  - System metrics: CPU, RAM, Disk every poll cycle
"""

import json, os, platform, socket, sys, time, uuid, logging, subprocess, re
from datetime import datetime, timezone
from pathlib import Path

try:
    import psutil
    import requests
except ImportError:
    print("[ERROR] Run:  pip install psutil requests")
    sys.exit(1)

# ── Configuration ──────────────────────────────────────────────────────────

SCRIPT_DIR    = Path(__file__).parent.resolve()
CONFIG_FILE   = SCRIPT_DIR / "agent_config.json"
LOG_FILE      = SCRIPT_DIR / "agent.log"

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

IS_WINDOWS = platform.system() == "Windows"

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
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return None

def save_config(cfg):
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

def register(server_url):
    """Register this agent with the SOC server and get credentials."""
    payload = {
        "hostname":   socket.gethostname(),
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
        "disk": psutil.disk_usage("/").percent if not IS_WINDOWS
                else psutil.disk_usage("C:\\").percent,
    }

def collect_processes(seen_pids):
    """Collect noteworthy processes: LOLBins and high-resource consumers."""
    events = []
    suspicious_names = [
        "mimikatz", "nc.exe", "ncat", "netcat", "psexec", "bloodhound", "sharphound"
    ]
    whitelist = ["system idle process", "system", "svchost.exe", "msmpeng.exe", "csrss.exe", "smss.exe", "services.exe", "lsass.exe"]
    try:
        for proc in psutil.process_iter(["pid", "name", "username", "cmdline", "cpu_percent", "memory_percent"]):
            try:
                info    = proc.info
                name    = (info.get("name") or "").lower()
                pid     = info["pid"]
                
                if name in whitelist:
                    continue

                cpu_p   = info.get("cpu_percent") or 0
                mem_p   = info.get("memory_percent") or 0
                
                cmd_str = " ".join(info.get("cmdline") or []).lower()
                is_susp = any(s in name for s in suspicious_names)
                if "powershell" in name and any(x in cmd_str for x in ["-enc", "bypass", "hidden"]):
                    is_susp = True
                if "certutil" in name and "urlcache" in cmd_str:
                    is_susp = True
                is_high = cpu_p > 80 or mem_p > 15

                if not (is_susp or is_high):
                    continue

                if pid in seen_pids:
                    continue
                seen_pids.add(pid)

                sev = "HIGH" if is_susp else "MEDIUM"
                events.append({
                    "id":         f"EVT-{short_id()}",
                    "timestamp":  now_iso(),
                    "event_type": "suspicious_process" if is_susp else "high_resource_process",
                    "process":    info.get("name", ""),
                    "username":   info.get("username", ""),
                    "severity":   sev,
                    "raw": {
                        "pid":     pid,
                        "cpu_pct": round(cpu_p, 1),
                        "mem_pct": round(mem_p, 2),
                        "cmdline": " ".join(info.get("cmdline") or [])[:200],
                    },
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        log.warning(f"Process collection error: {e}")
    return events[:50]

def collect_network_connections(seen_network):
    """Real network connections enriched with process name, PID, username."""
    events = []

    # Build pid -> {name, user} map
    pid_map = {}
    for proc in psutil.process_iter(["pid", "name", "username"]):
        try:
            pid_map[proc.pid] = {
                "name": proc.info["name"],
                "user": proc.info.get("username", ""),
            }
        except Exception:
            pass

    suspicious_ports = {4444, 4445, 6666, 1337, 31337, 5555}

    try:
        conns = psutil.net_connections(kind="inet")
        for c in conns:
            if c.status not in ("ESTABLISHED", "LISTEN"):
                continue

            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            key   = (laddr, raddr, c.status)
            if key in seen_network:
                continue
            seen_network.add(key)

            rip   = c.raddr.ip   if c.raddr else ""
            rport = c.raddr.port if c.raddr else 0
            lip   = c.laddr.ip   if c.laddr else ""
            lport = c.laddr.port if c.laddr else 0

            # Skip pure loopback-to-loopback noise
            if lip.startswith("127.") and (not rip or rip.startswith("127.")):
                continue

            proc_info = pid_map.get(c.pid, {})
            proc_name = proc_info.get("name", "")
            proc_user = proc_info.get("user", "")

            sev = "LOW"
            if rport in suspicious_ports or lport in suspicious_ports:
                sev = "HIGH"
                
            sus_procs = ["nc.exe", "ncat", "netcat", "mimikatz", "powershell.exe", "cmd.exe"]
            if any(b in proc_name.lower() for b in sus_procs):
                sev = "HIGH"

            events.append({
                "id":          f"EVT-{short_id()}",
                "timestamp":   now_iso(),
                "event_type":  "network_connection",
                "source_ip":   lip,
                "destination": f"{rip}:{rport}" if rip else f"LISTEN:{lport}",
                "process":     proc_name,
                "username":    proc_user,
                "severity":    sev,
                "raw": {
                    "pid":         c.pid,
                    "status":      c.status,
                    "local_port":  lport,
                    "remote_ip":   rip,
                    "remote_port": rport,
                },
            })
    except Exception as e:
        log.warning(f"Network collection error: {e}")
    return events[:60]

def collect_failed_logins_windows(seen_logs):
    """Read Windows Security Event Log for login events (4625, 4624, 4648)."""
    if not IS_WINDOWS:
        return []
    events = []
    for evid, etype, sev in [
        (4625, "failed_login",     "MEDIUM"),
        (4624, "successful_login", "LOW"),
        (4648, "explicit_cred",    "MEDIUM"),
    ]:
        ps_cmd = (
            f"Get-WinEvent -FilterHashtable @{{LogName='Security';Id={evid};"
            f"StartTime=(Get-Date).AddSeconds(-35)}} "
            "-ErrorAction SilentlyContinue | Select-Object -First 20 | "
            "ForEach-Object { "
            "  $xml=[xml]$_.ToXml(); "
            "  $data=$xml.Event.EventData.Data; "
            "  $user=($data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'; "
            "  $ip=($data | Where-Object {$_.Name -eq 'IpAddress'}).'#text'; "
            "  $domain=($data | Where-Object {$_.Name -eq 'TargetDomainName'}).'#text'; "
            "  Write-Output \"$user|$ip|$domain|$($_.RecordId)\" "
            "}"
        )
        try:
            result = subprocess.run(
                ["powershell", "-NonInteractive", "-NoProfile", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=12,
            )
            for line in result.stdout.strip().splitlines():
                parts = line.split("|")
                if len(parts) < 2:
                    continue
                user   = parts[0].strip() or "UNKNOWN"
                src_ip = parts[1].strip() if len(parts) > 1 else ""
                domain = parts[2].strip() if len(parts) > 2 else ""
                record_id = parts[3].strip() if len(parts) > 3 else ""
                if record_id:
                    if record_id in seen_logs: continue
                    seen_logs.add(record_id)
                if user.endswith("$") or user in ("SYSTEM", "-", ""):
                    continue   # skip machine accounts
                events.append({
                    "id":         f"EVT-{short_id()}",
                    "timestamp":  now_iso(),
                    "event_type": etype,
                    "username":   user,
                    "source_ip":  src_ip if src_ip and src_ip != "-" else None,
                    "severity":   sev,
                    "raw":        {"event_id": evid, "domain": domain},
                })
        except Exception as e:
            log.warning(f"Windows Event Log ({evid}) error: {e}")
    return events

def collect_failed_logins_linux(seen_logs):
    """Parse auth.log / journalctl for real security events."""
    events = []
    lines  = []

    try:
        result = subprocess.run(
            ["journalctl", "-u", "sshd", f"--since=-{POLL_INTERVAL + 5}s",
             "--no-pager", "-q"],
            capture_output=True, text=True, timeout=8,
        )
        lines = result.stdout.splitlines()
    except Exception:
        for f in ["/var/log/auth.log", "/var/log/secure"]:
            p = Path(f)
            if p.exists():
                try:
                    lines = subprocess.run(
                        ["tail", "-n", "50", str(p)],
                        capture_output=True, text=True, timeout=5,
                    ).stdout.splitlines()
                except Exception:
                    pass
                break

    for line in lines:
        if line in seen_logs: continue
        seen_logs.add(line)
        etype = None
        sev   = "MEDIUM"
        if "Failed password" in line or "authentication failure" in line:
            etype = "failed_login"
        elif "Accepted password" in line or "Accepted publickey" in line:
            etype, sev = "successful_login", "LOW"
        elif "Invalid user" in line:
            etype = "invalid_user_attempt"
        elif "sudo:" in line and "COMMAND" in line:
            etype = "sudo_command"
        if not etype:
            continue

        parts  = line.split()
        user   = "unknown"
        src_ip = None
        for i, p in enumerate(parts):
            if p in ("user", "for") and i + 1 < len(parts):
                user = parts[i + 1]
            if p == "from" and i + 1 < len(parts):
                src_ip = parts[i + 1]
        events.append({
            "id":         f"EVT-{short_id()}",
            "timestamp":  now_iso(),
            "event_type": etype,
            "username":   user,
            "source_ip":  src_ip,
            "severity":   sev,
        })
    return events

def collect_failed_logins(seen_logs):
    if IS_WINDOWS:
        return collect_failed_logins_windows(seen_logs)
    else:
        return collect_failed_logins_linux(seen_logs)

# ── Local Detection Rules ──────────────────────────────────────────────────

def run_detection_rules(events, counters):
    alerts = []

    # Rule 1: Brute force
    failed = [e for e in events if e["event_type"] == "failed_login"]
    counters["failed_logins"] = counters.get("failed_logins", 0) + len(failed)
    if len(failed) >= 5:
        alerts.append({
            "id":        f"ALR-{short_id()}",
            "timestamp": now_iso(),
            "name":      "Possible Brute Force Attack",
            "severity":  "HIGH",
            "technique": "T1110",
            "source_ip": failed[0].get("source_ip") or "-",
            "username":  failed[0].get("username") or "-",
        })
    elif len(failed) >= 2:
        alerts.append({
            "id":        f"ALR-{short_id()}",
            "timestamp": now_iso(),
            "name":      "Multiple Failed Logins",
            "severity":  "MEDIUM",
            "technique": "T1110",
            "source_ip": failed[0].get("source_ip") or "-",
            "username":  failed[0].get("username") or "-",
        })

    # Rule 2: Suspicious processes
    susp_procs = [e for e in events if e["event_type"] == "suspicious_process"]
    for sp in susp_procs:
        name = (sp.get("process") or "").lower()
        alerts.append({
            "id":        f"ALR-{short_id()}",
            "timestamp": now_iso(),
            "name":      "Suspicious PowerShell" if "powershell" in name else f"Suspicious Process: {sp.get('process','')}",
            "severity":  "HIGH",
            "technique": "T1059.001" if "powershell" in name else "T1059",
            "username":  sp.get("username") or "-",
        })

    # Rule 3: Suspicious network (flagged port or process)
    susp_net = [e for e in events if e["event_type"] == "network_connection" and e["severity"] in ("MEDIUM","HIGH")]
    for sn in susp_net[:5]:
        proc = sn.get("process") or "Unknown Process"
        dest = sn.get("destination") or "Unknown"
        alert_name = f"Suspicious Network: {proc} -> {dest}"
        alerts.append({
            "id":        f"ALR-{short_id()}",
            "timestamp": now_iso(),
            "name":      alert_name,
            "severity":  sn["severity"],
            "technique": "T1041",
            "source_ip": sn.get("source_ip") or "-",
        })

    # Rule 4: Explicit credential use
    cred = [e for e in events if e["event_type"] == "explicit_cred"]
    if len(cred) >= 2:
        alerts.append({
            "id":        f"ALR-{short_id()}",
            "timestamp": now_iso(),
            "name":      "Explicit Credential Use Detected",
            "severity":  "MEDIUM",
            "technique": "T1078",
            "username":  cred[0].get("username") or "-",
        })

    return alerts

# ── Send ───────────────────────────────────────────────────────────────────

def send(server_url, agent_id, api_key, endpoint, payload):
    headers = {"x-agent-id": agent_id, "x-api-key": api_key, "Content-Type": "application/json"}
    try:
        r = requests.post(f"{server_url}{endpoint}", json=payload, headers=headers, timeout=15)
        r.raise_for_status()
        return True
    except Exception as e:
        log.warning(f"Send to {endpoint} failed: {e}")
        return False

# ── Main Loop ──────────────────────────────────────────────────────────────

def run_agent(cfg):
    server_url = cfg["server_url"]
    agent_id   = cfg["agent_id"]
    api_key    = cfg["api_key"]
    counters   = {}
    seen_pids = set()
    seen_network = set()
    seen_logs = set()
    cycle      = 0

    log.info(f"Agent v2.0 | id={agent_id} | server={server_url} | interval={POLL_INTERVAL}s")
    log.info("Collecting: network connections (with process), login events, processes")
    log.info("Press Ctrl+C to stop.")

    while True:
        cycle += 1
        log.info(f"--- Cycle {cycle} ----------------------")

        metrics   = collect_system_metrics()
        logins    = collect_failed_logins(seen_logs)
        processes = collect_processes(seen_pids)
        network   = collect_network_connections(seen_network)

        if len(seen_pids) > 10000: seen_pids.clear()
        if len(seen_network) > 10000: seen_network.clear()
        if len(seen_logs) > 10000: seen_logs.clear()

        all_events = logins + processes + network
        log.info(
            f"Collected: {len(logins)} login, {len(processes)} proc, "
            f"{len(network)} net | CPU={metrics['cpu']}% MEM={metrics['mem']}%"
        )

        send(server_url, agent_id, api_key, "/api/agents/heartbeat", metrics)

        if all_events:
            ok = send(server_url, agent_id, api_key, "/api/ingest/events", {"events": all_events})
            if ok:
                log.info(f"Shipped {len(all_events)} events")

        alerts = run_detection_rules(all_events, counters)
        if alerts:
            ok = send(server_url, agent_id, api_key, "/api/ingest/alerts", {"alerts": alerts})
            if ok:
                log.info(f"Shipped {len(alerts)} alerts")

        log.info(f"Next cycle in {POLL_INTERVAL}s ...")
        time.sleep(POLL_INTERVAL)

# ── Entry Point ────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  SentinelSOC Security Agent  v2.0")
    print(f"  Host: {socket.gethostname()}  |  IP: {get_local_ip()}")
    print(f"  OS  : {platform.system()} {platform.release()}")
    print("=" * 60)

    cfg = load_config()
    if cfg:
        log.info(f"Existing config: agent_id={cfg['agent_id']} server={cfg['server_url']}")
        payload = {
            "hostname":   socket.gethostname(),
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

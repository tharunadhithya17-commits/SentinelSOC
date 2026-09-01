import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import { createReadStream, existsSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import db from './db.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-secret';
const AGENT_SECRET = process.env.AGENT_SECRET || 'agent-shared-secret';

app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json({ limit: '2mb' }));

const now = () => new Date().toISOString();
const short = () => randomUUID().replace(/-/g, '').slice(0, 12).toUpperCase();

// ── Auth Middleware ────────────────────────────────────────────────────────

function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Authentication required' });
  }
}

function agentAuth(req, res, next) {
  const key = req.headers['x-api-key'];
  const agentId = req.headers['x-agent-id'];
  if (!key || !agentId) return res.status(401).json({ error: 'Agent credentials required' });
  const agent = db.prepare('SELECT * FROM agents WHERE id=? AND api_key=?').get(agentId, key);
  if (!agent) return res.status(403).json({ error: 'Invalid agent credentials' });
  req.agent = agent;
  next();
}

// ── SOC User Auth ──────────────────────────────────────────────────────────

const users = [
  { username: 'admin',   password: 'admin123',   role: 'Administrator' },
  { username: 'senior',  password: 'senior123',  role: 'Senior Analyst' },
  { username: 'analyst', password: 'analyst123', role: 'SOC Analyst' },
];

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password || String(password).length < 4)
    return res.status(400).json({ error: 'Username and password are required.' });
  const role = users.find(u => u.username === username)?.role || 'SOC Analyst';
  const token = jwt.sign({ username, role }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token, user: { username, role } });
});

// ── Agent Registration & Heartbeat ────────────────────────────────────────

app.post('/api/agents/register', (req, res) => {
  const { hostname, ip, os, os_version, arch } = req.body || {};
  if (!hostname) return res.status(400).json({ error: 'hostname is required' });

  // Check if agent already registered for this hostname
  let agent = db.prepare('SELECT * FROM agents WHERE hostname=?').get(hostname);
  if (agent) {
    // Re-registration: update and return existing credentials
    db.prepare(`UPDATE agents SET ip=?, os=?, os_version=?, arch=?, status='ONLINE', last_seen=? WHERE id=?`)
      .run(ip, os, os_version, arch, now(), agent.id);
    return res.json({ agent_id: agent.id, api_key: agent.api_key, message: 'Re-registered' });
  }

  const agent_id = `AGT-${short()}`;
  const api_key = randomUUID();
  db.prepare(`INSERT INTO agents (id,api_key,hostname,ip,os,os_version,arch,status,last_seen,registered)
              VALUES (?,?,?,?,?,?,?,'ONLINE',?,?)`)
    .run(agent_id, api_key, hostname, ip, os, os_version, arch, now(), now());

  res.status(201).json({ agent_id, api_key, message: 'Agent registered successfully' });
});

app.post('/api/agents/heartbeat', agentAuth, (req, res) => {
  const { cpu = 0, mem = 0, disk = 0 } = req.body || {};
  db.prepare(`UPDATE agents SET status='ONLINE', last_seen=?, cpu=?, mem=?, disk=? WHERE id=?`)
    .run(now(), cpu, mem, disk, req.agent.id);
  res.json({ ok: true });
});

app.get('/api/agents', auth, (req, res) => {
  // Mark offline if not seen in 2 minutes
  db.prepare(`UPDATE agents SET status='OFFLINE' WHERE last_seen < datetime('now', '-2 minutes')`).run();
  const agents = db.prepare('SELECT * FROM agents ORDER BY last_seen DESC').all();
  res.json(agents);
});

// ── Event & Alert Ingestion ───────────────────────────────────────────────

const recentEvents = new Map();

app.post('/api/ingest/events', agentAuth, (req, res) => {
  const { events } = req.body || {};
  if (!Array.isArray(events)) return res.status(400).json({ error: 'events[] required' });

  const insert = db.prepare(`INSERT OR IGNORE INTO events (id,agent_id,hostname,timestamp,event_type,username,source_ip,destination,process,severity,raw)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)`);

  let ingestedCount = 0;
  const insertMany = db.transaction((evts) => {
    for (const e of evts) {
      const sig = `${req.agent.id}|${e.event_type}|${e.process}|${e.username}|${e.source_ip}|${e.destination}`;
      const lastSeen = recentEvents.get(sig);
      if (lastSeen && (Date.now() - lastSeen < 300000)) continue;
      recentEvents.set(sig, Date.now());

      insert.run(
        e.id || `EVT-${short()}`,
        req.agent.id,
        req.agent.hostname,
        e.timestamp || now(),
        e.event_type || 'unknown',
        e.username || null,
        e.source_ip || req.agent.ip,
        e.destination || null,
        e.process || null,
        e.severity || 'LOW',
        e.raw ? JSON.stringify(e.raw) : null
      );
      ingestedCount++;
    }
  });
  insertMany(events.slice(0, 500)); // cap per batch
  if (recentEvents.size > 10000) recentEvents.clear();

  res.status(201).json({ ingested: ingestedCount });
});

app.post('/api/ingest/alerts', agentAuth, (req, res) => {
  const { alerts } = req.body || {};
  if (!Array.isArray(alerts)) return res.status(400).json({ error: 'alerts[] required' });

  const insert = db.prepare(`INSERT OR IGNORE INTO alerts (id,agent_id,hostname,timestamp,name,severity,technique,source_ip,username,status)
    VALUES (?,?,?,?,?,?,?,?,?,'NEW')`);

  let ingestedAlerts = 0;
  const insertMany = db.transaction((alts) => {
    for (const a of alts) {
      const existing = db.prepare(`SELECT id FROM alerts WHERE name=? AND agent_id=? AND status != 'RESOLVED'`).get(a.name, req.agent.id);
      if (existing) continue;

      insert.run(
        a.id || `ALR-${short()}`,
        req.agent.id,
        req.agent.hostname,
        a.timestamp || now(),
        a.name,
        a.severity || 'MEDIUM',
        a.technique || null,
        a.source_ip || req.agent.ip,
        a.username || null
      );
      ingestedAlerts++;
    }
  });
  insertMany(alerts.slice(0, 100));

  // Update agent risk score
  const count = db.prepare(`SELECT COUNT(*) as c FROM alerts WHERE agent_id=? AND status!='RESOLVED'`).get(req.agent.id);
  const risk = Math.min(100, count.c * 8);
  db.prepare('UPDATE agents SET risk_score=?, alert_count=? WHERE id=?').run(risk, count.c, req.agent.id);

  res.status(201).json({ ingested: ingestedAlerts });
});

// ── Dashboard ─────────────────────────────────────────────────────────────

app.get('/api/dashboard', auth, (req, res) => {
  const totalAlerts = db.prepare('SELECT COUNT(*) as c FROM alerts').get().c;
  const critical   = db.prepare(`SELECT COUNT(*) as c FROM alerts WHERE severity='CRITICAL'`).get().c;
  const high       = db.prepare(`SELECT COUNT(*) as c FROM alerts WHERE severity='HIGH'`).get().c;
  const openInc    = db.prepare(`SELECT COUNT(*) as c FROM alerts WHERE status='NEW' OR status='INVESTIGATING'`).get().c;

  db.prepare(`UPDATE agents SET status='OFFLINE' WHERE last_seen < datetime('now', '-2 minutes')`).run();
  const activeEndpoints = db.prepare(`SELECT COUNT(*) as c FROM agents WHERE status='ONLINE'`).get().c;
  const threats = critical + high;

  const bySeverity = ['CRITICAL','HIGH','MEDIUM','LOW'].map(s => ({
    name: s,
    value: db.prepare(`SELECT COUNT(*) as c FROM alerts WHERE severity=?`).get(s).c
  }));

  // Alert timeline — last 12 hours grouped by hour
  const timeline = Array.from({ length: 12 }, (_, i) => {
    const h = new Date(Date.now() - (11 - i) * 3600000);
    const label = `${String(h.getHours()).padStart(2,'0')}:00`;
    const count = db.prepare(`SELECT COUNT(*) as c FROM alerts WHERE timestamp BETWEEN ? AND ?`)
      .get(new Date(h.getTime()).toISOString(), new Date(h.getTime() + 3600000).toISOString()).c;
    return { time: label, alerts: count };
  });

  const recent = db.prepare('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 10').all();
  const agents = db.prepare('SELECT * FROM agents ORDER BY last_seen DESC').all();

  res.json({
    hasAgents: agents.length > 0,
    kpis: { totalAlerts, critical, high, openIncidents: openInc, activeEndpoints, threatsDetected: threats },
    bySeverity,
    timeline,
    recent,
    agents
  });
});

// ── Data Endpoints ────────────────────────────────────────────────────────

app.get('/api/alerts', auth, (req, res) => {
  const rows = db.prepare('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 200').all();
  res.json(rows);
});

app.patch('/api/alerts/:id', auth, (req, res) => {
  const { status } = req.body || {};
  db.prepare('UPDATE alerts SET status=? WHERE id=?').run(status, req.params.id);
  res.json({ ok: true });
});

app.get('/api/endpoints', auth, (req, res) => {
  db.prepare(`UPDATE agents SET status='OFFLINE' WHERE last_seen < datetime('now', '-2 minutes')`).run();
  res.json(db.prepare('SELECT * FROM agents ORDER BY last_seen DESC').all());
});

app.get('/api/events', auth, (req, res) => {
  const rows = db.prepare('SELECT * FROM events ORDER BY timestamp DESC LIMIT 500').all();
  res.json(rows);
});

// ── Agent Download ────────────────────────────────────────────────────────

app.get('/api/download/agent', (req, res) => {
  const agentPath = join(__dirname, '..', '..', 'agent', 'sentinel_agent.py');
  if (!existsSync(agentPath)) return res.status(404).json({ error: 'Agent file not found' });
  
  const serverUrl = `http://${req.hostname}:4000`;
  const content = readFileSync(agentPath, 'utf8').replace(/http:\/\/localhost:4000/g, serverUrl);

  res.setHeader('Content-Disposition', 'attachment; filename="sentinel_agent.py"');
  res.setHeader('Content-Type', 'text/x-python');
  res.send(content);
});

app.get('/api/download/requirements', (req, res) => {
  const reqPath = join(__dirname, '..', '..', 'agent', 'requirements.txt');
  if (!existsSync(reqPath)) return res.status(404).json({ error: 'requirements.txt not found' });
  res.setHeader('Content-Disposition', 'attachment; filename="requirements.txt"');
  res.setHeader('Content-Type', 'text/plain');
  createReadStream(reqPath).pipe(res);
});

app.get('/api/download/install-bat', (req, res) => {
  const batPath = join(__dirname, '..', '..', 'agent', 'install_windows.bat');
  if (!existsSync(batPath)) return res.status(404).json({ error: 'install_windows.bat not found' });
  
  const serverUrl = `http://${req.hostname}:4000`;
  const content = readFileSync(batPath, 'utf8').replace(/http:\/\/localhost:4000/g, serverUrl);

  res.setHeader('Content-Disposition', 'attachment; filename="install_windows.bat"');
  res.setHeader('Content-Type', 'application/octet-stream');
  res.send(content);
});

app.get('/api/download/install-sh', (req, res) => {
  const shPath = join(__dirname, '..', '..', 'agent', 'install_linux.sh');
  if (!existsSync(shPath)) return res.status(404).json({ error: 'install_linux.sh not found' });
  
  const serverUrl = `http://${req.hostname}:4000`;
  const content = readFileSync(shPath, 'utf8').replace(/http:\/\/localhost:4000/g, serverUrl);

  res.setHeader('Content-Disposition', 'attachment; filename="install_linux.sh"');
  res.setHeader('Content-Type', 'application/octet-stream');
  res.send(content);
});

// ── MITRE / Detections (kept as static reference data) ───────────────────

const detectionRules = [
  { id:'RULE-001', name:'Multiple Failed Logins',      severity:'HIGH',     technique:'T1110',      enabled:true },
  { id:'RULE-002', name:'Possible Brute Force',         severity:'HIGH',     technique:'T1110',      enabled:true },
  { id:'RULE-003', name:'Suspicious PowerShell',        severity:'HIGH',     technique:'T1059.001',  enabled:true },
  { id:'RULE-004', name:'Suspicious Process',           severity:'MEDIUM',   technique:'T1059',      enabled:true },
  { id:'RULE-005', name:'EICAR Test File Detected',     severity:'CRITICAL', technique:'T1204',      enabled:true },
  { id:'RULE-006', name:'Privilege Escalation',         severity:'HIGH',     technique:'T1548.002',  enabled:true },
  { id:'RULE-007', name:'Possible Lateral Movement',    severity:'HIGH',     technique:'T1021',      enabled:true },
  { id:'RULE-008', name:'Suspicious Network Connection',severity:'MEDIUM',   technique:'T1041',      enabled:true },
].map(r => ({ ...r, triggerCount: db.prepare(`SELECT COUNT(*) as c FROM alerts WHERE name=?`).get(r.name).c, lastTriggered: now() }));

const mitreData = [
  ['T1110','Brute Force','Credential Access'],
  ['T1059','Command and Scripting Interpreter','Execution'],
  ['T1059.001','PowerShell','Execution'],
  ['T1548.002','Bypass UAC','Privilege Escalation'],
  ['T1021','Remote Services','Lateral Movement'],
  ['T1071.001','Web Protocols','C2'],
  ['T1003','Credential Dumping','Credential Access'],
  ['T1204','User Execution','Execution'],
].map(([id, name, tactic]) => ({
  id, name, tactic,
  detections: db.prepare(`SELECT COUNT(*) as c FROM alerts WHERE technique=?`).get(id).c
}));

app.get('/api/detections', auth, (req, res) => res.json(detectionRules));
app.get('/api/mitre/techniques', auth, (req, res) => res.json(mitreData));

app.post('/api/response-actions', auth, (req, res) => {
  res.status(201).json({ id: `ACT-${Date.now()}`, action: req.body?.action, status: 'SIMULATED', executedBy: req.user.username, time: now() });
});

app.get('/api/threat-intel/ip/:ip', auth, (req, res) => {
  const relatedAlerts = db.prepare(`SELECT COUNT(*) as c FROM alerts WHERE source_ip=?`).get(req.params.ip).c;
  res.json({ indicator: req.params.ip, reputation: relatedAlerts > 0 ? 'SUSPICIOUS' : 'UNKNOWN', relatedAlerts });
});

// ── Error Handler ─────────────────────────────────────────────────────────

app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Internal server error' }); });

app.listen(PORT, () => console.log(`SentinelSOC API running on http://localhost:${PORT}`));

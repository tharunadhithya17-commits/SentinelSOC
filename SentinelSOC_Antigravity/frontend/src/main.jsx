import React, { useEffect, useState, useCallback } from 'react';
import { createRoot } from 'react-dom/client';
import {
  LayoutDashboard, ShieldAlert, BriefcaseBusiness, Monitor, Search,
  Target, Waypoints, FileText, Settings, LogOut, Bell, Plus, Activity,
  Server, Radio, Download, CheckCircle, Copy, Terminal, Cpu, HardDrive,
  MemoryStick, Wifi, RefreshCw, AlertTriangle, Eye, EyeOff, Lock, User,
  Shield, Zap, X, Sun, Moon, Save, KeyRound, Globe, BellRing,
  UserCircle, Palette, Database, Info, ChevronRight
} from 'lucide-react';
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, AreaChart, Area
} from 'recharts';
import './styles.css';

// Apply saved appearance globally
try {
  const t = localStorage.getItem('theme') || 'dark';
  const d = localStorage.getItem('density') || 'comfortable';
  const a = localStorage.getItem('accentColor') || '#00d4ff';
  document.documentElement.setAttribute('data-theme', t);
  document.documentElement.setAttribute('data-density', d);
  document.documentElement.style.setProperty('--accent', a);
} catch(e) {}

// ── API Helper ─────────────────────────────────────────────────────────────
const BASE = 'http://localhost:4000/api';

async function api(path, opts = {}) {
  const r = await fetch(BASE + path, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${localStorage.token || ''}`,
      ...opts.headers,
    },
  });
  if (!r.ok) throw new Error((await r.json()).error || 'Request failed');
  return r.json();
}

// ── Animated Cyber Grid Background ────────────────────────────────────────
function CyberGrid() {
  return (
    <div className="login-grid" aria-hidden="true">
      {Array.from({ length: 20 }).map((_, i) => (
        <div key={i} className="grid-line-v" style={{ left: `${i * 5}%`, animationDelay: `${i * 0.15}s` }} />
      ))}
      {Array.from({ length: 12 }).map((_, i) => (
        <div key={i} className="grid-line-h" style={{ top: `${i * 8.33}%`, animationDelay: `${i * 0.2}s` }} />
      ))}
      {Array.from({ length: 8 }).map((_, i) => (
        <div key={i} className="scan-dot" style={{
          left: `${10 + i * 12}%`,
          top:  `${15 + (i % 3) * 30}%`,
          animationDelay: `${i * 0.6}s`
        }} />
      ))}
    </div>
  );
}

// ── Login ──────────────────────────────────────────────────────────────────
function Login({ onLogin }) {
  const [u, setU]           = useState('');
  const [p, setP]           = useState('');
  const [showPw, setShowPw] = useState(false);
  const [err, setErr]       = useState('');
  const [loading, setLoading] = useState(false);
  const [uFocus, setUFocus] = useState(false);
  const [pFocus, setPFocus] = useState(false);
  const [typed, setTyped]   = useState('');
  const tagline = 'Unified Security Operations Platform';

  // Typing animation for tagline
  useEffect(() => {
    let i = 0;
    const t = setInterval(() => {
      setTyped(tagline.slice(0, i + 1));
      i++;
      if (i >= tagline.length) clearInterval(t);
    }, 45);
    return () => clearInterval(t);
  }, []);

  const submit = async e => {
    e.preventDefault();
    if (!u.trim() || !p.trim()) { setErr('Username and password are required.'); return; }
    setLoading(true); setErr('');
    try {
      const d = await api('/auth/login', { method: 'POST', body: JSON.stringify({ username: u, password: p }) });
      localStorage.token = d.token;
      localStorage.user  = JSON.stringify(d.user);
      onLogin(d.user);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  };

  const demoUsers = [
    { label: 'Admin',         u: 'admin',   r: 'Administrator' },
    { label: 'Senior Analyst',u: 'senior',  r: 'Senior Analyst' },
    { label: 'SOC Analyst',   u: 'analyst', r: 'SOC Analyst' },
  ];

  return (
    <div className="login-bg">
      <CyberGrid />

      {/* Left panel – branding */}
      <div className="login-left">
        <div className="login-left-content">
          <div className="login-logo-wrap">
            <div className="login-logo-ring" />
            <div className="login-logo-inner">
              <Shield size={36} color="var(--accent)" />
            </div>
          </div>
          <h1 className="login-title">SentinelSOC</h1>
          <p className="login-typing">{typed}<span className="cursor-blink">|</span></p>

          <div className="login-features">
            {[
              { icon: Zap,        text: 'Real-time threat detection' },
              { icon: Server,     text: 'Multi-endpoint monitoring' },
              { icon: ShieldAlert,text: 'Automated alert triage' },
              { icon: Activity,   text: 'MITRE ATT&CK mapping' },
            ].map(({ icon: Icon, text }) => (
              <div className="login-feature" key={text}>
                <Icon size={15} color="var(--accent)" />
                <span>{text}</span>
              </div>
            ))}
          </div>

          <div className="login-status-row">
            <div className="login-status-dot" />
            <span>All systems operational</span>
          </div>
        </div>
      </div>

      {/* Right panel – login form */}
      <div className="login-right">
        <div className="login-card">
          <div className="login-card-header">
            <h2>Welcome back</h2>
            <p>Sign in to your SOC account</p>
          </div>

          <form onSubmit={submit} noValidate>
            {/* Username */}
            <div className={`login-field ${uFocus || u ? 'focused' : ''}`}>
              <label className="login-label">Username</label>
              <div className="login-input-wrap">
                <User size={16} className="login-input-icon" />
                <input
                  id="soc-username"
                  className="login-input"
                  value={u}
                  onChange={e => setU(e.target.value)}
                  onFocus={() => setUFocus(true)}
                  onBlur={() => setUFocus(false)}
                  placeholder="Enter your username"
                  autoComplete="username"
                  autoFocus
                />
              </div>
            </div>

            {/* Password */}
            <div className={`login-field ${pFocus || p ? 'focused' : ''}`}>
              <label className="login-label">Password</label>
              <div className="login-input-wrap">
                <Lock size={16} className="login-input-icon" />
                <input
                  id="soc-password"
                  className="login-input"
                  value={p}
                  onChange={e => setP(e.target.value)}
                  onFocus={() => setPFocus(true)}
                  onBlur={() => setPFocus(false)}
                  type={showPw ? 'text' : 'password'}
                  placeholder="Enter your password"
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  className="pw-toggle"
                  onClick={() => setShowPw(s => !s)}
                  tabIndex={-1}
                  aria-label={showPw ? 'Hide password' : 'Show password'}
                >
                  {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>

            {err && (
              <div className="login-error" role="alert">
                <AlertTriangle size={14} /> {err}
              </div>
            )}

            <button
              id="soc-login-btn"
              className="login-btn"
              type="submit"
              disabled={loading}
            >
              {loading
                ? <><span className="login-spinner" /> Authenticating…</>
                : <><Lock size={15} /> Sign In to SOC</>}
            </button>
          </form>

          {/* Demo accounts */}
          <div className="demo-accounts">
            <div className="demo-label">Demo accounts — click to fill</div>
            <div className="demo-row">
              {demoUsers.map(({ label, u: du, r }) => (
                <button
                  key={du}
                  type="button"
                  className="demo-chip"
                  onClick={() => { setU(du); setP(`${du}123`); }}
                >
                  <span className="demo-chip-name">{label}</span>
                  <span className="demo-chip-role">{r}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Utility Components ─────────────────────────────────────────────────────
function Card({ title, sub, children, action }) {
  return (
    <div className="card">
      <div className="card-header">
        <div>
          <div className="card-title">{title}</div>
          {sub && <div className="card-sub">{sub}</div>}
        </div>
        {action}
      </div>
      <div className="card-body no-pad">{children}</div>
    </div>
  );
}

function Badge({ val }) {
  const v = String(val || '').toLowerCase().replace(/\s+/g, '-');
  return <span className={`badge ${v}`}>{val}</span>;
}

function Modal({ title, data, onClose }) {
  if (!data) return null;
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h3 className="modal-title">{title}</h3>
          <button className="modal-close" onClick={onClose}><X size={18}/></button>
        </div>
        <div className="modal-body">
          <pre>{JSON.stringify(data, null, 2)}</pre>
        </div>
      </div>
    </div>
  );
}

function DataTable({ rows = [], cols = [], keys = [], onRowClick }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>{cols.map(c => <th key={c}>{c}</th>)}</tr>
        </thead>
        <tbody>
          {rows.length === 0
            ? <tr><td colSpan={cols.length} style={{ textAlign: 'center', padding: '32px', color: 'var(--text3)' }}>No data yet</td></tr>
            : rows.map((r, i) => (
              <tr key={r.id || i} onClick={() => onRowClick && onRowClick(r)} style={{ cursor: onRowClick ? 'pointer' : 'inherit' }}>
                {keys.map(k => (
                  <td key={k} className={['id','hostname','source_ip','destination'].includes(k) ? 'mono' : ''}>
                    {['severity','status'].includes(k)
                      ? <Badge val={r[k]} />
                      : k === 'timestamp'
                      ? new Date(r[k]).toLocaleString()
                      : k === 'cpu' || k === 'mem' || k === 'disk'
                      ? `${Number(r[k] || 0).toFixed(1)}%`
                      : k === 'enabled'
                      ? <Badge val={r[k] ? 'ACTIVE' : 'DISABLED'} />
                      : r[k] ?? '—'}
                  </td>
                ))}
              </tr>
            ))}
        </tbody>
      </table>
    </div>
  );
}

function ProgressBar({ value }) {
  const v = Math.min(100, Math.max(0, Number(value) || 0));
  const cls = v > 80 ? 'red' : v > 50 ? 'yellow' : 'green';
  return (
    <div className="progress">
      <div className="progress-bar" style={{ width: `${v}%`, background: cls === 'red' ? 'var(--danger)' : cls === 'yellow' ? 'var(--warning)' : 'var(--accent3)' }} />
    </div>
  );
}

function KpiCard({ label, value, icon: Icon, color = 'var(--accent)', sub = 'Live telemetry', onClick }) {
  return (
    <div
      className={`kpi${onClick ? ' kpi-clickable' : ''}`}
      onClick={onClick}
      title={onClick ? `View ${label} details` : undefined}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={onClick ? e => e.key === 'Enter' && onClick() : undefined}
    >
      <div className="kpi-icon" style={{ background: `${color}18` }}>
        <Icon size={18} color={color} />
      </div>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value" style={{ color }}>{value}</div>
      <div className="kpi-sub">{sub}</div>
      {onClick && <div className="kpi-click-hint">Click to view details →</div>}
    </div>
  );
}

// ── KPI Detail Drawer ──────────────────────────────────────────────────────
function KpiDrawer({ kpi, onClose, onRowClick }) {
  const [rows, setRows]       = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState('');

  // Config per KPI type
  const cfg = {
    'Total Alerts':     { path: '/alerts',    label: 'All Alerts',             cols: ['Alert ID','Name','Severity','Source IP','Endpoint','Status','Time'],    keys: ['id','name','severity','source_ip','hostname','status','timestamp'], filter: null },
    'Critical':         { path: '/alerts',    label: 'Critical Alerts',        cols: ['Alert ID','Name','Severity','Source IP','Endpoint','Status','Time'],    keys: ['id','name','severity','source_ip','hostname','status','timestamp'], filter: r => r.severity === 'CRITICAL' },
    'High':             { path: '/alerts',    label: 'High-Severity Alerts',   cols: ['Alert ID','Name','Severity','Source IP','Endpoint','Status','Time'],    keys: ['id','name','severity','source_ip','hostname','status','timestamp'], filter: r => r.severity === 'HIGH' },
    'Open Incidents':   { path: '/alerts',    label: 'Open Incidents',         cols: ['Alert ID','Name','Severity','Source IP','Endpoint','Status','Time'],    keys: ['id','name','severity','source_ip','hostname','status','timestamp'], filter: r => r.status === 'NEW' || r.status === 'INVESTIGATING' },
    'Active Endpoints': { path: '/endpoints', label: 'Online Endpoints',       cols: ['Agent ID','Hostname','IP','OS','Status','CPU','RAM','Disk','Risk'], keys: ['id','hostname','ip','os','status','cpu','mem','disk','risk_score'],  filter: r => r.status === 'ONLINE' },
    'Threats Detected': { path: '/alerts',    label: 'Critical + High Threats',cols: ['Alert ID','Name','Severity','Source IP','Endpoint','Status','Time'],    keys: ['id','name','severity','source_ip','hostname','status','timestamp'], filter: r => r.severity === 'CRITICAL' || r.severity === 'HIGH' },
  }[kpi?.label];

  useEffect(() => {
    if (!cfg) return;
    setLoading(true); setError('');
    api(cfg.path)
      .then(data => {
        const filtered = cfg.filter ? data.filter(cfg.filter) : data;
        setRows(filtered);
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [kpi]);

  if (!kpi) return null;

  const severityColor = { CRITICAL: 'var(--danger)', HIGH: 'var(--high)', MEDIUM: 'var(--warning)', LOW: 'var(--accent3)' };

  return (
    <>
      {/* Backdrop */}
      <div className="drawer-backdrop" onClick={onClose} />
      {/* Drawer */}
      <div className="kpi-drawer fade-in">
        {/* Header */}
        <div className="kpi-drawer-header">
          <div className="kpi-drawer-header-left">
            <div className="kpi-drawer-icon" style={{ background: `${kpi.color}18` }}>
              <kpi.icon size={20} color={kpi.color} />
            </div>
            <div>
              <div className="kpi-drawer-title">{cfg?.label || kpi.label}</div>
              <div className="kpi-drawer-sub">
                {loading ? 'Fetching live data…' : `${rows.length} record${rows.length !== 1 ? 's' : ''} • Live data`}
              </div>
            </div>
          </div>
          <button className="modal-close" onClick={onClose} aria-label="Close details"><X size={18}/></button>
        </div>

        {/* Summary row */}
        {!loading && !error && (
          <div className="kpi-drawer-summary">
            <div className="kpi-drawer-big-num" style={{ color: kpi.color }}>{rows.length}</div>
            <div style={{ fontSize: 12.5, color: 'var(--text3)' }}>Total {cfg?.label}</div>
          </div>
        )}

        {/* Body */}
        <div className="kpi-drawer-body">
          {loading && (
            <div className="empty-state" style={{ padding: 40 }}>
              <div className="login-spinner" style={{ width: 28, height: 28, borderTopColor: kpi.color }} />
              <span style={{ color: 'var(--text3)', fontSize: 13 }}>Fetching real-time data…</span>
            </div>
          )}
          {error && (
            <div className="login-error" style={{ margin: 16 }}>
              <AlertTriangle size={14}/> {error}
            </div>
          )}
          {!loading && !error && rows.length === 0 && (
            <div className="empty-state" style={{ padding: 40 }}>
              <div className="empty-icon"><CheckCircle size={24} color="var(--accent3)" /></div>
              <p>No records found. System is clean ✓</p>
            </div>
          )}
          {!loading && !error && rows.length > 0 && (
            <>
              {/* Compact row cards */}
              <div className="drawer-rows">
                {rows.map((row, i) => (
                  <div className="drawer-row-card" key={row.id || i} onClick={() => onRowClick?.(row)} style={{ cursor: onRowClick ? 'pointer' : 'default' }}>
                    <div className="drawer-row-top">
                      <span className="drawer-row-id mono">{row.id}</span>
                      {row.severity && (
                        <span className={`badge ${row.severity?.toLowerCase()}`}>{row.severity}</span>
                      )}
                      {row.status && !row.severity && (
                        <span className={`badge ${row.status?.toLowerCase()}`}>{row.status}</span>
                      )}
                    </div>
                    <div className="drawer-row-name">
                      {row.name || row.hostname || '—'}
                    </div>
                    <div className="drawer-row-meta">
                      {row.hostname && row.name && (
                        <span><Server size={11}/> {row.hostname}</span>
                      )}
                      {row.source_ip && (
                        <span><Globe size={11}/> {row.source_ip}</span>
                      )}
                      {row.ip && (
                        <span><Globe size={11}/> {row.ip}</span>
                      )}
                      {row.status && row.severity && (
                        <span className={`badge ${row.status?.toLowerCase()}`} style={{ fontSize: 10 }}>{row.status}</span>
                      )}
                      {(row.cpu !== undefined) && (
                        <span><Cpu size={11}/> CPU {Number(row.cpu||0).toFixed(0)}%</span>
                      )}
                      {row.timestamp && (
                        <span style={{ marginLeft: 'auto', color: 'var(--text3)' }}>
                          {new Date(row.timestamp).toLocaleString()}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        <div className="kpi-drawer-footer">
          <span style={{ fontSize: 12, color: 'var(--text3)' }}>Data pulled live from SOC backend</span>
          <button className="btn btn-ghost" style={{ fontSize: 12, padding: '5px 12px' }} onClick={onClose}>Close</button>
        </div>
      </div>
    </>
  );
}

// ── Dashboard ──────────────────────────────────────────────────────────────
function Dashboard({ data, onNavigate, onRowClick }) {
  if (!data) return <div className="empty-state"><div className="kpi-label">Loading SOC telemetry…</div></div>;

  if (!data.hasAgents) {
    return (
      <div className="empty-state fade-in">
        <div className="empty-icon"><Server size={28} /></div>
        <h3>No Agents Enrolled</h3>
        <p>Your SOC is ready. Download and install the security agent on any machine to start receiving real telemetry.</p>
        <button className="btn btn-primary" onClick={() => onNavigate('Download Agent')}>
          <Download size={16} /> Get the Agent
        </button>
      </div>
    );
  }

  const { kpis, bySeverity, timeline, recent } = data;
  const [drawerKpi, setDrawerKpi] = useState(null);

  const openDrawer = (label, icon, color) => setDrawerKpi({ label, icon, color });

  return (
    <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="kpi-grid">
        <KpiCard label="Total Alerts"      value={kpis.totalAlerts}      icon={ShieldAlert}       color="var(--accent)"  onClick={() => openDrawer('Total Alerts',     ShieldAlert,       'var(--accent)'  )} />
        <KpiCard label="Critical"          value={kpis.critical}         icon={Target}            color="var(--danger)"  sub="Requires immediate action" onClick={() => openDrawer('Critical',         Target,            'var(--danger)'  )} />
        <KpiCard label="High"              value={kpis.high}             icon={AlertTriangle}     color="var(--high)"    onClick={() => openDrawer('High',             AlertTriangle,     'var(--high)'    )} />
        <KpiCard label="Open Incidents"    value={kpis.openIncidents}    icon={BriefcaseBusiness} color="var(--warning)" onClick={() => openDrawer('Open Incidents',    BriefcaseBusiness, 'var(--warning)' )} />
        <KpiCard label="Active Endpoints"  value={kpis.activeEndpoints}  icon={Server}            color="var(--accent3)" sub="Online agents" onClick={() => openDrawer('Active Endpoints', Server,            'var(--accent3)' )} />
        <KpiCard label="Threats Detected"  value={kpis.threatsDetected}  icon={Radio}             color="var(--accent2)" onClick={() => openDrawer('Threats Detected',  Radio,             'var(--accent2)' )} />
      </div>
      <KpiDrawer kpi={drawerKpi} onClose={() => setDrawerKpi(null)} onRowClick={onRowClick} />

      <div className="grid-2">
        <Card title="Alert Timeline" sub="Last 12 hours">
          <div style={{ padding: '16px' }}>
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={timeline}>
                <defs>
                  <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="var(--accent)" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="var(--accent)" stopOpacity={0}   />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" tick={{ fontSize: 11 }} />
                <YAxis tick={{ fontSize: 11 }} />
                <Tooltip />
                <Area type="monotone" dataKey="alerts" stroke="var(--accent)" fill="url(#alertGrad)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card title="Alerts by Severity" sub="Distribution">
          <div style={{ padding: '16px' }}>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={bySeverity}>
                <XAxis dataKey="name" tick={{ fontSize: 11 }} />
                <YAxis tick={{ fontSize: 11 }} />
                <Tooltip />
                <Bar dataKey="value" fill="var(--accent2)" radius={[4,4,0,0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <Card title="Recent Alerts" sub={`${recent.length} latest`}>
        <DataTable rows={recent} cols={['Alert ID','Name','Severity','Source IP','Endpoint','Status']} keys={['id','name','severity','source_ip','hostname','status']} onRowClick={onRowClick} />
      </Card>
    </div>
  );
}

// ── Endpoints ──────────────────────────────────────────────────────────────
function Endpoints({ onNavigate }) {
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    api('/endpoints').then(setAgents).catch(console.error).finally(() => setLoading(false));
  }, []);
  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, [load]);

  if (loading) return <div className="empty-state">Loading endpoints…</div>;

  if (agents.length === 0) {
    return (
      <div className="empty-state fade-in">
        <div className="empty-icon"><Server size={28} /></div>
        <h3>No Agents Enrolled</h3>
        <p>Install the security agent on any machine to see it here.</p>
        <button className="btn btn-primary" onClick={() => onNavigate('Download Agent')}>
          <Download size={16} /> Get the Agent
        </button>
      </div>
    );
  }

  return (
    <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="kpi-grid" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(140px,1fr))' }}>
        <KpiCard label="Total Agents"  value={agents.length}                                     icon={Server}   color="var(--accent)"  sub="" />
        <KpiCard label="Online"        value={agents.filter(a => a.status === 'ONLINE').length}  icon={Wifi}     color="var(--accent3)" sub="" />
        <KpiCard label="Offline"       value={agents.filter(a => a.status === 'OFFLINE').length} icon={Server}   color="var(--text3)"   sub="" />
      </div>
      <div className="endpoint-grid">
        {agents.map(a => (
          <div className="endpoint-card fade-in" key={a.id}>
            <div className="endpoint-card-header">
              <div>
                <div className="endpoint-hostname">{a.hostname}</div>
                <div className="endpoint-ip">{a.ip || '—'}</div>
              </div>
              <Badge val={a.status === 'ONLINE' ? 'ONLINE' : 'OFFLINE'} />
            </div>
            <div style={{ fontSize: 12, color: 'var(--text3)' }}>{a.os} {a.os_version?.slice(0,40)}</div>
            <div style={{ fontSize: 12, color: 'var(--text3)', fontFamily: 'var(--mono)' }}>{a.id}</div>
            <div className="endpoint-metrics">
              <div className="metric-mini">
                <div className="metric-mini-label">CPU</div>
                <div className="metric-mini-value" style={{ color: a.cpu > 80 ? 'var(--danger)' : 'var(--text)' }}>{Number(a.cpu||0).toFixed(0)}%</div>
              </div>
              <div className="metric-mini">
                <div className="metric-mini-label">RAM</div>
                <div className="metric-mini-value" style={{ color: a.mem > 80 ? 'var(--danger)' : 'var(--text)' }}>{Number(a.mem||0).toFixed(0)}%</div>
              </div>
              <div className="metric-mini">
                <div className="metric-mini-label">Disk</div>
                <div className="metric-mini-value" style={{ color: a.disk > 85 ? 'var(--danger)' : 'var(--text)' }}>{Number(a.disk||0).toFixed(0)}%</div>
              </div>
            </div>
            <ProgressBar value={a.risk_score} />
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
              <span style={{ color: 'var(--text3)' }}>Risk: <b style={{ color: a.risk_score > 60 ? 'var(--danger)' : 'var(--warning)' }}>{a.risk_score}/100</b></span>
              <span style={{ color: 'var(--text3)' }}>{a.alert_count} alerts</span>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text3)' }}>
              Last seen: {a.last_seen ? new Date(a.last_seen).toLocaleString() : 'Never'}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Download Agent Page ────────────────────────────────────────────────────
function DownloadAgent() {
  const [copied, setCopied] = useState('');
  const [agentCount, setAgentCount] = useState(null);

  useEffect(() => {
    api('/endpoints').then(a => setAgentCount(a.length)).catch(() => {});
  }, []);

  const copy = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(''), 2000);
  };

  const CodeBlock = ({ id, code }) => (
    <div className="code-block">
      <code>{code}</code>
      <button className="copy-btn" onClick={() => copy(code, id)}>
        {copied === id ? <><CheckCircle size={12}/> Copied!</> : <><Copy size={12}/> Copy</>}
      </button>
    </div>
  );

  const apiUrl = `http://${window.location.hostname}:4000/api/download`;

  return (
    <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {agentCount !== null && (
        <div className="agent-count-banner">
          <CheckCircle size={18} />
          <span><b>{agentCount}</b> agent{agentCount !== 1 ? 's' : ''} currently enrolled in this SOC.</span>
        </div>
      )}

      <div className="download-hero">
        <div className="download-hero-icon">🛡️</div>
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <h2>SentinelSOC Security Agent</h2>
              <p>
                A lightweight Python agent that runs on any Windows or Linux machine. It auto-registers with
                this SOC, then continuously collects security events, failed logins, process activity, and
                network connections — shipping them here every 30 seconds.
              </p>
            </div>
            <button className="btn btn-ghost" onClick={() => copy(`${apiUrl}/agent`, 'share')} style={{ whiteSpace: 'nowrap', marginLeft: 20 }}>
              {copied === 'share' ? <><CheckCircle size={15}/> Copied!</> : <><Copy size={15}/> Copy Share Link</>}
            </button>
          </div>
          <div style={{ display: 'flex', gap: 10, marginTop: 14, flexWrap: 'wrap' }}>
            <a href={`${apiUrl}/agent`} download="sentinel_agent.py" className="btn btn-primary" style={{ textDecoration: 'none' }}>
              <Download size={16}/> sentinel_agent.py
            </a>
            <a href={`${apiUrl}/requirements`} download="requirements.txt" className="btn btn-ghost" style={{ textDecoration: 'none' }}>
              <Download size={16}/> requirements.txt
            </a>
            <a href={`${apiUrl}/install-bat`} download="install_windows.bat" className="btn btn-ghost" style={{ textDecoration: 'none' }}>
              <Download size={16}/> install_windows.bat
            </a>
            <a href={`${apiUrl}/install-sh`} download="install_linux.sh" className="btn btn-ghost" style={{ textDecoration: 'none' }}>
              <Download size={16}/> install_linux.sh
            </a>
          </div>
        </div>
      </div>

      <div className="grid-2">
        {/* Windows */}
        <Card title="🪟 Windows Installation" sub="Requires Python 3.9+">
          <div style={{ padding: 18 }}>
            <div className="steps">
              <div className="step">
                <div className="step-num">1</div>
                <div className="step-content">
                  <h4>Install Python (if not installed)</h4>
                  <p>Download Python 3.9+ from python.org. Make sure to tick <b>"Add to PATH"</b>.</p>
                </div>
              </div>
              <div className="step">
                <div className="step-num">2</div>
                <div className="step-content">
                  <h4>Download the agent files</h4>
                  <p>Click the download buttons above to get <code style={{fontFamily:'var(--mono)',color:'var(--accent3)'}}>sentinel_agent.py</code> and <code style={{fontFamily:'var(--mono)',color:'var(--accent3)'}}>requirements.txt</code>. Save them in the same folder.</p>
                </div>
              </div>
              <div className="step">
                <div className="step-num">3</div>
                <div className="step-content">
                  <h4>Option A — One-click installer</h4>
                  <p>Double-click <code style={{fontFamily:'var(--mono)',color:'var(--accent3)'}}>install_windows.bat</code> and follow the prompts.</p>
                </div>
              </div>
              <div className="step">
                <div className="step-num">4</div>
                <div className="step-content">
                  <h4>Option B — Manual (cmd / PowerShell)</h4>
                  <CodeBlock id="w1" code="pip install psutil requests pywin32" />
                  <div style={{ marginTop: 8 }}>
                    <CodeBlock id="w2" code="python sentinel_agent.py" />
                  </div>
                  <p style={{ marginTop: 8 }}>Enter this SOC's URL when prompted: <code style={{fontFamily:'var(--mono)',color:'var(--accent)'}}>http://localhost:4000</code></p>
                </div>
              </div>
            </div>
          </div>
        </Card>

        {/* Linux */}
        <Card title="🐧 Linux / macOS Installation" sub="Requires Python 3.9+">
          <div style={{ padding: 18 }}>
            <div className="steps">
              <div className="step">
                <div className="step-num">1</div>
                <div className="step-content">
                  <h4>Install Python dependencies</h4>
                  <CodeBlock id="l1" code="pip3 install psutil requests" />
                </div>
              </div>
              <div className="step">
                <div className="step-num">2</div>
                <div className="step-content">
                  <h4>Option A — Shell installer</h4>
                  <CodeBlock id="l2" code="chmod +x install_linux.sh && ./install_linux.sh" />
                </div>
              </div>
              <div className="step">
                <div className="step-num">3</div>
                <div className="step-content">
                  <h4>Option B — Manual</h4>
                  <CodeBlock id="l3" code="python3 sentinel_agent.py" />
                  <p style={{ marginTop: 8 }}>For full event log access on Linux, run with <code style={{fontFamily:'var(--mono)',color:'var(--accent3)'}}>sudo</code>.</p>
                </div>
              </div>
              <div className="step">
                <div className="step-num">4</div>
                <div className="step-content">
                  <h4>Run in background (optional)</h4>
                  <CodeBlock id="l4" code="nohup python3 sentinel_agent.py > agent.log 2>&1 &" />
                </div>
              </div>
            </div>
          </div>
        </Card>
      </div>

      <Card title="What the Agent Collects" sub="All collection is local — data is sent only to this SOC server">
        <div style={{ padding: 18 }}>
          <div className="grid-3" style={{ gap: 12 }}>
            {[
              { icon: '🔐', title: 'Failed Logins',       desc: 'Windows Event ID 4625 or Linux auth.log — brute force detection' },
              { icon: '⚙️', title: 'Process Activity',    desc: 'Running processes — flags known LOLBins (PowerShell, certutil…)' },
              { icon: '🌐', title: 'Network Connections', desc: 'Active TCP/UDP connections — flags suspicious ports' },
              { icon: '📊', title: 'System Metrics',      desc: 'CPU, RAM, disk usage — reported every 30s for health monitoring' },
              { icon: '🎯', title: 'Local Detection',     desc: 'On-device rule engine generates alerts before sending to SOC' },
              { icon: '🔑', title: 'Secure Auth',         desc: 'Per-agent API key — no shared passwords, data encrypted in transit' },
            ].map(item => (
              <div key={item.title} style={{ background: 'var(--bg3)', border: '1px solid var(--border)', borderRadius: 9, padding: 16 }}>
                <div style={{ fontSize: 24, marginBottom: 8 }}>{item.icon}</div>
                <div style={{ fontWeight: 600, fontSize: 13.5, marginBottom: 5 }}>{item.title}</div>
                <div style={{ fontSize: 12.5, color: 'var(--text2)', lineHeight: 1.5 }}>{item.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </Card>
    </div>
  );
}

// ── Settings Page Helpers ──────────────────────────────────────────────────
const Toggle = ({ checked, onChange, id }) => (
  <label htmlFor={id} className="settings-toggle" style={{ cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: 8 }}>
    <input id={id} type="checkbox" checked={checked} onChange={e => onChange(e.target.checked)} style={{ display: 'none' }} />
    <span className={`toggle-track ${checked ? 'on' : 'off'}`}>
      <span className="toggle-thumb" />
    </span>
  </label>
);

const Field = ({ label, hint, children }) => (
  <div className="settings-field">
    <div className="settings-field-label">
      <span>{label}</span>
      {hint && <span className="settings-hint">{hint}</span>}
    </div>
    <div className="settings-field-control">{children}</div>
  </div>
);

const SectionTitle = ({ icon: Icon, title, desc }) => (
  <div className="settings-section-title">
    <div className="settings-section-icon"><Icon size={18} color="var(--accent)" /></div>
    <div>
      <div style={{ fontWeight: 600, fontSize: 15 }}>{title}</div>
      {desc && <div style={{ fontSize: 12.5, color: 'var(--text3)', marginTop: 2 }}>{desc}</div>}
    </div>
  </div>
);

// ── Settings Page ─────────────────────────────────────────────────────────
function SettingsPage({ user, showToast }) {
  const [activeTab, setActiveTab] = useState('profile');

  // Profile state
  const [displayName, setDisplayName] = useState(user?.username || '');
  const [email, setEmail]             = useState('analyst@sentinelsoc.local');
  const [role]                        = useState(user?.role || 'SOC Analyst');
  const [username, setUsername]       = useState(user?.username || '');

  // Notifications state
  const [notifEmail,  setNotifEmail]  = useState(true);
  const [notifSound,  setNotifSound]  = useState(false);
  const [notifPopup,  setNotifPopup]  = useState(true);
  const [notifCrit,   setNotifCrit]   = useState(true);
  const [notifHigh,   setNotifHigh]   = useState(true);
  const [notifMed,    setNotifMed]    = useState(false);
  const [notifLow,    setNotifLow]    = useState(false);

  // Appearance state
  const [theme, setTheme]             = useState(() => localStorage.getItem('theme') || 'dark');
  const [density, setDensity]         = useState(() => localStorage.getItem('density') || 'comfortable');
  const [accentColor, setAccentColor] = useState(() => localStorage.getItem('accentColor') || '#00d4ff');

  // API state
  const [apiUrl, setApiUrl]           = useState('http://localhost:4000');
  const [apiTimeout, setApiTimeout]   = useState('30');
  const [refreshInterval, setRefreshInterval] = useState('30');

  // Security state
  const [oldPw, setOldPw]             = useState('');
  const [newPw, setNewPw]             = useState('');
  const [confPw, setConfPw]           = useState('');
  const [showOld, setShowOld]         = useState(false);
  const [showNew, setShowNew]         = useState(false);
  const [pwError, setPwError]         = useState('');
  const [sessionTimeout, setSessionTimeout] = useState('60');
  const [mfa, setMfa]                 = useState(false);

  const tabs = [
    { id: 'profile',       label: 'Profile',       icon: UserCircle },
    { id: 'notifications', label: 'Notifications', icon: BellRing  },
    { id: 'appearance',    label: 'Appearance',    icon: Palette   },
    { id: 'api',           label: 'API / Backend', icon: Database  },
    { id: 'security',      label: 'Security',      icon: KeyRound  },
  ];

  const handleSavePassword = () => {
    setPwError('');
    if (!oldPw)          { setPwError('Current password is required.'); return; }
    if (newPw.length < 4){ setPwError('New password must be at least 4 characters.'); return; }
    if (newPw !== confPw){ setPwError('Passwords do not match.'); return; }
    setOldPw(''); setNewPw(''); setConfPw('');
    showToast('✅ Password updated successfully');
  };

  const renderProfile = () => (
    <div className="settings-panel fade-in">
      <SectionTitle icon={UserCircle} title="Profile Information" desc="Update your display name, email, and account details" />
      <div className="settings-avatar-row">
        <div className="settings-avatar">{(displayName || 'U')[0].toUpperCase()}</div>
        <div>
          <div style={{ fontWeight: 600 }}>{displayName || user?.username}</div>
          <div style={{ fontSize: 12.5, color: 'var(--text3)', marginTop: 2 }}>{role}</div>
          <button className="btn btn-ghost" style={{ marginTop: 10, fontSize: 12, padding: '5px 12px' }}>Change Avatar</button>
        </div>
      </div>
      <div className="settings-fields">
        <Field label="Display Name" hint="Shown in the SOC header">
          <input className="settings-input" value={displayName} onChange={e => setDisplayName(e.target.value)} placeholder="Your name" />
        </Field>
        <Field label="Email Address" hint="Used for alert notifications">
          <input className="settings-input" value={email} onChange={e => setEmail(e.target.value)} placeholder="analyst@example.com" type="email" />
        </Field>
        <Field label="Role">
          <input className="settings-input" value={role} readOnly style={{ opacity: .6, cursor: 'not-allowed' }} />
        </Field>
        <Field label="Username" hint="Your login identifier">
          <input className="settings-input" value={username} onChange={e => setUsername(e.target.value)} placeholder="Username" />
        </Field>
      </div>
      <div className="settings-actions">
        <button className="btn btn-primary" onClick={() => showToast('✅ Profile saved')}>
          <Save size={15} /> Save Profile
        </button>
      </div>
    </div>
  );

  const renderNotifications = () => (
    <div className="settings-panel fade-in">
      <SectionTitle icon={BellRing} title="Notification Preferences" desc="Choose how and when you want to be notified" />
      <div className="settings-group">
        <div className="settings-group-label">Delivery Channels</div>
        <div className="settings-fields">
          <Field label="Email Notifications" hint="Receive alerts by email">
            <Toggle id="notif-email" checked={notifEmail} onChange={setNotifEmail} />
          </Field>
          <Field label="Sound Alerts" hint="Play a sound on new critical alerts">
            <Toggle id="notif-sound" checked={notifSound} onChange={setNotifSound} />
          </Field>
          <Field label="Desktop Popup" hint="Show browser push notifications">
            <Toggle id="notif-popup" checked={notifPopup} onChange={setNotifPopup} />
          </Field>
        </div>
      </div>
      <div className="settings-group">
        <div className="settings-group-label">Alert Severity Filters</div>
        <div className="settings-fields">
          <Field label="Critical" hint="Immediate action required">
            <Toggle id="notif-crit" checked={notifCrit} onChange={setNotifCrit} />
          </Field>
          <Field label="High" hint="High severity threats">
            <Toggle id="notif-high" checked={notifHigh} onChange={setNotifHigh} />
          </Field>
          <Field label="Medium">
            <Toggle id="notif-med" checked={notifMed} onChange={setNotifMed} />
          </Field>
          <Field label="Low">
            <Toggle id="notif-low" checked={notifLow} onChange={setNotifLow} />
          </Field>
        </div>
      </div>
      <div className="settings-actions">
        <button className="btn btn-primary" onClick={() => showToast('✅ Notification settings saved')}>
          <Save size={15} /> Save Preferences
        </button>
      </div>
    </div>
  );

  const renderAppearance = () => (
    <div className="settings-panel fade-in">
      <SectionTitle icon={Palette} title="Appearance" desc="Customize the look and feel of your SOC dashboard" />
      <div className="settings-fields">
        <Field label="Theme" hint="Choose your preferred color scheme">
          <div className="theme-selector">
            {['dark','light'].map(t => (
              <button
                key={t}
                className={`theme-btn ${theme === t ? 'active' : ''}`}
                onClick={() => setTheme(t)}
                id={`theme-${t}`}
              >
                {t === 'dark' ? <Moon size={15}/> : <Sun size={15}/>}
                {t.charAt(0).toUpperCase() + t.slice(1)}
              </button>
            ))}
          </div>
        </Field>
        <Field label="Density" hint="Controls spacing between UI elements">
          <div className="density-selector">
            {['compact','comfortable','spacious'].map(d => (
              <button
                key={d}
                className={`density-btn ${density === d ? 'active' : ''}`}
                onClick={() => setDensity(d)}
                id={`density-${d}`}
              >
                {d.charAt(0).toUpperCase() + d.slice(1)}
              </button>
            ))}
          </div>
        </Field>
        <Field label="Accent Color" hint="Primary highlight color across the UI">
          <div className="color-row">
            {['#00d4ff','#7c3aed','#10b981','#f59e0b','#ef4444','#3b82f6'].map(c => (
              <button
                key={c}
                title={c}
                className={`color-dot ${accentColor === c ? 'active' : ''}`}
                style={{ background: c }}
                onClick={() => setAccentColor(c)}
              />
            ))}
            <input type="color" value={accentColor} onChange={e => setAccentColor(e.target.value)}
              style={{ width: 32, height: 32, borderRadius: '50%', border: '2px solid var(--border2)', cursor: 'pointer', background: 'none', padding: 2 }}
            />
          </div>
        </Field>
      </div>
      <div className="settings-actions">
        <button className="btn btn-primary" onClick={() => {
          localStorage.setItem('theme', theme);
          localStorage.setItem('density', density);
          localStorage.setItem('accentColor', accentColor);
          document.documentElement.setAttribute('data-theme', theme);
          document.documentElement.setAttribute('data-density', density);
          document.documentElement.style.setProperty('--accent', accentColor);
          showToast('✅ Appearance saved');
        }}>
          <Save size={15} /> Apply Changes
        </button>
        <button className="btn btn-ghost" onClick={() => { setTheme('dark'); setDensity('comfortable'); setAccentColor('#00d4ff'); }}>
          Reset to Defaults
        </button>
      </div>
    </div>
  );

  const renderApi = () => (
    <div className="settings-panel fade-in">
      <SectionTitle icon={Database} title="API & Backend Connection" desc="Configure how the frontend connects to the SOC backend" />
      <div className="settings-fields">
        <Field label="Backend URL" hint="Base URL of the SentinelSOC API server">
          <div style={{ position: 'relative' }}>
            <Globe size={15} style={{ position: 'absolute', left: 13, top: '50%', transform: 'translateY(-50%)', color: 'var(--text3)' }} />
            <input className="settings-input" style={{ paddingLeft: 38 }} value={apiUrl} onChange={e => setApiUrl(e.target.value)} placeholder="http://localhost:4000" />
          </div>
        </Field>
        <Field label="Request Timeout" hint="Max wait time in seconds per API call">
          <input className="settings-input" type="number" min={5} max={120} value={apiTimeout} onChange={e => setApiTimeout(e.target.value)} />
        </Field>
        <Field label="Dashboard Refresh Interval" hint="How often (in seconds) to auto-refresh dashboard data">
          <input className="settings-input" type="number" min={5} max={300} value={refreshInterval} onChange={e => setRefreshInterval(e.target.value)} />
        </Field>
      </div>
      <div className="settings-info-box">
        <Info size={14} style={{ flexShrink: 0 }} />
        <span>Changes to the Backend URL require a page reload to take full effect.</span>
      </div>
      <div className="settings-actions">
        <button className="btn btn-primary" onClick={() => showToast('✅ API settings saved — reload to apply')}>
          <Save size={15} /> Save & Reload
        </button>
        <button className="btn btn-ghost" onClick={() => { setApiUrl('http://localhost:4000'); setApiTimeout('30'); setRefreshInterval('30'); }}>
          Reset
        </button>
      </div>
    </div>
  );

  const renderSecurity = () => (
    <div className="settings-panel fade-in">
      <SectionTitle icon={KeyRound} title="Security" desc="Manage your password, session, and authentication settings" />
      <div className="settings-group">
        <div className="settings-group-label">Change Password</div>
        <div className="settings-fields">
          <Field label="Current Password">
            <div style={{ position: 'relative' }}>
              <input
                className="settings-input"
                type={showOld ? 'text' : 'password'}
                value={oldPw} onChange={e => setOldPw(e.target.value)}
                placeholder="Enter current password"
                style={{ paddingRight: 42 }}
              />
              <button type="button" onClick={() => setShowOld(s => !s)} className="pw-toggle" style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)' }}>
                {showOld ? <EyeOff size={15}/> : <Eye size={15}/>}
              </button>
            </div>
          </Field>
          <Field label="New Password" hint="Minimum 4 characters">
            <div style={{ position: 'relative' }}>
              <input
                className="settings-input"
                type={showNew ? 'text' : 'password'}
                value={newPw} onChange={e => setNewPw(e.target.value)}
                placeholder="Enter new password"
                style={{ paddingRight: 42 }}
              />
              <button type="button" onClick={() => setShowNew(s => !s)} className="pw-toggle" style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)' }}>
                {showNew ? <EyeOff size={15}/> : <Eye size={15}/>}
              </button>
            </div>
          </Field>
          <Field label="Confirm New Password">
            <input
              className="settings-input"
              type="password"
              value={confPw} onChange={e => setConfPw(e.target.value)}
              placeholder="Repeat new password"
            />
          </Field>
        </div>
        {pwError && (
          <div className="login-error" style={{ margin: '4px 0 8px', fontSize: 12.5 }}>
            <AlertTriangle size={13}/> {pwError}
          </div>
        )}
        <div className="settings-actions">
          <button className="btn btn-primary" onClick={handleSavePassword}>
            <KeyRound size={15}/> Update Password
          </button>
        </div>
      </div>
      <div className="settings-group">
        <div className="settings-group-label">Session &amp; Authentication</div>
        <div className="settings-fields">
          <Field label="Session Timeout" hint="Minutes of inactivity before auto-logout">
            <input className="settings-input" type="number" min={5} max={480} value={sessionTimeout} onChange={e => setSessionTimeout(e.target.value)} />
          </Field>
          <Field label="Two-Factor Authentication" hint="Adds an extra layer of sign-in security">
            <Toggle id="mfa" checked={mfa} onChange={v => { setMfa(v); showToast(v ? '🔐 MFA enabled (simulated)' : 'MFA disabled'); }} />
          </Field>
        </div>
      </div>
      <div className="settings-danger-zone">
        <div style={{ fontWeight: 600, color: 'var(--danger)', marginBottom: 4 }}>Danger Zone</div>
        <div style={{ fontSize: 12.5, color: 'var(--text3)', marginBottom: 14 }}>These actions are irreversible. Proceed with caution.</div>
        <button className="btn btn-danger" onClick={() => showToast('⚠️ All sessions terminated (simulated)')}>Terminate All Sessions</button>
      </div>
    </div>
  );

  const renderMap = { profile: renderProfile, notifications: renderNotifications, appearance: renderAppearance, api: renderApi, security: renderSecurity };

  return (
    <div className="settings-layout fade-in">
      {/* Sidebar tabs */}
      <nav className="settings-nav">
        {tabs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            id={`settings-tab-${id}`}
            className={`settings-tab ${activeTab === id ? 'active' : ''}`}
            onClick={() => setActiveTab(id)}
          >
            <Icon size={16} />
            <span>{label}</span>
            <ChevronRight size={14} className="settings-tab-arrow" />
          </button>
        ))}
      </nav>
      {/* Content area */}
      <div className="settings-content">
        {renderMap[activeTab]?.()}
      </div>
    </div>
  );
}

// ── Investigation Page ─────────────────────────────────────────────────────
function InvestigationPage({ onRowClick }) {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState([]);
  const [searched, setSearched] = useState(false);

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!query.trim()) return;
    setLoading(true);
    try {
      const [alerts, events] = await Promise.all([
        api('/alerts'),
        api('/events')
      ]);
      const q = query.toLowerCase();
      
      const filteredAlerts = alerts.filter(a => 
        (a.source_ip || '').toLowerCase().includes(q) ||
        (a.process || '').toLowerCase().includes(q) ||
        (a.username || '').toLowerCase().includes(q) ||
        (a.name || '').toLowerCase().includes(q)
      ).map(a => ({ ...a, _type: 'alert' }));
      
      const filteredEvents = events.filter(e => 
        (e.source_ip || '').toLowerCase().includes(q) ||
        (e.process || '').toLowerCase().includes(q) ||
        (e.username || '').toLowerCase().includes(q)
      ).map(e => ({ ...e, _type: 'event' }));
      
      const combined = [...filteredAlerts, ...filteredEvents].sort((a, b) => 
        new Date(b.timestamp) - new Date(a.timestamp)
      );
      
      setData(combined);
      setSearched(true);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fade-in">
      <Card title="Threat Investigation" sub="Search and correlate alerts and events across all endpoints">
        <form onSubmit={handleSearch} style={{ display: 'flex', gap: 10, marginBottom: 20 }}>
          <div style={{ position: 'relative', flex: 1 }}>
            <Search size={16} style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: 'var(--text3)' }} />
            <input 
              className="settings-input" 
              style={{ paddingLeft: 40, width: '100%' }}
              placeholder="Search by IP, Process (e.g. powershell.exe), Username, or Alert Name..."
              value={query}
              onChange={e => setQuery(e.target.value)}
            />
          </div>
          <button type="submit" className="btn btn-primary" disabled={loading || !query.trim()}>
            {loading ? 'Searching...' : 'Search Telemetry'}
          </button>
        </form>

        {searched && (
          <div className="investigation-results" style={{ marginTop: 30 }}>
            <h3 style={{ marginBottom: 20, fontSize: 14, color: 'var(--text2)' }}>
              Found {data.length} records matching "{query}"
            </h3>
            
            {data.length === 0 ? (
               <div className="empty-state" style={{ padding: '40px 0' }}>No matching alerts or events found.</div>
            ) : (
              <div className="timeline">
                {data.map(item => (
                  <div key={item.id} className="timeline-item" onClick={() => onRowClick(item)}>
                    <div className="timeline-icon" style={{ background: item._type === 'alert' ? 'var(--danger)' : 'var(--accent)' }}>
                      {item._type === 'alert' ? <ShieldAlert size={14} /> : <Activity size={14} />}
                    </div>
                    <div className="timeline-content">
                      <div className="timeline-header">
                        <strong>{item._type === 'alert' ? item.name : item.event_type}</strong>
                        <span className="timeline-time">{new Date(item.timestamp).toLocaleString()}</span>
                      </div>
                      <div className="timeline-body">
                        {item.process && <span><Terminal size={12}/> {item.process}</span>}
                        {item.source_ip && <span><Globe size={12}/> {item.source_ip}</span>}
                        {item.username && <span><User size={12}/> {item.username}</span>}
                        {item.hostname && <span><Monitor size={12}/> {item.hostname}</span>}
                        {item.severity && <span style={{ color: item.severity === 'HIGH' || item.severity === 'CRITICAL' ? 'var(--danger)' : item.severity === 'MEDIUM' ? 'var(--warning)' : 'var(--success)' }}>{item.severity}</span>}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </Card>
    </div>
  );
}

// ── Generic Pages ──────────────────────────────────────────────────────────
function GenericPage({ page, onRowClick }) {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [importantOnly, setImportantOnly] = useState(false);

  const pathMap = {
    'Alerts':      ['/alerts',           ['Alert ID','Name','Severity','Source IP','Endpoint','Username','Status'], ['id','name','severity','source_ip','hostname','username','status']],
    'Endpoints':   ['/endpoints',        ['Agent ID','Hostname','IP','OS','Status','CPU','RAM','Disk','Alerts'],     ['id','hostname','ip','os','status','cpu','mem','disk','alert_count']],
    'Log Explorer':['/events',           ['Event ID','Timestamp','Type','Username','Source IP','Process','Severity'],['id','timestamp','event_type','username','source_ip','process','severity']],
    'Detections':  ['/detections',       ['Rule','Name','Severity','Technique','Triggers','Status'],                 ['id','name','severity','technique','triggerCount','enabled']],
    'MITRE ATT&CK':['/mitre/techniques', ['ID','Name','Tactic','Detections'],                                        ['id','name','tactic','detections']],
  };

  useEffect(() => {
    const cfg = pathMap[page];
    let t;
    if (cfg) {
      setLoading(true);
      const load = () => api(cfg[0]).then(setRows).catch(console.error).finally(() => setLoading(false));
      load();
      t = setInterval(load, 10000);
    } else { setLoading(false); }
    return () => { if (t) clearInterval(t); };
  }, [page]);

  const cfg = pathMap[page];
  if (!cfg) {
    return (
      <Card title={page}>
        <div className="empty-state">
          <div className="empty-icon"><FileText size={26}/></div>
          <h3>{page}</h3>
          <p>This module is ready for the next development phase. Integration with live agent data will be added here.</p>
        </div>
      </Card>
    );
  }

  if (loading) return <div className="empty-state">Loading {page}…</div>;

  let displayRows = rows;
  if (page === 'Alerts' && importantOnly) {
    displayRows = rows.filter(r => r.severity === 'CRITICAL' || r.severity === 'HIGH');
  }

  const actionBtn = page === 'Alerts' ? (
    <div className="setting-row" style={{ padding: 0, margin: 0, border: 'none', background: 'transparent' }}>
      <label style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
        <div className={`toggle ${importantOnly ? 'on' : ''}`}>
           <input type="checkbox" checked={importantOnly} onChange={(e) => setImportantOnly(e.target.checked)} style={{ display: 'none' }}/>
           <div className="toggle-thumb" />
        </div>
        Important Only (CRITICAL / HIGH)
      </label>
    </div>
  ) : null;

  return (
    <div className="fade-in">
      <Card title={`${page}`} sub={`${displayRows.length} records`} action={actionBtn}>
        <DataTable rows={displayRows} cols={cfg[1]} keys={cfg[2]} onRowClick={onRowClick} />
      </Card>
    </div>
  );
}

// ── Main App ───────────────────────────────────────────────────────────────
function App() {
  const [user,    setUser]    = useState(() => { try { return JSON.parse(localStorage.user); } catch { return null; } });
  const [page,    setPage]    = useState('Dashboard');
  const [data,    setData]    = useState(null);
  const [toast,   setToast]   = useState('');
  const [selectedDetails, setSelectedDetails] = useState(null);
  const [alertCt, setAlertCt] = useState(0);

  const logout = () => { localStorage.clear(); setUser(null); };

  const loadDashboard = useCallback(() => {
    if (user) api('/dashboard').then(d => { setData(d); setAlertCt(d.kpis?.totalAlerts || 0); }).catch(() => logout());
  }, [user]);

  useEffect(() => {
    loadDashboard();
    const t = setInterval(loadDashboard, 30000);
    return () => clearInterval(t);
  }, [loadDashboard]);

  const showToast = msg => { setToast(msg); setTimeout(() => setToast(''), 3000); };

  if (!user) return <Login onLogin={u => { setUser(u); }} />;

  const navSections = [
    { label: 'Monitoring', items: [
      ['Dashboard',    LayoutDashboard],
      ['Alerts',       ShieldAlert],
      ['Log Explorer', Radio],
    ]},
    { label: 'Assets', items: [
      ['Endpoints', Monitor],
      ['Incidents', BriefcaseBusiness],
    ]},
    { label: 'Intelligence', items: [
      ['Threat Intel',  Search],
      ['Detections',    Target],
      ['MITRE ATT&CK',  Waypoints],
      ['Investigation', Activity],
    ]},
    { label: 'Management', items: [
      ['Download Agent', Download],
      ['Reports',        FileText],
      ['Settings',       Settings],
    ]},
  ];

  return (
    <div className="app">
      <aside>
        <div className="brand"><ShieldAlert size={22}/> SentinelSOC</div>
        <div className="lab-badge">LIVE MODE</div>
        {navSections.map(sec => (
          <React.Fragment key={sec.label}>
            <div className="nav-section">{sec.label}</div>
            {sec.items.map(([n, Icon]) => (
              <button
                key={n}
                className={`nav${page === n ? ' active' : ''}`}
                onClick={() => setPage(n)}
              >
                <Icon size={16} />
                {n}
                {n === 'Alerts' && alertCt > 0 && (
                  <span style={{
                    marginLeft: 'auto', background: 'var(--danger)',
                    color: '#fff', borderRadius: 99, fontSize: 10,
                    padding: '1px 6px', fontWeight: 700
                  }}>{alertCt}</span>
                )}
              </button>
            ))}
          </React.Fragment>
        ))}
        <div style={{ flex: 1 }} />
        <button className="nav logout" onClick={logout}><LogOut size={16}/> Logout</button>
      </aside>

      <main>
        <header>
          <div>
            <strong>{page}</strong>
            <span className="crumb"> / Security Operations</span>
          </div>
          <div className="header-right">
            <div className="search-bar"><Search size={14}/> Global search…</div>
            <div className="bell-wrap">
              <Bell size={18}/>
              {alertCt > 0 && <div className="bell-dot"/>}
            </div>
            <div className="avatar" title={user.username}>{user.username[0].toUpperCase()}</div>
          </div>
        </header>

        <section className="content">
          <div className="page-head">
            <div>
              <h1>{page}</h1>
              <p>{page === 'Download Agent' ? 'Install the security agent on any machine to start ingesting real telemetry.' : 'Monitor, investigate and respond to security activity across all enrolled endpoints.'}</p>
            </div>
            <div className="page-actions">
              {page === 'Dashboard' && (
                <button className="btn btn-ghost" onClick={loadDashboard}><RefreshCw size={15}/> Refresh</button>
              )}
              {page === 'Download Agent' && (
                <button className="btn btn-primary" onClick={() => {
                  const a = document.createElement('a');
                  a.href = 'http://localhost:4000/api/download/agent';
                  a.download = 'sentinel_agent.py';
                  a.click();
                }}><Download size={15}/> Download Agent</button>
              )}
            </div>
          </div>

          {page === 'Dashboard'      && <Dashboard data={data} onNavigate={setPage} onRowClick={setSelectedDetails} />}
          {page === 'Endpoints'      && <Endpoints onNavigate={setPage} />}
          {page === 'Download Agent' && <DownloadAgent />}
          {page === 'Settings'       && <SettingsPage user={user} showToast={showToast} />}
          {page === 'Investigation'  && <InvestigationPage onRowClick={setSelectedDetails} />}
          {!['Dashboard','Endpoints','Download Agent','Settings','Investigation'].includes(page) && <GenericPage page={page} onRowClick={setSelectedDetails} />}
        </section>
      </main>

      <Modal title="Record Details" data={selectedDetails} onClose={() => setSelectedDetails(null)} />
      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}

createRoot(document.getElementById('root')).render(<App />);

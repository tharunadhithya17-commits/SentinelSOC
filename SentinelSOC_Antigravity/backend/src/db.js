import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { mkdirSync } from 'fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DB_PATH = join(__dirname, '..', 'data', 'sentinelsoc.db');

// Ensure data directory exists
mkdirSync(join(__dirname, '..', 'data'), { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ── Schema ─────────────────────────────────────────────────────────────────

db.exec(`
  CREATE TABLE IF NOT EXISTS agents (
    id          TEXT PRIMARY KEY,
    api_key     TEXT NOT NULL UNIQUE,
    hostname    TEXT NOT NULL,
    ip          TEXT,
    os          TEXT,
    os_version  TEXT,
    arch        TEXT,
    status      TEXT DEFAULT 'OFFLINE',
    last_seen   TEXT,
    registered  TEXT NOT NULL,
    cpu         REAL DEFAULT 0,
    mem         REAL DEFAULT 0,
    disk        REAL DEFAULT 0,
    risk_score  INTEGER DEFAULT 0,
    alert_count INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS events (
    id          TEXT PRIMARY KEY,
    agent_id    TEXT NOT NULL,
    hostname    TEXT,
    timestamp   TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    username    TEXT,
    source_ip   TEXT,
    destination TEXT,
    process     TEXT,
    severity    TEXT DEFAULT 'LOW',
    raw         TEXT,
    FOREIGN KEY (agent_id) REFERENCES agents(id)
  );

  CREATE TABLE IF NOT EXISTS alerts (
    id          TEXT PRIMARY KEY,
    agent_id    TEXT NOT NULL,
    hostname    TEXT,
    timestamp   TEXT NOT NULL,
    name        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    technique   TEXT,
    source_ip   TEXT,
    username    TEXT,
    status      TEXT DEFAULT 'NEW',
    FOREIGN KEY (agent_id) REFERENCES agents(id)
  );

  CREATE INDEX IF NOT EXISTS idx_events_agent   ON events(agent_id);
  CREATE INDEX IF NOT EXISTS idx_events_time    ON events(timestamp DESC);
  CREATE INDEX IF NOT EXISTS idx_alerts_agent   ON alerts(agent_id);
  CREATE INDEX IF NOT EXISTS idx_alerts_time    ON alerts(timestamp DESC);
  CREATE INDEX IF NOT EXISTS idx_alerts_status  ON alerts(status);
`);

export default db;

import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DB_PATH = join(__dirname, 'data', 'sentinelsoc.db');

const db = new Database(DB_PATH);
const alertsInfo = db.prepare(`DELETE FROM alerts`).run();
const eventsInfo = db.prepare(`DELETE FROM events`).run();
db.prepare('UPDATE agents SET alert_count=0, risk_score=0').run();
console.log('Deleted', alertsInfo.changes, 'alerts and', eventsInfo.changes, 'events.');

import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DB_PATH = join(__dirname, 'data', 'sentinelsoc.db');

const db = new Database(DB_PATH);
const info = db.prepare(`DELETE FROM alerts WHERE name = 'Suspicious Network Connection'`).run();
console.log('Deleted', info.changes, 'old generic alerts.');

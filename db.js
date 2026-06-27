const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'bughunter.db');
const KEY_PATH = process.env.VAULT_KEY_PATH || path.join(path.dirname(DB_PATH), '.vault_key');

// Persist encryption key to a file so it survives restarts
function loadOrCreateKey() {
  if (process.env.VAULT_ENCRYPTION_KEY) return process.env.VAULT_ENCRYPTION_KEY;
  try {
    const fs = require('fs');
    if (fs.existsSync(KEY_PATH)) return fs.readFileSync(KEY_PATH, 'utf8').trim();
    const key = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(KEY_PATH, key, { mode: 0o600 });
    return key;
  } catch (e) {
    return crypto.randomBytes(32).toString('hex');
  }
}
const ENCRYPTION_KEY = loadOrCreateKey();

let db;

function getDb() {
  if (!db) {
    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
    initSchema();
  }
  return db;
}

function initSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS targets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      url TEXT NOT NULL UNIQUE,
      slug TEXT NOT NULL UNIQUE,
      program_name TEXT,
      scope_in TEXT DEFAULT '*',
      scope_out TEXT DEFAULT '',
      target_type TEXT DEFAULT 'web',
      tech_stack TEXT DEFAULT '',
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS hunt_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target_id INTEGER NOT NULL,
      mode TEXT NOT NULL DEFAULT 'bounty',
      status TEXT NOT NULL DEFAULT 'pending',
      current_phase TEXT DEFAULT 'INIT',
      phase_data TEXT DEFAULT '{}',
      findings_count INTEGER DEFAULT 0,
      started_at TEXT DEFAULT (datetime('now')),
      completed_at TEXT,
      elapsed_seconds INTEGER DEFAULT 0,
      config TEXT DEFAULT '{}',
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS hunt_phases (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id INTEGER NOT NULL,
      phase_name TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      started_at TEXT,
      completed_at TEXT,
      duration_ms INTEGER DEFAULT 0,
      output TEXT DEFAULT '',
      error TEXT,
      retry_count INTEGER DEFAULT 0,
      FOREIGN KEY (session_id) REFERENCES hunt_sessions(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id INTEGER NOT NULL,
      agent_name TEXT,
      title TEXT NOT NULL,
      description TEXT,
      vulnerability_type TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'info',
      cvss_score REAL DEFAULT 0,
      cvss_vector TEXT,
      endpoint TEXT,
      method TEXT DEFAULT 'GET',
      parameter TEXT,
      payload_used TEXT,
      evidence TEXT,
      remediation TEXT,
      refs TEXT,
      is_zero_day INTEGER DEFAULT 0,
      has_poc INTEGER DEFAULT 0,
      cve_id TEXT,
      chain_parent_id INTEGER,
      status TEXT DEFAULT 'open',
      discovered_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (session_id) REFERENCES hunt_sessions(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS credentials (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target_name TEXT NOT NULL UNIQUE,
      username TEXT,
      password_encrypted TEXT,
      cookie TEXT,
      jwt TEXT,
      api_key_encrypted TEXT,
      notes TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS patterns (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      pattern_type TEXT NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      tech_stack TEXT,
      vulnerability_type TEXT,
      effectiveness TEXT DEFAULT 'unknown',
      payload TEXT,
      false_positive_rate REAL DEFAULT 0,
      times_used INTEGER DEFAULT 0,
      times_succeeded INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS learning_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id INTEGER,
      category TEXT NOT NULL,
      content TEXT NOT NULL,
      tags TEXT DEFAULT '',
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (session_id) REFERENCES hunt_sessions(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS hunt_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id INTEGER NOT NULL,
      event_type TEXT NOT NULL,
      phase TEXT,
      message TEXT NOT NULL,
      metadata TEXT DEFAULT '{}',
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (session_id) REFERENCES hunt_sessions(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS config (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT DEFAULT (datetime('now'))
    );
  `);

  // Seed default config
  const insertConfig = db.prepare(
    'INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)'
  );
  insertConfig.run('cvss_threshold_bounty', '8.0');
  insertConfig.run('cvss_threshold_pentest', '4.0');
  insertConfig.run('cvss_threshold_comprehensive', '0.0');
  insertConfig.run('max_concurrent_agents', '5');
  insertConfig.run('agent_timeout_minutes', '15');
  insertConfig.run('max_findings_bounty', '10');
  insertConfig.run('max_findings_pentest', '20');
  insertConfig.run('max_findings_comprehensive', '50');
}

function encrypt(text) {
  if (!text) return null;
  const iv = crypto.randomBytes(16);
  const key = Buffer.from(ENCRYPTION_KEY.slice(0, 64), 'hex');
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedText) {
  if (!encryptedText) return null;
  const parts = encryptedText.split(':');
  if (parts.length !== 2) return null;
  const iv = Buffer.from(parts[0], 'hex');
  const key = Buffer.from(ENCRYPTION_KEY.slice(0, 64), 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(parts[1], 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Target operations
function createTarget({ name, url, program_name, scope_in, scope_out, target_type, tech_stack }) {
  const slug = url.replace(/[^a-zA-Z0-9]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '').toLowerCase();
  const stmt = getDb().prepare(
    'INSERT INTO targets (name, url, slug, program_name, scope_in, scope_out, target_type, tech_stack) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  );
  return stmt.run(name, url, slug, program_name || null, scope_in || '*', scope_out || '', target_type || 'web', tech_stack || '');
}

function getTarget(id) {
  return getDb().prepare('SELECT * FROM targets WHERE id = ?').get(id);
}

function getTargetByUrl(url) {
  return getDb().prepare('SELECT * FROM targets WHERE url = ?').get(url);
}

function getAllTargets() {
  return getDb().prepare('SELECT * FROM targets ORDER BY updated_at DESC').all();
}

// Session operations
function createSession(target_id, mode, config = {}) {
  const stmt = getDb().prepare(
    'INSERT INTO hunt_sessions (target_id, mode, config, phase_data) VALUES (?, ?, ?, ?)'
  );
  const phases = ['INIT', 'MEMORY_LOAD', 'TARGET_INGEST', 'APP_UNDERSTANDING', 'RECON', 'AGENT_DEPLOY', 'DYNAMIC_TEST', 'VULN_ASSESS', 'LEARNING', 'REPORT'];
  const phaseData = {};
  phases.forEach(p => { phaseData[p] = 'pending'; });
  const result = stmt.run(target_id, mode, JSON.stringify(config), JSON.stringify(phaseData));

  // Create phase records
  const phaseStmt = getDb().prepare(
    'INSERT INTO hunt_phases (session_id, phase_name, status) VALUES (?, ?, ?)'
  );
  phases.forEach(p => { phaseStmt.run(result.lastInsertRowid, p, 'pending'); });

  return result;
}

function getSession(id) {
  const session = getDb().prepare('SELECT * FROM hunt_sessions WHERE id = ?').get(id);
  if (session) {
    session.phase_data = JSON.parse(session.phase_data || '{}');
    session.config = JSON.parse(session.config || '{}');
  }
  return session;
}

function getSessionsByTarget(target_id) {
  const sessions = getDb().prepare('SELECT * FROM hunt_sessions WHERE target_id = ? ORDER BY started_at DESC').all(target_id);
  return sessions.map(s => ({ ...s, phase_data: JSON.parse(s.phase_data || '{}'), config: JSON.parse(s.config || '{}') }));
}

function getAllSessions() {
  const sessions = getDb().prepare(`
    SELECT hs.*, t.name as target_name, t.url as target_url
    FROM hunt_sessions hs
    JOIN targets t ON hs.target_id = t.id
    ORDER BY hs.started_at DESC
  `).all();
  return sessions.map(s => ({ ...s, phase_data: JSON.parse(s.phase_data || '{}'), config: JSON.parse(s.config || '{}') }));
}

function updateSessionPhase(session_id, phase, status) {
  const session = getSession(session_id);
  if (!session) return;
  session.phase_data[phase] = status;
  getDb().prepare('UPDATE hunt_sessions SET phase_data = ?, current_phase = ?, updated_at = datetime(\'now\') WHERE id = ?')
    .run(JSON.stringify(session.phase_data), phase, session_id);
  getDb().prepare('UPDATE hunt_phases SET status = ?, started_at = COALESCE(started_at, datetime(\'now\')), completed_at = CASE WHEN ? IN (\'completed\',\'failed\',\'skipped\') THEN datetime(\'now\') ELSE completed_at END WHERE session_id = ? AND phase_name = ?')
    .run(status, status, session_id, phase);
}

function getSessionPhases(session_id) {
  return getDb().prepare('SELECT * FROM hunt_phases WHERE session_id = ? ORDER BY id').all(session_id);
}

// Finding operations
function createFinding(session_id, data) {
  const stmt = getDb().prepare(`
    INSERT INTO findings (session_id, agent_name, title, description, vulnerability_type, severity, cvss_score, cvss_vector, endpoint, method, parameter, payload_used, evidence, remediation, is_zero_day, has_poc, cve_id, refs)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const result = stmt.run(
    session_id, data.agent_name, data.title, data.description || '', data.vulnerability_type,
    data.severity || 'info', data.cvss_score || 0, data.cvss_vector || null,
    data.endpoint || null, data.method || 'GET', data.parameter || null,
    data.payload_used || null, data.evidence || '', data.remediation || '',
    data.is_zero_day || 0, data.has_poc || 0, data.cve_id || null, data.refs || ''
  );
  getDb().prepare('UPDATE hunt_sessions SET findings_count = findings_count + 1, updated_at = datetime(\'now\') WHERE id = ?').run(session_id);
  return result;
}

function getFindingsBySession(session_id) {
  return getDb().prepare('SELECT * FROM findings WHERE session_id = ? ORDER BY cvss_score DESC, discovered_at DESC').all(session_id);
}

function getAllFindings() {
  return getDb().prepare(`
    SELECT f.*, t.name as target_name, t.url as target_url
    FROM findings f
    JOIN hunt_sessions hs ON f.session_id = hs.id
    JOIN targets t ON hs.target_id = t.id
    ORDER BY f.discovered_at DESC
  `).all();
}

// Credential operations
function storeCredential(target_name, username, password, cookie, jwt, api_key, notes) {
  const stmt = getDb().prepare(`
    INSERT INTO credentials (target_name, username, password_encrypted, cookie, jwt, api_key_encrypted, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(target_name) DO UPDATE SET
      username = COALESCE(excluded.username, username),
      password_encrypted = COALESCE(excluded.password_encrypted, password_encrypted),
      cookie = COALESCE(excluded.cookie, cookie),
      jwt = COALESCE(excluded.jwt, jwt),
      api_key_encrypted = COALESCE(excluded.api_key_encrypted, api_key_encrypted),
      notes = COALESCE(excluded.notes, notes),
      updated_at = datetime('now')
  `);
  return stmt.run(target_name, username || null, encrypt(password), cookie || null, jwt || null, encrypt(api_key), notes || null);
}

function getCredential(target_name) {
  const row = getDb().prepare('SELECT * FROM credentials WHERE target_name = ?').get(target_name);
  if (!row) return null;
  return {
    ...row,
    password: decrypt(row.password_encrypted),
    api_key: decrypt(row.api_key_encrypted)
  };
}

function getAllCredentials() {
  const rows = getDb().prepare('SELECT id, target_name, username, cookie, jwt, password_encrypted, api_key_encrypted, notes, created_at, updated_at FROM credentials ORDER BY target_name').all();
  return rows.map(r => ({
    id: r.id,
    target_name: r.target_name,
    username: r.username,
    cookie: r.cookie,
    jwt: r.jwt,
    has_password: !!r.password_encrypted,
    has_api_key: !!r.api_key_encrypted,
    notes: r.notes,
    created_at: r.created_at,
    updated_at: r.updated_at
  }));
}

// Pattern operations
function savePattern(data) {
  const stmt = getDb().prepare(`
    INSERT INTO patterns (pattern_type, name, description, tech_stack, vulnerability_type, effectiveness, payload, false_positive_rate, times_used, times_succeeded)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  return stmt.run(data.pattern_type, data.name, data.description || '', data.tech_stack || '', data.vulnerability_type || '', data.effectiveness || 'unknown', data.payload || null, data.false_positive_rate || 0, data.times_used || 0, data.times_succeeded || 0);
}

function getPatternsByType(pattern_type) {
  return getDb().prepare('SELECT * FROM patterns WHERE pattern_type = ? ORDER BY times_succeeded DESC').all(pattern_type);
}

function getAllPatterns() {
  return getDb().prepare('SELECT * FROM patterns ORDER BY pattern_type, times_succeeded DESC').all();
}

// Event log operations
function logEvent(session_id, event_type, phase, message, metadata = {}) {
  return getDb().prepare('INSERT INTO hunt_events (session_id, event_type, phase, message, metadata) VALUES (?, ?, ?, ?, ?)')
    .run(session_id, event_type, phase || null, message, JSON.stringify(metadata));
}

function getEvents(session_id) {
  return getDb().prepare('SELECT * FROM hunt_events WHERE session_id = ? ORDER BY created_at').all(session_id);
}

// Learning log operations
function saveLearningLog(session_id, category, content, tags) {
  return getDb().prepare('INSERT INTO learning_logs (session_id, category, content, tags) VALUES (?, ?, ?, ?)')
    .run(session_id, category, content, tags || '');
}

function getLearningLogs(category) {
  if (category) {
    return getDb().prepare('SELECT * FROM learning_logs WHERE category = ? ORDER BY created_at DESC').all(category);
  }
  return getDb().prepare('SELECT * FROM learning_logs ORDER BY created_at DESC').all();
}

module.exports = {
  getDb, initSchema, encrypt, decrypt,
  createTarget, getTarget, getTargetByUrl, getAllTargets,
  createSession, getSession, getSessionsByTarget, getAllSessions, updateSessionPhase, getSessionPhases,
  createFinding, getFindingsBySession, getAllFindings,
  storeCredential, getCredential, getAllCredentials,
  savePattern, getPatternsByType, getAllPatterns,
  logEvent, getEvents,
  saveLearningLog, getLearningLogs,
  DB_PATH
};

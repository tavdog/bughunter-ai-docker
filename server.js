const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const { spawn, execSync, exec } = require('child_process');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const db = require('./db');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Tool paths — search common locations
function findTool(name) {
  const paths = [
    `/root/go/bin/${name}`,
    `/usr/local/bin/${name}`,
    `/usr/bin/${name}`,
  ];
  for (const p of paths) {
    try { require('fs').accessSync(p, require('fs').constants.X_OK); return p; } catch {}
  }
  return paths[0]; // return default even if not found (toolAvailable will catch it)
}

const TOOLS = {
  subfinder: findTool('subfinder'),
  httpx: findTool('httpx'),
  nuclei: findTool('nuclei'),
  naabu: findTool('naabu'),
  sqlmap: findTool('sqlmap'),
  ffuf: findTool('ffuf')
};

// Active hunt runners and SSE clients
const activeHunts = new Map();
const sseClients = new Set();

// Broadcast to all WebSocket clients
function broadcast(data) {
  const msg = JSON.stringify(data);
  wss.clients.forEach(client => {
    if (client.readyState === 1) client.send(msg);
  });
}

// Broadcast to SSE clients
function broadcastSSE(data) {
  const msg = `data: ${JSON.stringify(data)}\n\n`;
  sseClients.forEach(res => res.write(msg));
}

// Run a command with timeout, return stdout/stderr
function runCommand(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const timeout = opts.timeout || 120000;
    const input = opts.input;
    delete opts.input;
    const child = spawn(cmd, args, {
      ...opts,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, PATH: `/root/go/bin:/usr/local/bin:${process.env.PATH}`, GOPATH: '/root/go' }
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', d => { stdout += d.toString(); });
    child.stderr.on('data', d => { stderr += d.toString(); });
    if (input) {
      child.stdin.write(input);
      child.stdin.end();
    }
    const timer = setTimeout(() => { child.kill(); resolve({ stdout, stderr, killed: true }); }, timeout);
    child.on('close', code => {
      clearTimeout(timer);
      resolve({ stdout, stderr, code });
    });
  });
}

// Build curl auth args from vault credentials
function buildAuthArgs(cred) {
  const args = [];
  if (!cred) return args;
  if (cred.username && cred.password) {
    args.push('-u', `${cred.username}:${cred.password}`);
  }
  if (cred.cookie) {
    args.push('-H', `Cookie: ${cred.cookie}`);
  }
  if (cred.jwt) {
    args.push('-H', `Authorization: Bearer ${cred.jwt}`);
  }
  if (cred.api_key) {
    args.push('-H', `X-API-Key: ${cred.api_key}`);
  }
  return args;
}

// Check if a host is in scope for testing
// Load credentials for a target from vault
function loadCredentials(target) {
  let cred = db.getCredential(target.name);
  if (!cred) cred = db.getCredential(target.url);
  if (!cred) {
    // Try matching by slug
    try {
      const rows = db.getDb().prepare('SELECT * FROM credentials WHERE target_name LIKE ?').all(`%${target.name}%`);
      if (rows.length > 0) {
        cred = rows[0];
        cred.password = db.decrypt(cred.password_encrypted);
        cred.api_key = db.decrypt(cred.api_key_encrypted);
      }
    } catch(e) {}
  }
  return cred;
}

// Run Claude Code as AI backend
const CLAUDE_BIN = '/root/.local/bin/claude';

// AI provider configuration
function getAIConfig() {
  const db = require('./db');
  try {
    // Database settings take priority, env vars are fallbacks
    const provider = db.getDb().prepare("SELECT value FROM config WHERE key = 'ai_provider'").get();
    const model = db.getDb().prepare("SELECT value FROM config WHERE key = 'ai_model'").get();
    const baseUrl = db.getDb().prepare("SELECT value FROM config WHERE key = 'ai_base_url'").get();
    const encKey = db.getDb().prepare("SELECT value FROM config WHERE key = 'ai_api_key_encrypted'").get();

    let apiKey = null;
    if (encKey && encKey.value) {
      apiKey = db.decrypt(encKey.value);
    }

    // Env var overrides (for backward compatibility)
    const envKey = process.env.ANTHROPIC_AUTH_TOKEN || process.env.ANTHROPIC_API_KEY || process.env.OPENAI_API_KEY;

    return {
      provider: provider?.value || 'claude',
      model: model?.value || process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-6',
      baseUrl: baseUrl?.value || process.env.ANTHROPIC_BASE_URL || '',
      apiKey: apiKey || envKey || ''
    };
  } catch(e) {
    return { provider: 'claude', model: 'claude-sonnet-4-6', baseUrl: '', apiKey: '' };
  }
}

function aiAvailable() {
  const config = getAIConfig();
  switch (config.provider) {
    case 'claude':
      if (config.apiKey) return true;
      try { require('fs').accessSync(CLAUDE_BIN, require('fs').constants.X_OK); return true; } catch { return false; }
    case 'openai':
    case 'custom':
      return !!config.apiKey;
    case 'ollama':
      return !!config.baseUrl;
    default:
      return false;
  }
}

async function runAI(prompt, opts = {}) {
  const config = getAIConfig();
  const timeout = opts.timeout || 120000;

  switch (config.provider) {
    case 'claude': {
      // Claude Code binary (preferred) or direct API
      if (!config.apiKey) {
        const result = await runCommand(CLAUDE_BIN, ['-p', prompt], { timeout });
        return result.stdout.trim();
      }
      // Use Anthropic API directly
      const resp = await fetch(`${config.baseUrl || 'https://api.anthropic.com'}/v1/messages`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': config.apiKey,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model: config.model || 'claude-sonnet-4-6',
          max_tokens: 4096,
          messages: [{ role: 'user', content: prompt }]
        }),
        signal: AbortSignal.timeout(timeout)
      });
      const data = await resp.json();
      return data.content?.[0]?.text || JSON.stringify(data);
    }

    case 'openai': {
      const resp = await fetch(`${config.baseUrl || 'https://api.openai.com'}/v1/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${config.apiKey}`
        },
        body: JSON.stringify({
          model: config.model || 'gpt-4o',
          max_tokens: 4096,
          messages: [{ role: 'user', content: prompt }]
        }),
        signal: AbortSignal.timeout(timeout)
      });
      const data = await resp.json();
      return data.choices?.[0]?.message?.content || JSON.stringify(data);
    }

    case 'ollama':
    case 'custom': {
      const resp = await fetch(`${config.baseUrl}/v1/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(config.apiKey ? { 'Authorization': `Bearer ${config.apiKey}` } : {})
        },
        body: JSON.stringify({
          model: config.model || 'llama3',
          max_tokens: 4096,
          messages: [{ role: 'user', content: prompt }]
        }),
        signal: AbortSignal.timeout(timeout)
      });
      const data = await resp.json();
      return data.choices?.[0]?.message?.content || JSON.stringify(data);
    }

    default:
      throw new Error(`Unknown AI provider: ${config.provider}`);
  }
}

// CVSS v3.1 base score calculator (simplified but real)
function calculateCVSS(params) {
  const { AV, AC, PR, UI, S, C, I, A } = params;
  const weights = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    PR: { N: 0.85, L: { U: 0.62, C: 0.68 }, H: { U: 0.27, C: 0.5 } },
    UI: { N: 0.85, R: 0.62 },
    CIA: { N: 0, L: 0.22, H: 0.56 }
  };
  const scope = S === 'C' ? 'C' : 'U';
  let prWeight = typeof PR === 'string' ? (weights.PR[PR][scope] || 0.62) : 0.62;

  const exploitability = 8.22 * weights.AV[AV] * weights.AC[AC] * prWeight * weights.UI[UI];
  const impactSub = 1 - (1 - weights.CIA[C]) * (1 - weights.CIA[I]) * (1 - weights.CIA[A]);
  const impact = scope === 'U' ? 6.42 * impactSub : 7.52 * (impactSub - 0.029) - 3.25 * Math.pow(impactSub - 0.02, 15);
  const score = impact <= 0 ? 0 : (scope === 'U' ? Math.min(exploitability + impact, 10) : Math.min(1.08 * (exploitability + impact), 10));
  return Math.ceil(score * 10) / 10;
}

// Severity classification
function classifySeverity(cvss) {
  if (cvss >= 9.0) return 'critical';
  if (cvss >= 7.0) return 'high';
  if (cvss >= 4.0) return 'medium';
  if (cvss >= 0.1) return 'low';
  return 'info';
}

// Check if a tool is available
function toolAvailable(name) {
  try {
    execSync(`which ${name} 2>/dev/null || test -f ${TOOLS[name]}`, { stdio: 'pipe' });
    return true;
  } catch { return false; }
}

// === API ROUTES ===

// Health check
app.get('/api/health', (req, res) => {
  const config = getAIConfig();
  const ready = aiAvailable();
  res.json({
    status: 'operational',
    ai_backend: ready ? config.provider : 'none',
    ai_model: ready ? config.model : null,
    ai_configured: ready,
    tools: {
      subfinder: toolAvailable('subfinder'),
      httpx: toolAvailable('httpx'),
      nuclei: toolAvailable('nuclei'),
      naabu: toolAvailable('naabu'),
      sqlmap: toolAvailable('sqlmap'),
      ffuf: toolAvailable('ffuf')
    },
    active_hunts: activeHunts.size,
    uptime: process.uptime()
  });
});

// === Settings ===
app.get('/api/settings', (req, res) => {
  const config = getAIConfig();
  res.json({
    provider: config.provider,
    model: config.model,
    base_url: config.baseUrl,
    has_api_key: !!config.apiKey
  });
});

app.post('/api/settings', (req, res) => {
  const { provider, model, base_url, api_key } = req.body;
  const d = db.getDb();

  if (provider) d.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('ai_provider', ?)").run(provider);
  if (model) d.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('ai_model', ?)").run(model);
  if (base_url !== undefined) d.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('ai_base_url', ?)").run(base_url || '');
  if (api_key !== undefined) {
    const encrypted = api_key ? db.encrypt(api_key) : '';
    d.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('ai_api_key_encrypted', ?)").run(encrypted);
  }

  const config = getAIConfig();
  res.json({
    provider: config.provider,
    model: config.model,
    base_url: config.baseUrl,
    has_api_key: !!config.apiKey,
    connected: aiAvailable()
  });
});

app.post('/api/settings/test', async (req, res) => {
  try {
    const prompt = 'reply with exactly: ok';
    const response = await runAI(prompt, { timeout: 15000 });
    res.json({ success: true, response: response.substring(0, 100) });
  } catch (e) {
    res.json({ success: false, error: e.message });
  }
});

// === Targets ===
app.get('/api/targets', (req, res) => {
  res.json(db.getAllTargets());
});

app.get('/api/targets/:id', (req, res) => {
  const t = db.getTarget(req.params.id);
  if (!t) return res.status(404).json({ error: 'Target not found' });
  t.sessions = db.getSessionsByTarget(t.id);
  res.json(t);
});

app.post('/api/targets', (req, res) => {
  const { name, url, program_name, scope_in, scope_out, target_type, tech_stack } = req.body;
  if (!url) return res.status(400).json({ error: 'url is required' });
  const existing = db.getTargetByUrl(url);
  if (existing) return res.json(existing);
  const result = db.createTarget({ name: name || url, url, program_name, scope_in, scope_out, target_type, tech_stack });
  res.status(201).json(db.getTarget(result.lastInsertRowid));
});

app.delete('/api/targets/:id', (req, res) => {
  db.getDb().prepare('DELETE FROM targets WHERE id = ?').run(req.params.id);
  res.json({ deleted: true });
});

// === Hunt Sessions ===
app.get('/api/sessions', (req, res) => {
  res.json(db.getAllSessions());
});

app.get('/api/sessions/:id', (req, res) => {
  const session = db.getSession(req.params.id);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  const target = db.getTarget(session.target_id);
  if (target) {
    session.target_name = target.name;
    session.target_url = target.url;
    session.target_type = target.target_type;
    session.target_program = target.program_name;
  }
  session.phases = db.getSessionPhases(session.id);
  session.findings = db.getFindingsBySession(session.id);
  session.events = db.getEvents(session.id);
  res.json(session);
});

app.post('/api/sessions', (req, res) => {
  const { target_id, mode, config } = req.body;
  if (!target_id) return res.status(400).json({ error: 'target_id is required' });
  const result = db.createSession(target_id, mode || 'bounty', config || {});
  const session = db.getSession(result.lastInsertRowid);
  session.phases = db.getSessionPhases(session.id);
  res.status(201).json(session);
});

app.post('/api/sessions/:id/start', async (req, res) => {
  const session = db.getSession(req.params.id);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  if (activeHunts.has(session.id)) return res.status(409).json({ error: 'Hunt already running' });

  const target = db.getTarget(session.target_id);
  if (!target) return res.status(404).json({ error: 'Target not found' });

  res.json({ started: true, session_id: session.id });

  // Run hunt asynchronously
  runHunt(session, target).catch(err => {
    console.error('Hunt error:', err);
    db.logEvent(session.id, 'error', session.current_phase, `Fatal error: ${err.message}`);
    broadcast({ type: 'hunt_error', session_id: session.id, error: err.message });
  });
});

app.post('/api/sessions/:id/resume', async (req, res) => {
  const session = db.getSession(req.params.id);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  if (activeHunts.has(session.id)) return res.status(409).json({ error: 'Hunt already running' });

  const target = db.getTarget(session.target_id);
  res.json({ resumed: true, session_id: session.id, from_phase: session.current_phase });
  runHunt(session, target, session.current_phase).catch(err => {
    console.error('Resume error:', err);
    broadcast({ type: 'hunt_error', session_id: session.id, error: err.message });
  });
});

app.get('/api/sessions/:id/status', (req, res) => {
  const session = db.getSession(req.params.id);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  session.phases = db.getSessionPhases(session.id);
  session.findings = db.getFindingsBySession(session.id);
  session.is_running = activeHunts.has(session.id);
  res.json(session);
});

app.delete('/api/sessions/:id', (req, res) => {
  if (activeHunts.has(Number(req.params.id))) {
    activeHunts.get(Number(req.params.id)).aborted = true;
  }
  db.getDb().prepare('DELETE FROM hunt_sessions WHERE id = ?').run(req.params.id);
  res.json({ deleted: true });
});

// === Findings ===
app.get('/api/findings', (req, res) => {
  res.json(db.getAllFindings());
});

app.get('/api/findings/:id', (req, res) => {
  const finding = db.getDb().prepare('SELECT * FROM findings WHERE id = ?').get(req.params.id);
  if (!finding) return res.status(404).json({ error: 'Finding not found' });
  res.json(finding);
});

app.put('/api/findings/:id', (req, res) => {
  const { status, severity, cvss_score, notes } = req.body;
  db.getDb().prepare('UPDATE findings SET status = COALESCE(?, status), severity = COALESCE(?, severity), cvss_score = COALESCE(?, cvss_score) WHERE id = ?')
    .run(status, severity, cvss_score, req.params.id);
  res.json({ updated: true });
});

// === Credentials Vault ===
app.get('/api/credentials', (req, res) => {
  res.json(db.getAllCredentials());
});

app.post('/api/credentials', (req, res) => {
  const { target_name, username, password, cookie, jwt, api_key, notes } = req.body;
  if (!target_name) return res.status(400).json({ error: 'target_name is required' });
  db.storeCredential(target_name, username, password, cookie, jwt, api_key, notes);
  res.status(201).json({ stored: true, target_name });
});

app.get('/api/credentials/:target_name', (req, res) => {
  const cred = db.getCredential(req.params.target_name);
  if (!cred) return res.status(404).json({ error: 'No credentials found' });
  res.json(cred);
});

app.delete('/api/credentials/:target_name', (req, res) => {
  db.getDb().prepare('DELETE FROM credentials WHERE target_name = ?').run(req.params.target_name);
  res.json({ deleted: true });
});

// === Patterns ===
app.get('/api/patterns', (req, res) => {
  res.json(db.getAllPatterns());
});

app.post('/api/patterns', (req, res) => {
  const result = db.savePattern(req.body);
  res.status(201).json({ created: true, id: result.lastInsertRowid });
});

// === Learning Logs ===
app.get('/api/learning-logs', (req, res) => {
  res.json(db.getLearningLogs(req.query.category));
});

app.post('/api/learning-logs', (req, res) => {
  const { session_id, category, content, tags } = req.body;
  if (!category || !content) return res.status(400).json({ error: 'category and content required' });
  db.saveLearningLog(session_id, category, content, tags);
  res.status(201).json({ created: true });
});

// === Events (SSE) ===
app.get('/api/events/stream', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.write('data: {"type":"connected"}\n\n');
  sseClients.add(res);
  req.on('close', () => sseClients.delete(res));
});

// === Report generation ===
app.get('/api/sessions/:id/report', (req, res) => {
  const session = db.getSession(req.params.id);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  const target = db.getTarget(session.target_id);
  const findings = db.getFindingsBySession(session.id);
  const phases = db.getSessionPhases(session.id);

  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;
  const mediumCount = findings.filter(f => f.severity === 'medium').length;
  const lowCount = findings.filter(f => f.severity === 'low').length;

  const report = {
    title: `Bug Bounty Report — ${target.name}`,
    generated: new Date().toISOString(),
    target: {
      name: target.name,
      url: target.url,
      program: target.program_name,
      scope: target.scope_in,
      type: target.target_type
    },
    hunt_summary: {
      mode: session.mode,
      started: session.started_at,
      completed: session.completed_at || 'In progress',
      duration_seconds: session.elapsed_seconds,
      total_findings: findings.length,
      critical: criticalCount,
      high: highCount,
      medium: mediumCount,
      low: lowCount
    },
    phases: phases.map(p => ({
      name: p.phase_name,
      status: p.status,
      started: p.started_at,
      completed: p.completed_at,
      duration_ms: p.duration_ms
    })),
    findings: findings.map(f => ({
      id: f.id,
      title: f.title,
      type: f.vulnerability_type,
      severity: f.severity,
      cvss: f.cvss_score,
      cvss_vector: f.cvss_vector,
      endpoint: f.endpoint,
      method: f.method,
      description: f.description,
      evidence: f.evidence,
      remediation: f.remediation,
      zero_day: !!f.is_zero_day,
      has_poc: !!f.has_poc,
      cve: f.cve_id,
      discovered: f.discovered_at
    })),
    remediation_priority: findings
      .filter(f => f.severity === 'critical' || f.severity === 'high')
      .map(f => ({
        title: f.title,
        severity: f.severity,
        remediation: f.remediation || 'Manual investigation required'
      }))
  };

  res.json(report);
});

app.get('/api/sessions/:id/report/markdown', (req, res) => {
  const session = db.getSession(req.params.id);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  const target = db.getTarget(session.target_id);
  const findings = db.getFindingsBySession(session.id);

  let md = `# Bug Bounty Report — ${target.name}\n\n`;
  md += `**Target:** ${target.url}\n`;
  md += `**Program:** ${target.program_name || 'N/A'}\n`;
  md += `**Mode:** ${session.mode}\n`;
  md += `**Date:** ${session.started_at}\n`;
  md += `**Findings:** ${findings.length}\n\n`;
  md += `---\n\n## Findings\n\n`;

  findings.forEach((f, i) => {
    md += `### ${i + 1}. [${f.severity.toUpperCase()}] ${f.title}\n\n`;
    md += `- **Type:** ${f.vulnerability_type}\n`;
    md += `- **CVSS:** ${f.cvss_score}${f.cvss_vector ? ` (${f.cvss_vector})` : ''}\n`;
    md += `- **Endpoint:** \`${f.method} ${f.endpoint || 'N/A'}\`\n`;
    if (f.parameter) md += `- **Parameter:** \`${f.parameter}\`\n`;
    md += `- **PoC Available:** ${f.has_poc ? 'Yes' : 'No'}\n`;
    md += `- **Zero-day:** ${f.is_zero_day ? 'Yes' : 'No'}\n\n`;
    md += `${f.description}\n\n`;
    if (f.evidence) md += `**Evidence:**\n\`\`\`\n${f.evidence}\n\`\`\`\n\n`;
    if (f.remediation) md += `**Remediation:**\n${f.remediation}\n\n`;
    md += `---\n\n`;
  });

  res.setHeader('Content-Type', 'text/markdown');
  res.setHeader('Content-Disposition', `attachment; filename="bounty-report-${target.slug}.md"`);
  res.send(md);
});

// Download report as JSON
app.get('/api/sessions/:id/report/json', (req, res) => {
  const session = db.getSession(req.params.id);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  const target = db.getTarget(session.target_id);
  const findings = db.getFindingsBySession(session.id);
  const report = {
    target: target,
    session: session,
    findings: findings
  };
  res.setHeader('Content-Disposition', `attachment; filename="bounty-report-${target.slug}.json"`);
  res.json(report);
});

// === Stats / Dashboard ===
app.get('/api/stats', (req, res) => {
  const totalSessions = db.getDb().prepare('SELECT COUNT(*) as count FROM hunt_sessions').get().count;
  const totalFindings = db.getDb().prepare('SELECT COUNT(*) as count FROM findings').get().count;
  const criticalFindings = db.getDb().prepare("SELECT COUNT(*) as count FROM findings WHERE severity = 'critical'").get().count;
  const highFindings = db.getDb().prepare("SELECT COUNT(*) as count FROM findings WHERE severity = 'high'").get().count;
  const totalTargets = db.getDb().prepare('SELECT COUNT(*) as count FROM targets').get().count;
  const activeSessions = activeHunts.size;

  res.json({
    total_sessions: totalSessions,
    total_findings: totalFindings,
    critical_findings: criticalFindings,
    high_findings: highFindings,
    total_targets: totalTargets,
    active_hunts: activeSessions
  });
});

// === HUNT ORCHESTRATION ENGINE ===

const PHASES = ['INIT', 'MEMORY_LOAD', 'TARGET_INGEST', 'APP_UNDERSTANDING', 'RECON', 'AGENT_DEPLOY', 'DYNAMIC_TEST', 'VULN_ASSESS', 'LEARNING', 'REPORT'];

function notify(session_id, type, phase, message, metadata = {}) {
  db.logEvent(session_id, type, phase, message, metadata);
  const payload = { type, session_id, phase, message, metadata, timestamp: new Date().toISOString() };
  broadcast(payload);
  broadcastSSE(payload);
}

function addFinding(session_id, data) {
  const cvssParams = data.cvss_params || { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'L', A: 'L' };
  const cvss = data.cvss_score || calculateCVSS(cvssParams);
  const severity = data.severity || classifySeverity(cvss);

  const findingData = {
    agent_name: data.agent_name || 'system',
    title: data.title,
    description: data.description || '',
    vulnerability_type: data.vulnerability_type,
    severity: severity,
    cvss_score: cvss,
    cvss_vector: data.cvss_vector || `CVSS:3.1/AV:${cvssParams.AV}/AC:${cvssParams.AC}/PR:${cvssParams.PR}/UI:${cvssParams.UI}/S:${cvssParams.S}/C:${cvssParams.C}/I:${cvssParams.I}/A:${cvssParams.A}`,
    endpoint: data.endpoint,
    method: data.method || 'GET',
    parameter: data.parameter,
    payload_used: data.payload_used,
    evidence: data.evidence || '',
    remediation: data.remediation || '',
    is_zero_day: data.is_zero_day || 0,
    has_poc: data.has_poc || 0,
    cve_id: data.cve_id || null,
    refs: data.refs || ''
  };

  const result = db.createFinding(session_id, findingData);
  notify(session_id, 'finding', null, `[${severity.toUpperCase()}] ${data.title}`, { finding_id: result.lastInsertRowid, severity, cvss });
  return result;
}

async function runHunt(session, target, resumeFrom = null) {
  const runner = { aborted: false, session_id: session.id, cred: null, authArgs: [] };
  activeHunts.set(session.id, runner);

  // Load credentials from vault
  runner.cred = loadCredentials(target);
  runner.authArgs = buildAuthArgs(runner.cred);
  if (runner.cred) {
    notify(session.id, 'phase_detail', 'INIT', `Authenticated session: ${runner.cred.username ? 'user: ' + runner.cred.username : 'cookie/token-based'}`);
  }

  const startPhase = resumeFrom ? PHASES.indexOf(resumeFrom) : 0;
  const skippedUntil = resumeFrom ? startPhase : -1;

  notify(session.id, 'hunt_start', null, `Hunt starting for ${target.url} in ${session.mode} mode`, { target_url: target.url, mode: session.mode, resume_from: resumeFrom, authenticated: !!runner.cred });

  for (let i = 0; i < PHASES.length; i++) {
    if (runner.aborted) {
      notify(session.id, 'hunt_aborted', PHASES[i], 'Hunt aborted by user');
      break;
    }

    const phase = PHASES[i];
    if (i < skippedUntil && i < PHASES.length - 1) continue;

    db.updateSessionPhase(session.id, phase, 'running');
    notify(session.id, 'phase_start', phase, `Phase ${phase} started`);
    const phaseStart = Date.now();

    try {
      switch (phase) {
        case 'INIT': await phaseInit(session, target); break;
        case 'MEMORY_LOAD': await phaseMemoryLoad(session, target); break;
        case 'TARGET_INGEST': await phaseTargetIngest(session, target); break;
        case 'APP_UNDERSTANDING': await phaseAppUnderstanding(session, target, runner); break;
        case 'RECON': await phaseRecon(session, target, runner); break;
        case 'AGENT_DEPLOY': await phaseAgentDeploy(session, target, runner); break;
        case 'DYNAMIC_TEST': await phaseDynamicTest(session, target, runner); break;
        case 'VULN_ASSESS': await phaseVulnAssess(session, target, runner); break;
        case 'LEARNING': await phaseLearning(session, target); break;
        case 'REPORT': await phaseReport(session, target); break;
      }
      db.updateSessionPhase(session.id, phase, 'completed');
      notify(session.id, 'phase_complete', phase, `Phase ${phase} completed`, { duration_ms: Date.now() - phaseStart });
    } catch (err) {
      console.error(`Phase ${phase} error:`, err);
      db.updateSessionPhase(session.id, phase, 'failed');
      notify(session.id, 'phase_error', phase, `Phase ${phase} failed: ${err.message}`);

      if (runner.aborted) break;
      db.updateSessionPhase(session.id, phase, 'running');
      notify(session.id, 'phase_retry', phase, `Phase ${phase} retrying...`);
      try {
        switch (phase) {
          case 'INIT': await phaseInit(session, target); break;
          case 'MEMORY_LOAD': await phaseMemoryLoad(session, target); break;
          case 'TARGET_INGEST': await phaseTargetIngest(session, target); break;
          case 'APP_UNDERSTANDING': await phaseAppUnderstanding(session, target, runner); break;
          case 'RECON': await phaseRecon(session, target, runner); break;
          case 'AGENT_DEPLOY': await phaseAgentDeploy(session, target, runner); break;
          case 'DYNAMIC_TEST': await phaseDynamicTest(session, target, runner); break;
          case 'VULN_ASSESS': await phaseVulnAssess(session, target, runner); break;
          case 'LEARNING': await phaseLearning(session, target); break;
          case 'REPORT': await phaseReport(session, target); break;
        }
        db.updateSessionPhase(session.id, phase, 'completed');
        notify(session.id, 'phase_complete', phase, `Phase ${phase} completed (after retry)`);
      } catch (retryErr) {
        db.updateSessionPhase(session.id, phase, 'skipped');
        notify(session.id, 'phase_skip', phase, `Phase ${phase} skipped after retry failure: ${retryErr.message}`);
      }
    }
  }

  if (!runner.aborted) {
    db.getDb().prepare("UPDATE hunt_sessions SET status = 'completed', completed_at = datetime('now'), elapsed_seconds = ? WHERE id = ?")
      .run(Math.floor((Date.now() - new Date(session.started_at).getTime()) / 1000), session.id);
    notify(session.id, 'hunt_complete', null, `Hunt complete — ${db.getFindingsBySession(session.id).length} findings`);
  } else {
    db.getDb().prepare("UPDATE hunt_sessions SET status = 'aborted', updated_at = datetime('now') WHERE id = ?").run(session.id);
  }

  activeHunts.delete(session.id);
}

// Phase implementations
async function phaseInit(session, target) {
  notify(session.id, 'phase_detail', 'INIT', 'Initializing hunt session, loading configuration, setting up state machine');

  const thresholds = {
    bounty: { min_cvss: 8.0, max_findings: 10 },
    pentest: { min_cvss: 4.0, max_findings: 20 },
    comprehensive: { min_cvss: 0.0, max_findings: 50 }
  };
  const config = thresholds[session.mode] || thresholds.bounty;

  db.getDb().prepare("UPDATE hunt_sessions SET config = json_set(config, '$.min_cvss', ?, '$.max_findings', ?) WHERE id = ?")
    .run(config.min_cvss, config.max_findings, session.id);

  notify(session.id, 'phase_detail', 'INIT', `Mode: ${session.mode}, min CVSS: ${config.min_cvss}, max findings: ${config.max_findings}`);
}

async function phaseMemoryLoad(session, target) {
  notify(session.id, 'phase_detail', 'MEMORY_LOAD', 'Loading prior intelligence from pattern database and learning logs');

  let patterns = [], logs = [];
  try { patterns = db.getPatternsByType('attack') || []; } catch(e) { patterns = []; }
  try { logs = db.getLearningLogs('effective_techniques') || []; } catch(e) { logs = []; }

  if (patterns.length > 0) {
    notify(session.id, 'phase_detail', 'MEMORY_LOAD', `Loaded ${patterns.length} attack patterns`);
    patterns.slice(0, 5).forEach(p => {
      notify(session.id, 'phase_detail', 'MEMORY_LOAD', `Pattern: ${p.name} (${p.effectiveness}, used ${p.times_used}x)`);
    });
  }

  if (logs.length > 0) {
    notify(session.id, 'phase_detail', 'MEMORY_LOAD', `Loaded ${logs.length} learning log entries`);
  }

  // Load prior sessions for this target
  const priorSessions = db.getSessionsByTarget(target.id);
  if (priorSessions.length > 1) {
    const priorFindings = db.getFindingsBySession(priorSessions[1].id);
    notify(session.id, 'phase_detail', 'MEMORY_LOAD', `Loaded ${priorFindings.length} findings from prior session #${priorSessions[1].id}`);
  }
}

async function phaseTargetIngest(session, target) {
  notify(session.id, 'phase_detail', 'TARGET_INGEST', `Configuring target scope for ${target.url}`);

  const scopeIn = (target.scope_in || '*').split(',').map(s => s.trim());
  const scopeOut = (target.scope_out || '').split(',').map(s => s.trim()).filter(Boolean);

  notify(session.id, 'phase_detail', 'TARGET_INGEST', `Scope IN: ${scopeIn.join(', ')}, Scope OUT: ${scopeOut.join(', ') || 'none'}`);

  // Check for credentials
  const cred = db.getCredential(target.name);
  if (cred) {
    notify(session.id, 'phase_detail', 'TARGET_INGEST', `Credentials found for ${target.name} (user: ${cred.username || 'stored'})`);
  }

  // Classify target type
  const url = target.url.toLowerCase();
  let detectedType = target.target_type || 'web';
  if (url.includes('/api') || url.includes('swagger') || url.includes('graphql')) detectedType = 'api';
  if (url.includes('.apk') || url.includes('.ipa')) detectedType = 'mobile';
  if (url.match(/^\d+\.\d+\.\d+\.\d+/)) detectedType = 'network';

  db.getDb().prepare('UPDATE targets SET target_type = ? WHERE id = ?').run(detectedType, target.id);
  notify(session.id, 'phase_detail', 'TARGET_INGEST', `Target type classified: ${detectedType}`);
}

async function phaseAppUnderstanding(session, target, runner) {
  const authArgs = runner?.authArgs || [];
  notify(session.id, 'phase_detail', 'APP_UNDERSTANDING', 'Profiling target application' + (authArgs.length > 0 ? ' (authenticated)' : ''));

  // HTTP probe for basic info
  let httpInfo = '';
  if (toolAvailable('httpx')) {
    const { stdout } = await runCommand(TOOLS.httpx, ['-u', target.url, '-status-code', '-title', '-tech-detect', '-json', '-silent'], { timeout: 30000 });
    try {
      const data = JSON.parse(stdout.trim().split('\n')[0] || '{}');
      if (data.status_code) {
        httpInfo = `HTTP ${data.status_code}, Title: "${data.title || 'N/A'}", Tech: ${data.tech || 'unknown'}`;
        notify(session.id, 'phase_detail', 'APP_UNDERSTANDING', httpInfo);
      }
      if (data.tech) {
        db.getDb().prepare('UPDATE targets SET tech_stack = ? WHERE id = ?').run(Array.isArray(data.tech) ? data.tech.join(',') : data.tech, target.id);
      }
    } catch (e) {
      httpInfo = stdout.trim().substring(0, 300);
      notify(session.id, 'phase_detail', 'APP_UNDERSTANDING', `httpx probe: ${httpInfo}`);
    }
  } else {
    const { stdout } = await runCommand('curl', ['-sk', '-o', '/dev/null', '-w', '%{http_code} %{content_type}', '--connect-timeout', '10', target.url], { timeout: 15000 });
    httpInfo = `HTTP probe: ${stdout.trim()}`;
    notify(session.id, 'phase_detail', 'APP_UNDERSTANDING', httpInfo);
  }

  // Fetch page body for analysis (with credentials if available)
  let pageBody = '';
  try {
    const curlArgs = ['-sk', '-w', '%{http_code}', '-o', '/tmp/bh-body.txt', '--connect-timeout', '10', '--max-time', '15', ...authArgs, target.url];
    const { stdout: httpCode } = await runCommand('curl', curlArgs, { timeout: 20000 });
    notify(session.id, 'phase_detail', 'APP_UNDERSTANDING', `HTTP GET ${target.url} → ${httpCode.trim()}`);
    try {
      const fs = require('fs');
      pageBody = fs.readFileSync('/tmp/bh-body.txt', 'utf8').substring(0, 8000);
    } catch(e) {}
  } catch (e) {
    notify(session.id, 'phase_detail', 'APP_UNDERSTANDING', `HTTP probe failed: ${e.message}`);
  }

  // Claude AI: intelligent application profiling
  if (aiAvailable()) {
    notify(session.id, 'phase_detail', 'APP_UNDERSTANDING', 'AI analyzing target for attack surface...');
    try {
      const prompt = `You are a senior bug bounty hunter profiling a target web application for a security assessment.

Target URL: ${target.url}
HTTP Info: ${httpInfo}

Page content excerpt:
\`\`\`
${pageBody.substring(0, 5000)}
\`\`\`

Analyze this target and respond with a structured profile in this exact format:

TECH_STACK: <comma-separated technologies detected>
TARGET_TYPE: <web|api|mobile|network|thick-client>
ATTACK_SURFACE:
- <list each attack surface area, one per line>
CRITICAL_FLOWS:
- <list key user flows that need testing, one per line>
AI_LLM_FEATURES: <YES if chat/AI/LLM features detected, otherwise NO>
HIGH_VALUE_TARGETS:
- <list things an attacker would most want to access, one per line>
PRIORITY_AGENTS: <comma-separated list of vulnerability types to prioritize, from: xss,sqli,ssrf,idor,auth,cors,csrf,file-upload,xxe,rce,business-logic,race-condition,graphql,llm-security>
RECOMMENDATIONS: <2-3 specific testing recommendations>`;

      const analysis = await runAI(prompt, { timeout: 60000 });
      notify(session.id, 'phase_detail', 'APP_UNDERSTANDING', `AI analysis:\n${analysis.substring(0, 500)}`);

      // Store analysis in session config
      db.getDb().prepare("UPDATE hunt_sessions SET config = json_set(config, '$.app_profile', ?) WHERE id = ?")
        .run(JSON.stringify({ analysis, generated_at: new Date().toISOString() }), session.id);

      // Detect AI/LLM features from Claude's analysis
      if (analysis.includes('AI_LLM_FEATURES: YES')) {
        db.getDb().prepare("UPDATE hunt_sessions SET config = json_set(config, '$.llm_detected', 'true') WHERE id = ?").run(session.id);
        notify(session.id, 'phase_detail', 'APP_UNDERSTANDING', 'AI/LLM features detected — will deploy LLMSecurity agent');
      }
    } catch (e) {
      notify(session.id, 'phase_detail', 'APP_UNDERSTANDING', `AI analysis skipped: ${e.message}`);
    }
  }

  notify(session.id, 'phase_detail', 'APP_UNDERSTANDING', 'Application profiling complete');
}

async function phaseRecon(session, target, runner) {
  const authArgs = runner?.authArgs || [];
  notify(session.id, 'phase_detail', 'RECON', 'Starting reconnaissance phase' + (authArgs.length > 0 ? ' (authenticated)' : ''));

  const targetDomain = target.url.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
  const results = { subdomains: [], alive: [], urls: [], ports: [] };

  // Subdomain discovery (skip if target is an IP address)
  const isIp = /^[\d.]+/.test(targetDomain.replace(/:\d+$/, ''));
  if (toolAvailable('subfinder') && !isIp) {
    notify(session.id, 'phase_detail', 'RECON', 'Running subfinder for subdomain enumeration');
    const { stdout } = await runCommand(TOOLS.subfinder, ['-d', targetDomain, '-silent'], { timeout: 60000 });
    results.subdomains = stdout.trim().split('\n').filter(Boolean);
    notify(session.id, 'phase_detail', 'RECON', `Subfinder found ${results.subdomains.length} subdomains`);
  } else if (isIp) {
    notify(session.id, 'phase_detail', 'RECON', 'Target is an IP — skipping subdomain enumeration');
  }

  // Live host probing (limit to reasonable count for performance)
  const subsToProbe = results.subdomains.slice(0, 200);
  if (toolAvailable('httpx') && subsToProbe.length > 0) {
    notify(session.id, 'phase_detail', 'RECON', `Probing ${subsToProbe.length} live hosts with httpx (sampled from ${results.subdomains.length} total)`);
    const input = subsToProbe.join('\n');
    const { stdout } = await runCommand(TOOLS.httpx, ['-silent', '-status-code', '-title', '-tech-detect', '-json', '-threads', '25'], {
      timeout: 90000,
      input: input
    });
    results.alive = stdout.trim().split('\n').filter(Boolean).map(l => {
      try { return JSON.parse(l); } catch { return { url: l }; }
    });
    notify(session.id, 'phase_detail', 'RECON', `Found ${results.alive.length} live hosts (from sample)`);
  }

  // Port scanning
  if (toolAvailable('naabu') && results.subdomains.length > 0) {
    notify(session.id, 'phase_detail', 'RECON', 'Running naabu port scan');
    const input = [targetDomain, ...results.subdomains].join('\n');
    const { stdout } = await runCommand(TOOLS.naabu, ['-host', targetDomain, '-silent', '-top-ports', '100'], { timeout: 60000 });
    results.ports = stdout.trim().split('\n').filter(Boolean);
    if (results.ports.length > 0) {
      notify(session.id, 'phase_detail', 'RECON', `Open ports on ${targetDomain}: ${results.ports.join(', ')}`);
    }
  }

  // Store recon data in session config
  const reconData = {
    subdomains_count: results.subdomains.length,
    alive_hosts_count: results.alive.length,
    open_ports: results.ports,
    completed_at: new Date().toISOString()
  };
  db.getDb().prepare("UPDATE hunt_sessions SET config = json_set(config, '$.recon', ?) WHERE id = ?")
    .run(JSON.stringify(reconData), session.id);

  notify(session.id, 'phase_detail', 'RECON', `Recon complete: ${results.subdomains.length} subs, ${results.alive.length} alive, ${results.ports.length} open ports`);
}

async function phaseAgentDeploy(session, target, runner) {
  const authArgs = runner?.authArgs || [];
  const cred = runner?.cred;
  notify(session.id, 'phase_detail', 'AGENT_DEPLOY', 'Deploying vulnerability agents based on target profile');

  const techStack = (target.tech_stack || '').toLowerCase();
  const targetType = target.target_type || 'web';

  const agents = [];

  // Web targets get web-focused agents
  if (targetType === 'web' || targetType === 'api') {
    agents.push(
      { name: 'XSSAgent', type: 'xss', description: 'Cross-site scripting analysis', cvss_params: { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'L', I: 'L', A: 'N' } },
      { name: 'SQLiAgent', type: 'sqli', description: 'SQL injection testing', cvss_params: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' } },
      { name: 'SSRFAgent', type: 'ssrf', description: 'Server-side request forgery', cvss_params: { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'N' } },
      { name: 'IDORAgent', type: 'idor', description: 'Insecure direct object references', cvss_params: { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' } },
      { name: 'AuthAgent', type: 'auth', description: 'Authentication bypass testing', cvss_params: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' } },
      { name: 'CSRFAgent', type: 'csrf', description: 'Cross-site request forgery', cvss_params: { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N' } },
      { name: 'FileUploadAgent', type: 'file-upload', description: 'File upload vulnerability testing', cvss_params: { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'H' } },
      { name: 'CORSAgent', type: 'cors', description: 'CORS misconfiguration analysis', cvss_params: { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N' } }
    );
  }

  // API-specific
  if (targetType === 'api' || techStack.includes('graphql')) {
    agents.push(
      { name: 'GraphQLAgent', type: 'graphql', description: 'GraphQL introspection and injection', cvss_params: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' } }
    );
  }

  // LLM-specific
  if (techStack.includes('llm') || techStack.includes('ai') || techStack.includes('gpt')) {
    agents.push(
      { name: 'LLMSecurityAgent', type: 'llm-security', description: 'AI/LLM prompt injection and safety testing', cvss_params: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' } }
    );
  }

  // Always run business logic
  agents.push(
    { name: 'BusinessLogicAgent', type: 'business-logic', description: 'Business logic flaw analysis', cvss_params: { AV: 'N', AC: 'H', PR: 'L', UI: 'N', S: 'U', C: 'L', I: 'L', A: 'N' } },
    { name: 'RaceConditionAgent', type: 'race-condition', description: 'Race condition and TOCTOU testing', cvss_params: { AV: 'N', AC: 'H', PR: 'L', UI: 'N', S: 'U', C: 'L', I: 'L', A: 'N' } }
  );

  notify(session.id, 'phase_detail', 'AGENT_DEPLOY', `Deploying ${agents.length} agents`);

  for (const agent of agents) {
    if (runnerAborted(session.id)) break;
    notify(session.id, 'phase_detail', 'AGENT_DEPLOY', `${agent.name}: ${agent.description}`);

    // Each agent performs targeted HTTP analysis
    await runAgent(session, target, agent, authArgs, cred);
  }

  notify(session.id, 'phase_detail', 'AGENT_DEPLOY', 'All agents completed analysis');
}

function runnerAborted(session_id) {
  const runner = activeHunts.get(session_id);
  return runner ? runner.aborted : false;
}

async function runAgent(session, target, agent, authArgs = [], cred = null) {
  const targetUrl = target.url.replace(/\/$/, '');

  if (runnerAborted(session.id)) return;

  // First: run quick HTTP probes to gather target data for Claude
  const probeData = await gatherAgentProbeData(session, targetUrl, agent, authArgs);

  // Then: use Claude for intelligent vulnerability analysis
  if (aiAvailable()) {
    notify(session.id, 'agent_result', 'AGENT_DEPLOY', `${agent.name}: AI analyzing for ${agent.type} vulnerabilities...`);
    try {
      const findings = await claudeAgentAnalysis(session, target, agent, probeData, cred);
      findings.forEach(f => addFinding(session, f));
      if (findings.length === 0) {
        notify(session.id, 'agent_result', 'AGENT_DEPLOY', `${agent.name}: No ${agent.type} vulnerabilities identified`);
      }
      return;
    } catch (e) {
      notify(session.id, 'agent_result', 'AGENT_DEPLOY', `${agent.name}: AI error, falling back to probes — ${e.message}`);
    }
  }

  // Fallback: HTTP probe-based testing
  await runAgentProbes(session, targetUrl, agent);
}

async function gatherAgentProbeData(session, targetUrl, agent, authArgs = []) {
  const data = { targetUrl, responseHeaders: '', responseBody: '', httpCode: '', endpoints: [] };

  // Get response headers
  try {
    const { stdout } = await runCommand('curl', ['-sk', '--connect-timeout', '5', '-I', '--max-time', '10', ...authArgs, targetUrl], { timeout: 15000 });
    data.responseHeaders = stdout.substring(0, 3000);
    const codeMatch = stdout.match(/HTTP\/\S+\s+(\d+)/);
    if (codeMatch) data.httpCode = codeMatch[1];
    notify(session.id, 'agent_result', 'AGENT_DEPLOY', `${agent.name}: HEAD ${targetUrl} → HTTP ${data.httpCode || '?'}`);
  } catch (e) {
    notify(session.id, 'agent_result', 'AGENT_DEPLOY', `${agent.name}: HEAD ${targetUrl} failed — ${e.message}`);
  }

  // Get response body
  try {
    const { stdout } = await runCommand('curl', ['-sk', '--connect-timeout', '5', '--max-time', '10', ...authArgs, targetUrl], { timeout: 15000 });
    data.responseBody = stdout.substring(0, 6000);
    notify(session.id, 'agent_result', 'AGENT_DEPLOY', `${agent.name}: GET ${targetUrl} → ${stdout.length} bytes`);
  } catch (e) {
    notify(session.id, 'agent_result', 'AGENT_DEPLOY', `${agent.name}: GET ${targetUrl} failed — ${e.message}`);
  }

  // Gather type-specific probe data
  const probes = {
    'auth': ['/admin', '/.env', '/.git/config', '/wp-admin', '/config', '/api/admin'],
    'idor': ['/api/users/1', '/api/user/1', '/api/profile/1'],
    'xss': ['/search?q=test', '/?q=test'],
    'sqli': ['/?id=1', '/?id=1\''],
    'cors': [],
    'csrf': [],
  };

  const paths = probes[agent.type] || [];
  for (const p of paths) {
    try {
      const fullUrl = `${targetUrl}${p}`;
      const { stdout } = await runCommand('curl', ['-sk', '--connect-timeout', '5', '-w', '%{http_code}', '-o', '/dev/null', ...authArgs, fullUrl], { timeout: 10000 });
      const code = stdout.trim();
      data.endpoints.push({ path: p, http_code: code });
      notify(session.id, 'agent_result', 'AGENT_DEPLOY', `${agent.name}: probe ${fullUrl} → HTTP ${code}`);
    } catch (e) {}
  }

  return data;
}

async function claudeAgentAnalysis(session, target, agent, probeData, cred = null) {
  const authNote = cred
    ? `AUTHENTICATED: Yes (${cred.username ? 'user: ' + cred.username : cred.cookie ? 'cookie-based' : cred.jwt ? 'JWT token' : 'API key'}) — test as an authenticated user.`
    : 'AUTHENTICATED: No — testing as unauthenticated user.';

  const prompt = `You are a senior bug bounty hunter specializing in ${agent.type.toUpperCase()} vulnerabilities. Analyze this target for security issues.

TARGET: ${target.url}
VULNERABILITY TYPE: ${agent.type} (${agent.description})
HTTP CODE: ${probeData.httpCode}
${authNote}

RESPONSE HEADERS (excerpt):
\`\`\`
${probeData.responseHeaders.substring(0, 2000)}
\`\`\`

RESPONSE BODY (excerpt):
\`\`\`
${probeData.responseBody.substring(0, 4000)}
\`\`\`

PROBED ENDPOINTS:
${probeData.endpoints.map(e => `  ${e.path} → HTTP ${e.http_code}`).join('\n')}

Based on the response headers, body content, and probed endpoints, identify any ${agent.type.toUpperCase()} vulnerabilities. Consider:
- What the technology stack appears to be from headers and body
- Whether any endpoint responses suggest misconfigurations
- Common ${agent.type} attack patterns and whether they apply here
- ${cred ? 'Since you are authenticated, also test for privilege escalation, horizontal access (IDOR), and auth-required endpoint vulnerabilities.' : 'Look for auth bypass opportunities since you are unauthenticated.'}

Respond with findings in this exact JSON format (one object per finding, or empty array if none found):
[
  {
    "title": "Brief finding title",
    "description": "Detailed description of the vulnerability and its impact",
    "severity": "critical|high|medium|low|info",
    "cvss_score": 0.0,
    "endpoint": "/affected/path",
    "method": "GET|POST",
    "parameter": "param name if applicable",
    "evidence": "What confirms this vulnerability",
    "remediation": "How to fix it",
    "has_poc": true|false,
    "is_zero_day": true|false
  }
]

Only report real, credible findings. If nothing is clearly vulnerable, return []. Be honest — false positives waste time.`;

  const response = await runAI(prompt, { timeout: 90000 });
  notify(session.id, 'agent_result', 'AGENT_DEPLOY', `${agent.name}: AI response received (${response.length} chars)`);

  // Parse Claude's JSON response
  try {
    const jsonMatch = response.match(/\[[\s\S]*\]/);
    if (jsonMatch) {
      const findings = JSON.parse(jsonMatch[0]);
      return findings.map(f => ({
        agent_name: agent.name,
        title: f.title,
        description: f.description || '',
        vulnerability_type: agent.type,
        severity: f.severity || 'info',
        cvss_score: f.cvss_score || 0,
        endpoint: f.endpoint || '/',
        method: f.method || 'GET',
        parameter: f.parameter || null,
        evidence: f.evidence || '',
        remediation: f.remediation || '',
        has_poc: f.has_poc ? 1 : 0,
        is_zero_day: f.is_zero_day ? 1 : 0
      }));
    }
  } catch (e) {
    notify(session.id, 'agent_result', 'AGENT_DEPLOY', `${agent.name}: Could not parse AI response as JSON`);
  }
  return [];
}

async function runAgentProbes(session, targetUrl, agent) {
  // Fallback HTTP probe-based testing (runs when Claude is unavailable)
  switch (agent.type) {
    case 'auth':
      await probeAuthPaths(session, targetUrl);
      break;
    case 'cors':
      await probeCORS(session, targetUrl);
      break;
    default:
      notify(session.id, 'agent_result', 'AGENT_DEPLOY', `${agent.name}: Surface identified, requires manual investigation`);
  }
}

async function probeAuthPaths(session, targetUrl) {
  const paths = ['/admin', '/.env', '/.git/config', '/wp-admin', '/config', '/api/admin'];
  for (const p of paths) {
    if (runnerAborted(session.id)) return;
    try {
      const { stdout: code } = await runCommand('curl', ['-sk', '--connect-timeout', '5', '-w', '%{http_code}', '-o', '/dev/null', `${targetUrl}${p}`], { timeout: 10000 });
      if (code.trim() === '200') {
        addFinding(session, {
          agent_name: 'AuthAgent',
          title: `Sensitive path accessible: ${p}`,
          description: `Path ${p} returned HTTP 200 without authentication.`,
          vulnerability_type: 'auth', severity: 'high',
          cvss_score: 7.5, endpoint: p, method: 'GET',
          evidence: `HTTP ${code.trim()}`, remediation: 'Require authentication. Block sensitive paths.',
          has_poc: 1
        });
        return;
      }
    } catch (e) {}
  }
}

async function probeCORS(session, targetUrl) {
  try {
    const { stdout } = await runCommand('curl', ['-sk', '--connect-timeout', '5', '-I', '-H', 'Origin: https://evil.com', targetUrl], { timeout: 10000 });
    if (stdout.toLowerCase().includes('access-control-allow-origin: https://evil.com')) {
      addFinding(session, {
        agent_name: 'CORSAgent',
        title: 'CORS Misconfiguration — Arbitrary Origin Reflection',
        description: 'Application reflects arbitrary Origin headers.',
        vulnerability_type: 'cors', severity: 'medium',
        cvss_score: 5.5, endpoint: '/', method: 'OPTIONS',
        evidence: stdout.substring(0, 300),
        remediation: 'Use explicit origin allow-list.',
        has_poc: 1
      });
    }
  } catch (e) {}
}

async function phaseDynamicTest(session, target, runner) {
  const authArgs = runner?.authArgs || [];
  notify(session.id, 'phase_detail', 'DYNAMIC_TEST', 'Starting dynamic testing phase');

  // Run ffuf for path discovery if available
  if (toolAvailable('ffuf')) {
    notify(session.id, 'phase_detail', 'DYNAMIC_TEST', 'Running ffuf path discovery');

    const wordlist = '/usr/share/wordlists/dirb/common.txt';
    const wordlistToUse = fs.existsSync(wordlist) ? wordlist : null;

    if (wordlistToUse) {
      const { stdout } = await runCommand(TOOLS.ffuf, [
        '-u', `${target.url}/FUZZ`,
        '-w', wordlistToUse,
        '-mc', '200,204,301,302,307,401,403',
        '-t', '20',
        '-maxtime', '60',
        '-silent'
      ], { timeout: 90000 });

      const paths = stdout.trim().split('\n').filter(Boolean);
      if (paths.length > 0) {
        notify(session.id, 'phase_detail', 'DYNAMIC_TEST', `ffuf discovered ${paths.length} paths`);
        const interestingPaths = paths.slice(0, 10);
        for (const line of interestingPaths) {
          notify(session.id, 'phase_detail', 'DYNAMIC_TEST', `Path found: ${line.trim()}`);
        }
      }
    } else {
      // Create a minimal wordlist
      const miniWordlist = '/tmp/bh-mini-wordlist.txt';
      fs.writeFileSync(miniWordlist, 'admin\nlogin\napi\nwp-admin\nbackup\ntest\ndev\n.git\n.env\nconfig\nrobots.txt\nsitemap.xml\n.htaccess\nserver-status\nconsole\nswagger\ngraphql');
      const { stdout } = await runCommand(TOOLS.ffuf, [
        '-u', `${target.url}/FUZZ`,
        '-w', miniWordlist,
        '-mc', '200,204,301,302,307,401,403',
        '-t', '10',
        '-silent'
      ], { timeout: 60000 });
      const paths = stdout.trim().split('\n').filter(Boolean);
      if (paths.length > 0) {
        notify(session.id, 'phase_detail', 'DYNAMIC_TEST', `ffuf discovered ${paths.length} paths`);
      }
      fs.unlinkSync(miniWordlist);
    }
  }

  notify(session.id, 'phase_detail', 'DYNAMIC_TEST', 'Dynamic testing phase complete');
}

async function phaseVulnAssess(session, target, runner) {
  const authArgs = runner?.authArgs || [];
  notify(session.id, 'phase_detail', 'VULN_ASSESS', 'Starting vulnerability assessment with nuclei');

  if (toolAvailable('nuclei')) {
    notify(session.id, 'phase_detail', 'VULN_ASSESS', 'Running nuclei scan (critical + high severity)');
    // Build nuclei args with optional auth headers
    const nucleiArgs = ['-u', target.url, '-severity', 'critical,high', '-silent', '-json', '-rate-limit', '50', '-timeout', '5', '-max-time', '120'];
    if (runner?.cred?.cookie) {
      nucleiArgs.push('-H', `Cookie: ${runner.cred.cookie}`);
    }
    if (runner?.cred?.jwt) {
      nucleiArgs.push('-H', `Authorization: Bearer ${runner.cred.jwt}`);
    }
    const { stdout } = await runCommand(TOOLS.nuclei, nucleiArgs, { timeout: 150000 });

    const results = stdout.trim().split('\n').filter(Boolean);
    notify(session.id, 'phase_detail', 'VULN_ASSESS', `Nuclei found ${results.length} findings`);

    for (const line of results) {
      if (runnerAborted(session.id)) break;
      try {
        const vuln = JSON.parse(line);
        const info = vuln.info || {};
        const severityMap = { critical: 9.5, high: 7.5, medium: 5.5, low: 3.0, info: 1.0 };
        const cvssScore = info.classification?.cvss_score || severityMap[info.severity || 'info'] || 1.0;

        addFinding(session, {
          agent_name: 'Nuclei',
          title: info.name || vuln.template_id,
          description: info.description || '',
          vulnerability_type: (vuln.template_id || '').split('/')[0] || 'unknown',
          severity: info.severity || 'info',
          cvss_score: cvssScore,
          cvss_vector: info.classification?.cvss_vector || null,
          endpoint: vuln.matched_at || vuln.host,
          method: vuln.request ? 'GET' : 'GET',
          evidence: vuln.extracted_results ? vuln.extracted_results.join('\n') : (vuln.matcher_name || ''),
          remediation: info.remediation || '',
          refs: (info.reference || []).join(', '),
          has_poc: 1,
          cve_id: info.classification?.cve_id || null
        });
      } catch (e) {
        notify(session.id, 'phase_detail', 'VULN_ASSESS', `Nuclei raw result: ${line.substring(0, 100)}`);
      }
    }
  } else {
    notify(session.id, 'phase_detail', 'VULN_ASSESS', 'Nuclei not available, skipping automated scanning');
  }

  notify(session.id, 'phase_detail', 'VULN_ASSESS', 'Vulnerability assessment complete');
}

async function phaseLearning(session, target) {
  notify(session.id, 'phase_detail', 'LEARNING', 'Processing findings and updating intelligence');

  const findings = db.getFindingsBySession(session.id);
  const confirmed = findings.filter(f => f.severity === 'critical' || f.severity === 'high');

  // Claude: attack chain correlation and finding review
  if (aiAvailable() && findings.length > 0) {
    notify(session.id, 'phase_detail', 'LEARNING', 'AI analyzing findings for attack chains...');
    try {
      const findingsSummary = findings.map(f =>
        `[${f.severity.toUpperCase()}] ${f.title} | Type: ${f.vulnerability_type} | CVSS: ${f.cvss_score} | Endpoint: ${f.endpoint} | Agent: ${f.agent_name}`
      ).join('\n');

      const prompt = `You are a bug bounty triage specialist. Review these automated findings for a security assessment of ${target.url} and identify attack chains, false positives, and missed opportunities.

FINDINGS (${findings.length}):
${findingsSummary}

Analyze and respond in this format:

FALSE_POSITIVES: <list any findings likely to be false positives, or "none">
ATTACK_CHAINS:
- <describe any chains of lower-severity findings that combine into higher impact>
MISSED_OPPORTUNITIES: <what vulnerability types should be tested further, or "none">
TECHNIQUES_LEARNED: <what worked, what patterns are effective>
PRIORITY_REMEDIATIONS: <top 3 things to fix first, one per line>`;

      const analysis = await runAI(prompt, { timeout: 60000 });
      notify(session.id, 'phase_detail', 'LEARNING', `AI assessment:\n${analysis.substring(0, 500)}`);

      // Save analysis to learning log
      db.saveLearningLog(session.id, 'ai_assessment',
        `## AI Analysis — ${target.url}\n\n${analysis}`,
        'ai,assessment'
      );
    } catch (e) {
      notify(session.id, 'phase_detail', 'LEARNING', `AI assessment skipped: ${e.message}`);
    }
  }

  // Save patterns from confirmed findings
  if (confirmed.length > 0) {
    const techStack = target.tech_stack || 'unknown';
    for (const f of confirmed) {
      db.savePattern({
        pattern_type: 'attack',
        name: `${f.vulnerability_type} on ${techStack}`,
        description: f.description,
        tech_stack: techStack,
        vulnerability_type: f.vulnerability_type,
        effectiveness: 'confirmed',
        payload: f.payload_used,
        times_used: 1,
        times_succeeded: 1
      });
    }

    db.saveLearningLog(session.id, 'effective_techniques',
      `## Session ${session.id} — ${target.url}\n\n` +
      `### Confirmed Findings (${confirmed.length})\n` +
      confirmed.map(f => `- [${f.severity}] ${f.title} — ${f.endpoint}`).join('\n') + '\n\n' +
      `### Tech Stack: ${techStack}\n`,
      confirmed.map(f => f.vulnerability_type).join(',')
    );
  }

  notify(session.id, 'phase_detail', 'LEARNING', `Saved ${confirmed.length} patterns and learning logs`);
}

async function phaseReport(session, target) {
  const findings = db.getFindingsBySession(session.id);
  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;
  const mediumCount = findings.filter(f => f.severity === 'medium').length;
  const lowCount = findings.filter(f => f.severity === 'low').length;

  notify(session.id, 'phase_detail', 'REPORT',
    `Report Summary — Critical: ${criticalCount}, High: ${highCount}, Medium: ${mediumCount}, Low: ${lowCount}, Total: ${findings.length}`);

  // Generate report file
  const reportPath = path.join(__dirname, 'public', 'reports', `report-${session.id}.html`);
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });

  const reportHtml = generateReportHtml(session, target, findings);
  fs.writeFileSync(reportPath, reportHtml);

  // Also write markdown report
  const mdPath = path.join(__dirname, 'public', 'reports', `report-${session.id}.md`);
  const mdContent = generateReportMarkdown(session, target, findings);
  fs.writeFileSync(mdPath, mdContent);

  notify(session.id, 'phase_detail', 'REPORT', `Reports saved: /reports/report-${session.id}.html, /reports/report-${session.id}.md`);
}

function generateReportHtml(session, target, findings) {
  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;
  const mediumCount = findings.filter(f => f.severity === 'medium').length;
  const lowCount = findings.filter(f => f.severity === 'low').length;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Bug Bounty Report — ${target.name}</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; background: #0f172a; color: #e2e8f0; }
    h1 { color: #38bdf8; }
    h2 { color: #818cf8; border-bottom: 1px solid #334155; padding-bottom: 8px; }
    h3 { color: #e2e8f0; }
    .meta { display: flex; gap: 20px; flex-wrap: wrap; margin: 20px 0; }
    .meta-item { background: #1e293b; padding: 12px 20px; border-radius: 8px; }
    .severity-critical { color: #ef4444; font-weight: bold; }
    .severity-high { color: #f97316; font-weight: bold; }
    .severity-medium { color: #eab308; font-weight: bold; }
    .severity-low { color: #22c55e; }
    .finding { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 20px; margin: 16px 0; }
    .finding h3 { margin-top: 0; }
    .tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-right: 8px; }
    .tag-critical { background: #7f1d1d; color: #fca5a5; }
    .tag-high { background: #7c2d12; color: #fdba74; }
    .tag-medium { background: #713f12; color: #fde047; }
    .tag-low { background: #14532d; color: #86efac; }
    .tag-poc { background: #1e3a5f; color: #93c5fd; }
    .tag-zeroday { background: #581c87; color: #d8b4fe; }
    pre { background: #0f172a; padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 13px; }
    code { background: #334155; padding: 2px 6px; border-radius: 3px; font-size: 13px; }
  </style>
</head>
<body>
  <h1>Bug Bounty Report</h1>
  <div class="meta">
    <div class="meta-item"><strong>Target:</strong> ${target.url}</div>
    <div class="meta-item"><strong>Mode:</strong> ${session.mode}</div>
    <div class="meta-item"><strong>Date:</strong> ${session.started_at}</div>
    <div class="meta-item"><strong>Total Findings:</strong> ${findings.length}</div>
    <div class="meta-item"><strong>Critical:</strong> ${criticalCount} | <strong>High:</strong> ${highCount} | <strong>Medium:</strong> ${mediumCount} | <strong>Low:</strong> ${lowCount}</div>
  </div>

  <h2>Findings</h2>
  ${findings.map((f, i) => `
  <div class="finding">
    <h3>${i + 1}. [${f.severity.toUpperCase()}] ${f.title}</h3>
    <p>
      <span class="tag tag-${f.severity}">${f.severity.toUpperCase()}</span>
      <span class="tag">CVSS ${f.cvss_score}</span>
      ${f.has_poc ? '<span class="tag tag-poc">PoC Available</span>' : ''}
      ${f.is_zero_day ? '<span class="tag tag-zeroday">Zero-Day Indicator</span>' : ''}
    </p>
    <p><strong>Type:</strong> ${f.vulnerability_type} | <strong>Endpoint:</strong> <code>${f.method} ${f.endpoint || 'N/A'}</code>${f.parameter ? ` | <strong>Parameter:</strong> <code>${f.parameter}</code>` : ''}</p>
    <p>${f.description}</p>
    ${f.evidence ? `<p><strong>Evidence:</strong></p><pre>${f.evidence}</pre>` : ''}
    ${f.remediation ? `<p><strong>Remediation:</strong> ${f.remediation}</p>` : ''}
    ${f.refs ? `<p><strong>References:</strong> ${f.refs}</p>` : ''}
  </div>
  `).join('\n')}

  <p style="text-align:center;color:#64748b;margin-top:40px;">Generated by BugHunter AI — ${new Date().toISOString()}</p>
</body>
</html>`;
}

function generateReportMarkdown(session, target, findings) {
  let md = `# Bug Bounty Report — ${target.name}\n\n`;
  md += `- **Target:** ${target.url}\n`;
  md += `- **Mode:** ${session.mode}\n`;
  md += `- **Date:** ${session.started_at}\n`;
  md += `- **Total Findings:** ${findings.length}\n\n---\n\n`;

  findings.forEach((f, i) => {
    md += `## ${i + 1}. [${f.severity.toUpperCase()}] ${f.title}\n\n`;
    md += `| Property | Value |\n|----------|-------|\n`;
    md += `| Type | ${f.vulnerability_type} |\n`;
    md += `| CVSS | ${f.cvss_score} |\n`;
    md += `| Endpoint | \`${f.method} ${f.endpoint || 'N/A'}\` |\n`;
    if (f.parameter) md += `| Parameter | \`${f.parameter}\` |\n`;
    md += `| PoC | ${f.has_poc ? 'Yes' : 'No'} |\n`;
    md += `| Zero-Day | ${f.is_zero_day ? 'Yes' : 'No'} |\n\n`;
    md += `${f.description}\n\n`;
    if (f.evidence) md += `### Evidence\n\`\`\`\n${f.evidence}\n\`\`\`\n\n`;
    if (f.remediation) md += `### Remediation\n${f.remediation}\n\n`;
    md += `---\n\n`;
  });

  md += `\n*Generated by BugHunter AI — ${new Date().toISOString()}*\n`;
  return md;
}

// WebSocket handlers
wss.on('connection', (ws) => {
  ws.send(JSON.stringify({ type: 'welcome', message: 'Connected to BugHunter AI real-time feed' }));

  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data.toString());
      if (msg.type === 'subscribe_session') {
        ws.sessionSub = msg.session_id;
      }
    } catch (e) { /* invalid JSON */ }
  });
});

// Fallback: serve index.html for SPA routing
app.use((req, res, next) => {
  if (req.path.startsWith('/api/') || req.path.startsWith('/ws') || req.path.startsWith('/events')) return next();
  if (req.method === 'GET' && !req.path.includes('.')) {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } else {
    next();
  }
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`BugHunter AI server running on port ${PORT}`);
  console.log(`Database: ${db.DB_PATH}`);
  console.log(`Tools available: subfinder=${toolAvailable('subfinder')}, httpx=${toolAvailable('httpx')}, nuclei=${toolAvailable('nuclei')}, naabu=${toolAvailable('naabu')}, sqlmap=${toolAvailable('sqlmap')}, ffuf=${toolAvailable('ffuf')}`);
});

module.exports = { app, server };

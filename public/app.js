const C = {
  low: '#15803d',
  medium: '#b45309',
  high: '#c2410c',
  critical: '#b91c1c',
  info: '#1d4ed8',
};

const sampleLog = `2026-05-15T14:22:18Z INFO  api/auth user=alice@acme.io status=200
2026-05-15T14:22:19Z DEBUG db/query SELECT * FROM users WHERE email='alice@acme.io'
2026-05-15T14:22:20Z ERROR config loaded AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
2026-05-15T14:22:21Z INFO  payment.charge card=4242-4242-4242-4242 amount=1299
2026-05-15T14:22:22Z WARN  webhook payload password="hunter2" attempt=3
2026-05-15T14:22:23Z INFO  api/users ssn=123-45-6789 region=us-east-1
2026-05-15T14:22:24Z DEBUG token issued jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.x
2026-05-15T14:22:25Z INFO  api/health status=ok latency=12ms`;

const demoResult = {
  summary:
    'Detected 8 sensitive data exposures across 6 log lines. 2 critical secrets require immediate rotation; payload was blocked from downstream sinks.',
  risk_score: 87,
  risk_level: 'critical',
  action: 'blocked',
  findings: [
    { type: 'AWS Access Key', risk: 'critical', line: 3, value: 'AKIA••••••••••EXAMPLE' },
    { type: 'Credit Card (PAN)', risk: 'critical', line: 4, value: '4242-••••-••••-4242' },
    { type: 'Plaintext Password', risk: 'high', line: 5, value: 'password="••••••"' },
    { type: 'US SSN', risk: 'high', line: 6, value: '•••-••-6789' },
    { type: 'JWT Token', risk: 'medium', line: 7, value: 'eyJhbGc••••••••••••••••' },
    { type: 'Email Address', risk: 'low', line: 1, value: 'a****@acme.io' },
    { type: 'SQL Query w/ PII', risk: 'medium', line: 2, value: "SELECT * FROM users WHERE email='•••'" },
    { type: 'Region Disclosure', risk: 'info', line: 6, value: 'us-east-1' },
  ],
  insight_cards: [
    {
      title: 'Rotate AWS credentials now',
      severity: 'critical',
      impact: '1 long-lived access key exposed in plaintext logs.',
      recommendation: 'Rotate via IAM and revoke active sessions in CloudTrail.',
    },
    {
      title: 'PCI scope at risk',
      severity: 'critical',
      impact: 'Full PAN logged at INFO level in payment.charge.',
      recommendation: 'Apply card-number masking middleware before log emit.',
    },
    {
      title: 'Strip secrets from webhook bodies',
      severity: 'high',
      impact: 'Plaintext passwords appear in WARN-level webhook payloads.',
      recommendation: 'Add request-body redaction filter in webhook handler.',
    },
    {
      title: 'Reduce token telemetry',
      severity: 'medium',
      impact: 'JWTs emitted in DEBUG logs remain valid for current TTL.',
      recommendation: 'Replace jwt= field with token fingerprint hash.',
    },
  ],
  recommended_actions: [],
  sanitized_preview: sanitize(sampleLog),
};

const inputType = document.getElementById('inputType');
const fileInput = document.getElementById('fileInput');
const contentEl = document.getElementById('content');
const analyzeBtn = document.getElementById('analyzeBtn');
const clearBtn = document.getElementById('clearBtn');
const copyResultBtn = document.getElementById('copyResultBtn');
const copyPreviewBtn = document.getElementById('copyPreviewBtn');
const charCountEl = document.getElementById('charCount');
const resultBadge = document.getElementById('resultBadge');
const templateButtons = document.querySelectorAll('.template-btn');
const modeButtons = document.querySelectorAll('[data-mode]');
const dropZone = document.getElementById('dropZone');
const dropHint = document.getElementById('dropHint');
const textareaWrap = document.querySelector('.textarea-wrap');
const summaryEl = document.getElementById('summary');
const kpisEl = document.getElementById('kpis');
const insightsEl = document.getElementById('insights');
const findingsTable = document.getElementById('findingsTable');
const previewEl = document.getElementById('preview');
const visualizationEl = document.getElementById('visualization');
const densityBtn = document.getElementById('densityBtn');
const drawerOverlay = document.getElementById('drawerOverlay');
const drawerScrim = document.getElementById('drawerScrim');
const drawerClose = document.getElementById('drawerClose');
const drawerTitle = document.getElementById('drawerTitle');
const drawerSeverity = document.getElementById('drawerSeverity');
const drawerEvidence = document.getElementById('drawerEvidence');
const drawerWhy = document.getElementById('drawerWhy');
const drawerRemediation = document.getElementById('drawerRemediation');
const drawerCopy = document.getElementById('drawerCopy');
const rotatingWord = document.getElementById('rotatingWord');

let lastResult = null;
let selectedFile = null;
let lastFindings = [];
let dense = false;

const words = ['sensitive data', 'API keys', 'PII', 'secrets', 'passwords'];
let wordIndex = 0;
setInterval(() => {
  wordIndex = (wordIndex + 1) % words.length;
  rotatingWord.textContent = words[wordIndex];
}, 2400);

function normalizeRisk(risk) {
  const value = String(risk || 'info').toLowerCase();
  return ['critical', 'high', 'medium', 'low', 'info'].includes(value) ? value : 'info';
}

function riskClass(risk) {
  return `sev-${normalizeRisk(risk)}`;
}

function riskColor(risk) {
  return C[normalizeRisk(risk)] || C.info;
}

function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function sanitize(value) {
  return String(value || '')
    .replace(/AKIA[A-Z0-9]+/g, '[REDACTED_AWS_KEY]')
    .replace(/\b\d{4}-\d{4}-\d{4}-\d{4}\b/g, '[REDACTED_PAN]')
    .replace(/password="[^"]+"/g, 'password="[REDACTED]"')
    .replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED_SSN]')
    .replace(/jwt=[A-Za-z0-9.\-_]+/g, 'jwt=[REDACTED_JWT]')
    .replace(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi, '[REDACTED_EMAIL]');
}

function severityBadge(risk, label) {
  const normalized = normalizeRisk(risk);
  return `<span class="severity-badge ${riskClass(normalized)}" style="--sev:${riskColor(normalized)}">${escapeHtml(
    label || normalized[0].toUpperCase() + normalized.slice(1)
  )}</span>`;
}

function renderRiskGauge(score, level) {
  const safeScore = Math.max(0, Math.min(100, Number(score) || 0));
  const color = riskColor(level);
  const radius = 72;
  const circumference = 2 * Math.PI * radius;
  const arc = circumference * 0.75;
  const offset = arc - (arc * safeScore) / 100;
  const label = normalizeRisk(level);

  return `
    <div class="risk-gauge">
      <svg viewBox="0 0 168 168" style="transform: rotate(135deg)">
        <circle cx="84" cy="84" r="${radius}" fill="none" stroke="#E8E6DF" stroke-width="10" stroke-linecap="round" stroke-dasharray="${arc} ${circumference}"></circle>
        <circle cx="84" cy="84" r="${radius}" fill="none" stroke="${color}" stroke-width="10" stroke-linecap="round" stroke-dasharray="${arc} ${circumference}" stroke-dashoffset="${offset}"></circle>
      </svg>
      <strong>${safeScore}</strong>
      <span>Risk Score</span>
      <span class="risk-label ${riskClass(label)}" style="--sev:${color}">${label}</span>
    </div>
  `;
}

function renderVisualization(content, findings) {
  const source = content || sampleLog;
  const lines = source.split('\n');
  const flaggedLines = new Map();
  findings.forEach((finding) => {
    if (finding.line) flaggedLines.set(Number(finding.line), finding);
  });

  visualizationEl.innerHTML = lines
    .map((line, idx) => {
      const lineNum = idx + 1;
      const finding = flaggedLines.get(lineNum);
      const style = finding ? ` style="box-shadow: inset 3px 0 0 ${riskColor(finding.risk)}"` : '';
      return `<span class="line ${finding ? 'flagged' : ''}"${style}><strong>${lineNum}</strong>${escapeHtml(line)}</span>`;
    })
    .join('');
}

function renderResult(result, originalContent = contentEl.value || sampleLog) {
  lastResult = result;
  lastFindings = (result.findings || []).map((finding, index) => ({
    id: finding.id || `finding-${index}`,
    type: finding.type || 'Finding',
    risk: normalizeRisk(finding.risk || finding.severity || result.risk_level),
    line: finding.line ?? null,
    value: finding.value ?? finding.masked ?? '—',
    rawLine: finding.rawLine || lineAt(originalContent, finding.line),
    why:
      finding.why ||
      `${finding.type || 'This finding'} may expose sensitive information in logs or downstream telemetry.`,
    remediation: finding.remediation || [
      'Validate whether the value is real production data.',
      'Mask or remove the field at log emission.',
      'Rotate affected credentials when secrets are involved.',
    ],
  }));

  const riskLevel = normalizeRisk(result.risk_level);
  const action = String(result.action || 'review');
  resultBadge.textContent = `${riskLevel} · ${action}`;
  resultBadge.style.color = riskColor(riskLevel);
  resultBadge.style.borderColor = `${riskColor(riskLevel)}33`;
  resultBadge.style.background = `${riskColor(riskLevel)}12`;

  summaryEl.innerHTML = `<p>${escapeHtml(result.summary || 'Analysis complete.')}</p>`;
  kpisEl.innerHTML = `
    ${renderRiskGauge(result.risk_score, riskLevel)}
    <div class="mini-stats">
      <div class="mini-stat"><span>Findings</span><span>${lastFindings.length}</span></div>
      <div class="mini-stat"><span>Action</span><span>${severityBadge(riskLevel, action)}</span></div>
      <div class="mini-stat"><span>Trend · 15 scans</span><span style="color:${riskColor(riskLevel)}">+42%</span></div>
    </div>
  `;

  const cards =
    result.insight_cards && result.insight_cards.length
      ? result.insight_cards
      : (result.insights || []).map((insight) => ({
          title: insight,
          severity: riskLevel,
          impact: insight,
          recommendation: 'Review and remediate based on finding context.',
        }));

  insightsEl.innerHTML = cards.length
    ? cards
        .map(
          (card) => `
            <li class="insight-card">
              <div class="insight-card-head">
                <strong>${escapeHtml(card.title)}</strong>
                ${severityBadge(card.severity || riskLevel)}
              </div>
              <p>${escapeHtml(card.impact || '')}</p>
              <small>→ ${escapeHtml(card.recommendation || 'Review this item.')}</small>
            </li>
          `
        )
        .join('')
    : '<li class="insight-card"><strong>No recommended actions</strong><p>No additional insights were returned.</p></li>';

  findingsTable.innerHTML = lastFindings.length
    ? lastFindings
        .map(
          (finding, index) => `
            <tr data-finding-index="${index}">
              <td>
                <span class="finding-type">
                  <span class="severity-rail" style="background:${riskColor(finding.risk)}"></span>
                  ${escapeHtml(finding.type)}
                </span>
              </td>
              <td data-label="Risk">${severityBadge(finding.risk)}</td>
              <td data-label="Line"><span class="line-cell">${finding.line ? `L${finding.line}` : '—'}</span></td>
              <td data-label="Value"><span class="value-cell">${escapeHtml(finding.value)}</span></td>
            </tr>
          `
        )
        .join('')
    : '<tr><td colspan="4" class="empty-state">No findings — your input looks clean.</td></tr>';

  previewEl.textContent = result.sanitized_preview || sanitize(originalContent);
  renderVisualization(originalContent, lastFindings);
}

function lineAt(content, line) {
  if (!line) return '';
  return String(content || '').split('\n')[Number(line) - 1] || '';
}

function setEmptyState() {
  lastResult = null;
  lastFindings = [];
  resultBadge.textContent = 'Awaiting Input';
  resultBadge.removeAttribute('style');
  summaryEl.innerHTML = '<p>No analysis yet. Add content or use a sample template above, then click Analyze.</p>';
  kpisEl.innerHTML = `
    ${renderRiskGauge(0, 'info')}
    <div class="mini-stats">
      <div class="mini-stat"><span>Findings</span><span>0</span></div>
      <div class="mini-stat"><span>Action</span><span>—</span></div>
      <div class="mini-stat"><span>Trend · 15 scans</span><span>—</span></div>
    </div>
  `;
  insightsEl.innerHTML =
    '<li class="insight-card"><strong>Insight cards will appear here after analysis.</strong><p>Use the sample log to preview the populated state.</p></li>';
  findingsTable.innerHTML = '<tr><td colspan="4" class="empty-state">No findings — your input looks clean.</td></tr>';
  previewEl.textContent = '';
  visualizationEl.textContent = '';
}

function setLoadingState() {
  resultBadge.textContent = 'Loading';
  summaryEl.innerHTML = '<p>Analyzing input and building remediation guidance…</p>';
  kpisEl.innerHTML = '<div class="empty-state">Loading overview…</div>';
  insightsEl.innerHTML = '<li class="insight-card"><strong>Loading insights…</strong><p>Classifier response pending.</p></li>';
  findingsTable.innerHTML = '<tr><td colspan="4" class="empty-state">Loading findings…</td></tr>';
  previewEl.textContent = '';
  visualizationEl.textContent = '';
}

function setErrorState(message = 'Analysis failed — the upstream classifier returned an error.') {
  resultBadge.textContent = 'Error';
  resultBadge.style.color = C.critical;
  resultBadge.style.borderColor = `${C.critical}33`;
  resultBadge.style.background = `${C.critical}12`;
  summaryEl.innerHTML = `<div class="error-state"><span>${escapeHtml(message)}</span><button class="btn ghost small" type="button" id="retryBtn">Retry</button></div>`;
}

function updateCharCount() {
  charCountEl.textContent = String(contentEl.value.length);
}

function updateMode(mode) {
  inputType.value = mode;
  modeButtons.forEach((button) => button.classList.toggle('active', button.dataset.mode === mode));
  const fileMode = mode === 'file';
  dropZone.classList.toggle('visible', fileMode);
  textareaWrap.classList.toggle('hidden', fileMode);
}

async function analyzeJsonPayload(payload) {
  const response = await fetch('/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!response.ok) throw new Error(`Analysis failed: ${response.status}`);
  return response.json();
}

async function analyzeFilePayload(file, currentInputType, options) {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('input_type', currentInputType === 'file' ? 'log' : currentInputType);
  formData.append('mask', String(options.mask));
  formData.append('block_high_risk', String(options.block_high_risk));
  formData.append('log_analysis', String(options.log_analysis));

  const response = await fetch('/api/analyze/file', { method: 'POST', body: formData });
  if (!response.ok) throw new Error(`File analysis failed: ${response.status}`);
  return response.json();
}

async function setSelectedFile(file) {
  if (!file) return;
  selectedFile = file;
  dropHint.textContent = `Selected: ${file.name} (${Math.round(file.size / 1024)} KB)`;
  updateMode('file');
  try {
    contentEl.value = (await file.text()).slice(0, 15000);
    updateCharCount();
  } catch {
    contentEl.value = '';
  }
}

function openDrawer(finding) {
  if (!finding) return;
  drawerTitle.textContent = finding.type;
  drawerSeverity.className = `severity-badge ${riskClass(finding.risk)}`;
  drawerSeverity.style.setProperty('--sev', riskColor(finding.risk));
  drawerSeverity.textContent = normalizeRisk(finding.risk);
  drawerEvidence.textContent = `${finding.line ? `${finding.line}  ` : ''}${finding.value}`;
  drawerWhy.textContent = finding.why;
  drawerRemediation.innerHTML = finding.remediation.map((item) => `<li>${escapeHtml(item)}</li>`).join('');
  drawerOverlay.hidden = false;
}

function closeDrawer() {
  drawerOverlay.hidden = true;
}

analyzeBtn.addEventListener('click', async () => {
  analyzeBtn.disabled = true;
  analyzeBtn.innerHTML = '<span class="loading-spinner"></span>Analyzing…';
  setLoadingState();

  try {
    const currentInputType = inputType.value;
    const options = {
      mask: document.getElementById('mask').checked,
      block_high_risk: document.getElementById('blockHighRisk').checked,
      log_analysis: document.getElementById('logAnalysis').checked,
    };

    let result;
    let sourceContent = contentEl.value;
    const file = currentInputType === 'file' ? selectedFile || fileInput.files?.[0] : null;

    if (file) {
      sourceContent = contentEl.value || (await file.text());
      result = await analyzeFilePayload(file, currentInputType, options);
    } else {
      result = await analyzeJsonPayload({
        input_type: currentInputType,
        content: sourceContent,
        options,
      });
    }

    renderResult(result, sourceContent);
  } catch (error) {
    setErrorState(error.message);
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = 'Analyze';
  }
});

modeButtons.forEach((button) => {
  button.addEventListener('click', () => updateMode(button.dataset.mode));
});

templateButtons.forEach((button) => {
  button.addEventListener('click', () => {
    updateMode(button.dataset.type || 'text');
    contentEl.value = button.dataset.template || '';
    updateCharCount();
    renderResult(demoResult, contentEl.value || sampleLog);
    contentEl.focus();
  });
});

clearBtn.addEventListener('click', () => {
  contentEl.value = '';
  fileInput.value = '';
  selectedFile = null;
  dropHint.textContent = 'Supports .log, .txt, .pdf, .docx';
  updateCharCount();
  setEmptyState();
});

contentEl.addEventListener('input', updateCharCount);
fileInput.addEventListener('change', async () => setSelectedFile(fileInput.files?.[0]));
dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' || event.key === ' ') fileInput.click();
});

['dragenter', 'dragover'].forEach((eventName) => {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.add('drag-over');
  });
});

['dragleave', 'drop'].forEach((eventName) => {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.remove('drag-over');
  });
});

dropZone.addEventListener('drop', async (event) => setSelectedFile(event.dataTransfer?.files?.[0]));

copyResultBtn.addEventListener('click', async () => {
  if (!lastResult) return;
  await navigator.clipboard.writeText(JSON.stringify(lastResult, null, 2));
  copyResultBtn.textContent = 'Copied!';
  setTimeout(() => (copyResultBtn.textContent = 'Copy JSON'), 1200);
});

copyPreviewBtn.addEventListener('click', async () => {
  if (!previewEl.textContent) return;
  await navigator.clipboard.writeText(previewEl.textContent);
  copyPreviewBtn.textContent = 'Copied!';
  setTimeout(() => (copyPreviewBtn.textContent = 'Copy'), 1200);
});

findingsTable.addEventListener('click', (event) => {
  const row = event.target.closest('tr[data-finding-index]');
  if (!row) return;
  openDrawer(lastFindings[Number(row.dataset.findingIndex)]);
});

densityBtn.addEventListener('click', () => {
  dense = !dense;
  findingsTable.classList.toggle('dense', dense);
  densityBtn.textContent = dense ? 'Comfortable' : 'Compact';
});

drawerClose.addEventListener('click', closeDrawer);
drawerScrim.addEventListener('click', closeDrawer);
drawerCopy.addEventListener('click', async () => {
  await navigator.clipboard.writeText(drawerEvidence.textContent || '');
  drawerCopy.textContent = 'Copied!';
  setTimeout(() => (drawerCopy.textContent = 'Copy value'), 1200);
});

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') closeDrawer();
});

updateMode('log');
contentEl.value = sampleLog;
updateCharCount();
renderResult(demoResult, sampleLog);

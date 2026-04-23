/* SecureIntel AI — Frontend Application Logic */

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
const dropZone = document.getElementById('dropZone');
const dropHint = document.getElementById('dropHint');
const summaryEl = document.getElementById('summary');
const kpisEl = document.getElementById('kpis');
const insightsEl = document.getElementById('insights');
const findingsTable = document.getElementById('findingsTable');
const previewEl = document.getElementById('preview');
const visualizationEl = document.getElementById('visualization');

let lastResult = null;
let selectedFile = null;

/* ===== Helpers ===== */

function riskClass(risk) {
  return `risk-${risk}`;
}

function escapeHtml(str) {
  return str.replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/* ===== Renderers ===== */

function renderVisualization(content, findings) {
  const lines = (content || '').split('\n');
  const flaggedLines = new Set(findings.map((f) => f.line).filter(Boolean));
  visualizationEl.innerHTML = lines
    .map((line, idx) => {
      const lineNum = idx + 1;
      const isFlagged = flaggedLines.has(lineNum);
      return `<span class="line ${isFlagged ? 'flagged' : ''}"><strong>${lineNum
        .toString()
        .padStart(4, '0')}</strong>  ${escapeHtml(line)}</span>`;
    })
    .join('');
}

function renderResult(result, originalContent) {
  lastResult = result;

  // Status badge
  resultBadge.textContent = `${result.risk_level.toUpperCase()} · ${result.action.toUpperCase()}`;
  resultBadge.className = `hero-stat-value ${riskClass(result.risk_level)}`;

  // Summary
  summaryEl.innerHTML = `<p><strong>${escapeHtml(result.summary)}</strong></p>`;

  // KPIs
  kpisEl.innerHTML = `
    <div class="kpi-card">
      <span class="kpi-label">Risk Score</span>
      <span class="kpi-value">${result.risk_score}</span>
    </div>
    <div class="kpi-card">
      <span class="kpi-label">Risk Level</span>
      <span class="kpi-value ${riskClass(result.risk_level)}">${result.risk_level.toUpperCase()}</span>
    </div>
    <div class="kpi-card">
      <span class="kpi-label">Action</span>
      <span class="kpi-value">${result.action.toUpperCase()}</span>
    </div>
    <div class="kpi-card">
      <span class="kpi-label">Findings</span>
      <span class="kpi-value">${result.findings.length}</span>
    </div>
  `;

  // Insights
  insightsEl.innerHTML = '';
  const cards =
    result.insight_cards && result.insight_cards.length > 0
      ? result.insight_cards
      : (result.insights || []).map((insight) => ({
          title: insight,
          severity: result.risk_level,
          impact: insight,
          recommendation: 'Review and remediate based on finding context.',
        }));

  cards.forEach((card) => {
    const li = document.createElement('li');
    li.classList.add('insight-card');
    li.innerHTML = `<strong>${escapeHtml(card.title)}</strong> <span class="${riskClass(
      card.severity
    )}">(${card.severity.toUpperCase()})</span><br/>${escapeHtml(
      card.impact
    )}<br/><em>Action:</em> ${escapeHtml(card.recommendation)}`;
    insightsEl.appendChild(li);
  });

  if (result.recommended_actions && result.recommended_actions.length > 0) {
    const divider = document.createElement('li');
    divider.classList.add('insight-action');
    divider.innerHTML = '<strong>Recommended next actions:</strong>';
    insightsEl.appendChild(divider);
    result.recommended_actions.forEach((action) => {
      const li = document.createElement('li');
      li.classList.add('insight-action');
      li.textContent = `→ ${action}`;
      insightsEl.appendChild(li);
    });
  }

  // Findings table
  findingsTable.innerHTML = '';
  result.findings.forEach((finding) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${escapeHtml(finding.type)}</td>
      <td class="${riskClass(finding.risk)}">${finding.risk}</td>
      <td>${finding.line ?? '—'}</td>
      <td>${escapeHtml(finding.value ?? '—')}</td>
    `;
    findingsTable.appendChild(tr);
  });

  // Preview & visualization
  previewEl.textContent = result.sanitized_preview || '';
  renderVisualization(originalContent, result.findings);
}

function setEmptyState() {
  summaryEl.innerHTML =
    '<p>No analysis yet. Add content or use a sample template above, then click <strong>Analyze</strong>.</p>';
  kpisEl.innerHTML = `
    <div class="kpi-card"><span class="kpi-label">Risk Score</span><span class="kpi-value">—</span></div>
    <div class="kpi-card"><span class="kpi-label">Risk Level</span><span class="kpi-value">—</span></div>
    <div class="kpi-card"><span class="kpi-label">Action</span><span class="kpi-value">—</span></div>
    <div class="kpi-card"><span class="kpi-label">Findings</span><span class="kpi-value">0</span></div>
  `;
  insightsEl.innerHTML =
    '<li class="insight-action">Insight cards will appear here after analysis.</li>';
  findingsTable.innerHTML = '';
  previewEl.textContent = '';
  visualizationEl.textContent = '';
  resultBadge.textContent = 'Awaiting Input';
  resultBadge.className = 'hero-stat-value';
}

function updateCharCount() {
  charCountEl.textContent = String(contentEl.value.length);
}

/* ===== API Calls ===== */

async function analyzeJsonPayload(payload) {
  const response = await fetch('/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    throw new Error(`Analysis failed: ${response.status}`);
  }
  return response.json();
}

async function analyzeFilePayload(file, currentInputType, options) {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('input_type', currentInputType === 'file' ? 'log' : currentInputType);
  formData.append('mask', String(options.mask));
  formData.append('block_high_risk', String(options.block_high_risk));
  formData.append('log_analysis', String(options.log_analysis));

  const response = await fetch('/api/analyze/file', {
    method: 'POST',
    body: formData,
  });
  if (!response.ok) {
    throw new Error(`File analysis failed: ${response.status}`);
  }
  return response.json();
}

async function setSelectedFile(file) {
  if (!file) return;
  selectedFile = file;
  dropHint.textContent = `Selected: ${file.name} (${Math.round(file.size / 1024)} KB)`;
  if (inputType.value === 'text') {
    inputType.value = 'file';
  }
  try {
    const fileText = await file.text();
    contentEl.value = fileText.slice(0, 15000);
    updateCharCount();
  } catch {
    // non-text file preview may fail; keep silent and still analyze via upload endpoint
  }
}

/* ===== Event Listeners ===== */

analyzeBtn.addEventListener('click', async () => {
  analyzeBtn.disabled = true;
  analyzeBtn.innerHTML =
    '<span class="loading-spinner"></span><span>Analyzing…</span>';

  try {
    const currentInputType = inputType.value;
    const options = {
      mask: document.getElementById('mask').checked,
      block_high_risk: document.getElementById('blockHighRisk').checked,
      log_analysis: document.getElementById('logAnalysis').checked,
    };

    let result;
    let sourceContent = contentEl.value;

    const file =
      inputType.value === 'file'
        ? selectedFile || (fileInput.files?.length ? fileInput.files[0] : null)
        : null;
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
    summaryEl.innerHTML = `<p class="risk-critical">${escapeHtml(error.message)}</p>`;
    resultBadge.textContent = 'Error';
    resultBadge.className = 'hero-stat-value risk-critical';
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      <span>Analyze</span>
      <div class="btn-shimmer"></div>`;
  }
});

templateButtons.forEach((button) => {
  button.addEventListener('click', () => {
    const type = button.getAttribute('data-type') || 'text';
    const template = button.getAttribute('data-template') || '';
    inputType.value = type;
    contentEl.value = template;
    updateCharCount();
    contentEl.focus();
  });
});

clearBtn.addEventListener('click', () => {
  contentEl.value = '';
  fileInput.value = '';
  selectedFile = null;
  dropHint.textContent = 'Supports .log, .txt, .pdf, .docx';
  updateCharCount();
  lastResult = null;
  setEmptyState();
});

fileInput.addEventListener('change', async () => {
  const file = fileInput.files?.[0];
  await setSelectedFile(file);
});

['dragenter', 'dragover'].forEach((eventName) => {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    event.stopPropagation();
    dropZone.classList.add('drag-over');
  });
});

['dragleave', 'drop'].forEach((eventName) => {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    event.stopPropagation();
    dropZone.classList.remove('drag-over');
  });
});

dropZone.addEventListener('drop', async (event) => {
  const file = event.dataTransfer?.files?.[0];
  if (!file) return;
  await setSelectedFile(file);
});

dropZone.addEventListener('click', () => fileInput.click());

copyResultBtn.addEventListener('click', async () => {
  if (!lastResult) return;
  try {
    await navigator.clipboard.writeText(JSON.stringify(lastResult, null, 2));
    copyResultBtn.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
      Copied!`;
  } catch {
    copyResultBtn.textContent = 'Copy failed';
  }
  setTimeout(() => {
    copyResultBtn.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
      Copy JSON`;
  }, 1200);
});

copyPreviewBtn.addEventListener('click', async () => {
  if (!previewEl.textContent) return;
  try {
    await navigator.clipboard.writeText(previewEl.textContent);
    copyPreviewBtn.innerHTML = `
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
      Copied!`;
  } catch {
    copyPreviewBtn.textContent = 'Copy failed';
  }
  setTimeout(() => {
    copyPreviewBtn.innerHTML = `
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
      Copy`;
  }, 1200);
});

contentEl.addEventListener('input', updateCharCount);

inputType.addEventListener('change', () => {
  if (inputType.value !== 'file') {
    selectedFile = null;
    fileInput.value = '';
    dropHint.textContent = 'Supports .log, .txt, .pdf, .docx';
  }
});

dropZone.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' || event.key === ' ') {
    event.preventDefault();
    fileInput.click();
  }
});

/* ===== Init ===== */
setEmptyState();
updateCharCount();

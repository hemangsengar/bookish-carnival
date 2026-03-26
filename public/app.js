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

function riskClass(risk) {
  return `risk-${risk}`;
}

function renderVisualization(content, findings) {
  const lines = (content || '').split('\n');
  const flaggedLines = new Set(findings.map((f) => f.line).filter(Boolean));
  visualizationEl.innerHTML = lines
    .map((line, idx) => {
      const lineNum = idx + 1;
      const isFlagged = flaggedLines.has(lineNum);
      return `<span class="line ${isFlagged ? 'flagged' : ''}"><strong>${lineNum.toString().padStart(4, '0')}</strong>  ${line.replace(/</g, '&lt;')}</span>`;
    })
    .join('');
}

function renderResult(result, originalContent) {
  lastResult = result;
  resultBadge.textContent = `${result.risk_level.toUpperCase()} • ${result.action.toUpperCase()}`;
  resultBadge.className = `subtle-chip ${riskClass(result.risk_level)}`;

  summaryEl.innerHTML = `<p><strong>${result.summary}</strong></p>`;
  kpisEl.innerHTML = `
    <div>Risk Score<br /><strong>${result.risk_score}</strong></div>
    <div>Risk Level<br /><strong class="${riskClass(result.risk_level)}">${result.risk_level.toUpperCase()}</strong></div>
    <div>Action<br /><strong>${result.action.toUpperCase()}</strong></div>
    <div>Findings<br /><strong>${result.findings.length}</strong></div>
  `;

  insightsEl.innerHTML = '';
  const cards = result.insight_cards && result.insight_cards.length > 0
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
    li.innerHTML = `<strong>${card.title}</strong> <span class="${riskClass(card.severity)}">(${card.severity.toUpperCase()})</span><br/>${card.impact}<br/><em>Action:</em> ${card.recommendation}`;
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
      li.textContent = `• ${action}`;
      insightsEl.appendChild(li);
    });
  }

  findingsTable.innerHTML = '';
  result.findings.forEach((finding) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${finding.type}</td>
      <td class="${riskClass(finding.risk)}">${finding.risk}</td>
      <td>${finding.line ?? '-'}</td>
      <td>${finding.value ?? '-'}</td>
    `;
    findingsTable.appendChild(tr);
  });

  previewEl.textContent = result.sanitized_preview || '';
  renderVisualization(originalContent, result.findings);
}

function setEmptyState() {
  summaryEl.innerHTML = '<p><strong>No analysis yet.</strong> Add content or use a sample above, then click Analyze.</p>';
  kpisEl.innerHTML = `
    <div>Risk Score<br /><strong>0</strong></div>
    <div>Risk Level<br /><strong>—</strong></div>
    <div>Action<br /><strong>—</strong></div>
    <div>Findings<br /><strong>0</strong></div>
  `;
  insightsEl.innerHTML = '<li class="insight-action">Insight cards will appear here after analysis.</li>';
  findingsTable.innerHTML = '';
  previewEl.textContent = '';
  visualizationEl.textContent = '';
  resultBadge.textContent = 'Awaiting analysis';
  resultBadge.className = 'subtle-chip';
}

function updateCharCount() {
  charCountEl.textContent = String(contentEl.value.length);
}

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

analyzeBtn.addEventListener('click', async () => {
  analyzeBtn.disabled = true;
  analyzeBtn.textContent = 'Analyzing...';

  try {
    const currentInputType = inputType.value;
    const options = {
      mask: document.getElementById('mask').checked,
      block_high_risk: document.getElementById('blockHighRisk').checked,
      log_analysis: document.getElementById('logAnalysis').checked,
    };

    let result;
    let sourceContent = contentEl.value;

    const file = inputType.value === 'file'
      ? (selectedFile || (fileInput.files?.length ? fileInput.files[0] : null))
      : null;
    if (file) {
      sourceContent = contentEl.value || await file.text();
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
    summaryEl.innerHTML = `<p class="risk-critical">${error.message}</p>`;
    resultBadge.textContent = 'Analysis error';
    resultBadge.className = 'subtle-chip risk-critical';
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = 'Analyze';
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
  dropHint.textContent = 'Supported: .log, .txt, .pdf, .docx';
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
    copyResultBtn.textContent = 'Copied';
  } catch {
    copyResultBtn.textContent = 'Copy failed';
  }
  setTimeout(() => { copyResultBtn.textContent = 'Copy JSON'; }, 900);
});

copyPreviewBtn.addEventListener('click', async () => {
  if (!previewEl.textContent) return;
  try {
    await navigator.clipboard.writeText(previewEl.textContent);
    copyPreviewBtn.textContent = 'Copied';
  } catch {
    copyPreviewBtn.textContent = 'Copy failed';
  }
  setTimeout(() => { copyPreviewBtn.textContent = 'Copy Preview'; }, 900);
});

contentEl.addEventListener('input', updateCharCount);

inputType.addEventListener('change', () => {
  if (inputType.value !== 'file') {
    selectedFile = null;
    fileInput.value = '';
    dropHint.textContent = 'Supported: .log, .txt, .pdf, .docx';
  }
});

dropZone.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' || event.key === ' ') {
    event.preventDefault();
    fileInput.click();
  }
});

setEmptyState();
updateCharCount();

const inputType = document.getElementById('inputType');
const fileInput = document.getElementById('fileInput');
const contentEl = document.getElementById('content');
const analyzeBtn = document.getElementById('analyzeBtn');
const summaryEl = document.getElementById('summary');
const kpisEl = document.getElementById('kpis');
const insightsEl = document.getElementById('insights');
const findingsTable = document.getElementById('findingsTable');
const previewEl = document.getElementById('preview');
const visualizationEl = document.getElementById('visualization');

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
  summaryEl.innerHTML = `<p><strong>${result.summary}</strong></p>`;
  kpisEl.innerHTML = `
    <div>Risk Score<br /><strong>${result.risk_score}</strong></div>
    <div>Risk Level<br /><strong class="${riskClass(result.risk_level)}">${result.risk_level}</strong></div>
    <div>Action<br /><strong>${result.action}</strong></div>
    <div>Findings<br /><strong>${result.findings.length}</strong></div>
  `;

  insightsEl.innerHTML = '';
  result.insights.forEach((insight) => {
    const li = document.createElement('li');
    li.textContent = insight;
    insightsEl.appendChild(li);
  });

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

    if (fileInput.files?.length > 0) {
      const file = fileInput.files[0];
      sourceContent = await file.text();
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
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = 'Analyze';
  }
});

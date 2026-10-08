// CyberShield Frontend Interactive Engine - Full Screen Clean Interface

let scoreGaugeChart = null;
let currentEmlFile = null;

document.addEventListener("DOMContentLoaded", () => {
    initScoreGauge(0, "SAFE");
    initDropZone();
    switchMainTool('home-view');
});

// Switch between Home, Tool 1 (Analyse Email), and Tool 2 (Scan URL)
function switchMainTool(toolId) {
    const homeView = document.getElementById('home-view');
    const emailTool = document.getElementById('email-tool');
    const urlTool = document.getElementById('url-tool');
    const resultsSec = document.getElementById('results-section');

    const navBtnHome = document.getElementById('nav-btn-home');
    const navBtnEmail = document.getElementById('nav-btn-email');
    const navBtnUrl = document.getElementById('nav-btn-url');

    // Reset all nav tabs
    if (navBtnHome) navBtnHome.classList.remove('active');
    if (navBtnEmail) navBtnEmail.classList.remove('active');
    if (navBtnUrl) navBtnUrl.classList.remove('active');

    // Hide all views
    if (homeView) homeView.classList.add('hidden');
    if (emailTool) emailTool.classList.add('hidden');
    if (urlTool) urlTool.classList.add('hidden');

    if (toolId === 'home-view') {
        if (homeView) homeView.classList.remove('hidden');
        if (navBtnHome) navBtnHome.classList.add('active');
        if (resultsSec) resultsSec.classList.add('hidden');
    } else if (toolId === 'email-tool') {
        if (emailTool) emailTool.classList.remove('hidden');
        if (navBtnEmail) navBtnEmail.classList.add('active');
        if (resultsSec) resultsSec.classList.remove('hidden');
    } else if (toolId === 'url-tool') {
        if (urlTool) urlTool.classList.remove('hidden');
        if (navBtnUrl) navBtnUrl.classList.add('active');
        if (resultsSec) resultsSec.classList.remove('hidden');
    }

    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Switch between Manual Input and .eml File Upload inside Tool 1
function switchEmailMode(mode) {
    const manualSec = document.getElementById('email-manual-section');
    const emlSec = document.getElementById('email-eml-section');
    const btnManual = document.getElementById('mode-btn-manual');
    const btnEml = document.getElementById('mode-btn-eml');

    if (mode === 'manual') {
        manualSec.classList.remove('hidden');
        emlSec.classList.add('hidden');
        btnManual.classList.add('active');
        btnEml.classList.remove('active');
    } else {
        manualSec.classList.add('hidden');
        emlSec.classList.remove('hidden');
        btnManual.classList.remove('active');
        btnEml.classList.add('active');
    }
}

// Clear manual input fields
function clearManualFields() {
    document.getElementById('input-sender').value = '';
    document.getElementById('input-subject').value = '';
    document.getElementById('input-body').value = '';
    document.getElementById('attachments-container').innerHTML = '';
}

// ============================================================
// .EML File Drag & Drop & Upload
// ============================================================
function initDropZone() {
    const dropZone = document.getElementById('eml-drop-zone');
    const fileInput = document.getElementById('eml-file-input');

    if (!dropZone || !fileInput) return;

    dropZone.addEventListener('click', () => fileInput.click());

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            handleEmlFileSelect(e.dataTransfer.files);
        }
    });
}

function handleEmlFileSelect(files) {
    if (!files || files.length === 0) return;
    const file = files[0];

    if (!file.name.toLowerCase().endsWith('.eml')) {
        alert('Please select a valid RFC 822 .eml email file.');
        return;
    }

    currentEmlFile = file;
    document.getElementById('eml-filename').innerText = file.name;
    document.getElementById('eml-filesize').innerText = formatBytes(file.size);
    document.getElementById('eml-file-preview').classList.remove('hidden');
}

function clearEmlFile() {
    currentEmlFile = null;
    document.getElementById('eml-file-input').value = '';
    document.getElementById('eml-file-preview').classList.add('hidden');
}

async function uploadAndScanEml() {
    if (!currentEmlFile) {
        alert('Please select or drop a .eml file first.');
        return;
    }

    const btn = document.getElementById('btn-scan-eml');
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Parsing and Inspecting .eml...`;

    const formData = new FormData();
    formData.append('file', currentEmlFile);

    try {
        const res = await fetch('/api/scan/eml', {
            method: 'POST',
            body: formData
        });

        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.summary || 'Failed to scan .eml file');
        }

        const data = await res.json();
        renderScanResults(data);

        // Ensure results section is shown and scroll smoothly to results
        const resSec = document.getElementById('results-section');
        if (resSec) resSec.classList.remove('hidden');
        resSec.scrollIntoView({ behavior: 'smooth' });
    } catch (err) {
        alert('EML Analysis Error: ' + err.message);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-bolt text-lg"></i> Analyze Uploaded .eml File`;
    }
}

// ============================================================
// Tool 1: Manual Email Scan
// ============================================================
async function performManualEmailScan() {
    const sender = document.getElementById('input-sender').value.trim();
    const subject = document.getElementById('input-subject').value.trim();
    const body = document.getElementById('input-body').value.trim();

    if (!sender && !subject && !body) {
        alert('Please provide at least a sender address, subject, or email body to analyze.');
        return;
    }

    const btn = document.getElementById('btn-scan-manual');
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Inspecting 4 Layers...`;

    const payload = {
        sender: sender,
        subject: subject,
        body: body,
        attachments: getAttachmentsData(),
        triggerVirusTotal: true
    };

    try {
        const res = await fetch('/api/scan/email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!res.ok) throw new Error('Scan failed with status ' + res.status);
        const data = await res.json();
        renderScanResults(data);
        loadDatabaseHistory();

        const resSec = document.getElementById('results-section');
        if (resSec) resSec.classList.remove('hidden');
        resSec.scrollIntoView({ behavior: 'smooth' });
    } catch (err) {
        alert('Scan Error: ' + err.message);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-shield-virus text-lg"></i> Analyze Email (4-Layer Engine)`;
    }
}

// ============================================================
// Tool 2: URL Scan
// ============================================================
async function performUrlScan() {
    const urlInput = document.getElementById('input-target-url').value.trim();
    if (!urlInput) {
        alert('Please enter a target URL to scan.');
        return;
    }

    const btn = document.getElementById('btn-scan-url');
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Scanning URL...`;

    try {
        const res = await fetch('/api/scan/url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput, forceVirusTotal: true })
        });

        if (!res.ok) throw new Error('URL scan failed with status ' + res.status);
        const data = await res.json();
        renderScanResults(data);
        loadDatabaseHistory();

        const resSec = document.getElementById('results-section');
        if (resSec) resSec.classList.remove('hidden');
        resSec.scrollIntoView({ behavior: 'smooth' });
    } catch (err) {
        alert('URL Scan Error: ' + err.message);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-magnifying-glass"></i> Scan URL`;
    }
}

// ============================================================
// Result Rendering (Gauge, Layers, Findings Table)
// ============================================================
function renderScanResults(result) {
    // Score is strictly capped between 0 and 15
    const score = Math.min(15.0, Math.max(0, result.overallRiskScore));
    const classification = result.classification;

    // Score Value & Label
    const scoreVal = document.getElementById('gauge-score-value');
    const riskLabel = document.getElementById('gauge-risk-label');
    scoreVal.innerText = score.toFixed(1);

    riskLabel.className = 'text-xs font-extrabold px-3 py-1 rounded-full mt-1 ' +
        (classification === 'SAFE' ? 'badge-safe' : (classification === 'SUSPICIOUS' ? 'badge-suspicious' : 'badge-dangerous'));
    riskLabel.innerText = classification;

    updateScoreGauge(score, classification);

    // Execution time
    document.getElementById('scan-time-label').innerText = (result.totalExecutionTimeMs || 0) + ' ms';

    // Layer Scores
    const l1 = result.layerResults.find(l => l.layerNumber === 1);
    const l2 = result.layerResults.find(l => l.layerNumber === 2);
    const l3 = result.layerResults.find(l => l.layerNumber === 3);
    const l4 = result.layerResults.find(l => l.layerNumber === 4);

    document.getElementById('l1-score-pill').innerText = l1 ? l1.score.toFixed(1) : '0.0';
    document.getElementById('l2-score-pill').innerText = l2 ? l2.score.toFixed(1) : '0.0';
    document.getElementById('l3-score-pill').innerText = l3 ? l3.score.toFixed(1) : '0.0';
    document.getElementById('l4-score-pill').innerText = l4 ? l4.score.toFixed(1) : '0.0';

    // Recommendations
    const recsList = document.getElementById('recs-list');
    recsList.innerHTML = '';
    if (result.recommendations && result.recommendations.length > 0) {
        result.recommendations.forEach(r => {
            const li = document.createElement('li');
            li.innerText = r;
            recsList.appendChild(li);
        });
    } else {
        const li = document.createElement('li');
        li.innerText = 'No threat indicators flagged. Normal communication.';
        recsList.appendChild(li);
    }

    // Detailed Findings Table
    const tbody = document.getElementById('findings-tbody');
    tbody.innerHTML = '';

    let totalFindings = 0;
    if (result.layerResults) {
        result.layerResults.forEach(lr => {
            if (lr.indicators) {
                lr.indicators.forEach(ind => {
                    totalFindings++;
                    const tr = document.createElement('tr');
                    tr.className = 'hover:bg-slate-800/60 transition';

                    const sevBadge = ind.severity === 'CRITICAL' ? 'bg-red-950 text-red-300 border border-red-700' :
                        (ind.severity === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-700' :
                        'bg-blue-950 text-blue-300 border border-blue-700');

                    tr.innerHTML = `
                        <td class="p-3 font-mono font-bold text-slate-300 text-xs">${ind.layer}</td>
                        <td class="p-3 font-bold text-white text-xs">${escapeHtml(ind.title)}</td>
                        <td class="p-3"><span class="px-2 py-0.5 rounded-md text-[10px] font-extrabold font-mono ${sevBadge}">${ind.severity}</span></td>
                        <td class="p-3 font-mono font-extrabold text-red-400 text-xs">+${ind.scoreContribution.toFixed(1)}</td>
                        <td class="p-3 font-mono text-cyan-300 text-xs break-all">${escapeHtml(ind.evidence || '')}</td>
                        <td class="p-3 text-slate-200 text-xs leading-relaxed">${escapeHtml(ind.description || '')}</td>
                    `;
                    tbody.appendChild(tr);
                });
            }
        });
    }

    document.getElementById('findings-count').innerText = `${totalFindings} Finding(s)`;

    if (totalFindings === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="p-8 text-center text-emerald-400 font-bold text-sm">✓ Clean: No threat indicators triggered in any of the 4 detection layers.</td></tr>`;
    }
}

// ============================================================
// Attachments Handling
// ============================================================
function addAttachmentRow() {
    addAttachmentItem('', 0, 'application/octet-stream');
}

function addAttachmentItem(filename, size, mime) {
    const container = document.getElementById('attachments-container');
    const id = 'att-' + Date.now() + Math.random().toString(36).substr(2, 4);

    const div = document.createElement('div');
    div.id = id;
    div.className = 'flex flex-wrap items-center gap-2 card-sub p-2.5 rounded-lg text-xs font-mono';
    div.innerHTML = `
        <input type="text" placeholder="Filename (e.g. document.pdf.exe)" value="${filename}" class="att-name rounded px-3 py-2 flex-1 font-semibold">
        <input type="number" placeholder="Size in bytes" value="${size > 0 ? size : ''}" class="att-size rounded px-3 py-2 w-32">
        <input type="text" placeholder="MIME Type (optional)" value="${mime}" class="att-mime rounded px-3 py-2 w-48">
        <button type="button" onclick="document.getElementById('${id}').remove()" class="bg-red-950 text-red-300 border border-red-700 hover:bg-red-900 px-3 py-2 rounded font-bold">✕</button>
    `;
    container.appendChild(div);
}

function getAttachmentsData() {
    const items = [];
    document.querySelectorAll('#attachments-container > div').forEach(div => {
        const name = div.querySelector('.att-name').value.trim();
        const size = parseInt(div.querySelector('.att-size').value) || 0;
        const mime = div.querySelector('.att-mime').value.trim();
        if (name) {
            items.push({ filename: name, sizeBytes: size, contentType: mime });
        }
    });
    return items;
}

// Chart.js Gauge (Scale 0 - 15)
function initScoreGauge(score, classification) {
    const canvas = document.getElementById('scoreGaugeCanvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const cappedScore = Math.min(score, 15);
    scoreGaugeChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [cappedScore, Math.max(0, 15 - cappedScore)],
                backgroundColor: [getColorForClassification(classification), 'rgba(255, 255, 255, 0.1)'],
                borderWidth: 0,
                circumference: 260,
                rotation: 230
            }]
        },
        options: {
            responsive: false,
            cutout: '80%',
            plugins: { tooltip: { enabled: false } }
        }
    });
}

function updateScoreGauge(score, classification) {
    if (scoreGaugeChart) {
        const cappedScore = Math.min(score, 15);
        scoreGaugeChart.data.datasets[0].data = [cappedScore, Math.max(0, 15 - cappedScore)];
        scoreGaugeChart.data.datasets[0].backgroundColor[0] = getColorForClassification(classification);
        scoreGaugeChart.update();
    }
}

function getColorForClassification(c) {
    if (c === 'DANGEROUS') return '#ef4444';
    if (c === 'SUSPICIOUS') return '#f59e0b';
    return '#10b981';
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

// ============================================================
// H2 Database History Management
// ============================================================
let cachedDatabaseScans = [];

async function loadDatabaseHistory() {
    try {
        const res = await fetch('/api/scan/db-history');
        if (!res.ok) return;
        cachedDatabaseScans = await res.json();
        renderDatabaseHistory(cachedDatabaseScans);
    } catch (err) {
        console.warn('Could not fetch H2 database history:', err);
    }
}

function renderDatabaseHistory(scans) {
    const tbody = document.getElementById('db-history-tbody');
    if (!tbody) return;

    if (!scans || scans.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="px-4 py-8 text-center text-slate-400 italic text-sm">
                    No scans saved in H2 database yet. Run an email or URL scan above to automatically record it into H2!
                </td>
            </tr>`;
        return;
    }

    tbody.innerHTML = '';
    scans.forEach((scan, index) => {
        const tr = document.createElement('tr');
        tr.className = 'hover:bg-slate-800/60 transition';

        const classification = scan.classification || 'SAFE';
        const badgeClass = classification === 'DANGEROUS' ? 'badge-dangerous' :
                          (classification === 'SUSPICIOUS' ? 'badge-suspicious' : 'badge-safe');

        const typeBadge = scan.scanType === 'URL' ? 'bg-cyan-950 text-cyan-300 border border-cyan-700' :
                                                    'bg-blue-950 text-blue-300 border border-blue-700';

        const displayTarget = scan.inputTarget || scan.subject || scan.sender || 'Scan Record';
        const dateStr = scan.createdAt ? new Date(scan.createdAt).toLocaleString() : 'Recent';

        tr.innerHTML = `
            <td class="px-4 py-3"><span class="px-2 py-0.5 rounded text-[11px] font-mono font-bold ${typeBadge}">${escapeHtml(scan.scanType || 'EMAIL')}</span></td>
            <td class="px-4 py-3 font-semibold text-white max-w-md truncate" title="${escapeHtml(displayTarget)}">${escapeHtml(displayTarget)}</td>
            <td class="px-4 py-3"><span class="px-2.5 py-0.5 rounded-full text-xs font-bold font-mono ${badgeClass}">${classification}</span></td>
            <td class="px-4 py-3 font-mono font-bold ${classification === 'DANGEROUS' ? 'text-red-400' : (classification === 'SUSPICIOUS' ? 'text-amber-400' : 'text-emerald-400')}">${(scan.overallRiskScore || 0).toFixed(1)} / 15</td>
            <td class="px-4 py-3 text-xs text-slate-300 font-mono">${dateStr}</td>
            <td class="px-4 py-3 text-right">
                <button onclick="viewSavedScan(${index})" class="text-xs bg-blue-600 hover:bg-blue-500 text-white font-bold px-3 py-1.5 rounded-lg transition shadow">
                    <i class="fa-solid fa-eye mr-1"></i> View Audit
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function viewSavedScan(index) {
    const scan = cachedDatabaseScans[index];
    if (!scan) return;

    // Convert database entity into frontend scan result structure
    const layer1Indicators = (scan.indicators || []).filter(i => i.layer && i.layer.toLowerCase().includes('1'));
    const layer2Indicators = (scan.indicators || []).filter(i => i.layer && i.layer.toLowerCase().includes('2'));
    const layer3Indicators = (scan.indicators || []).filter(i => i.layer && i.layer.toLowerCase().includes('3'));
    const layer4Indicators = (scan.indicators || []).filter(i => i.layer && i.layer.toLowerCase().includes('4'));

    const reconstructed = {
        scanId: scan.scanId,
        scanType: scan.scanType,
        overallRiskScore: scan.overallRiskScore,
        classification: scan.classification,
        totalExecutionTimeMs: scan.totalExecutionTimeMs || 0,
        summary: scan.summary,
        recommendations: scan.summary ? [scan.summary] : ["Loaded from H2 Database audit record."],
        layerResults: [
            {
                layerNumber: 1,
                layerName: "Layer 1: Aho-Corasick Keywords & Sender Verification",
                score: layer1Indicators.reduce((sum, item) => sum + (item.scoreContribution || 0), 0),
                indicators: layer1Indicators
            },
            {
                layerNumber: 2,
                layerName: "Layer 2: Regex-Based Linguistic & Behavioral Analysis",
                score: layer2Indicators.reduce((sum, item) => sum + (item.scoreContribution || 0), 0),
                indicators: layer2Indicators
            },
            {
                layerNumber: 3,
                layerName: "Layer 3: Heuristic URL Analysis & Threat Intelligence",
                score: layer3Indicators.reduce((sum, item) => sum + (item.scoreContribution || 0), 0),
                indicators: layer3Indicators
            },
            {
                layerNumber: 4,
                layerName: "Layer 4: Attachment & Payload Analysis",
                score: layer4Indicators.reduce((sum, item) => sum + (item.scoreContribution || 0), 0),
                indicators: layer4Indicators
            }
        ]
    };

    // Switch tool view
    if (scan.scanType === 'URL') {
        switchMainTool('url-tool');
        const urlInput = document.getElementById('input-target-url');
        if (urlInput) urlInput.value = scan.inputTarget || '';
    } else {
        switchMainTool('email-tool');
        if (scan.sender) document.getElementById('input-sender').value = scan.sender;
        if (scan.subject) document.getElementById('input-subject').value = scan.subject;
    }

    renderScanResults(reconstructed);

    const resSec = document.getElementById('results-section');
    if (resSec) {
        resSec.classList.remove('hidden');
        resSec.scrollIntoView({ behavior: 'smooth' });
    }
}


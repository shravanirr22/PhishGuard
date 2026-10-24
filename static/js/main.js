/**
 * main.js — Shared utilities for all PhishGuard pages
 */

const API_BASE = window.location.origin;

// ---- Navbar scroll effect ----
(function initNavbar() {
  const navbar = document.getElementById('main-navbar');
  const toggle = document.getElementById('nav-toggle');
  const links = document.getElementById('nav-links');

  if (navbar) {
    window.addEventListener('scroll', () => {
      navbar.classList.toggle('scrolled', window.scrollY > 10);
    }, { passive: true });
  }

  if (toggle && links) {
    toggle.addEventListener('click', () => {
      links.classList.toggle('open');
    });
    // Close when clicking a link
    links.querySelectorAll('.nav-link, .btn').forEach(el => {
      el.addEventListener('click', () => links.classList.remove('open'));
    });
  }
})();

// ---- Active nav link ----
(function markActiveLink() {
  const path = window.location.pathname;
  document.querySelectorAll('.nav-link').forEach(link => {
    const href = link.getAttribute('href');
    if (href === path || (href !== '/' && path.startsWith(href))) {
      link.classList.add('active');
    }
  });
})();

// ---- API helpers ----
async function apiGet(endpoint) {
  const res = await fetch(API_BASE + endpoint);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function apiPost(endpoint, body) {
  const res = await fetch(API_BASE + endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) throw Object.assign(new Error(data.error || `HTTP ${res.status}`), { data, status: res.status });
  return data;
}

async function apiDelete(endpoint) {
  const res = await fetch(API_BASE + endpoint, { method: 'DELETE' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// ---- URL validation (client-side, light) ----
function validateUrlInput(url) {
  if (!url || url.trim().length === 0) return 'Please enter a URL.';
  if (url.length > 2048) return 'URL is too long (max 2048 characters).';
  return null;
}

// ---- Format confidence ----
function fmtConfidence(c) {
  return typeof c === 'number' ? c.toFixed(1) + '%' : '—';
}

// ---- Format date ----
function fmtDate(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch { return iso; }
}

// ---- Build result HTML ----
function buildResultHtml(data) {
  if (data.status === 'no_model') {
    return `
      <div class="result-card-nomodel">
        <div class="result-header">
          <div class="result-status-icon">⚙️</div>
          <div>
            <div class="result-label" style="color: var(--warning);">MODEL NOT TRAINED</div>
            <div class="result-url">${escHtml(data.display_url || '')}</div>
          </div>
        </div>
        <p style="color:var(--text-secondary);font-size:0.9rem;">${escHtml(data.message || '')}</p>
        <p class="result-disclaimer">
          Place a phishing CSV dataset in the <code>data/</code> folder and run:<br/>
          <code>python train_model.py --dataset data/phishing_dataset.csv --target Result</code>
        </p>
      </div>`;
  }

  const isPhish = data.is_phishing;
  const cls = isPhish ? 'phish' : 'legit';
  const icon = isPhish ? '🎣' : '✅';
  const label = isPhish ? 'PHISHING DETECTED' : 'CLASSIFIED AS LEGITIMATE';
  const confidence = data.confidence || 0;

  const explanationHtml = (data.explanations && data.explanations.length > 0)
    ? `<div class="result-section-title">${isPhish ? 'Suspicious Indicators' : 'Analysis Notes'}</div>
       <ul class="explanation-list">
         ${data.explanations.map(e => `<li>⚠️ ${escHtml(e)}</li>`).join('')}
       </ul>`
    : (isPhish ? '' : '<div class="result-section-title">No suspicious indicators detected in URL structure.</div>');

  // Key features to display
  const f = data.features || {};
  const keyFeatures = [
    { name: 'HTTPS', val: f.has_https ? 'Yes ✅' : 'No ❌' },
    { name: 'IP Address', val: f.is_ip_address ? 'Yes ⚠️' : 'No' },
    { name: 'URL Length', val: f.url_length ?? '—' },
    { name: 'Suspicious Words', val: f.suspicious_word_count ?? '—' },
    { name: 'Subdomains', val: f.subdomain_count ?? '—' },
    { name: 'Parameters', val: f.param_count ?? '—' },
    { name: 'Shortened', val: f.is_shortened ? 'Yes ⚠️' : 'No' },
    { name: 'Hyphens', val: f.hyphen_count ?? '—' },
    { name: 'Entropy', val: typeof f.url_entropy === 'number' ? f.url_entropy.toFixed(2) : '—' },
    { name: '@ Symbol', val: f.at_symbol ? 'Yes ⚠️' : 'No' },
  ];

  const featureHtml = `
    <div class="result-section-title">Extracted Features</div>
    <div class="features-grid-mini">
      ${keyFeatures.map(kf => `
        <div class="feat-mini">
          <div class="feat-mini-name">${escHtml(kf.name)}</div>
          <div class="feat-mini-val">${escHtml(String(kf.val))}</div>
        </div>`).join('')}
    </div>`;

  const recsHtml = isPhish ? `
    <div class="result-section-title">Recommendations</div>
    <ul class="explanation-list">
      <li>🚫 Do not visit this website or enter any credentials.</li>
      <li>🚫 Do not click any links received from this source.</li>
      <li>🛡️ If you received this via email, report it as phishing.</li>
      <li>🔑 If you already entered credentials, change your passwords immediately.</li>
    </ul>` : '';

  return `
    <div class="result-card-${cls}">
      <div class="result-header">
        <div class="result-status-icon">${icon}</div>
        <div>
          <div class="result-label">${label}</div>
          <div class="result-url">${escHtml(data.display_url || '')}</div>
        </div>
      </div>
      <div class="confidence-bar-wrap">
        <div class="confidence-label-row">
          <span>Model Confidence</span>
          <span id="conf-pct" style="font-weight:700;color:var(--${cls === 'phish' ? 'danger' : 'success'})">${confidence.toFixed(1)}%</span>
        </div>
        <div class="confidence-track">
          <div class="confidence-fill ${cls}-fill" id="conf-fill" style="width:0%"></div>
        </div>
      </div>
      ${explanationHtml}
      ${featureHtml}
      ${recsHtml}
      <div style="margin-top:1rem;font-size:0.78rem;color:var(--text-muted);">Model used: <strong>${escHtml(data.model_used || '—')}</strong></div>
      <div class="result-disclaimer">⚠️ ${escHtml(data.disclaimer || 'ML prediction — not a guarantee of website safety.')}</div>
    </div>`;
}

function animateConfidenceFill(confidence) {
  setTimeout(() => {
    const fill = document.getElementById('conf-fill');
    if (fill) fill.style.width = confidence + '%';
  }, 100);
}

function escHtml(str) {
  if (typeof str !== 'string') str = String(str);
  return str.replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
}

// ---- Home page logic ----
(function initHomePage() {
  const homeInput = document.getElementById('home-url-input');
  const homeBtn = document.getElementById('home-scan-btn');
  const homeResult = document.getElementById('home-result');
  const homeLoading = document.getElementById('home-loading');

  if (!homeInput) return;

  window.fillExample = function(url) {
    homeInput.value = url;
    homeInput.focus();
  };

  async function runHomeScan() {
    const url = homeInput.value.trim();
    const err = validateUrlInput(url);
    if (err) { alert(err); return; }

    homeResult.style.display = 'none';
    homeLoading.style.display = 'flex';
    homeBtn.disabled = true;

    try {
      const data = await apiPost('/api/predict', { url });
      homeResult.innerHTML = buildResultHtml(data);
      homeResult.style.display = 'block';
      animateConfidenceFill(data.confidence || 0);
    } catch (e) {
      homeResult.innerHTML = `<div class="result-card-nomodel"><p style="color:var(--danger);">Error: ${escHtml(e.message)}</p></div>`;
      homeResult.style.display = 'block';
    } finally {
      homeLoading.style.display = 'none';
      homeBtn.disabled = false;
    }
  }

  homeBtn.addEventListener('click', runHomeScan);
  homeInput.addEventListener('keydown', e => { if (e.key === 'Enter') runHomeScan(); });

  // Fetch model status & hero stats
  fetchHomeStats();
})();

async function fetchHomeStats() {
  // Model status
  const statusIcon = document.getElementById('status-icon');
  const statusTitle = document.getElementById('status-title');
  const statusDesc = document.getElementById('status-desc');
  const statusBtn = document.getElementById('status-btn');

  try {
    const health = await apiGet('/api/health');
    if (health.model_ready) {
      if (statusIcon) statusIcon.textContent = '✅';
      if (statusTitle) statusTitle.textContent = 'Model Ready';
      if (statusDesc) statusDesc.textContent = `${health.model_name} — Trained on ${fmtDate(health.trained_on)}`;
      if (statusBtn) statusBtn.style.display = 'inline-flex';
    } else {
      if (statusIcon) statusIcon.textContent = '⚙️';
      if (statusTitle) statusTitle.textContent = 'Model Not Trained';
      if (statusDesc) statusDesc.textContent = 'Place a dataset in data/ and run python train_model.py';
    }
  } catch (e) {
    if (statusIcon) statusIcon.textContent = '❌';
    if (statusTitle) statusTitle.textContent = 'Backend Unreachable';
    if (statusDesc) statusDesc.textContent = 'Make sure the Flask server is running on port 5000.';
  }

  // Metrics
  try {
    const metrics = await apiGet('/api/metrics');
    if (metrics.status === 'ok') {
      const bm = metrics.best_metrics || {};
      setStatVal('stat-accuracy', bm.accuracy ? (bm.accuracy * 100).toFixed(1) + '%' : '—');
      setStatVal('stat-f1', bm.f1_score ? (bm.f1_score * 100).toFixed(1) + '%' : '—');
      setStatVal('stat-samples', metrics.n_samples ? metrics.n_samples.toLocaleString() : '—');
    }
  } catch {}

  // Scan count from history
  try {
    const hist = await apiGet('/api/history?limit=1');
    // We get the actual count from the full history
    const fullHist = await apiGet('/api/history?limit=500');
    setStatVal('stat-scans', fullHist.count?.toLocaleString() || '0');
  } catch {}
}

function setStatVal(id, val) {
  const el = document.getElementById(id);
  if (el) {
    el.style.opacity = '0';
    el.textContent = val;
    el.style.transition = 'opacity 0.5s ease';
    setTimeout(() => { el.style.opacity = '1'; }, 50);
  }
}

/**
 * history.js — Scan History page
 */

(function initHistory() {
  const tbody = document.getElementById('history-tbody');
  const loadingEl = document.getElementById('history-loading');
  const emptyEl = document.getElementById('history-empty');
  const tableContainer = document.getElementById('table-container');
  const searchInput = document.getElementById('history-search');
  const refreshBtn = document.getElementById('refresh-btn');
  const clearBtn = document.getElementById('clear-btn');
  const totalEl = document.getElementById('total-scans');
  const phishEl = document.getElementById('phish-count');
  const legitEl = document.getElementById('legit-count');
  const modalOverlay = document.getElementById('confirm-modal');
  const modalCancel = document.getElementById('modal-cancel');
  const modalConfirm = document.getElementById('modal-confirm');
  const modalCount = document.getElementById('modal-count');

  let allRows = [];

  async function loadHistory() {
    loadingEl.style.display = 'flex';
    emptyEl.style.display = 'none';
    tableContainer.style.display = 'none';

    try {
      const data = await apiGet('/api/history?limit=500');
      allRows = data.history || [];
      renderTable(allRows);
      updateStats(allRows);
    } catch (e) {
      loadingEl.style.display = 'none';
      emptyEl.style.display = 'block';
      emptyEl.querySelector('h3').textContent = 'Failed to load history';
      emptyEl.querySelector('p').textContent = 'Make sure the Flask backend is running.';
    }
  }

  function updateStats(rows) {
    const phish = rows.filter(r => r.is_phishing).length;
    const legit = rows.length - phish;
    if (totalEl) totalEl.textContent = rows.length.toLocaleString();
    if (phishEl) phishEl.textContent = phish.toLocaleString();
    if (legitEl) legitEl.textContent = legit.toLocaleString();
  }

  function renderTable(rows) {
    loadingEl.style.display = 'none';

    if (!rows || rows.length === 0) {
      emptyEl.style.display = 'block';
      tableContainer.style.display = 'none';
      return;
    }

    emptyEl.style.display = 'none';
    tableContainer.style.display = 'block';

    tbody.innerHTML = rows.map((r, i) => {
      const badge = r.is_phishing
        ? '<span class="badge badge-phish">🎣 Phishing</span>'
        : '<span class="badge badge-legit">✅ Legitimate</span>';
      const conf = typeof r.confidence === 'number' ? (r.confidence * 100).toFixed(1) + '%' : fmtConfidence(r.confidence);
      return `
        <tr>
          <td style="color:var(--text-muted);font-family:var(--font-mono);font-size:0.75rem;">${r.id || (i + 1)}</td>
          <td title="${escHtml(r.display_url || '')}">${escHtml(r.display_url || '')}</td>
          <td>${badge}</td>
          <td style="font-family:var(--font-mono);font-size:0.83rem;color:${r.is_phishing ? 'var(--danger)' : 'var(--success)'};">${conf}</td>
          <td style="font-size:0.78rem;">${fmtDate(r.scanned_at)}</td>
        </tr>`;
    }).join('');
  }

  function filterRows(query) {
    if (!query.trim()) return allRows;
    const q = query.toLowerCase();
    return allRows.filter(r => (r.display_url || '').toLowerCase().includes(q));
  }

  // Search
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      const filtered = filterRows(searchInput.value);
      renderTable(filtered);
      updateStats(filtered);
    });
  }

  // Refresh
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
      if (searchInput) searchInput.value = '';
      loadHistory();
    });
  }

  // Clear with confirmation
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      if (modalCount) modalCount.textContent = allRows.length;
      modalOverlay.style.display = 'flex';
    });
  }
  if (modalCancel) {
    modalCancel.addEventListener('click', () => { modalOverlay.style.display = 'none'; });
  }
  modalOverlay && modalOverlay.addEventListener('click', e => {
    if (e.target === modalOverlay) modalOverlay.style.display = 'none';
  });
  if (modalConfirm) {
    modalConfirm.addEventListener('click', async () => {
      modalOverlay.style.display = 'none';
      try {
        await apiDelete('/api/history');
        allRows = [];
        renderTable([]);
        updateStats([]);
      } catch (e) {
        alert('Failed to clear history: ' + e.message);
      }
    });
  }

  loadHistory();
})();

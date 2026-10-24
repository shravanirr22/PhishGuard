/**
 * scanner.js — URL Scanner page logic
 */

(function initScanner() {
  const urlInput = document.getElementById('scanner-url-input');
  const scanBtn = document.getElementById('scanner-btn');
  const btnIcon = document.getElementById('btn-icon');
  const btnText = document.getElementById('btn-text');
  const urlError = document.getElementById('url-error');
  const loadingCard = document.getElementById('loading-card');
  const placeholderCard = document.getElementById('placeholder-card');
  const resultCard = document.getElementById('result-card');

  if (!urlInput) return;

  window.setUrl = function(url) {
    urlInput.value = url;
    urlInput.focus();
    clearError();
  };

  function showError(msg) {
    urlError.textContent = msg;
    urlError.style.display = 'block';
  }
  function clearError() {
    urlError.style.display = 'none';
    urlError.textContent = '';
  }

  function setLoading(loading) {
    if (loading) {
      placeholderCard.style.display = 'none';
      resultCard.style.display = 'none';
      loadingCard.style.display = 'block';
      scanBtn.disabled = true;
      btnIcon.textContent = '⏳';
      btnText.textContent = 'Analyzing…';
    } else {
      loadingCard.style.display = 'none';
      scanBtn.disabled = false;
      btnIcon.textContent = '🔍';
      btnText.textContent = 'Analyze Website';
    }
  }

  async function runScan() {
    const url = urlInput.value.trim();
    clearError();

    const err = validateUrlInput(url);
    if (err) {
      showError(err);
      urlInput.focus();
      return;
    }

    setLoading(true);

    try {
      const data = await apiPost('/api/predict', { url });
      resultCard.innerHTML = buildResultHtml(data);
      resultCard.style.display = 'block';
      animateConfidenceFill(data.confidence || 0);

      // Scroll result into view on mobile
      if (window.innerWidth < 1024) {
        setTimeout(() => resultCard.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
      }
    } catch (e) {
      const errMsg = (e.data && e.data.error) ? e.data.error : e.message;
      resultCard.innerHTML = `
        <div class="result-card-nomodel">
          <div class="result-header">
            <div class="result-status-icon">❌</div>
            <div>
              <div class="result-label" style="color:var(--danger);">ANALYSIS FAILED</div>
            </div>
          </div>
          <p style="color:var(--text-secondary);font-size:0.9rem;">
            ${escHtml(errMsg || 'An unexpected error occurred.')}
          </p>
          <p class="result-disclaimer">
            Make sure the Flask backend is running:<br/>
            <code>python app.py</code>
          </p>
        </div>`;
      resultCard.style.display = 'block';
    } finally {
      setLoading(false);
    }
  }

  scanBtn.addEventListener('click', runScan);
  urlInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') runScan();
  });

  // Clear error on typing
  urlInput.addEventListener('input', clearError);

  // Pre-fill from URL query param (?url=...)
  const params = new URLSearchParams(window.location.search);
  const preUrl = params.get('url');
  if (preUrl) {
    urlInput.value = preUrl;
    setTimeout(runScan, 500);
  }
})();

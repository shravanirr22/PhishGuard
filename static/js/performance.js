/**
 * performance.js — Model Performance page with Chart.js
 */

(function initPerformance() {
  const noModelBanner = document.getElementById('no-model-banner');
  const metricsContent = document.getElementById('metrics-content');

  async function loadMetrics() {
    let data;
    try {
      data = await apiGet('/api/metrics');
    } catch (e) {
      showNoModel('Cannot connect to backend. Is the Flask server running?');
      return;
    }

    if (data.status === 'no_model') {
      showNoModel(data.message);
      return;
    }

    noModelBanner.style.display = 'none';
    metricsContent.style.display = 'block';

    fillInfoBar(data);
    fillMetricCards(data.best_metrics || {});
    renderModelComparisonChart(data.all_model_results || []);
    renderConfusionMatrix(data.best_metrics || {});
    renderRadarChart(data.all_model_results || []);
    renderFeatureTags(data.feature_names || []);
  }

  function showNoModel(msg) {
    noModelBanner.style.display = 'block';
    metricsContent.style.display = 'none';
    const msgEl = noModelBanner.querySelector('p');
    if (msgEl && msg) {
      msgEl.textContent = msg;
    }
  }

  function fillInfoBar(data) {
    setText('info-model', data.selected_model || '—');
    setText('info-dataset', data.dataset_name || '—');
    setText('info-train', data.n_train ? data.n_train.toLocaleString() : '—');
    setText('info-test', data.n_test ? data.n_test.toLocaleString() : '—');
    setText('info-date', fmtDate(data.training_date));
  }

  function fillMetricCards(bm) {
    const metrics = [
      { id: 'accuracy', key: 'accuracy' },
      { id: 'precision', key: 'precision' },
      { id: 'recall', key: 'recall' },
      { id: 'f1', key: 'f1_score' },
      { id: 'roc', key: 'roc_auc' },
    ];
    metrics.forEach(({ id, key }) => {
      const val = bm[key];
      const el = document.getElementById('m-' + id);
      const bar = document.getElementById('mb-' + id);
      if (el) {
        el.textContent = val != null ? (val * 100).toFixed(1) + '%' : 'N/A';
      }
      if (bar && val != null) {
        setTimeout(() => { bar.style.width = (val * 100) + '%'; }, 300);
      }
    });
  }

  function renderModelComparisonChart(results) {
    const ctx = document.getElementById('model-comparison-chart');
    if (!ctx || !results.length) return;

    const labels = results.map(r => r.model_name);
    const colors = {
      accuracy: '#4e9af1',
      precision: '#63e6be',
      recall: '#f8a84b',
      f1_score: '#ff6b6b',
    };

    const datasets = Object.entries(colors).map(([key, color]) => ({
      label: key.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase()),
      data: results.map(r => parseFloat((r[key] * 100).toFixed(2))),
      backgroundColor: color + 'cc',
      borderColor: color,
      borderWidth: 1.5,
      borderRadius: 4,
    }));

    new Chart(ctx, {
      type: 'bar',
      data: { labels, datasets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            labels: { color: '#8fa8c8', font: { family: 'Inter', size: 11 } }
          },
          tooltip: {
            callbacks: {
              label: ctx => `${ctx.dataset.label}: ${ctx.parsed.y.toFixed(1)}%`
            }
          }
        },
        scales: {
          x: { ticks: { color: '#8fa8c8' }, grid: { color: 'rgba(255,255,255,0.05)' } },
          y: {
            min: 0, max: 100,
            ticks: { color: '#8fa8c8', callback: v => v + '%' },
            grid: { color: 'rgba(255,255,255,0.05)' }
          }
        }
      }
    });
  }

  function renderConfusionMatrix(bm) {
    const ctx = document.getElementById('confusion-matrix-chart');
    if (!ctx) return;

    const cm = bm.confusion_matrix;
    if (!cm || cm.length < 2) {
      ctx.parentElement.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:2rem;">No confusion matrix data available.</p>';
      return;
    }

    const tn = cm[0][0], fp = cm[0][1];
    const fn = cm[1][0], tp = cm[1][1];
    const maxVal = Math.max(tn, fp, fn, tp, 1);

    new Chart(ctx, {
      type: 'bar',
      data: {
        labels: ['Legitimate (Actual)', 'Phishing (Actual)'],
        datasets: [
          {
            label: 'Pred: Legitimate',
            data: [tn, fn],
            backgroundColor: ['rgba(46,204,113,0.6)', 'rgba(255,107,107,0.5)'],
            borderColor: ['#2ecc71', '#ff6b6b'],
            borderWidth: 1.5,
            borderRadius: 4,
          },
          {
            label: 'Pred: Phishing',
            data: [fp, tp],
            backgroundColor: ['rgba(255,107,107,0.5)', 'rgba(46,204,113,0.6)'],
            borderColor: ['#ff6b6b', '#2ecc71'],
            borderWidth: 1.5,
            borderRadius: 4,
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { labels: { color: '#8fa8c8', font: { family: 'Inter', size: 11 } } },
          tooltip: {
            callbacks: {
              label: ctx => `${ctx.dataset.label}: ${ctx.parsed.y.toLocaleString()}`,
            }
          }
        },
        scales: {
          x: { ticks: { color: '#8fa8c8' }, grid: { color: 'rgba(255,255,255,0.05)' } },
          y: { ticks: { color: '#8fa8c8' }, grid: { color: 'rgba(255,255,255,0.05)' } }
        }
      }
    });

    // Legend below chart
    const legend = document.getElementById('cm-legend');
    if (legend) {
      legend.innerHTML = `
        <div class="cm-legend-item"><span style="color:#2ecc71;font-weight:700;">TN=${tn.toLocaleString()}</span> True Negative</div>
        <div class="cm-legend-item"><span style="color:#ff6b6b;font-weight:700;">FP=${fp.toLocaleString()}</span> False Positive</div>
        <div class="cm-legend-item"><span style="color:#ff6b6b;font-weight:700;">FN=${fn.toLocaleString()}</span> False Negative</div>
        <div class="cm-legend-item"><span style="color:#2ecc71;font-weight:700;">TP=${tp.toLocaleString()}</span> True Positive</div>`;
    }
  }

  function renderRadarChart(results) {
    const ctx = document.getElementById('radar-chart');
    if (!ctx || !results.length) return;

    const metrics = ['accuracy', 'precision', 'recall', 'f1_score'];
    const metricLabels = ['Accuracy', 'Precision', 'Recall', 'F1 Score'];
    const colors = ['rgba(78,154,241,0.6)', 'rgba(99,230,190,0.6)', 'rgba(248,168,75,0.6)'];
    const borderColors = ['#4e9af1', '#63e6be', '#f8a84b'];

    const datasets = results.map((r, i) => ({
      label: r.model_name,
      data: metrics.map(m => parseFloat((r[m] * 100).toFixed(2))),
      fill: true,
      backgroundColor: colors[i % colors.length],
      borderColor: borderColors[i % borderColors.length],
      borderWidth: 2,
      pointRadius: 4,
    }));

    new Chart(ctx, {
      type: 'radar',
      data: { labels: metricLabels, datasets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { labels: { color: '#8fa8c8', font: { family: 'Inter', size: 11 } } }
        },
        scales: {
          r: {
            min: 0, max: 100,
            ticks: { color: '#4a6080', font: { size: 10 }, stepSize: 20,
                     callback: v => v + '%', backdropColor: 'transparent' },
            pointLabels: { color: '#8fa8c8', font: { family: 'Inter', size: 11 } },
            grid: { color: 'rgba(255,255,255,0.07)' },
            angleLines: { color: 'rgba(255,255,255,0.07)' }
          }
        }
      }
    });
  }

  function renderFeatureTags(featureNames) {
    const container = document.getElementById('feature-tags');
    if (!container || !featureNames.length) return;
    container.innerHTML = featureNames.map(f =>
      `<span class="feature-tag">${escHtml(f)}</span>`
    ).join('');
  }

  function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  }

  loadMetrics();
})();

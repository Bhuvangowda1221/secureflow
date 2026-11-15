/**
 * SecureFlow – dashboard.js
 * Chart.js dashboard visualizations
 */

function initDashboardCharts(data) {
  Chart.defaults.color = '#8b949e';
  Chart.defaults.borderColor = '#30363d';
  Chart.defaults.font.family = "'Inter', sans-serif";

  // ── Severity Distribution Doughnut ──────────────────────────────────────
  const sevCtx = document.getElementById('severityChart');
  if (sevCtx) {
    const { critical, high, medium, low } = data.severity;
    const total = critical + high + medium + low;
    new Chart(sevCtx, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
          data: [critical, high, medium, low],
          backgroundColor: ['#f85149', '#f0883e', '#d29922', '#58a6ff'],
          borderColor: '#161b22',
          borderWidth: 3,
          hoverOffset: 8,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        cutout: '65%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: { padding: 12, font: { size: 11 }, boxWidth: 12 },
          },
          tooltip: {
            callbacks: {
              label: (ctx) => {
                const pct = total > 0 ? Math.round((ctx.parsed / total) * 100) : 0;
                return ` ${ctx.label}: ${ctx.parsed} (${pct}%)`;
              },
            },
          },
        },
      },
    });
  }

  // ── Pipeline Bar Chart ──────────────────────────────────────────────────
  const pipCtx = document.getElementById('pipelineChart');
  if (pipCtx) {
    const { passed, failed } = data.pipeline;
    new Chart(pipCtx, {
      type: 'bar',
      data: {
        labels: ['Passed', 'Failed'],
        datasets: [{
          data: [passed, failed],
          backgroundColor: ['rgba(63,185,80,.5)', 'rgba(248,81,73,.5)'],
          borderColor: ['#3fb950', '#f85149'],
          borderWidth: 2,
          borderRadius: 6,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false } },
          y: {
            beginAtZero: true,
            ticks: { stepSize: 1, precision: 0 },
          },
        },
      },
    });
  }
}

// ── Load historical chart data from API ────────────────────────────────────
function loadChartData() {
  fetch('/api/dashboard/charts', { credentials: 'same-origin' })
    .then(r => r.json())
    .then(resp => {
      if (!resp.success) return;
      const d = resp.data;

      // ── Scan History Line Chart ────────────────────────────────────────
      const histCtx = document.getElementById('scanHistoryChart');
      if (histCtx && d.scan_history && d.scan_history.labels.length > 0) {
        new Chart(histCtx, {
          type: 'line',
          data: {
            labels: d.scan_history.labels,
            datasets: [
              {
                label: 'Scans',
                data: d.scan_history.counts,
                borderColor: '#58a6ff',
                backgroundColor: 'rgba(88,166,255,.1)',
                fill: true,
                tension: 0.4,
                pointBackgroundColor: '#58a6ff',
                pointRadius: 4,
              },
              {
                label: 'Avg Score',
                data: d.scores_over_time.scores,
                borderColor: '#3fb950',
                backgroundColor: 'transparent',
                borderDash: [4, 4],
                tension: 0.4,
                pointRadius: 3,
                yAxisID: 'y2',
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            plugins: {
              legend: {
                position: 'top',
                labels: { font: { size: 11 }, boxWidth: 12, padding: 10 },
              },
            },
            scales: {
              x: { grid: { color: 'rgba(48,54,61,.5)' }, ticks: { font: { size: 10 } } },
              y: {
                position: 'left',
                beginAtZero: true,
                ticks: { stepSize: 1, precision: 0, font: { size: 10 } },
              },
              y2: {
                position: 'right',
                beginAtZero: false,
                min: 0, max: 100,
                ticks: { font: { size: 10 } },
                grid: { drawOnChartArea: false },
              },
            },
          },
        });
      } else if (histCtx) {
        // No data yet — show placeholder
        new Chart(histCtx, {
          type: 'line',
          data: {
            labels: ['—'],
            datasets: [{ label: 'No scan data yet', data: [0], borderColor: '#30363d' }],
          },
          options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
          },
        });
      }
    })
    .catch(() => {});
}

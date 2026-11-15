/**
 * SecureFlow – main.js
 * Global utilities: sidebar toggle, notifications, CSRF, clickable rows
 */

// ── CSRF helpers ──────────────────────────────────────────────────────────────
function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  if (meta) return meta.content;
  const input = document.querySelector('input[name="csrf_token"]');
  return input ? input.value : '';
}

function apiFetch(url, options = {}) {
  const defaults = {
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': getCsrfToken(),
    },
    credentials: 'same-origin',
  };
  return fetch(url, { ...defaults, ...options });
}

// ── Sidebar toggle ────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const toggle = document.getElementById('sidebarToggle');
  const sidebar = document.getElementById('sidebar');
  const wrapper = document.getElementById('mainWrapper');

  if (toggle && sidebar) {
    toggle.addEventListener('click', () => {
      sidebar.classList.toggle('open');
    });
    // Close sidebar when clicking outside on mobile
    document.addEventListener('click', (e) => {
      if (window.innerWidth <= 768 &&
          !sidebar.contains(e.target) &&
          !toggle.contains(e.target)) {
        sidebar.classList.remove('open');
      }
    });
  }

  // ── Clickable table rows ─────────────────────────────────────────────────
  document.querySelectorAll('.sf-clickable-row[data-href]').forEach(row => {
    row.addEventListener('click', () => {
      window.location.href = row.dataset.href;
    });
  });

  // ── Auto-dismiss alerts ──────────────────────────────────────────────────
  document.querySelectorAll('.sf-alert').forEach(alert => {
    setTimeout(() => {
      const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
      if (bsAlert) bsAlert.close();
    }, 5000);
  });

  // ── Notifications ────────────────────────────────────────────────────────
  loadNotifications();

  // ── GitHub URL validator (repo add page) ─────────────────────────────────
  const urlInput = document.getElementById('url');
  if (urlInput) {
    urlInput.addEventListener('input', () => validateGithubUrl(urlInput));
  }
});

// ── Notifications ─────────────────────────────────────────────────────────────
function loadNotifications() {
  const badge = document.getElementById('notifBadge');
  const list  = document.getElementById('notifList');
  if (!badge || !list) return;

  apiFetch('/api/notifications')
    .then(r => r.json())
    .then(data => {
      if (!data.success) return;
      const { notifications, unread_count } = data.data;

      if (unread_count > 0) {
        badge.textContent = unread_count > 9 ? '9+' : unread_count;
        badge.classList.remove('d-none');
      }

      if (notifications.length === 0) return;

      list.innerHTML = '';
      notifications.slice(0, 8).forEach(n => {
        const item = document.createElement('div');
        item.className = `sf-notif-item${!n.is_read ? ' unread' : ''}`;
        item.innerHTML = `
          <div class="fw-semibold small">${escHtml(n.title)}</div>
          <div class="text-muted" style="font-size:11px">${escHtml(n.message)}</div>
        `;
        item.addEventListener('click', () => markRead(n.id, item));
        list.appendChild(item);
      });
    })
    .catch(() => {});
}

function markRead(id, element) {
  apiFetch(`/api/notifications/${id}/read`, { method: 'POST' })
    .then(() => {
      if (element) element.classList.remove('unread');
    }).catch(() => {});
}

function markAllRead() {
  document.querySelectorAll('.sf-notif-item.unread').forEach(el => {
    el.classList.remove('unread');
  });
  document.getElementById('notifBadge')?.classList.add('d-none');
}

// ── Password toggle ───────────────────────────────────────────────────────────
function togglePassword(inputId) {
  const input = document.getElementById(inputId);
  const eye   = document.getElementById('pwd-eye');
  if (!input) return;
  if (input.type === 'password') {
    input.type = 'text';
    if (eye) { eye.classList.remove('fa-eye'); eye.classList.add('fa-eye-slash'); }
  } else {
    input.type = 'password';
    if (eye) { eye.classList.remove('fa-eye-slash'); eye.classList.add('fa-eye'); }
  }
}

// ── Password strength indicator ───────────────────────────────────────────────
function checkPasswordStrength(password) {
  const bar  = document.getElementById('strengthBar');
  const text = document.getElementById('strengthText');
  if (!bar) return;

  let score = 0;
  if (password.length >= 8)  score++;
  if (password.length >= 12) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  const levels = [
    { pct: '20%', color: '#f85149', label: 'Very Weak' },
    { pct: '40%', color: '#f0883e', label: 'Weak' },
    { pct: '60%', color: '#d29922', label: 'Fair' },
    { pct: '80%', color: '#3fb950', label: 'Strong' },
    { pct: '100%', color: '#58a6ff', label: 'Very Strong' },
  ];
  const lvl = levels[Math.min(score - 1, 4)] || levels[0];
  bar.style.width  = password.length ? lvl.pct : '0';
  bar.style.background = lvl.color;
  if (text) text.textContent = password.length ? lvl.label : '';
}

// ── GitHub URL validation ────────────────────────────────────────────────────
function validateGithubUrl(input) {
  const fb = document.getElementById('urlFeedback');
  if (!fb) return;
  const val = input.value.trim();
  const pattern = /^https?:\/\/github\.com\/[\w\-\.]+\/[\w\-\.]+(?:\.git)?\/?$/;
  if (!val) { fb.innerHTML = ''; return; }
  if (pattern.test(val)) {
    fb.innerHTML = '<span class="text-success"><i class="fa-solid fa-check me-1"></i>Valid GitHub URL</span>';
    input.classList.remove('is-invalid');
    input.classList.add('is-valid');
  } else {
    fb.innerHTML = '<span class="text-danger"><i class="fa-solid fa-xmark me-1"></i>Must be a GitHub URL like https://github.com/owner/repo</span>';
    input.classList.remove('is-valid');
    input.classList.add('is-invalid');
  }
}

// ── Scan confirmation ────────────────────────────────────────────────────────
function confirmScan(repoName) {
  return confirm(`Start a security scan for "${repoName}"?\n\nThis will run Bandit, pip-audit, Gitleaks, and Trivy scans.`);
}

// ── Utilities ────────────────────────────────────────────────────────────────
function escHtml(str) {
  const div = document.createElement('div');
  div.appendChild(document.createTextNode(str));
  return div.innerHTML;
}

function showSpinner() { document.getElementById('globalSpinner')?.classList.remove('d-none'); }
function hideSpinner() { document.getElementById('globalSpinner')?.classList.add('d-none'); }

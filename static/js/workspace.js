// Workspace page core: CSRF helpers, view switching from the sidebar, toasts.
// Per-view code lives in enrich.js, graph.js, graph-dialogs.js and intel-browser.js.

function getCSRFToken() {
    return document.querySelector('meta[name="csrf-token"]').content;
}

// CSRF-aware fetch wrapper for API calls
async function csrfFetch(url, options = {}) {
    options.headers = options.headers || {};
    options.headers['X-CSRFToken'] = getCSRFToken();
    return fetch(url, options);
}

// htmx requests carry the CSRF token too
document.addEventListener('DOMContentLoaded', function () {
    document.body.addEventListener('htmx:configRequest', function (event) {
        event.detail.headers['X-CSRFToken'] = getCSRFToken();
    });

    // Graph menu items for ViewDNS and Chaos appear only when an admin has stored a key
    csrfFetch('/api/viewdns/settings').then(r => r.json())
        .then(data => { window.viewdnsApiConfigured = data.api_key_configured; })
        .catch(() => { window.viewdnsApiConfigured = false; });
    csrfFetch('/api/chaos/settings').then(r => r.json())
        .then(data => { window.chaosApiConfigured = data.api_key_configured; })
        .catch(() => { window.chaosApiConfigured = false; });
});

// ---- views ----
// Each view is a .tab-panel with id "<name>-panel"; the URL hash names the open view.
const WORKSPACE_VIEWS = ['adhoc', 'upload', 'runs', 'graph', 'graph-stats', 'intel-browser'];
// Which sidebar item is highlighted for each view
const VIEW_NAV = { 'adhoc': 'enrich', 'upload': 'enrich', 'runs': 'enrich', 'graph': 'graph', 'graph-stats': 'graph', 'intel-browser': 'intel' };

function switchTab(tabName, updateUrl = true) {
    if (!WORKSPACE_VIEWS.includes(tabName)) return;

    document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.remove('active'));
    document.getElementById(`${tabName}-panel`).classList.add('active');

    // In-page view switches (segmented controls) mark themselves with data-tab
    document.querySelectorAll('[data-tab]').forEach(el => {
        const on = el.dataset.tab === tabName;
        el.classList.toggle('on', on);
        el.classList.toggle('active', on);
    });
    document.querySelectorAll('.nav a[data-nav]').forEach(link => {
        const on = link.dataset.nav === VIEW_NAV[tabName];
        link.classList.toggle('on', on);
        if (on) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
    });

    // Results belong to the Enrich views
    const resultsContainer = document.getElementById('results-container');
    if (resultsContainer) {
        resultsContainer.style.display = ['adhoc', 'upload', 'runs'].includes(tabName) ? '' : 'none';
    }

    if (tabName === 'graph-stats' && window.refreshGraphStats) window.refreshGraphStats();
    if (tabName === 'intel-browser' && window.intelInit) window.intelInit();  // lazy first load
    if (tabName === 'runs' && window.runsRefresh) window.runsRefresh();

    if (updateUrl) window.history.replaceState({}, '', `#${tabName}`);
    const main = document.querySelector('.main');
    if (main) main.scrollTop = 0;
}

function handleHashChange() {
    const hash = window.location.hash.slice(1);
    switchTab(WORKSPACE_VIEWS.includes(hash) ? hash : 'adhoc', false);
}

window.addEventListener('hashchange', handleHashChange);
document.addEventListener('DOMContentLoaded', handleHashChange);

// ---- toasts ----
// showToast(message, type, duration): type is info | success | warning | error.
function showToast(message, type = 'info', duration = 4000) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const text = document.createElement('span');
    text.textContent = message;
    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'x';
    close.setAttribute('aria-label', 'Dismiss');
    close.textContent = '×';
    const dismiss = () => toast.remove();
    close.addEventListener('click', dismiss);
    toast.append(text, close);
    container.appendChild(toast);
    if (duration > 0) setTimeout(dismiss, duration);
    return toast;
}
window.showToast = showToast;

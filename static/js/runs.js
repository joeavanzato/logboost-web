// Workspace: Past runs. Lists the signed-in user's stored enrichments and reopens them.
(function () {
    'use strict';

    const SOURCE_LABELS = { dns: 'DNS', whois: 'WHOIS', idb: 'InternetDB', useti: 'Threat intel' };
    let stale = true;  // reload the list the next time the view opens

    function ago(iso) {
        const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
        if (seconds < 60) return 'just now';
        if (seconds < 3600) return Math.floor(seconds / 60) + ' min ago';
        if (seconds < 86400) { const h = Math.floor(seconds / 3600); return h + (h === 1 ? ' hour ago' : ' hours ago'); }
        const d = Math.floor(seconds / 86400);
        return d + (d === 1 ? ' day ago' : ' days ago');
    }

    function cell(text, className) {
        const td = document.createElement('td');
        if (className) td.className = className;
        td.textContent = text;
        return td;
    }

    function button(label, action, extraClass) {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'btn sm' + (extraClass ? ' ' + extraClass : '');
        b.dataset.runAction = action;
        b.textContent = label;
        return b;
    }

    function setStatus(message) {
        const el = document.getElementById('runs-status');
        if (el) el.textContent = message || '';
    }

    function render(runs) {
        const table = document.getElementById('runs-table');
        const body = document.getElementById('runs-rows');
        const empty = document.getElementById('runs-empty');
        body.replaceChildren();
        runs.forEach(run => {
            const tr = document.createElement('tr');
            tr.dataset.runId = run.id;

            const input = document.createElement('td');
            const name = document.createElement('b');
            name.textContent = run.label || (run.kind === 'text' ? 'Pasted text' : 'File');
            const kind = document.createElement('small');
            kind.textContent = run.kind === 'text' ? 'pasted text' : 'uploaded file';
            input.append(name, kind);

            const sources = document.createElement('td');
            if (run.sources.length) {
                run.sources.forEach(key => {
                    const tag = document.createElement('span');
                    tag.className = 'tag';
                    tag.textContent = SOURCE_LABELS[key] || key;
                    sources.append(tag, ' ');
                });
            } else {
                sources.className = 'faint';
                sources.textContent = '—';
            }

            const when = cell(ago(run.created_at), 'muted');
            when.title = new Date(run.created_at).toLocaleString();

            const actions = document.createElement('td');
            actions.className = 'right';
            const group = document.createElement('span');
            group.className = 'row';
            group.style.justifyContent = 'flex-end';
            group.append(button('Open', 'open'));
            if (run.can_edit) group.append(button('Edit input', 'edit'));
            group.append(button('Delete', 'delete', 'danger'));
            actions.append(group);

            tr.append(input,
                cell(run.ip_count == null ? '—' : Number(run.ip_count).toLocaleString(), 'num'),
                cell(run.row_count == null ? '—' : Number(run.row_count).toLocaleString(), 'num'),
                sources, when, actions);
            body.append(tr);
        });
        table.classList.toggle('hide', runs.length === 0);
        empty.classList.toggle('hide', runs.length > 0);
    }

    async function refresh(force) {
        if (!stale && !force) return;
        try {
            const response = await csrfFetch('/runs');
            if (!response.ok) throw new Error('HTTP ' + response.status);
            render((await response.json()).runs || []);
            stale = false;
            setStatus('');
        } catch (error) {
            setStatus('Could not load past runs. Reload the page to try again.');
        }
    }

    function openRun(id) {
        // The server renders the same results fragment as a fresh enrichment.
        htmx.ajax('GET', '/runs/' + encodeURIComponent(id), { target: '#results-container', swap: 'innerHTML' });
    }

    async function editInput(id) {
        const response = await csrfFetch('/runs/' + encodeURIComponent(id) + '/input');
        if (!response.ok) { showToast('The input of that run is no longer stored.', 'warning'); return; }
        const data = await response.json();
        const form = document.querySelector('#adhoc-panel form');
        const textarea = form.querySelector('textarea[name="text"]');
        textarea.value = data.text;
        textarea.dispatchEvent(new Event('input', { bubbles: true }));
        Object.keys(SOURCE_LABELS).forEach(key => {
            const box = form.querySelector('input[type="checkbox"][name="' + key + '"]');
            if (box && !box.disabled) box.checked = Boolean(data.options[key]);
        });
        window.location.hash = '#adhoc';
        textarea.focus();
    }

    async function deleteRun(id, row) {
        if (!window.confirm('Delete this run and its stored results? This cannot be undone.')) return;
        const response = await csrfFetch('/runs/' + encodeURIComponent(id) + '/delete', { method: 'POST' });
        if (!response.ok) { showToast('Could not delete that run.', 'error'); return; }
        row.remove();
        const left = document.querySelectorAll('#runs-rows tr').length;
        document.getElementById('runs-table').classList.toggle('hide', left === 0);
        document.getElementById('runs-empty').classList.toggle('hide', left > 0);
        showToast('Run deleted.', 'success');
    }

    document.addEventListener('click', function (event) {
        const control = event.target.closest('[data-run-action]');
        if (!control) return;
        const row = control.closest('tr');
        const id = row.dataset.runId;
        if (control.dataset.runAction === 'open') openRun(id);
        if (control.dataset.runAction === 'edit') editInput(id);
        if (control.dataset.runAction === 'delete') deleteRun(id, row);
    });

    // A finished enrichment adds a run: reload the list next time the view opens.
    document.addEventListener('htmx:afterSwap', function (event) {
        if (event.target && event.target.id === 'results-container') stale = true;
    });

    window.runsRefresh = function () { refresh(false); };
})();

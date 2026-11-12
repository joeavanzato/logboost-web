// Workspace, Enrich and Results views: the paste editor and upload drop zone, the row details
// drawer, the right-click menu, copy helpers and the shared-results loader.
// The results table itself lives in results.js (window.LBResults), the Stats tab in stats.js.

// Shared with graph.js and graph-dialogs.js, which build some markup as strings.
function escapeHtml(text) {
    // Safe for element content and for quoted attribute values
    return (text == null ? '' : String(text))
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function defangIOC(value) {
    if (!value || typeof value !== 'string') return value;

    let defanged = value;

    // Defang URLs first (before domain defanging) - only defang the protocol once
    defanged = defanged.replace(/https:\/\//i, 'hxxps[://]');
    defanged = defanged.replace(/http:\/\//i, 'hxxp[://]');

    // Check if it looks like an IP address (basic IPv4 pattern)
    const ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/\d+)?$/;
    if (ipPattern.test(defanged)) {
        // Defang IP: replace only the FIRST dot with [.]
        return defanged.replace(/\./, '[.]');
    }

    // Check if it looks like a domain (contains at least one dot and valid TLD pattern)
    const domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/;
    if (domainPattern.test(defanged)) {
        // Defang domain: replace only the FIRST dot with [.]
        return defanged.replace(/\./, '[.]');
    }

    // For values that contain IPs within text, defang only first dot of each IP
    return defanged.replace(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/g, '$1[.]$2.$3.$4');
}

// Load a shared result set (/?shared=<id>) into the results container.
async function loadSharedResults(shareId) {
    try {
        const response = await csrfFetch('/api/shared/results/' + shareId + '/render');
        if (!response.ok) {
            showToast('Shared results not found or expired', 'error');
            return;
        }

        const html = await response.text();
        const container = document.getElementById('results-container');
        if (container) {
            // A server-rendered fragment with no scripts; its data island is read by results.js
            container.innerHTML = html;
            if (window.LBResults) window.LBResults.init();
        }

        switchTab('adhoc', false);
        showToast('Loaded shared results', 'success');
    } catch (err) {
        console.error('Failed to load shared results:', err);
        showToast('Failed to load shared results', 'error');
    }
}

(function () {
    'use strict';

    const byId = (id) => document.getElementById(id);

    function el(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined) node.textContent = text;
        return node;
    }

    const IPV4 = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    const IPV6 = /^[0-9a-f:]+$/i;
    const looksLikeIp = (value) => IPV4.test(value) || (value.includes(':') && IPV6.test(value));

    // ================= Enrich: paste =================

    const pasteText = byId('adhoc-text');
    const pasteCount = byId('adhoc-count');
    const IPV4_IN_TEXT = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;

    // A rough live count; the server does the real extraction.
    function updatePasteCount() {
        if (!pasteText || !pasteCount) return;
        const unique = new Set(pasteText.value.match(IPV4_IN_TEXT) || []).size;
        pasteCount.textContent = unique + ' unique IPv4-looking address' + (unique === 1 ? '' : 'es');
    }

    if (pasteText) {
        let timer = null;
        pasteText.addEventListener('input', () => {
            clearTimeout(timer);
            timer = setTimeout(updatePasteCount, 150);
        });
        // The Intel browser fills the textarea from script and submits straight away
        pasteText.form.addEventListener('submit', updatePasteCount);
        byId('adhoc-clear').addEventListener('click', () => {
            pasteText.value = '';
            updatePasteCount();
            pasteText.focus();
        });
        updatePasteCount();
    }

    // Ctrl/Cmd+Enter submits the form of the Enrich view that is open
    document.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter' || !(e.ctrlKey || e.metaKey) || document.querySelector('dialog[open]')) return;
        const form = document.querySelector('#adhoc-panel.active form, #upload-panel.active form');
        if (!form) return;
        e.preventDefault();
        if (typeof form.requestSubmit === 'function') form.requestSubmit();
        else form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    });

    // ================= Enrich: upload =================

    const dropZone = byId('drop-zone');
    const fileInput = byId('file-input');
    const fileNameDisplay = byId('file-name');

    function formatSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }

    function updateFileName() {
        const file = fileInput.files[0];
        fileNameDisplay.textContent = file ? file.name + ' · ' + formatSize(file.size) : '';
        fileNameDisplay.classList.toggle('hide', !file);
        dropZone.classList.toggle('has-file', !!file);
    }

    if (dropZone && fileInput) {
        // The zone is the <label> of the file input, so a click opens the picker by itself
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });
        dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
                updateFileName();
            }
        });
        fileInput.addEventListener('change', updateFileName);
    }

    // ================= Results: row details drawer =================

    // Enrichment sections, in display order. Anything else with the lb_ prefix goes to "Other".
    const FIELD_GROUPS = [
        ['Identity', ['lb_IP', 'lb_Domains', 'lb_TLD']],
        ['Network', ['lb_ASN', 'lb_ASN_Number', 'lb_IPWhois_CIDR', 'lb_IPWhois_NetName', 'lb_IPWhois_NetType', 'lb_IPWhois_Parent']],
        ['Geolocation', ['lb_Country', 'lb_City']],
        ['IP WHOIS', ['lb_IPWhois_Organization', 'lb_IPWhois_Created', 'lb_IPWhois_Updated', 'lb_IPWhois_Country']],
        ['Domain WHOIS', ['lb_DomainWhois_CreatedDate', 'lb_DomainWhois_UpdatedDate', 'lb_DomainWhois_Country', 'lb_DomainWhois_Organization']],
        ['Threat intel', ['lb_ThreatCategories', 'lb_ThreatFeedCount', 'lb_ThreatFeeds']],
        ['Shodan / InternetDB', ['lb_IDB_cpes', 'lb_IDB_hostnames', 'lb_IDB_ports', 'lb_IDB_tags', 'lb_IDB_vulns']]
    ];
    const ORG_COLUMNS = ['lb_org', 'lb_organisation', 'lb_organization', 'lb_ipwhois_organization',
        'lb_ipwhoisorg', 'lb_whoisorg', 'lb_whois_orgname', 'lb_isp'];

    const drawer = byId('row-drawer');
    const view = { index: null, row: null, showEmpty: false, original: [], enrichment: [] };

    const displayName = (header) => header.replace(/^lb_/, '').replace(/_/g, ' ');
    const isBlank = (value) => !value || value.trim() === '';
    // LogBoost writes "none" where a lookup found nothing
    const isEmptyField = (field, enriched) => isBlank(field.value) || (enriched && field.value === 'none');
    const isThreatColumn = (header) => header.toLowerCase().startsWith('lb_threat');
    const splitValues = (value) => value.split('|').map(v => v.trim()).filter(Boolean);

    function drawerIsOpen() {
        return !!drawer && drawer.classList.contains('on');
    }

    function markSelectedRow() {
        document.querySelectorAll('#results-table tbody tr.sel').forEach(tr => tr.classList.remove('sel'));
        if (view.index === null) return;
        const tr = document.querySelector('#results-table tbody tr[data-row="' + view.index + '"]');
        if (tr) {
            tr.classList.add('sel');
            tr.scrollIntoView({ block: 'nearest' });
        }
    }

    function openRow(index) {
        if (!drawer || !window.LBResults) return;
        const rows = window.LBResults.pageRows();
        if (index < 0 || index >= rows.length) return;

        view.index = index;
        view.row = rows[index];
        renderDrawer(rows.length);

        drawer.classList.add('on');
        drawer.setAttribute('aria-hidden', 'false');
        document.body.classList.add('drawer-open');
        markSelectedRow();
    }

    function closeDrawer() {
        if (!drawer) return;
        view.index = null;
        view.row = null;
        drawer.classList.remove('on');
        drawer.setAttribute('aria-hidden', 'true');
        document.body.classList.remove('drawer-open');
        markSelectedRow();
    }

    function navigateRow(direction) {
        if (view.index !== null) openRow(view.index + direction);
    }

    function firstValue(fields, names) {
        for (const name of names) {
            const field = fields.find(f => f.header.toLowerCase() === name);
            if (field && !isEmptyField(field, true)) return field.value;
        }
        return '';
    }

    // The row's IP: an "IP" column first, then any value that looks like an address.
    function rowIp() {
        const fields = view.enrichment.concat(view.original);
        const named = fields.find(f => displayName(f.header).trim().toLowerCase() === 'ip' && !isEmptyField(f, true));
        if (named) return named.value.trim();
        const guessed = fields.find(f => looksLikeIp(f.value.trim()));
        return guessed ? guessed.value.trim() : '';
    }

    function valueNode(field, enriched) {
        const dd = el('dd');
        if (isEmptyField(field, enriched)) {
            dd.className = 'faint';
            dd.textContent = '—';
            return dd;
        }
        const items = field.value.includes('|') ? splitValues(field.value) : [];
        if (items.length > 1) {
            // Multi-value field (domains, threat feeds…): a list with its own CSV download
            const list = el('ul', 'kv-list');
            items.forEach(item => list.appendChild(el('li', '', item)));
            const download = el('button', 'linkbtn', 'Download as CSV');
            download.type = 'button';
            download.dataset.fieldName = displayName(field.header);
            download.dataset.values = field.value;
            dd.append(list, download);
        } else {
            dd.textContent = field.value;
        }
        return dd;
    }

    function section(title, fields, enriched, tone) {
        const shown = fields.filter(f => view.showEmpty || !isEmptyField(f, enriched));
        if (shown.length === 0) return null;
        const wrap = el('div');
        const heading = el('div', 'eyebrow' + (tone ? ' ' + tone : ''), title);
        heading.style.marginBottom = '10px';
        const list = el('dl', 'kv');
        shown.forEach(field => {
            const dt = el('dt', '', displayName(field.header));
            dt.title = field.header;
            list.append(dt, valueNode(field, enriched));
        });
        wrap.append(heading, list);
        return wrap;
    }

    function verdictNode() {
        const threats = view.enrichment.filter(f => isThreatColumn(f.header)
            && !isEmptyField(f, true) && !/^(0|false|no)$/i.test(f.value.trim()));
        if (threats.length === 0) return null;

        const byName = (pattern) => threats.find(f => pattern.test(f.header));
        const countField = byName(/count/i);
        const feedsField = threats.find(f => /feed/i.test(f.header) && !/count/i.test(f.header));
        const categoriesField = byName(/categor/i);
        const feeds = feedsField ? splitValues(feedsField.value) : [];
        const count = countField && /^\d+$/.test(countField.value.trim()) ? Number(countField.value) : feeds.length;

        const box = el('div', 'verdict');
        box.appendChild(el('strong', '', count > 0
            ? 'Listed in ' + count + ' threat feed' + (count === 1 ? '' : 's')
            : 'Threat intel match'));
        const lines = el('div', 'verdict-lines');
        if (feeds.length) lines.appendChild(el('div', 'mono', feeds.join(', ')));
        if (categoriesField) lines.appendChild(el('div', 'muted', splitValues(categoriesField.value).join(', ')));
        if (lines.children.length) box.appendChild(lines);
        return box;
    }

    function renderDrawer(rowCount) {
        const headers = window.LBResults.headers();
        view.original = [];
        view.enrichment = [];
        headers.forEach((header, index) => {
            if (!header || header.trim() === '') return;   // skip unnamed columns
            const raw = view.row[index];
            const field = { header, value: raw === undefined || raw === null ? '' : String(raw) };
            (header.startsWith('lb_') ? view.enrichment : view.original).push(field);
        });

        // Header: the IP when the row has one, with a one-line summary
        const ip = rowIp();
        byId('row-drawer-title').textContent = ip || 'Row ' + (view.index + 1);
        const summary = [
            firstValue(view.enrichment, ORG_COLUMNS),
            firstValue(view.enrichment, ['lb_asn']),
            [firstValue(view.enrichment, ['lb_city']), firstValue(view.enrichment, ['lb_country'])].filter(Boolean).join(', ')
        ].filter(Boolean);
        byId('row-drawer-sub').textContent = summary.join(' · ');

        const nodes = [verdictNode(), section('Original data', view.original, false)];

        const grouped = new Set();
        FIELD_GROUPS.forEach(([title, names]) => {
            const isThreat = title === 'Threat intel';
            const fields = view.enrichment.filter(f => names.includes(f.header) || (isThreat && isThreatColumn(f.header)));
            fields.forEach(f => grouped.add(f));
            nodes.push(section(title, fields, true, isThreat ? 'red' : ''));
        });
        nodes.push(section('Other', view.enrichment.filter(f => !grouped.has(f)), true));

        const emptyCount = view.original.filter(f => isEmptyField(f, false)).length
            + view.enrichment.filter(f => isEmptyField(f, true)).length;
        if (emptyCount > 0) {
            const note = el('div', 'muted', emptyCount + ' empty field' + (emptyCount === 1 ? '' : 's')
                + (view.showEmpty ? ' shown · ' : ' hidden · '));
            note.style.fontSize = '13px';
            const toggle = el('button', 'linkbtn green', view.showEmpty ? 'Hide' : 'Show');
            toggle.type = 'button';
            toggle.id = 'row-drawer-empty-toggle';
            toggle.style.fontSize = '13px';
            note.appendChild(toggle);
            nodes.push(note);
        }

        byId('row-drawer-body').replaceChildren(...nodes.filter(Boolean));
        updateDrawerPosition(rowCount);
    }

    function updateDrawerPosition(rowCount) {
        byId('row-drawer-pos').textContent = 'Row ' + (view.index + 1) + ' of ' + rowCount;
        byId('row-drawer-prev').disabled = view.index === 0;
        byId('row-drawer-next').disabled = view.index === rowCount - 1;
    }

    // ---- per-field CSV download ----

    function downloadFieldValues(fieldName, values) {
        let csvContent = '"' + fieldName.replace(/"/g, '""') + '"\n';
        splitValues(values).forEach(item => {
            csvContent += '"' + item.replace(/"/g, '""') + '"\n';
        });

        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = fieldName.replace(/\s+/g, '_').toLowerCase() + '_values.csv';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }

    // ---- copy ----

    function copyText(text, message) {
        const done = () => showToast(message, 'success', 2000);
        const fallback = () => {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            try {
                document.execCommand('copy');
                done();
            } catch (err) {
                showToast('Failed to copy. Please copy manually.', 'error');
            }
            document.body.removeChild(textarea);
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(done).catch(fallback);
        } else {
            fallback();
        }
    }

    // The enrichment fields with a value (the whole row when it has no enrichment columns)
    function copyFields() {
        const enriched = view.enrichment.length > 0;
        return (enriched ? view.enrichment : view.original).filter(f => !isEmptyField(f, true));
    }

    function copyEnrichmentReadable() {
        if (view.row === null) return;
        let text = '';
        copyFields().forEach(field => {
            const label = displayName(field.header);
            if (field.value.includes('|')) {
                text += label + ':\n';
                splitValues(field.value).forEach(item => { text += '  • ' + defangIOC(item) + '\n'; });
            } else {
                text += label + ': ' + defangIOC(field.value) + '\n';
            }
        });
        copyText(text.trim(), 'Copied to clipboard (defanged)');
    }

    function copyEnrichmentJSON() {
        if (view.row === null) return;
        const data = {};
        copyFields().forEach(field => {
            const key = field.header.replace(/^lb_/, '');
            data[key] = field.value.includes('|')
                ? splitValues(field.value).map(defangIOC)
                : defangIOC(field.value);
        });
        copyText(JSON.stringify(data, null, 2), 'JSON copied (defanged)');
    }

    // ---- graph ----

    function graphFromModal() {
        const ip = rowIp();
        if (!ip) {
            showToast('This row has no IP address to graph', 'warning');
            return;
        }
        window.graphManager.promptGraph(ip, 'ip');
        closeDrawer();
    }

    // ---- drawer events ----

    if (drawer) {
        byId('row-drawer-close').addEventListener('click', closeDrawer);
        byId('row-drawer-prev').addEventListener('click', () => navigateRow(-1));
        byId('row-drawer-next').addEventListener('click', () => navigateRow(1));
        byId('row-drawer-copy').addEventListener('click', copyEnrichmentReadable);
        byId('row-drawer-copy-json').addEventListener('click', copyEnrichmentJSON);
        byId('row-drawer-graph').addEventListener('click', graphFromModal);

        byId('row-drawer-body').addEventListener('click', (e) => {
            const download = e.target.closest('button[data-values]');
            if (download) {
                downloadFieldValues(download.dataset.fieldName, download.dataset.values);
            } else if (e.target.id === 'row-drawer-empty-toggle') {
                view.showEmpty = !view.showEmpty;
                renderDrawer(window.LBResults.pageRows().length);
            }
        });

        // Click a table row to open it
        document.addEventListener('click', (e) => {
            const tr = e.target.closest ? e.target.closest('#results-table tbody tr[data-row]') : null;
            if (!tr || String(window.getSelection()) !== '') return;   // not while selecting text
            openRow(Number(tr.dataset.row));
        });

        // Arrow keys step through the rows, Esc closes
        document.addEventListener('keydown', (e) => {
            if (!drawerIsOpen() || document.querySelector('dialog[open]')) return;
            const typing = e.target.matches && e.target.matches('input, textarea, select');
            if (e.key === 'Escape') {
                closeDrawer();
                hideMenu();
                e.stopImmediatePropagation();   // one Esc, one layer: fullscreen stays
            } else if (typing || e.ctrlKey || e.metaKey || e.altKey) {
                return;
            } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
                e.preventDefault();
                navigateRow(-1);
            } else if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
                e.preventDefault();
                navigateRow(1);
            }
        });

        // The table was redrawn (sort, filter, page, columns): follow the open row or close
        document.addEventListener('results:rendered', () => {
            if (!drawerIsOpen()) return;
            const rows = window.LBResults.pageRows();
            const index = rows.indexOf(view.row);
            if (index === -1) {
                closeDrawer();
            } else {
                view.index = index;
                updateDrawerPosition(rows.length);
                markSelectedRow();
            }
        });

        // New results (or an error) replaced the table; other views do not show the drawer
        document.addEventListener('htmx:afterSwap', (e) => {
            if (e.detail && e.detail.target && e.detail.target.id === 'results-container') closeDrawer();
        });
        window.addEventListener('hashchange', () => {
            const name = window.location.hash.slice(1);
            if (name && !['adhoc', 'upload', 'runs'].includes(name)) closeDrawer();
        });
    }

    // ================= Results: right-click menu =================

    const menu = byId('context-menu');
    let menuValue = null;
    let menuType = null;

    function hideMenu() {
        if (menu) menu.classList.add('hide');
    }

    if (menu) {
        document.addEventListener('contextmenu', (e) => {
            const td = e.target.closest ? e.target.closest('#results-table tbody td[data-col]') : null;
            if (!td || !window.LBResults) { hideMenu(); return; }

            const header = window.LBResults.headers()[Number(td.dataset.col)] || '';
            let value = (td.getAttribute('title') || td.textContent).trim();
            // Pipe-separated values: take the first one
            if (value.includes('|')) value = value.split('|')[0].trim();

            const name = header.toLowerCase();
            const isIpValue = IPV4.test(value);
            const isIpColumn = name.includes('ip');
            const isDomainColumn = name.includes('domain') || name.includes('hostname');
            if (!value || !(isIpColumn || isDomainColumn || isIpValue)) { hideMenu(); return; }

            e.preventDefault();
            menuValue = value;
            menuType = isIpValue ? 'ip' : 'domain';
            byId('context-menu-graph').textContent = 'Graph this ' + (menuType === 'ip' ? 'IP' : 'domain');

            menu.classList.remove('hide');
            menu.style.left = Math.min(e.clientX, window.innerWidth - menu.offsetWidth - 8) + 'px';
            menu.style.top = Math.min(e.clientY, window.innerHeight - menu.offsetHeight - 8) + 'px';
        });

        byId('context-menu-graph').addEventListener('click', () => {
            if (menuValue) window.graphManager.promptGraph(menuValue, menuType);
        });
        document.addEventListener('click', hideMenu);
        document.addEventListener('scroll', hideMenu, true);
        document.addEventListener('keydown', (e) => { if (e.key === 'Escape') hideMenu(); });
    }
})();

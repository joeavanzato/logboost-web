// Workspace page: Intel browser (templates/workspace/_intel.html).
// Source names and tags come from external feeds, so everything is built with
// createElement/textContent; no HTML strings and no inline handlers.

(function() {
    const PAGE_SIZE = 100;
    const COLUMNS = 4;
    let offset = 0;
    let hasMore = false;
    let initialized = false;
    let searchTimer = null;
    let inflight = null;

    const byId = (id) => document.getElementById(id);
    const $sources = () => byId('intel-source');
    const $tags = () => byId('intel-tag');
    const $search = () => byId('intel-search');
    const $rows = () => byId('intel-rows');
    const $status = () => byId('intel-status');
    const $prev = () => byId('intel-prev');
    const $next = () => byId('intel-next');

    function el(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text != null) node.textContent = text;
        return node;
    }

    function currentParams() {
        const params = new URLSearchParams();
        const src = $sources().value;
        const tag = $tags().value;
        const q = ($search().value || '').trim();
        if (src) params.set('source_id', src);
        if (tag) params.set('tag_id', tag);
        if (q) params.set('q', q);
        return params;
    }

    // One full-width row carrying a message (loading, empty, error).
    function setRowsMessage(message) {
        const td = el('td', 'muted', message);
        td.colSpan = COLUMNS;
        const tr = el('tr');
        tr.appendChild(td);
        $rows().replaceChildren(tr);
    }

    function splitList(value) {
        return String(value == null ? '' : value).split(',').map(s => s.trim()).filter(Boolean);
    }

    function buildRow(r) {
        const ip = String(r.ip == null ? '' : r.ip);
        const selected = selectedIPs.has(ip);
        const tr = el('tr', selected ? 'sel' : '');
        tr.dataset.ip = ip;

        const checkCell = el('td');
        const check = el('input', 'check');
        check.type = 'checkbox';
        check.checked = selected;
        check.setAttribute('aria-label', 'Select ' + ip);
        checkCell.appendChild(check);

        const sourcesCell = el('td');
        sourcesCell.appendChild(el('span', 'intel-sources', splitList(r.sources).join(', ')));

        const tagsCell = el('td');
        const tagWrap = el('span', 'intel-tags');
        splitList(r.tags).forEach(t => tagWrap.appendChild(el('span', 'tag', t)));
        tagsCell.appendChild(tagWrap);

        tr.append(checkCell, el('td', 'mono', ip), sourcesCell, tagsCell);
        return tr;
    }

    function fillSelect(select, firstLabel, items, labelKey) {
        const options = [new Option(firstLabel, '')];
        items.forEach(x => options.push(new Option(String(x[labelKey] == null ? '' : x[labelKey]), String(x.id))));
        select.replaceChildren(...options);
    }

    async function loadFilters() {
        try {
            const [sRes, tRes] = await Promise.all([
                fetch('/api/intel/sources').then(r => r.json()),
                fetch('/api/intel/tags').then(r => r.json()),
            ]);
            fillSelect($sources(), 'All sources', sRes.sources || [], 'name');
            fillSelect($tags(), 'All tags', tRes.tags || [], 'value');
        } catch (e) {
            // Filter dropdowns may stay empty if threats.db is missing — table itself surfaces the error
        }
    }

    async function loadPage() {
        if (inflight) inflight.abort();
        const ctrl = new AbortController();
        inflight = ctrl;

        const params = currentParams();
        params.set('limit', PAGE_SIZE);
        params.set('offset', offset);

        setRowsMessage('Loading…');
        $prev().disabled = true;
        $next().disabled = true;

        try {
            const res = await fetch('/api/intel/iocs?' + params.toString(), { signal: ctrl.signal });
            const data = await res.json();
            if (data.error) {
                setRowsMessage('Error: ' + data.error);
                $status().textContent = '—';
                return;
            }
            const rows = data.rows || [];
            hasMore = !!data.has_more;

            if (rows.length === 0) {
                setRowsMessage(offset === 0 ? 'No IOCs match the current filters.' : 'No more rows.');
            } else {
                $rows().replaceChildren(...rows.map(buildRow));
            }
            lastClickedIP = null;

            const start = rows.length === 0 ? 0 : offset + 1;
            const end = offset + rows.length;
            $status().textContent = rows.length === 0
                ? 'No results'
                : `Showing ${start.toLocaleString()}–${end.toLocaleString()}${hasMore ? ' (more available)' : ''}`;
            $prev().disabled = offset === 0;
            $next().disabled = !hasMore;
        } catch (err) {
            if (err.name === 'AbortError') return;
            setRowsMessage('Network error: ' + (err.message || ''));
            $status().textContent = '—';
        } finally {
            if (inflight === ctrl) inflight = null;
        }
    }

    window.intelInit = function() {
        if (initialized) return;
        initialized = true;
        loadFilters().then(loadPage);
        loadStats();  // totals for the subtitle; the Statistics tab reuses the result
    };

    function loadFirstPage() {
        offset = 0;
        clearSelection();
        loadPage();
    }
    window.intelLoadFirstPage = loadFirstPage;

    function debouncedSearch() {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(loadFirstPage, 300);
    }

    function clearFilters() {
        $sources().value = '';
        $tags().value = '';
        $search().value = '';
        loadFirstPage();
    }

    function prevPage() {
        offset = Math.max(0, offset - PAGE_SIZE);
        loadPage();
    }

    function nextPage() {
        if (!hasMore) return;
        offset += PAGE_SIZE;
        loadPage();
    }

    function exportCsv() {
        window.location.href = '/api/intel/export?' + currentParams().toString();
    }

    // ===== Sub-tabs (Browse / Statistics) =====
    let statsLoaded = false;
    let statsLoading = null;

    function switchSubTab(name) {
        document.querySelectorAll('#intel-subtabs [data-subtab]').forEach(a => {
            const on = a.dataset.subtab === name;
            a.classList.toggle('on', on);
            if (on) a.setAttribute('aria-current', 'true'); else a.removeAttribute('aria-current');
        });
        document.querySelectorAll('#intel-browser-panel .intel-sub-panel').forEach(p =>
            p.classList.toggle('hide', p.id !== `intel-sub-${name}`));
        if (name === 'stats' && !statsLoaded) loadStats();
    }
    window.intelSwitchSubTab = switchSubTab;

    function setStatMessage(container, message) {
        container.replaceChildren(el('span', 'muted', message));
    }

    function loadStats() {
        if (statsLoading) return statsLoading;
        statsLoading = fetchStats().finally(() => { statsLoading = null; });
        return statsLoading;
    }

    async function fetchStats() {
        const srcEl = byId('intel-stats-sources');
        const tagEl = byId('intel-stats-tags');
        setStatMessage(srcEl, 'Loading…');
        setStatMessage(tagEl, 'Loading…');

        try {
            const res = await fetch('/api/intel/stats');
            const data = await res.json();
            if (data.error) {
                setStatMessage(srcEl, 'Error: ' + data.error);
                setStatMessage(tagEl, 'Error: ' + data.error);
                return;
            }
            const sources = data.sources || [];
            const tags = data.tags || [];
            const uniqueIps = (data.unique_ips || 0).toLocaleString();
            byId('stat-total-entries').textContent = (data.total_entries || 0).toLocaleString();
            byId('stat-unique-ips').textContent = uniqueIps;
            byId('stat-source-count').textContent = sources.length.toLocaleString();
            byId('stat-tag-count').textContent = tags.length.toLocaleString();

            const subtitle = byId('intel-subtitle');
            if (subtitle) {
                subtitle.textContent = `${uniqueIps} IPs from ${sources.length.toLocaleString()} sources · browse by source or tag`;
            }

            renderStatList(srcEl, sources, 'source');
            renderStatList(tagEl, tags, 'tag');
            statsLoaded = true;
        } catch (err) {
            setStatMessage(srcEl, 'Network error: ' + (err.message || ''));
            setStatMessage(tagEl, 'Network error: ' + (err.message || ''));
        }
    }

    // A barlist: one button per source or tag, then its count. Clicks are delegated (see wire()).
    function renderStatList(container, items, kind) {
        if (items.length === 0) {
            setStatMessage(container, 'No data');
            return;
        }
        const max = Math.max(...items.map(i => i.count || 0)) || 1;
        const nodes = [];
        items.forEach(i => {
            const label = String((kind === 'source' ? i.name : i.value) || '');
            const bar = el('button', 'intel-bar');
            bar.type = 'button';
            if (i.id == null) {
                bar.disabled = true;  // rows with no feed/category have nothing to filter by
            } else {
                bar.dataset.kind = kind;
                bar.dataset.id = String(i.id);
                bar.title = `Filter Browse by ${kind}: ${label}`;
            }
            const fill = el('i');
            fill.style.width = ((i.count || 0) / max * 100).toFixed(1) + '%';
            bar.append(fill, el('span', '', label));
            nodes.push(bar, el('em', '', (i.count || 0).toLocaleString()));
        });
        container.replaceChildren(...nodes);
    }

    function pivotTo(kind, id) {
        if (kind === 'source') {
            $sources().value = String(id);
        } else {
            $tags().value = String(id);
        }
        offset = 0;
        clearSelection();
        switchSubTab('browser');
        loadPage();
    }
    window.intelPivotTo = pivotTo;

    // ===== Row selection (Ctrl/Cmd+click toggle, Shift+click range, or the row's checkbox) =====
    const SELECTION_CAP = 100;
    const selectedIPs = new Set();
    let lastClickedIP = null;
    let pendingGraphAction = null;

    function clearSelection() {
        if (selectedIPs.size === 0) return;
        selectedIPs.clear();
        updateSelectionUI();
    }

    function updateSelectionUI() {
        const count = selectedIPs.size;
        const enrich = byId('intel-enrich-btn');
        const graph = byId('intel-graph-btn');
        const indicator = byId('intel-selected-count');
        if (enrich) {
            enrich.textContent = `Enrich (${count})`;
            enrich.disabled = count === 0;
        }
        if (graph) {
            graph.textContent = `Graph (${count})`;
            graph.disabled = count === 0;
        }
        if (indicator) indicator.textContent = `${count} selected · up to ${SELECTION_CAP}`;
        // Sync row classes and checkboxes
        $rows().querySelectorAll('tr[data-ip]').forEach(tr => {
            const selected = selectedIPs.has(tr.dataset.ip);
            tr.classList.toggle('sel', selected);
            const check = tr.querySelector('input[type="checkbox"]');
            if (check) check.checked = selected;
        });
    }

    function toggleSelection(ip) {
        if (selectedIPs.has(ip)) {
            selectedIPs.delete(ip);
        } else {
            if (selectedIPs.size >= SELECTION_CAP) {
                showToast(`Selection capped at ${SELECTION_CAP} IPs`, 'warning');
                return;
            }
            selectedIPs.add(ip);
        }
    }

    function rangeSelectFromCurrentPage(fromIP, toIP) {
        const rows = Array.from($rows().querySelectorAll('tr[data-ip]'));
        const ips = rows.map(r => r.dataset.ip);
        const a = ips.indexOf(fromIP);
        const b = ips.indexOf(toIP);
        if (a < 0 || b < 0) return;
        const [lo, hi] = a <= b ? [a, b] : [b, a];
        for (let i = lo; i <= hi; i++) {
            if (selectedIPs.has(ips[i])) continue;
            if (selectedIPs.size >= SELECTION_CAP) {
                showToast(`Selection capped at ${SELECTION_CAP} IPs (range truncated)`, 'warning');
                break;
            }
            selectedIPs.add(ips[i]);
        }
    }

    // Delegated row click handler. The checkbox toggles on a plain click; anywhere else on the
    // row needs a modifier, as before.
    function onRowClick(e) {
        const tr = e.target.closest('tr[data-ip]');
        if (!tr) return;
        const ip = tr.dataset.ip;
        const onCheckbox = e.target.matches('input[type="checkbox"]');
        if (e.shiftKey && lastClickedIP) {
            rangeSelectFromCurrentPage(lastClickedIP, ip);
        } else if (e.ctrlKey || e.metaKey || onCheckbox) {
            toggleSelection(ip);
        } else {
            return; // plain click does nothing
        }
        lastClickedIP = ip;
        updateSelectionUI();  // also puts the checkbox back in step with the selection
    }

    function showToast(msg, kind) {
        if (typeof window.showToast === 'function') {
            window.showToast(msg, kind || 'info');
        } else {
            console.log('[intel]', msg);
        }
    }

    // ===== Enrich action (auto-submits the adhoc form) =====
    window.intelEnrichSelection = function() {
        if (selectedIPs.size === 0) return;
        const ips = Array.from(selectedIPs);
        const form = document.querySelector('#adhoc-panel form.enrichment-form');
        const textarea = form?.querySelector('textarea[name="text"]');
        if (!form || !textarea) {
            showToast('Could not find the enrichment form', 'error');
            return;
        }
        textarea.value = ips.join('\n');
        ['dns', 'whois', 'idb', 'useti'].forEach(name => {
            const cb = form.querySelector(`input[type="checkbox"][name="${name}"]`);
            if (cb && !cb.disabled) cb.checked = true;
        });
        switchTab('adhoc');
        // Auto-submit (HTMX listens for form submit events)
        if (typeof form.requestSubmit === 'function') {
            form.requestSubmit();
        } else {
            form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
        }
    };

    // ===== Graph action with Save / Discard / Cancel prompt =====
    const $confirm = () => byId('intel-graph-confirm');

    window.intelGraphSelection = function() {
        if (selectedIPs.size === 0) return;
        const gm = window.graphManager;
        const ips = Array.from(selectedIPs);
        if (!gm || gm.nodes.length === 0) {
            buildIntelGraph(ips);
            return;
        }
        // Prompt
        byId('intel-modal-node-count').textContent = gm.nodes.length;
        pendingGraphAction = ips;
        $confirm().showModal();
    };

    // Takes the pending selection and closes the prompt. Cancel, Esc and a backdrop click just
    // close the dialog (app.js / the browser); its close event drops the pending selection.
    function takePendingGraphAction() {
        const ips = pendingGraphAction;
        pendingGraphAction = null;
        if ($confirm().open) $confirm().close();
        return ips;
    }

    function graphConfirmDiscard() {
        const ips = takePendingGraphAction();
        if (ips) buildIntelGraph(ips);
    }

    // The save dialog belongs to the Graph view. It is open while it has class "active"
    // (overlay) or, if it is a native <dialog>, while its `open` property is set.
    function isSaveDialogOpen(saveModal) {
        return saveModal.open === true || saveModal.classList.contains('active');
    }

    function graphConfirmSave() {
        const ips = takePendingGraphAction();
        if (!ips) return;
        const gm = window.graphManager;
        const saveModal = byId('graph-save-modal');
        if (!gm || !saveModal) {
            buildIntelGraph(ips);
            return;
        }
        const wasModified = gm.isModified;
        // Open save modal; poll until it closes (saved or cancelled)
        gm.saveGraph();
        const start = Date.now();
        const tick = () => {
            const stillOpen = isSaveDialogOpen(saveModal);
            const justSaved = wasModified && !gm.isModified;
            if (!stillOpen) {
                if (justSaved || !wasModified) {
                    buildIntelGraph(ips);
                } else {
                    showToast('Save cancelled — graph unchanged', 'info');
                }
                return;
            }
            if (Date.now() - start > 120000) return; // 2-min safety timeout
            setTimeout(tick, 150);
        };
        setTimeout(tick, 250);
    }

    function buildIntelGraph(ips) {
        const gm = window.graphManager;
        if (!gm) {
            showToast('Graph manager unavailable', 'error');
            return;
        }
        switchTab('graph');
        // Reset directly (avoid the confirm dialog inside newGraph())
        gm.nodes = [];
        gm.edges = [];
        gm.graphId = null;
        gm.graphName = 'Intel Browser Selection';
        gm.isModified = false;
        if (gm.geoQueueTimer) {
            clearTimeout(gm.geoQueueTimer);
            gm.geoQueueTimer = null;
        }
        if (gm.pendingGeoIPs && typeof gm.pendingGeoIPs.clear === 'function') {
            gm.pendingGeoIPs.clear();
        }
        if (typeof gm.showGraph === 'function') gm.showGraph();
        ips.forEach((ip, i) => gm.addNode(ip, 'ip', i === 0));
        showToast(`Loaded ${ips.length} IP(s) into graph`, 'success');
    }

    // ===== Wiring (replaces the old inline handlers) =====
    function onBarClick(e) {
        const bar = e.target.closest('.intel-bar[data-kind]');
        if (bar) pivotTo(bar.dataset.kind, bar.dataset.id);
    }

    function wire() {
        if (!byId('intel-browser-panel')) return;
        $sources().addEventListener('change', loadFirstPage);
        $tags().addEventListener('change', loadFirstPage);
        $search().addEventListener('input', debouncedSearch);
        byId('intel-clear-btn').addEventListener('click', clearFilters);
        byId('intel-export-btn').addEventListener('click', exportCsv);
        byId('intel-enrich-btn').addEventListener('click', window.intelEnrichSelection);
        byId('intel-graph-btn').addEventListener('click', window.intelGraphSelection);
        $prev().addEventListener('click', prevPage);
        $next().addEventListener('click', nextPage);
        $rows().addEventListener('click', onRowClick);
        byId('intel-subtabs').addEventListener('click', (e) => {
            const tab = e.target.closest('[data-subtab]');
            if (!tab) return;
            e.preventDefault();
            switchSubTab(tab.dataset.subtab);
        });
        byId('intel-stats-sources').addEventListener('click', onBarClick);
        byId('intel-stats-tags').addEventListener('click', onBarClick);
        byId('intel-graph-discard-btn').addEventListener('click', graphConfirmDiscard);
        byId('intel-graph-save-btn').addEventListener('click', graphConfirmSave);
        $confirm().addEventListener('close', () => { pendingGraphAction = null; });
    }

    wire();
})();

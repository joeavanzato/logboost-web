// Workspace page: Intel browser. Moved verbatim from templates/index.html.

(function() {
    const PAGE_SIZE = 100;
    let offset = 0;
    let hasMore = false;
    let initialized = false;
    let searchTimer = null;
    let inflight = null;

    const $sources = () => document.getElementById('intel-source');
    const $tags = () => document.getElementById('intel-tag');
    const $search = () => document.getElementById('intel-search');
    const $rows = () => document.getElementById('intel-rows');
    const $status = () => document.getElementById('intel-status');
    const $prev = () => document.getElementById('intel-prev');
    const $next = () => document.getElementById('intel-next');

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

    function setRowsHTML(html) {
        $rows().innerHTML = html;
    }

    function escapeHtml(s) {
        return (s == null ? '' : String(s))
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    async function loadFilters() {
        try {
            const [sRes, tRes] = await Promise.all([
                fetch('/api/intel/sources').then(r => r.json()),
                fetch('/api/intel/tags').then(r => r.json()),
            ]);
            const s = $sources();
            const t = $tags();
            const sources = sRes.sources || [];
            const tags = tRes.tags || [];
            s.innerHTML = '<option value="">All sources</option>' +
                sources.map(x => `<option value="${escapeHtml(x.id)}">${escapeHtml(x.name)}</option>`).join('');
            t.innerHTML = '<option value="">All tags</option>' +
                tags.map(x => `<option value="${escapeHtml(x.id)}">${escapeHtml(x.value)}</option>`).join('');
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

        setRowsHTML('<tr class="intel-empty"><td colspan="3">Loading...</td></tr>');
        $prev().disabled = true;
        $next().disabled = true;

        try {
            const res = await fetch('/api/intel/iocs?' + params.toString(), { signal: ctrl.signal });
            const data = await res.json();
            if (data.error) {
                setRowsHTML(`<tr class="intel-empty"><td colspan="3">Error: ${escapeHtml(data.error)}</td></tr>`);
                $status().textContent = '—';
                return;
            }
            const rows = data.rows || [];
            hasMore = !!data.has_more;

            if (rows.length === 0) {
                const msg = offset === 0 ? 'No IOCs match the current filters.' : 'No more rows.';
                setRowsHTML(`<tr class="intel-empty"><td colspan="3">${msg}</td></tr>`);
            } else {
                setRowsHTML(rows.map(r => {
                    const sel = selectedIPs.has(r.ip) ? ' class="selected"' : '';
                    return `<tr data-ip="${escapeHtml(r.ip)}"${sel}><td>${escapeHtml(r.ip)}</td><td>${escapeHtml(r.sources)}</td><td>${escapeHtml(r.tags)}</td></tr>`;
                }).join(''));
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
            setRowsHTML(`<tr class="intel-empty"><td colspan="3">Network error: ${escapeHtml(err.message || '')}</td></tr>`);
            $status().textContent = '—';
        } finally {
            if (inflight === ctrl) inflight = null;
        }
    }

    window.intelInit = function() {
        if (initialized) return;
        initialized = true;
        loadFilters().then(loadPage);
    };

    window.intelLoadFirstPage = function() {
        offset = 0;
        clearSelection();
        loadPage();
    };

    window.intelDebouncedSearch = function() {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => { offset = 0; clearSelection(); loadPage(); }, 300);
    };

    window.intelClearFilters = function() {
        $sources().value = '';
        $tags().value = '';
        $search().value = '';
        offset = 0;
        clearSelection();
        loadPage();
    };

    window.intelPrev = function() {
        offset = Math.max(0, offset - PAGE_SIZE);
        loadPage();
    };

    window.intelNext = function() {
        if (!hasMore) return;
        offset += PAGE_SIZE;
        loadPage();
    };

    window.intelExport = function() {
        const params = currentParams();
        window.location.href = '/api/intel/export?' + params.toString();
    };

    // ===== Sub-tabs (Browser / Statistics) =====
    let statsLoaded = false;

    window.intelSwitchSubTab = function(name) {
        document.querySelectorAll('.intel-subtab').forEach(b =>
            b.classList.toggle('active', b.dataset.subtab === name));
        document.querySelectorAll('.intel-sub-panel').forEach(p =>
            p.classList.toggle('active', p.id === `intel-sub-${name}`));
        if (name === 'stats' && !statsLoaded) loadStats();
    };

    async function loadStats() {
        const srcEl = document.getElementById('intel-stats-sources');
        const tagEl = document.getElementById('intel-stats-tags');
        srcEl.textContent = 'Loading...';
        tagEl.textContent = 'Loading...';

        try {
            const res = await fetch('/api/intel/stats');
            const data = await res.json();
            if (data.error) {
                srcEl.textContent = 'Error: ' + data.error;
                tagEl.textContent = 'Error: ' + data.error;
                return;
            }
            document.getElementById('stat-total-entries').textContent = (data.total_entries || 0).toLocaleString();
            document.getElementById('stat-unique-ips').textContent = (data.unique_ips || 0).toLocaleString();
            document.getElementById('stat-source-count').textContent = (data.sources || []).length.toLocaleString();
            document.getElementById('stat-tag-count').textContent = (data.tags || []).length.toLocaleString();

            srcEl.innerHTML = renderStatList(data.sources || [], 'source');
            tagEl.innerHTML = renderStatList(data.tags || [], 'tag');
            statsLoaded = true;
        } catch (err) {
            srcEl.textContent = 'Network error: ' + (err.message || '');
            tagEl.textContent = 'Network error: ' + (err.message || '');
        }
    }

    function renderStatList(items, kind) {
        if (items.length === 0) return '<div style="padding:1rem;color:var(--text-muted)">No data</div>';
        const max = Math.max(...items.map(i => i.count || 0)) || 1;
        return items.map(i => {
            const label = kind === 'source' ? i.name : i.value;
            const pct = (i.count || 0) / max * 100;
            return `<button class="intel-stat-row" type="button" onclick="intelPivotTo('${kind}', ${Number(i.id)})" title="Filter Browser by ${kind}: ${escapeHtml(label)}">
                <span class="intel-stat-bar" style="width: ${pct.toFixed(1)}%"></span>
                <span class="intel-stat-name">${escapeHtml(label)}</span>
                <span class="intel-stat-count">${(i.count || 0).toLocaleString()}</span>
            </button>`;
        }).join('');
    }

    window.intelPivotTo = function(kind, id) {
        if (kind === 'source') {
            $sources().value = String(id);
        } else {
            $tags().value = String(id);
        }
        offset = 0;
        clearSelection();
        intelSwitchSubTab('browser');
        loadPage();
    };

    // ===== Row selection (Ctrl/Cmd+click toggle, Shift+click range) =====
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
        const enrich = document.getElementById('intel-enrich-btn');
        const graph = document.getElementById('intel-graph-btn');
        if (enrich) {
            enrich.innerHTML = enrich.innerHTML.replace(/Enrich \(\d+\)/, `Enrich (${count})`);
            enrich.disabled = count === 0;
        }
        if (graph) {
            graph.innerHTML = graph.innerHTML.replace(/Graph \(\d+\)/, `Graph (${count})`);
            graph.disabled = count === 0;
        }
        // Sync row classes
        $rows().querySelectorAll('tr[data-ip]').forEach(tr => {
            tr.classList.toggle('selected', selectedIPs.has(tr.dataset.ip));
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

    // Delegated row click handler
    document.getElementById('intel-rows').addEventListener('click', (e) => {
        const tr = e.target.closest('tr[data-ip]');
        if (!tr) return;
        const ip = tr.dataset.ip;
        if (e.shiftKey && lastClickedIP) {
            rangeSelectFromCurrentPage(lastClickedIP, ip);
        } else if (e.ctrlKey || e.metaKey) {
            toggleSelection(ip);
        } else {
            return; // plain click does nothing
        }
        lastClickedIP = ip;
        updateSelectionUI();
    });

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
    window.intelGraphSelection = function() {
        if (selectedIPs.size === 0) return;
        const gm = window.graphManager;
        const ips = Array.from(selectedIPs);
        if (!gm || gm.nodes.length === 0) {
            buildIntelGraph(ips);
            return;
        }
        // Prompt
        document.getElementById('intel-modal-node-count').textContent = gm.nodes.length;
        pendingGraphAction = ips;
        document.getElementById('intel-graph-confirm').classList.add('active');
    };

    window.intelGraphConfirmCancel = function() {
        pendingGraphAction = null;
        document.getElementById('intel-graph-confirm').classList.remove('active');
    };

    window.intelGraphConfirmDiscard = function() {
        const ips = pendingGraphAction;
        pendingGraphAction = null;
        document.getElementById('intel-graph-confirm').classList.remove('active');
        if (ips) buildIntelGraph(ips);
    };

    window.intelGraphConfirmSave = function() {
        const ips = pendingGraphAction;
        pendingGraphAction = null;
        document.getElementById('intel-graph-confirm').classList.remove('active');
        if (!ips) return;
        const gm = window.graphManager;
        const wasModified = gm.isModified;
        const saveModal = document.getElementById('graph-save-modal');
        if (!gm || !saveModal) {
            buildIntelGraph(ips);
            return;
        }
        // Open save modal; poll until it closes (saved or cancelled)
        gm.saveGraph();
        const start = Date.now();
        const tick = () => {
            const stillOpen = saveModal.classList.contains('active');
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
    };

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
})();

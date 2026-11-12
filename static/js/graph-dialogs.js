// Workspace: graph dialogs (node details, save/load, add node/connection, IOC import, Shodan pivot).

// Every graph dialog is a native <dialog>. The "active" class mirrors the open state because
// other workspace scripts check it (for example the Intel browser waits for the save dialog to close).
const GRAPH_DIALOG_IDS = ['add-connection-modal', 'graph-save-modal', 'graph-load-modal',
    'graph-prompt-modal', 'add-node-modal', 'bulk-graph-modal', 'shodan-pivot-modal'];

function openGraphDialog(id) {
    const dialog = document.getElementById(id);
    if (!dialog) return;
    if (!dialog.open) dialog.showModal();
    dialog.classList.add('active');
}

function closeGraphDialog(id) {
    const dialog = document.getElementById(id);
    if (!dialog) return;
    if (dialog.open) dialog.close();
    dialog.classList.remove('active');
}

function closeGraphSaveModalBtn() { closeGraphDialog('graph-save-modal'); }
function closeGraphLoadModalBtn() { closeGraphDialog('graph-load-modal'); }
function closeGraphPromptModalBtn() { closeGraphDialog('graph-prompt-modal'); }
function closeAddConnectionModalBtn() { closeGraphDialog('add-connection-modal'); }
function closeAddNodeModalBtn() { closeGraphDialog('add-node-modal'); }

// ========== Bulk Graph Modal ==========
let bulkGraphData = { ips: [], domains: [] };
let selectedBulkFile = null;

function showBulkGraphModal() {
    // Reset state
    bulkGraphData = { ips: [], domains: [] };
    selectedBulkFile = null;
    document.getElementById('bulk-text-input').value = '';
    document.getElementById('bulk-url-input').value = '';
    document.getElementById('bulk-file-input').value = '';
    document.getElementById('bulk-create-btn-text').textContent = 'Create graph';
    document.getElementById('bulk-file-selected').style.display = 'none';
    document.getElementById('bulk-status').style.display = 'none';
    document.getElementById('bulk-results').style.display = 'none';
    document.getElementById('bulk-create-btn').disabled = true;
    switchBulkTab('text');

    openGraphDialog('bulk-graph-modal');
}

function closeBulkGraphModalBtn() {
    closeGraphDialog('bulk-graph-modal');
}

function switchBulkTab(tabName) {
    if (!['text', 'url', 'file'].includes(tabName)) return;
    document.querySelectorAll('.bulk-tab').forEach(t => {
        const on = t.dataset.bulkTab === tabName;
        t.classList.toggle('on', on);
        t.setAttribute('aria-pressed', on ? 'true' : 'false');
    });
    ['text', 'url', 'file'].forEach(name => {
        document.getElementById(`bulk-panel-${name}`).classList.toggle('hide', name !== tabName);
    });
}

async function extractFromText() {
    const text = document.getElementById('bulk-text-input').value.trim();
    if (!text) {
        showToast('Please enter some text to extract IOCs from', 'error');
        return;
    }
    await performExtraction({ text });
}

async function extractFromUrl() {
    const url = document.getElementById('bulk-url-input').value.trim();
    if (!url) {
        showToast('Please enter a URL', 'error');
        return;
    }
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        showToast('Please enter a valid URL starting with http:// or https://', 'error');
        return;
    }
    await performExtraction({ url });
}

function handleBulkFileSelect(event) {
    const file = event.target.files[0];
    if (file) {
        selectedBulkFile = file;
        document.getElementById('bulk-file-name').textContent = file.name;
        document.getElementById('bulk-file-selected').style.display = 'flex';
    }
}

function handleBulkFileDrop(event) {
    event.preventDefault();
    document.getElementById('bulk-file-dropzone').classList.remove('dragover');

    const file = event.dataTransfer.files[0];
    if (file) {
        selectedBulkFile = file;
        document.getElementById('bulk-file-name').textContent = file.name;
        document.getElementById('bulk-file-selected').style.display = 'flex';
    }
}

async function extractFromFile() {
    if (!selectedBulkFile) {
        showToast('Please select a file', 'error');
        return;
    }

    const formData = new FormData();
    formData.append('file', selectedBulkFile);

    await performExtraction(formData, true);
}

async function performExtraction(data, isFormData = false) {
    const statusDiv = document.getElementById('bulk-status');
    const resultsDiv = document.getElementById('bulk-results');

    statusDiv.style.display = 'block';
    resultsDiv.style.display = 'none';

    try {
        const response = await csrfFetch('/api/ioc/extract', {
            method: 'POST',
            headers: isFormData ? {} : { 'Content-Type': 'application/json' },
            body: isFormData ? data : JSON.stringify(data)
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Extraction failed');
        }

        // Log extraction capabilities
        console.log('IOC Extraction Result:', {
            ips: result.ips?.length || 0,
            domains: result.domains?.length || 0,
            defang_support: result.defang_support,
            tld_validation: result.tld_validation
        });

        if (!result.defang_support) {
            console.warn('IOC Extraction: Defanged IOC support not available (iocextract not installed)');
        }
        if (!result.tld_validation) {
            console.warn('IOC Extraction: TLD validation not available (tldextract not installed)');
        }

        bulkGraphData = {
            ips: result.ips || [],
            domains: result.domains || []
        };

        displayBulkResults();

    } catch (error) {
        showToast(`Extraction failed: ${error.message}`, 'error');
    } finally {
        statusDiv.style.display = 'none';
    }
}

function displayBulkResults() {
    const resultsDiv = document.getElementById('bulk-results');

    // Update counts
    document.getElementById('bulk-ip-count').textContent = bulkGraphData.ips.length;
    document.getElementById('bulk-domain-count').textContent = bulkGraphData.domains.length;
    document.getElementById('bulk-ip-count-2').textContent = bulkGraphData.ips.length;
    document.getElementById('bulk-domain-count-2').textContent = bulkGraphData.domains.length;

    // Populate the two checklists (values are untrusted: text nodes only)
    fillBulkList(document.getElementById('bulk-ips-list'), bulkGraphData.ips, 'ip');
    fillBulkList(document.getElementById('bulk-domains-list'), bulkGraphData.domains, 'domain');

    // Reset checkboxes
    document.getElementById('bulk-include-ips').checked = true;
    document.getElementById('bulk-include-domains').checked = true;

    // Show results
    resultsDiv.style.display = 'block';

    updateBulkSelection();
}

function fillBulkList(container, values, type) {
    const fragment = document.createDocumentFragment();
    values.forEach((value, i) => {
        const item = document.createElement('label');
        item.className = 'bulk-ioc-item';
        const box = document.createElement('input');
        box.type = 'checkbox';
        box.className = 'check';
        box.checked = true;
        box.dataset.type = type;
        box.dataset.index = String(i);
        const text = document.createElement('span');
        text.textContent = value;
        item.append(box, text);
        fragment.append(item);
    });
    container.replaceChildren(fragment);
}

function updateBulkSelection() {
    const includeIps = document.getElementById('bulk-include-ips').checked;
    const includeDomains = document.getElementById('bulk-include-domains').checked;

    // Update individual checkboxes based on master checkbox
    document.querySelectorAll('#bulk-ips-list input[type="checkbox"]').forEach(cb => {
        cb.checked = includeIps;
        cb.closest('.bulk-ioc-item').classList.toggle('excluded', !includeIps);
    });
    document.querySelectorAll('#bulk-domains-list input[type="checkbox"]').forEach(cb => {
        cb.checked = includeDomains;
        cb.closest('.bulk-ioc-item').classList.toggle('excluded', !includeDomains);
    });

    updateBulkCount();
}

// Recount after the master or a single checkbox changed
function updateBulkCount() {
    document.querySelectorAll('#bulk-ips-list input[type="checkbox"], #bulk-domains-list input[type="checkbox"]').forEach(cb => {
        cb.closest('.bulk-ioc-item').classList.toggle('excluded', !cb.checked);
    });

    // Count selected
    const selectedIps = document.querySelectorAll('#bulk-ips-list input[type="checkbox"]:checked').length;
    const selectedDomains = document.querySelectorAll('#bulk-domains-list input[type="checkbox"]:checked').length;
    const total = selectedIps + selectedDomains;

    // Update button
    const createBtn = document.getElementById('bulk-create-btn');
    const createBtnText = document.getElementById('bulk-create-btn-text');
    createBtn.disabled = total === 0;
    createBtnText.textContent = total > 0 ? `Create graph (${total} IOCs)` : 'Create graph';
}

async function createBulkGraph() {
    const gm = window.graphManager;
    if (!gm) {
        showToast('Graph manager not initialized', 'error');
        return;
    }

    // Collect selected IOCs
    const selectedIps = [];
    const selectedDomains = [];

    document.querySelectorAll('#bulk-ips-list input[type="checkbox"]:checked').forEach(cb => {
        const index = parseInt(cb.dataset.index);
        selectedIps.push(bulkGraphData.ips[index]);
    });

    document.querySelectorAll('#bulk-domains-list input[type="checkbox"]:checked').forEach(cb => {
        const index = parseInt(cb.dataset.index);
        selectedDomains.push(bulkGraphData.domains[index]);
    });

    const total = selectedIps.length + selectedDomains.length;
    if (total === 0) {
        showToast('No IOCs selected', 'error');
        return;
    }

    const autoEnrich = document.getElementById('bulk-auto-enrich').checked;

    // Close modal
    closeBulkGraphModalBtn();

    // Switch to graph tab
    switchTab('graph');

    // Show loading state
    showToast(`Creating graph with ${total} IOCs...`, 'info');

    // Reset graph state directly (avoid newGraph() which has confirm dialog)
    gm.nodes = [];
    gm.edges = [];
    gm.graphId = null;
    gm.graphName = 'Bulk Import';
    gm.isModified = false;

    // Clear any pending geo queue from previous graph
    if (gm.geoQueueTimer) {
        clearTimeout(gm.geoQueueTimer);
        gm.geoQueueTimer = null;
    }
    gm.pendingGeoIPs.clear();

    // Show the graph visualization
    gm.showGraph();

    // Add IPs first - queueGeoResolution will be called automatically for each
    // which handles Geo/ASN enrichment
    for (let i = 0; i < selectedIps.length; i++) {
        gm.addNode(selectedIps[i], 'ip', i === 0); // First IP is origin
    }

    // Add domains - use addDomainWithTLD to auto-extract base domains
    for (let i = 0; i < selectedDomains.length; i++) {
        // First domain is origin only if there are no IPs
        const isOrigin = selectedIps.length === 0 && i === 0;
        gm.addDomainWithTLD(selectedDomains[i], isOrigin);
    }

    // Render initial graph
    gm.render();

    // Trigger enrichment if enabled
    if (autoEnrich) {
        // Geo/ASN enrichment for IPs
        if (selectedIps.length > 0) {
            // Clear the debounced timer and process immediately
            if (gm.geoQueueTimer) {
                clearTimeout(gm.geoQueueTimer);
                gm.geoQueueTimer = null;
            }
            // Add all IPs to pending queue and process
            selectedIps.forEach(ip => gm.pendingGeoIPs.add(ip));
            console.log('Bulk Graph: Triggering geo enrichment for', selectedIps.length, 'IPs');
            gm.processGeoQueue();
        }

        // DNS resolution for all nodes
        console.log('Bulk Graph: Triggering DNS resolution');
        // Use setTimeout to let geo enrichment start first
        setTimeout(() => {
            gm.resolveAllDNS();
        }, 100);
    } else if (gm.geoQueueTimer) {
        // Cancel pending geo queue if auto-enrich is disabled
        clearTimeout(gm.geoQueueTimer);
        gm.pendingGeoIPs.clear();
    }

    showToast(`Graph created with ${gm.nodes.length} nodes`, 'success');
}

// Shodan Pivot modal functions
function closeShodanPivotModalBtn() {
    closeGraphDialog('shodan-pivot-modal');
    window.shodanPivotState = null;
}

// Shodan queryable filters (from https://beta.shodan.io/search/filters)
const SHODAN_QUERYABLE_FILTERS = new Set([
    'asn', 'city', 'country', 'geo', 'hash', 'has_ipv6', 'has_screenshot', 'has_ssl',
    'hostname', 'ip', 'isp', 'link', 'net', 'org', 'os', 'port', 'postal', 'product',
    'region', 'scan', 'state', 'version',
    'cloud.provider', 'cloud.region', 'cloud.service',
    'http.component', 'http.component_category', 'http.favicon.hash', 'http.headers_hash',
    'http.html', 'http.html_hash', 'http.robots_hash', 'http.status', 'http.title', 'http.waf',
    'screenshot.hash', 'screenshot.label',
    'snmp.contact', 'snmp.location', 'snmp.name',
    'ssl.alpn', 'ssl.cert.alg', 'ssl.cert.expired', 'ssl.cert.extension', 'ssl.cert.fingerprint',
    'ssl.cert.issuer.cn', 'ssl.cert.pubkey.bits', 'ssl.cert.pubkey.type', 'ssl.cert.serial',
    'ssl.cert.subject.cn', 'ssl.chain_count', 'ssl.cipher.bits', 'ssl.cipher.name',
    'ssl.cipher.version', 'ssl.ja3s', 'ssl.jarm', 'ssl.version',
    'telnet.do', 'telnet.dont', 'telnet.option', 'telnet.will', 'telnet.wont'
]);

// Excluded filters (user specified)
const SHODAN_EXCLUDED_FILTERS = new Set(['tag', 'vuln', 'tags', 'vulns']);

// State for current pivot
window.shodanPivotState = null;

function flattenShodanData(obj, prefix = '', result = {}) {
    // Flatten nested Shodan data to dot-notation paths
    // Normalizes paths by stripping 'data.' prefix since Shodan nests service data under 'data' array
    if (obj === null || obj === undefined) return result;

    if (Array.isArray(obj)) {
        // For arrays, flatten each element
        obj.forEach((item, index) => {
            if (typeof item === 'object' && item !== null) {
                // For 'data' array elements, don't add 'data.' to their child paths
                // since Shodan filters don't use this prefix
                const childPrefix = (prefix === 'data') ? '' : prefix;
                flattenShodanData(item, childPrefix, result);
            } else if (item !== null && item !== undefined && item !== '') {
                // For primitive values in arrays, use the prefix without trailing dot
                let key = prefix.replace(/\.$/, '');
                // Normalize: strip leading 'data.' 
                if (key.startsWith('data.')) key = key.substring(5);
                else if (key === 'data') key = '';
                if (key) {
                    if (!result[key]) result[key] = new Set();
                    result[key].add(item);
                }
            }
        });
    } else if (typeof obj === 'object') {
        for (const [key, value] of Object.entries(obj)) {
            let newPrefix = prefix ? `${prefix}.${key}` : key;
            // Normalize: strip leading 'data.' from paths
            if (newPrefix.startsWith('data.')) newPrefix = newPrefix.substring(5);

            if (typeof value === 'object' && value !== null) {
                flattenShodanData(value, newPrefix, result);
            } else if (value !== null && value !== undefined && value !== '') {
                if (!result[newPrefix]) result[newPrefix] = new Set();
                result[newPrefix].add(value);
            }
        }
    }

    return result;
}

function normalizeFilterPath(path) {
    // Strip leading "data." prefix from paths since Shodan nests service data under "data" array
    // but the query filters don't use this prefix
    if (path.startsWith('data.')) {
        return path.substring(5);
    }
    return path;
}

function isQueryableFilter(path) {
    // Normalize the path first (strip data. prefix) - in case it wasn't already normalized
    const normalizedPath = normalizeFilterPath(path);

    // Check if the path or any of its parent paths are queryable
    if (SHODAN_EXCLUDED_FILTERS.has(normalizedPath) || SHODAN_EXCLUDED_FILTERS.has(normalizedPath.split('.')[0])) {
        return false;
    }

    // Direct match
    if (SHODAN_QUERYABLE_FILTERS.has(normalizedPath)) return true;

    // Check if parent path is queryable (e.g., ssl.cert.issuer.cn)
    const parts = normalizedPath.split('.');
    for (let i = parts.length; i > 0; i--) {
        const subPath = parts.slice(0, i).join('.');
        if (SHODAN_QUERYABLE_FILTERS.has(subPath)) return true;
    }

    return false;
}

function filterPivotAttributes(searchText) {
    const search = searchText.toLowerCase();
    const items = document.querySelectorAll('.pivot-attribute-item');
    items.forEach(item => {
        const text = item.textContent.toLowerCase();
        item.style.display = text.includes(search) ? '' : 'none';
    });
}

function updatePivotQueryPreview() {
    const checked = document.querySelectorAll('.pivot-attribute-checkbox:checked');
    const previewDiv = document.getElementById('pivot-query-preview');
    const previewText = document.getElementById('pivot-query-text');
    const executeBtn = document.getElementById('pivot-execute-btn');

    if (checked.length === 0) {
        previewDiv.style.display = 'none';
        executeBtn.disabled = true;
        return;
    }

    // Group values by filter name
    const filterGroups = {};

    checked.forEach(cb => {
        const filter = cb.dataset.filter;
        const value = cb.dataset.value;
        console.log('[Shodan Pivot] Checkbox:', filter, '=', value);

        if (!filterGroups[filter]) {
            filterGroups[filter] = [];
        }
        filterGroups[filter].push(value);
    });

    // Build query: OR within same filter (comma), AND between filters (space)
    const queryParts = [];
    for (const [filter, values] of Object.entries(filterGroups)) {
        if (values.length === 1) {
            // Single value - quote if has spaces
            const quotedValue = values[0].includes(' ') ? `"${values[0]}"` : values[0];
            queryParts.push(`${filter}:${quotedValue}`);
        } else {
            // Multiple values - join with comma (OR in Shodan)
            // Quote individual values if they have spaces
            const quotedValues = values.map(v => v.includes(' ') ? `"${v}"` : v);
            queryParts.push(`${filter}:${quotedValues.join(',')}`);
        }
    }

    const query = queryParts.join(' ');
    console.log('[Shodan Pivot] Built query:', query);

    // Build explanation text
    const filterCount = Object.keys(filterGroups).length;
    const multiValueFilters = Object.entries(filterGroups)
        .filter(([f, v]) => v.length > 1)
        .map(([f, v]) => `${f} (${v.length} values OR'd)`);

    const code = document.createElement('code');
    code.className = 'code';
    code.textContent = query;
    previewText.replaceChildren(code);

    if (multiValueFilters.length > 0 || filterCount > 1) {
        const info = document.createElement('div');
        info.className = 'pivot-query-info';
        if (multiValueFilters.length > 0) {
            const strong = document.createElement('strong');
            strong.textContent = multiValueFilters.join(', ');
            info.append(strong);
        }
        if (filterCount > 1) {
            info.append((multiValueFilters.length > 0 ? ' \u2022 ' : '') + `${filterCount} filters AND'd together`);
        }
        previewText.append(info);
    }

    previewDiv.style.display = 'block';
    executeBtn.disabled = false;

    // Store query in state
    if (window.shodanPivotState) {
        window.shodanPivotState.query = query;
    }
}

async function executeShodanPivot() {
    if (!window.shodanPivotState || !window.shodanPivotState.query) {
        showToast('No query selected', 'error');
        return;
    }

    const { query, sourceIp, nodeId } = window.shodanPivotState;
    console.log('[Shodan Pivot] Executing query:', query, 'from source:', sourceIp);

    const executeBtn = document.getElementById('pivot-execute-btn');
    const originalText = executeBtn.textContent;

    executeBtn.disabled = true;
    executeBtn.textContent = 'Searching...';

    try {
        const response = await csrfFetch('/api/shodan/pivot', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                query: query,
                source_ip: sourceIp
            })
        });

        const result = await response.json();

        if (result.error) {
            showToast(result.error, 'error');
            return;
        }

        // Close modal
        closeShodanPivotModalBtn();

        // Log response for debugging
        console.log('[Shodan Pivot] Query:', query);
        console.log('[Shodan Pivot] Response:', result);

        // Add results to graph
        const gm = window.graphManager;
        if (!gm) return;

        // Filter hosts (excluding source IP)
        const validHosts = (result.hosts || []).filter(host => host.ip && host.ip !== sourceIp);

        // If no hosts found, just show a message and don't add anything to graph
        if (validHosts.length === 0) {
            const totalInfo = result.total_results > 0 
                ? ` (Shodan reports ${result.total_results} total, but all were filtered out)`
                : '';
            showToast(`Pivot found 0 matching hosts${totalInfo}`, 'info');
            console.log('[Shodan Pivot] 0 valid hosts. Source IP:', sourceIp, 'Raw hosts:', result.hosts);
            return;
        }

        // Create pivot node for the query
        const pivotNodeId = `pivot:${query}`;
        gm.addNode(pivotNodeId, 'pivot', false, { query: query });

        // Connect source IP to pivot node
        gm.addEdge(nodeId, pivotNodeId, 'Pivot Source');

        // Add result IPs and connect to pivot node
        for (const host of validHosts) {
            gm.addNode(host.ip, 'ip', false);
            gm.addEdge(pivotNodeId, host.ip, 'Pivot Result');
        }

        gm.render();

        const limitMsg = result.limited ? ` (limited from ${result.total_results} total)` : '';
        showToast(`Pivot found ${validHosts.length} hosts${limitMsg}`, 'success');

    } catch (err) {
        console.error('Pivot error:', err);
        showToast('Failed to execute pivot query: ' + err.message, 'error');
    } finally {
        executeBtn.textContent = originalText;
        executeBtn.disabled = false;
    }
}

function updateAddNodePlaceholder() {
    const type = document.getElementById('add-node-type').value;
    const input = document.getElementById('add-node-value');
    const info = document.getElementById('add-node-info');

    const placeholders = {
        'ip': 'e.g., 8.8.8.8 or 2001:4860:4860::8888',
        'domain': 'e.g., example.com',
        'email': 'e.g., admin@example.com',
        'registrant': 'e.g., John Doe',
        'org': 'e.g., Acme Corporation',
        'asn': 'e.g., AS15169_Google',
        'country': 'e.g., US or United States',
        'port': 'e.g., 443 or 8080',
        'tag': 'e.g., cdn or self-signed'
    };

    input.placeholder = placeholders[type] || 'Enter value...';

    // Show/hide enrichment info for IPs and domains
    info.classList.toggle('hide', !(type === 'ip' || type === 'domain'));
}
function submitAddNode() {
    const type = document.getElementById('add-node-type').value;
    const value = document.getElementById('add-node-value').value.trim();

    if (!value) {
        alert('Please enter a value');
        return;
    }

    if (window.graphManager) {
        window.graphManager.addNodeFromModal(value, type);
    }

    // Clear and close
    document.getElementById('add-node-value').value = '';
    closeAddNodeModalBtn();
}

// ---- wiring (no inline handlers in the templates) ----
document.addEventListener('DOMContentLoaded', function() {
    const byId = (id) => document.getElementById(id);
    const on = (id, type, handler) => { const el = byId(id); if (el) el.addEventListener(type, handler); };
    const gm = () => window.graphManager;

    // Keep the "active" class in step with the dialog however it was closed (button, Esc, backdrop)
    GRAPH_DIALOG_IDS.forEach(id => {
        on(id, 'close', () => {
            byId(id).classList.remove('active');
            if (id === 'shodan-pivot-modal') window.shodanPivotState = null;
        });
    });

    // Add connection
    on('connection-relationship', 'change', function() {
        byId('custom-relationship-group').style.display = this.value === 'custom' ? '' : 'none';
    });
    on('add-connection-confirm-btn', 'click', () => gm() && gm().confirmAddConnection());

    // Save, add-to-graph prompt
    on('graph-save-confirm-btn', 'click', () => gm() && gm().confirmSave());
    on('graph-save-name', 'keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); if (gm()) gm().confirmSave(); }
    });
    on('graph-prompt-new-btn', 'click', () => gm() && gm().createNewGraph());
    on('graph-prompt-add-btn', 'click', () => gm() && gm().addToExistingGraph());

    // Open a saved graph
    on('load-graphs-list', 'click', (e) => {
        const item = e.target.closest('.load-graph-item');
        if (item && gm()) gm().loadGraphFromModal(item.dataset.graphId);
    });

    // Add node
    on('add-node-type', 'change', updateAddNodePlaceholder);
    on('add-node-value', 'keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); submitAddNode(); }
    });
    on('add-node-submit-btn', 'click', submitAddNode);

    // Bulk IOC import
    document.querySelectorAll('.bulk-tab').forEach(tab => {
        tab.addEventListener('click', () => switchBulkTab(tab.dataset.bulkTab));
    });
    on('bulk-extract-text-btn', 'click', extractFromText);
    on('bulk-extract-url-btn', 'click', extractFromUrl);
    on('bulk-extract-file-btn', 'click', extractFromFile);
    on('bulk-file-input', 'change', handleBulkFileSelect);
    on('bulk-file-dropzone', 'dragover', (e) => { e.preventDefault(); byId('bulk-file-dropzone').classList.add('dragover'); });
    on('bulk-file-dropzone', 'dragleave', () => byId('bulk-file-dropzone').classList.remove('dragover'));
    on('bulk-file-dropzone', 'drop', handleBulkFileDrop);
    on('bulk-include-ips', 'change', updateBulkSelection);
    on('bulk-include-domains', 'change', updateBulkSelection);
    on('bulk-ips-list', 'change', updateBulkCount);
    on('bulk-domains-list', 'change', updateBulkCount);
    on('bulk-create-btn', 'click', createBulkGraph);

    // Shodan pivot
    on('pivot-attribute-search', 'input', function() { filterPivotAttributes(this.value); });
    on('pivot-attributes-list', 'change', updatePivotQueryPreview);
    on('pivot-execute-btn', 'click', executeShodanPivot);

    // Check for shared results to load
    if (document.body.dataset.sharedResults) {
        loadSharedResults(document.body.dataset.sharedResults);
    }
});

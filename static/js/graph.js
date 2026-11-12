// Workspace page: infrastructure graph (GraphManager), its table view and graph statistics.
// Markup: templates/workspace/_graph.html and _graph_dialogs.html. Styles: static/css/graph.css.

(function() {
    'use strict';

    // Toasts come from workspace.js (window.showToast, same signature).

    class GraphManager {
        constructor() {
            this.nodes = [];
            this.edges = [];
            this.graphId = null;
            this.graphName = 'Untitled Graph';
            this.isModified = false;
            this.showEdgeLabels = true;
            this.currentView = 'graph'; // 'graph' or 'table'
            this.simulation = null;
            this.svg = null;
            this.zoom = null;
            this.pendingValue = null;
            this.pendingType = null;
            this.selectedNode = null;
            this.contextMenuNode = null;

            // Physics settings with defaults
            this.physicsSettings = {
                linkDistance: 100,
                linkStrength: 0.3,
                charge: -300,
                collision: 35,
                center: 0.05,
                decay: 0.02
            };
            this.physicsPanelOpen = false;

            // Filter settings
            this.filterPanelOpen = false;
            this.hiddenNodeTypes = new Set();
            this.hiddenEdgeTypes = new Set();
            this.knownNodeTypes = new Map(); // type -> count (persists across renders)
            this.knownEdgeTypes = new Map(); // type -> count (persists across renders)

            // Search settings
            this.searchResults = [];
            this.searchSelectedIndex = -1;

            // Auto Geo enrichment queue
            this.pendingGeoIPs = new Set();
            this.geoQueueTimer = null;

            // View state: is a graph on screen, and the canvas size the simulation was centred for
            this.graphVisible = false;
            this.lastWidth = 0;
            this.lastHeight = 0;
            this.palette = null;

            this.init();
        }

        init() {
            this.loadSavedGraphsList();

            // Check URL for graph ID
            const urlParams = new URLSearchParams(window.location.search);
            const graphId = urlParams.get('graph');
            if (graphId) {
                this.loadGraph(graphId);
            }

            this.bindUI();
            this.updateHeader();

            // Click outside to close search results
            document.addEventListener('click', (e) => {
                const searchContainer = document.querySelector('.graph-search-container');
                if (searchContainer && !searchContainer.contains(e.target)) {
                    document.getElementById('graph-search-results').classList.remove('active');
                }
            });

            // Keyboard shortcut for search (Ctrl+F or /)
            document.addEventListener('keydown', (e) => {
                // Only while the graph view is open, a graph is on the canvas and no dialog is in front
                const panel = document.getElementById('graph-panel');
                const searchInput = document.getElementById('graph-search-input');
                if (!panel || !panel.classList.contains('active') || !searchInput || searchInput.offsetParent === null) return;
                if (document.querySelector('dialog[open]')) return;
                if ((e.ctrlKey && e.key === 'f') || (e.key === '/' && !e.target.matches('input, textarea, select'))) {
                    e.preventDefault();
                    searchInput.focus();
                    searchInput.select();
                }
            });

            // Keep the simulation centred when the canvas changes size (view switch, full screen, window resize)
            const canvas = document.getElementById('graph-visualization');
            if (canvas && window.ResizeObserver) {
                new ResizeObserver(() => this.handleResize()).observe(canvas);
            }
        }

        // ========== UI wiring (the templates carry no inline handlers) ==========

        bindUI() {
            const byId = (id) => document.getElementById(id);
            const on = (id, type, handler) => {
                const el = byId(id);
                if (el) el.addEventListener(type, handler);
            };

            // Header: view switch and file actions
            document.addEventListener('click', (e) => {
                // Canvas / Table. The copies in the Stats view are links to #graph, which then opens this view.
                const viewSwitch = e.target.closest('[data-graph-view]');
                if (viewSwitch) this.setView(viewSwitch.dataset.graphView);
            });
            on('load-graph-btn', 'click', () => this.showLoadModal());
            on('save-graph-btn', 'click', () => this.saveGraph());
            on('share-graph-btn', 'click', () => this.shareCurrentGraph());
            on('export-png-btn', 'click', () => this.exportPNG());
            on('export-json-btn', 'click', () => this.exportJSON());
            on('new-graph-btn', 'click', () => this.newGraph());
            on('add-node-btn', 'click', () => this.showAddNodeModal());
            on('graph-stats-refresh-btn', 'click', () => window.refreshGraphStats());

            // Drop-down menus (Export, Resolve all) and the node menu close on any click elsewhere
            document.addEventListener('click', (e) => {
                const trigger = e.target.closest('[data-gmenu]');
                const target = trigger ? byId(trigger.dataset.gmenu) : null;
                const wasOpen = !!target && target.classList.contains('open');
                this.closeMenus();
                if (target && !wasOpen) {
                    target.classList.add('open');
                    trigger.setAttribute('aria-expanded', 'true');
                }
                const nodeMenu = byId('node-context-menu');
                if (nodeMenu) nodeMenu.classList.remove('active');
            });

            // Esc closes an open menu first, then leaves full screen
            document.addEventListener('keydown', (e) => {
                if (e.key !== 'Escape') return;
                const nodeMenu = byId('node-context-menu');
                if (document.querySelector('.gmenu.open') || (nodeMenu && nodeMenu.classList.contains('active'))) {
                    this.closeMenus();
                    this.hideContextMenu();
                    return;
                }
                if (document.querySelector('dialog[open]')) return;
                if (e.target.matches && e.target.matches('input, textarea, select')) return;
                const container = byId('graph-container');
                if (container && container.classList.contains('fullscreen')) this.toggleFullscreen();
            });

            // Canvas tools
            on('graph-search-input', 'input', (e) => this.handleSearchInput(e.target.value));
            on('graph-search-input', 'keydown', (e) => this.handleSearchKeydown(e));
            on('graph-search-results', 'click', (e) => {
                const item = e.target.closest('.search-result-item');
                if (item) {
                    e.preventDefault();
                    e.stopPropagation();
                    this.selectSearchResult(parseInt(item.dataset.index, 10));
                }
            });
            on('graph-search-results', 'mouseover', (e) => {
                const item = e.target.closest('.search-result-item');
                if (!item) return;
                const index = parseInt(item.dataset.index, 10);
                if (index !== this.searchSelectedIndex) {
                    this.searchSelectedIndex = index;
                    // Update selection highlight without full re-render
                    byId('graph-search-results').querySelectorAll('.search-result-item').forEach((el, i) => {
                        el.classList.toggle('selected', i === index);
                    });
                }
            });
            on('freeze-all-btn', 'click', () => this.toggleFreezeAll());
            on('resolve-all-dns-btn', 'click', () => this.resolveAllDNS());
            on('resolve-all-whois-btn', 'click', () => this.resolveAllWhois());
            on('resolve-all-geo-btn', 'click', () => this.resolveAllGeo());
            on('resolve-all-idb-btn', 'click', () => this.resolveAllIDB());
            on('filter-panel-btn', 'click', () => this.toggleFilterPanel());
            on('filter-panel-close', 'click', () => this.toggleFilterPanel());
            on('physics-panel-btn', 'click', () => this.togglePhysicsPanel());
            on('physics-panel-close', 'click', () => this.togglePhysicsPanel());
            on('edge-labels-toggle', 'click', () => this.toggleEdgeLabels());
            on('fullscreen-toggle', 'click', () => this.toggleFullscreen());

            // Layout (physics) panel: sliders carry the property name and the divisor for their value
            on('physics-panel', 'input', (e) => {
                const slider = e.target.closest('[data-physics]');
                if (!slider) return;
                const divisor = parseFloat(slider.dataset.divisor) || 1;
                this.updatePhysics(slider.dataset.physics, parseFloat(slider.value) / divisor);
            });
            on('physics-panel', 'click', (e) => {
                const preset = e.target.closest('[data-preset]');
                if (preset) this.applyPhysicsPreset(preset.dataset.preset);
            });
            on('physics-reset-btn', 'click', () => this.applyPhysicsPreset('default'));

            // Filter panel
            on('filter-panel', 'click', (e) => {
                const all = e.target.closest('[data-filter-all]');
                const none = e.target.closest('[data-filter-none]');
                if (all) {
                    if (all.dataset.filterAll === 'node') this.showAllNodeTypes(); else this.showAllEdgeTypes();
                } else if (none) {
                    if (none.dataset.filterNone === 'node') this.hideAllNodeTypes(); else this.hideAllEdgeTypes();
                }
            });
            on('filter-node-types', 'change', (e) => {
                const item = e.target.closest('.filter-item');
                if (item) this.toggleNodeTypeVisibility(item.dataset.type);
            });
            on('filter-edge-types', 'change', (e) => {
                const item = e.target.closest('.filter-item');
                if (item) this.toggleEdgeTypeVisibility(item.dataset.type);
            });

            // Node panel
            on('graph-node-close', 'click', () => this.clearSelection());
            on('enrich-node-btn', 'click', () => this.enrichNode());
            on('whois-node-btn', 'click', () => this.resolveWhois());
            on('geo-node-btn', 'click', () => this.resolveGeoFromModal());
            on('circl-download-btn', 'click', () => { if (this.selectedNode) this.downloadCirclPDNS(this.selectedNode); });
            on('remove-node-btn', 'click', () => this.removeNode());
            on('graph-node-content', 'click', (e) => {
                const button = e.target.closest('[data-node-action]');
                if (!button || !this.selectedNode) return;
                switch (button.dataset.nodeAction) {
                    case 'download-whois': this.downloadWhoisJSON(this.selectedNode.id); break;
                    case 'download-shodan': this.downloadShodanJSON(this.selectedNode.id); break;
                    case 'download-jarm': this.downloadJARMPivotJSON(this.selectedNode.id); break;
                    case 'download-pdns': this.downloadCirclPDNS(this.selectedNode); break;
                }
            });

            // Node right-click menu
            on('node-context-menu', 'click', (e) => {
                const trigger = e.target.closest('.submenu-trigger');
                if (trigger) {
                    // Open the ViewDNS submenu on click too (hover and keyboard focus open it through CSS)
                    e.stopPropagation();
                    const open = trigger.parentElement.classList.toggle('open');
                    trigger.setAttribute('aria-expanded', open ? 'true' : 'false');
                    return;
                }
                const item = e.target.closest('[data-action]');
                if (item) this.contextMenuAction(item.dataset.action);
            });

            // Empty state
            on('graph-start-btn', 'click', () => this.startFromInput());
            on('graph-start-input', 'keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    this.startFromInput();
                }
            });
            on('graph-bulk-btn', 'click', () => showBulkGraphModal());
            on('saved-graphs-list', 'click', (e) => {
                const button = e.target.closest('[data-saved-action]');
                const row = e.target.closest('.saved-graph-item');
                if (!button || !row) return;
                const graphId = row.dataset.graphId;
                switch (button.dataset.savedAction) {
                    case 'open': this.loadGraph(graphId); break;
                    case 'share': this.shareGraph(graphId); break;
                    case 'unshare': this.unshareGraph(graphId); break;
                    case 'delete': this.deleteGraph(graphId); break;
                }
            });

            // Table view
            on('graph-table-search', 'input', (e) => this.filterTable(e.target.value));
            on('graph-table-csv-btn', 'click', () => this.downloadTableCSV());
            on('graph-table-body', 'click', (e) => {
                const button = e.target.closest('[data-remove-edge]');
                const row = button && button.closest('tr');
                if (row) this.removeEdgeFromTable(row.dataset.source, row.dataset.target);
            });
        }

        closeMenus() {
            document.querySelectorAll('.gmenu.open').forEach(menu => menu.classList.remove('open'));
            document.querySelectorAll('[data-gmenu]').forEach(trigger => trigger.setAttribute('aria-expanded', 'false'));
        }

        // A one-line note for lists that are empty, loading or failed
        noteElement(text, className = 'empty') {
            const note = document.createElement('div');
            note.className = className;
            note.textContent = text;
            return note;
        }

        // ========== Saved Graphs ==========

        async loadSavedGraphsList() {
            const container = document.getElementById('saved-graphs-list');
            try {
                const response = await csrfFetch('/api/graph/list');
                const data = await response.json();

                if (data.graphs && data.graphs.length > 0) {
                    const action = (label, name, title, extraClass = '') => {
                        const button = document.createElement('button');
                        button.type = 'button';
                        button.className = `btn sm ${extraClass}`.trim();
                        button.dataset.savedAction = name;
                        button.textContent = label;
                        button.title = title;
                        return button;
                    };

                    const fragment = document.createDocumentFragment();
                    data.graphs.forEach(g => {
                        const row = document.createElement('div');
                        row.className = 'line saved-graph-item';
                        row.dataset.graphId = g.id;

                        const open = document.createElement('button');
                        open.type = 'button';
                        open.className = 'grow saved-graph-open';
                        open.dataset.savedAction = 'open';
                        open.title = 'Open this graph';
                        const name = document.createElement('b');
                        name.className = 'saved-graph-name';
                        name.textContent = g.name;
                        const date = document.createElement('small');
                        date.className = 'saved-graph-date';
                        date.textContent = new Date(g.updated_at).toLocaleDateString();
                        open.append(name, date);
                        row.append(open);

                        if (g.is_shared) {
                            const shared = document.createElement('span');
                            shared.className = 'tag green';
                            shared.textContent = 'shared';
                            row.append(shared);
                        }
                        row.append(action(g.is_shared ? 'Copy link' : 'Share', 'share', g.is_shared ? 'Copy share link' : 'Share and copy link'));
                        if (g.is_shared) row.append(action('Stop sharing', 'unshare', 'Stop sharing'));
                        row.append(action('Delete', 'delete', 'Delete this graph', 'danger'));
                        fragment.append(row);
                    });
                    container.replaceChildren(fragment);
                } else {
                    container.replaceChildren(this.noteElement('No saved graphs yet'));
                }
            } catch (err) {
                console.error('Failed to load graphs:', err);
                container.replaceChildren(this.noteElement('Failed to load saved graphs', 'card-b red'));
            }
        }

        async loadGraph(graphId) {
            try {
                const response = await csrfFetch(`/api/graph/${graphId}`);
                if (!response.ok) throw new Error('Graph not found');

                const graph = await response.json();

                // Check if user owns this graph
                const isOwner = graph.is_owner;

                if (isOwner) {
                    // User owns this graph - load normally
                    this.graphId = graph.id;
                    this.graphName = graph.name;
                } else {
                    // User doesn't own this graph - create a copy
                    this.graphId = null;  // Will generate new ID on save
                    this.graphName = graph.name + ' (Copy)';
                    showToast('Opened shared graph as your own copy', 'info');
                }

                this.nodes = graph.data.nodes || [];
                this.edges = graph.data.edges || [];
                this.isModified = !isOwner;  // Mark as modified if it's a copy

                // Restore physics settings if saved
                if (graph.data.physics) {
                    this.physicsSettings = { ...this.physicsSettings, ...graph.data.physics };
                    this.updatePhysicsUI();
                }

                // Reset filter state for new graph
                this.hiddenNodeTypes.clear();
                this.hiddenEdgeTypes.clear();
                this.knownNodeTypes.clear();
                this.knownEdgeTypes.clear();

                // Switch to graph tab
                switchTab('graph');

                this.showGraph();
                this.render();

                // Update URL only if owner
                if (isOwner) {
                    window.history.replaceState({}, '', `?graph=${graphId}`);
                } else {
                    window.history.replaceState({}, '', '#graph');
                }

                // Update the header (name and counts)
                this.updateHeader();

            } catch (err) {
                console.error('Failed to load graph:', err);
                alert('Failed to load graph');
            }
        }

        async deleteGraph(graphId) {
            if (!confirm('Are you sure you want to delete this graph?')) return;

            try {
                await csrfFetch(`/api/graph/${graphId}`, { method: 'DELETE' });
                this.loadSavedGraphsList();

                if (this.graphId === graphId) {
                    this.reset();
                }
            } catch (err) {
                console.error('Failed to delete graph:', err);
            }
        }

        async shareGraph(graphId) {
            try {
                // Sharing is explicit: the server marks the graph, then any signed-in user can open a copy
                const response = await csrfFetch(`/api/graph/${encodeURIComponent(graphId)}/share`, { method: 'POST' });
                const result = await response.json();
                if (!response.ok || result.error) throw new Error(result.error || 'Share failed');
                this.loadSavedGraphsList();
                try {
                    await navigator.clipboard.writeText(result.share_url);
                    showToast('Graph shared and link copied. Any signed-in user can open a copy.', 'success');
                } catch (clipboardErr) {
                    showToast('Graph shared: ' + result.share_url, 'success', 10000);
                }
            } catch (err) {
                console.error('Failed to share graph:', err);
                showToast('Failed to share graph', 'error');
            }
        }

        async unshareGraph(graphId) {
            try {
                const response = await csrfFetch(`/api/graph/${encodeURIComponent(graphId)}/share`, { method: 'DELETE' });
                if (!response.ok) throw new Error('Unshare failed');
                this.loadSavedGraphsList();
                showToast('Sharing stopped. The link no longer works for other users.', 'success');
            } catch (err) {
                console.error('Failed to stop sharing graph:', err);
                showToast('Failed to stop sharing', 'error');
            }
        }

        // ========== Graph Operations ==========

        promptGraph(value, type) {
            this.pendingValue = value;
            this.pendingType = type;

            if (this.nodes.length > 0) {
                // Show prompt modal
                document.getElementById('graph-prompt-value').textContent = value;
                openGraphDialog('graph-prompt-modal');
            } else {
                this.createNewGraph();
            }
        }

        createNewGraph() {
            closeGraphDialog('graph-prompt-modal');

            this.reset();
            this.addNode(this.pendingValue, this.pendingType, true);
            this.resolveAndExpand(this.pendingValue, this.pendingType);

            // Switch to graph tab
            switchTab('graph');
        }

        addToExistingGraph() {
            closeGraphDialog('graph-prompt-modal');

            if (!this.nodeExists(this.pendingValue)) {
                this.addNode(this.pendingValue, this.pendingType, false);
                this.resolveAndExpand(this.pendingValue, this.pendingType);
            }

            switchTab('graph');
        }

        reset() {
            this.nodes = [];
            this.edges = [];
            this.graphId = null;
            this.graphName = 'Untitled Graph';
            this.isModified = false;

            // Reset physics to defaults
            this.physicsSettings = {
                linkDistance: 100,
                linkStrength: 0.3,
                charge: -300,
                collision: 35,
                center: 0.05,
                decay: 0.02
            };
            this.updatePhysicsUI();

            // Reset filter state
            this.hiddenNodeTypes.clear();
            this.hiddenEdgeTypes.clear();
            this.knownNodeTypes.clear();
            this.knownEdgeTypes.clear();

            window.history.replaceState({}, '', window.location.pathname);

            this.hideGraph();
        }

        nodeExists(value) {
            return this.nodes.some(n => n.id.toLowerCase() === value.toLowerCase());
        }

        getNode(value) {
            return this.nodes.find(n => n.id.toLowerCase() === value.toLowerCase());
        }

        addNode(value, type, isOrigin = false) {
            // Check if node already exists (case-insensitive)
            const existing = this.getNode(value);
            if (existing) return existing;  // Return existing node instead of null

            const node = {
                id: value,
                type: type, // 'ip', 'domain', 'tld', 'registrant', 'email', 'org', 'registrar', 'asn', 'country', 'basedomain'
                isOrigin: isOrigin,
                data: {
                    dnsResolved: false,
                    whoisResolved: false
                }
            };

            this.nodes.push(node);
            this.isModified = true;

            // Auto-queue IP for Geo resolution
            if (type === 'ip') {
                this.queueGeoResolution(value);
            }

            return node;
        }

        queueGeoResolution(ip) {
            // Add IP to pending queue
            this.pendingGeoIPs.add(ip);

            // Debounce: wait 500ms after last IP added before processing
            if (this.geoQueueTimer) {
                clearTimeout(this.geoQueueTimer);
            }

            this.geoQueueTimer = setTimeout(() => {
                this.processGeoQueue();
            }, 500);
        }

        async processGeoQueue() {
            if (this.pendingGeoIPs.size === 0) return;

            // Get IPs from queue and clear it
            const ips = [...this.pendingGeoIPs];
            this.pendingGeoIPs.clear();

            // Filter to only IPs that haven't been resolved yet
            const unresolvedIPs = ips.filter(ip => {
                const node = this.nodes.find(n => n.id === ip && n.type === 'ip');
                return node && (!node.data || !node.data.geoResolved);
            });

            if (unresolvedIPs.length === 0) return;

            console.log('Auto Geo: Processing queue for IPs:', unresolvedIPs);

            try {
                const response = await csrfFetch('/api/graph/enrich', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ips: unresolvedIPs })
                });

                const result = await response.json();

                if (result.error) {
                    console.error('Auto Geo enrichment failed:', result.error);
                    return;
                }

                if (result.geo_data) {
                    let nodesAdded = false;

                    for (const ip of unresolvedIPs) {
                        const ipNode = this.nodes.find(n => n.id === ip && n.type === 'ip');
                        if (!ipNode) continue;

                        const geoInfo = result.geo_data[ip];

                        if (geoInfo) {
                            // Store geo data on node
                            ipNode.data = ipNode.data || {};
                            ipNode.data.geo = geoInfo;
                            ipNode.data.geoResolved = true;
                            this.isModified = true;

                            // Add ASN node if present
                            if (geoInfo.asn || geoInfo.asn_id) {
                                let asnNodeId;
                                if (geoInfo.asn_id) {
                                    asnNodeId = geoInfo.asn_name 
                                        ? `${geoInfo.asn_id}_${geoInfo.asn_name}`
                                        : geoInfo.asn_id;
                                } else {
                                    asnNodeId = geoInfo.asn;
                                }

                                const asnNode = this.addNode(asnNodeId, 'asn', false);
                                if (asnNode) {
                                    asnNode.data = {
                                        asn_id: geoInfo.asn_id || '',
                                        asn_name: geoInfo.asn_name || '',
                                        asn_org: geoInfo.org || ''
                                    };
                                    nodesAdded = true;
                                }
                                this.addEdge(ip, asnNodeId, 'ASN');
                            }

                            // Add Country node if present
                            if (geoInfo.country) {
                                const countryNode = this.addNode(geoInfo.country, 'country', false);
                                if (countryNode) nodesAdded = true;
                                this.addEdge(ip, geoInfo.country, 'country');
                            }
                        } else {
                            // Mark as resolved even if no data found
                            ipNode.data = ipNode.data || {};
                            ipNode.data.geoResolved = true;
                        }
                    }

                    // Re-render if nodes were added
                    if (nodesAdded) {
                        this.render();
                    }
                }

            } catch (err) {
                console.error('Auto Geo resolution failed:', err);
            }
        }

        addEdge(source, target, relationship) {
            // Normalize source and target to match actual node IDs
            const sourceNode = this.getNode(source);
            const targetNode = this.getNode(target);

            if (!sourceNode || !targetNode) {
                console.warn(`addEdge: Cannot create edge, missing node. Source: ${source} (${!!sourceNode}), Target: ${target} (${!!targetNode})`);
                return;
            }

            // Use the actual node IDs (which may differ in case)
            const sourceId = sourceNode.id;
            const targetId = targetNode.id;

            // Check if edge already exists (handle both string IDs and D3's node object references)
            const exists = this.edges.some(e => {
                const eSource = typeof e.source === 'object' ? e.source.id : e.source;
                const eTarget = typeof e.target === 'object' ? e.target.id : e.target;
                return (eSource === sourceId && eTarget === targetId) ||
                       (eSource === targetId && eTarget === sourceId);
            });

            if (!exists) {
                this.edges.push({
                    source: sourceId,
                    target: targetId,
                    relationship: relationship
                });
                this.isModified = true;
            }
        }

        // ========== DNS Resolution ==========

        isIPv6(ip) {
            return ip.includes(':');
        }

        /**
         * Check if a string is a valid IP address (IPv4 or IPv6)
         */
        isValidIP(value) {
            if (!value || typeof value !== 'string') return false;

            // IPv4 pattern
            const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
            if (ipv4Pattern.test(value)) {
                // Verify each octet is 0-255
                const octets = value.split('.');
                return octets.every(octet => {
                    const num = parseInt(octet, 10);
                    return num >= 0 && num <= 255;
                });
            }

            // IPv6 pattern (simplified - contains colons and valid hex chars)
            if (value.includes(':')) {
                const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
                return ipv6Pattern.test(value) || /^::$/.test(value) || /^::1$/.test(value);
            }

            return false;
        }

        extractTLD(domain) {
            // Extract TLD from domain using PSL library for proper handling
            if (!domain || domain.includes('/')) return null;

            const cleanDomain = domain.toLowerCase().trim();

            // Use PSL library if available
            if (typeof psl !== 'undefined') {
                const parsed = psl.parse(cleanDomain);
                if (parsed && parsed.tld) {
                    return parsed.tld;
                }
            }

            // Fallback: simple extraction
            const parts = cleanDomain.split('.');
            if (parts.length < 2) return null;
            return parts[parts.length - 1];
        }

        extractBaseDomain(domain) {
            // Extract the registrable base domain (e.g., google.com from x.google.com)
            if (!domain || domain.includes('/')) return null;

            const cleanDomain = domain.toLowerCase().trim();

            // Use PSL library if available
            if (typeof psl !== 'undefined') {
                const parsed = psl.parse(cleanDomain);
                if (parsed && parsed.domain) {
                    return parsed.domain;
                }
            }

            // Fallback: simple extraction (last 2 parts, or 3 for known multi-part TLDs)
            const parts = cleanDomain.split('.');
            if (parts.length < 2) return null;

            const multiPartTLDs = ['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'co.jp', 'co.nz', 'co.za', 'com.au', 'org.au', 'com.br', 'co.in', 'com.cn'];
            if (parts.length >= 3) {
                const lastTwo = parts.slice(-2).join('.');
                if (multiPartTLDs.includes(lastTwo)) {
                    return parts.slice(-3).join('.');
                }
            }

            return parts.slice(-2).join('.');
        }

        isSubdomain(domain) {
            // Check if domain is a subdomain (has more parts than the base domain)
            if (!domain) return false;
            const baseDomain = this.extractBaseDomain(domain);
            return baseDomain && domain.toLowerCase() !== baseDomain.toLowerCase();
        }

        addDomainWithTLD(domain, isOrigin = false) {
            // Add domain node and extract/add its TLD and BaseDomain
            const node = this.addNode(domain, 'domain', isOrigin);

            if (node || this.nodeExists(domain)) {
                const baseDomain = this.extractBaseDomain(domain);

                // Check if this is a subdomain
                if (baseDomain && domain.toLowerCase() !== baseDomain.toLowerCase()) {
                    // This is a subdomain - add BaseDomain node and SubDomain edge
                    const baseDomainNode = this.addNode(baseDomain, 'basedomain', false);
                    this.addEdge(domain, baseDomain, 'SubDomain');

                    // Connect BaseDomain to TLD
                    const tld = this.extractTLD(baseDomain);
                    if (tld && tld !== baseDomain) {
                        this.addNode(tld, 'tld', false);
                        this.addEdge(baseDomain, tld, 'tld');
                    }
                } else {
                    // This is already a base domain - just connect to TLD
                    const tld = this.extractTLD(domain);
                    if (tld && tld !== domain) {
                        this.addNode(tld, 'tld', false);
                        this.addEdge(domain, tld, 'tld');
                    }
                }
            }

            return node;
        }

        async resolveAndExpand(value, type, skipRender = false) {
            this.showLoading(true);
            if (!skipRender) this.showGraph();

            // Mark this node as resolved
            const currentNode = this.nodes.find(n => n.id === value);
            if (currentNode) {
                currentNode.data = currentNode.data || {};
                currentNode.data.dnsResolved = true;
            }

            try {
                if (type === 'ip') {
                    // Determine record type based on IP version
                    const recordType = this.isIPv6(value) ? 'AAAA' : 'A';

                    // Get related domains from dataset
                    const related = await this.getRelatedFromDataset(value, 'ip');
                    const domainsToResolve = [];

                    for (const domain of related.domains || []) {
                        const node = this.addDomainWithTLD(domain, false);
                        if (node) {
                            this.addEdge(value, domain, recordType);
                            domainsToResolve.push(domain);
                        }
                    }

                    for (const tld of related.tlds || []) {
                        const node = this.addNode(tld, 'tld', false);
                        if (node) {
                            // Connect TLD to domains that have it
                            for (const domain of related.domains || []) {
                                if (domain.endsWith('.' + tld) || domain === tld) {
                                    this.addEdge(domain, tld, 'tld');
                                }
                            }
                        }
                    }

                    // Also do reverse DNS
                    const dnsResults = await this.resolveDNS([value], 'ip');
                    for (const ptr of dnsResults[value]?.PTR || []) {
                        const node = this.addDomainWithTLD(ptr, false);
                        if (node) {
                            this.addEdge(value, ptr, 'PTR');
                            domainsToResolve.push(ptr);
                        }
                    }

                    // Auto-resolve all discovered domains
                    if (domainsToResolve.length > 0) {
                        const domainDnsResults = await this.resolveDNS(domainsToResolve, 'domain');
                        for (const domain of domainsToResolve) {
                            // Mark domain as resolved
                            const domainNode = this.nodes.find(n => n.id === domain);
                            if (domainNode) {
                                domainNode.data = domainNode.data || {};
                                domainNode.data.dnsResolved = true;
                            }

                            const results = domainDnsResults[domain] || {};

                            // Add resolved IPs from domains
                            for (const ip of results.A || []) {
                                const node = this.addNode(ip, 'ip', false);
                                if (node) {
                                    this.addEdge(domain, ip, 'A');
                                }
                            }

                            for (const ip of results.AAAA || []) {
                                const node = this.addNode(ip, 'ip', false);
                                if (node) {
                                    this.addEdge(domain, ip, 'AAAA');
                                }
                            }

                            for (const cname of results.CNAME || []) {
                                const node = this.addDomainWithTLD(cname, false);
                                if (node) {
                                    this.addEdge(domain, cname, 'CNAME');
                                }
                            }

                            // Add NS records
                            for (const ns of results.NS || []) {
                                const node = this.addDomainWithTLD(ns, false);
                                if (node) {
                                    this.addEdge(domain, ns, 'NS');
                                }
                            }
                        }
                    }

                    // Process geo data returned from the API
                    if (related.geo_data && related.geo_data[value]) {
                        const geoInfo = related.geo_data[value];

                        // Store geo data on node
                        if (currentNode) {
                            currentNode.data.geo = geoInfo;
                            currentNode.data.geoResolved = true;
                        }

                        // Add ASN node if present
                        if (geoInfo.asn || geoInfo.asn_id) {
                            // Create ASN node ID as "ID_NAME" to avoid collisions
                            // If we have asn_id, use that as the base
                            let asnNodeId;
                            if (geoInfo.asn_id) {
                                asnNodeId = geoInfo.asn_name 
                                    ? `${geoInfo.asn_id}_${geoInfo.asn_name}`
                                    : geoInfo.asn_id;
                            } else {
                                asnNodeId = geoInfo.asn;
                            }

                            const asnNode = this.addNode(asnNodeId, 'asn', false);
                            if (asnNode) {
                                asnNode.data = {
                                    asn_id: geoInfo.asn_id || '',
                                    asn_name: geoInfo.asn_name || '',
                                    asn_org: geoInfo.org || ''
                                };
                            }
                            this.addEdge(value, asnNodeId, 'ASN');
                        }

                        // Add Country node if present
                        if (geoInfo.country) {
                            this.addNode(geoInfo.country, 'country', false);
                            this.addEdge(value, geoInfo.country, 'country');
                        }
                    }

                } else {
                    // Domain - resolve DNS
                    const dnsResults = await this.resolveDNS([value], 'domain');
                    const results = dnsResults[value] || {};

                    // Extract and add TLD for the source domain
                    const tld = this.extractTLD(value);
                    if (tld && tld !== value) {
                        this.addNode(tld, 'tld', false);
                        this.addEdge(value, tld, 'tld');
                    }

                    // Add resolved IPs
                    for (const ip of results.A || []) {
                        const node = this.addNode(ip, 'ip', false);
                        if (node) {
                            this.addEdge(value, ip, 'A');
                        }
                    }

                    for (const ip of results.AAAA || []) {
                        const node = this.addNode(ip, 'ip', false);
                        if (node) {
                            this.addEdge(value, ip, 'AAAA');
                        }
                    }

                    for (const cname of results.CNAME || []) {
                        const node = this.addDomainWithTLD(cname, false);
                        if (node) {
                            this.addEdge(value, cname, 'CNAME');
                        }
                    }

                    for (const mx of results.MX || []) {
                        const node = this.addDomainWithTLD(mx, false);
                        if (node) {
                            this.addEdge(value, mx, 'MX');
                        }
                    }

                    // Add NS records (nameservers)
                    for (const ns of results.NS || []) {
                        const node = this.addDomainWithTLD(ns, false);
                        if (node) {
                            this.addEdge(value, ns, 'NS');
                        }
                    }

                    // Add SOA record (primary nameserver)
                    for (const soa of results.SOA || []) {
                        const node = this.addDomainWithTLD(soa, false);
                        if (node) {
                            this.addEdge(value, soa, 'SOA');
                        }
                    }

                    // Get related IPs, domains, and TLDs from dataset
                    const related = await this.getRelatedFromDataset(value, 'domain');
                    for (const ip of related.ips || []) {
                        // Determine record type based on IP version
                        const recordType = this.isIPv6(ip) ? 'AAAA' : 'A';
                        const node = this.addNode(ip, 'ip', false);
                        if (node) {
                            this.addEdge(value, ip, recordType);
                        }
                    }

                    for (const domain of related.domains || []) {
                        const node = this.addDomainWithTLD(domain, false);
                        if (node) {
                            this.addEdge(value, domain, 'related');
                        }
                    }

                    for (const tld of related.tlds || []) {
                        const node = this.addNode(tld, 'tld', false);
                        if (node) {
                            this.addEdge(value, tld, 'tld');
                        }
                    }

                    // Process geo data for discovered IPs
                    if (related.geo_data) {
                        for (const [ip, geoInfo] of Object.entries(related.geo_data)) {
                            const ipNode = this.nodes.find(n => n.id === ip);
                            if (ipNode) {
                                ipNode.data = ipNode.data || {};
                                ipNode.data.geo = geoInfo;
                                ipNode.data.geoResolved = true;

                                // Add ASN node if present
                                // Add ASN node if present
                                if (geoInfo.asn || geoInfo.asn_id) {
                                    // Create ASN node ID as "ID_NAME" to avoid collisions
                                    let asnNodeId;
                                    if (geoInfo.asn_id) {
                                        asnNodeId = geoInfo.asn_name 
                                            ? `${geoInfo.asn_id}_${geoInfo.asn_name}`
                                            : geoInfo.asn_id;
                                    } else {
                                        asnNodeId = geoInfo.asn;
                                    }

                                    const asnNode = this.addNode(asnNodeId, 'asn', false);
                                    if (asnNode) {
                                        asnNode.data = {
                                            asn_id: geoInfo.asn_id || '',
                                            asn_name: geoInfo.asn_name || '',
                                            asn_org: geoInfo.org || ''
                                        };
                                    }
                                    this.addEdge(ip, asnNodeId, 'ASN');
                                }

                                // Add Country node if present
                                if (geoInfo.country) {
                                    this.addNode(geoInfo.country, 'country', false);
                                    this.addEdge(ip, geoInfo.country, 'country');
                                }
                            }
                        }
                    }
                }

            } catch (err) {
                console.error('Failed to resolve:', err);
            } finally {
                this.showLoading(false);
                if (!skipRender) this.render();
            }
        }

        // ========== Bulk Resolution Functions ==========

        async resolveAllDNS() {
            // Find all unresolved IP and domain nodes
            const unresolvedNodes = this.nodes.filter(n => 
                (n.type === 'ip' || n.type === 'domain') && 
                (!n.data || !n.data.dnsResolved)
            );

            if (unresolvedNodes.length === 0) {
                showToast('All nodes have already been DNS resolved.', 'info');
                return;
            }

            const btn = document.getElementById('resolve-all-dns-btn');
            const originalHTML = btn.innerHTML;
            btn.disabled = true;
            btn.textContent = 'Resolving...';

            this.showLoading(true);

            try {
                // Separate IPs and domains
                const ipNodes = unresolvedNodes.filter(n => n.type === 'ip');
                const domainNodes = unresolvedNodes.filter(n => n.type === 'domain');

                const total = unresolvedNodes.length;
                btn.textContent = `DNS ${total}...`;

                // Bulk resolve domains
                if (domainNodes.length > 0) {
                    const domainQueries = domainNodes.map(n => n.id);
                    const dnsResponse = await csrfFetch('/api/dns/resolve-bulk', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ queries: domainQueries, type: 'domain' })
                    });
                    const dnsData = await dnsResponse.json();

                    if (dnsData.results) {
                        for (const domainNode of domainNodes) {
                            const dnsResults = dnsData.results[domainNode.id];
                            if (dnsResults) {
                                domainNode.data = domainNode.data || {};
                                domainNode.data.dns = dnsResults;
                                domainNode.data.dnsResolved = true;
                                this.isModified = true;

                                // Add resolved IPs as nodes
                                const ips = [];
                                if (dnsResults.A) ips.push(...dnsResults.A);
                                if (dnsResults.AAAA) ips.push(...dnsResults.AAAA);

                                for (const ip of ips) {
                                    this.addNode(ip, 'ip', false);
                                    this.addEdge(domainNode.id, ip, 'A');
                                }

                                // Extract and add TLD
                                const tld = this.extractTLD(domainNode.id);
                                if (tld && tld !== domainNode.id) {
                                    this.addNode(tld, 'tld', false);
                                    this.addEdge(domainNode.id, tld, 'tld');
                                }
                            }
                        }
                    }
                }

                // Bulk resolve IPs (reverse DNS)
                if (ipNodes.length > 0) {
                    const ipQueries = ipNodes.map(n => n.id);
                    const ptrResponse = await csrfFetch('/api/dns/resolve-bulk', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ queries: ipQueries, type: 'ip' })
                    });
                    const ptrData = await ptrResponse.json();

                    if (ptrData.results) {
                        for (const ipNode of ipNodes) {
                            const ptrResults = ptrData.results[ipNode.id];
                            if (ptrResults) {
                                ipNode.data = ipNode.data || {};
                                ipNode.data.dns = ptrResults;
                                ipNode.data.dnsResolved = true;
                                this.isModified = true;

                                // Add PTR domains as nodes
                                if (ptrResults.PTR && ptrResults.PTR.length > 0) {
                                    for (const ptr of ptrResults.PTR) {
                                        this.addDomainWithTLD(ptr, false);
                                        this.addEdge(ipNode.id, ptr, 'PTR');
                                    }
                                }
                            }
                        }
                    }
                }

                // Now fetch related data from enrichment for all nodes
                for (const node of unresolvedNodes) {
                    try {
                        const response = await csrfFetch('/api/graph/related', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                value: node.id,
                                type: node.type
                            })
                        });

                        const related = await response.json();

                        if (!related.error) {
                            // Add related IPs
                            if (related.ips) {
                                for (const ip of related.ips) {
                                    const ipNode = this.addNode(ip, 'ip', false);
                                    this.addEdge(node.id, ip, 'A');
                                }
                            }

                            // Add related domains
                            if (related.domains) {
                                for (const domain of related.domains) {
                                    this.addDomainWithTLD(domain, false);
                                    this.addEdge(node.id, domain, 'resolves');
                                }
                            }

                            // Process geo data
                            if (related.geo_data) {
                                for (const [ip, geoInfo] of Object.entries(related.geo_data)) {
                                    const ipNode = this.nodes.find(n => n.id === ip);
                                    if (ipNode) {
                                        ipNode.data = ipNode.data || {};
                                        ipNode.data.geo = geoInfo;
                                        ipNode.data.geoResolved = true;

                                        // Add ASN node if present
                                        if (geoInfo.asn || geoInfo.asn_id) {
                                            let asnNodeId;
                                            if (geoInfo.asn_id) {
                                                asnNodeId = geoInfo.asn_name 
                                                    ? `${geoInfo.asn_id}_${geoInfo.asn_name}`
                                                    : geoInfo.asn_id;
                                            } else {
                                                asnNodeId = geoInfo.asn;
                                            }

                                            const asnNode = this.addNode(asnNodeId, 'asn', false);
                                            if (asnNode) {
                                                asnNode.data = {
                                                    asn_id: geoInfo.asn_id || '',
                                                    asn_name: geoInfo.asn_name || '',
                                                    asn_org: geoInfo.org || ''
                                                };
                                            }
                                            this.addEdge(ip, asnNodeId, 'ASN');
                                        }

                                        // Add Country node if present
                                        if (geoInfo.country) {
                                            this.addNode(geoInfo.country, 'country', false);
                                            this.addEdge(ip, geoInfo.country, 'country');
                                        }
                                    }
                                }
                            }
                        }
                    } catch (err) {
                        console.warn(`Related lookup failed for ${node.id}:`, err);
                    }
                }

                this.render();
                showToast(`DNS resolved ${unresolvedNodes.length} nodes`, 'success');

            } catch (err) {
                console.error('Bulk DNS resolution failed:', err);
                showToast('Some DNS resolutions failed: ' + err.message, 'error');
            } finally {
                this.showLoading(false);
                btn.disabled = false;
                btn.innerHTML = originalHTML;
            }
        }

        async resolveAllWhois() {
            // Find all unresolved domain nodes
            const unresolvedDomains = this.nodes.filter(n => 
                n.type === 'domain' && 
                (!n.data || !n.data.whoisResolved)
            );

            if (unresolvedDomains.length === 0) {
                showToast('All domains have already been WHOIS resolved.', 'info');
                return;
            }

            const btn = document.getElementById('resolve-all-whois-btn');
            const originalHTML = btn.innerHTML;
            btn.disabled = true;
            btn.textContent = 'WHOIS...';

            this.showLoading(true);

            try {
                const domains = unresolvedDomains.map(n => n.id);
                btn.textContent = `WHOIS ${domains.length}...`;

                // Use bulk endpoint for concurrent resolution
                const response = await csrfFetch('/api/whois/resolve-bulk', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domains })
                });

                const bulkData = await response.json();

                if (bulkData.error) {
                    showToast('WHOIS resolution failed: ' + bulkData.error, 'error');
                    return;
                }

                // Process results
                let successCount = 0;
                for (const domainNode of unresolvedDomains) {
                    const data = bulkData.results[domainNode.id];

                    if (data && !data.error) {
                        // Store WHOIS data in node
                        domainNode.data = domainNode.data || {};
                        domainNode.data.whois = data;
                        domainNode.data.whoisResolved = true;
                        this.isModified = true;
                        successCount++;

                        // Add all names as registrant nodes
                        if (data.all_names && data.all_names.length > 0) {
                            for (const name of data.all_names) {
                                const node = this.addNode(name, 'registrant', false);
                                if (node) {
                                    node.data = { entityType: 'registrant_name' };
                                }
                                this.addEdge(domainNode.id, name, 'registrant');
                            }
                        } else if (data.registrant_name) {
                            const node = this.addNode(data.registrant_name, 'registrant', false);
                            if (node) {
                                node.data = { entityType: 'registrant_name' };
                            }
                            this.addEdge(domainNode.id, data.registrant_name, 'registrant');
                        }

                        // Add all emails as email nodes
                        if (data.all_emails && data.all_emails.length > 0) {
                            for (const email of data.all_emails) {
                                const node = this.addNode(email, 'email', false);
                                if (node) {
                                    node.data = { entityType: 'registrant_email' };
                                }
                                this.addEdge(domainNode.id, email, 'email');
                            }
                        } else if (data.registrant_email) {
                            const node = this.addNode(data.registrant_email, 'email', false);
                            if (node) {
                                node.data = { entityType: 'registrant_email' };
                            }
                            this.addEdge(domainNode.id, data.registrant_email, 'email');
                        }

                        // Add all organizations as org nodes
                        if (data.all_organizations && data.all_organizations.length > 0) {
                            for (const org of data.all_organizations) {
                                const node = this.addNode(org, 'org', false);
                                if (node) {
                                    node.data = { entityType: 'organization' };
                                }
                                this.addEdge(domainNode.id, org, 'org');
                            }
                        } else if (data.organization) {
                            const node = this.addNode(data.organization, 'org', false);
                            if (node) {
                                node.data = { entityType: 'organization' };
                            }
                            this.addEdge(domainNode.id, data.organization, 'org');
                        }

                        // Add all registrars as registrar nodes
                        if (data.all_registrars && data.all_registrars.length > 0) {
                            for (const registrar of data.all_registrars) {
                                const registrarId = `registrar:${registrar}`;
                                const node = this.addNode(registrarId, 'registrar', false);
                                if (node) {
                                    node.data = { entityType: 'registrar', name: registrar };
                                }
                                this.addEdge(domainNode.id, registrarId, 'Registrar');
                            }
                        } else if (data.registrar) {
                            const registrarId = `registrar:${data.registrar}`;
                            const node = this.addNode(registrarId, 'registrar', false);
                            if (node) {
                                node.data = { entityType: 'registrar', name: data.registrar };
                            }
                            this.addEdge(domainNode.id, registrarId, 'Registrar');
                        }
                    } else {
                        // Mark as resolved even if failed to prevent retries
                        domainNode.data = domainNode.data || {};
                        domainNode.data.whoisResolved = true;
                        console.warn(`WHOIS failed for ${domainNode.id}:`, data?.error || 'Unknown error');
                    }
                }

                this.render();
                showToast(`WHOIS resolved ${successCount}/${domains.length} domains`, 'success');

            } catch (err) {
                console.error('Bulk WHOIS resolution failed:', err);
                showToast('Some WHOIS resolutions failed: ' + err.message, 'error');
            } finally {
                this.showLoading(false);
                btn.disabled = false;
                btn.innerHTML = originalHTML;
            }
        }

        async resolveAllGeo() {
            // Find all unresolved IP nodes
            const unresolvedIPs = this.nodes.filter(n => 
                n.type === 'ip' && 
                (!n.data || !n.data.geoResolved)
            );

            console.log('resolveAllGeo: Found unresolved IPs:', unresolvedIPs.map(n => n.id));

            if (unresolvedIPs.length === 0) {
                showToast('All IP nodes have already been geo resolved.', 'info');
                return;
            }

            const btn = document.getElementById('resolve-all-geo-btn');
            const originalHTML = btn.innerHTML;
            btn.disabled = true;
            btn.textContent = 'Enriching...';

            this.showLoading(true);

            try {
                // Batch request all IPs at once - use /api/graph/enrich to run LogBoost
                const ips = unresolvedIPs.map(n => n.id);

                console.log('resolveAllGeo: Enriching IPs via LogBoost:', ips);

                btn.textContent = `Enriching ${ips.length}...`;

                const response = await csrfFetch('/api/graph/enrich', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ips })
                });

                const result = await response.json();

                console.log('resolveAllGeo: Enrich API response:', result);

                if (result.error) {
                    showToast('Enrichment failed: ' + result.error, 'error');
                    return;
                }

                if (result.geo_data) {
                    console.log('resolveAllGeo: geo_data keys:', Object.keys(result.geo_data));

                    for (const ipNode of unresolvedIPs) {
                        const geoInfo = result.geo_data[ipNode.id];

                        console.log(`resolveAllGeo: Processing IP ${ipNode.id}, geoInfo:`, geoInfo);

                        if (geoInfo) {
                            // Store geo data on node
                            ipNode.data = ipNode.data || {};
                            ipNode.data.geo = geoInfo;
                            ipNode.data.geoResolved = true;
                            this.isModified = true;

                            // Add ASN node if present
                            if (geoInfo.asn || geoInfo.asn_id) {
                                // Create ASN node ID as "ID_NAME" to avoid collisions
                                let asnNodeId;
                                if (geoInfo.asn_id) {
                                    asnNodeId = geoInfo.asn_name 
                                        ? `${geoInfo.asn_id}_${geoInfo.asn_name}`
                                        : geoInfo.asn_id;
                                } else {
                                    asnNodeId = geoInfo.asn;
                                }

                                console.log(`resolveAllGeo: Adding ASN node: ${asnNodeId}`);
                                const asnNode = this.addNode(asnNodeId, 'asn', false);
                                if (asnNode) {
                                    asnNode.data = {
                                        asn_id: geoInfo.asn_id || '',
                                        asn_name: geoInfo.asn_name || '',
                                        asn_org: geoInfo.org || ''
                                    };
                                }
                                this.addEdge(ipNode.id, asnNodeId, 'ASN');
                            }

                            // Add Country node if present
                            if (geoInfo.country) {
                                console.log(`resolveAllGeo: Adding Country node: ${geoInfo.country}`);
                                const countryNode = this.addNode(geoInfo.country, 'country', false);
                                this.addEdge(ipNode.id, geoInfo.country, 'country');
                            }
                        } else {
                            // Mark as resolved even if no data found
                            ipNode.data = ipNode.data || {};
                            ipNode.data.geoResolved = true;
                        }
                    }
                }

                this.render();

            } catch (err) {
                console.error('Bulk geo resolution failed:', err);
                showToast('Geo resolution failed: ' + err.message, 'error');
            } finally {
                this.showLoading(false);
                btn.disabled = false;
                btn.innerHTML = originalHTML;
            }
        }

        async resolveDNS(queries, type) {
            try {
                const response = await csrfFetch('/api/dns/resolve', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ queries, type })
                });
                const data = await response.json();
                return data.results || {};
            } catch (err) {
                console.error('DNS resolution failed:', err);
                return {};
            }
        }

        async getRelatedFromDataset(value, type) {
            try {
                const response = await csrfFetch('/api/graph/related', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ value, type })
                });
                return await response.json();
            } catch (err) {
                console.error('Failed to get related:', err);
                return {};
            }
        }

        // ========== Node Actions ==========

        showNodeDetails(node) {
            this.selectedNode = node;

            const title = document.getElementById('graph-node-title');
            const content = document.getElementById('graph-node-content');

            // A refresh of the same node keeps its opened "View raw data" sections open
            const sameNode = content.dataset.nodeId === String(node.id);
            const openSections = sameNode ? [...content.querySelectorAll('details')].map(d => d.open) : [];

            title.textContent = node.id;

            // Show/hide WHOIS button based on node type (domain only)
            const whoisBtn = document.getElementById('whois-node-btn');
            whoisBtn.style.display = (node.type === 'domain') ? '' : 'none';

            // Show/hide Geo button based on node type (IP only)
            const geoBtn = document.getElementById('geo-node-btn');
            geoBtn.style.display = (node.type === 'ip') ? '' : 'none';

            // Show/hide CIRCL download button based on whether node has CIRCL data
            const circlBtn = document.getElementById('circl-download-btn');
            circlBtn.style.display = (node.data && node.data.circlPdns) ? '' : 'none';

            // Build content
            let html = '<div class="node-details">';
            html += `<div class="detail-row"><span class="detail-label">Type</span><span class="detail-value">${this.escapeHtml(String(node.type).toUpperCase())}</span></div>`;
            html += `<div class="detail-row"><span class="detail-label">Origin</span><span class="detail-value">${node.isOrigin ? 'Yes (starting point)' : 'No (discovered)'}</span></div>`;

            // Show ASN details if this is an ASN node
            if (node.type === 'asn' && node.data) {
                html += '<div class="detail-section"><h4>ASN Information</h4>';
                if (node.data.asn_id) html += `<div class="detail-row"><span class="detail-label">ASN ID</span><span class="detail-value">${this.escapeHtml(node.data.asn_id)}</span></div>`;
                if (node.data.asn_name) html += `<div class="detail-row"><span class="detail-label">Name</span><span class="detail-value">${this.escapeHtml(node.data.asn_name)}</span></div>`;
                if (node.data.asn_org) html += `<div class="detail-row"><span class="detail-label">Organization</span><span class="detail-value">${this.escapeHtml(node.data.asn_org)}</span></div>`;
                html += '</div>';
            }

            // Show Port details if this is a Port node
            if (node.type === 'port' && node.data) {
                html += '<div class="detail-section"><h4>Port Information</h4>';
                html += `<div class="detail-row"><span class="detail-label">Port Number</span><span class="detail-value">${this.escapeHtml(node.data.port)}</span></div>`;
                html += '</div>';
            }

            // Show Tag details if this is a Tag node
            if (node.type === 'tag' && node.data) {
                html += '<div class="detail-section"><h4>Tag Information</h4>';
                html += `<div class="detail-row"><span class="detail-label">Tag</span><span class="detail-value">${this.escapeHtml(node.data.tag)}</span></div>`;
                html += '</div>';
            }

            // Show Geo data if available (for IP nodes)
            if (node.data && node.data.geo) {
                const g = node.data.geo;
                html += '<div class="detail-section"><h4>Geo Information</h4>';
                if (g.country) html += `<div class="detail-row"><span class="detail-label">Country</span><span class="detail-value">${this.escapeHtml(g.country)}</span></div>`;
                if (g.city) html += `<div class="detail-row"><span class="detail-label">City</span><span class="detail-value">${this.escapeHtml(g.city)}</span></div>`;
                if (g.asn) html += `<div class="detail-row"><span class="detail-label">ASN</span><span class="detail-value">${this.escapeHtml(g.asn)}</span></div>`;
                if (g.org) html += `<div class="detail-row"><span class="detail-label">Organization</span><span class="detail-value">${this.escapeHtml(g.org)}</span></div>`;
                html += '</div>';
            }

            // Show IDB data if available (for IP nodes)
            if (node.data && node.data.idb) {
                const idb = node.data.idb;
                html += '<div class="detail-section"><h4>InternetDB Data</h4>';
                if (idb.ports && idb.ports.length > 0) html += `<div class="detail-row"><span class="detail-label">Open Ports</span><span class="detail-value">${idb.ports.map(p => this.escapeHtml(String(p))).join(', ')}</span></div>`;
                if (idb.tags && idb.tags.length > 0) html += `<div class="detail-row"><span class="detail-label">Tags</span><span class="detail-value">${idb.tags.map(t => this.escapeHtml(String(t))).join(', ')}</span></div>`;
                html += '</div>';
            }

            // Show WHOIS data if available (with download button)
            if (node.data && node.data.whois) {
                const w = node.data.whois;
                html += '<div class="detail-section">';
                html += '<div class="detail-section-header"><h4>WHOIS Information</h4>';
                html += `<button type="button" class="linkbtn detail-download-btn" data-node-action="download-whois" title="Download WHOIS JSON">`;
                html += 'Download';
                html += '</button></div>';
                if (w.registrant_name) html += `<div class="detail-row"><span class="detail-label">Registrant</span><span class="detail-value">${this.escapeHtml(w.registrant_name)}</span></div>`;
                if (w.registrant_email) html += `<div class="detail-row"><span class="detail-label">Email</span><span class="detail-value">${this.escapeHtml(w.registrant_email)}</span></div>`;
                if (w.organization) html += `<div class="detail-row"><span class="detail-label">Organization</span><span class="detail-value">${this.escapeHtml(w.organization)}</span></div>`;
                if (w.registrar) html += `<div class="detail-row"><span class="detail-label">Registrar</span><span class="detail-value">${this.escapeHtml(w.registrar)}</span></div>`;
                if (w.creation_date) html += `<div class="detail-row"><span class="detail-label">Created</span><span class="detail-value">${this.escapeHtml(w.creation_date)}</span></div>`;
                if (w.expiration_date) html += `<div class="detail-row"><span class="detail-label">Expires</span><span class="detail-value">${this.escapeHtml(w.expiration_date)}</span></div>`;
                if (w.name_servers && w.name_servers.length > 0) html += `<div class="detail-row"><span class="detail-label">Nameservers</span><span class="detail-value">${w.name_servers.map(ns => this.escapeHtml(ns)).join(', ')}</span></div>`;
                // Collapsible raw JSON
                html += '<details class="raw-data-details"><summary>View Raw WHOIS Data</summary>';
                html += `<pre class="raw-data-pre">${this.escapeHtml(JSON.stringify(w, null, 2))}</pre>`;
                html += '</details>';
                html += '</div>';
            }

            // Show Shodan data if available (with download button)
            if (node.data && node.data.shodan) {
                const s = node.data.shodan;
                html += '<div class="detail-section">';
                html += '<div class="detail-section-header"><h4>Shodan Information</h4>';
                html += `<button type="button" class="linkbtn detail-download-btn" data-node-action="download-shodan" title="Download Shodan JSON">`;
                html += 'Download';
                html += '</button></div>';

                // Organization & Network
                if (s.org) html += `<div class="detail-row"><span class="detail-label">Organization</span><span class="detail-value">${this.escapeHtml(s.org)}</span></div>`;
                if (s.isp) html += `<div class="detail-row"><span class="detail-label">ISP</span><span class="detail-value">${this.escapeHtml(s.isp)}</span></div>`;
                if (s.asn) html += `<div class="detail-row"><span class="detail-label">ASN</span><span class="detail-value">${this.escapeHtml(s.asn)}</span></div>`;

                // Location
                let location = [];
                if (s.city) location.push(s.city);
                if (s.region_code) location.push(s.region_code);
                if (s.country_name) location.push(s.country_name);
                if (location.length > 0) html += `<div class="detail-row"><span class="detail-label">Location</span><span class="detail-value">${this.escapeHtml(location.join(', '))}</span></div>`;
                if (s.latitude && s.longitude) html += `<div class="detail-row"><span class="detail-label">Coordinates</span><span class="detail-value">${this.escapeHtml(s.latitude)}, ${this.escapeHtml(s.longitude)}</span></div>`;

                // OS
                if (s.os) html += `<div class="detail-row"><span class="detail-label">OS</span><span class="detail-value">${this.escapeHtml(s.os)}</span></div>`;

                // Ports (numbers are safe but escape for defense in depth)
                if (s.ports && s.ports.length > 0) html += `<div class="detail-row"><span class="detail-label">Open Ports</span><span class="detail-value">${[...s.ports].sort((a,b) => a-b).map(p => this.escapeHtml(String(p))).join(', ')}</span></div>`;

                // Hostnames & Domains
                if (s.hostnames && s.hostnames.length > 0) html += `<div class="detail-row"><span class="detail-label">Hostnames</span><span class="detail-value">${s.hostnames.map(h => this.escapeHtml(h)).join(', ')}</span></div>`;
                if (s.domains && s.domains.length > 0) html += `<div class="detail-row"><span class="detail-label">Domains</span><span class="detail-value">${s.domains.map(d => this.escapeHtml(d)).join(', ')}</span></div>`;

                // Vulnerabilities (can be object keys or array)
                const vulns = s.vulns ? (Array.isArray(s.vulns) ? s.vulns : Object.keys(s.vulns)) : [];
                if (vulns.length > 0) {
                    html += `<div class="detail-row"><span class="detail-label">Vulnerabilities</span><span class="detail-value vuln-list">${vulns.map(v => `<span class="vuln-tag">${this.escapeHtml(v)}</span>`).join(' ')}</span></div>`;
                }

                // Tags
                if (s.tags && s.tags.length > 0) html += `<div class="detail-row"><span class="detail-label">Tags</span><span class="detail-value">${s.tags.map(t => this.escapeHtml(t)).join(', ')}</span></div>`;

                // Last Update
                if (s.last_update) html += `<div class="detail-row"><span class="detail-label">Last Scan</span><span class="detail-value">${this.escapeHtml(s.last_update)}</span></div>`;

                // Services from raw Shodan 'data' array
                const services = s.data || s.services || [];
                if (services.length > 0) {
                    html += '<details class="raw-data-details"><summary>View Services (' + Number(services.length) + ')</summary>';
                    html += '<div class="services-list">';
                    for (const svc of services) {
                        html += '<div class="service-item">';
                        html += `<strong>Port ${this.escapeHtml(String(svc.port))}/${this.escapeHtml(svc.transport || 'tcp')}</strong>`;
                        if (svc.product) html += ` - ${this.escapeHtml(svc.product)}${svc.version ? ' ' + this.escapeHtml(svc.version) : ''}`;
                        if (svc.http && svc.http.title) html += `<br><small>Title: ${this.escapeHtml(svc.http.title)}</small>`;
                        if (svc.http && svc.http.server) html += `<br><small>Server: ${this.escapeHtml(svc.http.server)}</small>`;
                        if (svc.ssl && svc.ssl.jarm) html += `<br><small>JARM: ${this.escapeHtml(svc.ssl.jarm.substring(0, 30))}...</small>`;
                        if (svc.ssl && svc.ssl.cert && svc.ssl.cert.subject) {
                            const cn = svc.ssl.cert.subject.CN || svc.ssl.cert.subject.cn || svc.ssl.cert.subject.commonName;
                            if (cn) html += `<br><small>Cert CN: ${this.escapeHtml(cn)}</small>`;
                        }
                        // Show banner snippet if available
                        const banner = svc.data || svc.banner;
                        if (banner && typeof banner === 'string' && banner.length > 0) {
                            const bannerSnippet = banner.substring(0, 100).replace(/[\r\n]+/g, ' ');
                            html += `<br><small class="banner-snippet">Banner: ${this.escapeHtml(bannerSnippet)}${banner.length > 100 ? '...' : ''}</small>`;
                        }
                        html += '</div>';
                    }
                    html += '</div></details>';
                }

                // Collapsible raw JSON
                html += '<details class="raw-data-details"><summary>View Raw Shodan Data</summary>';
                html += `<pre class="raw-data-pre">${this.escapeHtml(JSON.stringify(s, null, 2))}</pre>`;
                html += '</details>';
                html += '</div>';
            }

            // Show JARM details if this is a JARM node (with download button for pivot results)
            if (node.type === 'jarm' && node.data) {
                html += '<div class="detail-section">';
                html += '<div class="detail-section-header"><h4>JARM Information</h4>';
                if (node.data.pivot_results) {
                    html += `<button type="button" class="linkbtn detail-download-btn" data-node-action="download-jarm" title="Download JARM Pivot Results">`;
                    html += 'Download';
                    html += '</button>';
                }
                html += '</div>';
                if (node.data.host_count !== undefined) html += `<div class="detail-row"><span class="detail-label">Hosts with JARM</span><span class="detail-value">${this.escapeHtml(Number(node.data.host_count).toLocaleString())}</span></div>`;
                if (node.data.source_ip) html += `<div class="detail-row"><span class="detail-label">Source IP</span><span class="detail-value">${this.escapeHtml(node.data.source_ip)}</span></div>`;
                if (node.data.port) html += `<div class="detail-row"><span class="detail-label">Port</span><span class="detail-value">${this.escapeHtml(node.data.port)}</span></div>`;
                if (node.data.hostnames && node.data.hostnames.length > 0) {
                    html += `<div class="detail-row"><span class="detail-label">Hostnames</span><span class="detail-value">${node.data.hostnames.map(h => this.escapeHtml(h)).join(', ')}</span></div>`;
                }
                // Collapsible raw JSON for pivot results
                if (node.data.pivot_results) {
                    html += '<details class="raw-data-details"><summary>View Pivot Results</summary>';
                    html += `<pre class="raw-data-pre">${this.escapeHtml(JSON.stringify(node.data.pivot_results, null, 2))}</pre>`;
                    html += '</details>';
                }
                html += '</div>';
            }

            // Show CIRCL Passive DNS data if available
            if (node.data && node.data.circlPdns) {
                const pdns = node.data.circlPdns;
                html += '<div class="detail-section">';
                html += '<div class="detail-section-header"><h4>CIRCL Passive DNS</h4>';
                html += `<button type="button" class="linkbtn detail-download-btn" data-node-action="download-pdns" title="Download CIRCL PDNS JSON">`;
                html += 'Download';
                html += '</button></div>';

                html += `<div class="detail-row"><span class="detail-label">Records Found</span><span class="detail-value">${Number(pdns.length)}</span></div>`;

                if (node.data.circlPdnsFromCache) {
                    html += `<div class="detail-row"><span class="detail-label">From Cache</span><span class="detail-value">Yes (${this.escapeHtml(node.data.circlPdnsCachedAt || 'unknown time')})</span></div>`;
                }

                // Count by record type
                const typeCounts = {};
                for (const r of pdns) {
                    typeCounts[r.rrtype] = (typeCounts[r.rrtype] || 0) + 1;
                }
                const typeStr = Object.entries(typeCounts).map(([t, c]) => `${t}: ${c}`).join(', ');
                html += `<div class="detail-row"><span class="detail-label">Record Types</span><span class="detail-value">${this.escapeHtml(typeStr)}</span></div>`;

                // Show first/last seen from the records
                let firstSeen = Infinity;
                let lastSeen = 0;
                for (const r of pdns) {
                    if (r.time_first && r.time_first < firstSeen) firstSeen = r.time_first;
                    if (r.time_last && r.time_last > lastSeen) lastSeen = r.time_last;
                }
                if (firstSeen !== Infinity) {
                    html += `<div class="detail-row"><span class="detail-label">First Seen</span><span class="detail-value">${new Date(firstSeen * 1000).toLocaleDateString()}</span></div>`;
                }
                if (lastSeen !== 0) {
                    html += `<div class="detail-row"><span class="detail-label">Last Seen</span><span class="detail-value">${new Date(lastSeen * 1000).toLocaleDateString()}</span></div>`;
                }

                // Collapsible raw data
                html += '<details class="raw-data-details"><summary>View Raw PDNS Data</summary>';
                html += `<pre class="raw-data-pre">${this.escapeHtml(JSON.stringify(pdns, null, 2))}</pre>`;
                html += '</details>';
                html += '</div>';
            }

            // Get connected nodes (handle both string IDs and D3's node object references)
            const connections = this.edges.filter(e => {
                const sourceId = typeof e.source === 'object' ? e.source.id : e.source;
                const targetId = typeof e.target === 'object' ? e.target.id : e.target;
                return sourceId === node.id || targetId === node.id;
            });
            if (connections.length > 0) {
                html += `<div class="detail-row"><span class="detail-label">Connections</span><span class="detail-value">${connections.length}</span></div>`;
                html += '<div class="connection-list">';
                for (const conn of connections) {
                    const sourceId = typeof conn.source === 'object' ? conn.source.id : conn.source;
                    const targetId = typeof conn.target === 'object' ? conn.target.id : conn.target;
                    const other = sourceId === node.id ? targetId : sourceId;
                    html += `<div class="connection-item">${this.escapeHtml(other)} <span class="conn-type">(${this.escapeHtml(conn.relationship)})</span></div>`;
                }
                html += '</div>';
            }

            html += '</div>';
            content.innerHTML = html;
            content.dataset.nodeId = String(node.id);
            content.querySelectorAll('details').forEach((d, i) => {
                if (openSections[i]) d.open = true;
            });

            const count = connections.length;
            document.getElementById('graph-node-sub').textContent =
                `${String(node.type).toUpperCase()} \u00b7 ${node.isOrigin ? 'starting point' : 'discovered'} \u00b7 ` +
                `${count} connection${count === 1 ? '' : 's'}${node.frozen ? ' \u00b7 frozen' : ''}`;

            // Show the node in the docked panel and mark it on the canvas
            document.getElementById('graph-node-empty').hidden = true;
            document.getElementById('graph-node-detail').hidden = false;
            if (this.svg) this.svg.selectAll('.node').classed('selected', d => d.id === node.id);
        }

        clearSelection() {
            this.selectedNode = null;
            const detail = document.getElementById('graph-node-detail');
            if (detail) {
                detail.hidden = true;
                document.getElementById('graph-node-empty').hidden = false;
            }
            if (this.svg) this.svg.selectAll('.node').classed('selected', false);
        }

        // After a re-render: keep the panel in step with the node it shows
        refreshNodePanel() {
            if (!this.selectedNode) return;
            const current = this.nodes.find(n => n.id === this.selectedNode.id);
            if (!current) {
                this.clearSelection();
                return;
            }
            const detail = document.getElementById('graph-node-detail');
            if (detail && !detail.hidden) this.showNodeDetails(current);
        }

        showContextMenu(event, node) {
            this.contextMenuNode = node;

            const menu = document.getElementById('node-context-menu');
            const freezeText = document.getElementById('freeze-menu-text');
            const dnsItem = document.getElementById('context-dns-item');
            const whoisItem = document.getElementById('context-whois-item');
            const geoItem = document.getElementById('context-geo-item');
            const idbItem = document.getElementById('context-idb-item');
            const shodanHostItem = document.getElementById('context-shodan-host-item');
            const shodanItem = document.getElementById('context-shodan-item');
            const shodanPivotItem = document.getElementById('context-shodan-pivot-item');
            const circlPdnsItem = document.getElementById('context-circl-pdns-item');

            // Update freeze text based on current state
            freezeText.textContent = node.frozen ? 'Unfreeze position' : 'Freeze position';

            // Show/hide DNS option based on node type (IP, domain, basedomain only)
            dnsItem.style.display = (node.type === 'ip' || node.type === 'domain' || node.type === 'basedomain') ? '' : 'none';

            // Show/hide WHOIS option based on node type (domain only)
            whoisItem.style.display = (node.type === 'domain') ? '' : 'none';

            // Show/hide Geo option based on node type (IP only)
            geoItem.style.display = (node.type === 'ip') ? '' : 'none';

            // Show/hide IDB option based on node type (IP only)
            idbItem.style.display = (node.type === 'ip') ? '' : 'none';

            // Show/hide Shodan Host Info option based on node type (IP only)
            shodanHostItem.style.display = (node.type === 'ip') ? '' : 'none';

            // Show/hide Shodan JARM & Pivot option based on node type (IP and domain only)
            shodanItem.style.display = (node.type === 'ip' || node.type === 'domain') ? '' : 'none';

            // Show/hide Shodan Pivot option based on node type (IP only)
            shodanPivotItem.style.display = (node.type === 'ip') ? '' : 'none';

            // Show/hide CIRCL PDNS option based on node type (IP, domain, basedomain)
            circlPdnsItem.style.display = (node.type === 'ip' || node.type === 'domain' || node.type === 'basedomain') ? '' : 'none';

            // Show/hide HackerTarget Shared NS option based on node type (domain, basedomain only)
            const hackertargetNsItem = document.getElementById('context-hackertarget-ns-item');
            hackertargetNsItem.style.display = (node.type === 'domain' || node.type === 'basedomain') ? '' : 'none';

            // Show/hide Chaos Subdomains option based on node type (domain, basedomain only) AND API key configured
            const chaosItem = document.getElementById('context-chaos-item');
            const chaosConfigured = window.chaosApiConfigured || false;
            chaosItem.style.display = (chaosConfigured && (node.type === 'domain' || node.type === 'basedomain')) ? '' : 'none';

            // Show/hide ViewDNS option based on node type (domain, basedomain only) AND API key configured
            const viewdnsItem = document.getElementById('context-viewdns-item');
            // Check if ViewDNS API key is configured (async check already done on page load)
            const viewdnsConfigured = window.viewdnsApiConfigured || false;
            viewdnsItem.style.display = (viewdnsConfigured && (node.type === 'domain' || node.type === 'basedomain')) ? '' : 'none';

            // Show/hide standalone ViewDNS Reverse WHOIS for registrar, email, registrant nodes
            const viewdnsWhoisStandaloneItem = document.getElementById('context-viewdns-whois-standalone-item');
            const whoisPivotTypes = ['registrar', 'email', 'registrant', 'org'];
            viewdnsWhoisStandaloneItem.style.display = (viewdnsConfigured && whoisPivotTypes.includes(node.type)) ? '' : 'none';

            // A heading ("Resolve", "Pivot") goes when every item under it is hidden
            menu.querySelectorAll('.menu-group').forEach(group => {
                const anyVisible = [...group.querySelectorAll(':scope > .context-menu-item')]
                    .some(item => item.style.display !== 'none');
                group.style.display = anyVisible ? '' : 'none';
            });
            menu.querySelectorAll('.has-submenu').forEach(wrap => {
                wrap.classList.remove('open', 'flip');
                const trigger = wrap.querySelector('.submenu-trigger');
                if (trigger) trigger.setAttribute('aria-expanded', 'false');
            });
            this.closeMenus();

            // Position menu at cursor
            let x = event.clientX;
            let y = event.clientY;

            // Ensure menu stays within viewport
            menu.classList.add('active');
            const menuRect = menu.getBoundingClientRect();

            if (x + menuRect.width > window.innerWidth) {
                x = window.innerWidth - menuRect.width - 10;
            }
            if (y + menuRect.height > window.innerHeight) {
                y = window.innerHeight - menuRect.height - 10;
            }

            menu.style.left = Math.max(x, 0) + 'px';
            menu.style.top = Math.max(y, 0) + 'px';

            // Open the ViewDNS submenu to the left when there is no room on the right
            if (x + menuRect.width + 200 > window.innerWidth) {
                menu.querySelectorAll('.has-submenu').forEach(wrap => wrap.classList.add('flip'));
            }
        }

        hideContextMenu() {
            document.getElementById('node-context-menu').classList.remove('active');
            this.contextMenuNode = null;
        }

        async contextMenuAction(action) {
            const node = this.contextMenuNode;
            if (!node) return;

            this.hideContextMenu();

            switch (action) {
                case 'freeze':
                    this.toggleFreezeNode(node);
                    break;
                case 'dns':
                    await this.resolveAndExpand(node.id, node.type);
                    break;
                case 'whois':
                    if (node.type === 'domain') {
                        this.selectedNode = node;
                        await this.resolveWhois(true); // Skip modal
                    }
                    break;
                case 'geo':
                    if (node.type === 'ip') {
                        await this.resolveGeoForNode(node);
                    }
                    break;
                case 'idb':
                    if (node.type === 'ip') {
                        await this.resolveIDBForNode(node);
                    }
                    break;
                case 'shodan-host':
                    if (node.type === 'ip') {
                        await this.resolveShodanHostInfo(node);
                    }
                    break;
                case 'shodan':
                    if (node.type === 'ip' || node.type === 'domain') {
                        await this.resolveShodan(node);
                    }
                    break;
                case 'shodan-pivot':
                    if (node.type === 'ip') {
                        await this.showShodanPivotModal(node);
                    }
                    break;
                case 'circl-pdns':
                    if (node.type === 'ip' || node.type === 'domain' || node.type === 'basedomain') {
                        await this.resolveCirclPDNS(node);
                    }
                    break;
                case 'hackertarget-shared-ns':
                    if (node.type === 'domain' || node.type === 'basedomain') {
                        await this.resolveHackerTargetSharedNS(node);
                    }
                    break;
                case 'chaos-subdomains':
                    if (node.type === 'domain' || node.type === 'basedomain') {
                        await this.resolveChaosSubdomains(node);
                    }
                    break;
                case 'viewdns-reverse-mx':
                    if (node.type === 'domain' || node.type === 'basedomain') {
                        await this.resolveViewDNSReverseMX(node);
                    }
                    break;
                case 'viewdns-reverse-ns':
                    if (node.type === 'domain' || node.type === 'basedomain') {
                        await this.resolveViewDNSReverseNS(node);
                    }
                    break;
                case 'viewdns-reverse-whois':
                    // For domain/basedomain nodes - pivot on the domain name
                    if (node.type === 'domain' || node.type === 'basedomain') {
                        await this.resolveViewDNSReverseWhois(node, node.id);
                    }
                    break;
                case 'viewdns-reverse-whois-standalone':
                    // For registrar/email/registrant/org nodes - pivot on the node value
                    if (['registrar', 'email', 'registrant', 'org'].includes(node.type)) {
                        // For registrar nodes, strip the 'registrar:' prefix if present
                        let pivotValue = node.id;
                        if (node.type === 'registrar' && pivotValue.startsWith('registrar:')) {
                            pivotValue = pivotValue.substring(10);
                        }
                        await this.resolveViewDNSReverseWhois(node, pivotValue);
                    }
                    break;
                case 'all':
                    await this.resolveAndExpand(node.id, node.type);
                    if (node.type === 'domain') {
                        this.selectedNode = node;
                        await this.resolveWhois(true); // Skip modal
                    }
                    if (node.type === 'ip') {
                        await this.resolveGeoForNode(node);
                    }
                    break;
                case 'connect':
                    this.showAddConnectionModal(node);
                    break;
                case 'remove':
                    this.selectedNode = node;
                    this.removeNode();
                    break;
            }
        }

        async resolveGeoForNode(node) {
            if (node.type !== 'ip') return;

            this.showLoading(true);

            try {
                // Use /api/graph/enrich to run LogBoost for this IP
                const response = await csrfFetch('/api/graph/enrich', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ips: [node.id] })
                });

                const result = await response.json();

                if (result.error) {
                    console.error('Geo enrichment failed:', result.error);
                    return;
                }

                if (result.geo_data && result.geo_data[node.id]) {
                    const geoInfo = result.geo_data[node.id];

                    // Store geo data on node
                    node.data = node.data || {};
                    node.data.geo = geoInfo;
                    node.data.geoResolved = true;
                    this.isModified = true;

                    // Add ASN node if present
                    if (geoInfo.asn || geoInfo.asn_id) {
                        // Create ASN node ID as "ID_NAME" to avoid collisions
                        let asnNodeId;
                        if (geoInfo.asn_id) {
                            asnNodeId = geoInfo.asn_name 
                                ? `${geoInfo.asn_id}_${geoInfo.asn_name}`
                                : geoInfo.asn_id;
                        } else {
                            asnNodeId = geoInfo.asn;
                        }

                        const asnNode = this.addNode(asnNodeId, 'asn', false);
                        if (asnNode) {
                            asnNode.data = {
                                asn_id: geoInfo.asn_id || '',
                                asn_name: geoInfo.asn_name || '',
                                asn_org: geoInfo.org || ''
                            };
                        }
                        this.addEdge(node.id, asnNodeId, 'ASN');
                    }

                    // Add Country node if present
                    if (geoInfo.country) {
                        const countryNode = this.addNode(geoInfo.country, 'country', false);
                        this.addEdge(node.id, geoInfo.country, 'country');
                    }

                    this.render();
                } else {
                    // Mark as resolved even if no data found
                    node.data = node.data || {};
                    node.data.geoResolved = true;
                }
            } catch (err) {
                console.error('Geo resolution failed:', err);
            } finally {
                this.showLoading(false);
            }
        }

        async resolveIDBForNode(node) {
            if (node.type !== 'ip') return;

            this.showLoading(true);
            showToast('Resolving ports/tags for ' + node.id + '...', 'info');

            try {
                const response = await csrfFetch('/api/graph/enrich-idb', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ips: [node.id] })
                });

                const result = await response.json();

                if (result.error) {
                    console.error('IDB enrichment failed:', result.error);
                    showToast('IDB enrichment failed: ' + result.error, 'error');
                    return;
                }

                if (result.idb_data && result.idb_data[node.id]) {
                    const idbInfo = result.idb_data[node.id];

                    // Store IDB data on node
                    node.data = node.data || {};
                    node.data.idb = idbInfo;
                    node.data.idbResolved = true;
                    this.isModified = true;

                    let nodesAdded = false;

                    // Add Port nodes
                    if (idbInfo.ports && idbInfo.ports.length > 0) {
                        for (const port of idbInfo.ports) {
                            const portNodeId = `port:${port}`;
                            const portNode = this.addNode(portNodeId, 'port', false);
                            if (portNode) {
                                portNode.data = { port: port };
                                nodesAdded = true;
                            }
                            this.addEdge(node.id, portNodeId, 'Open Port');
                        }
                    }

                    // Add Tag nodes
                    if (idbInfo.tags && idbInfo.tags.length > 0) {
                        for (const tag of idbInfo.tags) {
                            const tagNodeId = `tag:${tag}`;
                            const tagNode = this.addNode(tagNodeId, 'tag', false);
                            if (tagNode) {
                                tagNode.data = { tag: tag };
                                nodesAdded = true;
                            }
                            this.addEdge(node.id, tagNodeId, 'has_tag');
                        }
                    }

                    if (nodesAdded) {
                        this.render();
                        const portCount = idbInfo.ports ? idbInfo.ports.length : 0;
                        const tagCount = idbInfo.tags ? idbInfo.tags.length : 0;
                        showToast(`Found ${portCount} ports, ${tagCount} tags for ${node.id}`, 'success');
                    } else {
                        showToast('No ports or tags found for ' + node.id, 'info');
                    }
                } else {
                    node.data = node.data || {};
                    node.data.idbResolved = true;
                    showToast('No IDB data found for ' + node.id, 'info');
                }
            } catch (err) {
                console.error('IDB resolution failed:', err);
                showToast('IDB resolution failed', 'error');
            } finally {
                this.showLoading(false);
            }
        }

        async resolveAllIDB() {
            // Find all IP nodes that haven't been IDB resolved
            const unresolvedIPs = this.nodes.filter(n => 
                n.type === 'ip' && (!n.data || !n.data.idbResolved)
            );

            if (unresolvedIPs.length === 0) {
                showToast('All IPs already have IDB data resolved', 'info');
                return;
            }

            const btn = document.getElementById('resolve-all-idb-btn');
            const originalHTML = btn.innerHTML;

            this.showLoading(true);
            btn.disabled = true;
            btn.textContent = `Resolving ${unresolvedIPs.length}...`;

            try {
                const ips = unresolvedIPs.map(n => n.id);

                const response = await csrfFetch('/api/graph/enrich-idb', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ips })
                });

                const result = await response.json();

                if (result.error) {
                    showToast('IDB enrichment failed: ' + result.error, 'error');
                    return;
                }

                let totalPorts = 0;
                let totalTags = 0;

                if (result.idb_data) {
                    for (const ipNode of unresolvedIPs) {
                        const idbInfo = result.idb_data[ipNode.id];

                        if (idbInfo) {
                            ipNode.data = ipNode.data || {};
                            ipNode.data.idb = idbInfo;
                            ipNode.data.idbResolved = true;
                            this.isModified = true;

                            // Add Port nodes
                            if (idbInfo.ports && idbInfo.ports.length > 0) {
                                for (const port of idbInfo.ports) {
                                    const portNodeId = `port:${port}`;
                                    const portNode = this.addNode(portNodeId, 'port', false);
                                    if (portNode) {
                                        portNode.data = { port: port };
                                    }
                                    this.addEdge(ipNode.id, portNodeId, 'Open Port');
                                }
                                totalPorts += idbInfo.ports.length;
                            }

                            // Add Tag nodes
                            if (idbInfo.tags && idbInfo.tags.length > 0) {
                                for (const tag of idbInfo.tags) {
                                    const tagNodeId = `tag:${tag}`;
                                    const tagNode = this.addNode(tagNodeId, 'tag', false);
                                    if (tagNode) {
                                        tagNode.data = { tag: tag };
                                    }
                                    this.addEdge(ipNode.id, tagNodeId, 'has_tag');
                                }
                                totalTags += idbInfo.tags.length;
                            }
                        } else {
                            ipNode.data = ipNode.data || {};
                            ipNode.data.idbResolved = true;
                        }
                    }
                }

                this.render();
                showToast(`IDB complete: ${totalPorts} ports, ${totalTags} tags across ${unresolvedIPs.length} IPs`, 'success');

            } catch (err) {
                console.error('Bulk IDB resolution failed:', err);
                showToast('IDB resolution failed: ' + err.message, 'error');
            } finally {
                this.showLoading(false);
                btn.disabled = false;
                btn.innerHTML = originalHTML;
            }
        }

        async resolveShodanHostInfo(node) {
            if (node.type !== 'ip') return;

            this.showLoading(true);
            showToast('Querying Shodan for host info...', 'info');

            try {
                console.log(`Resolving Shodan host info for IP: ${node.id}`);

                // Query Shodan for host info (same endpoint, we just won't pivot)
                const response = await csrfFetch('/api/shodan/resolve', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ value: node.id, type: 'ip' })
                });

                const result = await response.json();

                if (result.error) {
                    console.error('Shodan host info failed:', result.error);
                    showToast('Shodan lookup failed: ' + result.error, 'error');
                    return;
                }

                console.log('Shodan host info result:', result);

                // Store Shodan data on node
                node.data = node.data || {};
                node.data.shodanHostResolved = true;
                this.isModified = true;

                let nodesAdded = false;

                if (result.host_info && Object.keys(result.host_info).length > 0) {
                    node.data.shodan = result.host_info;

                    // Add hostnames as domain nodes with PTR relationship
                    const hostnames = result.host_info.hostnames || [];
                    if (hostnames.length > 0) {
                        console.log(`Found ${hostnames.length} hostnames for ${node.id}`);
                        for (const hostname of hostnames) {
                            if (hostname && hostname.trim()) {
                                // Check if hostname node already exists and is connected
                                const existingEdge = this.edges.find(e => {
                                    const sourceId = typeof e.source === 'object' ? e.source.id : e.source;
                                    const targetId = typeof e.target === 'object' ? e.target.id : e.target;
                                    return (sourceId === node.id && targetId === hostname) || 
                                           (sourceId === hostname && targetId === node.id);
                                });

                                if (!existingEdge) {
                                    const domainNode = this.addDomainWithTLD(hostname, false);
                                    if (domainNode) nodesAdded = true;
                                    this.addEdge(node.id, hostname, 'PTR');
                                }
                            }
                        }
                    }

                    // Update/add Country relationship if country_name exists
                    const countryName = result.host_info.country_name;
                    if (countryName) {
                        // Find existing country edge for this IP
                        const existingCountryEdge = this.edges.find(e => {
                            const sourceId = typeof e.source === 'object' ? e.source.id : e.source;
                            return sourceId === node.id && e.relationship === 'country';
                        });

                        if (existingCountryEdge) {
                            const existingCountryId = typeof existingCountryEdge.target === 'object' 
                                ? existingCountryEdge.target.id 
                                : existingCountryEdge.target;

                            // If country differs, remove old edge and add new one
                            if (existingCountryId !== countryName) {
                                console.log(`Updating country from ${existingCountryId} to ${countryName}`);
                                // Remove old edge
                                const edgeIndex = this.edges.indexOf(existingCountryEdge);
                                if (edgeIndex > -1) {
                                    this.edges.splice(edgeIndex, 1);
                                }
                                // Add new country node and edge
                                const countryNode = this.addNode(countryName, 'country', false);
                                if (countryNode) nodesAdded = true;
                                this.addEdge(node.id, countryName, 'country');
                            }
                        } else {
                            // No existing country edge, add one
                            const countryNode = this.addNode(countryName, 'country', false);
                            if (countryNode) nodesAdded = true;
                            this.addEdge(node.id, countryName, 'country');
                        }
                    }

                    const hostnameCount = hostnames.length;
                    showToast(`Shodan: Found ${hostnameCount} hostname(s) for ${node.id}`, 'success');
                } else {
                    showToast(result.message || 'No Shodan host info available', 'info');
                }

                if (nodesAdded) {
                    this.render();
                }

            } catch (err) {
                console.error('Shodan host info failed:', err);
                showToast('Shodan lookup failed: ' + err.message, 'error');
            } finally {
                this.showLoading(false);
            }
        }

        async showShodanPivotModal(node) {
            if (node.type !== 'ip') return;

            const ip = node.id;

            // Check if we have Shodan data
            if (!node.data || !node.data.shodan) {
                // Need to fetch Shodan data first
                showToast('Fetching Shodan data for ' + ip + '...', 'info');

                try {
                    this.showLoading(true);

                    const response = await csrfFetch('/api/shodan/resolve', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ value: ip, type: 'ip' })
                    });

                    const result = await response.json();

                    if (result.error) {
                        showToast('Shodan error: ' + result.error, 'error');
                        return;
                    }

                    if (!result.host_info || !result.host_info.data || result.host_info.data.length === 0) {
                        showToast('No Shodan data available for this IP', 'error');
                        return;
                    }

                    // Store shodan data on node
                    node.data = node.data || {};
                    node.data.shodan = result.host_info;
                    node.data.shodanHostResolved = true;

                } catch (err) {
                    console.error('Shodan fetch failed:', err);
                    showToast('Failed to fetch Shodan data: ' + err.message, 'error');
                    return;
                } finally {
                    this.showLoading(false);
                }
            }

            const shodanData = node.data.shodan;

            if (!shodanData || typeof shodanData !== 'object') {
                showToast('No Shodan data available for pivot', 'error');
                return;
            }

            // Flatten the Shodan data
            const flattened = flattenShodanData(shodanData);

            // Filter to queryable fields only and deduplicate
            const queryableAttributes = [];
            const seenPairs = new Set();  // Track unique filter:value pairs

            for (const [path, values] of Object.entries(flattened)) {
                // path is already normalized (data. prefix stripped during flattening)
                if (isQueryableFilter(path) && values.size > 0) {
                    // Convert Set to Array and add each value
                    for (const value of values) {
                        // Skip empty or very long values
                        if (!value || String(value).length > 200) continue;
                        // Skip numeric values that don't make sense as filters
                        // Allow: port, status codes, key bits, and all hash values
                        const allowedNumericFilters = [
                            'port', 'http.status', 'ssl.cert.pubkey.bits', 'ssl.cipher.bits',
                            'hash', 'http.headers_hash', 'http.html_hash', 'http.favicon.hash',
                            'http.robots_hash', 'screenshot.hash'
                        ];
                        if (typeof value === 'number' && !allowedNumericFilters.some(f => path.includes(f) || path === f)) continue;

                        // Deduplicate by filter:value pair
                        const pairKey = `${path}:${String(value)}`;
                        if (seenPairs.has(pairKey)) continue;
                        seenPairs.add(pairKey);

                        queryableAttributes.push({
                            filter: path,
                            value: String(value),
                            display: `${path}: ${String(value).substring(0, 80)}${String(value).length > 80 ? '...' : ''}`
                        });
                    }
                }
            }

            if (queryableAttributes.length === 0) {
                showToast('No queryable Shodan attributes found for this IP', 'error');
                return;
            }

            // Sort by filter name
            queryableAttributes.sort((a, b) => a.filter.localeCompare(b.filter) || a.value.localeCompare(b.value));

            // Initialize state
            window.shodanPivotState = {
                sourceIp: ip,
                nodeId: node.id,
                query: null
            };

            // Populate modal
            document.getElementById('shodan-pivot-ip').textContent = ip;
            document.getElementById('pivot-attribute-search').value = '';
            document.getElementById('pivot-query-preview').style.display = 'none';
            document.getElementById('pivot-execute-btn').disabled = true;

            const listContainer = document.getElementById('pivot-attributes-list');
            listContainer.innerHTML = queryableAttributes.map((attr, idx) => `
                <label class="pivot-attribute-item">
                    <input type="checkbox" class="check pivot-attribute-checkbox"
                           data-filter="${this.escapeHtml(attr.filter)}"
                           data-value="${this.escapeHtml(attr.value)}">
                    <span class="pivot-filter-name">${this.escapeHtml(attr.filter)}:</span>
                    <span class="pivot-filter-value">${this.escapeHtml(attr.value)}</span>
                </label>
            `).join('');

            // Show modal
            openGraphDialog('shodan-pivot-modal');
        }

        async resolveShodan(node) {
            if (node.type !== 'ip' && node.type !== 'domain') return;

            this.showLoading(true);

            try {
                console.log(`Resolving Shodan for ${node.type}: ${node.id}`);

                // Step 1: Query Shodan for JARM fingerprints
                const response = await csrfFetch('/api/shodan/resolve', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ value: node.id, type: node.type })
                });

                const result = await response.json();

                if (result.error) {
                    console.error('Shodan resolve failed:', result.error);
                    alert('Shodan lookup failed: ' + result.error);
                    return;
                }

                console.log('Shodan resolve result:', result);

                // Mark node as Shodan resolved and store full Shodan data
                node.data = node.data || {};
                node.data.shodanResolved = true;
                if (result.host_info && Object.keys(result.host_info).length > 0) {
                    node.data.shodan = result.host_info;
                }
                this.isModified = true;

                if (!result.jarms || result.jarms.length === 0) {
                    console.log('No JARM fingerprints found');
                    showToast(result.message || 'No JARM fingerprints found', 'info');
                    this.render();
                    return;
                }

                console.log(`Found ${result.jarms.length} unique JARM fingerprint(s) - processing all of them`);

                // Track limited results for summary
                const limitedJarms = [];

                // Step 2: For each JARM, add it to the graph and pivot
                let jarmIndex = 0;
                for (const jarmInfo of result.jarms) {
                    jarmIndex++;
                    const jarm = jarmInfo.jarm;

                    console.log(`Processing JARM ${jarmIndex}/${result.jarms.length}: ${jarm.substring(0, 20)}...`);

                    // Add JARM node
                    const jarmNode = this.addNode(jarm, 'jarm', false);
                    if (jarmNode) {
                        jarmNode.data = {
                            source_ip: jarmInfo.source_ip,
                            port: jarmInfo.port,
                            hostnames: jarmInfo.hostnames,
                            host_count: 0
                        };
                    }

                    // Connect original node to JARM
                    this.addEdge(node.id, jarm, 'JARM');

                    // Throttle: wait 1 second before pivot query
                    await new Promise(resolve => setTimeout(resolve, 1000));

                    // Step 3: Pivot on JARM to find other hosts
                    console.log(`Pivoting on JARM: ${jarm}`);
                    const pivotResponse = await csrfFetch('/api/shodan/pivot-jarm', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ jarm })
                    });

                    const pivotResult = await pivotResponse.json();

                    if (pivotResult.error) {
                        console.error('JARM pivot failed:', pivotResult.error);
                        continue;
                    }

                    console.log('JARM pivot result:', pivotResult);

                    // Update JARM node with host count and pivot results
                    const existingJarmNode = this.getNode(jarm);
                    if (existingJarmNode) {
                        existingJarmNode.data = existingJarmNode.data || {};
                        existingJarmNode.data.host_count = pivotResult.total_results;
                        existingJarmNode.data.pivot_results = pivotResult;  // Store full pivot results
                    }

                    // Add discovered IPs
                    for (const ip of pivotResult.ips || []) {
                        if (ip !== node.id) { // Don't add the original node
                            const ipNode = this.addNode(ip, 'ip', false);
                            this.addEdge(jarm, ip, 'JARM');
                        }
                    }

                    // Add discovered hostnames as domains
                    for (const hostname of pivotResult.hostnames || []) {
                        const domainNode = this.addDomainWithTLD(hostname, false);
                        this.addEdge(jarm, hostname, 'JARM');
                    }

                    // Track if any results were limited
                    if (pivotResult.limited) {
                        limitedJarms.push({
                            jarm: jarm.substring(0, 20) + '...',
                            total: pivotResult.total_results
                        });
                    }

                    // Throttle between multiple JARMs (not after the last one)
                    if (jarmIndex < result.jarms.length) {
                        await new Promise(resolve => setTimeout(resolve, 1000));
                    }
                }

                // Show summary if any results were limited
                if (limitedJarms.length > 0) {
                    const limitMsg = limitedJarms.map(l => `${l.jarm}: ${l.total} hosts`).join('\n');
                    console.warn(`Some JARM pivots had limited results (showing 100 of total):\n${limitMsg}`);
                }

                console.log(`Shodan resolution complete: processed ${result.jarms.length} JARM(s)`);
                showToast(`Found ${result.jarms.length} JARM fingerprint(s)`, 'success');
                this.render();

            } catch (err) {
                console.error('Shodan resolution failed:', err);
                alert('Shodan resolution failed: ' + err.message);
            } finally {
                this.showLoading(false);
            }
        }

        toggleFreezeNode(node) {
            if (node.frozen) {
                // Unfreeze
                node.frozen = false;
                node.fx = null;
                node.fy = null;
            } else {
                // Freeze at current position
                node.frozen = true;
                node.fx = node.x;
                node.fy = node.y;
            }
            this.isModified = true;

            // Update the frozen ring on the canvas
            if (this.svg) {
                const nodeEl = this.svg.select(`.node[data-id="${CSS.escape(node.id)}"]`);
                if (!nodeEl.empty()) this.drawFrozenRing(nodeEl, node);
            }

            // Restart simulation to update
            if (this.simulation) {
                this.simulation.alpha(0.1).restart();
            }
        }

        async resolveCirclPDNS(node) {
            /**
             * Query CIRCL Passive DNS for historical DNS data
             * Creates nodes and edges based on rrtype:
             * - A/AAAA: Domain -> IP
             * - CNAME/MX/NS: Domain -> Domain
             * - PTR: IP -> Domain
             */
            if (node.type !== 'ip' && node.type !== 'domain' && node.type !== 'basedomain') return;

            this.showLoading(true);
            const queryValue = node.id;
            const queryType = node.type === 'ip' ? 'ip' : 'domain';

            try {
                const response = await csrfFetch('/api/circl/pdns', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ value: queryValue, type: queryType })
                });

                const result = await response.json();

                if (result.error) {
                    console.error('CIRCL PDNS query failed:', result.error);
                    showToast('CIRCL PDNS query failed: ' + result.error, 'error');
                    this.showLoading(false);
                    return;
                }

                if (!result.results || result.results.length === 0) {
                    console.log('No CIRCL PDNS results for:', queryValue);
                    showToast('No passive DNS records found for ' + queryValue, 'warning');
                    this.showLoading(false);
                    return;
                }

                console.log(`[CIRCL PDNS] Found ${result.results.length} records for ${queryValue}`);

                // Store raw CIRCL data on the source node for download
                node.data = node.data || {};
                node.data.circlPdns = result.results;
                node.data.circlPdnsQuery = queryValue;
                node.data.circlPdnsFromCache = result.from_cache;
                node.data.circlPdnsCachedAt = result.cached_at;

                // Process results and create nodes/edges
                let nodesAdded = 0;
                let edgesAdded = 0;

                for (const record of result.results) {
                    const rrtype = record.rrtype;
                    const rrname = record.rrname;
                    const rdata = record.rdata;
                    const firstSeen = record.time_first ? new Date(record.time_first * 1000).toISOString() : null;
                    const lastSeen = record.time_last ? new Date(record.time_last * 1000).toISOString() : null;
                    const count = record.count || 0;

                    // Determine source and target based on our query and rrtype
                    let sourceNode, targetNode, edgeLabel;
                    let sourceType, targetType;

                    if (rrtype === 'A' || rrtype === 'AAAA') {
                        // Domain -> IP relationship
                        // If we queried an IP, rrname is the IP, rdata is the domain
                        // If we queried a domain, rrname is the domain, rdata is the IP
                        // BUT: Always verify actual types since data can be unexpected
                        if (queryType === 'ip') {
                            // Expected: rrname = IP we queried, rdata = domain that pointed to it
                            sourceNode = rdata;
                            targetNode = rrname;
                        } else {
                            // Expected: rrname = domain we queried, rdata = IP it resolved to
                            sourceNode = rrname;
                            targetNode = rdata;
                        }
                        // Determine actual types by checking if values are IPs
                        sourceType = this.isValidIP(sourceNode) ? 'ip' : 'domain';
                        targetType = this.isValidIP(targetNode) ? 'ip' : 'domain';
                        edgeLabel = rrtype;
                    } else if (rrtype === 'CNAME') {
                        // Domain -> Domain (alias), but verify actual types
                        sourceNode = rrname;
                        targetNode = rdata;
                        // Check if source is actually an IP
                        sourceType = this.isValidIP(rrname) ? 'ip' : 'domain';
                        // Check if target is actually an IP
                        if (this.isValidIP(rdata)) {
                            targetType = 'ip';
                            edgeLabel = this.isIPv6(rdata) ? 'AAAA' : 'A';
                        } else {
                            targetType = 'domain';
                            edgeLabel = 'CNAME';
                        }
                    } else if (rrtype === 'MX') {
                        // Domain -> Domain (mail server), but verify actual types
                        // MX rdata often has priority prefix like "10 mail.example.com"
                        let mxHost = rdata;
                        if (rdata && rdata.includes(' ')) {
                            mxHost = rdata.split(' ').pop();
                        }
                        sourceNode = rrname;
                        targetNode = mxHost;
                        // Check if source is actually an IP
                        sourceType = this.isValidIP(rrname) ? 'ip' : 'domain';
                        // Check if target is actually an IP
                        if (this.isValidIP(mxHost)) {
                            targetType = 'ip';
                            edgeLabel = this.isIPv6(mxHost) ? 'AAAA' : 'A';
                        } else {
                            targetType = 'domain';
                            edgeLabel = 'MX';
                        }
                    } else if (rrtype === 'NS') {
                        // Domain -> Domain (nameserver), but verify actual types
                        sourceNode = rrname;
                        targetNode = rdata;
                        // Check if source is actually an IP
                        sourceType = this.isValidIP(rrname) ? 'ip' : 'domain';
                        // Check if target is actually an IP
                        if (this.isValidIP(rdata)) {
                            targetType = 'ip';
                            edgeLabel = this.isIPv6(rdata) ? 'AAAA' : 'A';
                        } else {
                            targetType = 'domain';
                            edgeLabel = 'NS';
                        }
                    } else if (rrtype === 'PTR') {
                        // IP -> Domain (reverse DNS), but verify actual types
                        sourceNode = rrname;
                        targetNode = rdata;
                        // Check actual types
                        sourceType = this.isValidIP(rrname) ? 'ip' : 'domain';
                        targetType = this.isValidIP(rdata) ? 'ip' : 'domain';
                        edgeLabel = 'PTR';
                    } else {
                        // Skip other record types for now
                        continue;
                    }

                    // Clean up domain names (remove trailing dots)
                    if (sourceType === 'domain' && sourceNode) {
                        sourceNode = sourceNode.replace(/\.$/, '').toLowerCase();
                    }
                    if (targetType === 'domain' && targetNode) {
                        targetNode = targetNode.replace(/\.$/, '').toLowerCase();
                    }

                    // Skip if source or target is empty
                    if (!sourceNode || !targetNode) continue;

                    // Create source node if it doesn't exist
                    const existingSource = this.getNode(sourceNode);
                    if (!existingSource) {
                        const newSource = this.addNode(sourceNode, sourceType, false);
                        if (newSource) {
                            newSource.data = newSource.data || {};
                            newSource.data.circlFirstSeen = firstSeen;
                            newSource.data.circlLastSeen = lastSeen;
                            newSource.data.circlCount = count;
                            nodesAdded++;

                            // Extract BaseDomain/TLD for new domains
                            if (sourceType === 'domain') {
                                this.extractBaseDomainAndTLD(sourceNode, newSource);
                            }
                        }
                    }

                    // Create target node if it doesn't exist
                    const existingTarget = this.getNode(targetNode);
                    if (!existingTarget) {
                        const newTarget = this.addNode(targetNode, targetType, false);
                        if (newTarget) {
                            newTarget.data = newTarget.data || {};
                            newTarget.data.circlFirstSeen = firstSeen;
                            newTarget.data.circlLastSeen = lastSeen;
                            newTarget.data.circlCount = count;
                            nodesAdded++;

                            // Extract BaseDomain/TLD for new domains
                            if (targetType === 'domain') {
                                this.extractBaseDomainAndTLD(targetNode, newTarget);
                            }
                        }
                    }

                    // Create edge
                    const edgeCreated = this.addEdge(sourceNode, targetNode, edgeLabel);
                    if (edgeCreated) {
                        // Add CIRCL metadata to the edge
                        const edge = this.edges.find(e => 
                            (e.source.id || e.source) === sourceNode && 
                            (e.target.id || e.target) === targetNode
                        );
                        if (edge) {
                            edge.data = edge.data || {};
                            edge.data.circlFirstSeen = firstSeen;
                            edge.data.circlLastSeen = lastSeen;
                            edge.data.circlCount = count;
                        }
                        edgesAdded++;
                    }
                }

                console.log(`[CIRCL PDNS] Added ${nodesAdded} nodes and ${edgesAdded} edges`);

                this.isModified = true;
                this.render();

                // Restart simulation with low alpha to settle new nodes
                if (this.simulation) {
                    this.simulation.alpha(0.3).restart();
                }

            } catch (error) {
                console.error('CIRCL PDNS error:', error);
                showToast('CIRCL PDNS query failed: ' + error.message, 'error');
            } finally {
                this.showLoading(false);
            }
        }

        extractBaseDomainAndTLD(domainName, domainNode) {
            /**
             * Extract and create BaseDomain and TLD nodes for a domain
             * Helper for CIRCL PDNS to maintain graph relationships
             */
            const parts = domainName.split('.');
            if (parts.length < 2) return;

            // Simple TLD extraction (doesn't handle multi-part TLDs like .co.uk)
            const tld = parts[parts.length - 1];
            let baseDomain;

            // Handle common multi-part TLDs
            const multiPartTLDs = ['co.uk', 'com.au', 'co.nz', 'co.za', 'com.br', 'co.jp', 'co.kr', 'org.uk', 'net.au'];
            const lastTwo = parts.slice(-2).join('.');

            if (multiPartTLDs.includes(lastTwo) && parts.length >= 3) {
                baseDomain = parts.slice(-3).join('.');
            } else {
                baseDomain = parts.slice(-2).join('.');
            }

            // Create TLD node if needed
            const tldNode = this.getNode(tld);
            if (!tldNode) {
                this.addNode(tld, 'tld', false);
            }

            // Create BaseDomain node if needed (and if different from the domain)
            if (baseDomain !== domainName) {
                const baseNode = this.getNode(baseDomain);
                if (!baseNode) {
                    this.addNode(baseDomain, 'basedomain', false);
                }

                // Connect domain -> basedomain
                this.addEdge(domainName, baseDomain, 'subdomain_of');

                // Connect basedomain -> tld
                this.addEdge(baseDomain, tld, 'registered_under');
            } else {
                // Domain is the base domain, connect directly to TLD
                this.addEdge(domainName, tld, 'registered_under');
            }
        }

        downloadCirclPDNS(node) {
            /**
             * Download CIRCL PDNS results for a node as JSON
             */
            if (!node || !node.data || !node.data.circlPdns) {
                showToast('No CIRCL PDNS data available for this node', 'warning');
                return;
            }

            const queryValue = node.data.circlPdnsQuery || node.id;
            const data = {
                query: queryValue,
                result_count: node.data.circlPdns.length,
                from_cache: node.data.circlPdnsFromCache,
                cached_at: node.data.circlPdnsCachedAt,
                results: node.data.circlPdns
            };

            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `circl_pdns_${queryValue.replace(/[^a-z0-9]/gi, '_')}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }

        async resolveHackerTargetSharedNS(node) {
            /**
             * Query HackerTarget for domains sharing the same nameserver
             * Creates Domain nodes and NS edges pointing to the queried node
             */
            if (node.type !== 'domain' && node.type !== 'basedomain') return;

            this.showLoading(true);
            const queryValue = node.id;

            try {
                const response = await csrfFetch('/api/hackertarget/shared-ns', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ value: queryValue })
                });

                const result = await response.json();

                if (result.error) {
                    console.error('HackerTarget query failed:', result.error);
                    showToast('HackerTarget query failed: ' + result.error, 'error');
                    this.showLoading(false);
                    return;
                }

                if (!result.results || result.results.length === 0) {
                    console.log('No HackerTarget results for:', queryValue);
                    showToast('No domains found sharing nameserver ' + queryValue, 'warning');
                    this.showLoading(false);
                    return;
                }

                console.log(`[HackerTarget] Found ${result.results.length} domains for ${queryValue}`);

                // Store raw HackerTarget data on the source node
                node.data = node.data || {};
                node.data.hackerTargetSharedNS = result.results;
                node.data.hackerTargetFromCache = result.from_cache;
                node.data.hackerTargetCachedAt = result.cached_at;

                // Process results and create nodes/edges
                let nodesAdded = 0;
                let edgesAdded = 0;

                for (const domain of result.results) {
                    // Clean up domain name
                    const cleanDomain = domain.replace(/\.$/, '').toLowerCase();

                    // Skip if same as queried node
                    if (cleanDomain === queryValue) continue;

                    // Create domain node if it doesn't exist
                    const existingNode = this.getNode(cleanDomain);
                    if (!existingNode) {
                        const newNode = this.addNode(cleanDomain, 'domain', false);
                        if (newNode) {
                            nodesAdded++;

                            // Extract BaseDomain/TLD for new domains
                            this.extractBaseDomainAndTLD(cleanDomain, newNode);
                        }
                    }

                    // Create NS edge: domain -> nameserver (the queried node)
                    const edgeCreated = this.addEdge(cleanDomain, queryValue, 'NS');
                    if (edgeCreated) {
                        edgesAdded++;
                    }
                }

                console.log(`[HackerTarget] Added ${nodesAdded} nodes and ${edgesAdded} edges`);

                this.isModified = true;
                this.render();

                // Restart simulation with low alpha to settle new nodes
                if (this.simulation) {
                    this.simulation.alpha(0.3).restart();
                }

            } catch (error) {
                console.error('HackerTarget error:', error);
                showToast('HackerTarget query failed: ' + error.message, 'error');
            } finally {
                this.showLoading(false);
            }
        }

        async resolveChaosSubdomains(node) {
            /**
             * Query Chaos (ProjectDiscovery) for subdomains of a domain
             * Creates Domain nodes connected to the BaseDomain with SubDomain edges
             */
            if (node.type !== 'domain' && node.type !== 'basedomain') return;

            this.showLoading(true);

            // Get the base domain for the query
            const baseDomain = node.type === 'basedomain' ? node.id : this.extractBaseDomain(node.id);
            if (!baseDomain) {
                showToast('Could not determine base domain', 'error');
                this.showLoading(false);
                return;
            }

            try {
                const response = await csrfFetch('/api/chaos/subdomains', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain: baseDomain })
                });

                const result = await response.json();

                if (result.error) {
                    console.error('Chaos query failed:', result.error);
                    showToast('Chaos query failed: ' + result.error, 'error');
                    this.showLoading(false);
                    return;
                }

                if (!result.subdomains || result.subdomains.length === 0) {
                    console.log('No Chaos results for:', baseDomain);
                    showToast('No subdomains found for ' + baseDomain, 'warning');
                    this.showLoading(false);
                    return;
                }

                console.log(`[Chaos] Found ${result.subdomain_count} subdomains for ${baseDomain}`);

                // Store raw Chaos data on the source node
                node.data = node.data || {};
                node.data.chaosSubdomains = result.subdomains;
                node.data.chaosSubdomainCount = result.subdomain_count;
                node.data.chaosFromCache = result.from_cache;
                node.data.chaosCachedAt = result.cached_at;

                // Ensure BaseDomain node exists
                let baseDomainNode = this.getNode(baseDomain);
                if (!baseDomainNode) {
                    baseDomainNode = this.addNode(baseDomain, 'basedomain', false);
                }

                // Process results and create nodes/edges
                let nodesAdded = 0;
                let edgesAdded = 0;

                for (const subdomain of result.subdomains) {
                    // Build full domain name
                    // Chaos returns subdomain prefixes (e.g., "www", "api", "*")
                    // Skip wildcard entries
                    if (subdomain === '*' || subdomain.includes('*')) continue;

                    const fullDomain = subdomain === '' ? baseDomain : `${subdomain}.${baseDomain}`;
                    const cleanDomain = fullDomain.toLowerCase();

                    // Skip if same as base domain
                    if (cleanDomain === baseDomain) continue;

                    // Create domain node if it doesn't exist
                    const existingNode = this.getNode(cleanDomain);
                    if (!existingNode) {
                        const newNode = this.addNode(cleanDomain, 'domain', false);
                        if (newNode) {
                            nodesAdded++;
                        }
                    }

                    // Create SubDomain edge: subdomain -> basedomain
                    const edgeCreated = this.addEdge(cleanDomain, baseDomain, 'SubDomain');
                    if (edgeCreated) {
                        edgesAdded++;
                    }
                }

                console.log(`[Chaos] Added ${nodesAdded} nodes and ${edgesAdded} edges`);

                const cacheMsg = result.from_cache ? ' (cached)' : '';
                showToast(`Found ${result.subdomain_count} subdomains for ${baseDomain}${cacheMsg}`, 'success');

                this.isModified = true;
                this.render();

                // Restart simulation with low alpha to settle new nodes
                if (this.simulation) {
                    this.simulation.alpha(0.3).restart();
                }

            } catch (error) {
                console.error('Chaos error:', error);
                showToast('Chaos query failed: ' + error.message, 'error');
            } finally {
                this.showLoading(false);
            }
        }

        async resolveViewDNSReverseMX(node) {
            /**
             * Query ViewDNS for domains using the same mail server
             * Creates Domain nodes and MX edges pointing to the queried node
             */
            if (node.type !== 'domain' && node.type !== 'basedomain') return;

            this.showLoading(true);
            const queryValue = node.id;

            try {
                const response = await csrfFetch('/api/viewdns/reverse-mx', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ value: queryValue })
                });

                const result = await response.json();

                if (result.error) {
                    console.error('ViewDNS Reverse MX failed:', result.error);
                    showToast('ViewDNS Reverse MX failed: ' + result.error, 'error');
                    this.showLoading(false);
                    return;
                }

                if (!result.results || result.results.length === 0) {
                    console.log('No ViewDNS Reverse MX results for:', queryValue);
                    showToast('No domains found using mail server ' + queryValue, 'warning');
                    this.showLoading(false);
                    return;
                }

                console.log(`[ViewDNS] Found ${result.results.length} domains for MX ${queryValue}`);

                // Store raw data on the source node
                node.data = node.data || {};
                node.data.viewdnsReverseMX = result.results;
                node.data.viewdnsReverseMXFromCache = result.from_cache;
                node.data.viewdnsReverseMXCachedAt = result.cached_at;

                // Get max nodes setting
                const settingsResp = await csrfFetch('/api/viewdns/settings');
                const settings = await settingsResp.json();
                const maxNodes = settings.max_nodes || 100;

                // Process results and create nodes/edges (limited)
                let nodesAdded = 0;
                let edgesAdded = 0;
                const domainsToProcess = result.results.slice(0, maxNodes);

                for (const domain of domainsToProcess) {
                    const cleanDomain = domain.replace(/\.$/, '').toLowerCase();

                    // Skip if same as queried node
                    if (cleanDomain === queryValue) continue;

                    // Create domain node if it doesn't exist
                    const existingNode = this.getNode(cleanDomain);
                    if (!existingNode) {
                        const newNode = this.addNode(cleanDomain, 'domain', false);
                        if (newNode) {
                            nodesAdded++;
                            this.extractBaseDomainAndTLD(cleanDomain, newNode);
                        }
                    }

                    // Create MX edge: domain -> mail server (the queried node)
                    const edgeCreated = this.addEdge(cleanDomain, queryValue, 'MX');
                    if (edgeCreated) edgesAdded++;
                }

                if (result.results.length > maxNodes) {
                    showToast(`Showing ${maxNodes} of ${result.results.length} domains. Download full results from node details.`, 'info');
                }

                console.log(`[ViewDNS] Added ${nodesAdded} nodes and ${edgesAdded} MX edges`);

                this.isModified = true;
                this.render();

                if (this.simulation) {
                    this.simulation.alpha(0.3).restart();
                }

            } catch (error) {
                console.error('ViewDNS Reverse MX error:', error);
                showToast('ViewDNS Reverse MX failed: ' + error.message, 'error');
            } finally {
                this.showLoading(false);
            }
        }

        async resolveViewDNSReverseNS(node) {
            /**
             * Query ViewDNS for domains using the same nameserver
             * Creates Domain nodes and NS edges pointing to the queried node
             */
            if (node.type !== 'domain' && node.type !== 'basedomain') return;

            this.showLoading(true);
            const queryValue = node.id;

            try {
                const response = await csrfFetch('/api/viewdns/reverse-ns', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ value: queryValue })
                });

                const result = await response.json();

                if (result.error) {
                    console.error('ViewDNS Reverse NS failed:', result.error);
                    showToast('ViewDNS Reverse NS failed: ' + result.error, 'error');
                    this.showLoading(false);
                    return;
                }

                if (!result.results || result.results.length === 0) {
                    console.log('No ViewDNS Reverse NS results for:', queryValue);
                    showToast('No domains found using nameserver ' + queryValue, 'warning');
                    this.showLoading(false);
                    return;
                }

                console.log(`[ViewDNS] Found ${result.results.length} domains for NS ${queryValue}`);

                // Store raw data on the source node
                node.data = node.data || {};
                node.data.viewdnsReverseNS = result.results;
                node.data.viewdnsReverseNSFromCache = result.from_cache;
                node.data.viewdnsReverseNSCachedAt = result.cached_at;

                // Get max nodes setting
                const settingsResp = await csrfFetch('/api/viewdns/settings');
                const settings = await settingsResp.json();
                const maxNodes = settings.max_nodes || 100;

                // Process results and create nodes/edges (limited)
                let nodesAdded = 0;
                let edgesAdded = 0;
                const domainsToProcess = result.results.slice(0, maxNodes);

                for (const domain of domainsToProcess) {
                    const cleanDomain = domain.replace(/\.$/, '').toLowerCase();

                    // Skip if same as queried node
                    if (cleanDomain === queryValue) continue;

                    // Create domain node if it doesn't exist
                    const existingNode = this.getNode(cleanDomain);
                    if (!existingNode) {
                        const newNode = this.addNode(cleanDomain, 'domain', false);
                        if (newNode) {
                            nodesAdded++;
                            this.extractBaseDomainAndTLD(cleanDomain, newNode);
                        }
                    }

                    // Create NS edge: domain -> nameserver (the queried node)
                    const edgeCreated = this.addEdge(cleanDomain, queryValue, 'NS');
                    if (edgeCreated) edgesAdded++;
                }

                if (result.results.length > maxNodes) {
                    showToast(`Showing ${maxNodes} of ${result.results.length} domains. Download full results from node details.`, 'info');
                }

                console.log(`[ViewDNS] Added ${nodesAdded} nodes and ${edgesAdded} NS edges`);

                this.isModified = true;
                this.render();

                if (this.simulation) {
                    this.simulation.alpha(0.3).restart();
                }

            } catch (error) {
                console.error('ViewDNS Reverse NS error:', error);
                showToast('ViewDNS Reverse NS failed: ' + error.message, 'error');
            } finally {
                this.showLoading(false);
            }
        }

        async resolveViewDNSReverseWhois(node, queryValue) {
            /**
             * Execute ViewDNS Reverse WHOIS lookup
             * Creates Domain nodes and links them to Registrar nodes
             * @param {Object} node - The source node
             * @param {string} queryValue - The value to search for (domain, email, name, org, etc)
             */
            if (!node || !queryValue) return;

            this.showLoading(true);
            console.log(`[ViewDNS] Executing Reverse WHOIS for: ${queryValue}`);

            try {
                const response = await csrfFetch('/api/viewdns/reverse-whois', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ value: queryValue })
                });

                const result = await response.json();

                if (result.error) {
                    console.error('ViewDNS Reverse WHOIS failed:', result.error);
                    showToast('ViewDNS Reverse WHOIS failed: ' + result.error, 'error');
                    this.showLoading(false);
                    return;
                }

                if (!result.results || result.results.length === 0) {
                    console.log('No ViewDNS Reverse WHOIS results for:', queryValue);
                    showToast('No domains found matching ' + queryValue, 'warning');
                    this.showLoading(false);
                    return;
                }

                console.log(`[ViewDNS] Found ${result.results.length} domains for WHOIS ${queryValue}`);

                // Store raw data on the source node
                node.data = node.data || {};
                node.data.viewdnsReverseWhois = result.results;
                node.data.viewdnsReverseWhoisQuery = queryValue;
                node.data.viewdnsReverseWhoisFromCache = result.from_cache;
                node.data.viewdnsReverseWhoisCachedAt = result.cached_at;

                // Get max nodes setting
                const settingsResp = await csrfFetch('/api/viewdns/settings');
                const settings = await settingsResp.json();
                const maxNodes = settings.max_nodes || 100;

                // Track registrars we've seen
                const registrarNodes = new Map();

                // Process results and create nodes/edges (limited)
                let nodesAdded = 0;
                let edgesAdded = 0;
                const matchesToProcess = result.results.slice(0, maxNodes);

                for (const match of matchesToProcess) {
                    const domain = match.domain.replace(/\.$/, '').toLowerCase();
                    const registrar = match.registrar || '';

                    // Skip if same as queried node
                    if (domain === node.id) continue;

                    // Create domain node if it doesn't exist
                    const existingNode = this.getNode(domain);
                    if (!existingNode) {
                        const newNode = this.addNode(domain, 'domain', false);
                        if (newNode) {
                            newNode.data = newNode.data || {};
                            newNode.data.viewdnsCreatedDate = match.created_date;
                            newNode.data.viewdnsRegistrar = registrar;
                            nodesAdded++;
                            this.extractBaseDomainAndTLD(domain, newNode);
                        }
                    }

                    // Create or get registrar node if registrar is present
                    if (registrar) {
                        const registrarId = `registrar:${registrar}`;
                        if (!registrarNodes.has(registrarId)) {
                            let regNode = this.getNode(registrarId);
                            if (!regNode) {
                                regNode = this.addNode(registrarId, 'registrar', false);
                                if (regNode) {
                                    regNode.data = { name: registrar };
                                    nodesAdded++;
                                }
                            }
                            registrarNodes.set(registrarId, regNode);

                            // Link original node to registrar as well (only for domain nodes)
                            if (node.type === 'domain' || node.type === 'basedomain') {
                                const origEdge = this.addEdge(node.id, registrarId, 'Registrar');
                                if (origEdge) edgesAdded++;
                            }
                        }

                        // Link domain to registrar
                        const edgeCreated = this.addEdge(domain, registrarId, 'Registrar');
                        if (edgeCreated) edgesAdded++;
                    }
                }

                if (result.results.length > maxNodes) {
                    showToast(`Showing ${maxNodes} of ${result.results.length} domains. Download full results from node details.`, 'info');
                }

                console.log(`[ViewDNS] Added ${nodesAdded} nodes and ${edgesAdded} Registrar edges`);

                this.isModified = true;
                this.render();

                if (this.simulation) {
                    this.simulation.alpha(0.3).restart();
                }

            } catch (error) {
                console.error('ViewDNS Reverse WHOIS error:', error);
                showToast('ViewDNS Reverse WHOIS failed: ' + error.message, 'error');
            } finally {
                this.showLoading(false);
            }
        }

        toggleFreezeAll() {
            if (this.nodes.length === 0) return;

            // Check if all nodes are frozen
            const allFrozen = this.nodes.every(n => n.frozen);

            // Toggle all nodes
            for (const node of this.nodes) {
                if (allFrozen) {
                    // Unfreeze all
                    node.frozen = false;
                    node.fx = null;
                    node.fy = null;
                } else {
                    // Freeze all at current positions
                    node.frozen = true;
                    node.fx = node.x;
                    node.fy = node.y;
                }
            }

            this.isModified = true;

            // Update button text
            const btnText = document.getElementById('freeze-all-text');
            btnText.textContent = allFrozen ? 'Freeze all' : 'Unfreeze all';

            // Restart simulation to update visual indicators
            if (this.simulation) {
                this.simulation.alpha(0.1).restart();
            }

            this.render();
        }

        // ========== Physics Panel ==========

        togglePhysicsPanel() {
            this.physicsPanelOpen = !this.physicsPanelOpen;
            const panel = document.getElementById('physics-panel');
            const btn = document.getElementById('physics-panel-btn');

            if (this.physicsPanelOpen) {
                // Close filter panel if open
                if (this.filterPanelOpen) {
                    this.toggleFilterPanel();
                }
                panel.classList.add('active');
                btn.classList.add('active');
                this.updatePhysicsUI();
            } else {
                panel.classList.remove('active');
                btn.classList.remove('active');
            }
        }

        // ========== Filter Panel ==========

        toggleFilterPanel() {
            this.filterPanelOpen = !this.filterPanelOpen;
            const panel = document.getElementById('filter-panel');
            const btn = document.getElementById('filter-panel-btn');

            if (this.filterPanelOpen) {
                // Close physics panel if open
                if (this.physicsPanelOpen) {
                    this.togglePhysicsPanel();
                }
                panel.classList.add('active');
                btn.classList.add('active');
                this.updateFilterUI();
            } else {
                panel.classList.remove('active');
                btn.classList.remove('active');
            }
        }

        updateFilterUI() {
            // Build type counts from current nodes/edges
            // We rebuild counts fresh each time to get accurate numbers
            const nodeTypeCounts = new Map();
            const edgeTypeCounts = new Map();

            // Count node types from the raw nodes array
            for (const node of this.nodes) {
                if (node && node.type) {
                    nodeTypeCounts.set(node.type, (nodeTypeCounts.get(node.type) || 0) + 1);
                }
            }

            // Count edge types from the raw edges array
            for (const edge of this.edges) {
                const edgeType = edge.relationship || 'unknown';
                edgeTypeCounts.set(edgeType, (edgeTypeCounts.get(edgeType) || 0) + 1);
            }

            // Update knownNodeTypes (only add, never remove)
            for (const [type, count] of nodeTypeCounts) {
                this.knownNodeTypes.set(type, count);
            }

            // Update knownEdgeTypes (only add, never remove)
            for (const [type, count] of edgeTypeCounts) {
                this.knownEdgeTypes.set(type, count);
            }

            // Render node type filters using fresh counts
            const nodeContainer = document.getElementById('filter-node-types');
            if (nodeTypeCounts.size > 0) {
                const sortedTypes = [...nodeTypeCounts.entries()].sort((a, b) => b[1] - a[1]);
                nodeContainer.innerHTML = sortedTypes.map(([type, count]) => {
                    const isHidden = this.hiddenNodeTypes.has(type);
                    const color = this.getNodeColor(type);
                    return `
                        <label class="filter-item ${isHidden ? 'type-hidden' : ''}" data-type="${this.escapeHtml(type)}">
                            <input type="checkbox" class="check" ${!isHidden ? 'checked' : ''}>
                            <div class="filter-item-icon" style="background: ${this.escapeHtml(color)};">
                                ${this.escapeHtml(this.getNodeAbbr(type))}
                            </div>
                            <span class="filter-item-label">${this.escapeHtml(type)}</span>
                            <span class="filter-item-count">${this.escapeHtml(String(count))}</span>
                        </label>
                    `;
                }).join('');
            } else {
                nodeContainer.innerHTML = '<div class="filter-empty">No nodes in graph</div>';
            }

            // Render edge type filters using fresh counts
            const edgeContainer = document.getElementById('filter-edge-types');
            if (edgeTypeCounts.size > 0) {
                const sortedTypes = [...edgeTypeCounts.entries()].sort((a, b) => b[1] - a[1]);
                edgeContainer.innerHTML = sortedTypes.map(([type, count]) => {
                    const isHidden = this.hiddenEdgeTypes.has(type);
                    return `
                        <label class="filter-item ${isHidden ? 'type-hidden' : ''}" data-type="${this.escapeHtml(type)}">
                            <input type="checkbox" class="check" ${!isHidden ? 'checked' : ''}>
                            <div class="filter-item-icon edge" aria-hidden="true">
                                ─
                            </div>
                            <span class="filter-item-label">${this.escapeHtml(type)}</span>
                            <span class="filter-item-count">${this.escapeHtml(String(count))}</span>
                        </label>
                    `;
                }).join('');
            } else {
                edgeContainer.innerHTML = '<div class="filter-empty">No edges in graph</div>';
            }

            // Update stats
            let visibleCount = 0;
            for (const node of this.nodes) {
                if (node && node.type && !this.hiddenNodeTypes.has(node.type)) {
                    visibleCount++;
                }
            }
            document.getElementById('filter-visible-nodes').textContent = visibleCount;
            document.getElementById('filter-total-nodes').textContent = this.nodes.length;
            this.updateFilterButton();
        }

        // Colours come from the custom properties in graph.css. They are resolved to literal values
        // once, because the SVG gets them as plain attributes (an exported PNG has no stylesheet).
        getPalette() {
            if (this.palette) return this.palette;
            const style = getComputedStyle(document.documentElement);
            const read = (name, fallback) => (style.getPropertyValue(name) || '').trim() || fallback;
            const fallbacks = {
                ip: '#19e68c', domain: '#6aa9ff', basedomain: '#9cc4ff', tld: '#7d8bf0',
                registrant: '#d58cf0', email: '#f08cc0', org: '#a7b1ba', registrar: '#b08cff',
                asn: '#e8b04a', country: '#5fc9d6', jarm: '#c9d65f', port: '#8d98a3',
                tag: '#f0605a', pivot: '#f08a5d'
            };
            const types = {};
            for (const [type, fallback] of Object.entries(fallbacks)) {
                types[type] = read(`--g-${type}`, fallback);
            }
            this.palette = {
                types,
                other: read('--g-other', '#6b7783'),
                canvas: read('--bg-side', '#0d1114'),
                edge: read('--g-edge', '#2f3a44'),
                edgeLabel: read('--faint', '#5d6873'),
                label: read('--text-2', '#c8d2da'),
                highlight: read('--green', '#19e68c')
            };
            return this.palette;
        }

        getNodeColor(type) {
            const palette = this.getPalette();
            return Object.prototype.hasOwnProperty.call(palette.types, type) ? palette.types[type] : palette.other;
        }

        // One to three letters drawn inside the node circle
        getNodeAbbr(type) {
            const abbreviations = {
                ip: 'IP', domain: 'D', basedomain: 'BD', tld: 'TLD', registrant: 'RG', email: '@',
                org: 'ORG', registrar: 'RR', asn: 'AS', country: 'CC', jarm: 'J', port: 'P',
                tag: 'T', pivot: 'PV'
            };
            if (Object.prototype.hasOwnProperty.call(abbreviations, type)) return abbreviations[type];
            return String(type || '?').substring(0, 2).toUpperCase();
        }

        toggleNodeTypeVisibility(type) {
            if (this.hiddenNodeTypes.has(type)) {
                this.hiddenNodeTypes.delete(type);
            } else {
                this.hiddenNodeTypes.add(type);
            }
            this.render();
            // Just update checkbox states, don't rebuild HTML
            if (this.filterPanelOpen) {
                this.updateFilterCheckboxState();
            }
        }

        toggleEdgeTypeVisibility(type) {
            if (this.hiddenEdgeTypes.has(type)) {
                this.hiddenEdgeTypes.delete(type);
            } else {
                this.hiddenEdgeTypes.add(type);
            }
            this.render();
            // Just update checkbox states, don't rebuild HTML
            if (this.filterPanelOpen) {
                this.updateFilterCheckboxState();
            }
        }

        showAllNodeTypes() {
            this.hiddenNodeTypes.clear();
            this.render();
            if (this.filterPanelOpen) {
                this.updateFilterCheckboxState();
            }
        }

        hideAllNodeTypes() {
            // Collect all types from current nodes
            const allTypes = new Set();
            for (const node of this.nodes) {
                if (node && node.type) {
                    allTypes.add(node.type);
                }
            }
            for (const type of allTypes) {
                this.hiddenNodeTypes.add(type);
            }
            this.render();
            if (this.filterPanelOpen) {
                this.updateFilterCheckboxState();
            }
        }

        showAllEdgeTypes() {
            this.hiddenEdgeTypes.clear();
            this.render();
            if (this.filterPanelOpen) {
                this.updateFilterCheckboxState();
            }
        }

        hideAllEdgeTypes() {
            // Collect all edge types from current edges
            const allTypes = new Set();
            for (const edge of this.edges) {
                allTypes.add(edge.relationship || 'unknown');
            }
            for (const type of allTypes) {
                this.hiddenEdgeTypes.add(type);
            }
            this.render();
            if (this.filterPanelOpen) {
                this.updateFilterCheckboxState();
            }
        }

        // Update checkbox states and classes without rebuilding HTML
        updateFilterCheckboxState() {
            // Update node type checkboxes
            document.querySelectorAll('#filter-node-types .filter-item').forEach(item => {
                const type = item.dataset.type;
                if (type) {
                    const checkbox = item.querySelector('input[type="checkbox"]');
                    const isHidden = this.hiddenNodeTypes.has(type);
                    if (checkbox) checkbox.checked = !isHidden;
                    item.classList.toggle('type-hidden', isHidden);
                }
            });

            // Update edge type checkboxes
            document.querySelectorAll('#filter-edge-types .filter-item').forEach(item => {
                const type = item.dataset.type;
                if (type) {
                    const checkbox = item.querySelector('input[type="checkbox"]');
                    const isHidden = this.hiddenEdgeTypes.has(type);
                    if (checkbox) checkbox.checked = !isHidden;
                    item.classList.toggle('type-hidden', isHidden);
                }
            });

            // Update stats
            let visibleCount = 0;
            for (const node of this.nodes) {
                if (node && node.type && !this.hiddenNodeTypes.has(node.type)) {
                    visibleCount++;
                }
            }
            document.getElementById('filter-visible-nodes').textContent = visibleCount;
            document.getElementById('filter-total-nodes').textContent = this.nodes.length;
            this.updateFilterButton();
        }

        isNodeVisible(node) {
            return !this.hiddenNodeTypes.has(node.type);
        }

        isEdgeVisible(edge) {
            // Edge is hidden if its type is hidden OR if either endpoint node type is hidden
            const edgeType = edge.relationship || 'unknown';
            if (this.hiddenEdgeTypes.has(edgeType)) return false;
            const sourceNode = this.nodes.find(n => n.id === edge.source || n.id === edge.source?.id);
            const targetNode = this.nodes.find(n => n.id === edge.target || n.id === edge.target?.id);
            if (sourceNode && this.hiddenNodeTypes.has(sourceNode.type)) return false;
            if (targetNode && this.hiddenNodeTypes.has(targetNode.type)) return false;
            return true;
        }

        // ========== Search Functions ==========

        handleSearchInput(query) {
            const resultsContainer = document.getElementById('graph-search-results');

            if (!query || query.length < 1) {
                resultsContainer.classList.remove('active');
                this.searchResults = [];
                this.searchSelectedIndex = -1;
                return;
            }

            const lowerQuery = query.toLowerCase();

            // Search nodes
            this.searchResults = this.nodes
                .filter(n => n.id.toLowerCase().includes(lowerQuery))
                .slice(0, 10)
                .map(n => ({
                    node: n,
                    isHidden: this.hiddenNodeTypes.has(n.type)
                }));

            this.searchSelectedIndex = this.searchResults.length > 0 ? 0 : -1;
            this.renderSearchResults();
        }

        renderSearchResults() {
            const resultsContainer = document.getElementById('graph-search-results');

            if (this.searchResults.length === 0) {
                resultsContainer.innerHTML = '<div class="search-no-results">No matching nodes found</div>';
                resultsContainer.classList.add('active');
                return;
            }

            resultsContainer.innerHTML = this.searchResults.map((result, index) => {
                const n = result.node;
                const color = this.getNodeColor(n.type);
                const isSelected = index === this.searchSelectedIndex;

                // Get additional info based on node type
                let extraInfo = '';
                if (n.data) {
                    if (n.type === 'ip' && n.data.geo) {
                        extraInfo = n.data.geo.country || '';
                    } else if (n.type === 'domain' && n.data.whois) {
                        extraInfo = n.data.whois.registrar || '';
                    } else if (n.type === 'asn' && n.data.asn_name) {
                        extraInfo = n.data.asn_name.substring(0, 30);
                    }
                }

                return `
                    <div class="search-result-item ${isSelected ? 'selected' : ''}" data-index="${index}">
                        <div class="search-result-icon" style="background: ${this.escapeHtml(color)};">
                            ${this.escapeHtml(this.getNodeAbbr(n.type))}
                        </div>
                        <div class="search-result-info">
                            <div class="search-result-id">${this.escapeHtml(n.id)}</div>
                            <div class="search-result-type">${this.escapeHtml(n.type)}${extraInfo ? ' • ' + this.escapeHtml(extraInfo) : ''}</div>
                        </div>
                        ${result.isHidden ? '<span class="search-result-hidden">Hidden</span>' : ''}
                    </div>
                `;
            }).join('');

            // Clicks and hover selection are delegated once, in bindUI()
            resultsContainer.classList.add('active');
        }

        handleSearchKeydown(event) {
            const resultsContainer = document.getElementById('graph-search-results');

            if (!resultsContainer.classList.contains('active') || this.searchResults.length === 0) {
                return;
            }

            switch (event.key) {
                case 'ArrowDown':
                    event.preventDefault();
                    this.searchSelectedIndex = Math.min(this.searchSelectedIndex + 1, this.searchResults.length - 1);
                    this.renderSearchResults();
                    break;
                case 'ArrowUp':
                    event.preventDefault();
                    this.searchSelectedIndex = Math.max(this.searchSelectedIndex - 1, 0);
                    this.renderSearchResults();
                    break;
                case 'Enter':
                    event.preventDefault();
                    if (this.searchSelectedIndex >= 0) {
                        this.selectSearchResult(this.searchSelectedIndex);
                    }
                    break;
                case 'Escape':
                    resultsContainer.classList.remove('active');
                    document.getElementById('graph-search-input').blur();
                    break;
            }
        }

        selectSearchResult(index) {
            const result = this.searchResults[index];
            if (!result) return;

            const node = result.node;

            // Close search results
            document.getElementById('graph-search-results').classList.remove('active');
            document.getElementById('graph-search-input').value = '';
            this.searchResults = [];

            // If node type is hidden, unhide it first
            if (this.hiddenNodeTypes.has(node.type)) {
                this.hiddenNodeTypes.delete(node.type);
                this.render();
                if (this.filterPanelOpen) {
                    this.updateFilterUI();
                }
            }

            // Center and zoom to node
            this.centerOnNode(node);
        }

        centerOnNode(node) {
            if (!this.svg || !this.zoom) return;

            // Find the actual node in the simulation (which has x,y coordinates)
            const actualNode = this.nodes.find(n => n.id === node.id);
            if (!actualNode || actualNode.x === undefined || actualNode.y === undefined) {
                console.warn('Cannot center on node - no coordinates:', node.id);
                return;
            }

            const container = document.getElementById('graph-visualization');
            const width = container.clientWidth;
            const height = container.clientHeight;

            // Calculate transform to center on node
            const scale = 1.5;
            const x = width / 2 - actualNode.x * scale;
            const y = height / 2 - actualNode.y * scale;

            // Animate zoom transition
            this.svg.transition()
                .duration(750)
                .call(
                    this.zoom.transform,
                    d3.zoomIdentity.translate(x, y).scale(scale)
                );

            // Highlight the node briefly
            this.highlightNode(actualNode);
        }

        highlightNode(node) {
            // Find the node element and add highlight effect
            const nodeEl = this.svg.select(`.node[data-id="${CSS.escape(node.id)}"]`);
            if (nodeEl.empty()) return;

            // Pulse a ring on the base circle, which has no stroke of its own
            const color = this.getPalette().highlight;
            nodeEl.select('.node-base')
                .transition()
                .duration(200)
                .attr('stroke', color)
                .attr('stroke-width', 6)
                .transition()
                .duration(200)
                .attr('stroke', color)
                .attr('stroke-width', 10)
                .transition()
                .duration(200)
                .attr('stroke', color)
                .attr('stroke-width', 6)
                .transition()
                .duration(200)
                .attr('stroke', color)
                .attr('stroke-width', 10)
                .transition()
                .duration(500)
                .attr('stroke', 'none')
                .attr('stroke-width', 0);
        }

        updatePhysicsUI() {
            // Update all slider values and displays
            const ps = this.physicsSettings;

            document.getElementById('physics-link-distance').value = ps.linkDistance;
            document.getElementById('physics-link-distance-value').textContent = ps.linkDistance;

            document.getElementById('physics-link-strength').value = ps.linkStrength * 100;
            document.getElementById('physics-link-strength-value').textContent = ps.linkStrength.toFixed(2);

            document.getElementById('physics-charge').value = ps.charge;
            document.getElementById('physics-charge-value').textContent = ps.charge;

            document.getElementById('physics-collision').value = ps.collision;
            document.getElementById('physics-collision-value').textContent = ps.collision;

            document.getElementById('physics-center').value = ps.center * 100;
            document.getElementById('physics-center-value').textContent = ps.center.toFixed(2);

            document.getElementById('physics-decay').value = ps.decay * 1000;
            document.getElementById('physics-decay-value').textContent = ps.decay.toFixed(3);
        }

        updatePhysics(property, value) {
            const numValue = parseFloat(value);
            this.physicsSettings[property] = numValue;
            this.isModified = true;

            // Update display value
            const displayEl = document.getElementById(`physics-${property === 'linkDistance' ? 'link-distance' : 
                property === 'linkStrength' ? 'link-strength' : property}-value`);
            if (displayEl) {
                if (property === 'linkStrength' || property === 'center') {
                    displayEl.textContent = numValue.toFixed(2);
                } else if (property === 'decay') {
                    displayEl.textContent = numValue.toFixed(3);
                } else {
                    displayEl.textContent = numValue;
                }
            }

            // Apply to simulation if active
            if (this.simulation) {
                const ps = this.physicsSettings;

                switch (property) {
                    case 'linkDistance':
                        this.simulation.force('link').distance(numValue);
                        break;
                    case 'linkStrength':
                        this.simulation.force('link').strength(numValue);
                        break;
                    case 'charge':
                        this.simulation.force('charge').strength(numValue);
                        break;
                    case 'collision':
                        this.simulation.force('collision').radius(numValue);
                        break;
                    case 'center':
                        this.simulation.force('center').strength(numValue);
                        break;
                    case 'decay':
                        this.simulation.alphaDecay(numValue);
                        break;
                }

                // Reheat simulation
                this.simulation.alpha(0.3).restart();
            }
        }

        applyPhysicsPreset(preset) {
            const presets = {
                default: {
                    linkDistance: 100,
                    linkStrength: 0.3,
                    charge: -300,
                    collision: 35,
                    center: 0.05,
                    decay: 0.02
                },
                compact: {
                    linkDistance: 50,
                    linkStrength: 0.6,
                    charge: -150,
                    collision: 25,
                    center: 0.1,
                    decay: 0.02
                },
                spread: {
                    linkDistance: 200,
                    linkStrength: 0.2,
                    charge: -500,
                    collision: 50,
                    center: 0.02,
                    decay: 0.015
                },
                clustered: {
                    linkDistance: 60,
                    linkStrength: 0.8,
                    charge: -200,
                    collision: 30,
                    center: 0.03,
                    decay: 0.025
                }
            };

            const settings = presets[preset];
            if (!settings) return;

            // Apply all settings
            this.physicsSettings = { ...settings };
            this.isModified = true;

            // Update UI
            this.updatePhysicsUI();

            // Update preset button states
            document.querySelectorAll('.preset-btn').forEach(btn => {
                btn.classList.toggle('on', btn.dataset.preset === preset);
            });

            // Apply to simulation
            if (this.simulation) {
                const ps = this.physicsSettings;
                this.simulation.force('link').distance(ps.linkDistance).strength(ps.linkStrength);
                this.simulation.force('charge').strength(ps.charge);
                this.simulation.force('collision').radius(ps.collision);
                this.simulation.force('center').strength(ps.center);
                this.simulation.alphaDecay(ps.decay);
                this.simulation.alpha(0.5).restart();
            }

            showToast(`Applied "${preset}" preset`, 'success', 2000);
        }

        newGraph() {
            if (this.nodes.length === 0) {
                // Already empty, just reset
                this.reset();
                this.hideGraph();
                return;
            }

            const confirmed = confirm('Are you sure you want to create a new graph? This will clear all current nodes and edges.');

            if (confirmed) {
                this.reset();
                this.hideGraph();

                // Update URL to remove any graph ID
                const url = new URL(window.location.href);
                url.hash = '#graph';
                window.history.replaceState({}, '', url);
            }
        }

        showAddNodeModal() {
            // Reset the form
            document.getElementById('add-node-type').value = 'ip';
            document.getElementById('add-node-value').value = '';
            updateAddNodePlaceholder();

            // Show modal
            openGraphDialog('add-node-modal');

            // Focus input
            setTimeout(() => {
                document.getElementById('add-node-value').focus();
            }, 100);
        }

        async addNodeFromModal(value, type) {
            // Format node ID based on type
            let nodeId = value;
            if (type === 'port') {
                nodeId = `port:${value}`;
            } else if (type === 'tag') {
                nodeId = `tag:${value}`;
            }

            // Check if node already exists
            if (this.nodeExists(nodeId)) {
                showToast(`Node "${nodeId}" already exists in graph`, 'info');
                // Highlight existing node
                const existingNode = this.getNode(nodeId);
                if (existingNode) {
                    this.showNodeDetails(existingNode);
                    this.centerOnNode(existingNode);
                }
                return;
            }

            // Ensure graph is visible
            this.showGraph();

            // Add the node based on type
            if (type === 'domain') {
                this.addDomainWithTLD(value, false);
            } else if (type === 'port') {
                const node = this.addNode(nodeId, 'port', false);
                if (node) {
                    node.data = { port: value };
                }
            } else if (type === 'tag') {
                const node = this.addNode(nodeId, 'tag', false);
                if (node) {
                    node.data = { tag: value };
                }
            } else {
                this.addNode(nodeId, type, false);
            }

            // For IPs and domains, do automatic enrichment
            if (type === 'ip' || type === 'domain') {
                showToast(`Adding ${type} "${value}" with enrichment...`, 'info');
                await this.resolveAndExpand(value, type);
                showToast(`Node "${value}" added and enriched`, 'success');
            } else {
                // For other types, just render
                this.render();
                showToast(`Node "${nodeId}" added`, 'success');
            }
        }

        showAddConnectionModal(sourceNode) {
            this.connectionSourceNode = sourceNode;

            document.getElementById('connection-source-name').textContent = sourceNode.id;
            document.getElementById('connection-target').value = '';
            document.getElementById('connection-target-type').value = 'domain';
            document.getElementById('connection-relationship').value = 'A';
            document.getElementById('connection-custom-relationship').value = '';
            document.getElementById('custom-relationship-group').style.display = 'none';

            openGraphDialog('add-connection-modal');
        }

        confirmAddConnection() {
            const sourceNode = this.connectionSourceNode;
            if (!sourceNode) return;

            const targetValue = document.getElementById('connection-target').value.trim();
            const targetType = document.getElementById('connection-target-type').value;
            let relationship = document.getElementById('connection-relationship').value;

            if (relationship === 'custom') {
                relationship = document.getElementById('connection-custom-relationship').value.trim();
            }

            if (!targetValue) {
                alert('Please enter a target node value.');
                return;
            }

            if (!relationship) {
                alert('Please enter a relationship type.');
                return;
            }

            // Add the target node if it doesn't exist
            if (targetType === 'domain') {
                this.addDomainWithTLD(targetValue, false);
            } else {
                this.addNode(targetValue, targetType, false);
            }

            // Add the edge
            this.addEdge(sourceNode.id, targetValue, relationship);

            // Close modal and re-render
            closeGraphDialog('add-connection-modal');
            this.connectionSourceNode = null;
            this.render();
        }

        async enrichNode() {
            if (!this.selectedNode) return;

            // The panel stays open; render() refreshes it when the lookups finish
            await this.resolveAndExpand(this.selectedNode.id, this.selectedNode.type);
        }

        async resolveWhois(skipModal = false) {
            if (!this.selectedNode || this.selectedNode.type !== 'domain') return;

            // The selection can change while the lookup runs, so hold on to the node
            const target = this.selectedNode;
            const domain = target.id;
            const whoisBtn = document.getElementById('whois-node-btn');
            const originalText = whoisBtn ? whoisBtn.innerHTML : '';

            if (whoisBtn) {
                whoisBtn.disabled = true;
                whoisBtn.textContent = 'Loading...';
            }

            try {
                const response = await csrfFetch('/api/whois/resolve', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain })
                });

                const data = await response.json();

                if (data.error) {
                    if (!skipModal) alert('WHOIS lookup failed: ' + data.error);
                    return;
                }

                // Store WHOIS data in node and mark as resolved
                target.data = target.data || {};
                target.data.whois = data;
                target.data.whoisResolved = true;
                this.isModified = true;

                // Add all names as registrant nodes
                if (data.all_names && data.all_names.length > 0) {
                    for (const name of data.all_names) {
                        const node = this.addNode(name, 'registrant', false);
                        if (node) {
                            node.data = { entityType: 'registrant_name' };
                        }
                        this.addEdge(domain, name, 'registrant');
                    }
                } else if (data.registrant_name) {
                    // Fallback to single value for backwards compatibility
                    const node = this.addNode(data.registrant_name, 'registrant', false);
                    if (node) {
                        node.data = { entityType: 'registrant_name' };
                    }
                    this.addEdge(domain, data.registrant_name, 'registrant');
                }

                // Add all emails as email nodes
                if (data.all_emails && data.all_emails.length > 0) {
                    for (const email of data.all_emails) {
                        const node = this.addNode(email, 'email', false);
                        if (node) {
                            node.data = { entityType: 'registrant_email' };
                        }
                        this.addEdge(domain, email, 'email');
                    }
                } else if (data.registrant_email) {
                    // Fallback to single value for backwards compatibility
                    const node = this.addNode(data.registrant_email, 'email', false);
                    if (node) {
                        node.data = { entityType: 'registrant_email' };
                    }
                    this.addEdge(domain, data.registrant_email, 'email');
                }

                // Add all organizations as org nodes
                if (data.all_organizations && data.all_organizations.length > 0) {
                    for (const org of data.all_organizations) {
                        const node = this.addNode(org, 'org', false);
                        if (node) {
                            node.data = { entityType: 'organization' };
                        }
                        this.addEdge(domain, org, 'org');
                    }
                } else if (data.organization) {
                    // Fallback to single value for backwards compatibility
                    const node = this.addNode(data.organization, 'org', false);
                    if (node) {
                        node.data = { entityType: 'organization' };
                    }
                    this.addEdge(domain, data.organization, 'org');
                }

                // Add all registrars as registrar nodes
                if (data.all_registrars && data.all_registrars.length > 0) {
                    for (const registrar of data.all_registrars) {
                        const registrarId = `registrar:${registrar}`;
                        const node = this.addNode(registrarId, 'registrar', false);
                        if (node) {
                            node.data = { entityType: 'registrar', name: registrar };
                        }
                        this.addEdge(domain, registrarId, 'Registrar');
                    }
                } else if (data.registrar) {
                    // Fallback to single value for backwards compatibility
                    const registrarId = `registrar:${data.registrar}`;
                    const node = this.addNode(registrarId, 'registrar', false);
                    if (node) {
                        node.data = { entityType: 'registrar', name: data.registrar };
                    }
                    this.addEdge(domain, registrarId, 'Registrar');
                }

                // Refresh the modal content only if not skipping
                if (!skipModal && this.selectedNode === target) {
                    this.showNodeDetails(target);
                }

                // Re-render graph
                this.render();

            } catch (err) {
                console.error('WHOIS lookup failed:', err);
                if (!skipModal) alert('WHOIS lookup failed: ' + err.message);
            } finally {
                if (whoisBtn) {
                    whoisBtn.disabled = false;
                    whoisBtn.innerHTML = originalText;
                }
            }
        }

        async resolveGeoFromModal() {
            if (!this.selectedNode || this.selectedNode.type !== 'ip') return;

            const target = this.selectedNode;
            const geoBtn = document.getElementById('geo-node-btn');
            const originalText = geoBtn.innerHTML;

            geoBtn.disabled = true;
            geoBtn.textContent = 'Loading...';

            try {
                await this.resolveGeoForNode(target);

                // Refresh the panel content
                if (this.selectedNode === target) this.showNodeDetails(target);

            } catch (err) {
                console.error('Geo lookup failed:', err);
                alert('Geo lookup failed: ' + err.message);
            } finally {
                geoBtn.disabled = false;
                geoBtn.innerHTML = originalText;
            }
        }

        removeNode() {
            if (!this.selectedNode) return;

            const nodeId = this.selectedNode.id;

            // Remove node
            this.nodes = this.nodes.filter(n => n.id !== nodeId);

            // Remove connected edges (handle both string IDs and D3's node object references)
            this.edges = this.edges.filter(e => {
                const sourceId = typeof e.source === 'object' ? e.source.id : e.source;
                const targetId = typeof e.target === 'object' ? e.target.id : e.target;
                return sourceId !== nodeId && targetId !== nodeId;
            });

            this.isModified = true;

            this.clearSelection();

            if (this.nodes.length === 0) {
                this.hideGraph();
            } else {
                this.render();
            }
        }

        // ========== Save/Export ==========

        saveGraph() {
            document.getElementById('graph-save-name').value = this.graphName;
            openGraphDialog('graph-save-modal');
        }

        async showLoadModal() {
            const listContainer = document.getElementById('load-graphs-list');

            // Show the dialog with a loading state
            listContainer.replaceChildren(this.noteElement('Loading saved graphs…'));
            openGraphDialog('graph-load-modal');

            try {
                const response = await csrfFetch('/api/graph/list');
                const data = await response.json();

                if (data.graphs && data.graphs.length > 0) {
                    const fragment = document.createDocumentFragment();
                    data.graphs.forEach(g => {
                        const item = document.createElement('button');
                        item.type = 'button';
                        item.className = 'line load-graph-item';
                        item.dataset.graphId = g.id;

                        const info = document.createElement('span');
                        info.className = 'grow load-graph-info';
                        const name = document.createElement('b');
                        name.className = 'load-graph-name';
                        name.textContent = g.name;
                        const date = document.createElement('small');
                        date.className = 'load-graph-date';
                        const updated = new Date(g.updated_at);
                        date.textContent = `${updated.toLocaleDateString()} ${updated.toLocaleTimeString()}`;
                        info.append(name, date);

                        const hint = document.createElement('span');
                        hint.className = 'faint';
                        hint.textContent = g.is_shared ? 'shared · Open' : 'Open';
                        item.append(info, hint);
                        fragment.append(item);
                    });
                    listContainer.replaceChildren(fragment);
                } else {
                    listContainer.replaceChildren(this.noteElement('No saved graphs found'));
                }
            } catch (err) {
                console.error('Failed to load graphs:', err);
                listContainer.replaceChildren(this.noteElement('Failed to load saved graphs', 'card-b red'));
            }
        }

        async loadGraphFromModal(graphId) {
            // Close the modal
            closeGraphDialog('graph-load-modal');

            // Check if current graph has unsaved changes
            if (this.nodes.length > 0 && this.isModified) {
                if (!confirm('You have unsaved changes. Are you sure you want to load a different graph?')) {
                    return;
                }
            }

            // Load the graph
            await this.loadGraph(graphId);
        }

        async confirmSave() {
            const name = document.getElementById('graph-save-name').value.trim() || 'Untitled Graph';
            this.graphName = name;

            // Serialize edges with string IDs (D3 mutates them to object references)
            const serializedEdges = this.edges.map(e => ({
                source: typeof e.source === 'object' ? e.source.id : e.source,
                target: typeof e.target === 'object' ? e.target.id : e.target,
                relationship: e.relationship
            }));

            // Serialize nodes without D3's simulation properties
            const serializedNodes = this.nodes.map(n => ({
                id: n.id,
                type: n.type,
                isOrigin: n.isOrigin,
                data: n.data,
                frozen: n.frozen || false
            }));

            try {
                const response = await csrfFetch('/api/graph/save', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        id: this.graphId,
                        name: this.graphName,
                        data: {
                            nodes: serializedNodes,
                            edges: serializedEdges,
                            physics: this.physicsSettings
                        }
                    })
                });

                const result = await response.json();

                if (result.success) {
                    this.graphId = result.id;
                    this.isModified = false;

                    window.history.replaceState({}, '', `?graph=${result.id}`);
                    this.updateHeader();

                    this.loadSavedGraphsList();
                }
            } catch (err) {
                console.error('Failed to save graph:', err);
                alert('Failed to save graph');
            }

            closeGraphDialog('graph-save-modal');
            this.updateHeader();
        }

        exportPNG() {
            const svg = document.getElementById('graph-svg');
            if (!svg) return;

            const width = svg.clientWidth;
            const height = svg.clientHeight;
            if (!width || !height) {
                showToast('Open the canvas view to export a PNG', 'info');
                return;
            }

            // Serialise a copy with an explicit pixel size. Everything the drawing needs (colours,
            // glyph letters, fonts with generic fallbacks) is in SVG attributes, not in the stylesheet.
            const copy = svg.cloneNode(true);
            copy.setAttribute('width', width);
            copy.setAttribute('height', height);
            copy.removeAttribute('style');
            const svgString = new XMLSerializer().serializeToString(copy);

            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            const img = new Image();

            canvas.width = width * 2;
            canvas.height = height * 2;
            ctx.scale(2, 2);
            ctx.fillStyle = this.getPalette().canvas;
            ctx.fillRect(0, 0, width, height);

            img.onload = () => {
                ctx.drawImage(img, 0, 0, width, height);
                const link = document.createElement('a');
                link.download = `graph_${this.graphId || 'export'}.png`;
                link.href = canvas.toDataURL('image/png');
                link.click();
            };
            img.onerror = () => showToast('PNG export failed', 'error');

            img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgString)));
        }

        exportJSON() {
            // Serialize edges with string IDs (D3 mutates them to object references)
            const serializedEdges = this.edges.map(e => ({
                source: typeof e.source === 'object' ? e.source.id : e.source,
                target: typeof e.target === 'object' ? e.target.id : e.target,
                relationship: e.relationship
            }));

            // Serialize nodes without D3's simulation properties
            const serializedNodes = this.nodes.map(n => ({
                id: n.id,
                type: n.type,
                isOrigin: n.isOrigin,
                data: n.data,
                frozen: n.frozen || false
            }));

            const data = {
                id: this.graphId,
                name: this.graphName,
                nodes: serializedNodes,
                edges: serializedEdges,
                exportedAt: new Date().toISOString()
            };

            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const link = document.createElement('a');
            link.download = `graph_${this.graphId || 'export'}.json`;
            link.href = URL.createObjectURL(blob);
            link.click();
            URL.revokeObjectURL(link.href);
        }

        // ========== View Toggle ==========

        toggleView() {
            this.setView(this.currentView === 'graph' ? 'table' : 'graph');
        }

        // 'graph' is the canvas, 'table' the relationship table (Stats is its own workspace view)
        setView(view) {
            if (view !== 'graph' && view !== 'table') return;
            this.currentView = view;
            this.updateViewVisibility();
            if (view === 'table') this.renderTable();
        }

        updateViewVisibility() {
            const showCanvas = this.graphVisible && this.currentView === 'graph';
            const showTable = this.graphVisible && this.currentView === 'table';
            document.getElementById('graph-empty-state').style.display = this.graphVisible ? 'none' : '';
            document.getElementById('graph-canvas-view').style.display = showCanvas ? '' : 'none';
            document.getElementById('graph-table-view').style.display = showTable ? '' : 'none';
            document.querySelectorAll('#graph-panel [data-graph-view]').forEach(button => {
                const on = button.dataset.graphView === this.currentView;
                button.classList.toggle('on', on);
                button.setAttribute('aria-pressed', on ? 'true' : 'false');
            });
        }

        toggleEdgeLabels() {
            this.showEdgeLabels = !this.showEdgeLabels;
            const button = document.getElementById('edge-labels-toggle');
            button.classList.toggle('active', this.showEdgeLabels);
            button.setAttribute('aria-pressed', this.showEdgeLabels ? 'true' : 'false');

            if (this.svg) {
                this.svg.selectAll('.edge-label').style('display', this.showEdgeLabels ? '' : 'none');
            }
        }

        toggleFullscreen() {
            const container = document.getElementById('graph-container');
            const btn = document.getElementById('fullscreen-toggle');

            const fullscreen = !container.classList.contains('fullscreen');
            container.classList.toggle('fullscreen', fullscreen);
            btn.classList.toggle('active', fullscreen);
            btn.setAttribute('aria-pressed', fullscreen ? 'true' : 'false');
            btn.textContent = fullscreen ? 'Exit full screen' : 'Full screen';
            document.body.style.overflow = fullscreen ? 'hidden' : '';

            // Re-render to adjust to new size
            if (this.simulation) {
                this.simulation.alpha(0.3).restart();
            }
        }

        // The canvas changed size: re-centre the simulation on it
        handleResize() {
            const container = document.getElementById('graph-visualization');
            const width = container.clientWidth;
            const height = container.clientHeight;
            if (!width || !height || !this.svg || !this.simulation) return;
            if (width === this.lastWidth && height === this.lastHeight) return;
            this.lastWidth = width;
            this.lastHeight = height;

            this.svg.attr('width', width).attr('height', height);
            this.simulation.force('center', d3.forceCenter(width / 2, height / 2).strength(this.physicsSettings.center));
            this.simulation.alpha(0.3).restart();
        }

        // Header subtitle: graph name, node and relationship counts
        updateHeader() {
            const nodes = this.nodes.length;
            const edges = this.edges.length;
            const name = this.graphName || 'Untitled Graph';
            const counts = ` · ${nodes} node${nodes === 1 ? '' : 's'} · ${edges} relationship${edges === 1 ? '' : 's'}` +
                (this.isModified && nodes > 0 ? ' · unsaved changes' : '');

            const nameEl = document.getElementById('graph-name-display');
            const countsEl = document.getElementById('graph-counts');
            const statsEl = document.getElementById('graph-stats-subtitle');
            if (nameEl) nameEl.textContent = name;
            if (countsEl) countsEl.textContent = counts;
            if (statsEl) statsEl.textContent = name + counts;
            this.updateFilterButton();
        }

        // The Filters button says how much is visible while a filter is on
        updateFilterButton() {
            const button = document.getElementById('filter-panel-btn');
            if (!button) return;
            const filtered = this.hiddenNodeTypes.size > 0 || this.hiddenEdgeTypes.size > 0;
            const visible = this.nodes.filter(n => this.isNodeVisible(n)).length;
            button.textContent = filtered ? `Filters · ${visible} of ${this.nodes.length}` : 'Filters';
        }

        // Header "Share": shares the saved graph that is open (the saved-graphs list has the per-graph buttons)
        shareCurrentGraph() {
            if (!this.graphId) {
                showToast('Save this graph first, then share it.', 'info');
                return;
            }
            this.shareGraph(this.graphId);
        }

        // ========== Rendering ==========

        showGraph() {
            this.graphVisible = true;
            this.updateViewVisibility();
            this.updateHeader();
        }

        hideGraph() {
            this.graphVisible = false;
            this.renderedNodeIds = null;
            this.currentView = 'graph';
            this.updateViewVisibility();
            this.clearSelection();
            this.updateHeader();
            this.loadSavedGraphsList();
        }

        showLoading(show, message = 'Loading...') {
            document.getElementById('graph-loading').style.display = show ? 'flex' : 'none';
            if (show) {
                document.getElementById('graph-loading-text').textContent = message;
            }
        }

        render() {
            if (this.nodes.length === 0) {
                this.hideGraph();
                return;
            }

            const container = document.getElementById('graph-visualization');
            const width = container.clientWidth;
            const height = container.clientHeight || 500;
            this.lastWidth = width;
            this.lastHeight = container.clientHeight;
            const palette = this.getPalette();
            const monoFont = 'JetBrains Mono, Consolas, monospace';
            const nodeRadius = 16;

            // Clear previous
            d3.select('#graph-svg').selectAll('*').remove();

            this.svg = d3.select('#graph-svg')
                .attr('width', width)
                .attr('height', height);

            // Create arrow marker
            this.svg.append('defs').append('marker')
                .attr('id', 'arrowhead')
                .attr('viewBox', '-0 -5 10 10')
                .attr('refX', 19)
                .attr('refY', 0)
                .attr('orient', 'auto')
                .attr('markerWidth', 6)
                .attr('markerHeight', 6)
                .append('path')
                .attr('d', 'M 0,-5 L 10 ,0 L 0,5')
                .attr('fill', palette.edgeLabel);

            // Prepare data for D3 - filter visible nodes and edges
            const nodeMap = {};
            this.nodes.forEach(n => nodeMap[n.id] = n);

            // Filter visible nodes
            const visibleNodes = this.nodes.filter(n => this.isNodeVisible(n));
            const visibleNodeIds = new Set(visibleNodes.map(n => n.id));

            // Filter visible edges (must have both endpoints visible and edge type visible)
            const visibleEdges = this.edges.filter(e => {
                const edgeType = e.relationship || 'unknown';
                if (this.hiddenEdgeTypes.has(edgeType)) return false;
                const sourceId = typeof e.source === 'object' ? e.source.id : e.source;
                const targetId = typeof e.target === 'object' ? e.target.id : e.target;
                return visibleNodeIds.has(sourceId) && visibleNodeIds.has(targetId);
            });

            const links = visibleEdges.map(e => ({
                source: typeof e.source === 'object' ? e.source.id : e.source,
                target: typeof e.target === 'object' ? e.target.id : e.target,
                relationship: e.relationship
            }));

            // Is this a redraw of the graph that was on screen, or a different graph?
            const sameGraph = !!this.renderedNodeIds && visibleNodes.some(n => this.renderedNodeIds.has(n.id));
            this.renderedNodeIds = visibleNodeIds;

            // Create simulation using physics settings (the previous one must not keep ticking)
            if (this.simulation) this.simulation.stop();
            const ps = this.physicsSettings;
            this.simulation = d3.forceSimulation(visibleNodes)
                .force('link', d3.forceLink(links).id(d => d.id).distance(ps.linkDistance).strength(ps.linkStrength))
                .force('charge', d3.forceManyBody().strength(ps.charge))
                .force('center', d3.forceCenter(width / 2, height / 2).strength(ps.center))
                .force('collision', d3.forceCollide().radius(ps.collision))
                .alphaDecay(ps.decay);

            // Draw edges
            const edgeGroup = this.svg.append('g').attr('class', 'edges');

            const edge = edgeGroup.selectAll('line')
                .data(links)
                .enter()
                .append('line')
                .attr('class', 'edge')
                .attr('stroke', palette.edge)
                .attr('stroke-width', 1.5)
                .attr('marker-end', 'url(#arrowhead)');

            // Edge labels
            const edgeLabels = edgeGroup.selectAll('.edge-label')
                .data(links)
                .enter()
                .append('text')
                .attr('class', 'edge-label')
                .attr('font-family', monoFont)
                .attr('font-size', '10px')
                .attr('fill', palette.edgeLabel)
                .attr('text-anchor', 'middle')
                .style('display', this.showEdgeLabels ? '' : 'none')
                .text(d => d.relationship);

            // Draw nodes
            const nodeGroup = this.svg.append('g').attr('class', 'nodes');

            const node = nodeGroup.selectAll('.node')
                .data(visibleNodes)
                .enter()
                .append('g')
                .attr('class', d => `node node-${d.type} ${d.isOrigin ? 'node-origin' : 'node-discovered'}`)
                .attr('data-id', d => d.id)
                .call(d3.drag()
                    .on('start', (event, d) => {
                        if (!event.active) this.simulation.alphaTarget(0.3).restart();
                        d.fx = d.x;
                        d.fy = d.y;
                    })
                    .on('drag', (event, d) => {
                        d.fx = event.x;
                        d.fy = event.y;
                    })
                    .on('end', (event, d) => {
                        if (!event.active) this.simulation.alphaTarget(0);
                        // Only unfreeze if not explicitly frozen
                        if (!d.frozen) {
                            d.fx = null;
                            d.fy = null;
                        }
                    }))
                .on('click', (event, d) => {
                    event.stopPropagation();
                    this.closeMenus();
                    this.hideContextMenu();
                    this.showNodeDetails(d);
                })
                .on('contextmenu', (event, d) => {
                    event.preventDefault();
                    event.stopPropagation();
                    this.showContextMenu(event, d);
                });

            // Node glyphs: a coloured circle with a short type abbreviation inside. Colours are written
            // as literal attributes so the drawing survives PNG export without the stylesheet or fonts.
            const manager = this;
            node.each(function(d) {
                const g = d3.select(this);
                const color = manager.getNodeColor(d.type);
                const abbr = manager.getNodeAbbr(d.type);

                // Tooltip with the full value
                g.append('title').text(`${d.id} (${d.type})`);

                // Opaque base so edges do not show through; the search highlight pulses on it
                g.append('circle')
                    .attr('class', 'node-base')
                    .attr('r', nodeRadius)
                    .attr('fill', palette.canvas);

                // Type colour; starting points get a thicker ring
                g.append('circle')
                    .attr('class', 'node-shape')
                    .attr('r', nodeRadius)
                    .attr('fill', color)
                    .attr('fill-opacity', d.isOrigin ? 0.22 : 0.1)
                    .attr('stroke', color)
                    .attr('stroke-width', d.isOrigin ? 3.5 : 1.5);

                g.append('text')
                    .attr('class', 'node-glyph')
                    .attr('text-anchor', 'middle')
                    .attr('dy', '0.35em')
                    .attr('font-family', monoFont)
                    .attr('font-size', abbr.length > 2 ? '8px' : '10px')
                    .attr('font-weight', 500)
                    .attr('fill', color)
                    .attr('pointer-events', 'none')
                    .text(abbr);

                // Dashed outer ring for frozen nodes
                manager.drawFrozenRing(g, d);
            });

            // Node labels
            node.append('text')
                .attr('class', 'node-label')
                .attr('dy', nodeRadius + 14)
                .attr('text-anchor', 'middle')
                .attr('font-family', monoFont)
                .attr('font-size', '10px')
                .attr('fill', palette.label)
                .text(d => d.id.length > 20 ? d.id.substring(0, 18) + '...' : d.id);

            // The node shown in the panel stays marked
            node.classed('selected', d => !!this.selectedNode && d.id === this.selectedNode.id);

            // A click on the empty canvas clears the selection
            this.svg.on('click', () => this.clearSelection());

            // Simulation tick
            this.simulation.on('tick', () => {
                edge
                    .attr('x1', d => d.source.x)
                    .attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x)
                    .attr('y2', d => d.target.y);

                edgeLabels
                    .attr('x', d => (d.source.x + d.target.x) / 2)
                    .attr('y', d => (d.source.y + d.target.y) / 2);

                node.attr('transform', d => `translate(${d.x},${d.y})`);
            });

            // Zoom
            this.zoom = d3.zoom()
                .scaleExtent([0.1, 4])
                .on('zoom', (event) => {
                    nodeGroup.attr('transform', event.transform);
                    edgeGroup.attr('transform', event.transform);
                });

            this.svg.call(this.zoom);

            // A redraw keeps the pan and zoom the user had; a different graph starts from the default view
            if (!sameGraph) this.svg.call(this.zoom.transform, d3.zoomIdentity);
            const currentTransform = d3.zoomTransform(this.svg.node());
            nodeGroup.attr('transform', currentTransform);
            edgeGroup.attr('transform', currentTransform);

            this.updateHeader();
            this.refreshNodePanel();

            // Also render table if in table view
            if (this.currentView === 'table') {
                this.renderTable();
            }
        }

        // Dashed outer ring that marks a frozen node (also called when a single node is frozen)
        drawFrozenRing(g, d) {
            g.selectAll('.node-frozen').remove();
            if (!d.frozen) return;
            g.append('circle')
                .attr('class', 'node-frozen')
                .attr('r', 21)
                .attr('fill', 'none')
                .attr('stroke', this.getNodeColor(d.type))
                .attr('stroke-width', 1)
                .attr('stroke-dasharray', '3,2')
                .attr('opacity', 0.7)
                .attr('pointer-events', 'none');
        }

        renderTable() {
            const tbody = document.getElementById('graph-table-body');
            const tones = { ip: 'green', asn: 'amber', tag: 'red' };

            const nodeCell = (node, id) => {
                const td = document.createElement('td');
                const type = document.createElement('span');
                type.className = `tag ${tones[node.type] || ''}`.trim();
                type.textContent = String(node.type);
                const value = document.createElement('span');
                value.className = 'mono';
                value.textContent = id;
                td.append(type, ' ', value);
                return td;
            };

            // Build table data: one row per edge
            const fragment = document.createDocumentFragment();

            this.edges.forEach(edge => {
                // Handle both string IDs and D3's node object references
                const sourceId = typeof edge.source === 'object' ? edge.source.id : edge.source;
                const targetId = typeof edge.target === 'object' ? edge.target.id : edge.target;

                const sourceNode = this.nodes.find(n => n.id === sourceId);
                const targetNode = this.nodes.find(n => n.id === targetId);

                if (!sourceNode || !targetNode) return;

                const row = document.createElement('tr');
                row.dataset.source = sourceId;
                row.dataset.target = targetId;

                const relationshipCell = document.createElement('td');
                const relationship = document.createElement('span');
                relationship.className = 'code';
                relationship.textContent = edge.relationship;
                relationshipCell.append(relationship);

                const actionCell = document.createElement('td');
                actionCell.className = 'right';
                const remove = document.createElement('button');
                remove.type = 'button';
                remove.className = 'btn sm';
                remove.dataset.removeEdge = '';
                remove.title = 'Remove relationship';
                remove.textContent = 'Remove';
                actionCell.append(remove);

                row.append(nodeCell(sourceNode, sourceId), relationshipCell, nodeCell(targetNode, targetId), actionCell);
                fragment.append(row);
            });

            if (!fragment.childNodes.length) {
                const row = document.createElement('tr');
                const td = document.createElement('td');
                td.colSpan = 4;
                td.className = 'muted';
                td.style.textAlign = 'center';
                td.textContent = 'No relationships to display';
                row.append(td);
                fragment.append(row);
            }

            tbody.replaceChildren(fragment);

            // Keep the filter the user typed
            const search = document.getElementById('graph-table-search');
            if (search && search.value) this.filterTable(search.value);
        }

        filterTable(searchTerm) {
            const rows = document.querySelectorAll('#graph-table-body tr');
            const term = searchTerm.toLowerCase();

            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(term) ? '' : 'none';
            });
        }

        removeEdgeFromTable(source, target) {
            // Remove the edge - handle both string IDs and D3's node object references
            this.edges = this.edges.filter(e => {
                const eSource = typeof e.source === 'object' ? e.source.id : e.source;
                const eTarget = typeof e.target === 'object' ? e.target.id : e.target;
                return !(eSource === source && eTarget === target);
            });
            this.isModified = true;

            // Check if any nodes are now orphaned (no edges)
            const connectedNodes = new Set();
            this.edges.forEach(e => {
                const eSource = typeof e.source === 'object' ? e.source.id : e.source;
                const eTarget = typeof e.target === 'object' ? e.target.id : e.target;
                connectedNodes.add(eSource);
                connectedNodes.add(eTarget);
            });

            // Remove orphaned non-origin nodes
            this.nodes = this.nodes.filter(n => n.isOrigin || connectedNodes.has(n.id));

            if (this.nodes.length === 0) {
                this.hideGraph();
            } else {
                this.render();
            }
        }

        removeFromTable(domain) {
            // Find and remove the domain node and its edges
            const cleanDomain = domain.replace('[IP] ', '');
            this.nodes = this.nodes.filter(n => n.id !== cleanDomain);
            // Handle both string IDs and D3's node object references
            this.edges = this.edges.filter(e => {
                const sourceId = typeof e.source === 'object' ? e.source.id : e.source;
                const targetId = typeof e.target === 'object' ? e.target.id : e.target;
                return sourceId !== cleanDomain && targetId !== cleanDomain;
            });

            this.isModified = true;

            if (this.nodes.length === 0) {
                this.hideGraph();
            } else {
                this.render();
            }
        }

        downloadTableCSV() {
            const rows = [['Source', 'Source Type', 'Relationship', 'Target', 'Target Type']];

            // Build CSV from edges data directly (not from DOM) for cleaner output
            this.edges.forEach(edge => {
                const sourceId = typeof edge.source === 'object' ? edge.source.id : edge.source;
                const targetId = typeof edge.target === 'object' ? edge.target.id : edge.target;

                const sourceNode = this.nodes.find(n => n.id === sourceId);
                const targetNode = this.nodes.find(n => n.id === targetId);

                if (sourceNode && targetNode) {
                    rows.push([
                        sourceId,
                        sourceNode.type.toUpperCase(),
                        edge.relationship,
                        targetId,
                        targetNode.type.toUpperCase()
                    ]);
                }
            });

            const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
            const blob = new Blob([csv], { type: 'text/csv' });
            const link = document.createElement('a');
            link.download = `graph_table_${this.graphId || 'export'}.csv`;
            link.href = URL.createObjectURL(blob);
            link.click();
            URL.revokeObjectURL(link.href);
        }

        startFromInput() {
            const input = document.getElementById('graph-start-input');
            const value = input.value.trim();

            if (!value) {
                alert('Please enter an IP address or domain');
                return;
            }

            const type = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value) ? 'ip' : 'domain';

            this.reset();
            this.addNode(value, type, true);
            this.resolveAndExpand(value, type);

            input.value = '';
        }

        escapeHtml(str) {
            // Safe for element content and for quoted attribute values
            return (str == null ? '' : String(str))
                .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        }

        downloadWhoisJSON(nodeId) {
            const node = this.getNode(nodeId);
            if (!node || !node.data || !node.data.whois) {
                showToast('No WHOIS data available', 'error');
                return;
            }

            const json = JSON.stringify(node.data.whois, null, 2);
            const blob = new Blob([json], { type: 'application/json' });
            const link = document.createElement('a');
            link.download = `whois_${nodeId.replace(/[^a-zA-Z0-9.-]/g, '_')}.json`;
            link.href = URL.createObjectURL(blob);
            link.click();
            URL.revokeObjectURL(link.href);
            showToast('WHOIS JSON downloaded', 'success');
        }

        downloadShodanJSON(nodeId) {
            const node = this.getNode(nodeId);
            if (!node || !node.data || !node.data.shodan) {
                showToast('No Shodan data available', 'error');
                return;
            }

            const json = JSON.stringify(node.data.shodan, null, 2);
            const blob = new Blob([json], { type: 'application/json' });
            const link = document.createElement('a');
            link.download = `shodan_${nodeId.replace(/[^a-zA-Z0-9.-]/g, '_')}.json`;
            link.href = URL.createObjectURL(blob);
            link.click();
            URL.revokeObjectURL(link.href);
            showToast('Shodan JSON downloaded', 'success');
        }

        downloadJARMPivotJSON(nodeId) {
            const node = this.getNode(nodeId);
            if (!node || !node.data || !node.data.pivot_results) {
                showToast('No JARM pivot results available', 'error');
                return;
            }

            const json = JSON.stringify(node.data.pivot_results, null, 2);
            const blob = new Blob([json], { type: 'application/json' });
            const link = document.createElement('a');
            // Use first 20 chars of JARM for filename
            const jarmPrefix = nodeId.substring(0, 20);
            link.download = `jarm_pivot_${jarmPrefix}.json`;
            link.href = URL.createObjectURL(blob);
            link.click();
            URL.revokeObjectURL(link.href);
            showToast('JARM pivot results downloaded', 'success');
        }
    }

    // ========================================
    // Graph Statistics Functions
    // ========================================

    window.refreshGraphStats = function() {
        const container = document.getElementById('graph-stats-content');
        if (!container) return;

        const el = (tag, className, text) => {
            const node = document.createElement(tag);
            if (className) node.className = className;
            if (text !== undefined) node.textContent = text;
            return node;
        };

        const gm = window.graphManager;
        if (gm) gm.updateHeader();
        if (!gm || !gm.nodes || gm.nodes.length === 0) {
            const card = el('div', 'card');
            card.append(el('div', 'empty', 'No graph data yet. Add nodes to the graph to see statistics.'));
            container.replaceChildren(card);
            return;
        }

        // Compute statistics
        const nodes = gm.nodes;
        const edges = gm.edges;
        const endId = (end) => (end && typeof end === 'object') ? end.id : end;

        // Node type counts
        const nodeTypeCounts = {};
        nodes.forEach(n => {
            nodeTypeCounts[n.type] = (nodeTypeCounts[n.type] || 0) + 1;
        });

        // Edge type counts - use relationship property
        const edgeTypeCounts = {};
        edges.forEach(e => {
            const edgeType = e.relationship || 'unknown';
            edgeTypeCounts[edgeType] = (edgeTypeCounts[edgeType] || 0) + 1;
        });

        // Count connections per node (how many edges connect to each node)
        const nodeConnectionCounts = {};
        edges.forEach(e => {
            const source = endId(e.source);
            const target = endId(e.target);
            nodeConnectionCounts[source] = (nodeConnectionCounts[source] || 0) + 1;
            nodeConnectionCounts[target] = (nodeConnectionCounts[target] || 0) + 1;
        });

        // Helper to get display name from node ID
        function getDisplayName(nodeId, nodeType) {
            if (nodeType === 'port') return nodeId.replace('port:', '');
            if (nodeType === 'tag') return nodeId.replace('tag:', '');
            if (nodeType === 'asn') {
                // Format: AS{number}_{name} -> show name
                const match = nodeId.match(/^AS\d+_(.+)$/);
                return match ? match[1] : nodeId;
            }
            return nodeId;
        }

        // Build value counts for each node type (excluding ip, domain, basedomain)
        // Count = number of connections to that node
        const nodeTypeValues = {};
        const excludedTypes = ['ip', 'domain', 'basedomain'];

        nodes.forEach(n => {
            if (excludedTypes.includes(n.type)) return;

            if (!nodeTypeValues[n.type]) {
                nodeTypeValues[n.type] = {};
            }

            const displayName = getDisplayName(String(n.id), n.type);
            const connectionCount = nodeConnectionCounts[n.id] || 0;
            nodeTypeValues[n.type][displayName] = (nodeTypeValues[n.type][displayName] || 0) + connectionCount;
        });

        // Section titles and the column heading used when a section is shown as a table
        const typeConfig = {
            tld: { label: 'TLDs', singular: 'TLD' },
            email: { label: 'Emails', singular: 'Email' },
            registrant: { label: 'Registrants', singular: 'Registrant' },
            org: { label: 'Organizations', singular: 'Organization' },
            registrar: { label: 'Registrars', singular: 'Registrar' },
            asn: { label: 'ASNs', singular: 'ASN' },
            country: { label: 'Countries', singular: 'Country' },
            jarm: { label: 'JARM fingerprints', singular: 'JARM fingerprint' },
            port: { label: 'Open ports', singular: 'Open port' },
            tag: { label: 'Tags', singular: 'Tag' }
        };

        // A card with a heading and a bar per [label, count] row (app.css "barlist")
        const sectionCard = (title, note) => {
            const card = el('div', 'card');
            const head = el('div', 'card-h');
            head.append(el('h2', '', title));
            if (note) head.append(el('span', 'muted', note));
            card.append(head);
            return card;
        };
        const barCard = (title, note, rows, colorFor) => {
            const card = sectionCard(title, note);
            const list = el('div', 'card-b barlist graph-barlist');
            const max = rows.length > 0 ? rows[0][1] : 1;
            rows.forEach(([label, count]) => {
                const bar = el('div');
                bar.title = label;
                const fill = el('i');
                fill.style.width = `${max > 0 ? (count / max * 100).toFixed(0) : 0}%`;
                if (colorFor) {
                    fill.className = 'typed';
                    fill.style.background = colorFor(label);
                }
                bar.append(fill, el('span', '', label));
                list.append(bar, el('em', '', String(count)));
            });
            card.append(list);
            return card;
        };

        // Summary cards
        const summary = el('div', 'card graph-stat-grid');
        [
            [nodes.length, 'Nodes'],
            [edges.length, 'Relationships'],
            [Object.keys(nodeTypeCounts).length, 'Node types'],
            [Object.keys(edgeTypeCounts).length, 'Relationship types']
        ].forEach(([value, label]) => {
            const stat = el('div', 'stat');
            stat.append(el('b', '', String(value)), el('span', '', label));
            summary.append(stat);
        });

        const grid = el('div', 'cols graph-stats-cols');

        // Node type distribution
        const sortedNodeTypes = Object.entries(nodeTypeCounts).sort((a, b) => b[1] - a[1]);
        grid.append(barCard('Node types', '', sortedNodeTypes, (type) => gm.getNodeColor(type)));

        // Edge type distribution
        if (Object.keys(edgeTypeCounts).length > 0) {
            const sortedEdgeTypes = Object.entries(edgeTypeCounts).sort((a, b) => b[1] - a[1]);
            grid.append(barCard('Relationship types', '', sortedEdgeTypes));
        }

        // Value distribution sections for each node type
        // Order: Country, ASN, Org, TLD, Registrar, Registrant, Port, Tag, Email, JARM
        const typeOrder = ['country', 'asn', 'org', 'tld', 'registrar', 'registrant', 'port', 'tag', 'email', 'jarm'];

        typeOrder.forEach(nodeType => {
            const values = nodeTypeValues[nodeType];
            if (!values || Object.keys(values).length === 0) return;

            const config = typeConfig[nodeType];
            const sortedValues = Object.entries(values).sort((a, b) => b[1] - a[1]);
            const note = `${sortedValues.length} unique`;

            // Use bar chart for smaller lists, table for larger
            if (sortedValues.length <= 15) {
                grid.append(barCard(config.label, note, sortedValues));
                return;
            }

            const card = sectionCard(config.label, note);
            const table = el('table', 'graph-stats-table');
            const headRow = el('tr');
            headRow.append(el('th', '', config.singular), el('th', 'num', 'Connections'));
            const thead = el('thead');
            thead.append(headRow);
            const tbody = el('tbody');
            sortedValues.slice(0, 25).forEach(([value, count]) => {
                const row = el('tr');
                row.title = value;
                const displayVal = value.length > 50 ? value.substring(0, 47) + '...' : value;
                row.append(el('td', 'mono', displayVal), el('td', 'num', String(count)));
                tbody.append(row);
            });
            if (sortedValues.length > 25) {
                const row = el('tr', 'more-row');
                const td = el('td', 'muted', `... and ${sortedValues.length - 25} more`);
                td.colSpan = 2;
                row.append(td);
                tbody.append(row);
            }
            table.append(thead, tbody);
            card.append(table);
            grid.append(card);
        });

        container.replaceChildren(summary, grid);
    };

    // Initialize graph manager
    window.graphManager = new GraphManager();
})();

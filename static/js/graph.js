// Workspace page: infrastructure graph (GraphManager). Moved verbatim from templates/index.html.

(function() {
    'use strict';

    // Toast notification utility
    function showToast(message, type = 'info', duration = 4000) {
        const container = document.getElementById('toast-container');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;

        // Icon based on type
        let iconSvg = '';
        switch (type) {
            case 'success':
                iconSvg = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>';
                break;
            case 'warning':
                iconSvg = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
                break;
            case 'error':
                iconSvg = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';
                break;
            default: // info
                iconSvg = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>';
        }

        toast.innerHTML = `
            <span class="toast-icon">${iconSvg}</span>
            <span class="toast-message">${escapeHtml(message)}</span>
            <button class="toast-close" onclick="this.parentElement.remove()">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="18" y1="6" x2="6" y2="18"/>
                    <line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
            </button>
        `;

        container.appendChild(toast);

        // Auto-remove after duration
        if (duration > 0) {
            setTimeout(() => {
                toast.classList.add('toast-exit');
                setTimeout(() => toast.remove(), 300);
            }, duration);
        }

        return toast;
    }

    // Make showToast globally accessible
    window.showToast = showToast;

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

            // Click outside to close search results
            document.addEventListener('click', (e) => {
                const searchContainer = document.querySelector('.graph-search-container');
                if (searchContainer && !searchContainer.contains(e.target)) {
                    document.getElementById('graph-search-results').classList.remove('active');
                }
            });

            // Keyboard shortcut for search (Ctrl+F or /)
            document.addEventListener('keydown', (e) => {
                // Only if we're in the graph tab
                if (document.querySelector('.tab[data-tab="graph"]')?.classList.contains('active')) {
                    if ((e.ctrlKey && e.key === 'f') || (e.key === '/' && !e.target.matches('input, textarea'))) {
                        e.preventDefault();
                        const searchInput = document.getElementById('graph-search-input');
                        if (searchInput) {
                            searchInput.focus();
                            searchInput.select();
                        }
                    }
                }
            });
        }

        // ========== Saved Graphs ==========

        async loadSavedGraphsList() {
            try {
                const response = await csrfFetch('/api/graph/list');
                const data = await response.json();

                const container = document.getElementById('saved-graphs-list');
                if (data.graphs && data.graphs.length > 0) {
                    container.innerHTML = data.graphs.map(g => `
                        <div class="saved-graph-item" data-graph-id="${this.escapeHtml(g.id)}" onclick="window.graphManager.loadGraph(this.dataset.graphId)">
                            <div class="saved-graph-info">
                                <span class="saved-graph-name">${this.escapeHtml(g.name)}</span>
                                <span class="saved-graph-date">${new Date(g.updated_at).toLocaleDateString()}${g.is_shared ? ' • shared' : ''}</span>
                            </div>
                            <div class="saved-graph-actions">
                                <button class="saved-graph-share" onclick="event.stopPropagation(); window.graphManager.shareGraph(this.closest('.saved-graph-item').dataset.graphId)" title="${g.is_shared ? 'Copy share link' : 'Share and copy link'}">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <circle cx="18" cy="5" r="3"/>
                                        <circle cx="6" cy="12" r="3"/>
                                        <circle cx="18" cy="19" r="3"/>
                                        <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
                                        <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
                                    </svg>
                                </button>
                                ${g.is_shared ? `
                                <button class="saved-graph-share" onclick="event.stopPropagation(); window.graphManager.unshareGraph(this.closest('.saved-graph-item').dataset.graphId)" title="Stop sharing">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <circle cx="12" cy="12" r="10"/>
                                        <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
                                    </svg>
                                </button>` : ''}
                                <button class="saved-graph-delete" onclick="event.stopPropagation(); window.graphManager.deleteGraph(this.closest('.saved-graph-item').dataset.graphId)" title="Delete">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <polyline points="3 6 5 6 21 6"/>
                                        <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
                                    </svg>
                                </button>
                            </div>
                        </div>
                    `).join('');
                } else {
                    container.innerHTML = '<p class="no-graphs">No saved graphs yet</p>';
                }
            } catch (err) {
                console.error('Failed to load graphs:', err);
                document.getElementById('saved-graphs-list').innerHTML = '<p class="error">Failed to load saved graphs</p>';
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

                // Update name display
                document.getElementById('graph-name-display').textContent = `- ${this.graphName}`;

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
                document.getElementById('graph-prompt-modal').classList.add('active');
            } else {
                this.createNewGraph();
            }
        }

        createNewGraph() {
            document.getElementById('graph-prompt-modal').classList.remove('active');

            this.reset();
            this.addNode(this.pendingValue, this.pendingType, true);
            this.resolveAndExpand(this.pendingValue, this.pendingType);

            // Switch to graph tab
            switchTab('graph');
        }

        addToExistingGraph() {
            document.getElementById('graph-prompt-modal').classList.remove('active');

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

            document.getElementById('graph-name-display').textContent = '';
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
            btn.innerHTML = '<svg class="spinning" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg> Resolving...';

            this.showLoading(true);

            try {
                // Separate IPs and domains
                const ipNodes = unresolvedNodes.filter(n => n.type === 'ip');
                const domainNodes = unresolvedNodes.filter(n => n.type === 'domain');

                const total = unresolvedNodes.length;
                btn.innerHTML = `<svg class="spinning" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg> DNS ${total}...`;

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
            btn.innerHTML = '<svg class="spinning" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg> WHOIS...';

            this.showLoading(true);

            try {
                const domains = unresolvedDomains.map(n => n.id);
                btn.innerHTML = `<svg class="spinning" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg> WHOIS ${domains.length}...`;

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
            btn.innerHTML = '<svg class="spinning" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg> Enriching...';

            this.showLoading(true);

            try {
                // Batch request all IPs at once - use /api/graph/enrich to run LogBoost
                const ips = unresolvedIPs.map(n => n.id);

                console.log('resolveAllGeo: Enriching IPs via LogBoost:', ips);

                btn.innerHTML = `<svg class="spinning" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg> Enriching ${ips.length}...`;

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

            const modal = document.getElementById('graph-node-modal');
            const title = document.getElementById('graph-node-modal-value');
            const content = document.getElementById('graph-node-modal-content');

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
            html += `<div class="detail-row"><span class="detail-label">Type:</span><span class="detail-value">${this.escapeHtml(String(node.type).toUpperCase())}</span></div>`;
            html += `<div class="detail-row"><span class="detail-label">Origin:</span><span class="detail-value">${node.isOrigin ? 'Yes (Starting Point)' : 'No (Discovered)'}</span></div>`;

            // Show ASN details if this is an ASN node
            if (node.type === 'asn' && node.data) {
                html += '<div class="detail-section"><h4>ASN Information</h4>';
                if (node.data.asn_id) html += `<div class="detail-row"><span class="detail-label">ASN ID:</span><span class="detail-value">${this.escapeHtml(node.data.asn_id)}</span></div>`;
                if (node.data.asn_name) html += `<div class="detail-row"><span class="detail-label">Name:</span><span class="detail-value">${this.escapeHtml(node.data.asn_name)}</span></div>`;
                if (node.data.asn_org) html += `<div class="detail-row"><span class="detail-label">Organization:</span><span class="detail-value">${this.escapeHtml(node.data.asn_org)}</span></div>`;
                html += '</div>';
            }

            // Show Port details if this is a Port node
            if (node.type === 'port' && node.data) {
                html += '<div class="detail-section"><h4>Port Information</h4>';
                html += `<div class="detail-row"><span class="detail-label">Port Number:</span><span class="detail-value">${this.escapeHtml(node.data.port)}</span></div>`;
                html += '</div>';
            }

            // Show Tag details if this is a Tag node
            if (node.type === 'tag' && node.data) {
                html += '<div class="detail-section"><h4>Tag Information</h4>';
                html += `<div class="detail-row"><span class="detail-label">Tag:</span><span class="detail-value">${this.escapeHtml(node.data.tag)}</span></div>`;
                html += '</div>';
            }

            // Show Geo data if available (for IP nodes)
            if (node.data && node.data.geo) {
                const g = node.data.geo;
                html += '<div class="detail-section"><h4>Geo Information</h4>';
                if (g.country) html += `<div class="detail-row"><span class="detail-label">Country:</span><span class="detail-value">${this.escapeHtml(g.country)}</span></div>`;
                if (g.city) html += `<div class="detail-row"><span class="detail-label">City:</span><span class="detail-value">${this.escapeHtml(g.city)}</span></div>`;
                if (g.asn) html += `<div class="detail-row"><span class="detail-label">ASN:</span><span class="detail-value">${this.escapeHtml(g.asn)}</span></div>`;
                if (g.org) html += `<div class="detail-row"><span class="detail-label">Organization:</span><span class="detail-value">${this.escapeHtml(g.org)}</span></div>`;
                html += '</div>';
            }

            // Show IDB data if available (for IP nodes)
            if (node.data && node.data.idb) {
                const idb = node.data.idb;
                html += '<div class="detail-section"><h4>InternetDB Data</h4>';
                if (idb.ports && idb.ports.length > 0) html += `<div class="detail-row"><span class="detail-label">Open Ports:</span><span class="detail-value">${idb.ports.map(p => this.escapeHtml(String(p))).join(', ')}</span></div>`;
                if (idb.tags && idb.tags.length > 0) html += `<div class="detail-row"><span class="detail-label">Tags:</span><span class="detail-value">${idb.tags.map(t => this.escapeHtml(String(t))).join(', ')}</span></div>`;
                html += '</div>';
            }

            // Show WHOIS data if available (with download button)
            if (node.data && node.data.whois) {
                const w = node.data.whois;
                html += '<div class="detail-section">';
                html += '<div class="detail-section-header"><h4>WHOIS Information</h4>';
                html += `<button class="detail-download-btn" onclick="window.graphManager.downloadWhoisJSON(window.graphManager.selectedNode.id)" title="Download WHOIS JSON">`;
                html += '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';
                html += '</button></div>';
                if (w.registrant_name) html += `<div class="detail-row"><span class="detail-label">Registrant:</span><span class="detail-value">${this.escapeHtml(w.registrant_name)}</span></div>`;
                if (w.registrant_email) html += `<div class="detail-row"><span class="detail-label">Email:</span><span class="detail-value">${this.escapeHtml(w.registrant_email)}</span></div>`;
                if (w.organization) html += `<div class="detail-row"><span class="detail-label">Organization:</span><span class="detail-value">${this.escapeHtml(w.organization)}</span></div>`;
                if (w.registrar) html += `<div class="detail-row"><span class="detail-label">Registrar:</span><span class="detail-value">${this.escapeHtml(w.registrar)}</span></div>`;
                if (w.creation_date) html += `<div class="detail-row"><span class="detail-label">Created:</span><span class="detail-value">${this.escapeHtml(w.creation_date)}</span></div>`;
                if (w.expiration_date) html += `<div class="detail-row"><span class="detail-label">Expires:</span><span class="detail-value">${this.escapeHtml(w.expiration_date)}</span></div>`;
                if (w.name_servers && w.name_servers.length > 0) html += `<div class="detail-row"><span class="detail-label">Nameservers:</span><span class="detail-value">${w.name_servers.map(ns => this.escapeHtml(ns)).join(', ')}</span></div>`;
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
                html += `<button class="detail-download-btn" onclick="window.graphManager.downloadShodanJSON(window.graphManager.selectedNode.id)" title="Download Shodan JSON">`;
                html += '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';
                html += '</button></div>';

                // Organization & Network
                if (s.org) html += `<div class="detail-row"><span class="detail-label">Organization:</span><span class="detail-value">${this.escapeHtml(s.org)}</span></div>`;
                if (s.isp) html += `<div class="detail-row"><span class="detail-label">ISP:</span><span class="detail-value">${this.escapeHtml(s.isp)}</span></div>`;
                if (s.asn) html += `<div class="detail-row"><span class="detail-label">ASN:</span><span class="detail-value">${this.escapeHtml(s.asn)}</span></div>`;

                // Location
                let location = [];
                if (s.city) location.push(s.city);
                if (s.region_code) location.push(s.region_code);
                if (s.country_name) location.push(s.country_name);
                if (location.length > 0) html += `<div class="detail-row"><span class="detail-label">Location:</span><span class="detail-value">${this.escapeHtml(location.join(', '))}</span></div>`;
                if (s.latitude && s.longitude) html += `<div class="detail-row"><span class="detail-label">Coordinates:</span><span class="detail-value">${this.escapeHtml(s.latitude)}, ${this.escapeHtml(s.longitude)}</span></div>`;

                // OS
                if (s.os) html += `<div class="detail-row"><span class="detail-label">OS:</span><span class="detail-value">${this.escapeHtml(s.os)}</span></div>`;

                // Ports (numbers are safe but escape for defense in depth)
                if (s.ports && s.ports.length > 0) html += `<div class="detail-row"><span class="detail-label">Open Ports:</span><span class="detail-value">${[...s.ports].sort((a,b) => a-b).map(p => this.escapeHtml(String(p))).join(', ')}</span></div>`;

                // Hostnames & Domains
                if (s.hostnames && s.hostnames.length > 0) html += `<div class="detail-row"><span class="detail-label">Hostnames:</span><span class="detail-value">${s.hostnames.map(h => this.escapeHtml(h)).join(', ')}</span></div>`;
                if (s.domains && s.domains.length > 0) html += `<div class="detail-row"><span class="detail-label">Domains:</span><span class="detail-value">${s.domains.map(d => this.escapeHtml(d)).join(', ')}</span></div>`;

                // Vulnerabilities (can be object keys or array)
                const vulns = s.vulns ? (Array.isArray(s.vulns) ? s.vulns : Object.keys(s.vulns)) : [];
                if (vulns.length > 0) {
                    html += `<div class="detail-row"><span class="detail-label">Vulnerabilities:</span><span class="detail-value vuln-list">${vulns.map(v => `<span class="vuln-tag">${this.escapeHtml(v)}</span>`).join(' ')}</span></div>`;
                }

                // Tags
                if (s.tags && s.tags.length > 0) html += `<div class="detail-row"><span class="detail-label">Tags:</span><span class="detail-value">${s.tags.map(t => this.escapeHtml(t)).join(', ')}</span></div>`;

                // Last Update
                if (s.last_update) html += `<div class="detail-row"><span class="detail-label">Last Scan:</span><span class="detail-value">${this.escapeHtml(s.last_update)}</span></div>`;

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
                    html += `<button class="detail-download-btn" onclick="window.graphManager.downloadJARMPivotJSON(window.graphManager.selectedNode.id)" title="Download JARM Pivot Results">`;
                    html += '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';
                    html += '</button>';
                }
                html += '</div>';
                if (node.data.host_count !== undefined) html += `<div class="detail-row"><span class="detail-label">Hosts with JARM:</span><span class="detail-value">${this.escapeHtml(Number(node.data.host_count).toLocaleString())}</span></div>`;
                if (node.data.source_ip) html += `<div class="detail-row"><span class="detail-label">Source IP:</span><span class="detail-value">${this.escapeHtml(node.data.source_ip)}</span></div>`;
                if (node.data.port) html += `<div class="detail-row"><span class="detail-label">Port:</span><span class="detail-value">${this.escapeHtml(node.data.port)}</span></div>`;
                if (node.data.hostnames && node.data.hostnames.length > 0) {
                    html += `<div class="detail-row"><span class="detail-label">Hostnames:</span><span class="detail-value">${node.data.hostnames.map(h => this.escapeHtml(h)).join(', ')}</span></div>`;
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
                html += `<button class="detail-download-btn" onclick="window.graphManager.downloadCirclPDNS(window.graphManager.selectedNode)" title="Download CIRCL PDNS JSON">`;
                html += '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';
                html += '</button></div>';

                html += `<div class="detail-row"><span class="detail-label">Records Found:</span><span class="detail-value">${Number(pdns.length)}</span></div>`;

                if (node.data.circlPdnsFromCache) {
                    html += `<div class="detail-row"><span class="detail-label">From Cache:</span><span class="detail-value">Yes (${this.escapeHtml(node.data.circlPdnsCachedAt || 'unknown time')})</span></div>`;
                }

                // Count by record type
                const typeCounts = {};
                for (const r of pdns) {
                    typeCounts[r.rrtype] = (typeCounts[r.rrtype] || 0) + 1;
                }
                const typeStr = Object.entries(typeCounts).map(([t, c]) => `${t}: ${c}`).join(', ');
                html += `<div class="detail-row"><span class="detail-label">Record Types:</span><span class="detail-value">${this.escapeHtml(typeStr)}</span></div>`;

                // Show first/last seen from the records
                let firstSeen = Infinity;
                let lastSeen = 0;
                for (const r of pdns) {
                    if (r.time_first && r.time_first < firstSeen) firstSeen = r.time_first;
                    if (r.time_last && r.time_last > lastSeen) lastSeen = r.time_last;
                }
                if (firstSeen !== Infinity) {
                    html += `<div class="detail-row"><span class="detail-label">First Seen:</span><span class="detail-value">${new Date(firstSeen * 1000).toLocaleDateString()}</span></div>`;
                }
                if (lastSeen !== 0) {
                    html += `<div class="detail-row"><span class="detail-label">Last Seen:</span><span class="detail-value">${new Date(lastSeen * 1000).toLocaleDateString()}</span></div>`;
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
                html += `<div class="detail-row"><span class="detail-label">Connections:</span><span class="detail-value">${connections.length}</span></div>`;
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

            modal.classList.add('active');
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
            freezeText.textContent = node.frozen ? 'Unfreeze Position' : 'Freeze Position';

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

            menu.style.left = x + 'px';
            menu.style.top = y + 'px';
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
            btn.innerHTML = `<svg class="spinning" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg> Resolving ${unresolvedIPs.length}...`;

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
                    <input type="checkbox" class="pivot-attribute-checkbox" 
                           data-filter="${this.escapeHtml(attr.filter)}" 
                           data-value="${this.escapeHtml(attr.value)}"
                           onchange="updatePivotQueryPreview()">
                    <span class="pivot-filter-name">${this.escapeHtml(attr.filter)}:</span>
                    <span class="pivot-filter-value">${this.escapeHtml(attr.value)}</span>
                </label>
            `).join('');

            // Show modal
            document.getElementById('shodan-pivot-modal').classList.add('active');
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
            btnText.textContent = allFrozen ? 'Freeze All' : 'Unfreeze All';

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
                            <input type="checkbox" ${!isHidden ? 'checked' : ''} 
                                   onchange="window.graphManager.toggleNodeTypeVisibility(this.closest('.filter-item').dataset.type)">
                            <div class="filter-item-icon" style="background: ${color}; color: #000;">
                                ${this.escapeHtml(type.substring(0, 2).toUpperCase())}
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
                            <input type="checkbox" ${!isHidden ? 'checked' : ''} 
                                   onchange="window.graphManager.toggleEdgeTypeVisibility(this.closest('.filter-item').dataset.type)">
                            <div class="filter-item-icon" style="background: var(--text-muted); color: #000;">
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
        }

        getNodeColor(type) {
            const colors = {
                'ip': '#00ff88',
                'domain': '#00a8ff',
                'basedomain': '#00bcd4',
                'tld': '#ffa500',
                'registrant': '#9c27b0',
                'email': '#e91e63',
                'org': '#673ab7',
                'registrar': '#3f51b5',
                'asn': '#ff5722',
                'country': '#4caf50',
                'jarm': '#ffc107',
                'port': '#ff9800',
                'tag': '#cddc39',
                'pivot': '#7c4dff'
            };
            return colors[type] || '#888888';
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
            const searchInput = document.getElementById('graph-search-input');
            const inputRect = searchInput.getBoundingClientRect();

            // Position the dropdown below the search input (fixed positioning)
            resultsContainer.style.top = (inputRect.bottom + 4) + 'px';
            resultsContainer.style.left = inputRect.left + 'px';
            resultsContainer.style.width = Math.max(inputRect.width, 260) + 'px';

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
                        <div class="search-result-icon" style="background: ${color}; color: #000;">
                            ${this.escapeHtml(n.type.substring(0, 2).toUpperCase())}
                        </div>
                        <div class="search-result-info">
                            <div class="search-result-id">${this.escapeHtml(n.id)}</div>
                            <div class="search-result-type">${this.escapeHtml(n.type)}${extraInfo ? ' • ' + this.escapeHtml(extraInfo) : ''}</div>
                        </div>
                        ${result.isHidden ? '<span class="search-result-hidden">Hidden</span>' : ''}
                    </div>
                `;
            }).join('');

            // Attach click handlers via event delegation
            resultsContainer.onclick = (e) => {
                const item = e.target.closest('.search-result-item');
                if (item) {
                    e.preventDefault();
                    e.stopPropagation();
                    const index = parseInt(item.dataset.index, 10);
                    this.selectSearchResult(index);
                }
            };

            // Handle mouseenter for hover selection
            resultsContainer.onmouseover = (e) => {
                const item = e.target.closest('.search-result-item');
                if (item) {
                    const index = parseInt(item.dataset.index, 10);
                    if (index !== this.searchSelectedIndex) {
                        this.searchSelectedIndex = index;
                        // Update selection highlight without full re-render
                        resultsContainer.querySelectorAll('.search-result-item').forEach((el, i) => {
                            el.classList.toggle('selected', i === index);
                        });
                    }
                }
            };

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

            // Add pulsing highlight class
            nodeEl.select('circle')
                .transition()
                .duration(200)
                .attr('stroke', '#00ff88')
                .attr('stroke-width', 4)
                .transition()
                .duration(200)
                .attr('stroke', '#00ff88')
                .attr('stroke-width', 6)
                .transition()
                .duration(200)
                .attr('stroke', '#00ff88')
                .attr('stroke-width', 4)
                .transition()
                .duration(200)
                .attr('stroke', '#00ff88')
                .attr('stroke-width', 6)
                .transition()
                .duration(500)
                .attr('stroke', node.frozen ? '#ff6b6b' : 'none')
                .attr('stroke-width', node.frozen ? 2 : 0);
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
                btn.classList.remove('active');
            });
            event.target.classList.add('active');

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
            document.getElementById('add-node-modal').classList.add('active');

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
                    this.selectNode(existingNode);
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

            document.getElementById('add-connection-modal').classList.add('active');
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
            document.getElementById('add-connection-modal').classList.remove('active');
            this.connectionSourceNode = null;
            this.render();
        }

        async enrichNode() {
            if (!this.selectedNode) return;

            document.getElementById('graph-node-modal').classList.remove('active');
            await this.resolveAndExpand(this.selectedNode.id, this.selectedNode.type);
        }

        async resolveWhois(skipModal = false) {
            if (!this.selectedNode || this.selectedNode.type !== 'domain') return;

            const domain = this.selectedNode.id;
            const whoisBtn = document.getElementById('whois-node-btn');
            const originalText = whoisBtn ? whoisBtn.innerHTML : '';

            if (whoisBtn) {
                whoisBtn.disabled = true;
                whoisBtn.innerHTML = '<svg class="spinning" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg> Loading...';
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
                this.selectedNode.data = this.selectedNode.data || {};
                this.selectedNode.data.whois = data;
                this.selectedNode.data.whoisResolved = true;
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
                if (!skipModal) {
                    this.showNodeDetails(this.selectedNode);
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

            const geoBtn = document.getElementById('geo-node-btn');
            const originalText = geoBtn.innerHTML;

            geoBtn.disabled = true;
            geoBtn.innerHTML = '<svg class="spinning" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg> Loading...';

            try {
                await this.resolveGeoForNode(this.selectedNode);

                // Refresh the modal content
                this.showNodeDetails(this.selectedNode);

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

            document.getElementById('graph-node-modal').classList.remove('active');
            this.selectedNode = null;

            if (this.nodes.length === 0) {
                this.hideGraph();
            } else {
                this.render();
            }
        }

        // ========== Save/Export ==========

        saveGraph() {
            document.getElementById('graph-save-name').value = this.graphName;
            document.getElementById('graph-save-modal').classList.add('active');
        }

        async showLoadModal() {
            const modal = document.getElementById('graph-load-modal');
            const listContainer = document.getElementById('load-graphs-list');

            // Show modal with loading state
            listContainer.innerHTML = '<p class="loading-text">Loading saved graphs...</p>';
            modal.classList.add('active');

            try {
                const response = await csrfFetch('/api/graph/list');
                const data = await response.json();

                if (data.graphs && data.graphs.length > 0) {
                    listContainer.innerHTML = data.graphs.map(g => `
                        <div class="load-graph-item" data-graph-id="${this.escapeHtml(g.id)}" onclick="window.graphManager.loadGraphFromModal(this.dataset.graphId)">
                            <div class="load-graph-info">
                                <span class="load-graph-name">${this.escapeHtml(g.name)}</span>
                                <span class="load-graph-date">${new Date(g.updated_at).toLocaleDateString()} ${new Date(g.updated_at).toLocaleTimeString()}</span>
                            </div>
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="load-graph-arrow">
                                <polyline points="9 18 15 12 9 6"/>
                            </svg>
                        </div>
                    `).join('');
                } else {
                    listContainer.innerHTML = '<p class="no-graphs">No saved graphs found</p>';
                }
            } catch (err) {
                console.error('Failed to load graphs:', err);
                listContainer.innerHTML = '<p class="error">Failed to load saved graphs</p>';
            }
        }

        async loadGraphFromModal(graphId) {
            // Close the modal
            document.getElementById('graph-load-modal').classList.remove('active');

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
                    document.getElementById('graph-name-display').textContent = `- ${this.graphName}`;

                    this.loadSavedGraphsList();
                }
            } catch (err) {
                console.error('Failed to save graph:', err);
                alert('Failed to save graph');
            }

            document.getElementById('graph-save-modal').classList.remove('active');
        }

        exportPNG() {
            const svg = document.getElementById('graph-svg');
            if (!svg) return;

            const serializer = new XMLSerializer();
            const svgString = serializer.serializeToString(svg);

            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            const img = new Image();

            canvas.width = svg.clientWidth * 2;
            canvas.height = svg.clientHeight * 2;
            ctx.scale(2, 2);
            ctx.fillStyle = '#0a0a0f';
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            img.onload = () => {
                ctx.drawImage(img, 0, 0);
                const link = document.createElement('a');
                link.download = `graph_${this.graphId || 'export'}.png`;
                link.href = canvas.toDataURL('image/png');
                link.click();
            };

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
            if (this.currentView === 'graph') {
                this.currentView = 'table';
                document.getElementById('graph-visualization').style.display = 'none';
                document.getElementById('graph-table-view').style.display = 'flex';
                document.querySelector('#graph-view-toggle .view-graph').style.display = 'none';
                document.querySelector('#graph-view-toggle .view-table').style.display = '';
                this.renderTable();
            } else {
                this.currentView = 'graph';
                document.getElementById('graph-visualization').style.display = '';
                document.getElementById('graph-table-view').style.display = 'none';
                document.querySelector('#graph-view-toggle .view-graph').style.display = '';
                document.querySelector('#graph-view-toggle .view-table').style.display = 'none';
            }
        }

        toggleEdgeLabels() {
            this.showEdgeLabels = !this.showEdgeLabels;
            document.getElementById('edge-labels-toggle').classList.toggle('active', this.showEdgeLabels);

            if (this.svg) {
                this.svg.selectAll('.edge-label').style('display', this.showEdgeLabels ? '' : 'none');
            }
        }

        toggleFullscreen() {
            const container = document.getElementById('graph-container');
            const btn = document.getElementById('fullscreen-toggle');

            if (container.classList.contains('fullscreen')) {
                container.classList.remove('fullscreen');
                btn.classList.remove('active');
                document.body.style.overflow = '';
            } else {
                container.classList.add('fullscreen');
                btn.classList.add('active');
                document.body.style.overflow = 'hidden';
            }

            // Re-render to adjust to new size
            if (this.simulation) {
                this.simulation.alpha(0.3).restart();
            }
        }

        // ========== Rendering ==========

        showGraph() {
            document.getElementById('graph-empty-state').style.display = 'none';
            document.getElementById('graph-visualization').style.display = '';
            document.getElementById('graph-legend').style.display = 'flex';
        }

        hideGraph() {
            document.getElementById('graph-empty-state').style.display = '';
            document.getElementById('graph-visualization').style.display = 'none';
            document.getElementById('graph-table-view').style.display = 'none';
            document.getElementById('graph-legend').style.display = 'none';
            this.currentView = 'graph';
            document.querySelector('#graph-view-toggle .view-graph').style.display = '';
            document.querySelector('#graph-view-toggle .view-table').style.display = 'none';
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

            // Clear previous
            d3.select('#graph-svg').selectAll('*').remove();

            this.svg = d3.select('#graph-svg')
                .attr('width', width)
                .attr('height', height);

            // Create arrow marker
            this.svg.append('defs').append('marker')
                .attr('id', 'arrowhead')
                .attr('viewBox', '-0 -5 10 10')
                .attr('refX', 25)
                .attr('refY', 0)
                .attr('orient', 'auto')
                .attr('markerWidth', 6)
                .attr('markerHeight', 6)
                .append('path')
                .attr('d', 'M 0,-5 L 10 ,0 L 0,5')
                .attr('fill', '#666');

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

            // Create simulation using physics settings
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
                .attr('stroke', '#444')
                .attr('stroke-width', 1.5)
                .attr('marker-end', 'url(#arrowhead)');

            // Edge labels
            const edgeLabels = edgeGroup.selectAll('.edge-label')
                .data(links)
                .enter()
                .append('text')
                .attr('class', 'edge-label')
                .attr('font-size', '10px')
                .attr('fill', '#888')
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
                    this.showNodeDetails(d);
                })
                .on('contextmenu', (event, d) => {
                    event.preventDefault();
                    event.stopPropagation();
                    this.showContextMenu(event, d);
                });

            // Node icons using Material Symbols
            node.each(function(d) {
                const g = d3.select(this);

                // Determine colors and icon based on type
                let bgColor, borderColor, icon;
                if (d.type === 'ip') {
                    bgColor = d.isOrigin ? 'rgba(0, 255, 136, 0.15)' : 'rgba(0, 255, 136, 0.08)';
                    borderColor = d.isOrigin ? '#00ff88' : '#00cc6a';
                    icon = 'lan';  // Network/LAN icon for IP
                } else if (d.type === 'tld') {
                    bgColor = 'rgba(255, 165, 0, 0.15)';
                    borderColor = '#ffa500';
                    icon = 'sell';  // Tag icon for TLD
                } else if (d.type === 'registrant') {
                    bgColor = 'rgba(156, 39, 176, 0.15)';
                    borderColor = '#9c27b0';
                    icon = 'person';  // Person icon for registrant
                } else if (d.type === 'email') {
                    bgColor = 'rgba(233, 30, 99, 0.15)';
                    borderColor = '#e91e63';
                    icon = 'mail';  // Email icon
                } else if (d.type === 'org') {
                    bgColor = 'rgba(103, 58, 183, 0.15)';
                    borderColor = '#673ab7';
                    icon = 'apartment';  // Building icon for organization
                } else if (d.type === 'registrar') {
                    bgColor = 'rgba(63, 81, 181, 0.15)';
                    borderColor = '#3f51b5';
                    icon = 'business';  // Business icon for registrar
                } else if (d.type === 'asn') {
                    bgColor = 'rgba(255, 87, 34, 0.15)';
                    borderColor = '#ff5722';
                    icon = 'hub';  // Hub icon for ASN
                } else if (d.type === 'country') {
                    bgColor = 'rgba(76, 175, 80, 0.15)';
                    borderColor = '#4caf50';
                    icon = 'flag';  // Flag icon for country
                } else if (d.type === 'jarm') {
                    bgColor = 'rgba(255, 193, 7, 0.15)';
                    borderColor = '#ffc107';
                    icon = 'fingerprint';  // Fingerprint icon for JARM
                } else if (d.type === 'basedomain') {
                    bgColor = 'rgba(0, 188, 212, 0.15)';
                    borderColor = '#00bcd4';
                    icon = 'domain';  // Domain icon for base domain
                } else if (d.type === 'port') {
                    bgColor = 'rgba(255, 152, 0, 0.15)';
                    borderColor = '#ff9800';
                    icon = 'settings_ethernet';  // Ethernet/port icon
                } else if (d.type === 'tag') {
                    bgColor = 'rgba(205, 220, 57, 0.15)';
                    borderColor = '#cddc39';
                    icon = 'label';  // Label/tag icon
                } else {
                    // domain
                    bgColor = d.isOrigin ? 'rgba(0, 168, 255, 0.15)' : 'rgba(0, 168, 255, 0.08)';
                    borderColor = d.isOrigin ? '#00a8ff' : '#0088cc';
                    icon = 'language';  // Globe icon for domain
                }

                // Background circle
                const circle = g.append('circle')
                    .attr('r', 22)
                    .attr('fill', bgColor)
                    .attr('stroke', borderColor)
                    .attr('stroke-width', d.frozen ? 3 : 2);

                // Add dashed ring for frozen nodes
                if (d.frozen) {
                    g.append('circle')
                        .attr('r', 26)
                        .attr('fill', 'none')
                        .attr('stroke', borderColor)
                        .attr('stroke-width', 1)
                        .attr('stroke-dasharray', '3,2')
                        .attr('opacity', 0.6);
                }

                // Icon using foreignObject
                g.append('foreignObject')
                    .attr('x', -14)
                    .attr('y', -14)
                    .attr('width', 28)
                    .attr('height', 28)
                    .append('xhtml:div')
                    .style('width', '100%')
                    .style('height', '100%')
                    .style('display', 'flex')
                    .style('align-items', 'center')
                    .style('justify-content', 'center')
                    .append('xhtml:span')
                    .attr('class', 'material-symbols-outlined')
                    .style('font-size', '20px')
                    .style('color', borderColor)
                    .text(icon);
            });

            // Node labels
            node.append('text')
                .attr('class', 'node-label')
                .attr('dy', 30)
                .attr('text-anchor', 'middle')
                .attr('font-size', '11px')
                .attr('fill', '#ccc')
                .text(d => d.id.length > 20 ? d.id.substring(0, 18) + '...' : d.id);

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

            // Also render table if in table view
            if (this.currentView === 'table') {
                this.renderTable();
            }
        }

        renderTable() {
            const tbody = document.getElementById('graph-table-body');

            // Build table data: one row per edge
            let html = '';

            this.edges.forEach(edge => {
                // Handle both string IDs and D3's node object references
                const sourceId = typeof edge.source === 'object' ? edge.source.id : edge.source;
                const targetId = typeof edge.target === 'object' ? edge.target.id : edge.target;

                const sourceNode = this.nodes.find(n => n.id === sourceId);
                const targetNode = this.nodes.find(n => n.id === targetId);

                if (!sourceNode || !targetNode) return;

                // Get display info
                const sourceDisplay = sourceId;
                const targetDisplay = targetId;
                const relationship = edge.relationship;

                html += `
                    <tr data-source="${this.escapeHtml(sourceId)}" data-target="${this.escapeHtml(targetId)}">
                        <td><span class="node-type-badge ${this.escapeHtml(sourceNode.type)}">${this.escapeHtml(String(sourceNode.type).toUpperCase())}</span> ${this.escapeHtml(sourceDisplay)}</td>
                        <td><span class="relationship-badge">${this.escapeHtml(relationship)}</span></td>
                        <td><span class="node-type-badge ${this.escapeHtml(targetNode.type)}">${this.escapeHtml(String(targetNode.type).toUpperCase())}</span> ${this.escapeHtml(targetDisplay)}</td>
                        <td>
                            <button class="table-action-btn" onclick="window.graphManager.removeEdgeFromTable(this.closest('tr').dataset.source, this.closest('tr').dataset.target)" title="Remove relationship">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <line x1="18" y1="6" x2="6" y2="18"/>
                                    <line x1="6" y1="6" x2="18" y2="18"/>
                                </svg>
                            </button>
                        </td>
                    </tr>
                `;
            });

            if (html === '') {
                html = '<tr><td colspan="4" style="text-align:center;color:var(--text-muted);">No relationships to display</td></tr>';
            }

            tbody.innerHTML = html;
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

        const gm = window.graphManager;
        if (!gm || !gm.nodes || gm.nodes.length === 0) {
            container.innerHTML = `
                <div class="graph-stats-empty">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="18" cy="5" r="3"/>
                        <circle cx="6" cy="12" r="3"/>
                        <circle cx="18" cy="19" r="3"/>
                        <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
                        <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
                    </svg>
                    <p>No graph data available</p>
                    <p class="hint">Add nodes to the graph to see statistics</p>
                </div>
            `;
            return;
        }

        const escapeHtml = (str) => gm.escapeHtml(str);

        // Compute statistics
        const nodes = gm.nodes;
        const edges = gm.edges;

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
            nodeConnectionCounts[e.source] = (nodeConnectionCounts[e.source] || 0) + 1;
            nodeConnectionCounts[e.target] = (nodeConnectionCounts[e.target] || 0) + 1;
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

            const displayName = getDisplayName(n.id, n.type);
            const connectionCount = nodeConnectionCounts[n.id] || 0;
            nodeTypeValues[n.type][displayName] = (nodeTypeValues[n.type][displayName] || 0) + connectionCount;
        });

        // Type display names and colors
        const typeConfig = {
            tld: { label: 'TLDs', color: '#9C27B0' },
            email: { label: 'Emails', color: '#E91E63' },
            registrant: { label: 'Registrants', color: '#FF9800' },
            org: { label: 'Organizations', color: '#00BCD4' },
            registrar: { label: 'Registrars', color: '#795548' },
            asn: { label: 'ASNs', color: '#607D8B' },
            country: { label: 'Countries', color: '#FFC107' },
            jarm: { label: 'JARM Fingerprints', color: '#9E9E9E' },
            port: { label: 'Open Ports', color: '#ff9800' },
            tag: { label: 'Tags', color: '#cddc39' },
            pivot: { label: 'Pivots', color: '#7c4dff' }
        };

        // Build HTML
        let html = '<div class="graph-stats-grid">';

        // Summary cards
        html += '<div class="stats-summary-row">';
        html += `<div class="stats-card summary"><div class="stats-card-value">${nodes.length}</div><div class="stats-card-label">Total Nodes</div></div>`;
        html += `<div class="stats-card summary"><div class="stats-card-value">${edges.length}</div><div class="stats-card-label">Total Edges</div></div>`;
        html += `<div class="stats-card summary"><div class="stats-card-value">${Object.keys(nodeTypeCounts).length}</div><div class="stats-card-label">Node Types</div></div>`;
        html += `<div class="stats-card summary"><div class="stats-card-value">${Object.keys(edgeTypeCounts).length}</div><div class="stats-card-label">Edge Types</div></div>`;
        html += '</div>';

        // Node type distribution
        html += '<div class="stats-section">';
        html += '<h3>Node Types</h3>';
        html += '<div class="stats-bar-chart">';
        const sortedNodeTypes = Object.entries(nodeTypeCounts).sort((a, b) => b[1] - a[1]);
        const maxNodeCount = sortedNodeTypes.length > 0 ? sortedNodeTypes[0][1] : 1;
        const typeColors = {
            ip: '#4CAF50', domain: '#2196F3', tld: '#9C27B0', email: '#E91E63',
            registrant: '#FF9800', org: '#00BCD4', registrar: '#795548', asn: '#607D8B',
            country: '#FFC107', jarm: '#9E9E9E', basedomain: '#00bcd4', port: '#ff9800', tag: '#cddc39',
            pivot: '#7c4dff'
        };
        sortedNodeTypes.forEach(([type, count]) => {
            const pct = (count / maxNodeCount * 100).toFixed(0);
            const color = typeColors[type] || '#999';
            html += `<div class="stats-bar-row">
                <span class="stats-bar-label">${escapeHtml(type)}</span>
                <div class="stats-bar-container">
                    <div class="stats-bar" style="width: ${pct}%; background: ${color};"></div>
                </div>
                <span class="stats-bar-value">${count}</span>
            </div>`;
        });
        html += '</div></div>';

        // Edge type distribution
        if (Object.keys(edgeTypeCounts).length > 0) {
            html += '<div class="stats-section">';
            html += '<h3>Edge Types (Relationships)</h3>';
            html += '<div class="stats-bar-chart">';
            const sortedEdgeTypes = Object.entries(edgeTypeCounts).sort((a, b) => b[1] - a[1]);
            const maxEdgeCount = sortedEdgeTypes.length > 0 ? sortedEdgeTypes[0][1] : 1;

            // Color mapping for edge/relationship types
            const edgeColors = {
                // DNS record types
                'A': '#4CAF50',
                'AAAA': '#8BC34A',
                'CNAME': '#2196F3',
                'MX': '#03A9F4',
                'NS': '#00BCD4',
                'TXT': '#009688',
                'PTR': '#26A69A',
                'SOA': '#00796B',
                // Domain structure
                'TLD': '#9C27B0',
                'SubDomain': '#AB47BC',
                // Enrichment
                'country': '#FFC107',
                'asn': '#607D8B',
                'org': '#00BCD4',
                // WHOIS
                'Registrant': '#FF9800',
                'Registrar': '#795548',
                'Admin Email': '#E91E63',
                'Tech Email': '#F06292',
                // Shodan/IDB
                'Open Port': '#ff5722',
                'has_tag': '#cddc39',
                // JARM
                'JARM': '#9E9E9E',
                // Pivot
                'Pivot Source': '#7c4dff',
                'Pivot Result': '#b388ff'
            };

            // Generate color for unknown types based on hash
            function hashColor(str) {
                let hash = 0;
                for (let i = 0; i < str.length; i++) {
                    hash = str.charCodeAt(i) + ((hash << 5) - hash);
                }
                const hue = Math.abs(hash % 360);
                return `hsl(${hue}, 65%, 55%)`;
            }

            sortedEdgeTypes.forEach(([type, count]) => {
                const pct = (count / maxEdgeCount * 100).toFixed(0);
                const color = edgeColors[type] || hashColor(type);
                html += `<div class="stats-bar-row">
                    <span class="stats-bar-label">${escapeHtml(type)}</span>
                    <div class="stats-bar-container">
                        <div class="stats-bar" style="width: ${pct}%; background: ${color};"></div>
                    </div>
                    <span class="stats-bar-value">${count}</span>
                </div>`;
            });
            html += '</div></div>';
        }

        // Value distribution sections for each node type
        // Order: Country, ASN, Org, TLD, Registrar, Registrant, Port, Tag, Email, JARM
        const typeOrder = ['country', 'asn', 'org', 'tld', 'registrar', 'registrant', 'port', 'tag', 'email', 'jarm'];

        typeOrder.forEach(nodeType => {
            const values = nodeTypeValues[nodeType];
            if (!values || Object.keys(values).length === 0) return;

            const config = typeConfig[nodeType] || { label: nodeType, color: '#999' };
            const sortedValues = Object.entries(values).sort((a, b) => b[1] - a[1]);
            const maxVal = sortedValues.length > 0 ? sortedValues[0][1] : 1;

            html += '<div class="stats-section">';
            html += `<h3>${config.label} <small>(${sortedValues.length} unique)</small></h3>`;

            // Use bar chart for smaller lists, table for larger
            if (sortedValues.length <= 15) {
                html += '<div class="stats-bar-chart">';
                sortedValues.forEach(([value, count]) => {
                    const pct = (count / maxVal * 100).toFixed(0);
                    // Truncate long values
                    const displayVal = value.length > 40 ? value.substring(0, 37) + '...' : value;
                    html += `<div class="stats-bar-row" title="${escapeHtml(value)}">
                        <span class="stats-bar-label">${escapeHtml(displayVal)}</span>
                        <div class="stats-bar-container">
                            <div class="stats-bar" style="width: ${pct}%; background: ${config.color};"></div>
                        </div>
                        <span class="stats-bar-value">${count}</span>
                    </div>`;
                });
                html += '</div>';
            } else {
                // Table for larger lists
                html += '<div class="stats-table"><table>';
                html += `<thead><tr><th>${config.label.replace(/s$/, '')}</th><th>Connections</th></tr></thead><tbody>`;
                sortedValues.slice(0, 25).forEach(([value, count]) => {
                    const displayVal = value.length > 50 ? value.substring(0, 47) + '...' : value;
                    html += `<tr title="${escapeHtml(value)}"><td>${escapeHtml(displayVal)}</td><td>${count}</td></tr>`;
                });
                if (sortedValues.length > 25) {
                    html += `<tr class="more-row"><td colspan="2">... and ${sortedValues.length - 25} more</td></tr>`;
                }
                html += '</tbody></table></div>';
            }

            html += '</div>';
        });

        html += '</div>';

        container.innerHTML = html;
    };

    // Initialize graph manager
    window.graphManager = new GraphManager();
})();

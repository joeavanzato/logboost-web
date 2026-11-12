// Workspace page: CSRF helpers, tabs, enrichment forms, results table and row details.
// Moved verbatim from templates/index.html.

// Get CSRF token from meta tag
function getCSRFToken() {
    return document.querySelector('meta[name="csrf-token"]').content;
}

// Configure HTMX to include CSRF token in all requests
document.addEventListener('DOMContentLoaded', function() {
    document.body.addEventListener('htmx:configRequest', function(event) {
        event.detail.headers['X-CSRFToken'] = getCSRFToken();
    });
});

// CSRF-aware fetch wrapper for API calls
async function csrfFetch(url, options = {}) {
    options.headers = options.headers || {};
    options.headers['X-CSRFToken'] = getCSRFToken();
    return fetch(url, options);
}

// Expanded view toggle
function toggleExpandedView() {
    const mainContent = document.querySelector('.main-content');
    const expandIcon = document.getElementById('expand-icon');
    const collapseIcon = document.getElementById('collapse-icon');
    const expandText = document.getElementById('expand-text');

    mainContent.classList.toggle('expanded');

    if (mainContent.classList.contains('expanded')) {
        expandIcon.classList.add('hidden');
        collapseIcon.classList.remove('hidden');
        expandText.textContent = 'Collapse';
        localStorage.setItem('logboost-expanded', 'true');
    } else {
        expandIcon.classList.remove('hidden');
        collapseIcon.classList.add('hidden');
        expandText.textContent = 'Expand';
        localStorage.setItem('logboost-expanded', 'false');
    }
}

// Restore expanded state on load
document.addEventListener('DOMContentLoaded', () => {
    if (localStorage.getItem('logboost-expanded') === 'true') {
        toggleExpandedView();
    }

    // Check if ViewDNS API is configured
    csrfFetch('/api/viewdns/settings')
        .then(resp => resp.json())
        .then(data => {
            window.viewdnsApiConfigured = data.api_key_configured;
        })
        .catch(() => {
            window.viewdnsApiConfigured = false;
        });

    // Check if Chaos API is configured
    csrfFetch('/api/chaos/settings')
        .then(resp => resp.json())
        .then(data => {
            window.chaosApiConfigured = data.api_key_configured;
        })
        .catch(() => {
            window.chaosApiConfigured = false;
        });
});

// Tab switching
function switchTab(tabName, updateUrl = true) {
    document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.remove('active'));

    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    document.getElementById(`${tabName}-panel`).classList.add('active');

    // Hide/show results container based on tab
    const resultsContainer = document.getElementById('results-container');
    if (resultsContainer) {
        resultsContainer.style.display = (tabName === 'graph' || tabName === 'graph-stats' || tabName === 'intel-browser') ? 'none' : '';
    }

    // Refresh graph stats when switching to that tab
    if (tabName === 'graph-stats' && window.refreshGraphStats) {
        window.refreshGraphStats();
    }

    // Lazy-init intel browser on first activation
    if (tabName === 'intel-browser' && window.intelInit) {
        window.intelInit();
    }

    // Update URL hash
    if (updateUrl) {
        window.history.replaceState({}, '', `#${tabName}`);
    }
}

// Handle initial URL hash and hash changes
function handleHashChange() {
    const hash = window.location.hash.slice(1); // Remove #
    const validTabs = ['adhoc', 'upload', 'graph', 'graph-stats', 'intel-browser'];
    if (validTabs.includes(hash)) {
        switchTab(hash, false);
    }
}

// Listen for hash changes
window.addEventListener('hashchange', handleHashChange);

// Check initial hash on page load
document.addEventListener('DOMContentLoaded', function() {
    if (window.location.hash) {
        handleHashChange();
    }
});

// File upload handling
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const fileNameDisplay = document.getElementById('file-name');

if (dropZone && fileInput) {
    dropZone.addEventListener('click', () => fileInput.click());

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });

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

function updateFileName() {
    if (fileInput.files.length) {
        fileNameDisplay.textContent = fileInput.files[0].name;
        dropZone.classList.add('has-file');
    } else {
        fileNameDisplay.textContent = '';
        dropZone.classList.remove('has-file');
    }
}

// Page size change handler
document.body.addEventListener('change', (e) => {
    if (e.target.matches('.page-size-select')) {
        const pageSize = e.target.value;
        htmx.ajax('GET', `/results/page?page=1&page_size=${pageSize}`, {
            target: '#results-table-container',
            indicator: '#loading-indicator'
        });
    }
});

// Modal functionality
let currentRowIndex = 0;
let tableRows = [];
let tableHeaders = [];

function openRowModal(rowIndex) {
    const table = document.querySelector('.results-table');
    if (!table) return;

    // Get headers - only from first row, not filter row
    tableHeaders = Array.from(table.querySelectorAll('thead tr:first-child th')).map(th => th.textContent.trim());

    // Get all body rows (exclude any hidden rows from filtering)
    tableRows = Array.from(table.querySelectorAll('tbody tr:not([style*="display: none"])'));

    if (rowIndex < 0 || rowIndex >= tableRows.length) return;

    currentRowIndex = rowIndex;
    updateModalContent();

    document.getElementById('row-modal').classList.add('active');
    document.body.style.overflow = 'hidden';
}

function updateModalContent() {
    const row = tableRows[currentRowIndex];
    if (!row) return;

    const cells = Array.from(row.querySelectorAll('td'));
    const modalContent = document.getElementById('modal-content');

    // Separate LogBoost columns from original data, filtering out empty headers
    let originalFields = [];
    let enrichmentFields = [];

    tableHeaders.forEach((header, index) => {
        // Skip empty headers
        if (!header || header.trim() === '') return;

        const value = cells[index] ? cells[index].getAttribute('title') || cells[index].textContent.trim() : '';
        const field = { header, value };

        if (header.startsWith('lb_')) {
            enrichmentFields.push(field);
        } else {
            originalFields.push(field);
        }
    });

    let html = '';

    // Original Data Section
    if (originalFields.length > 0) {
        html += `
            <div class="modal-section">
                <h4 class="modal-section-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                        <path d="M14 2v6h6"/>
                    </svg>
                    Original Data
                </h4>
                <div class="modal-fields">
                    ${originalFields.map(f => createFieldHtml(f, false)).join('')}
                </div>
            </div>
        `;
    }

    // Enrichment Data Section - organized into logical groups
    if (enrichmentFields.length > 0) {
        // Store enrichment data for copy functions
        window.currentEnrichmentFields = enrichmentFields;

        // Define field groupings
        const fieldGroups = {
            'Identity': {
                icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4l2 2"/></svg>',
                fields: ['lb_IP', 'lb_Domains', 'lb_TLD']
            },
            'Network': {
                icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>',
                fields: ['lb_ASN', 'lb_ASN_Number', 'lb_IPWhois_CIDR', 'lb_IPWhois_NetName', 'lb_IPWhois_NetType', 'lb_IPWhois_Parent']
            },
            'Geolocation': {
                icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0118 0z"/><circle cx="12" cy="10" r="3"/></svg>',
                fields: ['lb_Country', 'lb_City']
            },
            'IP WHOIS': {
                icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
                fields: ['lb_IPWhois_Organization', 'lb_IPWhois_Created', 'lb_IPWhois_Updated', 'lb_IPWhois_Country']
            },
            'Domain WHOIS': {
                icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>',
                fields: ['lb_DomainWhois_CreatedDate', 'lb_DomainWhois_UpdatedDate', 'lb_DomainWhois_Country', 'lb_DomainWhois_Organization']
            },
            'Threat Intel': {
                icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
                fields: ['lb_ThreatCategories', 'lb_ThreatFeedCount', 'lb_ThreatFeeds']
            },
            'Shodan / InternetDB': {
                icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>',
                fields: ['lb_IDB_cpes', 'lb_IDB_hostnames', 'lb_IDB_ports', 'lb_IDB_tags', 'lb_IDB_vulns']
            }
        };

        // Build a map of field header to field data
        const fieldMap = {};
        enrichmentFields.forEach(f => {
            fieldMap[f.header] = f;
        });

        // Generate HTML for each group
        let groupsHtml = '';
        let hasAnyData = false;

        for (const [groupName, groupConfig] of Object.entries(fieldGroups)) {
            const groupFields = groupConfig.fields
                .filter(h => fieldMap[h] && fieldMap[h].value && fieldMap[h].value.trim() !== '')
                .map(h => fieldMap[h]);

            if (groupFields.length > 0) {
                hasAnyData = true;
                const isThreat = groupName === 'Threat Intel';
                groupsHtml += `
                    <div class="enrichment-group${isThreat ? ' threat-group' : ''}">
                        <h5 class="enrichment-group-title${isThreat ? ' threat' : ''}">
                            ${groupConfig.icon}
                            ${groupName}
                        </h5>
                        <div class="enrichment-group-fields">
                            ${groupFields.map(f => createFieldHtml(f, true)).join('')}
                        </div>
                    </div>
                `;
            }
        }

        // Handle any fields that don't fit in predefined groups
        const allGroupedFields = Object.values(fieldGroups).flatMap(g => g.fields);
        const ungroupedFields = enrichmentFields.filter(f => 
            !allGroupedFields.includes(f.header) && f.value && f.value.trim() !== ''
        );

        if (ungroupedFields.length > 0) {
            hasAnyData = true;
            groupsHtml += `
                <div class="enrichment-group">
                    <h5 class="enrichment-group-title">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"/>
                            <path d="M12 16v-4M12 8h.01"/>
                        </svg>
                        Other
                    </h5>
                    <div class="enrichment-group-fields">
                        ${ungroupedFields.map(f => createFieldHtml(f, true)).join('')}
                    </div>
                </div>
            `;
        }

        if (hasAnyData) {
            html += `
                <div class="modal-section">
                    <div class="modal-section-header">
                        <h4 class="modal-section-title enrichment">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="12" cy="12" r="10"/>
                                <path d="M12 6v6l4 2"/>
                            </svg>
                            LogBoost Enrichment
                        </h4>
                        <div class="modal-copy-buttons">
                            <button class="modal-copy-btn" onclick="copyEnrichmentReadable()" title="Copy for email/text">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M16 4h2a2 2 0 012 2v14a2 2 0 01-2 2H6a2 2 0 01-2-2V6a2 2 0 012-2h2"/>
                                    <rect x="8" y="2" width="8" height="4" rx="1" ry="1"/>
                                </svg>
                                Copy
                            </button>
                            <button class="modal-copy-btn" onclick="copyEnrichmentJSON()" title="Copy as JSON">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <polyline points="16 18 22 12 16 6"/>
                                    <polyline points="8 6 2 12 8 18"/>
                                </svg>
                                JSON
                            </button>
                        </div>
                    </div>
                    <div class="enrichment-groups-container">
                        ${groupsHtml}
                    </div>
                </div>
            `;
        }
    }

    modalContent.innerHTML = html;

    // Update navigation
    document.getElementById('modal-row-indicator').textContent = `Row ${currentRowIndex + 1} of ${tableRows.length}`;
    document.getElementById('modal-prev').disabled = currentRowIndex === 0;
    document.getElementById('modal-next').disabled = currentRowIndex === tableRows.length - 1;
}

function createFieldHtml(field, isEnrichment) {
    const displayHeader = field.header.replace(/^lb_/, '').replace(/_/g, ' ');
    const isEmpty = !field.value || field.value === 'none' || field.value === '';
    const valueClass = isEmpty ? 'empty' : (isEnrichment ? 'enrichment' : '');
    const displayValue = isEmpty ? '—' : field.value;

    // Special formatting for certain fields
    let formattedValue = displayValue;
    let downloadBtn = '';

    if (field.value && field.value.includes('|')) {
        // Multi-value field (like domains, threat feeds)
        const items = field.value.split('|').filter(v => v.trim());
        if (items.length > 1) {
            formattedValue = `<ul class="modal-value-list">${items.map(i => `<li>${escapeHtml(i.trim())}</li>`).join('')}</ul>`;
            // Add download button for multi-value fields
            const fieldName = field.header.replace(/^lb_/, '').replace(/_/g, ' ');
            downloadBtn = `
                <button class="modal-download-btn" data-field-name="${escapeHtml(fieldName)}" data-values="${escapeHtml(field.value)}" onclick="downloadFieldValues(this.dataset.fieldName, this.dataset.values)" title="Download as CSV">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
                        <polyline points="7 10 12 15 17 10"/>
                        <line x1="12" y1="15" x2="12" y2="3"/>
                    </svg>
                </button>
            `;
        } else {
            formattedValue = escapeHtml(displayValue);
        }
    } else {
        formattedValue = escapeHtml(displayValue);
    }

    return `
        <div class="modal-field ${isEnrichment ? 'enrichment-field' : ''}">
            <div class="modal-field-header">
                <span class="modal-field-label">${escapeHtml(displayHeader)}</span>
                ${downloadBtn}
            </div>
            <span class="modal-field-value ${valueClass}">${formattedValue}</span>
        </div>
    `;
}


function downloadFieldValues(fieldName, values) {
    const items = values.split('|').filter(v => v.trim()).map(v => v.trim());

    // Create CSV content
    let csvContent = `"${fieldName}"\n`;
    items.forEach(item => {
        // Escape quotes in values
        const escaped = item.replace(/"/g, '""');
        csvContent += `"${escaped}"\n`;
    });

    // Create download
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${fieldName.replace(/\s+/g, '_').toLowerCase()}_values.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

function copyEnrichmentReadable() {
    if (!window.currentEnrichmentFields) return;

    // Build human-readable format (no header)
    let text = '';

    window.currentEnrichmentFields.forEach(field => {
        const displayHeader = field.header.replace(/^lb_/, '').replace(/_/g, ' ');
        const isEmpty = !field.value || field.value === 'none' || field.value === '';

        if (!isEmpty) {
            // Handle multi-value fields
            if (field.value.includes('|')) {
                const items = field.value.split('|').filter(v => v.trim()).map(v => defangIOC(v.trim()));
                text += `${displayHeader}:\n`;
                items.forEach(item => {
                    text += `  • ${item}\n`;
                });
            } else {
                text += `${displayHeader}: ${defangIOC(field.value)}\n`;
            }
        }
    });

    // Copy to clipboard
    navigator.clipboard.writeText(text.trim()).then(() => {
        showCopyToast('Copied to clipboard (defanged)!');
    }).catch(err => {
        console.error('Failed to copy:', err);
        // Fallback for older browsers
        fallbackCopy(text.trim());
    });
}

function copyEnrichmentJSON() {
    if (!window.currentEnrichmentFields) return;

    // Build JSON object
    const data = {};

    window.currentEnrichmentFields.forEach(field => {
        const key = field.header.replace(/^lb_/, '');
        const isEmpty = !field.value || field.value === 'none' || field.value === '';

        if (!isEmpty) {
            // Handle multi-value fields
            if (field.value.includes('|')) {
                data[key] = field.value.split('|').filter(v => v.trim()).map(v => defangIOC(v.trim()));
            } else {
                data[key] = defangIOC(field.value);
            }
        }
    });

    const jsonText = JSON.stringify(data, null, 2);

    // Copy to clipboard
    navigator.clipboard.writeText(jsonText).then(() => {
        showCopyToast('JSON copied (defanged)!');
    }).catch(err => {
        console.error('Failed to copy:', err);
        fallbackCopy(jsonText);
    });
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
        defanged = defanged.replace(/\./, '[.]');
        return defanged;
    }

    // Check if it looks like a domain (contains at least one dot and valid TLD pattern)
    const domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/;
    if (domainPattern.test(defanged)) {
        // Defang domain: replace only the FIRST dot with [.]
        defanged = defanged.replace(/\./, '[.]');
        return defanged;
    }

    // For values that contain IPs within text, defang only first dot of each IP
    defanged = defanged.replace(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/g, '$1[.]$2.$3.$4');

    return defanged;
}

function showCopyToast(message) {
    // Remove existing toast if any
    const existingToast = document.querySelector('.copy-toast');
    if (existingToast) existingToast.remove();

    const toast = document.createElement('div');
    toast.className = 'copy-toast';
    toast.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
            <polyline points="22 4 12 14.01 9 11.01"/>
        </svg>
        ${escapeHtml(message)}
    `;
    document.body.appendChild(toast);

    // Trigger animation
    setTimeout(() => toast.classList.add('show'), 10);

    // Remove after delay
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 2000);
}

function fallbackCopy(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
        document.execCommand('copy');
        showCopyToast('Copied to clipboard!');
    } catch (err) {
        alert('Failed to copy. Please copy manually.');
    }
    document.body.removeChild(textarea);
}

function downloadFilteredCSV() {
    const table = document.querySelector('.results-table');
    if (!table) return;

    const headers = Array.from(table.querySelectorAll('thead th')).map(th => th.textContent.trim());
    const visibleRows = Array.from(table.querySelectorAll('tbody tr')).filter(row => 
        !row.style.display || row.style.display !== 'none'
    );

    if (visibleRows.length === 0) {
        alert('No visible rows to download');
        return;
    }

    // Build CSV content
    let csvContent = headers.map(h => `"${h.replace(/"/g, '""')}"`).join(',') + '\n';

    visibleRows.forEach(row => {
        const cells = Array.from(row.querySelectorAll('td'));
        const rowData = cells.map(cell => {
            // Get full value from title attribute or cell text
            const value = cell.getAttribute('title') || cell.textContent.trim();
            return `"${value.replace(/"/g, '""')}"`;
        });
        csvContent += rowData.join(',') + '\n';
    });

    // Create and trigger download
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'logboost_filtered_results.csv';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

function escapeHtml(text) {
    // Safe for element content and for quoted attribute values
    return (text == null ? '' : String(text))
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function navigateRow(direction) {
    const newIndex = currentRowIndex + direction;
    if (newIndex >= 0 && newIndex < tableRows.length) {
        currentRowIndex = newIndex;
        updateModalContent();
    }
}

function closeModal() {
    document.getElementById('row-modal').classList.remove('active');
    document.body.style.overflow = '';
}

function closeModalOnOverlay(event) {
    if (event.target.id === 'row-modal') {
        closeModal();
    }
}

// Keyboard navigation for modal
document.addEventListener('keydown', (e) => {
    const modal = document.getElementById('row-modal');
    if (!modal.classList.contains('active')) return;

    if (e.key === 'Escape') {
        closeModal();
    } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
        navigateRow(-1);
    } else if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
        navigateRow(1);
    }
});

// Delegate click handler for table rows
document.body.addEventListener('click', (e) => {
    const row = e.target.closest('.results-table tbody tr');
    if (row && !row.style.display?.includes('none')) {
        // Get index among visible rows only
        const allRows = Array.from(row.parentElement.querySelectorAll('tr:not([style*="display: none"])'));
        const index = allRows.indexOf(row);
        if (index !== -1) {
            openRowModal(index);
        }
    }
});

// Context menu handler for right-click
let contextMenuTarget = null;
let contextMenuValue = null;
let contextMenuType = null;

document.body.addEventListener('contextmenu', (e) => {
    const row = e.target.closest('.results-table tbody tr');
    const cell = e.target.closest('td');

    if (row && cell) {
        e.preventDefault();

        // Determine what was right-clicked (IP or Domain)
        const cellIndex = Array.from(row.children).indexOf(cell);
        const headers = window.resultHeaders || [];
        const header = headers[cellIndex] || '';
        let value = cell.textContent.trim();

        // Handle pipe-separated values - take the first one
        if (value.includes('|')) {
            value = value.split('|')[0].trim();
        }

        // Check if it's an IP or domain column
        const isIPColumn = header.toLowerCase().includes('ip') || /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value);
        const isDomainColumn = header.toLowerCase().includes('domain') || header.toLowerCase().includes('hostname') || header === 'lb_Domains' || header === 'lb_IDB_HOSTNAMES';

        if (value && (isIPColumn || isDomainColumn || /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value))) {
            contextMenuTarget = row;
            contextMenuValue = value;
            contextMenuType = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value) ? 'ip' : 'domain';

            const menu = document.getElementById('context-menu');
            const menuText = document.getElementById('context-menu-graph-text');
            menuText.textContent = `Graph this ${contextMenuType === 'ip' ? 'IP' : 'Domain'}`;

            // Use clientX/clientY for fixed positioning
            menu.style.left = e.clientX + 'px';
            menu.style.top = e.clientY + 'px';
            menu.classList.add('active');
        }
    }
});

document.addEventListener('click', () => {
    document.getElementById('context-menu').classList.remove('active');
});

function contextMenuGraph() {
    if (contextMenuValue) {
        window.graphManager.promptGraph(contextMenuValue, contextMenuType);
    }
    document.getElementById('context-menu').classList.remove('active');
}

function graphFromModal() {
    // Modal fields are rendered by createFieldHtml() as
    //   <div class="modal-field">
    //     <div class="modal-field-header"><span class="modal-field-label">IP</span></div>
    //     <span class="modal-field-value">1.2.3.4</span>
    //   </div>
    const fields = document.querySelectorAll('#modal-content .modal-field');
    const ipv4 = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    const ipv6 = /^[0-9a-f:]+$/i;

    // Pass 1: exact "IP" label (lb_IP -> "IP" after the lb_ prefix is stripped).
    for (const f of fields) {
        const label = (f.querySelector('.modal-field-label')?.textContent || '').trim().toLowerCase();
        const value = (f.querySelector('.modal-field-value')?.textContent || '').trim();
        if (label === 'ip' && value && value !== '—') {
            window.graphManager.promptGraph(value, 'ip');
            closeModal();
            return;
        }
    }
    // Pass 2: any field whose value looks like an IPv4/IPv6 address.
    for (const f of fields) {
        const value = (f.querySelector('.modal-field-value')?.textContent || '').trim();
        if (ipv4.test(value) || (value.includes(':') && ipv6.test(value))) {
            window.graphManager.promptGraph(value, 'ip');
            closeModal();
            return;
        }
    }
    console.warn('[graphFromModal] no IP found in row modal');
}

// Graph modal helpers
function closeGraphNodeModal(e) {
    if (e.target === e.currentTarget) closeGraphNodeModalBtn();
}
function closeGraphNodeModalBtn() {
    document.getElementById('graph-node-modal').classList.remove('active');
}
function closeGraphSaveModal(e) {
    if (e.target === e.currentTarget) closeGraphSaveModalBtn();
}
function closeGraphSaveModalBtn() {
    document.getElementById('graph-save-modal').classList.remove('active');
}
function closeGraphLoadModal(e) {
    if (e.target === e.currentTarget) closeGraphLoadModalBtn();
}
function closeGraphLoadModalBtn() {
    document.getElementById('graph-load-modal').classList.remove('active');
}
function closeGraphPromptModal(e) {
    if (e.target === e.currentTarget) closeGraphPromptModalBtn();
}
function closeGraphPromptModalBtn() {
    document.getElementById('graph-prompt-modal').classList.remove('active');
}
function closeAddConnectionModal(e) {
    if (e.target === e.currentTarget) closeAddConnectionModalBtn();
}
function closeAddConnectionModalBtn() {
    document.getElementById('add-connection-modal').classList.remove('active');
}

// Add Node modal functions
function closeAddNodeModal(e) {
    if (e.target === e.currentTarget) closeAddNodeModalBtn();
}
function closeAddNodeModalBtn() {
    document.getElementById('add-node-modal').classList.remove('active');
}

// ========== Bulk Graph Modal ==========
let bulkGraphData = { ips: [], domains: [] };
let selectedBulkFile = null;

function showBulkGraphModal() {
    // Reset state
    bulkGraphData = { ips: [], domains: [] };
    selectedBulkFile = null;
    document.getElementById('bulk-text-input').value = '';
    document.getElementById('bulk-url-input').value = '';
    document.getElementById('bulk-file-selected').style.display = 'none';
    document.getElementById('bulk-status').style.display = 'none';
    document.getElementById('bulk-results').style.display = 'none';
    document.getElementById('bulk-create-btn').disabled = true;
    switchBulkTab('text');

    document.getElementById('bulk-graph-modal').classList.add('active');
}

function closeBulkGraphModal(e) {
    if (e.target === e.currentTarget) closeBulkGraphModalBtn();
}

function closeBulkGraphModalBtn() {
    document.getElementById('bulk-graph-modal').classList.remove('active');
}

function switchBulkTab(tabName) {
    document.querySelectorAll('.bulk-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.bulk-panel').forEach(p => p.classList.remove('active'));
    document.querySelector(`.bulk-tab[data-tab="${tabName}"]`).classList.add('active');
    document.getElementById(`bulk-panel-${tabName}`).classList.add('active');
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
    event.currentTarget.classList.remove('dragover');

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

    // Populate IP list
    const ipsList = document.getElementById('bulk-ips-list');
    ipsList.innerHTML = bulkGraphData.ips.map((ip, i) => `
        <div class="bulk-ioc-item">
            <input type="checkbox" checked data-type="ip" data-index="${i}">
            <span>${escapeHtml(ip)}</span>
        </div>
    `).join('');

    // Populate domains list
    const domainsList = document.getElementById('bulk-domains-list');
    domainsList.innerHTML = bulkGraphData.domains.map((domain, i) => `
        <div class="bulk-ioc-item">
            <input type="checkbox" checked data-type="domain" data-index="${i}">
            <span>${escapeHtml(domain)}</span>
        </div>
    `).join('');

    // Reset checkboxes
    document.getElementById('bulk-include-ips').checked = true;
    document.getElementById('bulk-include-domains').checked = true;

    // Show results
    resultsDiv.style.display = 'block';

    updateBulkSelection();
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

    // Count selected
    const selectedIps = document.querySelectorAll('#bulk-ips-list input[type="checkbox"]:checked').length;
    const selectedDomains = document.querySelectorAll('#bulk-domains-list input[type="checkbox"]:checked').length;
    const total = selectedIps + selectedDomains;

    // Update button
    const createBtn = document.getElementById('bulk-create-btn');
    const createBtnText = document.getElementById('bulk-create-btn-text');
    createBtn.disabled = total === 0;
    createBtnText.textContent = total > 0 ? `Create Graph (${total} IOCs)` : 'Create Graph';
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
function closeShodanPivotModal(e) {
    if (e.target === e.currentTarget) closeShodanPivotModalBtn();
}
function closeShodanPivotModalBtn() {
    document.getElementById('shodan-pivot-modal').classList.remove('active');
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

    let explanationHtml = '';
    if (multiValueFilters.length > 0 || filterCount > 1) {
        const parts = [];
        if (multiValueFilters.length > 0) {
            parts.push(`<strong>${escapeHtml(multiValueFilters.join(', '))}</strong>`);
        }
        if (filterCount > 1) {
            parts.push(`${filterCount} filters AND'd together`);
        }
        explanationHtml = `<div class="pivot-query-info">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/>
                <path d="M12 16v-4"/>
                <path d="M12 8h.01"/>
            </svg>
            <span>${parts.join(' • ')}</span>
        </div>`;
    }

    previewText.innerHTML = `<code>${escapeHtml(query)}</code>${explanationHtml}`;
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
    const originalText = executeBtn.innerHTML;

    executeBtn.disabled = true;
    executeBtn.innerHTML = `
        <svg class="spinning" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/>
        </svg>
        Searching...
    `;

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
        executeBtn.innerHTML = originalText;
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
    if (type === 'ip' || type === 'domain') {
        info.style.display = 'flex';
    } else {
        info.style.display = 'none';
    }
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

// Custom relationship toggle
document.addEventListener('DOMContentLoaded', function() {
    const relationshipSelect = document.getElementById('connection-relationship');
    if (relationshipSelect) {
        relationshipSelect.addEventListener('change', function() {
            const customGroup = document.getElementById('custom-relationship-group');
            customGroup.style.display = this.value === 'custom' ? 'block' : 'none';
        });
    }

    // Hide context menu on click outside
    document.addEventListener('click', function() {
        document.getElementById('node-context-menu').classList.remove('active');
    });

    // Check for shared results to load
    if (document.body.dataset.sharedResults) {
        loadSharedResults(document.body.dataset.sharedResults);
    }
});

// Load shared results
async function loadSharedResults(shareId) {
    try {
        // Fetch the rendered HTML directly
        const response = await csrfFetch('/api/shared/results/' + shareId + '/render');

        if (!response.ok) {
            showToast('Shared results not found or expired', 'error');
            return;
        }

        const html = await response.text();
        const container = document.getElementById('results-container');
        if (container) {
            container.innerHTML = html;

            // Execute any scripts in the inserted HTML
            const scripts = container.querySelectorAll('script');
            scripts.forEach(oldScript => {
                const newScript = document.createElement('script');
                Array.from(oldScript.attributes).forEach(attr => {
                    newScript.setAttribute(attr.name, attr.value);
                });
                newScript.textContent = oldScript.textContent;
                oldScript.parentNode.replaceChild(newScript, oldScript);
            });
        }

        // Switch to adhoc tab to show results
        switchTab('adhoc', false);

        showToast('Loaded shared results', 'success');

    } catch (err) {
        console.error('Failed to load shared results:', err);
        showToast('Failed to load shared results', 'error');
    }
}

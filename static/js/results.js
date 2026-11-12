// Results view: the client-side table (columns, filters, sorting, paging, widths), fullscreen,
// sharing and the filtered CSV download. The fragment templates/partials/results.html carries the
// data in a JSON island; this file is loaded once and (re)initialises whenever a fragment arrives.
// All markup is built with DOM nodes: headers and cell values come from log data.
(function () {
    'use strict';

    var S = null;            // state of the result set on the page; null when there is none
    var dropdown = null;     // the one value dropdown shared by all filter cells
    var justResized = false; // swallows the click that ends a column drag

    function byId(id) { return document.getElementById(id); }

    function el(tag, className, text) {
        var node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined) node.textContent = text;
        return node;
    }

    function isEnrichment(header) { return header.indexOf('lb_') === 0; }

    // Display only: filters, exports and the row JSON keep the real names.
    function displayName(header) {
        return header.replace(/^lb_/, '').replace(/_/g, ' ');
    }

    function cell(row, index) {
        var value = row[index];
        return value === undefined || value === null ? '' : String(value);
    }

    // ========== DEFAULT COLUMNS ==========

    // A readable first view for enriched results: the IP, organisation, ASN, country, city and
    // the threat-intel columns. Returns null when the file has no such columns (show everything).
    function defaultColumns(headers) {
        var lower = headers.map(function (h) { return h.toLowerCase(); });
        function firstOf(names) {
            for (var i = 0; i < names.length; i++) {
                var index = lower.indexOf(names[i]);
                if (index !== -1) return index;
            }
            return -1;
        }

        var ip = firstOf(['lb_ip', 'ip', 'ip_address', 'ipaddress', 'ip address']);
        if (ip === -1) {
            for (var i = 0; i < lower.length && ip === -1; i++) {
                if (lower[i].indexOf('lb_') !== 0 && /(^|[^a-z])ip([^a-z]|$)/.test(lower[i])) ip = i;
            }
        }
        var asn = firstOf(['lb_asn']);
        var country = firstOf(['lb_country']);
        if (ip === -1 || (asn === -1 && country === -1)) return null;

        var picks = [ip, asn, country, firstOf(['lb_city']),
            firstOf(['lb_org', 'lb_organisation', 'lb_organization', 'lb_ipwhois_organization',
                'lb_ipwhoisorg', 'lb_whoisorg', 'lb_whois_orgname', 'lb_isp'])];
        lower.forEach(function (h, index) {
            if (h.indexOf('lb_threat') === 0) picks.push(index);
        });

        var visible = new Set();
        picks.forEach(function (index) { if (index !== -1) visible.add(index); });
        return visible;
    }

    function allColumns() {
        var visible = new Set();
        S.headers.forEach(function (_, index) { visible.add(index); });
        return visible;
    }

    function visibleIndexes() {
        var list = [];
        S.headers.forEach(function (_, index) { if (S.visible.has(index)) list.push(index); });
        return list;
    }

    // ========== INIT ==========

    function init() {
        closeDropdown();
        document.body.classList.remove('results-fullscreen');

        var wrapper = byId('results-wrapper');
        var island = byId('results-data');
        if (!wrapper || !island) { S = null; return; }
        if (wrapper.dataset.ready === 'true') return;
        wrapper.dataset.ready = 'true';

        var data;
        try {
            data = JSON.parse(island.textContent);
        } catch (err) {
            console.error('Results data could not be read:', err);
            S = null;
            return;
        }

        var pageSize = parseInt(wrapper.dataset.pageSize, 10);
        S = {
            headers: (data.headers || []).map(String),
            rows: data.rows || [],
            filtered: [],
            page: 1,
            pageSize: pageSize > 0 ? pageSize : 50,
            filters: {},          // column index -> array of filter values
            filtersVisible: false,
            visible: null,        // Set of column indexes
            sortColumn: null,
            sortDirection: 'asc',
            widths: {},           // column index -> px, once the user sized columns
            fixedLayout: false,
            valueCounts: {},      // column index -> [{value, count}], computed on first use
            statsUrl: wrapper.dataset.statsUrl || '/stats',
            statsLoaded: false,
            statsLoading: false
        };
        S.visible = defaultColumns(S.headers) || allColumns();

        var select = byId('page-size');
        if (select) select.value = String(S.pageSize);

        syncColumnPicker();
        renderTable();
    }

    // ========== RENDERING ==========

    function renderTable() {
        renderHeaders();
        renderFilterRow();
        applyFilters();
    }

    function renderHeaders() {
        var headerRow = byId('header-row');
        if (!headerRow) return;

        var fragment = document.createDocumentFragment();
        visibleIndexes().forEach(function (index) {
            var header = S.headers[index];
            var th = el('th', isEnrichment(header) ? 'lb-col' : '');
            th.dataset.col = index;
            th.title = header + ' · click to sort';
            th.scope = 'col';

            var label = displayName(header);
            if (S.sortColumn === index) {
                th.classList.add('sorted');
                th.setAttribute('aria-sort', S.sortDirection === 'asc' ? 'ascending' : 'descending');
                label += S.sortDirection === 'asc' ? ' ▲' : ' ▼';
            }
            th.appendChild(el('span', 'th-label', label));

            var resizer = el('span', 'col-resizer');
            resizer.dataset.col = index;
            resizer.setAttribute('aria-hidden', 'true');
            th.appendChild(resizer);

            applyWidth(th, index);
            fragment.appendChild(th);
        });
        headerRow.replaceChildren(fragment);

        var table = byId('results-table');
        if (table) table.style.tableLayout = S.fixedLayout ? 'fixed' : '';
    }

    function applyWidth(th, index) {
        if (!S.fixedLayout) return;
        var width = (S.widths[index] || 160) + 'px';
        th.style.width = width;
        th.style.minWidth = width;
    }

    function renderFilterRow() {
        var filterRow = byId('filter-row');
        if (!filterRow) return;

        var fragment = document.createDocumentFragment();
        visibleIndexes().forEach(function (index) {
            var header = S.headers[index];
            var filters = S.filters[index] || [];
            var th = el('th', 'filter-cell');
            th.dataset.col = index;

            if (filters.length) {
                var tags = el('div', 'filter-tags');
                filters.forEach(function (value, position) {
                    var tag = el('span', 'tag filter-tag');
                    tag.title = value;
                    tag.appendChild(el('span', '', value.length > 15 ? value.substring(0, 15) + '...' : value));
                    var remove = el('button', 'x', '×');
                    remove.type = 'button';
                    remove.dataset.act = 'remove-filter';
                    remove.dataset.position = position;
                    remove.setAttribute('aria-label', 'Remove filter ' + value);
                    tag.appendChild(remove);
                    tags.appendChild(tag);
                });
                th.appendChild(tags);
            }

            var inputRow = el('div', 'filter-input-row');
            var input = el('input', 'input filter-input');
            input.type = 'text';
            input.placeholder = filters.length ? 'Add filter…' : 'Filter…';
            input.setAttribute('aria-label', 'Filter ' + displayName(header) + ' (press Enter to add)');
            var pick = el('button', 'btn sm filter-dropdown-btn', '▾');
            pick.type = 'button';
            pick.dataset.act = 'filter-values';
            pick.title = 'Select values';
            pick.setAttribute('aria-label', 'Select values for ' + displayName(header));
            inputRow.append(input, pick);
            th.appendChild(inputRow);

            fragment.appendChild(th);
        });
        filterRow.replaceChildren(fragment);
    }

    function pageBounds() {
        if (S.pageSize === 'all') return [0, S.filtered.length];
        var start = (S.page - 1) * S.pageSize;
        return [start, Math.min(start + S.pageSize, S.filtered.length)];
    }

    function renderBody() {
        var tbody = byId('table-body');
        if (!tbody) return;

        var bounds = pageBounds();
        var columns = visibleIndexes();
        var pageData = S.filtered.slice(bounds[0], bounds[1]);
        var fragment = document.createDocumentFragment();

        if (pageData.length === 0 || columns.length === 0) {
            var emptyRow = el('tr', 'empty-row');
            var message = columns.length === 0 ? 'No columns shown. Choose some under Columns.'
                : (totalFilterCount() > 0 ? 'No matching rows found' : 'No data');
            var emptyCell = el('td', 'empty', message);
            emptyCell.colSpan = Math.max(1, columns.length);
            emptyRow.appendChild(emptyCell);
            fragment.appendChild(emptyRow);
        } else {
            pageData.forEach(function (row, rowIndex) {
                var tr = el('tr');
                tr.dataset.row = rowIndex;   // position on this page; the row drawer steps through these
                columns.forEach(function (index) {
                    var value = cell(row, index);
                    var td = el('td', isEnrichment(S.headers[index]) ? 'lb-col' : '',
                        value.length > 100 ? value.substring(0, 100) + '...' : value);
                    td.dataset.col = index;
                    td.title = value;
                    tr.appendChild(td);
                });
                fragment.appendChild(tr);
            });
        }

        tbody.replaceChildren(fragment);
        updatePagination(bounds[0], bounds[1]);
        updateFilteredCount();
        document.dispatchEvent(new CustomEvent('results:rendered'));
    }

    function pageButton(label, page, options) {
        var button = el('button', 'btn sm' + (options && options.current ? ' on' : ''), label);
        button.type = 'button';
        button.dataset.page = page;
        if (options && options.disabled) button.disabled = true;
        if (options && options.current) button.setAttribute('aria-current', 'page');
        return button;
    }

    function updatePagination(startIndex, endIndex) {
        var total = S.filtered.length;
        byId('page-start').textContent = total > 0 ? startIndex + 1 : 0;
        byId('page-end').textContent = endIndex;
        byId('page-total').textContent = total;

        var controls = byId('pagination-controls');
        if (!controls) return;
        if (S.pageSize === 'all' || total <= S.pageSize) {
            controls.replaceChildren();
            return;
        }

        var totalPages = Math.ceil(total / S.pageSize);
        var nodes = [pageButton('‹ Prev', S.page - 1, { disabled: S.page === 1 })];

        var startPage = Math.max(1, S.page - 2);
        var endPage = Math.min(totalPages, startPage + 4);
        startPage = Math.max(1, endPage - 4);

        if (startPage > 1) {
            nodes.push(pageButton('1', 1));
            if (startPage > 2) nodes.push(el('span', 'faint', '…'));
        }
        for (var i = startPage; i <= endPage; i++) {
            nodes.push(pageButton(String(i), i, { current: i === S.page }));
        }
        if (endPage < totalPages) {
            if (endPage < totalPages - 1) nodes.push(el('span', 'faint', '…'));
            nodes.push(pageButton(String(totalPages), totalPages));
        }
        nodes.push(pageButton('Next ›', S.page + 1, { disabled: S.page === totalPages }));

        controls.replaceChildren.apply(controls, nodes);
    }

    function updateFilteredCount() {
        var display = byId('filtered-count-display');
        var count = byId('filtered-rows-count');
        if (!display || !count) return;
        var hasFilters = totalFilterCount() > 0;
        if (hasFilters) count.textContent = S.filtered.length;
        display.classList.toggle('hide', !hasFilters);
    }

    function totalFilterCount() {
        var count = 0;
        Object.keys(S.filters).forEach(function (index) { count += S.filters[index].length; });
        return count;
    }

    // ========== FILTER VALUE DROPDOWN ==========

    function columnValueCounts(index) {
        if (!S.valueCounts[index]) {
            var counts = new Map();
            S.rows.forEach(function (row) {
                var value = cell(row, index);
                if (value !== '') counts.set(value, (counts.get(value) || 0) + 1);
            });
            var sorted = [];
            counts.forEach(function (count, value) { sorted.push({ value: value, count: count }); });
            sorted.sort(function (a, b) { return b.count - a.count; });
            S.valueCounts[index] = sorted;
        }
        return S.valueCounts[index];
    }

    function ensureDropdown() {
        if (dropdown && dropdown.isConnected) return dropdown;
        dropdown = el('div', 'menu pop filter-dropdown hide');
        dropdown.id = 'filter-dropdown';
        var search = el('input', 'input filter-search-input');
        search.type = 'text';
        search.placeholder = 'Search values…';
        search.setAttribute('aria-label', 'Search values');
        dropdown.append(search, el('div', 'pop-list filter-dropdown-list'));
        byId('results-wrapper').appendChild(dropdown);
        return dropdown;
    }

    function closeDropdown() {
        if (dropdown) {
            dropdown.classList.add('hide');
            delete dropdown.dataset.col;
        }
    }

    function toggleDropdown(index, button) {
        var open = dropdown && !dropdown.classList.contains('hide') && dropdown.dataset.col === String(index);
        closeDropdown();
        if (open) return;

        var box = ensureDropdown();
        box.dataset.col = index;
        box.querySelector('.filter-search-input').value = '';
        populateDropdown('');

        var rect = button.getBoundingClientRect();
        box.classList.remove('hide');
        box.style.left = Math.max(8, Math.min(rect.right - box.offsetWidth, window.innerWidth - box.offsetWidth - 8)) + 'px';
        box.style.top = Math.min(rect.bottom + 4, window.innerHeight - 120) + 'px';
        box.style.maxHeight = Math.max(160, window.innerHeight - rect.bottom - 20) + 'px';
        setTimeout(function () { box.querySelector('.filter-search-input').focus(); }, 50);
    }

    function populateDropdown(searchTerm) {
        if (!dropdown || dropdown.dataset.col === undefined) return;
        var index = Number(dropdown.dataset.col);
        var list = dropdown.querySelector('.filter-dropdown-list');
        var values = columnValueCounts(index);
        var current = S.filters[index] || [];
        var term = (searchTerm || '').toLowerCase();

        var matching = term ? values.filter(function (item) {
            return item.value.toLowerCase().indexOf(term) !== -1;
        }) : values;
        var shown = matching.slice(0, 100);   // top 100, for speed

        var nodes = shown.map(function (item) {
            var selected = current.indexOf(item.value) !== -1;
            var option = el('button', 'pop-item filter-dropdown-item' + (selected ? ' selected' : ''));
            option.type = 'button';
            option.dataset.value = item.value;
            option.setAttribute('aria-pressed', selected ? 'true' : 'false');
            var text = el('span', 'grow ell', item.value.length > 40 ? item.value.substring(0, 40) + '...' : item.value);
            text.title = item.value;
            option.append(el('span', 'filter-item-check green', selected ? '✓' : ''), text,
                el('span', 'faint mono', '(' + item.count + ')'));
            return option;
        });

        if (shown.length === 0) nodes.push(el('div', 'pop-note', 'No matching values'));
        if (values.length > 100 && !term) {
            nodes.push(el('div', 'pop-note', 'Showing top 100 of ' + values.length + ' values. Use search to find more.'));
        }
        list.replaceChildren.apply(list, nodes);
    }

    // ========== FILTERS (AND between columns and within a column) ==========

    function filtersChanged() {
        S.page = 1;
        renderFilterRow();
        applyFilters();
        updateFilterUI();
    }

    function toggleFilterValue(index, value) {
        var list = S.filters[index] || (S.filters[index] = []);
        var position = list.indexOf(value);
        if (position === -1) list.push(value); else list.splice(position, 1);
        if (list.length === 0) delete S.filters[index];

        if (dropdown) populateDropdown(dropdown.querySelector('.filter-search-input').value);
        filtersChanged();
    }

    function addFilter(index, value) {
        if (!value) return;
        var list = S.filters[index] || (S.filters[index] = []);
        if (list.indexOf(value) !== -1) return;   // no duplicates
        list.push(value);
        filtersChanged();
    }

    function removeFilter(index, position) {
        if (!S.filters[index]) return;
        S.filters[index].splice(position, 1);
        if (S.filters[index].length === 0) delete S.filters[index];
        filtersChanged();
    }

    function clearAllFilters() {
        S.filters = {};
        filtersChanged();
    }

    function applyFilters() {
        var active = Object.keys(S.filters).map(function (index) {
            return { index: Number(index), values: S.filters[index].map(function (v) { return v.toLowerCase(); }) };
        });

        if (active.length === 0) {
            S.filtered = S.rows.slice();
        } else {
            S.filtered = S.rows.filter(function (row) {
                return active.every(function (filter) {
                    var value = cell(row, filter.index).toLowerCase();
                    return filter.values.every(function (wanted) { return value.indexOf(wanted) !== -1; });
                });
            });
        }

        if (S.sortColumn !== null) applySorting();
        renderBody();
    }

    function updateFilterUI() {
        var count = totalFilterCount();
        var badge = byId('active-filter-count');
        var clear = byId('clear-filters-btn');
        if (badge) {
            badge.textContent = count;
            badge.classList.toggle('hide', count === 0);
        }
        if (clear) clear.classList.toggle('hide', count === 0);
    }

    function setFiltersVisible(visible) {
        S.filtersVisible = visible;
        var filterRow = byId('filter-row');
        var button = byId('filter-toggle-btn');
        if (filterRow) filterRow.classList.toggle('hide', !visible);
        if (button) {
            button.classList.toggle('on', visible);
            button.setAttribute('aria-pressed', visible ? 'true' : 'false');
        }
        if (!visible) closeDropdown();
    }

    // ========== SORTING ==========

    function sortByColumn(index) {
        if (S.sortColumn === index) {
            S.sortDirection = S.sortDirection === 'asc' ? 'desc' : 'asc';
        } else {
            S.sortColumn = index;
            S.sortDirection = 'asc';
        }
        applySorting();
        renderHeaders();
        renderBody();
    }

    function applySorting() {
        var index = S.sortColumn;
        var direction = S.sortDirection === 'asc' ? 1 : -1;
        S.filtered.sort(function (a, b) {
            var valA = cell(a, index);
            var valB = cell(b, index);
            var numA = parseFloat(valA);
            var numB = parseFloat(valB);
            if (!isNaN(numA) && !isNaN(numB)) return (numA - numB) * direction;
            return valA.localeCompare(valB) * direction;
        });
    }

    // ========== PAGINATION ==========

    function goToPage(page) {
        var totalPages = S.pageSize === 'all' ? 1 : Math.ceil(S.filtered.length / S.pageSize);
        S.page = Math.max(1, Math.min(page, totalPages));
        renderBody();
    }

    function changePageSize(size) {
        S.pageSize = size === 'all' ? 'all' : (parseInt(size, 10) || 50);
        S.page = 1;
        renderBody();
    }

    // ========== COLUMN VISIBILITY ==========

    function syncColumnPicker() {
        document.querySelectorAll('#column-selector-list input').forEach(function (box, index) {
            box.checked = S.visible.has(index);
        });
        var count = byId('visible-column-count');
        if (count) count.textContent = S.visible.size;
    }

    function setVisibleColumns(visible) {
        S.visible = visible;
        closeDropdown();
        syncColumnPicker();
        renderHeaders();
        renderFilterRow();
        renderBody();
    }

    function toggleColumnPicker(open) {
        var menu = byId('column-selector-dropdown');
        var button = byId('column-selector-btn');
        if (!menu) return;
        var show = open === undefined ? menu.classList.contains('hide') : open;
        menu.classList.toggle('hide', !show);
        if (button) button.setAttribute('aria-expanded', show ? 'true' : 'false');
    }

    // ========== COLUMN WIDTHS ==========

    // Fixed layout needs a width for every column; start from what is on screen.
    function freezeWidths() {
        if (S.fixedLayout) return;
        document.querySelectorAll('#header-row th').forEach(function (th) {
            S.widths[th.dataset.col] = th.offsetWidth;
        });
        S.fixedLayout = true;
    }

    function autoSizeColumns() {
        var table = byId('results-table');
        if (!table) return;

        S.widths = {};
        S.fixedLayout = false;
        renderHeaders();

        var measurer = el('div');
        measurer.style.cssText = 'position:absolute;visibility:hidden;white-space:nowrap;';
        var sample = table.querySelector('tbody td');
        if (sample) measurer.style.font = getComputedStyle(sample).font;
        document.body.appendChild(measurer);

        var widths = {};
        document.querySelectorAll('#header-row th').forEach(function (th) {
            var index = th.dataset.col;
            var widest = th.offsetWidth;
            table.querySelectorAll('tbody td[data-col="' + index + '"]').forEach(function (td) {
                measurer.textContent = td.textContent;
                widest = Math.max(widest, measurer.offsetWidth + 30);
            });
            widths[index] = Math.min(widest, 400);
        });
        document.body.removeChild(measurer);

        S.widths = widths;
        S.fixedLayout = true;
        renderHeaders();
    }

    function resetColumnWidths() {
        S.widths = {};
        S.fixedLayout = false;
        renderHeaders();
    }

    function startColumnDrag(event, handle) {
        var th = handle.closest('th');
        if (!th) return;
        event.preventDefault();

        freezeWidths();
        renderHeaders();
        var index = handle.dataset.col;
        var startX = event.clientX;
        var startWidth = S.widths[index] || th.offsetWidth;
        document.body.classList.add('col-resizing');

        function move(e) {
            S.widths[index] = Math.max(60, startWidth + e.clientX - startX);
            var current = document.querySelector('#header-row th[data-col="' + index + '"]');
            if (current) applyWidth(current, Number(index));
        }
        function stop() {
            document.removeEventListener('mousemove', move);
            document.removeEventListener('mouseup', stop);
            document.body.classList.remove('col-resizing');
            justResized = true;
            setTimeout(function () { justResized = false; }, 0);
        }
        document.addEventListener('mousemove', move);
        document.addEventListener('mouseup', stop);
    }

    // ========== TABS ==========

    function switchResultsTab(name) {
        document.querySelectorAll('#results-wrapper [data-results-tab]').forEach(function (tab) {
            var on = tab.dataset.resultsTab === name;
            tab.classList.toggle('on', on);
            tab.setAttribute('aria-selected', on ? 'true' : 'false');
        });
        ['table', 'stats'].forEach(function (panelName) {
            var panel = byId('results-' + panelName + '-panel');
            if (panel) panel.classList.toggle('hide', panelName !== name);
        });
        closeDropdown();
        toggleColumnPicker(false);
        if (name === 'stats') loadStats();
    }

    // The Stats tab is fetched the first time it is opened.
    function loadStats() {
        var container = byId('stats-container');
        if (!container || S.statsLoaded || S.statsLoading) return;
        var state = S;
        state.statsLoading = true;
        htmx.ajax('GET', state.statsUrl, { target: '#stats-container', swap: 'innerHTML' }).then(function () {
            state.statsLoaded = true;
            state.statsLoading = false;
        }, function () {
            state.statsLoading = false;
        });
    }

    // ========== DOWNLOAD ==========

    function csvField(value) {
        return '"' + String(value === undefined || value === null ? '' : value).replace(/"/g, '""') + '"';
    }

    // Every column (real names), filtered rows only.
    function downloadFilteredCSV() {
        if (S.filtered.length === 0) {
            window.showToast('No rows to download', 'warning');
            return;
        }
        var lines = [S.headers.map(csvField).join(',')];
        S.filtered.forEach(function (row) {
            lines.push(S.headers.map(function (_, index) { return csvField(row[index]); }).join(','));
        });

        var blob = new Blob([lines.join('\n') + '\n'], { type: 'text/csv;charset=utf-8;' });
        var url = URL.createObjectURL(blob);
        var link = document.createElement('a');
        link.href = url;
        link.download = 'logboost_filtered_results.csv';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }

    // ========== FULLSCREEN ==========

    function isFullscreen() {
        var wrapper = byId('results-wrapper');
        return !!wrapper && wrapper.classList.contains('fullscreen');
    }

    function toggleFullscreen() {
        var wrapper = byId('results-wrapper');
        var button = byId('fullscreen-btn');
        if (!wrapper) return;
        var on = !wrapper.classList.contains('fullscreen');
        wrapper.classList.toggle('fullscreen', on);
        document.body.classList.toggle('results-fullscreen', on);
        if (button) {
            button.textContent = on ? 'Exit fullscreen' : 'Fullscreen';
            button.setAttribute('aria-pressed', on ? 'true' : 'false');
        }
        closeDropdown();
        setTimeout(function () { window.dispatchEvent(new Event('resize')); }, 100);
    }

    // ========== SHARE ==========

    async function shareResults() {
        var button = byId('share-results-btn');
        if (!button) return;
        button.disabled = true;
        try {
            var response = await fetch('/api/results/share', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCSRFToken() }
            });
            var result = await response.json();
            if (result.error) {
                window.showToast(result.error, 'error');
                return;
            }
            await navigator.clipboard.writeText(result.share_url);
            window.showToast('Share link copied to clipboard. Expires in ' + result.expires_in_days + ' days.', 'success');
        } catch (err) {
            console.error('Share failed:', err);
            window.showToast('Failed to create share link: ' + err.message, 'error');
        } finally {
            button.disabled = false;
        }
    }

    // ========== EVENTS (delegated; registered once) ==========

    var ACTIONS = {
        'share': shareResults,
        'fullscreen': toggleFullscreen,
        'download-filtered': downloadFilteredCSV,
        'dismiss-warning': function (target) {
            var notice = target.closest('.notice');
            if (notice) notice.classList.add('hide');
        },
        'columns': function () { toggleColumnPicker(); },
        'columns-all': function () { setVisibleColumns(allColumns()); },
        'columns-none': function () { setVisibleColumns(new Set()); },
        'columns-enrichment': function () {
            var visible = new Set();
            S.headers.forEach(function (header, index) { if (isEnrichment(header)) visible.add(index); });
            setVisibleColumns(visible);
        },
        'autofit': autoSizeColumns,
        'reset-widths': resetColumnWidths,
        'filters': function () { setFiltersVisible(!S.filtersVisible); },
        'clear-filters': clearAllFilters,
        'filter-values': function (target) {
            toggleDropdown(Number(target.closest('.filter-cell').dataset.col), target);
        },
        'remove-filter': function (target) {
            removeFilter(Number(target.closest('.filter-cell').dataset.col), Number(target.dataset.position));
        }
    };

    document.addEventListener('click', function (event) {
        if (!S) return;
        var target = event.target;
        var wrapper = target.closest ? target.closest('#results-wrapper') : null;

        // Clicks elsewhere close the popovers
        if (!target.closest || !target.closest('.pop-wrap')) toggleColumnPicker(false);
        if (!target.closest || !(target.closest('#filter-dropdown') || target.closest('[data-act="filter-values"]'))) closeDropdown();
        if (!wrapper) return;

        var tab = target.closest('[data-results-tab]');
        if (tab) { switchResultsTab(tab.dataset.resultsTab); return; }

        var action = target.closest('[data-act]');
        if (action && ACTIONS[action.dataset.act]) { ACTIONS[action.dataset.act](action); return; }

        var page = target.closest('#pagination-controls [data-page]');
        if (page) { goToPage(Number(page.dataset.page)); return; }

        var option = target.closest('.filter-dropdown-item');
        if (option && dropdown && dropdown.dataset.col !== undefined) {
            toggleFilterValue(Number(dropdown.dataset.col), option.dataset.value);
            return;
        }

        if (target.closest('.col-resizer') || justResized) return;
        var th = target.closest('#header-row th');
        if (th) sortByColumn(Number(th.dataset.col));
    });

    document.addEventListener('change', function (event) {
        if (!S) return;
        var target = event.target;
        if (target.id === 'page-size') {
            changePageSize(target.value);
        } else if (target.matches && target.matches('#column-selector-list input')) {
            var boxes = Array.prototype.slice.call(document.querySelectorAll('#column-selector-list input'));
            var index = boxes.indexOf(target);
            var visible = new Set(S.visible);
            if (target.checked) visible.add(index); else visible.delete(index);
            setVisibleColumns(visible);
        }
    });

    document.addEventListener('input', function (event) {
        if (S && event.target.matches && event.target.matches('.filter-search-input')) {
            populateDropdown(event.target.value);
        }
    });

    document.addEventListener('keydown', function (event) {
        if (!S) return;
        var target = event.target;
        if (event.key === 'Enter' && target.matches && target.matches('.filter-input')) {
            var value = target.value.trim();
            if (!value) return;
            var index = Number(target.closest('.filter-cell').dataset.col);
            addFilter(index, value);
            // the filter row was rebuilt; put the caret back in the same column
            var again = document.querySelector('#filter-row .filter-cell[data-col="' + index + '"] .filter-input');
            if (again) again.focus();
        } else if (event.key === 'Escape') {
            if (document.querySelector('dialog[open]')) return;   // the dialog takes this Esc
            var menu = byId('column-selector-dropdown');
            if (dropdown && !dropdown.classList.contains('hide')) {
                closeDropdown();
            } else if (menu && !menu.classList.contains('hide')) {
                toggleColumnPicker(false);
            } else if (isFullscreen()) {
                toggleFullscreen();
            }
        }
    });

    document.addEventListener('mousedown', function (event) {
        if (!S || event.button !== 0 || !event.target.closest) return;
        var handle = event.target.closest('#header-row .col-resizer');
        if (handle) startColumnDrag(event, handle);
    });

    // The value dropdown is positioned against the viewport, so it cannot follow a scroll.
    document.addEventListener('scroll', function (event) {
        if (dropdown && !dropdown.classList.contains('hide') && !dropdown.contains(event.target)) closeDropdown();
    }, true);

    // A fragment arrived: from the Enrich forms (htmx) or from the shared-results loader.
    document.addEventListener('htmx:afterSwap', function (event) {
        var target = event.detail && event.detail.target;
        if (!target || target.id !== 'results-container') return;
        init();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
    document.addEventListener('DOMContentLoaded', init);

    // ========== API for the other workspace scripts ==========

    function findColumn(name) {
        return S ? S.headers.indexOf(name) : -1;
    }

    window.LBResults = {
        init: init,
        active: function () { return !!S; },
        headers: function () { return S ? S.headers.slice() : []; },
        displayName: displayName,
        // Rows on the current page, in table order (arrays of cell values, one per header).
        pageRows: function () {
            if (!S) return [];
            var bounds = pageBounds();
            return S.filtered.slice(bounds[0], bounds[1]);
        },
        // Stats click-through: show the table with its filter row and filter `column` by `value`.
        filterBy: function (column, value) {
            var index = findColumn(column);
            if (index === -1 || !value) return false;
            switchResultsTab('table');
            setFiltersVisible(true);
            if (!S.visible.has(index)) {
                var visible = new Set(S.visible);
                visible.add(index);
                setVisibleColumns(visible);
            }
            addFilter(index, String(value));
            return true;
        }
    };
})();

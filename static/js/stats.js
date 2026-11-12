// Results > Stats tab (templates/partials/stats.html, fetched by results.js when the tab opens).
// Everything is delegated from the document, so the fragment needs no script of its own:
// click a value to filter the table, flip a card between most and least common, and the
// "All values" dialog whose list is fetched on demand.
(function () {
    'use strict';

    var modalData = { values: [], column: '', reversed: false, totalRows: 0 };

    function el(tag, className, text) {
        var node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined) node.textContent = text;
        return node;
    }

    // ---- click a value: filter the table by it ----

    // The statistics name columns loosely (lb_Org, lb_Ports…); find the closest real header.
    function matchColumn(column) {
        var headers = window.LBResults ? window.LBResults.headers() : [];
        if (headers.indexOf(column) !== -1) return column;

        var wanted = column.toLowerCase();
        var bare = wanted.replace('lb_', '');
        function strip(header) { return header.toLowerCase().replace('lb_', ''); }

        return headers.find(function (h) { return h.toLowerCase() === wanted; })
            || headers.find(function (h) { return strip(h).includes(bare) || bare.includes(strip(h)); })
            || headers.find(function (h) { return h.toLowerCase().endsWith(bare) || bare.endsWith(strip(h)); })
            || null;
    }

    function pivotToFilter(element) {
        var column = element.dataset.column;
        var value = element.dataset.value;
        if (!column || !value || !window.LBResults) return;

        var target = matchColumn(column);
        if (!target || !window.LBResults.filterBy(target, value)) {
            window.showToast('The table has no column to filter for "' + column.replace(/^lb_/, '') + '"', 'warning');
        }
    }

    // ---- most / least common ----

    function flipCard(button) {
        var card = button.closest('[data-stat-card]');
        var list = card && card.querySelector('.value-distribution, .tag-cloud');
        if (!list) return;

        var items = Array.prototype.slice.call(list.children);
        var reversed = card.dataset.reversed === 'true';
        items.sort(function (a, b) {
            var countA = parseInt(a.dataset.count, 10);
            var countB = parseInt(b.dataset.count, 10);
            return reversed ? countB - countA : countA - countB;
        });
        items.forEach(function (item) { list.appendChild(item); });

        card.dataset.reversed = reversed ? 'false' : 'true';
        button.textContent = reversed ? 'Most common' : 'Least common';
        button.setAttribute('aria-pressed', reversed ? 'false' : 'true');
    }

    // ---- "All values" dialog ----

    function expandCard(button) {
        // The full list is not embedded in the page; fetch it when the dialog opens
        var key = button.dataset.valuesKey;
        var root = button.closest('[data-stats-root]');
        var dialog = document.getElementById('stats-expand-modal');
        if (!key || !dialog) return;

        fetch('/stats/values/' + key + (root ? root.dataset.valuesQuery || '' : ''), { credentials: 'same-origin' })
            .then(function (response) { return response.json(); })
            .then(function (data) {
                modalData.values = data.values || [];
                modalData.totalRows = data.total_rows || 0;
                modalData.column = button.dataset.column;
                modalData.reversed = false;

                document.getElementById('stats-modal-title').textContent =
                    button.dataset.title + ' (' + modalData.values.length + ' values)';
                document.getElementById('modal-sort-label').textContent = 'Most common';
                renderModalValues();
                if (!dialog.open) dialog.showModal();
            })
            .catch(function (err) {
                console.error('Failed to load values:', err);
                window.showToast('Could not load the values', 'error');
            });
    }

    function renderModalValues() {
        // Built with DOM nodes: values come from log data and must never be parsed as HTML
        var body = document.getElementById('stats-modal-body');
        var values = modalData.reversed ? modalData.values.slice().reverse() : modalData.values;

        var list = el('div', 'barlist wide value-distribution');
        values.forEach(function (entry) {
            var value = String(entry[0]);
            var count = entry[1];
            var pct = modalData.totalRows ? (count / modalData.totalRows * 100).toFixed(1) : '0.0';

            var pair = el('div', 'bar-pair');
            var item = el('button', 'stat-bar');
            item.type = 'button';
            item.title = value;
            item.dataset.pivot = '';
            item.dataset.column = modalData.column;
            item.dataset.value = value;
            item.dataset.count = count;

            var bar = el('i');
            bar.style.width = Math.min(100, parseFloat(pct)) + '%';
            item.append(bar, el('span', '', value.length > 60 ? value.substring(0, 60) + '...' : value));

            pair.append(item, el('em', '', count + ' (' + pct + '%)'));
            list.appendChild(pair);
        });
        body.replaceChildren(list);
    }

    function flipModalValues() {
        modalData.reversed = !modalData.reversed;
        document.getElementById('modal-sort-label').textContent = modalData.reversed ? 'Least common' : 'Most common';
        renderModalValues();
    }

    // ---- events ----

    document.addEventListener('click', function (event) {
        if (!event.target.closest) return;

        var action = event.target.closest('[data-stat-act]');
        if (action) {
            if (action.dataset.statAct === 'flip') flipCard(action);
            else if (action.dataset.statAct === 'expand') expandCard(action);
            else if (action.dataset.statAct === 'flip-modal') flipModalValues();
            return;
        }

        var value = event.target.closest('[data-pivot]');
        if (value && value.closest('#stats-container')) {
            var dialog = value.closest('dialog');
            if (dialog && dialog.open) dialog.close();
            pivotToFilter(value);
        }
    });
})();

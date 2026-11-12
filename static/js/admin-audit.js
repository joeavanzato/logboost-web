// Audit log page: expand/collapse the details row of an event, and show the viewer's local
// time as a tooltip on each UTC time. Displayed times and day headings always stay in UTC.
(function () {
  'use strict';

  document.addEventListener('click', function (event) {
    var button = event.target.closest('[data-audit-toggle]');
    if (!button) return;
    var row = document.getElementById(button.getAttribute('aria-controls'));
    if (!row) return;
    var open = row.hidden;
    row.hidden = !open;
    button.setAttribute('aria-expanded', open ? 'true' : 'false');
    button.textContent = open ? 'Hide' : 'Details';
  });

  Array.prototype.forEach.call(document.querySelectorAll('[data-utc]'), function (cell) {
    var when = new Date(cell.dataset.utc);
    if (cell.dataset.utc && !isNaN(when.getTime())) cell.title = 'Local time: ' + when.toLocaleString();
  });
})();

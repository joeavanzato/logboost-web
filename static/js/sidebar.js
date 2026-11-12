// Collapsible sidebar. Loaded in <head> so the stored state applies before the first paint;
// the class sits on <html> because <body> does not exist yet at that point.
(function () {
  'use strict';
  var KEY = 'logboost-sidebar';
  var root = document.documentElement;

  function stored() {
    try { return window.localStorage.getItem(KEY); } catch (e) { return null; }  // storage may be blocked
  }

  if (stored() === 'collapsed') root.classList.add('side-collapsed');

  function sync() {
    var collapsed = root.classList.contains('side-collapsed');
    document.querySelectorAll('[data-side-toggle]').forEach(function (button) {
      var label = collapsed ? 'Expand sidebar' : 'Collapse sidebar';
      button.setAttribute('aria-expanded', String(!collapsed));
      button.setAttribute('aria-label', label);
      button.title = label;
    });
  }

  document.addEventListener('DOMContentLoaded', sync);
  document.addEventListener('click', function (event) {
    if (!event.target.closest || !event.target.closest('[data-side-toggle]')) return;
    var collapsed = root.classList.toggle('side-collapsed');
    try { window.localStorage.setItem(KEY, collapsed ? 'collapsed' : 'expanded'); } catch (e) { /* not remembered */ }
    sync();
    window.dispatchEvent(new Event('resize'));  // the graph canvas re-centres on resize
  });
})();

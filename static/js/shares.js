// Shares page: "Copy link" buttons (<button data-copy="url">).
(function () {
  'use strict';

  function fallbackCopy(text) {
    var input = document.createElement('textarea');
    input.value = text;
    input.setAttribute('readonly', '');
    input.style.position = 'fixed';
    input.style.opacity = '0';
    document.body.appendChild(input);
    input.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    input.remove();
    return ok;
  }

  function copy(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).then(function () { return true; }, function () { return fallbackCopy(text); });
    }
    return Promise.resolve(fallbackCopy(text));
  }

  document.addEventListener('click', function (event) {
    var button = event.target.closest('[data-copy]');
    if (!button) return;
    var label = button.dataset.label || button.textContent;
    button.dataset.label = label;
    copy(button.dataset.copy).then(function (ok) {
      button.textContent = ok ? 'Copied' : 'Copy failed';
      setTimeout(function () { button.textContent = label; }, 1500);
    });
  });
})();

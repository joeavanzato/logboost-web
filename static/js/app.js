// Behaviour shared by every page in the app layout. No page-specific code here.
(function () {
  'use strict';

  // <input data-autosubmit>: submit the surrounding form as soon as the value changes.
  document.addEventListener('change', function (event) {
    var el = event.target;
    if (el.matches && el.matches('[data-autosubmit]') && el.form) el.form.submit();
  });

  // <form data-confirm="question">: ask before a destructive submit.
  document.addEventListener('submit', function (event) {
    var message = event.target.dataset && event.target.dataset.confirm;
    if (message && !window.confirm(message)) event.preventDefault();
  });

  // [data-dialog-open="id"] opens a <dialog>; [data-dialog-close] closes the one it sits in.
  // A click on the backdrop closes it too; Esc is handled by the browser.
  document.addEventListener('click', function (event) {
    var opener = event.target.closest('[data-dialog-open]');
    if (opener) {
      var dialog = document.getElementById(opener.dataset.dialogOpen);
      if (dialog && dialog.showModal) dialog.showModal();
      return;
    }
    var closer = event.target.closest('[data-dialog-close]');
    if (closer) {
      closer.closest('dialog').close();
      return;
    }
    if (event.target.tagName === 'DIALOG') event.target.close();
  });

  // Helpers for page scripts.
  window.LB = {
    csrf: function () {
      var meta = document.querySelector('meta[name="csrf-token"]');
      return meta ? meta.content : '';
    },
    // fetch() with the CSRF header; a JSON body is encoded for you.
    api: function (url, options) {
      options = options || {};
      var headers = Object.assign({ 'X-CSRFToken': window.LB.csrf() }, options.headers || {});
      if (options.json !== undefined) {
        headers['Content-Type'] = 'application/json';
        options.body = JSON.stringify(options.json);
      }
      return fetch(url, Object.assign({}, options, { headers: headers }));
    }
  };
})();

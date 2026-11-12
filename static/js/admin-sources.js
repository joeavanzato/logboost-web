// Data sources page: key tests, Shodan account info, .mmdb upload, LogBoost binary updates.
// Everything that comes from the server or a third-party API is written with textContent.
(function () {
  'use strict';

  function show(el, ok, message) {
    el.className = 'notice ' + (ok ? 'green' : 'red');
    el.textContent = message;
  }

  // A <details> that holds an invalid field opens, so the browser can point at the field.
  document.addEventListener('invalid', function (event) {
    var details = event.target.closest && event.target.closest('details');
    if (details) details.open = true;
  }, true);

  // "Remove key" shares its form with Save, so the question is asked on the button.
  document.addEventListener('click', function (event) {
    var button = event.target.closest('button[data-confirm]');
    if (button && !window.confirm(button.dataset.confirm)) event.preventDefault();
  });

  // ---------- Test a key. An empty field tests the stored key, which the page never receives.
  document.addEventListener('click', function (event) {
    var button = event.target.closest('[data-test-url]');
    if (!button) return;
    var key = document.getElementById(button.dataset.testInput).value;
    var result = document.getElementById(button.dataset.testResult);
    if (!key && button.dataset.keyStored !== 'true') {
      show(result, false, 'Enter a key first');
      return;
    }
    button.disabled = true;
    button.textContent = 'Testing…';
    result.className = 'notice plain';
    result.textContent = 'Testing connection…';
    window.LB.api(button.dataset.testUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'api_key=' + encodeURIComponent(key)
    })
      .then(function (response) { return response.json(); })
      .then(function (data) {
        var message = data.message;
        if (data.success && data.plan) {
          message += ' (Plan: ' + data.plan + ', Credits: ' + data.query_credits + ')';
        }
        show(result, !!data.success, message);
      })
      .catch(function (error) { show(result, false, 'Connection error: ' + error.message); })
      .finally(function () {
        button.disabled = false;
        button.textContent = 'Test';
      });
  });

  // ---------- Shodan plan and credits: one outbound call, made after the page is on screen.
  var shodanInfo = document.getElementById('shodan-info');
  if (shodanInfo) {
    fetch(shodanInfo.dataset.url)
      .then(function (response) { return response.json(); })
      .then(function (info) {
        if (!info) return;
        shodanInfo.querySelectorAll('[data-shodan-info]').forEach(function (el) {
          el.textContent = info[el.dataset.shodanInfo];
        });
        shodanInfo.classList.remove('hide');
      })
      .catch(function () {});
  }

  // ---------- Upload the three GeoLite2 .mmdb files.
  var dialog = document.getElementById('mmdb-dialog');
  var uploadForm = document.getElementById('mmdb-upload-form');
  var fileInput = document.getElementById('mmdb-file-input');
  var dropArea = document.getElementById('mmdb-drop');
  var uploadButton = document.getElementById('mmdb-upload-btn');
  var uploadStatus = document.getElementById('mmdb-upload-status');
  var rows = Array.prototype.slice.call(uploadForm.querySelectorAll('[data-mmdb-file]'));
  var required = rows.map(function (row) { return row.dataset.mmdbFile; });
  var selected = new Map();

  function refreshChecklist() {
    rows.forEach(function (row) {
      var has = selected.has(row.dataset.mmdbFile);
      var dot = row.querySelector('.dot');
      dot.className = 'dot ' + (has ? 'green' : 'grey');
      dot.textContent = has ? 'Selected' : 'Not selected';
    });
    uploadButton.disabled = !required.every(function (name) { return selected.has(name); });
  }

  // Files can be added in several goes; only the three required names are kept.
  function addFiles(files) {
    Array.prototype.forEach.call(files, function (file) {
      if (required.indexOf(file.name) !== -1) selected.set(file.name, file);
    });
    refreshChecklist();
  }

  fileInput.addEventListener('change', function () { addFiles(fileInput.files); });
  dropArea.addEventListener('dragover', function (event) {
    event.preventDefault();
    dropArea.style.borderColor = 'var(--green)';
  });
  dropArea.addEventListener('dragleave', function () { dropArea.style.borderColor = ''; });
  dropArea.addEventListener('drop', function (event) {
    event.preventDefault();
    dropArea.style.borderColor = '';
    addFiles(event.dataTransfer.files);
  });

  dialog.addEventListener('close', function () {
    selected.clear();
    fileInput.value = '';
    uploadStatus.className = 'notice hide';
    uploadButton.textContent = 'Upload files';
    refreshChecklist();
  });

  uploadForm.addEventListener('submit', function (event) {
    event.preventDefault();
    var body = new FormData();
    selected.forEach(function (file) { body.append('mmdb_files', file); });
    uploadButton.disabled = true;
    uploadButton.textContent = 'Uploading…';
    uploadStatus.className = 'notice hide';

    function failed(message) {
      show(uploadStatus, false, message);
      uploadButton.disabled = false;
      uploadButton.textContent = 'Upload files';
    }

    window.LB.api(uploadForm.dataset.uploadUrl, { method: 'POST', body: body })
      .then(function (response) {
        return response.json().then(function (result) {
          if (!response.ok) {
            failed(result.error || 'Upload failed');
            return;
          }
          show(uploadStatus, true, result.message || 'Files uploaded');
          setTimeout(function () { window.location.reload(); }, 1500);
        });
      })
      .catch(function (error) { failed('Network error: ' + error.message); });
  });

  // ---------- LogBoost binary: check GitHub for a release, then download and install it.
  var binary = document.getElementById('binary');
  var checkButton = document.getElementById('check-update-btn');
  var installButton = document.getElementById('install-update-btn');
  var binaryStatus = document.getElementById('binary-status');
  var binaryMessage = document.getElementById('binary-message');

  checkButton.addEventListener('click', function () {
    checkButton.disabled = true;
    checkButton.textContent = 'Checking…';
    installButton.disabled = true;
    binaryStatus.className = 'dot hide';
    binaryMessage.className = 'notice hide';

    fetch(binary.dataset.checkUrl)
      .then(function (response) { return response.json(); })
      .then(function (data) {
        if (data.error) {
          show(binaryMessage, false, data.error);
          return;
        }
        document.getElementById('binary-latest').textContent = data.latest_tag;
        document.getElementById('binary-installed').textContent = data.installed_version;
        document.getElementById('binary-checked').textContent = data.checked_at;
        binaryStatus.className = 'dot ' + (data.update_available ? 'amber' : 'green');
        binaryStatus.textContent = data.update_available ? 'Update available' : 'Up to date';
        installButton.disabled = !data.update_available;
      })
      .catch(function (error) { show(binaryMessage, false, 'Error: ' + error.message); })
      .finally(function () {
        checkButton.disabled = false;
        checkButton.textContent = 'Check for updates';
      });
  });

  installButton.addEventListener('click', function () {
    installButton.disabled = true;
    binaryMessage.className = 'notice plain';
    binaryMessage.textContent = 'Downloading and installing…';

    window.LB.api(binary.dataset.installUrl, { method: 'POST' })
      .then(function (response) { return response.json(); })
      .then(function (data) {
        if (data.error) {
          show(binaryMessage, false, data.error);
          installButton.disabled = false;
          return;
        }
        show(binaryMessage, true, 'Installed ' + data.version + ' to ' + data.path + '. Reloading…');
        setTimeout(function () { window.location.reload(); }, 2000);
      })
      .catch(function (error) {
        show(binaryMessage, false, 'Error: ' + error.message);
        installButton.disabled = false;
      });
  });
})();

// Threat feeds page: search and tag filter, add/edit dialog, connectivity tests, delete.
// Feed names, URLs and tags are untrusted: everything is written with textContent or dataset.
(function () {
  'use strict';

  var dialog = document.getElementById('feed-dialog');
  if (!dialog) return;

  var FLASH_KEY = 'lb-feeds-status';
  var feedApi = dialog.dataset.feedApi;   // POST adds; "/<index>" takes PUT and DELETE
  var testApi = dialog.dataset.testApi;

  var statusLine = document.getElementById('feeds-status');
  var sub = document.getElementById('feeds-sub');
  var search = document.getElementById('feed-search');
  var chips = document.getElementById('tag-chips');
  var tbody = document.getElementById('feed-rows');
  var noMatch = document.getElementById('feeds-no-match');
  var testAllBtn = document.getElementById('test-all');

  var form = document.getElementById('feed-form');
  var dialogTitle = document.getElementById('feed-dialog-title');
  var formError = document.getElementById('feed-form-error');
  var nameInput = document.getElementById('feed-name');
  var urlInput = document.getElementById('feed-url');
  var tagList = document.getElementById('feed-tags');
  var tagInput = document.getElementById('feed-tag-input');
  var tagHint = document.getElementById('feed-tags-hint');
  var suggestions = document.getElementById('feed-tag-suggestions');
  var submitBtn = document.getElementById('feed-submit');

  var selectedTag = null;   // null = "All"
  var editingRow = null;    // null while adding
  var dialogTags = [];

  // ---------- helpers ----------

  function setStatus(text, isError) {
    statusLine.textContent = text;
    statusLine.className = isError ? 'red' : 'muted';
  }

  // Shown after the reload that follows an add or a delete.
  function reloadWith(message) {
    try { sessionStorage.setItem(FLASH_KEY, message); } catch (e) { /* storage unavailable */ }
    location.reload();
  }

  function request(url, options) {
    return window.LB.api(url, options).then(function (res) {
      return res.json().catch(function () {
        return { error: 'Unexpected response (HTTP ' + res.status + ')' };
      });
    });
  }

  function rows() {
    return tbody ? Array.prototype.slice.call(tbody.rows) : [];
  }

  function rowTags(row) {
    return Array.prototype.map.call(row.querySelectorAll('[data-feed-tags] .tag'), function (el) {
      return el.textContent;
    });
  }

  function displayUrl(url) {
    return url.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  // ---------- filter ----------

  function applyFilter() {
    if (!tbody) return;
    var query = search.value.trim().toLowerCase();
    var shown = 0;
    rows().forEach(function (row) {
      var tags = rowTags(row);
      var haystack = [row.dataset.name, row.dataset.url].concat(tags).join('\n').toLowerCase();
      var match = (!query || haystack.indexOf(query) !== -1) &&
                  (selectedTag === null || tags.indexOf(selectedTag) !== -1);
      row.classList.toggle('hide', !match);
      if (match) shown += 1;
    });
    noMatch.classList.toggle('hide', shown > 0);
  }

  function chip(label, count, tag) {
    var on = tag === selectedTag;
    var button = el('button', on ? 'chip on' : 'chip', label + ' ');
    button.type = 'button';
    button.setAttribute('aria-pressed', on ? 'true' : 'false');
    if (tag === null) button.dataset.all = '';
    else button.dataset.tag = tag;
    button.appendChild(el('small', '', String(count)));
    return button;
  }

  // Rebuild the chips, the tag suggestions and the subtitle from the rows (after an edit).
  function refreshTags() {
    if (!tbody) return;
    var counts = new Map();
    var all = rows();
    all.forEach(function (row) {
      rowTags(row).forEach(function (tag) { counts.set(tag, (counts.get(tag) || 0) + 1); });
    });
    var names = Array.from(counts.keys()).sort();
    if (selectedTag !== null && !counts.has(selectedTag)) selectedTag = null;

    chips.replaceChildren(chip('All', all.length, null));
    suggestions.replaceChildren();
    names.forEach(function (tag) {
      chips.appendChild(chip(tag, counts.get(tag), tag));
      var option = document.createElement('option');
      option.value = tag;
      suggestions.appendChild(option);
    });
    sub.textContent = all.length + (all.length === 1 ? ' source' : ' sources') + ' · ' +
                      names.length + (names.length === 1 ? ' tag' : ' tags');
    applyFilter();
  }

  if (tbody) {
    search.addEventListener('input', applyFilter);
    chips.addEventListener('click', function (event) {
      var clicked = event.target.closest('.chip');
      if (!clicked) return;
      selectedTag = 'all' in clicked.dataset ? null : clicked.dataset.tag;
      Array.prototype.forEach.call(chips.querySelectorAll('.chip'), function (button) {
        var on = button === clicked;
        button.classList.toggle('on', on);
        button.setAttribute('aria-pressed', on ? 'true' : 'false');
      });
      applyFilter();
    });
  }

  // ---------- connectivity tests ----------

  function showTest(row, data) {
    var cell = row.querySelector('[data-feed-test]');
    var result;
    if (data === null) {
      result = el('span', 'muted', 'Testing…');
    } else if (data.ok) {
      result = el('span', 'dot green', 'Reachable');
      var parts = [];
      if (data.status_code) parts.push('HTTP ' + data.status_code);
      if (data.elapsed_ms != null) parts.push(data.elapsed_ms + ' ms');
      if (data.method) parts.push('via ' + data.method);
      if (data.content_type) parts.push(data.content_type);
      if (data.content_length != null) parts.push(Number(data.content_length).toLocaleString() + ' bytes');
      if (data.redirect) parts.push('redirects to ' + data.redirect);
      result.title = parts.join(' · ');
    } else {
      result = el('span', 'dot red', data.error || 'Failed');
      result.style.whiteSpace = 'normal';
      result.style.overflowWrap = 'anywhere';
    }
    cell.replaceChildren(result);
  }

  // Resolves to true when the feed answered.
  function testFeed(row) {
    var url = row.dataset.url;
    if (!url) {
      showTest(row, { ok: false, error: 'URL is required' });
      return Promise.resolve(false);
    }
    var button = row.querySelector('[data-feed-test-run]');
    button.disabled = true;
    showTest(row, null);
    return request(testApi, { method: 'POST', json: { url: url } })
      .catch(function (err) { return { ok: false, error: err.message || 'Network error' }; })
      .then(function (data) {
        button.disabled = false;
        showTest(row, data);
        return !!data.ok;
      });
  }

  function testAll() {
    var queue = rows();
    var total = queue.length;
    if (!total) return;
    var reachable = 0;
    testAllBtn.disabled = true;
    setStatus('Testing ' + total + (total === 1 ? ' feed…' : ' feeds…'));

    function worker() {
      var row = queue.shift();
      if (!row) return Promise.resolve();
      return testFeed(row).then(function (ok) {
        if (ok) reachable += 1;
        return worker();
      });
    }

    var workers = [];
    for (var i = 0; i < Math.min(5, total); i += 1) workers.push(worker());
    Promise.all(workers).then(function () {
      testAllBtn.disabled = false;
      var failed = total - reachable;
      setStatus('Tested ' + total + (total === 1 ? ' feed: ' : ' feeds: ') + reachable + ' reachable, ' +
                failed + ' failed.', failed > 0);
    });
  }

  if (testAllBtn) testAllBtn.addEventListener('click', testAll);

  // ---------- add / edit dialog ----------

  function showFormError(message) {
    formError.textContent = message;
    formError.classList.toggle('hide', !message);
  }

  function renderDialogTags() {
    tagList.replaceChildren();
    dialogTags.forEach(function (tag) {
      var pill = el('span', 'tag', tag + ' ');
      var remove = el('button', 'linkbtn', '×');
      remove.type = 'button';
      remove.dataset.removeTag = tag;
      remove.setAttribute('aria-label', 'Remove tag ' + tag);
      pill.appendChild(remove);
      tagList.appendChild(pill);
    });
    tagList.classList.toggle('hide', dialogTags.length === 0);
  }

  // Move what is typed in the tag field into the tag list.
  function commitTagInput() {
    var tag = tagInput.value.trim().toLowerCase();
    tagInput.value = '';
    if (tag && dialogTags.indexOf(tag) === -1) {
      dialogTags.push(tag);
      renderDialogTags();
    }
  }

  function openDialog(row) {
    editingRow = row || null;
    dialogTitle.textContent = row ? 'Edit feed' : 'Add feed';
    submitBtn.textContent = row ? 'Save changes' : 'Add feed';
    tagHint.textContent = row ? 'Press Enter to add a tag.'
                              : 'Press Enter to add a tag. A feed added without tags is tagged "suspicious".';
    nameInput.value = row ? row.dataset.name : '';
    urlInput.value = row ? row.dataset.url : '';
    tagInput.value = '';
    dialogTags = row ? rowTags(row) : [];
    renderDialogTags();
    showFormError('');
    submitBtn.disabled = false;
    dialog.showModal();
    nameInput.focus();
  }

  function updateRow(row, feed) {
    var name = String(feed.name == null ? '' : feed.name);
    var url = String(feed.url == null ? '' : feed.url);
    var tags = Array.isArray(feed.type) ? feed.type : [];
    if (url !== row.dataset.url) row.querySelector('[data-feed-test]').replaceChildren();
    row.dataset.name = name;
    row.dataset.url = url;
    row.querySelector('[data-feed-name]').textContent = name;
    var urlEl = row.querySelector('[data-feed-url]');
    urlEl.textContent = displayUrl(url);
    urlEl.title = url;
    var tagCell = row.querySelector('[data-feed-tags]');
    tagCell.replaceChildren();
    tags.forEach(function (tag) { tagCell.appendChild(el('span', 'tag', String(tag))); });
    row.querySelector('[data-feed-delete]').dataset.confirm = 'Delete feed "' + name + '"?';
  }

  tagInput.addEventListener('keydown', function (event) {
    if (event.key !== 'Enter') return;
    event.preventDefault();   // Enter adds the tag; it must not submit the form
    commitTagInput();
  });
  document.getElementById('feed-tag-add').addEventListener('click', function () {
    commitTagInput();
    tagInput.focus();
  });
  tagList.addEventListener('click', function (event) {
    var remove = event.target.closest('[data-remove-tag]');
    if (!remove) return;
    dialogTags = dialogTags.filter(function (tag) { return tag !== remove.dataset.removeTag; });
    renderDialogTags();
  });

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    commitTagInput();
    var name = nameInput.value.trim();
    var url = urlInput.value.trim();
    if (!name) { showFormError('Please enter a feed name'); nameInput.focus(); return; }
    if (!url) { showFormError('Please enter a feed URL'); urlInput.focus(); return; }

    var row = editingRow;
    var pending;
    if (row) {
      // Send only what changed, as the old inline edits did.
      var changes = {};
      if (name !== row.dataset.name) changes.name = name;
      if (url !== row.dataset.url) changes.url = url;
      if (dialogTags.join('\n') !== rowTags(row).join('\n')) changes.type = dialogTags.slice();
      if (!Object.keys(changes).length) { dialog.close(); return; }
      pending = request(feedApi + '/' + row.dataset.index, { method: 'PUT', json: changes });
    } else {
      pending = request(feedApi, {
        method: 'POST',
        json: { name: name, url: url, type: dialogTags.length ? dialogTags.slice() : ['suspicious'] }
      });
    }

    showFormError('');
    submitBtn.disabled = true;
    pending.then(function (data) {
      if (data.error) throw new Error(data.error);
      if (!row) { reloadWith('Added feed "' + name + '".'); return; }
      updateRow(row, data.feed || { name: name, url: url, type: dialogTags });
      refreshTags();
      dialog.close();
      setStatus('Saved "' + row.dataset.name + '".');
    }).catch(function (err) {
      submitBtn.disabled = false;
      showFormError(err.message || 'Network error');
    });
  });

  // ---------- page-level clicks and delete ----------

  document.addEventListener('click', function (event) {
    if (event.target.closest('[data-feed-add]')) { openDialog(null); return; }
    var edit = event.target.closest('[data-feed-edit]');
    if (edit) { openDialog(edit.closest('tr')); return; }
    var test = event.target.closest('[data-feed-test-run]');
    if (test) testFeed(test.closest('tr'));
  });

  // Runs after app.js has asked the data-confirm question.
  document.addEventListener('submit', function (event) {
    var deleteForm = event.target;
    if (!deleteForm.matches || !deleteForm.matches('[data-feed-delete]')) return;
    if (event.defaultPrevented) return;   // the user said no
    event.preventDefault();
    var row = deleteForm.closest('tr');
    var button = deleteForm.querySelector('button');
    button.disabled = true;
    request(feedApi + '/' + row.dataset.index, { method: 'DELETE' }).then(function (data) {
      if (data.error) throw new Error(data.error);
      // Reload: the feeds after this one have moved up by one index.
      reloadWith('Deleted feed "' + (data.deleted || row.dataset.name) + '".');
    }).catch(function (err) {
      button.disabled = false;
      setStatus('Could not delete "' + row.dataset.name + '": ' + (err.message || 'Network error'), true);
    });
  });

  try {
    var flash = sessionStorage.getItem(FLASH_KEY);
    if (flash) {
      sessionStorage.removeItem(FLASH_KEY);
      setStatus(flash);
    }
  } catch (e) { /* storage unavailable */ }
})();

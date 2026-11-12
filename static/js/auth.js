// Sign-in, first-run setup and account pages: show/hide password, strength meter, Caps Lock hint.
(function () {
  'use strict';

  document.querySelectorAll('[data-host]').forEach(function (el) { el.textContent = window.location.host; });

  document.querySelectorAll('[data-show-password]').forEach(function (button) {
    var input = document.getElementById(button.dataset.showPassword);
    if (!input) return;
    button.addEventListener('click', function () {
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      button.textContent = show ? 'Hide' : 'Show';
      button.setAttribute('aria-pressed', String(show));
    });
  });

  // 0-4: length carries most of the score; character variety adds one step.
  function strength(value) {
    if (value.length < 8) return 0;
    var classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter(function (re) { return re.test(value); }).length;
    var score = 1 + (value.length >= 12 ? 1 : 0) + (value.length >= 16 ? 1 : 0) + (classes >= 3 ? 1 : 0);
    return Math.min(score, 4);
  }
  var LABELS = ['Too short', 'Weak', 'Fair', 'Good', 'Strong'];

  document.querySelectorAll('[data-meter-for]').forEach(function (meter) {
    var id = meter.dataset.meterFor;
    var input = document.getElementById(id);
    var label = document.querySelector('[data-meter-label="' + id + '"]');
    if (!input) return;
    var segments = meter.querySelectorAll('i');
    function update() {
      var value = input.value;
      var score = strength(value);
      segments.forEach(function (seg, n) { seg.classList.toggle('on', n < score); });
      if (!label) return;
      label.textContent = value
        ? LABELS[score] + ' · ' + value.length + ' characters. Minimum is 8.'
        : 'Minimum is 8 characters.';
    }
    input.addEventListener('input', update);
    update();
  });

  document.querySelectorAll('[data-caps-hint]').forEach(function (input) {
    var hint = document.getElementById(input.dataset.capsHint);
    if (!hint) return;
    function check(event) {
      if (event.getModifierState) hint.classList.toggle('hide', !event.getModifierState('CapsLock'));
    }
    input.addEventListener('keydown', check);
    input.addEventListener('keyup', check);
    input.addEventListener('blur', function () { hint.classList.add('hide'); });
  });
})();

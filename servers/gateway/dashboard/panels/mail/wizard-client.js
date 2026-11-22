/**
 * Crow Mail's setup-wizard client script (plan 5, Task 5): the actions behind the Gmail and Microsoft
 * cards the settings page draws (`wizard-html.js`). It does only what a plain link cannot:
 *
 *   App password. Connect posts the card's address and the 16-character password to
 *   `POST /dashboard/mail/api/accounts` as a password account naming the provider preset ("gmail").
 *   Every SPACE is stripped from the password first (Google shows it in groups of four), the field is
 *   emptied as the secret leaves the page, and the field is never written back: the paragraph the card
 *   carries (`data-ml-app-password-failed`, C8) is shown when the connect is refused. Nothing else is
 *   sent: no host, no port and no label — the server applies the preset's endpoints and Sent-copy rule,
 *   and the address is the account's label.
 *
 *   Sign in. Connect runs the wizard's own checks in order — the client id's shape, the redirect
 *   address this machine still mints, the scopes — each one a POST to `/oauth/check` whose fixed hint
 *   key picks the approved sentence (`client_id_shape` → C26, `redirect_mismatch` → C22,
 *   `no_dashboard_address` → C19). A passed check shows the card's tick with N1's approved sentence
 *   beside it (the whole element is hidden until then, so nothing is read before it is true). Only
 *   when the address is still the one the card shows does it POST `/oauth/start` and hand the browser
 *   to the `authUrl` the route answers: a sign-in belongs to the provider's page, so it is a plain
 *   navigation, never Turbo.
 *
 *   The tenant. The Microsoft card may carry one optional field (`data-ml-tenant`, labelled with N4's
 *   approved rows): a directory (tenant) GUID or a domain name travels as `tenant` with
 *   `/oauth/start`; an empty field sends no tenant at all, so the server keeps its own "common"; and
 *   any other value starts NOTHING — no check, no start — and shows N6's approved sentence in the
 *   tenant field's own line. A `400 bad_input` the start route answers for a tenant the page sent is
 *   the same refusal, so it lands in that same line rather than in the form's (the same rule
 *   `tenantFor()` applies server-side).
 *
 *   The card's address. On load, `GET /oauth/redirect-uri` is read once per card: an answer that
 *   differs from the address the page drew is written into it (textContent, never markup), and a page
 *   whose machine has since lost its dashboard address hides the sign-in path and shows C19 instead.
 *   Copy copies that same value and then says N2's approved sentence ("Copied."); a browser with no
 *   clipboard falls back to selecting the value, and then says nothing it did not do.
 *
 *   The test message. An account's `[data-ml-selftest]` posts `/accounts/:id/selftest` at the
 *   person's TAP and at no other time — nothing here runs it on load — and shows the card's own
 *   sentence for the outcome (C21's two).
 *
 * Every sentence comes from the page: the card carries each of them as a `data-ml-*` attribute, so
 * this script has no translated text of its own. Requests go only to the mail API's own owner routes,
 * always through the one `post()` helper, which sends the server-bound `x-crow-csrf` token from
 * `window.crowCsrf` (never a cookie). Nothing is built in JavaScript but nodes and text: no
 * `innerHTML`, no markup sink, and a secret is only ever read out of a `type=password` field, sent, and
 * cleared.
 *
 * Lifecycle: Turbo re-runs this script on every visit, so every listener is bound behind a marker on
 * the element it is bound to (the element is replaced with the page, so a fresh one binds again).
 *
 * Emitted inside a template literal: no backticks, no dollar-brace, no backslash that is not doubled.
 */

export function mailWizardClientJs(lang = "en") {
  // `lang` is here for the panel's uniform view signature: every word this script can show is a
  // data-ml-* attribute the server already translated.
  void lang;
  return `<script>
(function () {
  var root = document.querySelector('[data-ml]');
  if (!root) { return; }
  var cards = root.querySelectorAll('[data-ml-wizard]');
  if (!cards.length) { return; }

  var ACCOUNTS_PATH = '/dashboard/mail/api/accounts';
  var CHECK_PATH = '/dashboard/mail/api/oauth/check';
  var START_PATH = '/dashboard/mail/api/oauth/start';
  var REDIRECT_PATH = '/dashboard/mail/api/oauth/redirect-uri';

  function csrf() {
    try { return window.crowCsrf ? window.crowCsrf() : ''; } catch (e) { return ''; }
  }
  function request(method, url, body) {
    var options = { method: method, credentials: 'same-origin', headers: { 'x-crow-csrf': csrf() } };
    if (body !== undefined) {
      options.headers['content-type'] = 'application/json';
      options.body = JSON.stringify(body);
    }
    return fetch(url, options).then(function (response) {
      return response.json().then(function (json) {
        return { ok: response.ok, status: response.status, json: json };
      }, function () {
        return { ok: response.ok, status: response.status, json: null };
      });
    }, function () {
      return { ok: false, status: 0, json: null };
    });
  }
  function post(url, body) { return request('POST', url, body); }
  function get(url) { return request('GET', url); }

  function closestOf(node, selector) {
    if (node && typeof node.closest === 'function') { return node.closest(selector); }
    var found = node;
    while (found && found.getAttribute) {
      if (typeof found.matches === 'function' && found.matches(selector)) { return found; }
      found = found.parentNode;
    }
    return null;
  }
  function attr(node, name) {
    if (!node || typeof node.getAttribute !== 'function') { return ''; }
    var value = node.getAttribute(name);
    return value === null || value === undefined ? '' : String(value);
  }
  function field(scope, hook) {
    return scope ? scope.querySelector('[data-ml-' + hook + ']') : null;
  }
  function valueOf(input) {
    return input ? String(input.value || '') : '';
  }
  function clear(input) {
    if (input) { input.value = ''; }
  }
  function lineOf(scope) {
    var line = scope ? scope.querySelector('[data-ml-result]') : null;
    if (line) { return line; }
    if (!scope || typeof scope.appendChild !== 'function') { return null; }
    line = document.createElement('p');
    line.className = 'ml-note ml-wizard-check';
    line.setAttribute('role', 'status');
    line.setAttribute('data-ml-result', '');
    line.setAttribute('hidden', '');
    scope.appendChild(line);
    return line;
  }
  function tick(scope, shown) {
    var mark = scope ? scope.querySelector('[data-ml-check-tick]') : null;
    if (!mark) { return; }
    if (shown) { mark.removeAttribute('hidden'); }
    else { mark.setAttribute('hidden', ''); }
  }
  /* The Copy control's OWN tick: a copy is not a passed check, so it never lights the card's first
     tick (the one the app password Connect shows). */
  function copyTick(node, shown) {
    var mark = node ? node.querySelector('[data-ml-copy-tick]') : null;
    if (!mark) { return; }
    if (shown) { mark.removeAttribute('hidden'); }
    else { mark.setAttribute('hidden', ''); }
  }
  /* N2's approved sentence ("Copied."), the page's own text, shown after the control only once the
     value really was copied: a fallback that only selects the address says nothing. */
  function copiedSaid(node, shown) {
    var said = node ? node.querySelector('[data-ml-copied]') : null;
    if (!said) { return; }
    if (shown) { said.removeAttribute('hidden'); }
    else { said.setAttribute('hidden', ''); }
  }
  function showLine(line, text) {
    if (!line) { return; }
    var value = text === null || text === undefined ? '' : String(text);
    line.textContent = value;
    if (value === '') { line.setAttribute('hidden', ''); }
    else { line.removeAttribute('hidden'); }
  }
  function say(scope, text) {
    showLine(lineOf(scope), text);
  }
  function errorText(result) {
    var box = document.querySelector('[data-ml-errs]');
    var code = result && result.json && typeof result.json.error === 'string' && result.json.error !== ''
      ? result.json.error
      : 'network';
    if (!box) { return ''; }
    var text = box.getAttribute('data-ml-err-' + code.toLowerCase());
    if (!text) { text = box.getAttribute('data-ml-err-generic'); }
    return String(text || '');
  }
  function hintText(card, hint) {
    if (!card || typeof hint !== 'string' || hint === '') { return ''; }
    return attr(card, 'data-ml-hint-' + hint);
  }
  function busy(button, waiting) {
    if (!button) { return; }
    if (waiting) { button.setAttribute('disabled', ''); }
    else { button.removeAttribute('disabled'); }
  }

  function redirectUriOf(card) {
    var node = card ? card.querySelector('[data-ml-redirect-uri]') : null;
    return node ? String(node.textContent || '').trim() : '';
  }
  function writeRedirectUri(card, uri) {
    var node = card ? card.querySelector('[data-ml-redirect-uri]') : null;
    if (node) { node.textContent = String(uri || ''); }
  }
  function showNoAddress(card, unavailable) {
    // A page drawn WITH an address has no C19 block to fall back on, and this script may not invent
    // one: the sign-in path is left as it is and the Connect control reports the missing address in
    // its own line (C19) when it re-reads the route. The block exists only on a page drawn without
    // an address, where hiding the path and showing it are both this block's own halves.
    var block = card ? card.querySelector('[data-ml-no-address]') : null;
    if (!block) { return; }
    var paths = card ? card.querySelectorAll('[data-ml-oauth-path]') : [];
    for (var i = 0; i < paths.length; i++) {
      if (unavailable) { paths[i].setAttribute('hidden', ''); }
      else { paths[i].removeAttribute('hidden'); }
    }
    if (unavailable) { block.removeAttribute('hidden'); }
    else { block.setAttribute('hidden', ''); }
  }

  /* ------------------------------------------------------------- the app password */

  function connectAppPassword(card, form) {
    var addressInput = field(form, 'address');
    var passwordInput = field(form, 'password');
    var address = valueOf(addressInput).trim();
    // Google shows an app password in groups of four: the spaces are not part of it.
    var password = valueOf(passwordInput).replace(/\\s+/g, '');
    if (address === '' || password === '') { return; }
    // The secret leaves the page as it is sent, before any answer can arrive: it is never left sitting
    // in the field, and nothing is written back into it whatever the connect answers.
    clear(passwordInput);
    var button = form ? form.querySelector('[data-ml-connect-password-btn]') : null;
    busy(button, true);
    say(form, '');
    tick(form, false);
    post(ACCOUNTS_PATH, {
      authKind: 'password',
      provider: attr(card, 'data-ml-preset'),
      label: address,
      address: address,
      password: password
    }).then(function (result) {
      busy(button, false);
      if (!result.ok) {
        var refused = attr(card, 'data-ml-connect-failed');
        if (refused === '') { refused = errorText(result); }
        say(form, refused);
        return;
      }
      // Connected: the page reloads so the new account's own card (and its status word) is drawn.
      navigate(location.href);
    });
  }

  /* --------------------------------------------------------------- the tenant (N4) */

  /* Microsoft signs a work or school account in against ONE directory: a tenant (directory) GUID or a
     verified domain name. The field may be left empty, which means Microsoft's "common"; a value that
     is neither is refused HERE, before any request, with N6's sentence in the field's own line, and
     exactly as tenantFor() in mail/oauth/flow.js refuses it on the server. */
  var TENANT_GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  var TENANT_LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;
  function tenantAllowed(value) {
    var tenant = String(value === null || value === undefined ? '' : value);
    if (TENANT_GUID.test(tenant)) { return true; }
    if (tenant.length === 0 || tenant.length > 253) { return false; }
    var labels = tenant.split('.');
    if (labels.length < 2) { return false; }
    for (var i = 0; i < labels.length; i++) {
      if (!TENANT_LABEL.test(labels[i])) { return false; }
    }
    return true;
  }
  /* N6's approved sentence lives in the tenant field's own line (the page drew it there, hidden): a
     refused tenant is never reported in the form's shared line, and no sentence is invented here. */
  function tenantRefused(form, shown) {
    var line = field(form, 'tenant-invalid');
    if (!line) { return; }
    if (shown) { line.removeAttribute('hidden'); }
    else { line.setAttribute('hidden', ''); }
  }

  /* ---------------------------------------------------------------- the sign-in */

  function checkResult(card, step, body) {
    return post(CHECK_PATH, body).then(function (result) {
      if (!result.ok) { return { ok: false, text: errorText(result) }; }
      var json = result.json || {};
      if (json.ok === true) { return { ok: true, text: '' }; }
      var hint = hintText(card, json.hint);
      return { ok: false, text: hint === '' ? errorText(result) : hint };
    });
  }

  function connectOauth(card, form) {
    var provider = attr(card, 'data-ml-provider');
    var address = valueOf(field(form, 'address')).trim();
    var clientId = valueOf(field(form, 'client-id')).trim();
    var secretInput = field(form, 'client-secret');
    var clientSecret = valueOf(secretInput);
    // The tenant field exists on the Microsoft card only; anywhere else this is empty.
    var tenant = provider === 'microsoft' ? valueOf(field(form, 'tenant')).trim() : '';
    if (address === '' || clientId === '') { return; }
    // Nothing is sent for a tenant that cannot be one: N6's sentence says so in the field's own line,
    // and a sign-in against a value that is not a directory would only fail later.
    tenantRefused(form, false);
    if (tenant !== '' && !tenantAllowed(tenant)) {
      say(form, '');
      tick(form, false);
      tenantRefused(form, true);
      return;
    }
    var button = form ? form.querySelector('[data-ml-oauth-connect]') : null;
    busy(button, true);
    say(form, '');
    tick(form, false);

    checkResult(card, 'client_id', { step: 'client_id', provider: provider, clientId: clientId })
      .then(function (checked) {
        if (!checked.ok) { return checked; }
        return checkResult(card, 'redirect', {
          step: 'redirect',
          provider: provider,
          pastedRedirectUri: redirectUriOf(card)
        });
      })
      .then(function (checked) {
        if (!checked.ok) { return checked; }
        return checkResult(card, 'scopes', { step: 'scopes', provider: provider });
      })
      .then(function (checked) {
        if (!checked.ok) { return checked; }
        // The card's address must still be the one this machine mints: a dashboard address changed in
        // another tab would make the sign-in come back to a place this Crow no longer answers on.
        return get(REDIRECT_PATH).then(function (result) {
          var uri = result.ok && result.json && typeof result.json.redirectUri === 'string'
            ? result.json.redirectUri
            : null;
          if (uri === null) {
            showNoAddress(card, true);
            return { ok: false, text: hintText(card, 'no_dashboard_address') };
          }
          if (redirectUriOf(card) !== '' && redirectUriOf(card) !== uri) {
            writeRedirectUri(card, uri);
            return { ok: false, text: hintText(card, 'redirect_mismatch') };
          }
          writeRedirectUri(card, uri);
          return startFlow(card, { provider: provider, address: address, clientId: clientId, clientSecret: clientSecret, tenant: tenant }, form);
        });
      })
      .then(function (checked) {
        clear(secretInput);
        busy(button, false);
        tick(form, checked && checked.ok === true);
        say(form, checked && checked.ok ? '' : String((checked && checked.text) || ''));
      });
  }

  /**
   * The provider's own authorization page, as this script is willing to leave the dashboard for: the
   * URL must be https AND its host must be exactly the provider's sign-in host (the card's own
   * provider). Anything else — another origin, a look-alike suffix, a plain-http address, a URL with a
   * port or a userinfo part — is refused, and the caller shows the card's K3 sentence with nothing
   * navigated: an authorization URL a route answered is a value from the wire, and this is the one
   * place it would be followed.
   */
  var AUTH_HOSTS = { google: 'accounts.google.com', microsoft: 'login.microsoftonline.com' };
  function authUrlAllowed(provider, url) {
    if (typeof url !== 'string' || url.indexOf('https://') !== 0) { return false; }
    var expected = AUTH_HOSTS[provider];
    if (!expected) { return false; }
    var rest = url.slice('https://'.length);
    var cut = rest.length;
    var marks = ['/', '?', '#'];
    for (var i = 0; i < marks.length; i++) {
      var at = rest.indexOf(marks[i]);
      if (at !== -1 && at < cut) { cut = at; }
    }
    var host = rest.slice(0, cut).toLowerCase();
    return host === expected;
  }

  /** POST /oauth/start and hand the browser to the provider. Nothing is stored here. */
  function startFlow(card, fields, form) {
    var body = { provider: fields.provider, address: fields.address, label: fields.address, clientId: fields.clientId };
    if (fields.clientSecret !== '') { body.clientSecret = fields.clientSecret; }
    // Only a value the person typed travels: an empty tenant is the server's own default ("common").
    if (typeof fields.tenant === 'string' && fields.tenant !== '') { body.tenant = fields.tenant; }
    return beginFlow(card, body, form);
  }

  /** The one navigation both start paths take: build the URL server-side, check it, then leave. */
  function beginFlow(scope, body, form) {
    return post(START_PATH, body).then(function (result) {
      if (!result.ok) {
        // A tenant the page sent and the server refused (its own 400 bad_input) is the tenant
        // field's refusal: N6 in that field's line, never the server's code and never an invented
        // sentence. Any other refusal keeps its own line.
        if (form && typeof body.tenant === 'string' && body.tenant !== '' && result.status === 400
          && result.json && result.json.error === 'bad_input') {
          tenantRefused(form, true);
          return { ok: false, text: '' };
        }
        return { ok: false, text: errorText(result) };
      }
      var authUrl = result.json && typeof result.json.authUrl === 'string' ? result.json.authUrl : '';
      if (!authUrlAllowed(body.provider, authUrl)) {
        // Not the provider's own https page: nothing navigates, and the approved K3 sentence says so.
        return { ok: false, text: hintText(scope, 'flow_failed') };
      }
      // The provider's own page: a plain navigation, never a Turbo visit.
      if (location && typeof location.assign === 'function') { location.assign(authUrl); }
      return { ok: true, text: '' };
    });
  }

  /* ------------------------------------------------------------------- the copy */

  function copyUri(card, button) {
    var uri = redirectUriOf(card);
    if (uri === '') { return; }
    var step = closestOf(button, '[data-ml-copy-step]') || card;
    var done = function () { copyTick(step, true); copiedSaid(step, true); };
    var failed = function () {
      // No clipboard here: select the address so the person can copy it by hand.
      var node = card.querySelector('[data-ml-redirect-uri]');
      var selection = window.getSelection ? window.getSelection() : null;
      if (!node || !selection || typeof document.createRange !== 'function') { return; }
      var range = document.createRange();
      range.selectNodeContents(node);
      selection.removeAllRanges();
      selection.addRange(range);
    };
    if (navigator && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      navigator.clipboard.writeText(uri).then(done, failed);
      return;
    }
    failed();
  }

  /* ------------------------------------------------------------- the reconnect */

  /**
   * The account card's Reconnect (plan 5, Task 6): the same start route and the same host-checked
   * navigation as the wizard's Connect, with reconnectAccountId in place of a pasted registration.
   * The card names the account, its provider and the address it already has; the client id and the
   * client secret are read server-side from the sealed keychain, so neither is on this page and no
   * secret is ever sent from here.
   */
  function reconnect(button) {
    var banner = closestOf(button, '[data-ml-reconnect-banner]');
    var accountId = attr(button, 'data-account');
    var provider = attr(button, 'data-ml-reconnect-provider');
    var address = attr(button, 'data-ml-reconnect-address');
    if (accountId === '' || provider === '' || address === '') { return; }
    var line = banner ? banner.querySelector('[data-ml-reconnect-result]') : null;
    showLine(line, '');
    busy(button, true);
    beginFlow(banner, { reconnectAccountId: accountId, provider: provider, address: address, label: address })
      .then(function (checked) {
        busy(button, false);
        if (checked && checked.ok === true) { return; }
        showLine(line, String((checked && checked.text) || ''));
      });
  }

  /* --------------------------------------------------------------- the test mail */

  function sendTest(card, button) {
    var id = attr(button, 'data-account');
    if (id === '') { return; }
    busy(button, true);
    var scope = card || button.parentNode;
    post(ACCOUNTS_PATH + '/' + encodeURIComponent(id) + '/selftest', {}).then(function (result) {
      busy(button, false);
      var ok = result.ok && result.json && result.json.ok === true;
      say(scope, attr(button, ok ? 'data-ml-selftest-sent' : 'data-ml-selftest-failed'));
    });
  }

  /* ------------------------------------------------------------------- the wiring */

  function navigate(url) {
    var target = String(url || '');
    if (window.Turbo && typeof window.Turbo.visit === 'function') { window.Turbo.visit(target); return; }
    if (location && typeof location.reload === 'function') { location.reload(); }
  }

  function bindCard(card) {
    if (card.getAttribute('data-ml-bound') === 'wizard') { return; }
    card.setAttribute('data-ml-bound', 'wizard');

    var forms = card.querySelectorAll('[data-ml-connect-password]');
    for (var i = 0; i < forms.length; i++) {
      (function (form) {
        form.addEventListener('submit', function (event) {
          // Cancelled first, before a field is read: this form carries a secret and names no target.
          if (typeof event.preventDefault === 'function') { event.preventDefault(); }
          connectAppPassword(card, form);
        });
      })(forms[i]);
    }
    var oauthForms = card.querySelectorAll('[data-ml-oauth]');
    for (var j = 0; j < oauthForms.length; j++) {
      (function (form) {
        form.addEventListener('submit', function (event) {
          if (typeof event.preventDefault === 'function') { event.preventDefault(); }
          connectOauth(card, form);
        });
      })(oauthForms[j]);
    }
    // A dashboard address that moved since the page was drawn: write the current one into the card,
    // and hide a sign-in path this machine can no longer finish.
    if (card.querySelector('[data-ml-redirect-uri]')) {
      get(REDIRECT_PATH).then(function (result) {
        if (!result.ok) { return; }
        var uri = result.json && typeof result.json.redirectUri === 'string' ? result.json.redirectUri : null;
        if (uri === null) { showNoAddress(card, true); return; }
        writeRedirectUri(card, uri);
        showNoAddress(card, false);
      }, function () {});
    }
  }

  for (var i = 0; i < cards.length; i++) { bindCard(cards[i]); }

  if (!root.getAttribute('data-ml-wizard-bound')) {
    root.setAttribute('data-ml-wizard-bound', '1');
    root.addEventListener('click', function (event) {
      var target = event.target && event.target.closest ? event.target : null;
      if (!target) { return; }
      var copy = target.closest('[data-ml-copy-redirect]');
      if (copy) { copyUri(closestOf(copy, '[data-ml-wizard]'), copy); return; }
      var test = target.closest('[data-ml-selftest]');
      if (test) { sendTest(closestOf(test, '[data-ml-account]'), test); return; }
      var again = target.closest('[data-ml-reconnect]');
      if (again) { reconnect(again); return; }
    });
  }
})();
</script>`;
}

export default mailWizardClientJs;
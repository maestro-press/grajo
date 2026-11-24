/**
 * Schedule panel: the small client script (ES5, no backticks: it is embedded in a template
 * literal). Everything works without it; it adds the modal create sheet, the browser's zone,
 * the live preview (debounced 250 ms, words → read-back + next 3 runs), the toast, focus on an
 * opened detail, Escape to close it, and the wide pane's top offset. Runs on every Turbo render;
 * document-level listeners are bound once.
 */
export function scheduleClientJs() {
  return `<script>
(function () {
  var page = document.querySelector(".sc-page");
  if (!page) return;

  var toast = document.getElementById("sc-toast");
  if (toast && toast.getAttribute("data-sc-toast")) {
    setTimeout(function () { toast.textContent = toast.getAttribute("data-sc-toast"); }, 60);
    setTimeout(function () { toast.textContent = ""; }, 8000);
  }

  // Copy buttons (read-only sources' fixes): the text is already on the page; the button only
  // puts it on the clipboard, and says so in the toast. Hidden until this script runs.
  function say(msg) {
    if (!toast || !msg) return;
    toast.textContent = "";
    setTimeout(function () { toast.textContent = msg; }, 30);
    setTimeout(function () { toast.textContent = ""; }, 5000);
  }
  document.querySelectorAll("[data-sc-copy]").forEach(function (b) {
    b.hidden = false;
    b.addEventListener("click", function () {
      var text = b.getAttribute("data-sc-copy");
      var fallback = function () {
        var code = b.parentNode.querySelector(".sc-copy-text");
        try {
          var r = document.createRange(); r.selectNodeContents(code);
          var sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(r);
          say(b.getAttribute(document.execCommand("copy") ? "data-l-copied" : "data-l-failed"));
        } catch (e) { say(b.getAttribute("data-l-failed")); }
      };
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(function () { say(b.getAttribute("data-l-copied")); }, fallback);
      else fallback();
    });
  });

  // The browser's zone rides a sheet's form when it has none (stored only when it differs from the
  // instance's); the edit sheet arrives with the reminder's own zone, so an edit never re-anchors it.
  var zone = "";
  try { zone = Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch (e) {}
  document.querySelectorAll("[data-sc-tz]").forEach(function (i) { if (!i.value) i.value = zone; });

  var dlg = document.getElementById("sc-create");
  var edlg = document.getElementById("sc-edit");
  function focusFirst(d) {
    var af = d.querySelector("[autofocus]") || d.querySelector("[name=text]");
    if (af) af.focus();
  }
  function openSheet(d) {
    if (!d || typeof d.showModal !== "function") return false;
    if (!d.open) d.showModal();
    focusFirst(d);
    return true;
  }
  document.querySelectorAll(".sc-dialog").forEach(function (d) {
    d.querySelectorAll("[data-sc-dismiss]").forEach(function (b) { b.addEventListener("click", function () { d.close(); }); });
    if (d.hasAttribute("data-open-on-load")) openSheet(d);
  });
  document.querySelectorAll("[data-sc-new]").forEach(function (a) {
    a.addEventListener("click", function (e) { if (openSheet(dlg)) e.preventDefault(); });
  });
  // Edit: the same sheet as New schedule, filled in with the reminder's words and its schedule.
  document.querySelectorAll("[data-sc-edit]").forEach(function (a) {
    a.addEventListener("click", function (e) { if (openSheet(edlg)) e.preventDefault(); });
  });
  // EDIT ONLY: words the owner types into When win over the cron field, which is what the server's
  // edit rule saves (schedule-actions.editWhenFields). The edit sheet opens with the exact expression
  // in that field whenever describeCron cannot word the schedule, so a stale expression would
  // otherwise silently beat the words. New schedule keeps its own rule (an advanced cron wins).
  if (edlg) {
    var editWhen = edlg.querySelector("[name=when]"), editCron = edlg.querySelector("[name=cron]");
    if (editWhen && editCron) editWhen.addEventListener("input", function () { editCron.value = ""; });
  }

  // An opened detail takes focus (its heading; the delete confirm's text; an action's result).
  var opened = document.querySelector(".sc-dialog[data-open-on-load]");
  var target = document.getElementById("sc-confirm-text") || document.getElementById("sc-done") || document.getElementById("sc-detail-h");
  if (target && !opened) {
    var focusIt = function () { if (document.activeElement === document.body || !document.activeElement) { try { target.focus(); } catch (e) {} } };
    focusIt();
    if (document.readyState !== "complete") window.addEventListener("load", function () { setTimeout(focusIt, 0); }, { once: true });
    else setTimeout(focusIt, 0);
  } else if (!document.getElementById("sc-detail") && /^#sc-\\d+$/.test(location.hash)) {
    // Back from a closed detail: focus returns to its row.
    var row = document.querySelector(location.hash + " .sc-hit");
    if (row) setTimeout(function () { try { row.focus(); } catch (e) {} }, 0);
  }

  // Live preview: the same parser the server saves with, through the session-gated JSON route.
  // One per sheet (New schedule and Edit), each with its own form and read-back box. A sheet names
  // its own field rule with data-sc-preview-mode: the edit sheet sends "edit", so its live preview
  // resolves the fields with the same function as its Save and its no-JS Preview (a typed When wins).
  // A sheet without one is the create form, which keeps its own rule (a filled cron wins).
  function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined) n.textContent = text; return n; }
  document.querySelectorAll(".sc-dialog").forEach(function (sheet) {
    var form = sheet.querySelector("form");
    var box = sheet.querySelector(".sc-preview");
    if (!form || !box) return;
    var mode = sheet.getAttribute("data-sc-preview-mode") || "";
    var timer = null, seq = 0;
    function render(p) {
      while (box.firstChild) box.removeChild(box.firstChild);
      if (!p) { box.appendChild(el("p", "sc-muted", box.getAttribute("data-l-empty"))); return; }
      if (!p.ok) { var e = el("p", "sc-note sc-note-err", p.hint || ""); box.appendChild(e); return; }
      var s = el("p", "sc-preview-sum"); s.appendChild(el("b", "", p.summary)); box.appendChild(s);
      box.appendChild(el("p", "sc-muted", box.getAttribute("data-l-next")));
      var ol = el("ol", "sc-next");
      (p.next3 || []).forEach(function (x) { var li = el("li"); var tm = el("time", "", x.text); tm.setAttribute("datetime", x.iso); li.appendChild(tm); ol.appendChild(li); });
      box.appendChild(ol);
    }
    function preview() {
      var when = form.querySelector("[name=when]").value, cron = form.querySelector("[name=cron]").value;
      if (!when.trim() && !cron.trim()) { render(null); return; }
      // The form's own zone (the reminder's, on Edit), so the read-back matches what will be saved.
      var tzi = form.querySelector("[data-sc-tz]");
      var tz = tzi && tzi.value ? tzi.value : zone;
      var mine = ++seq;
      var u = "/dashboard/schedule/preview?when=" + encodeURIComponent(when) + "&cron=" + encodeURIComponent(cron) + "&tz=" + encodeURIComponent(tz) + "&lang=" + encodeURIComponent(box.getAttribute("data-lang") || "en") + (mode ? "&mode=" + encodeURIComponent(mode) : "");
      fetch(u, { credentials: "same-origin", headers: { Accept: "application/json" } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (p) { if (mine === seq && p) render(p); })
        .catch(function () {});
    }
    ["when", "cron"].forEach(function (n) {
      var i = form.querySelector("[name=" + n + "]");
      if (i) i.addEventListener("input", function () { clearTimeout(timer); timer = setTimeout(preview, 250); });
    });
  });

  // Escape closes an open detail (not while a sheet is open: the dialog handles its own Escape).
  if (!window.__scEscBound) {
    window.__scEscBound = true;
    document.addEventListener("keydown", function (e) {
      if (e.key !== "Escape") return;
      var open = document.querySelector(".sc-dialog[open]");
      if (open) return;
      var close = document.querySelector(".sc-detail [data-sc-close]");
      if (close) { e.preventDefault(); close.click(); }
    });
  }

  // Wide pane: pin its top to the strip's top while it is on screen.
  function pane() {
    var d = document.querySelector(".sc-page .sc-detail"), top0 = document.querySelector(".sc-page .sc-attn");
    if (!d || !top0 || window.innerWidth < 769) return;
    var top = Math.max(16, Math.round(top0.getBoundingClientRect().top));
    document.querySelector(".sc-page").style.setProperty("--sc-pane-top", top + "px");
  }
  pane();
  if (!window.__scPaneBound) {
    window.__scPaneBound = true;
    document.addEventListener("scroll", pane, true);
    window.addEventListener("resize", pane);
  }
})();
</script>`;
}

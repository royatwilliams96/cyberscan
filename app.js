"use strict";
(function () {
  // ---- config ----
  var CONTACT_URL = "https://www.royatwilliams.com/contact";
  var GRADE_COLORS = { A: "#008000", B: "#2e8b57", C: "#9a7d0a", D: "#c25e00", F: "#c00000" };
  var STATUS_WHITELIST = ["fail", "warn", "info", "pass"];
  var STATUS_ORDER = { fail: 0, warn: 1, info: 2, pass: 3 };
  var CATEGORY_ORDER = ["SSL / TLS", "HTTPS", "Security Headers", "Cookies", "Information Disclosure", "DNS / Email", "WordPress"];
  var REQUEST_TIMEOUT_MS = 25000;
  var MAX_INPUT = 253;

  // ---- safe DOM builder: every dynamic value goes through textContent, never innerHTML ----
  // `style` is only ever passed values built from the whitelisted GRADE_COLORS / fixed constants below.
  function el(tag, opts, children) {
    var n = document.createElement(tag);
    opts = opts || {};
    if (opts.cls) n.className = opts.cls;
    if (opts.text != null) n.textContent = opts.text;
    if (opts.style) n.setAttribute("style", opts.style);
    if (opts.href) n.setAttribute("href", opts.href);
    if (opts.attrs) { for (var k in opts.attrs) { if (Object.prototype.hasOwnProperty.call(opts.attrs, k)) n.setAttribute(k, opts.attrs[k]); } }
    if (children) { for (var i = 0; i < children.length; i++) { if (children[i]) n.appendChild(children[i]); } }
    return n;
  }
  function txt(s) { return document.createTextNode(String(s)); }
  function clampInt(v, lo, hi) { v = Math.floor(Number(v)); if (!isFinite(v)) v = lo; return Math.max(lo, Math.min(hi, v)); }
  function str(v, max) { return String(v == null ? "" : v).slice(0, max || 300); }
  function safeColor(hex) { return /^#[0-9a-fA-F]{3,8}$/.test(hex) ? hex : "#888888"; }

  var loadingTimer = null;

  function byId(id) { return document.getElementById(id); }

  function showErr(msg) {
    var slot = byId("err-slot");
    slot.textContent = "";
    slot.appendChild(el("div", { cls: "msg msg-err", text: "⚠ " + str(msg, 200) }));
  }

  function cycleLoadingText() {
    var msgs = [
      "Scanning… checking SSL certificate",
      "Inspecting HTTP security headers…",
      "Looking up DNS & email records…",
      "Fingerprinting platform…",
      "Compiling your report…"
    ];
    var i = 0;
    var t = byId("loading-text");
    clearInterval(loadingTimer);
    t.textContent = msgs[0];
    loadingTimer = setInterval(function () { i = (i + 1) % msgs.length; t.textContent = msgs[i]; }, 1600);
  }

  function failBack(msg) {
    clearInterval(loadingTimer);
    byId("loading").style.display = "none";
    byId("scan-panel").style.display = "block";
    showErr(msg);
  }

  function runScan() {
    var input = byId("url-input");
    var consent = byId("consent");
    byId("err-slot").textContent = "";

    var val = (input.value || "").trim();
    if (!val) { showErr("Enter a store URL to scan."); return; }
    if (val.length > MAX_INPUT) { showErr("That URL is too long."); return; }
    if (!consent.checked) { showErr("Please confirm you own or have permission to test this site."); return; }

    byId("scan-panel").style.display = "none";
    byId("results").style.display = "none";
    byId("loading").style.display = "block";
    cycleLoadingText();

    var controller = new AbortController();
    var timer = setTimeout(function () { controller.abort(); }, REQUEST_TIMEOUT_MS);

    fetch("/.netlify/functions/scan?url=" + encodeURIComponent(val), {
      signal: controller.signal,
      headers: { "Accept": "application/json" }
    })
      .then(function (r) {
        return r.text().then(function (body) {
          var data = null;
          try { data = JSON.parse(body); } catch (e) { throw new Error("The scanner returned an unexpected response."); }
          if (!r.ok) throw new Error((data && data.error) || "Scan failed.");
          return data;
        });
      })
      .then(renderResults)
      .catch(function (e) {
        failBack(e && e.name === "AbortError" ? "The scan timed out. Please try again." : (e && e.message) || "Something went wrong. Please try again.");
      })
      .then(function () { clearTimeout(timer); }, function () { clearTimeout(timer); });
  }

  function countPill(n, label, color) {
    var p = el("span", { cls: "count-pill", style: "color:" + safeColor(color) + ";" });
    p.appendChild(el("b", { text: String(clampInt(n, 0, 999)) }));
    p.appendChild(txt(label));
    return p;
  }

  function renderFinding(f) {
    if (!f || typeof f !== "object") return null;
    var status = STATUS_WHITELIST.indexOf(f.status) !== -1 ? f.status : "info";
    var box = el("div", { cls: "finding " + status });
    var head = el("div", { cls: "finding-head" });
    head.appendChild(el("span", { cls: "status-chip " + status, text: status }));
    head.appendChild(el("span", { cls: "finding-title", text: str(f.title, 200) }));
    box.appendChild(head);
    box.appendChild(el("div", { cls: "finding-detail", text: str(f.detail, 600) }));
    if (f.fix) {
      var fx = el("div", { cls: "finding-fix" });
      fx.appendChild(el("b", { text: "Fix: " }));
      fx.appendChild(txt(str(f.fix, 600)));
      box.appendChild(fx);
    }
    return box;
  }

  function renderResults(data) {
    clearInterval(loadingTimer);
    byId("loading").style.display = "none";

    // Treat the API response as untrusted: validate shape and whitelist every value.
    if (!data || typeof data !== "object" || !Array.isArray(data.findings)) {
      failBack("The scanner returned no readable results."); return;
    }

    var grade = /^[A-F]$/.test(data.grade) ? data.grade : "?";
    var gc = safeColor(GRADE_COLORS[grade] || "#888888");
    var score = clampInt(data.score, 0, 100);
    var label = str(data.label, 40).toUpperCase();
    var platform = str(data.platform, 40) || "Unknown";
    var target = str(data.target, MAX_INPUT);
    var counts = (data.counts && typeof data.counts === "object") ? data.counts : {};

    var frag = document.createDocumentFragment();

    // hero (colours come only from the whitelisted grade map)
    var hero = el("div", { cls: "score-hero" });
    hero.appendChild(el("div", { cls: "target-name", text: target }));
    hero.appendChild(el("div", { cls: "grade", style: "color:" + gc + ";", text: grade }));
    hero.appendChild(el("div", { cls: "grade-label", text: label + " · " + score + "/100" }));
    hero.appendChild(el("div", { cls: "platform-chip", text: "Platform: " + platform }));
    var cr = el("div", { cls: "count-row" });
    cr.appendChild(countPill(counts.fail, "Critical", "#c00000"));
    cr.appendChild(countPill(counts.warn, "Warnings", "#9a7d0a"));
    cr.appendChild(countPill(counts.pass, "Passed", "#008000"));
    hero.appendChild(cr);
    frag.appendChild(hero);

    // Save-as-PDF toolbar (hidden when printing). Uses the browser's native
    // print/save dialog — no popup, no injected script, so the strict CSP is unaffected.
    var actions = el("div", { cls: "report-actions" });
    var pdfBtn = el("button", { cls: "save-pdf", text: "💾  Save as PDF", attrs: { type: "button" } });
    pdfBtn.addEventListener("click", function () { window.print(); });
    actions.appendChild(pdfBtn);
    frag.appendChild(actions);

    // disclaimer (static)
    var disc = el("div", { cls: "disclaimer" });
    disc.appendChild(el("p", {}, [
      el("strong", { text: "Disclaimer: " }),
      txt("This is an automated snapshot of publicly visible configuration only. It is not a full penetration test and does not guarantee your store is secure. No results are stored or transmitted to third parties.")
    ]));
    frag.appendChild(disc);

    // group + order findings
    var cats = {};
    data.findings.forEach(function (f) {
      if (!f || typeof f !== "object") return;
      var cat = str(f.category, 60) || "Other";
      (cats[cat] = cats[cat] || []).push(f);
    });
    Object.keys(cats).forEach(function (k) {
      cats[k].sort(function (a, b) {
        var oa = STATUS_ORDER[a.status]; var ob = STATUS_ORDER[b.status];
        return (oa == null ? 9 : oa) - (ob == null ? 9 : ob);
      });
    });
    var ordered = Object.keys(cats).sort(function (a, b) {
      var ia = CATEGORY_ORDER.indexOf(a), ib = CATEGORY_ORDER.indexOf(b);
      return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
    });
    ordered.forEach(function (cat) {
      var group = el("div", { cls: "cat-group" });
      group.appendChild(el("div", { cls: "cat-title", text: cat }));
      cats[cat].forEach(function (f) { var node = renderFinding(f); if (node) group.appendChild(node); });
      frag.appendChild(group);
    });

    // CTA (fixed href only)
    var cta = el("div", { cls: "cta" });
    cta.appendChild(el("h3", { text: "Want these issues fixed for you?" }));
    cta.appendChild(el("p", { text: "Get expert help hardening your store and closing every gap above." }));
    cta.appendChild(el("a", { text: "Contact Us →", href: CONTACT_URL, attrs: { target: "_blank", rel: "noopener noreferrer" } }));
    frag.appendChild(cta);

    var rescan = el("button", { cls: "rescan", text: "← Scan another store", attrs: { type: "button" } });
    rescan.addEventListener("click", resetScan);
    frag.appendChild(rescan);

    var d = new Date(data.scannedAt);
    var dateStr = isNaN(d.getTime()) ? "" : d.toLocaleString("en-GB", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
    frag.appendChild(el("p", { cls: "footer-note", text: "CyberScan · " + (dateStr ? "Scanned " + dateStr + " · " : "") + "All checks read-only" }));

    var res = byId("results");
    res.textContent = "";
    res.appendChild(frag);
    res.style.display = "block";
    window.scrollTo(0, 0);
  }

  function resetScan() {
    byId("results").style.display = "none";
    byId("scan-panel").style.display = "block";
    byId("url-input").value = "";
    byId("consent").checked = false;
    byId("err-slot").textContent = "";
    window.scrollTo(0, 0);
  }

  // ---- wire up (no inline handlers, so a strict CSP can block all inline script) ----
  document.addEventListener("DOMContentLoaded", function () {
    byId("scan-btn").addEventListener("click", runScan);
    byId("url-input").addEventListener("keydown", function (e) { if (e.key === "Enter") runScan(); });
  });
})();

// CyberScan — store security health check (serverless function)
// Uses only Node built-in modules: no npm install required.
// Runs real checks: TLS certificate, HTTP security headers, HTTPS enforcement,
// DNS/email records (SPF, DMARC, MX), platform fingerprint, cookie flags.

const https = require("https");
const http = require("http");
const tls = require("tls");
const dns = require("dns").promises;
const { URL } = require("url");

const UA = "CyberScan/1.0 (+security health check)";
const TIMEOUT = 4000; // keep each check short so the whole scan finishes within Netlify's 10s limit

// ---------- safety: refuse private / internal targets (anti-SSRF) ----------
function isPrivateIP(ip) {
  if (!ip) return true;
  if (ip === "::1") return true;
  const p = ip.split(".").map(Number);
  if (p.length === 4 && p.every((n) => !isNaN(n))) {
    if (p[0] === 10) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 127) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    if (p[0] === 0) return true;
  }
  const low = ip.toLowerCase();
  if (low.startsWith("fc") || low.startsWith("fd") || low.startsWith("fe80")) return true;
  return false;
}

// ---------- HTTP fetch with redirect following ----------
function fetchUrl(targetUrl, maxRedirects = 5) {
  return new Promise((resolve) => {
    const chain = [];
    const visit = (urlStr, left) => {
      let u;
      try { u = new URL(urlStr); } catch { return resolve({ ok: false, error: "Invalid URL", chain }); }
      const lib = u.protocol === "http:" ? http : https;
      const req = lib.request(
        u,
        { method: "GET", timeout: TIMEOUT, headers: { "User-Agent": UA, "Accept": "text/html,*/*" }, rejectUnauthorized: false },
        (res) => {
          const status = res.statusCode;
          chain.push({ url: urlStr, status, protocol: u.protocol });
          if ([301, 302, 303, 307, 308].includes(status) && res.headers.location && left > 0) {
            res.resume();
            let next;
            try { next = new URL(res.headers.location, u).toString(); } catch { next = null; }
            if (next) return visit(next, left - 1);
          }
          let body = "", size = 0;
          res.on("data", (c) => { size += c.length; if (size <= 250000) body += c.toString("utf8"); });
          res.on("end", () => resolve({ ok: true, status, headers: res.headers, body, finalUrl: urlStr, chain }));
        }
      );
      req.on("error", (e) => resolve({ ok: false, error: e.message, chain }));
      req.on("timeout", () => { req.destroy(); resolve({ ok: false, error: "Request timed out", chain }); });
      req.end();
    };
    visit(targetUrl, maxRedirects);
  });
}

// ---------- TLS certificate inspection ----------
function checkSSL(host) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (r) => { if (!settled) { settled = true; resolve(r); } };
    try {
      const socket = tls.connect(
        { host, port: 443, servername: host, timeout: TIMEOUT, rejectUnauthorized: false },
        () => {
          const cert = socket.getPeerCertificate();
          const authorized = socket.authorized;
          const authError = socket.authorizationError;
          socket.end();
          if (!cert || Object.keys(cert).length === 0) return done({ ok: false, error: "No certificate returned" });
          const validTo = new Date(cert.valid_to);
          const daysLeft = Math.floor((validTo - new Date()) / 86400000);
          done({
            ok: true, daysLeft,
            validTo: cert.valid_to, validFrom: cert.valid_from,
            issuer: (cert.issuer && (cert.issuer.O || cert.issuer.CN)) || "Unknown",
            subject: (cert.subject && cert.subject.CN) || host,
            authorized, authError: authError || null,
          });
        }
      );
      socket.on("error", (e) => done({ ok: false, error: e.message }));
      socket.on("timeout", () => { socket.destroy(); done({ ok: false, error: "Connection timed out" }); });
    } catch (e) { done({ ok: false, error: e.message }); }
  });
}

// ---------- DNS / email records ----------
async function checkDNS(domain) {
  const out = {};
  const safe = async (fn) => { try { return await fn(); } catch { return null; } };
  out.a = (await safe(() => dns.resolve4(domain))) || [];
  out.mx = (await safe(() => dns.resolveMx(domain))) || [];
  out.ns = (await safe(() => dns.resolveNs(domain))) || [];
  out.caa = (await safe(() => dns.resolveCaa(domain))) || [];
  const txt = (await safe(() => dns.resolveTxt(domain))) || [];
  const flat = txt.map((r) => r.join(""));
  out.txt = flat;
  out.spf = flat.find((t) => /v=spf1/i.test(t)) || null;
  const dmarcTxt = (await safe(() => dns.resolveTxt("_dmarc." + domain))) || [];
  out.dmarc = dmarcTxt.map((r) => r.join("")).find((t) => /v=DMARC1/i.test(t)) || null;
  return out;
}

// ---------- platform fingerprint ----------
function detectPlatform(headers, body) {
  const h = JSON.stringify(headers || {}).toLowerCase();
  const b = (body || "").toLowerCase();
  if (headers["x-shopify-stage"] || h.includes("shopify") || b.includes("cdn.shopify.com")) return "Shopify";
  if (headers["x-wix-request-id"] || h.includes("x-wix") || b.includes("static.wixstatic.com") || b.includes("wix.com")) return "Wix";
  if (b.includes("/wp-content/") || b.includes("/wp-json") || b.includes("wp-includes") ||
      (headers["link"] && String(headers["link"]).includes("wp-json"))) return "WordPress";
  return "Unknown / Custom";
}

// ---------- finding helpers ----------
function F(category, title, status, severity, detail, fix) {
  return { category, title, status, severity, detail, fix: fix || null };
}

// ---------- scoring ----------
function scoreFrom(findings) {
  let score = 100;
  const wFail = { high: 18, medium: 10, low: 5 };
  const wWarn = { high: 9, medium: 5, low: 2 };
  for (const f of findings) {
    if (f.status === "fail") score -= wFail[f.severity] || 8;
    else if (f.status === "warn") score -= wWarn[f.severity] || 4;
  }
  return Math.max(0, Math.min(100, Math.round(score)));
}
function gradeFor(score) {
  if (score >= 85) return { grade: "A", label: "Excellent" };
  if (score >= 70) return { grade: "B", label: "Good" };
  if (score >= 55) return { grade: "C", label: "Fair" };
  if (score >= 35) return { grade: "D", label: "Poor" };
  return { grade: "F", label: "Critical" };
}

// ---------- main handler ----------
exports.handler = async (event) => {
  // Lock this down after deploy: set ALLOWED_ORIGIN to your site URL
  // (e.g. https://cyberscan.netlify.app) so only your own page can call the function.
  const cors = {
    "Access-Control-Allow-Origin": process.env.ALLOWED_ORIGIN || "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Content-Type": "application/json",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
  };
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers: cors, body: "" };

  const raw = (event.queryStringParameters && event.queryStringParameters.url || "").trim();
  if (!raw) return { statusCode: 400, headers: cors, body: JSON.stringify({ error: "Missing 'url' parameter." }) };

  // normalise input -> https URL + hostname
  let host, origin;
  try {
    const withScheme = /^https?:\/\//i.test(raw) ? raw : "https://" + raw;
    const u = new URL(withScheme);
    host = u.hostname;
    origin = "https://" + host;
  } catch {
    return { statusCode: 400, headers: cors, body: JSON.stringify({ error: "That doesn't look like a valid domain." }) };
  }

  // anti-SSRF: resolve and reject private/internal targets
  try {
    const addrs = await dns.resolve4(host).catch(() => []);
    if (host === "localhost" || addrs.some(isPrivateIP) || isPrivateIP(host)) {
      return { statusCode: 400, headers: cors, body: JSON.stringify({ error: "Only public websites can be scanned." }) };
    }
    if (addrs.length === 0) {
      // maybe IPv6-only or unresolvable; try a quick AAAA
      const v6 = await dns.resolve6(host).catch(() => []);
      if (v6.length === 0) {
        return { statusCode: 400, headers: cors, body: JSON.stringify({ error: "Could not resolve that domain. Check the spelling." }) };
      }
    }
  } catch {
    return { statusCode: 400, headers: cors, body: JSON.stringify({ error: "Could not resolve that domain." }) };
  }

  // run checks in parallel
  const [ssl, dnsRec, httpsRes, httpRes] = await Promise.all([
    checkSSL(host),
    checkDNS(host),
    fetchUrl(origin),
    fetchUrl("http://" + host, 0),
  ]);

  const findings = [];
  const headers = (httpsRes.ok && httpsRes.headers) || {};
  const body = (httpsRes.ok && httpsRes.body) || "";
  const platform = detectPlatform(headers, body);

  // --- SSL / TLS ---
  if (ssl.ok) {
    if (ssl.authError && ssl.authError !== "CERT_HAS_EXPIRED") {
      findings.push(F("SSL / TLS", "Certificate not trusted", "fail", "high",
        "The certificate did not validate (" + ssl.authError + "). Browsers may show a security warning.",
        "Reissue a valid certificate from a trusted CA (e.g. Let's Encrypt) and ensure the full chain is installed."));
    }
    if (ssl.daysLeft < 0) {
      findings.push(F("SSL / TLS", "SSL certificate expired", "fail", "high",
        "The certificate expired " + Math.abs(ssl.daysLeft) + " day(s) ago. Visitors will see a browser warning.",
        "Renew the certificate immediately. Most hosts auto-renew — check the renewal settings."));
    } else if (ssl.daysLeft <= 14) {
      findings.push(F("SSL / TLS", "SSL certificate expiring soon", "warn", "medium",
        "The certificate expires in " + ssl.daysLeft + " day(s) (issued by " + ssl.issuer + ").",
        "Renew now or confirm auto-renewal is enabled to avoid downtime."));
    } else {
      findings.push(F("SSL / TLS", "Valid SSL certificate", "pass", "low",
        "Certificate is valid for " + ssl.daysLeft + " more day(s), issued by " + ssl.issuer + ".", null));
    }
  } else {
    findings.push(F("SSL / TLS", "No working HTTPS / SSL", "fail", "high",
      "Could not establish a secure connection: " + ssl.error + ".",
      "Install a valid SSL certificate. Traffic without HTTPS is unencrypted and flagged by browsers."));
  }

  // --- HTTPS enforcement ---
  if (httpRes.ok) {
    const endedHttps = (httpRes.finalUrl || "").startsWith("https") ||
      (httpRes.chain || []).some((c) => c.protocol === "https:");
    const redirected = (httpRes.chain || []).some((c) => c.status >= 300 && c.status < 400) || endedHttps;
    if (endedHttps && redirected) {
      findings.push(F("HTTPS", "HTTP redirects to HTTPS", "pass", "low",
        "Insecure http:// requests are redirected to the secure https:// version.", null));
    } else {
      findings.push(F("HTTPS", "HTTP not forced to HTTPS", "warn", "medium",
        "The site is reachable over plain http:// without redirecting to https://.",
        "Add a permanent redirect from http:// to https:// at the host or CDN level."));
    }
  }

  // --- security headers ---
  const wanted = [
    ["strict-transport-security", "HSTS (Strict-Transport-Security)", "high",
      "Forces browsers to always use HTTPS, preventing downgrade and cookie-hijacking attacks.",
      "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"],
    ["content-security-policy", "Content-Security-Policy", "medium",
      "Limits which scripts/resources can load, a strong defence against cross-site scripting (XSS).",
      "Define a Content-Security-Policy suited to your store's scripts and payment providers."],
    ["x-frame-options", "X-Frame-Options / frame-ancestors", "medium",
      "Stops your store being embedded in a hidden frame for click-jacking.",
      "Add: X-Frame-Options: SAMEORIGIN (or a frame-ancestors CSP directive)."],
    ["x-content-type-options", "X-Content-Type-Options", "low",
      "Prevents browsers from MIME-sniffing responses into an unintended content type.",
      "Add: X-Content-Type-Options: nosniff"],
    ["referrer-policy", "Referrer-Policy", "low",
      "Controls how much referrer information leaks to third parties.",
      "Add: Referrer-Policy: strict-origin-when-cross-origin"],
    ["permissions-policy", "Permissions-Policy", "low",
      "Restricts access to browser features like camera, mic and geolocation.",
      "Add a Permissions-Policy header disabling features you don't use."],
  ];
  if (httpsRes.ok) {
    // CSP can appear as frame-ancestors covering X-Frame-Options; keep simple per-header
    for (const [key, title, sev, detail, fix] of wanted) {
      if (headers[key]) {
        findings.push(F("Security Headers", title + " present", "pass", "low", detail, null));
      } else {
        findings.push(F("Security Headers", "Missing " + title, "warn", sev, detail, fix));
      }
    }
    // server / tech version disclosure
    const leak = [];
    if (headers["server"] && /\d/.test(headers["server"])) leak.push("Server: " + headers["server"]);
    if (headers["x-powered-by"]) leak.push("X-Powered-By: " + headers["x-powered-by"]);
    if (leak.length) {
      findings.push(F("Information Disclosure", "Software version exposed", "warn", "low",
        "Response headers reveal software details (" + leak.join("; ") + ") that help attackers target known bugs.",
        "Suppress or genericise the Server / X-Powered-By headers at your host or CDN."));
    }
    // cookie flags
    const setCookie = headers["set-cookie"];
    if (setCookie && setCookie.length) {
      const joined = Array.isArray(setCookie) ? setCookie.join(" | ") : String(setCookie);
      const insecure = /httponly/i.test(joined) === false || /secure/i.test(joined) === false;
      if (insecure) {
        findings.push(F("Cookies", "Cookies missing Secure / HttpOnly", "warn", "medium",
          "One or more cookies are set without the Secure and/or HttpOnly flags, making them easier to steal.",
          "Set Secure and HttpOnly on session cookies; add SameSite=Lax or Strict where possible."));
      } else {
        findings.push(F("Cookies", "Cookie flags look good", "pass", "low",
          "Cookies include Secure and HttpOnly flags.", null));
      }
    }
  }

  // --- DNS / email ---
  if (dnsRec.mx.length > 0) {
    if (dnsRec.spf) {
      findings.push(F("DNS / Email", "SPF record present", "pass", "low",
        "An SPF record is published, helping prevent email spoofing from your domain.", null));
    } else {
      findings.push(F("DNS / Email", "No SPF record", "fail", "medium",
        "Your domain sends/receives email (MX records exist) but has no SPF record, so anyone can spoof your address.",
        "Publish an SPF TXT record listing your authorised mail servers."));
    }
    if (dnsRec.dmarc) {
      findings.push(F("DNS / Email", "DMARC record present", "pass", "low",
        "A DMARC policy is published, instructing receivers how to handle spoofed mail.", null));
    } else {
      findings.push(F("DNS / Email", "No DMARC record", "fail", "medium",
        "No DMARC policy found. Spoofed emails claiming to be from your domain won't be rejected.",
        "Publish a _dmarc TXT record (start with p=none to monitor, then move to quarantine/reject)."));
    }
  } else {
    findings.push(F("DNS / Email", "No mail (MX) records", "info", "low",
      "No mail servers are configured for this domain. If you don't send email from it, that's fine — " +
      "but consider a strict SPF/DMARC anyway to stop spoofing.", null));
  }
  if (dnsRec.caa.length === 0) {
    findings.push(F("DNS / Email", "No CAA record", "warn", "low",
      "No CAA record found. CAA restricts which certificate authorities may issue certificates for your domain.",
      "Add a CAA record naming your CA (e.g. letsencrypt.org) to reduce mis-issuance risk."));
  } else {
    findings.push(F("DNS / Email", "CAA record present", "pass", "low",
      "A CAA record restricts certificate issuance to authorised CAs.", null));
  }

  // --- WordPress-specific light checks (read-only, public endpoints) ---
  if (platform === "WordPress") {
    const [users, xmlrpc] = await Promise.all([
      fetchUrl(origin.replace(/\/$/, "") + "/wp-json/wp/v2/users", 2),
      fetchUrl(origin.replace(/\/$/, "") + "/xmlrpc.php", 1),
    ]);
    if (users.ok && users.status === 200 && /\[\s*{/.test(users.body || "")) {
      findings.push(F("WordPress", "User list publicly exposed", "warn", "medium",
        "The WordPress REST API is returning your author/user accounts publicly, which hands attackers valid usernames for login attacks.",
        "Restrict the /wp-json/wp/v2/users endpoint or block user enumeration via a security plugin."));
    }
    if (xmlrpc.ok && xmlrpc.status !== 404 && xmlrpc.status !== 403) {
      findings.push(F("WordPress", "xmlrpc.php reachable", "warn", "low",
        "xmlrpc.php is enabled and can be abused for brute-force amplification and pingback attacks.",
        "Disable XML-RPC if unused, or block it at the server/CDN level."));
    }
  }

  const score = scoreFrom(findings);
  const { grade, label } = gradeFor(score);

  const counts = findings.reduce((a, f) => { a[f.status] = (a[f.status] || 0) + 1; return a; }, {});

  return {
    statusCode: 200,
    headers: cors,
    body: JSON.stringify({
      target: host,
      scannedAt: new Date().toISOString(),
      platform,
      score,
      grade,
      label,
      counts,
      findings,
    }),
  };
};

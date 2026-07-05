# CyberScan — Store Security Health Check

A lightweight scanner that checks Shopify / Wix / WordPress stores for common
security issues and gives the owner an instant grade plus a plain-English
fix-list. Styled as a nostalgic Windows-2000 dialog so non-technical store
owners feel at home.

## What it checks
- **SSL / TLS** — certificate validity, expiry, issuer, trust
- **HTTPS** — whether http:// is forced to https://
- **Security headers** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **Cookies** — Secure / HttpOnly flags
- **Information disclosure** — leaked server / software versions
- **DNS & email** — SPF, DMARC, MX, CAA records
- **Platform detection** — Shopify / Wix / WordPress
- **WordPress extras** — public user enumeration, xmlrpc.php exposure

All checks are **read-only** and use only publicly visible information.

## Why it needs a backend
SSL inspection, cross-site header reads, and DNS lookups are impossible from a
browser (CORS + no TLS/DNS APIs). The actual scanning runs in a Netlify
serverless function; the page just calls it. The function uses **only Node
built-in modules**, so there's nothing to `npm install`. The frontend uses only
system fonts, so it makes **zero third-party requests**.

## Folder structure
```
cyberscan/
├── index.html                    ← the scanner page (HTML + retro CSS)
├── app.js                        ← frontend logic (loaded by index.html)
├── netlify.toml                  ← Netlify config + security headers
├── netlify/
│   └── functions/
│       └── scan.js               ← the scanner (backend, no dependencies)
└── README.md
```

## Deploy to Netlify (≈5 min)

> ⚠️ **Use the CLI or Git — not drag-and-drop.** Netlify's drag-and-drop
> deploy often fails to bundle serverless functions, which makes every scan
> return "unexpected response." The two methods below deploy the function reliably.

**Option A — Netlify CLI (fastest):**
```
npm install -g netlify-cli
cd cyberscan
netlify deploy --prod
```
Follow the prompts to create/link a site. The CLI reads `netlify.toml`,
bundles the function, and publishes the page.

**Option B — Git:**
1. Push this `cyberscan/` folder to a GitHub/GitLab repo.
2. In Netlify: **Add new site → Import an existing project** → pick the repo.
3. `netlify.toml` handles the rest. Deploy.

**After deploying, confirm the function is live:**
- In the dashboard, open **Site → Functions** — you should see `scan` listed.
- Or visit `https://<your-site>.netlify.app/.netlify/functions/scan?url=example.com`
  directly — it should return JSON, not a 404 page.

## Recommended: lock the function to your own site
By default the function accepts calls from anywhere (`*`). After your first
deploy, stop other websites from using your scanner on your dime:

1. In Netlify → **Site settings → Environment variables**, add:
   `ALLOWED_ORIGIN = https://your-site.netlify.app` (your real URL)
2. Redeploy. The function will now only answer requests from your own page.

## Customising
- **Contact link:** edit the `CONTACT_URL` constant at the top of `app.js`
  (currently `https://www.royatwilliams.com/contact`).
- **Questions / checks:** add or adjust findings in `scan.js`.
- **Colours / theme:** all styling lives in the `<style>` block of `index.html`.

## Security notes (built in)
- **No inline scripts or handlers.** All JS is in `app.js`; a strict
  Content-Security-Policy (`script-src 'self'`) blocks inline execution.
- **XSS-safe rendering.** Results are built with `document.createElement` +
  `textContent` — no `innerHTML` — so nothing from a scanned site can be
  parsed as HTML.
- **Untrusted API response.** The frontend validates and whitelists every
  field it displays (grade, status, score, colours).
- **Anti-SSRF.** The function refuses localhost and private/internal IPs, so it
  can't be abused to probe internal networks.
- **The site serves its own security headers** (HSTS, X-Frame-Options, nosniff,
  Referrer-Policy, Permissions-Policy, CSP) via `netlify.toml` — so it passes
  the same checks it runs on others.
- **Nothing is stored.** Each scan runs on demand and renders once in the browser.
- **Consent gate.** Users must confirm they own / may test the site before scanning.

## Limitations
- This is an automated snapshot of publicly visible configuration, **not** a full
  penetration test. It won't find application-logic flaws, injection bugs, or
  anything behind authentication.
- Very slow sites may hit the function's timeout; the page reports this cleanly.

## Optional future upgrades
- Add a lightweight rate limit if the tool gets popular.
- Add DNSSEC validation and TLS-version / cipher grading for a deeper report.
- Add an email-capture step so free scans feed your consulting pipeline.
# cyberscan

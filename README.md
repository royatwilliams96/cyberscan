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

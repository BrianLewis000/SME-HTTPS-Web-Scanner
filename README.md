# SME Header Auditor

Chrome extension + local backend to (1) check the 6 headers on any site you
browse, and (2) log qualifying sites straight into your research dataset.

## 1. Backend setup

```bash
pip install flask flask-cors --break-system-packages
```

Edit `server.py` and set `DB_PATH` to your actual dataset `.db` file
(so it writes into the same table you're already building, not a new one).
If your existing table has a different name/columns than `sites`
(business_name, url, sector, category, established_year, source,
date_added, notes), either rename the table in your DB to `sites` or edit
the SQL in `init_db()` / `add_site()` to match your real schema. (City/state
aren't tracked, since the sample is pan-India rather than region-stratified.)

If you're running this against a database you already started collecting
data in before this version, `init_db()` will add the new
`established_year` column to your existing `sites` table automatically the
next time you start the server — existing rows just get `NULL` for that
column until you go back and fill them in.

Run it:
```bash
python server.py
```
Leave this running in a terminal while you browse — the extension talks to
it on `localhost:5000`.

## 2. Load the extension in Chrome

1. Go to `chrome://extensions`
2. Turn on "Developer mode" (top right)
3. Click "Load unpacked"
4. Select this folder (`sme-extension/`)

## 3. Use it

1. Visit any SME site
2. Click the extension icon
3. You'll see pass/fail/weak on the 6 headers and a 0–1 quality-graded
   score with A–F tier
4. Business name, sector, category, and year established are best-effort
   auto-filled from page metadata and page text — all fields stay editable,
   so correct anything wrong before saving. Many small sites won't have
   enough metadata to auto-fill cleanly; that's expected, just fill in
   manually
5. **Year established is required** — the "Add to dataset" button will
   refuse to save without a plausible 4-digit year. Auto-fill looks for
   two kinds of signal, in this order:
   - explicit wording ("Established 1998", "Founded in 2005", "Since 2012")
     — treated as reliable
   - failing that, the earliest year in a copyright notice ("© 1998–2024")
     — treated as a weaker proxy and flagged in the popup (orange field +
     a note) so you check it before saving, since a copyright year can
     reflect a site relaunch rather than the business's actual founding
6. If it's a site you want in your dataset, click "Add to dataset" — it
   checks for duplicates first via the URL UNIQUE constraint

## Scoring methodology

Each header contributes a different amount to the overall score
(severity-tiered weight), and within that weight, it earns credit based on
**how well it's actually configured** — not just whether it exists. This
is what makes the score reflect real effectiveness rather than surface-level
compliance.

**Step 1 — severity weight** (sum to 1.0):

| Header | Weight | Attack class mitigated | Severity rationale |
|---|---|---|---|
| Content-Security-Policy | 0.25 | Cross-site scripting (XSS), data injection | Highest-prevalence, highest-impact web vulnerability class (OWASP Top 10) |
| Strict-Transport-Security | 0.20 | MITM / SSL-stripping / downgrade attacks | Compromises confidentiality and integrity of the entire connection |
| X-Frame-Options | 0.15 | Clickjacking | Real but narrower attack surface than XSS/MITM |
| Referrer-Policy | 0.15 | Sensitive-data leakage via URLs | Information disclosure, not code execution |
| Permissions-Policy | 0.15 | Unauthorized hardware/feature access | Situational impact, depends on what features a page actually uses |
| X-Content-Type-Options | 0.10 | MIME-sniffing / content-type confusion | Older, narrower attack class; largely mitigated in modern browsers by default |

**Step 2 — quality credit per header** (checked in `popup.js` / mirrored
in `server.py`):

| Status | Credit | Meaning |
|---|---|---|
| ✓ pass | 1.0 (full weight) | Present and well-configured (e.g. CSP with no `unsafe-inline`/wildcard, HSTS with `max-age` ≥ 6 months) |
| ⚠ weak | 0.5 (half weight) | Present but misconfigured in a way that undermines its protection (e.g. CSP with `unsafe-inline`, a leaky Referrer-Policy) |
| ✗ fail | 0.0 (no credit) | Header absent entirely |

**Final score:**
```
score = Σ (weight_i × credit_i)  for each of the 6 headers
```
This means a site with all 6 headers present but half of them
misconfigured will score noticeably lower than a site with all 6 present
and well-configured — which is the point: "technically present" and
"actually effective" are now different things in the number itself, not
just a cosmetic ⚠ flag.

Tiers: **A** ≥ 0.90, **B** ≥ 0.75, **C** ≥ 0.60, **D** ≥ 0.40, **F** < 0.40.

**For your methodology section:** this is a hybrid presence+quality scoring
model. If you're benchmarking directly against Buchanan et al. (2018) or
the Maldives 2024 study and either of those used pure presence-based
scoring, note the deviation explicitly — your numbers won't be directly
comparable to theirs unless you also compute a presence-only score
alongside this one for that specific comparison.

## Notes / limits

- Headers are only captured for pages you actually navigate to (the
  extension listens via `webRequest.onHeadersReceived`) — if you open the
  popup before the page finishes loading once, reload the tab.
- Redirects (e.g. http → https) are handled: only the final response's
  headers are captured, not the intermediate redirect's.
- Each of the 6 headers is checked for both **presence** (feeds your
  paper's 0–1 score, unchanged) and basic **quality** (shown as ⚠ "weak"
  in the popup — e.g. CSP with `unsafe-inline`, HSTS with a short
  `max-age`, a leaky Referrer-Policy). Weak still counts as "present" for
  scoring, since your paper's methodology is presence-based, but you can
  see at a glance which sites are only superficially compliant.
- "Additional signals" (cookie flags, Server/X-Powered-By disclosure) are
  informational only and are NOT part of the 6-header score.
- This only reads headers of pages rendered in your browser. It does not
  do SSL/cert checks or probe for exposed files — that's still the job of
  the server-side backend for your full remediation tool later.
- Reload the extension (chrome://extensions → refresh icon) after editing
  any file.

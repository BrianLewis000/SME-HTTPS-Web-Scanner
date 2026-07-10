const BACKEND = "http://localhost:5000";

// ---- Core 6-header quality assessment ----------------------------------
// Each check returns "pass" | "weak" | "fail" plus a short human reason.
// "pass"/"fail" feed your paper's presence-based score (unchanged).
// "weak" also counts as present for that score, but is flagged in the UI
// so you can see at a glance which sites have the header only superficially.

function checkCSP(headers) {
  const v = headers["content-security-policy"];
  if (!v) return { status: "fail", detail: "not set" };
  const risky = /unsafe-inline|unsafe-eval|(^|[\s;])\*(?=[\s;]|$)/i.test(v);
  if (risky) return { status: "weak", detail: "present but allows unsafe-inline/eval or wildcard sources" };
  return { status: "pass", detail: "present, no obvious wildcard/unsafe-inline" };
}

function checkHSTS(headers) {
  const v = headers["strict-transport-security"];
  if (!v) return { status: "fail", detail: "not set" };
  const match = v.match(/max-age=(\d+)/i);
  const maxAge = match ? parseInt(match[1], 10) : 0;
  const sixMonths = 15768000;
  if (maxAge < sixMonths) {
    return { status: "weak", detail: `max-age too short (${maxAge}s, recommend \u2265 6 months)` };
  }
  return { status: "pass", detail: `max-age=${maxAge}s` };
}

function checkXFO(headers) {
  const v = headers["x-frame-options"];
  const csp = headers["content-security-policy"] || "";
  if (!v) {
    if (/frame-ancestors/i.test(csp)) {
      return { status: "weak", detail: "header missing, but covered by CSP frame-ancestors" };
    }
    return { status: "fail", detail: "not set" };
  }
  const val = v.trim().toUpperCase();
  if (val === "DENY" || val === "SAMEORIGIN") return { status: "pass", detail: val };
  return { status: "weak", detail: `unusual value: ${v}` };
}

function checkXCTO(headers) {
  const v = headers["x-content-type-options"];
  if (!v) return { status: "fail", detail: "not set" };
  if (v.trim().toLowerCase() === "nosniff") return { status: "pass", detail: "nosniff" };
  return { status: "weak", detail: `unexpected value: ${v}` };
}

function checkReferrerPolicy(headers) {
  const v = headers["referrer-policy"];
  if (!v) return { status: "fail", detail: "not set" };
  const weakValues = ["unsafe-url", "no-referrer-when-downgrade"];
  const first = v.split(",")[0].trim().toLowerCase();
  if (weakValues.includes(first)) return { status: "weak", detail: `leaky policy: ${v}` };
  return { status: "pass", detail: v };
}

function checkPermissionsPolicy(headers) {
  const v = headers["permissions-policy"];
  if (!v) return { status: "fail", detail: "not set" };
  if (/=\(?\*\)?/.test(v)) return { status: "weak", detail: "grants a feature to all origins (*)" };
  return { status: "pass", detail: "present, no wildcard grants" };
}

// Severity-tiered weights (sum to 1.0). Rationale, for your methodology
// section: CSP and HSTS mitigate high-impact, high-prevalence attack
// classes (XSS; MITM/downgrade) and are weighted highest. X-Frame-Options
// and Referrer-Policy address real but narrower attack surfaces (clickjacking;
// info leakage) and sit in the middle tier. Permissions-Policy is situational
// (hardware/feature misuse) and X-Content-Type-Options addresses an older,
// narrower MIME-sniffing attack class - both weighted lowest.
const REQUIRED_HEADERS = [
  { key: "content-security-policy", label: "Content-Security-Policy", check: checkCSP, weight: 0.25 },
  { key: "strict-transport-security", label: "Strict-Transport-Security", check: checkHSTS, weight: 0.20 },
  { key: "x-frame-options", label: "X-Frame-Options", check: checkXFO, weight: 0.15 },
  { key: "referrer-policy", label: "Referrer-Policy", check: checkReferrerPolicy, weight: 0.15 },
  { key: "permissions-policy", label: "Permissions-Policy", check: checkPermissionsPolicy, weight: 0.15 },
  { key: "x-content-type-options", label: "X-Content-Type-Options", check: checkXCTO, weight: 0.10 },
];

function tierFromScore(score) {
  if (score >= 0.9) return "A";
  if (score >= 0.75) return "B";
  if (score >= 0.6) return "C";
  if (score >= 0.4) return "D";
  return "F";
}

// ---- Extra signals (NOT part of your 6-header score) --------------------
// Informational only - separate section in the UI.

function checkCookies(setCookies) {
  if (!setCookies || setCookies.length === 0) {
    return { present: false, secure: 0, httpOnly: 0, sameSite: 0, total: 0 };
  }
  let secure = 0, httpOnly = 0, sameSite = 0;
  setCookies.forEach((c) => {
    if (/;\s*secure/i.test(c)) secure++;
    if (/;\s*httponly/i.test(c)) httpOnly++;
    if (/;\s*samesite/i.test(c)) sameSite++;
  });
  return { present: true, secure, httpOnly, sameSite, total: setCookies.length };
}

function checkInfoDisclosure(headers) {
  const findings = [];
  if (headers["server"]) findings.push(`Server: ${headers["server"]}`);
  if (headers["x-powered-by"]) findings.push(`X-Powered-By: ${headers["x-powered-by"]}`);
  return findings;
}

// ---- Metadata extraction (runs inside the page) --------------------------

function extractMetadata() {
  const getMeta = (selector) => {
    const el = document.querySelector(selector);
    if (!el) return null;
    return el.content || el.textContent || null;
  };

  let businessName =
    getMeta('meta[property="og:site_name"]') ||
    getMeta('meta[name="application-name"]') ||
    null;

  let category = null;

  const scripts = document.querySelectorAll('script[type="application/ld+json"]');
  for (const s of scripts) {
    try {
      const parsed = JSON.parse(s.textContent);
      const items = Array.isArray(parsed) ? parsed : [parsed];
      for (const item of items) {
        if (!businessName && item.name) businessName = item.name;
        if (!category && item["@type"]) category = item["@type"];
      }
    } catch (e) {
      // not valid JSON-LD, skip
    }
  }

  if (!businessName && document.title) {
    businessName = document.title.split(/[-|\u2013]/)[0].trim();
  }

  // Best-effort sector guess via keyword matching against page text.
  // This is heuristic, not authoritative - it's meant to save typing for
  // the obvious cases, not to be trusted blindly.
  const SECTOR_KEYWORDS = {
    "Healthcare": ["hospital", "clinic", "doctor", "pharmacy", "dental", "diagnostic", "healthcare", "medical"],
    "Retail": ["shop", "store", "retail", "boutique", "mart", "supermarket", "grocery"],
    "Hospitality/Food": ["restaurant", "cafe", "hotel", "resort", "catering", "bakery", "dining", "food"],
    "Education": ["school", "college", "institute", "academy", "coaching", "university", "education", "tuition"],
    "Finance": ["bank", "finance", "insurance", "loan", "investment", "accounting", "chartered accountant", "tax"],
    "IT/Technology": ["software", "technology", "it services", "web design", "app development", "saas", "tech solutions"],
    "Real Estate": ["real estate", "property", "builder", "realty", "construction", "developers"],
    "Beauty/Wellness": ["salon", "spa", "wellness", "gym", "fitness", "yoga", "beauty parlour"],
    "Automotive": ["automobile", "car dealer", "auto parts", "garage", "car service", "showroom"],
    "Legal": ["law firm", "advocate", "legal services", "attorney"],
    "Manufacturing": ["manufacturer", "manufacturing", "factory", "industries", "exporter"],
    "Professional Services": ["consultancy", "consulting", "agency", "services pvt", "solutions"],
  };

  const haystack = [
    document.title || "",
    getMeta('meta[name="description"]') || "",
    getMeta('meta[name="keywords"]') || "",
  ]
    .join(" ")
    .toLowerCase();

  let sector = null;
  for (const [name, keywords] of Object.entries(SECTOR_KEYWORDS)) {
    if (keywords.some((kw) => haystack.includes(kw))) {
      sector = name;
      break;
    }
  }

  // Best-effort establishment year. Two tiers of confidence:
  // "high" = explicit wording (established/founded/since <year>), which is
  // about as reliable as self-reported text gets.
  // "low" = a bare copyright year (© 1998) or a copyright range (© 1998-2024,
  // taking the earlier year) — this is a common proxy but can be wrong
  // (e.g. a site relaunch resetting the copyright year), so it's flagged
  // in the UI for a manual check rather than trusted silently.
  const currentYear = new Date().getFullYear();
  const isPlausibleYear = (y) => y >= 1900 && y <= currentYear;
  const pageText = document.body ? document.body.innerText : "";

  let establishedYear = null;
  let establishedConfidence = null;

  const strongMatch = pageText.match(
    /\b(?:established|est\.?|founded|incorporated|in\s*business)\s*(?:in|since)?\s*[:\-]?\s*(\d{4})\b/i
  ) || pageText.match(/\bsince\s*(\d{4})\b/i);
  if (strongMatch) {
    const y = parseInt(strongMatch[1], 10);
    if (isPlausibleYear(y)) {
      establishedYear = y;
      establishedConfidence = "high";
    }
  }

  if (!establishedYear) {
    const copyrightMatches = [...pageText.matchAll(/\u00a9\s*(\d{4})(?:\s*[-\u2013]\s*\d{2,4})?/g)];
    let earliest = null;
    copyrightMatches.forEach((m) => {
      const y = parseInt(m[1], 10);
      if (isPlausibleYear(y) && (earliest === null || y < earliest)) earliest = y;
    });
    if (earliest) {
      establishedYear = earliest;
      establishedConfidence = "low";
    }
  }

  return { businessName, category, sector, establishedYear, establishedConfidence };
}

// ---- Main ------------------------------------------------------------

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  document.getElementById("url").textContent = tab.url;

  try {
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: extractMetadata,
    });
    if (result) {
      if (result.businessName) document.getElementById("business-name").value = result.businessName;
      if (result.sector) document.getElementById("sector").value = result.sector;
      if (result.category) document.getElementById("category").value = result.category;
      if (result.establishedYear) {
        const yearInput = document.getElementById("established-year");
        yearInput.value = result.establishedYear;
        if (result.establishedConfidence === "low") {
          yearInput.classList.add("low-confidence");
          document.getElementById("established-hint").style.display = "block";
        }
      }
    }
  } catch (e) {
    // page blocks script injection (chrome:// pages, web store, etc.) - skip silently
  }

  const stored = await chrome.storage.session.get(`tab_${tab.id}`);
  const record = stored[`tab_${tab.id}`];

  const list = document.getElementById("header-list");
  list.innerHTML = "";

  if (!record) {
    document.getElementById("score").textContent =
      "No headers captured yet — reload this tab, then reopen the popup.";
  } else {
    const headers = record.headers || {};
    let weightedScore = 0;
    let presentCount = 0;

    // Quality-graded credit: a header contributes its full weight only if
    // well-configured. "weak" (present but misconfigured, e.g. CSP with
    // unsafe-inline) earns half credit rather than full credit - this is
    // what makes the score reflect actual effectiveness, not just presence.
    const CREDIT = { pass: 1.0, weak: 0.5, fail: 0.0 };

    REQUIRED_HEADERS.forEach((h) => {
      const result = h.check(headers);
      weightedScore += h.weight * CREDIT[result.status];
      if (result.status !== "fail") presentCount++;

      const li = document.createElement("li");
      li.className = result.status; // "pass" | "weak" | "fail"
      const icon = result.status === "pass" ? "\u2713" : result.status === "weak" ? "\u26a0" : "\u2717";
      li.textContent = `${icon} ${h.label} (w=${h.weight}) \u2014 ${result.detail}`;
      list.appendChild(li);
    });

    document.getElementById("score").textContent =
      `${weightedScore.toFixed(2)} / 1.00 \u2014 Tier ${tierFromScore(weightedScore)} (${presentCount}/6 headers present)`;

    // Extra signals - informational, not part of the score
    const extraList = document.getElementById("extra-list");
    extraList.innerHTML = "";

    const cookieInfo = checkCookies(record.setCookies);
    if (cookieInfo.present) {
      const li = document.createElement("li");
      li.textContent =
        `Cookies: ${cookieInfo.total} set \u2014 ${cookieInfo.secure} Secure, ` +
        `${cookieInfo.httpOnly} HttpOnly, ${cookieInfo.sameSite} SameSite`;
      extraList.appendChild(li);
    }

    const disclosures = checkInfoDisclosure(headers);
    disclosures.forEach((d) => {
      const li = document.createElement("li");
      li.textContent = `Info disclosure: ${d}`;
      li.className = "weak";
      extraList.appendChild(li);
    });

    if (!cookieInfo.present && disclosures.length === 0) {
      const li = document.createElement("li");
      li.textContent = "No cookies or server-identifying headers observed.";
      extraList.appendChild(li);
    }
  }

  const yearInputEl = document.getElementById("established-year");
  yearInputEl.addEventListener("input", () => {
    yearInputEl.classList.remove("low-confidence");
    document.getElementById("established-hint").style.display = "none";
  });

  const addBtn = document.getElementById("add-btn");
  const statusEl = document.getElementById("status");

  try {
    const res = await fetch(`${BACKEND}/check_duplicate?url=${encodeURIComponent(tab.url)}`);
    const dup = await res.json();
    if (dup.exists) {
      addBtn.textContent = "Already in dataset";
      addBtn.disabled = true;
    }
  } catch (e) {
    statusEl.textContent = "Backend not running (start server.py on :5000)";
  }

  addBtn.addEventListener("click", () => addToDataset(tab.url));
}

async function addToDataset(url) {
  const statusEl = document.getElementById("status");

  const yearRaw = document.getElementById("established-year").value.trim();
  const currentYear = new Date().getFullYear();
  const year = parseInt(yearRaw, 10);
  const validYear = yearRaw !== "" && Number.isInteger(year) && year >= 1900 && year <= currentYear;

  if (!validYear) {
    statusEl.textContent = "Year established is required (e.g. 1998) before this can be saved";
    document.getElementById("established-year").focus();
    return;
  }

  const payload = {
    url,
    business_name: document.getElementById("business-name").value,
    sector: document.getElementById("sector").value,
    category: document.getElementById("category").value,
    established_year: year,
    notes: document.getElementById("notes").value,
  };

  try {
    const res = await fetch(`${BACKEND}/add_site`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const result = await res.json();

    if (result.status === "added") {
      statusEl.textContent = "Added \u2713";
      document.getElementById("add-btn").textContent = "Already in dataset";
      document.getElementById("add-btn").disabled = true;
    } else if (result.status === "duplicate") {
      statusEl.textContent = "Already in dataset";
    } else {
      statusEl.textContent = `Error: ${result.message || "unknown"}`;
    }
  } catch (e) {
    statusEl.textContent = "Could not reach backend (localhost:5000)";
  }
}

document.addEventListener("DOMContentLoaded", init);

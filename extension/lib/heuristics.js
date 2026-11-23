// PhishGuard — detection scoring (shared by the extension and the tests).
// Risk score 0–100:  Safe 0–29 · Caution 30–69 · Danger 70–100
// Four signal groups, matching the proposal: Reputation, URL heuristics,
// Domain signals, Page signals.

export const THRESHOLDS = { caution: 30, danger: 70 };

// Brands people commonly impersonate → their real registrable domains.
export const BRANDS = {
  paypal: ["paypal.com", "paypalobjects.com", "paypal.me"],
  google: ["google.com", "gmail.com", "youtube.com", "googleusercontent.com", "googleapis.com", "gstatic.com", "googlevideo.com", "google.co.uk"],
  microsoft: ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com"],
  outlook: ["outlook.com", "live.com", "office.com"],
  office365: ["office.com", "microsoftonline.com"],
  apple: ["apple.com", "icloud.com"],
  icloud: ["icloud.com", "apple.com"],
  amazon: ["amazon.com", "amazon.co.uk", "amazon.ca", "amazonaws.com", "media-amazon.com"],
  facebook: ["facebook.com", "fb.com"],
  instagram: ["instagram.com"],
  netflix: ["netflix.com"],
  linkedin: ["linkedin.com"],
  dropbox: ["dropbox.com"],
  docusign: ["docusign.com", "docusign.net"],
  coinbase: ["coinbase.com"],
  chase: ["chase.com"],
  wellsfargo: ["wellsfargo.com"],
  bankofamerica: ["bankofamerica.com"],
  venmo: ["venmo.com"],
  kean: ["kean.edu"],
  canvas: ["instructure.com"],
};

// Brands that are also everyday English words: only flag exact lookalikes, not substrings.
const SHORT_OR_COMMON = new Set(["chase", "apple", "canvas", "kean", "venmo"]);

const MULTI_PART_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
  "co.jp", "co.in", "com.br", "com.mx", "co.za", "com.cn", "com.tr", "co.kr",
]);

const RISKY_TLDS = new Set([
  "zip", "mov", "xyz", "top", "click", "country", "tk", "ml", "ga", "cf", "gq",
  "work", "support", "rest", "fit", "cam", "monster", "icu", "buzz", "live",
]);

const HOMOGLYPHS = [
  [/rn/g, "m"], [/vv/g, "w"], [/0/g, "o"], [/1/g, "l"], [/3/g, "e"],
  [/4/g, "a"], [/5/g, "s"], [/7/g, "t"], [/8/g, "b"], [/\$/g, "s"], [/@/g, "a"],
];

export function parseUrl(raw) {
  try { return new URL(raw); } catch { return null; }
}

export function isIp(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[");
}

// eTLD+1 approximation, good enough for scoring.
export function registrableDomain(host) {
  host = host.toLowerCase().replace(/\.$/, "");
  if (isIp(host)) return host;
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  const lastTwo = parts.slice(-2).join(".");
  return MULTI_PART_SUFFIXES.has(lastTwo) ? parts.slice(-3).join(".") : lastTwo;
}

function normalizeLookalike(s) {
  let out = s.toLowerCase();
  for (const [re, rep] of HOMOGLYPHS) out = out.replace(re, rep);
  return out.replace(/[^a-z]/g, "");
}

export function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    }
  }
  return dp[a.length][b.length];
}

function isOfficial(brand, domain) {
  return BRANDS[brand].includes(domain);
}

// Which brand (if any) is this host pretending to be?
export function findImpersonation(host) {
  const domain = registrableDomain(host);
  const label = domain.split(".")[0];
  const normLabel = normalizeLookalike(label);
  const hostTokens = host.toLowerCase().split(/[.\-_]/).filter(Boolean);

  for (const brand of Object.keys(BRANDS)) {
    if (isOfficial(brand, domain)) return null; // it IS the brand

    // 1) Typosquat / homoglyph: paypa1.com, rnicrosoft.com, gooogle.com
    const dist = levenshtein(normLabel, brand);
    const typoLimit = brand.length >= 8 ? 2 : 1;
    if (!SHORT_OR_COMMON.has(brand) && label !== brand && dist <= typoLimit && normLabel.length >= 4) {
      return { brand, kind: "lookalike", official: BRANDS[brand][0] };
    }
    if (normLabel === brand && label !== brand) {
      return { brand, kind: "lookalike", official: BRANDS[brand][0] };
    }

    // 2) Brand used as a token on someone else's domain: paypal-secure-login.com, kean-edu-login.net
    const tokenHit = hostTokens.includes(brand) ||
      (!SHORT_OR_COMMON.has(brand) && host.toLowerCase().includes(brand));
    if (tokenHit) {
      return { brand, kind: "brand-in-host", official: BRANDS[brand][0] };
    }
  }
  return null;
}

// ---------- URL heuristics (instant, local) ----------
export function urlHeuristics(rawUrl) {
  const u = parseUrl(rawUrl);
  const signals = [];
  if (!u || !/^https?:$/.test(u.protocol)) return { score: 0, signals, skipped: true };

  const host = u.hostname.toLowerCase();
  const domain = registrableDomain(host);
  const tld = domain.split(".").pop();
  const add = (points, id, text) => signals.push({ group: "url", points, id, text });

  const imp = findImpersonation(host);
  if (imp?.kind === "lookalike") add(50, "lookalike", `The address looks like ${imp.official}, but it isn't`);
  else if (imp?.kind === "brand-in-host") add(40, "brand-in-host", `Uses the name “${imp.brand}” but isn't ${imp.official}`);

  if (host.includes("xn--")) add(30, "punycode", "The address uses look-alike international characters");
  if (isIp(host)) add(30, "raw-ip", "The address is a raw IP number instead of a name");
  if (u.username || u.password) add(25, "at-sign", "The address hides its real destination after an @");
  if (u.protocol === "http:") add(10, "no-https", "The connection isn't encrypted");
  if (RISKY_TLDS.has(tld)) add(10, "risky-tld", `Ends in .${tld}, a domain ending often used for scams`);
  if (host.split(".").length >= 5) add(10, "deep-subdomain", "Unusually long chain of subdomains");
  if ((domain.match(/-/g) || []).length >= 2) add(10, "hyphens", "Many hyphens in the domain name");
  if (rawUrl.length > 120) add(5, "long-url", "Very long address");

  return { score: sum(signals), signals, host, domain, impersonation: imp };
}

// ---------- Combine all four groups ----------
// rep:    { safeBrowsing: bool|null, openPhish: bool|null, virusTotal: {malicious:int}|null }
// domain: { ageDays: number|null, certAgeDays: number|null }
// page:   { hasPassword, crossDomainForm, formTarget, titleBrand }
export function scoreAll(rawUrl, { rep = {}, domain = {}, page = {} } = {}) {
  const base = urlHeuristics(rawUrl);
  if (base.skipped) return { score: 0, level: "safe", signals: [], skipped: true };
  const signals = [...base.signals];
  const add = (group, points, id, text) => signals.push({ group, points, id, text });

  // Reputation (known-bad lists) — these set a floor, not just add points.
  let floor = 0;
  if (rep.safeBrowsing) { floor = Math.max(floor, 90); add("reputation", 0, "gsb", "Google Safe Browsing lists this site as unsafe"); }
  if (rep.openPhish) { floor = Math.max(floor, 90); add("reputation", 0, "openphish", "This site is on the OpenPhish phishing feed"); }
  const vt = rep.virusTotal?.malicious ?? 0;
  if (vt >= 3) { floor = Math.max(floor, 80); add("reputation", 0, "vt", `${vt} security vendors on VirusTotal flag this site`); }
  else if (vt >= 1) add("reputation", 25, "vt-low", `${vt} security vendor${vt > 1 ? "s" : ""} on VirusTotal flag this site`);

  // Domain signals
  if (domain.ageDays != null) {
    if (domain.ageDays < 30) add("domain", 30, "new-domain", `The site was created ${plural(domain.ageDays, "day")} ago`);
    else if (domain.ageDays < 180) add("domain", 10, "young-domain", `The site was created ${Math.round(domain.ageDays / 30)} months ago`);
  }
  if (domain.certAgeDays != null && domain.certAgeDays < 7) {
    add("domain", 15, "new-cert", "Its security certificate was issued in the last few days");
  }

  // Page signals (from the content script)
  if (page.crossDomainForm) add("page", 40, "cross-form", `A login form sends your password to ${page.formTarget || "another site"}`);
  if (page.titleBrand && !base.impersonation) {
    add("page", page.hasPassword ? 30 : 15, "title-brand",
      `The page calls itself ${cap(page.titleBrand)} but the address doesn't match`);
  }
  if (page.hasPassword && rawUrl.startsWith("http:")) add("page", 20, "http-password", "Asks for a password over an unencrypted connection");

  const score = Math.min(100, Math.max(floor, sum(signals)));
  return { score, level: levelFor(score), signals, host: base.host, domain: base.domain };
}

export function levelFor(score) {
  if (score >= THRESHOLDS.danger) return "danger";
  if (score >= THRESHOLDS.caution) return "caution";
  return "safe";
}

// Which brand does a page title claim to be? (used by content script results)
export function brandInText(text, host) {
  if (!text) return null;
  const domain = registrableDomain(host);
  const t = text.toLowerCase().replace(/\s+/g, "");
  for (const brand of Object.keys(BRANDS)) {
    if (SHORT_OR_COMMON.has(brand)) continue;
    if (t.includes(brand) && !isOfficial(brand, domain)) return brand;
  }
  return null;
}

const sum = (s) => s.reduce((n, x) => n + x.points, 0);
const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;
const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
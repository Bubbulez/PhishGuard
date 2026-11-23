// PhishGuard backend (Node.js 18+, no dependencies).
// - Keeps API keys out of the extension
// - Caches recent verdicts to cut latency
// - Queues requests to respect API rate limits
// Threat intel: Google Safe Browsing v4, VirusTotal v3, OpenPhish feed, RDAP domain age, TLS cert age.
import http from "node:http";
import tls from "node:tls";
import fs from "node:fs";

loadEnv(new URL("./.env", import.meta.url));
const PORT = Number(process.env.PORT || 8787);
const GSB_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY || "";
const VT_KEY = process.env.VIRUSTOTAL_KEY || "";
const CACHE_TTL = 15 * 60 * 1000;
const OPENPHISH_URL = process.env.OPENPHISH_FEED || "https://openphish.com/feed.txt";

// ---------- Cache ----------
const cache = new Map();
function cached(key, fn, ttl = CACHE_TTL) {
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < ttl) return hit.value;
  const value = fn();
  cache.set(key, { value, at: Date.now() });
  Promise.resolve(value).catch(() => cache.delete(key));
  if (cache.size > 5000) cache.delete(cache.keys().next().value);
  return value;
}

// ---------- Rate-limited queue (VirusTotal free tier: 4 requests/min) ----------
function rateLimiter(perMinute) {
  const gap = 60000 / perMinute;
  let next = 0;
  return (fn) => {
    const wait = Math.max(0, next - Date.now());
    next = Math.max(Date.now(), next) + gap;
    return new Promise((res) => setTimeout(res, wait)).then(fn);
  };
}
const vtQueue = rateLimiter(Number(process.env.VIRUSTOTAL_PER_MIN || 4));

const withTimeout = (p, ms, fallback = null) =>
  Promise.race([p, new Promise((r) => setTimeout(() => r(fallback), ms))]);

// ---------- Google Safe Browsing ----------
async function safeBrowsing(url) {
  if (!GSB_KEY) return null;
  const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GSB_KEY}`, {
    method: "POST",
    signal: AbortSignal.timeout(4500),
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client: { clientId: "phishguard-kean", clientVersion: "1.0.0" },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }],
      },
    }),
  });
  if (!res.ok) throw new Error(`Safe Browsing HTTP ${res.status}: ${(await res.text()).slice(0, 300)}`);
  const json = await res.json();
  return Array.isArray(json.matches) && json.matches.length > 0;
}

// ---------- VirusTotal ----------
async function virusTotal(url) {
  if (!VT_KEY) return null;
  const id = Buffer.from(url).toString("base64url");
  const res = await vtQueue(() => fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
    headers: { "x-apikey": VT_KEY },
    signal: AbortSignal.timeout(3500),
  }));
  if (res.status === 404) return { malicious: 0, suspicious: 0, known: false };
  if (!res.ok) throw new Error(`VirusTotal HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
  const s = (await res.json()).data?.attributes?.last_analysis_stats ?? {};
  return { malicious: s.malicious ?? 0, suspicious: s.suspicious ?? 0, known: true };
}

// ---------- OpenPhish feed (refreshed every 30 min) ----------
let openPhish = { urls: new Set(), hosts: new Set(), at: 0 };
async function refreshOpenPhish() {
  try {
    const res = await fetch(OPENPHISH_URL, { signal: AbortSignal.timeout(15000) });
    if (!res.ok) throw new Error(`OpenPhish ${res.status}`);
    const lines = (await res.text()).split("\n").map((l) => l.trim()).filter(Boolean);
    const hosts = new Set();
    for (const l of lines) { try { hosts.add(new URL(l).hostname); } catch {} }
    openPhish = { urls: new Set(lines), hosts, at: Date.now() };
    console.log(`[openphish] loaded ${lines.length} URLs`);
  } catch (e) { console.warn(`[openphish] ${e.message}`); }
}
function inOpenPhish(url) {
  if (!openPhish.at) return null;
  try { return openPhish.urls.has(url) || openPhish.hosts.has(new URL(url).hostname); } catch { return false; }
}

// ---------- RDAP domain age ----------
async function domainAgeDays(domain) {
  const res = await fetch(`https://rdap.org/domain/${domain}`, { signal: AbortSignal.timeout(6000) });
  if (!res.ok) return null;
  const reg = (await res.json()).events?.find((e) => e.eventAction === "registration")?.eventDate;
  return reg ? Math.floor((Date.now() - Date.parse(reg)) / 86400000) : null;
}

// ---------- TLS certificate age ----------
function certAgeDays(host) {
  return new Promise((resolve) => {
    const sock = tls.connect({ host, port: 443, servername: host, timeout: 5000 }, () => {
      const cert = sock.getPeerCertificate();
      sock.end();
      resolve(cert?.valid_from ? Math.floor((Date.now() - Date.parse(cert.valid_from)) / 86400000) : null);
    });
    sock.on("error", () => resolve(null));
    sock.on("timeout", () => { sock.destroy(); resolve(null); });
  });
}

function registrable(host) {
  const p = host.toLowerCase().split(".");
  if (/^\d+(\.\d+){3}$/.test(host)) return host;
  const two = p.slice(-2).join(".");
  return p.length > 2 && /^(co|com|org|net|ac|gov)\.[a-z]{2}$/.test(two) ? p.slice(-3).join(".") : two;
}

// ---------- /check ----------
async function check(url) {
  const u = new URL(url);
  if (!/^https?:$/.test(u.protocol)) throw new Error("only http(s) URLs");
  const domain = registrable(u.hostname);
  const errors = {};
  const safe = (name, p, ms = 5000) => withTimeout(Promise.resolve(p).catch((e) => {
    errors[name] = e.message;
    console.warn(`[${name}] ${e.message}`);
    return null;
  }), ms);

  const [gsb, vt, age, cert] = await Promise.all([
    safe("safeBrowsing", cached(`gsb:${url}`, () => safeBrowsing(url))),
    safe("virusTotal", cached(`vt:${url}`, () => virusTotal(url)), 4000), // don't block on the queue
    safe("rdap", cached(`rdap:${domain}`, () => domainAgeDays(domain), 24 * 3600 * 1000)),
    Promise.resolve(null), // Direct TLS lookup disabled for SSRF protection
  ]);
  return {
    url,
    rep: { safeBrowsing: gsb, openPhish: inOpenPhish(url), virusTotal: vt },
    domain: { ageDays: age, certAgeDays: cert },
    registrable: domain,
    errors,
    checkedAt: new Date().toISOString(),
  };
}

// ---------- Per-user rate limit (protects your shared API quotas once hosted) ----------
const PER_IP_PER_MIN = Number(process.env.PER_IP_PER_MIN || 60);
const hits = new Map(); // ip -> { count, windowStart }
function overLimit(req) {
  const ip = req.socket.remoteAddress || "unknown";
  const now = Date.now();
  const h = hits.get(ip);
  if (!h || now - h.windowStart > 60000) { hits.set(ip, { count: 1, windowStart: now }); return false; }
  return ++h.count > PER_IP_PER_MIN;
}
setInterval(() => { const cut = Date.now() - 120000; for (const [ip, h] of hits) if (h.windowStart < cut) hits.delete(ip); }, 60000).unref();

// ---------- HTTP server ----------
const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin || "";
  const allowed =
    /^(chrome|moz)-extension:\/\/[a-z0-9-]+$/i.test(origin) ||
    /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
  res.setHeader("Access-Control-Allow-Origin", allowed ? origin : "null");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.end();
  const send = (code, body) => { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(body)); };

  // Demo pages for presentations: open via http://127.0.0.1:8787/demo/caution (raw IP + HTTP = Caution)
  const demo = req.method === "GET" && req.url.match(/^\/demo\/(caution|danger)\/?$/);
  if (demo) {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    return res.end(fs.readFileSync(new URL(`./demo/${demo[1]}.html`, import.meta.url)));
  }
  if (req.method === "GET" && req.url === "/health") {
    return send(200, { ok: true, services: {
      safeBrowsing: !!GSB_KEY, virusTotal: !!VT_KEY, openPhish: openPhish.at > 0, rdap: true,
    } });
  }
  if (req.method === "GET" && req.url === "/") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end("PhishGuard backend is running. Endpoints: GET /health, POST /check");
  }
  if (req.method === "POST" && req.url === "/check") {
    if (overLimit(req)) return send(429, { error: "slow down" });
    let body = "";
    for await (const chunk of req) { body += chunk; if (body.length > 10000) return send(413, { error: "too large" }); }
    try {
      const { url } = JSON.parse(body || "{}");
      return send(200, await check(url));
    } catch (e) { return send(400, { error: e.message }); }
  }
  send(404, { error: "not found" });
});

if (process.argv[1] && /server\.js$/i.test(process.argv[1])) {
  server.listen(PORT, () => {
    console.log(`PhishGuard backend on http://localhost:${PORT}`);
    console.log(`  Safe Browsing: ${GSB_KEY ? "on" : "off (set GOOGLE_SAFE_BROWSING_KEY)"}`);
    console.log(`  VirusTotal:    ${VT_KEY ? "on" : "off (set VIRUSTOTAL_KEY)"}`);
  });
  refreshOpenPhish();
  setInterval(refreshOpenPhish, 30 * 60 * 1000).unref();
}

export { check, server, registrable };

function loadEnv(file) {
  try {
    for (const line of fs.readFileSync(file, "utf8").split("\n")) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
      if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, "");
    }
  } catch { /* no .env file */ }
}
// PhishGuard service worker: runs local heuristics + scoring, asks the backend
// for reputation/domain data, sets the toolbar icon, and shows the warning page.
import { scoreAll, urlHeuristics, registrableDomain, parseUrl } from "./lib/heuristics.js";
import { DEFAULT_BACKEND_URL } from "./lib/config.js";

const DEFAULTS = { enabled: true, backendUrl: DEFAULT_BACKEND_URL };

// An older version saved "http://localhost:8787" explicitly; drop it so the
// built-in default (your deployed backend) takes over after an update.
chrome.runtime.onInstalled.addListener(async () => {
  const { backendUrl } = await chrome.storage.sync.get("backendUrl");
  if (backendUrl === "http://localhost:8787" && DEFAULT_BACKEND_URL !== backendUrl) {
    await chrome.storage.sync.remove("backendUrl");
  }
});
const verdicts = new Map();        // tabId -> verdict
const pageSignals = new Map();     // tabId -> page signals from content script
const remoteCache = new Map();     // url (no #hash) -> { data, at, ttl }
const REMOTE_TTL = 15 * 60 * 1000; // good answers
const RETRY_TTL = 30 * 1000;       // backend offline / an API errored: retry soon
const cacheKey = (url) => url.split("#")[0];

async function settings() {
  return { ...DEFAULTS, ...(await chrome.storage.sync.get(Object.keys(DEFAULTS))) };
}

// ---------- Backend / threat intelligence ----------
async function remoteLookup(url, domain) {
  const hit = remoteCache.get(cacheKey(url));
  if (hit && Date.now() - hit.at < hit.ttl) return hit.data;

  const { backendUrl } = await settings();
  let data = { rep: {}, domain: {}, backend: "offline" };
  if (backendUrl) {
    try {
      const res = await fetch(`${backendUrl.replace(/\/$/, "")}/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },

        // URL privacy: remove sensitive information before backend transmission.
        body: JSON.stringify({
          url: (() => {
            const sanitized = new URL(url);
            sanitized.username = "";
            sanitized.password = "";
            sanitized.search = "";
            sanitized.hash = "";
            return sanitized.href;
          })(),
        }),

        signal: AbortSignal.timeout(6000),
      });
      if (res.ok) data = { ...(await res.json()), backend: "online" };
    } catch { /* backend not running — fall back below */ }
  }
  // Without the backend we can still get domain age straight from public RDAP.
  if (data.backend === "offline") {
    data.domain = { ageDays: await rdapAgeDays(domain), certAgeDays: null };
  }
  const complete = data.backend === "online" && !Object.keys(data.errors || {}).length;
  remoteCache.set(cacheKey(url), { data, at: Date.now(), ttl: complete ? REMOTE_TTL : RETRY_TTL });
  return data;
}

async function rdapAgeDays(domain) {
  try {
    const res = await fetch(`https://rdap.org/domain/${domain}`, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) return null;
    const json = await res.json();
    const reg = json.events?.find((e) => e.eventAction === "registration")?.eventDate;
    return reg ? Math.floor((Date.now() - Date.parse(reg)) / 86400000) : null;
  } catch { return null; }
}

// ---------- Allowlist for "Continue anyway" (this browser session only) ----------
// Keyed by exact hostname, not registrable domain: allowing one page on a shared
// host (appspot.com, github.io, …) must not allow every other site on it.
async function isAllowed(url) {
  const { allow = [] } = await chrome.storage.session.get("allow");
  return allow.includes(new URL(url).hostname);
}
async function allowHost(url) {
  const host = new URL(url).hostname;
  const { allow = [] } = await chrome.storage.session.get("allow");
  if (!allow.includes(host)) allow.push(host);
  await chrome.storage.session.set({ allow });
}

// ---------- Main check ----------
async function checkTab(tabId, url) {
  const { enabled } = await settings();
  const u = parseUrl(url);
  if (!enabled || !u || !/^https?:$/.test(u.protocol)) {
    verdicts.delete(tabId);
    return setIcon(tabId, enabled ? "safe" : "off");
  }
  const domain = registrableDomain(u.hostname);

  // 1) Instant local verdict from URL heuristics.
  let verdict = finalize(url, scoreAll(url, { page: pageSignals.get(tabId) }), null);
  publish(tabId, verdict);

  // 2) Enrich with reputation + domain age.
  const remote = await remoteLookup(url, domain);
  // The user may have moved on while we waited — don't act on an old page.
  const now = await chrome.tabs.get(tabId).catch(() => null);
  if (!now || cacheKey(now.url || "") !== cacheKey(url)) return;
  verdict = finalize(url, scoreAll(url, { rep: remote.rep, domain: remote.domain, page: pageSignals.get(tabId) }), remote);
  publish(tabId, verdict);

  if (verdict.level === "danger" && !(await isAllowed(url))) {
    const warn = chrome.runtime.getURL("warning/warning.html") + "?" + new URLSearchParams({ tab: tabId, url });
    chrome.tabs.update(tabId, { url: warn }).catch(() => {}); // tab may have been swapped; onReplaced re-checks
  }
}

function finalize(url, result, remote) {
  return {
    ...result,
    url,
    secure: url.startsWith("https:"),
    reported: !remote ? "Checking…"
      : remote.rep?.safeBrowsing || remote.rep?.openPhish ? "Yes"
      : remote.backend === "online" && remote.rep?.safeBrowsing === false ? "No"
      : "Unknown",
    backend: remote?.backend ?? "pending",
    ageDays: remote?.domain?.ageDays ?? null,
    checkedAt: Date.now(),
  };
}

function publish(tabId, verdict) {
  verdicts.set(tabId, verdict);
  chrome.storage.session.set({ [`v:${tabId}`]: verdict }); // survives worker restarts
  setIcon(tabId, verdict.level);
}

const ICON_TITLES = {
  safe: "PhishGuard — Looks safe",
  caution: "PhishGuard — Be careful",
  danger: "PhishGuard — Danger: suspected phishing",
  off: "PhishGuard — Protection paused",
};
function setIcon(tabId, level) {
  const path = Object.fromEntries([16, 32, 48, 128].map((s) => [s, `icons/${level}-${s}.png`]));
  chrome.action.setIcon({ tabId, path }).catch(() => {});
  chrome.action.setTitle({ tabId, title: ICON_TITLES[level] }).catch(() => {});
}

// ---------- Events ----------
chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === "loading" && tab.url && !tab.url.startsWith(chrome.runtime.getURL(""))) {
    pageSignals.delete(tabId);
    checkTab(tabId, tab.url);
  }
});
// Chrome often loads a typed address early in a hidden "prerender" tab and then
// swaps it in under a NEW tab id. Re-check the tab that's actually visible.
chrome.tabs.onReplaced.addListener(async (addedTabId, removedTabId) => {
  verdicts.delete(removedTabId); pageSignals.delete(removedTabId);
  chrome.storage.session.remove(`v:${removedTabId}`);
  const tab = await chrome.tabs.get(addedTabId).catch(() => null);
  if (tab?.url) checkTab(addedTabId, tab.url);
});
// Safety net: when you switch to a tab we never checked, check it now.
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  if (verdicts.has(tabId)) return;
  const tab = await chrome.tabs.get(tabId).catch(() => null);
  if (tab?.url && /^https?:/.test(tab.url)) checkTab(tabId, tab.url);
});
chrome.tabs.onRemoved.addListener((tabId) => {
  verdicts.delete(tabId); pageSignals.delete(tabId);
  chrome.storage.session.remove(`v:${tabId}`);
});

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  (async () => {
    switch (msg.type) {
      case "pageSignals": {         // from content script
        const tabId = sender.tab?.id;
        if (tabId == null) return reply({});
        pageSignals.set(tabId, msg.signals);
        const prev = verdicts.get(tabId);
        if (prev && prev.url === sender.tab.url) {
          const remote = remoteCache.get(cacheKey(prev.url))?.data ?? null;
          const v = finalize(prev.url, scoreAll(prev.url, { rep: remote?.rep, domain: remote?.domain, page: msg.signals }), remote);
          publish(tabId, v);
          if (v.level === "danger" && prev.level !== "danger" && !(await isAllowed(prev.url))) checkTab(tabId, prev.url);
        }
        return reply({});
      }
      case "scoreLink":             // hover check on links
        return reply(urlHeuristics(msg.url));
      case "getVerdict": {          // popup
        const { enabled } = await settings();
        let v = verdicts.get(msg.tabId) ?? (await chrome.storage.session.get(`v:${msg.tabId}`))[`v:${msg.tabId}`];
        // Never checked, or checked a different address? Check right now before answering.
        const tab = await chrome.tabs.get(msg.tabId).catch(() => null);
        if (enabled && tab?.url && /^https?:/.test(tab.url) && (!v || cacheKey(v.url) !== cacheKey(tab.url))) {
          await checkTab(msg.tabId, tab.url);
          v = verdicts.get(msg.tabId);
        }
        return reply({ enabled, verdict: v ?? null });
      }
      case "setEnabled": {
        await chrome.storage.sync.set({ enabled: msg.enabled });
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab) await checkTab(tab.id, tab.url);
        return reply({ ok: true });
      }
      case "continueAnyway": {      // warning page
        await allowHost(msg.url);
        return reply({ ok: true });
      }
      case "getWarning":
        return reply(verdicts.get(Number(msg.tabId)) ?? (await chrome.storage.session.get(`v:${msg.tabId}`))[`v:${msg.tabId}`] ?? null);
    }
  })();
  return true; // async reply
});
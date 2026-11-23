const $ = (id) => document.getElementById(id);
const COPY = {
  safe:    { eyebrow: "SAFE",    headline: "Looks safe" },
  caution: { eyebrow: "CAUTION", headline: "Be careful" },
  danger:  { eyebrow: "DANGER",  headline: "Likely phishing" },
  off:     { eyebrow: "OFF",     headline: "Protection paused" },
};
const ICON = {
  safe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg>',
  caution: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01"/></svg>',
  danger: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></svg>',
  off: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M8 12h8"/></svg>',
};

async function render() {
  // ?tab=<id> lets you open the popup in a full tab for debugging/screenshots.
  const forced = Number(new URLSearchParams(location.search).get("tab"));
  const tab = forced ? await chrome.tabs.get(forced) : (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
  const { enabled, verdict } = await chrome.runtime.sendMessage({ type: "getVerdict", tabId: tab.id });
  $("enabled").checked = enabled;
  const level = !enabled ? "off" : verdict?.level ?? "safe";
  $("banner").className = `banner ${level}`;
  $("eyebrow").textContent = COPY[level].eyebrow;
  $("eyeIcon").innerHTML = ICON[level];
  $("headline").textContent = !verdict && enabled ? "Nothing to check" : COPY[level].headline;
  $("score").parentElement.hidden = !enabled || !verdict;
  $("score").textContent = verdict?.score ?? 0;

  $("site").textContent = verdict?.domain ?? (tab.url ? new URL(tab.url).protocol.replace(":", " page") : "—");
  $("conn").textContent = verdict ? (verdict.secure ? "Secure" : "Not secure") : "—";
  $("reported").textContent = verdict?.reported ?? "—";

  const notes = $("notes");
  notes.innerHTML = "";
  if (enabled && verdict) {
    const items = verdict.signals.filter((s) => s.text).sort((a, b) => b.points - a.points).slice(0, 3);
    if (verdict.ageDays != null && verdict.ageDays < 30 && !items.some((s) => s.id === "new-domain")) {
      items.push({ text: "This site is very new." });
    }
    for (const s of items) {
      const li = document.createElement("li");
      li.textContent = s.text;
      notes.appendChild(li);
    }
  }
  $("backend").textContent = verdict?.backend === "online" ? "● live intel" : verdict ? "○ local only" : "";
  $("backend").title = verdict?.backend === "online"
    ? "Connected to the PhishGuard backend (Safe Browsing, VirusTotal, OpenPhish)"
    : "Backend not reachable: using local heuristics + RDAP only";
  $("report").onclick = (e) => {
    e.preventDefault();
    const url = verdict?.url ?? tab.url;
    chrome.tabs.create({ url: `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(url)}` });
  };
}

$("enabled").addEventListener("change", async (e) => {
  await chrome.runtime.sendMessage({ type: "setEnabled", enabled: e.target.checked });
  render();
});
render();

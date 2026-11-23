import { DEFAULT_BACKEND_URL } from "../lib/config.js";
const $ = (id) => document.getElementById(id);
chrome.storage.sync.get({ backendUrl: DEFAULT_BACKEND_URL, enabled: true }, (s) => {
  $("backendUrl").value = s.backendUrl; $("enabled").checked = s.enabled;
});
$("save").onclick = async () => {
  const backendUrl = $("backendUrl").value.trim();
  await chrome.storage.sync.set({ enabled: $("enabled").checked });
  // Matching the built-in default → don't pin it, so future updates can change it.
  if (backendUrl === DEFAULT_BACKEND_URL) await chrome.storage.sync.remove("backendUrl");
  else await chrome.storage.sync.set({ backendUrl });
  let msg = "Saved.";
  if (backendUrl) {
    try {
      const r = await fetch(backendUrl.replace(/\/$/, "") + "/health", { signal: AbortSignal.timeout(3000) });
      const h = await r.json();
      msg += ` Backend online (${Object.entries(h.services).filter(([, on]) => on).map(([k]) => k).join(", ") || "no API keys set"}).`;
    } catch { msg += " Backend not reachable yet."; }
  }
  $("status").textContent = msg;
};

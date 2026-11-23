const params = new URLSearchParams(location.search);
const url = params.get("url");
const tabId = params.get("tab");
const $ = (id) => document.getElementById(id);

$("addr").textContent = url;
const v = await chrome.runtime.sendMessage({ type: "getWarning", tabId });
if (v) {
  $("score").textContent = v.score;
  const imp = v.signals.find((s) => s.id === "lookalike" || s.id === "brand-in-host");
  if (imp) {
    const brand = imp.text.match(/like ([^,]+),|isn't (.+)$/);
    const name = (brand?.[1] || brand?.[2] || "").split(".")[0];
    const NAMES = { paypal: "PayPal", linkedin: "LinkedIn", icloud: "iCloud", docusign: "DocuSign", wellsfargo: "Wells Fargo",
      bankofamerica: "Bank of America", kean: "Kean University", office365: "Office 365", instructure: "Canvas" };
    const pretty = NAMES[name] || name.charAt(0).toUpperCase() + name.slice(1);
    $("lede").textContent = `PhishGuard thinks this site is pretending to be ${pretty}.`;
  }
  for (const s of v.signals.filter((s) => s.text).sort((a, b) => b.points - a.points).slice(0, 4)) {
    const li = document.createElement("li");
    li.textContent = s.text;
    $("reasons").appendChild(li);
  }
}

$("back").onclick = async () => {
  // Skip the dangerous page in history; if there's nowhere to go, close the tab.
  if (history.length > 2) history.go(-2);
  else chrome.tabs.getCurrent().then((t) => t && chrome.tabs.remove(t.id)).catch(() => {});
};
$("continue").onclick = async (e) => {
  e.preventDefault();
  await chrome.runtime.sendMessage({ type: "continueAnyway", url });
  location.replace(url);
};

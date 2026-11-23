// PhishGuard content script: reads links, forms and the page title,
// reports page signals to the service worker, and warns on risky links.
(() => {
  const BRANDS = ["paypal", "google", "microsoft", "outlook", "office365", "icloud", "amazon",
    "facebook", "instagram", "netflix", "linkedin", "dropbox", "docusign", "coinbase",
    "wellsfargo", "bankofamerica"];

  // Respect the user's protection setting.
  let enabled = false;

  const baseDomain = (host) => {
    const p = host.toLowerCase().split(".");
    const two = p.slice(-2).join(".");
    return p.length > 2 && /^(co|com|org|net|ac|gov)\.[a-z]{2}$/.test(two) ? p.slice(-3).join(".") : two;
  };
  const here = baseDomain(location.hostname);

  function collectSignals() {
    const hasPassword = !!document.querySelector('input[type="password"]');
    let crossDomainForm = false, formTarget = null;
    for (const form of document.forms) {
      if (!form.querySelector('input[type="password"], input[type="email"], input[name*="user" i]')) continue;
      try {
        const action = new URL(form.getAttribute("action") || location.href, location.href);
        if (/^https?:$/.test(action.protocol) && baseDomain(action.hostname) !== here) {
          crossDomainForm = true; formTarget = action.hostname; break;
        }
      } catch { /* ignore malformed action */ }
    }
    const title = (document.title + " " + (document.querySelector('meta[property="og:site_name"]')?.content || ""))
      .toLowerCase().replace(/\s+/g, "");
    const titleBrand = BRANDS.find((b) => title.includes(b) && !here.startsWith(b + ".")) || null;
    return { hasPassword, crossDomainForm, formTarget, titleBrand };
  }

  let last = "";
  function report() {
    if (!enabled) return;

    const signals = collectSignals();
    const key = JSON.stringify(signals);
    if (key === last) return;
    last = key;
    chrome.runtime.sendMessage({ type: "pageSignals", signals }).catch(() => {});
  }

  // Login forms are often injected after load.
  const observer = new MutationObserver(debounce(report, 800));

  // ---------- Link hover warnings ----------
  const tip = document.createElement("div");
  tip.id = "phishguard-tip";
  tip.setAttribute("role", "tooltip");
  tip.hidden = true;
  document.documentElement.appendChild(tip);
  const cache = new Map();

  // Pause or resume webpage scanning.
  function updateProtection(value) {
    enabled = value;
    last = "";
    cache.clear();
    tip.hidden = true;
    observer.disconnect();

    if (enabled) {
      report();
      observer.observe(document.documentElement, {
        childList: true,
        subtree: true
      });
    }
  }

  // Listen for changes to the protection toggle.
  let settingChanged = false;

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "sync" && changes.enabled) {
      settingChanged = true;
      updateProtection(changes.enabled.newValue ?? true);
    }
  });

  // Load the saved protection setting.
  chrome.storage.sync.get({ enabled: true }).then((settings) => {
    if (!settingChanged) updateProtection(settings.enabled);
  }).catch(() => {
    // Keep scanning disabled if settings cannot be loaded.
  });

  document.addEventListener("mouseover", async (e) => {
    if (!enabled) return;

    const a = e.target.closest?.("a[href]");
    if (!a) return;
    let url;
    try { url = new URL(a.href); } catch { return; }
    if (!/^https?:$/.test(url.protocol)) return;

    const linkDomain = baseDomain(url.hostname);
    const shown = (a.textContent || "").trim();
    const textDomain = (shown.match(/([a-z0-9-]+\.)+[a-z]{2,}/i) || [])[0];
    const mismatchText = textDomain && baseDomain(textDomain) !== linkDomain;

    if (!cache.has(a.href)) {
      cache.set(a.href, await chrome.runtime.sendMessage({ type: "scoreLink", url: a.href }).catch(() => null));
    }

    // Protection may have been disabled during the lookup.
    if (!enabled) return;

    const res = cache.get(a.href);
    const risky = mismatchText || (res && res.score >= 30);
    if (!risky) return;

    const expected = mismatchText ? baseDomain(textDomain)
      : res?.impersonation?.official || null;
    tip.innerHTML = "";
    const strong = document.createElement("strong");
    strong.textContent = expected ? `Caution: this link doesn't go to ${expected}.` : "Caution: this link looks suspicious.";
    const small = document.createElement("span");
    small.textContent = `It goes to ${url.hostname}`;
    tip.append(strong, small);
    const r = a.getBoundingClientRect();
    tip.style.left = `${Math.min(window.innerWidth - 300, r.right + 8)}px`;
    tip.style.top = `${Math.max(8, r.top - 4)}px`;
    tip.hidden = false;
    a.addEventListener("mouseleave", () => (tip.hidden = true), { once: true });
  });

  function debounce(fn, ms) {
    let t; return () => { clearTimeout(t); t = setTimeout(fn, ms); };
  }
})();
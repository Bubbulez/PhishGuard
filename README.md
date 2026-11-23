# PhishGuard - Team 6, Computer Security

A Chrome & Firefox extension that checks every site you visit and warns you about phishing in real time.
It's built from the Team 6 proposal deck (architecture, tech stack, and 0–100 scoring), and its screens follow the Figma frames.

```
extension/   Browser extension (Manifest V3, plain JavaScript)
  background.js        Service worker: local heuristics + scoring, calls the backend, sets icon, shows warning
  lib/heuristics.js    Detection scoring system (shared with tests)
  content/             Content script: reads links, forms, page title; link hover warnings
  popup/               Toolbar popup (Safe / Caution / Danger / Off)
  warning/             Full-page danger warning ("Back to safety" / "Continue anyway")
  options/             Settings: backend URL, on/off
  icons/               Shield icons for the four states (16/32/48/128 px)
backend/     Node.js threat-intel proxy (no npm dependencies)
test/        Scoring tests (node --test)
```

## 1. Load the extension

**Chrome / Edge:** go to `chrome://extensions`, turn on **Developer mode**, click **Load unpacked**, and pick the `extension/` folder.

**Firefox (121+):** copy `extension/manifest.firefox.json` over `extension/manifest.json`. Then go to `about:debugging#/runtime/this-firefox`, click **Load Temporary Add-on**, and pick `extension/manifest.json`.

The extension works right away without the backend. In that mode it uses URL heuristics, page signals, and domain age from RDAP. The popup shows **○ local only**.

## 2. Run the backend (adds Safe Browsing, VirusTotal, OpenPhish)

```bash
cd backend
cp .env.example .env        # paste your two free API keys
node server.js              # → http://localhost:8787
```

- **Google Safe Browsing key:** go to Google Cloud Console, enable *Safe Browsing API*, then open Credentials and create an API key.
- **VirusTotal key:** sign up at virustotal.com, open your profile, and copy the API key. The free tier allows 4 requests/min, and the backend queues requests to stay under that.
- **OpenPhish:** uses the free community feed and refreshes it every 30 minutes. No key needed.

Open the extension's **Options** page and click **Save**. It checks `/health` and lists which services are live. When the backend is connected, the popup shows **● live intel**.

## How scoring works

| Group | Signals | Points |
|---|---|---|
| Reputation | Listed by Safe Browsing or OpenPhish → score set to at least 90. VirusTotal ≥3 vendors → at least 80. VirusTotal 1–2 vendors → +25 | floor / +25 |
| URL heuristics | Lookalike (`paypa1.com`, `rnicrosoft.com`) +50 · brand name on someone else's domain (`paypal-secure-login.com`) +40 · punycode +30 · raw IP +30 · `@` trick +25 · no HTTPS +10 · risky TLD +10 · deep subdomains +10 · many hyphens +10 | |
| Domain signals | Registered <30 days ago +30 (<180 days +10) · TLS certificate <7 days old +15 | |
| Page signals | Login form posts to another domain +40 · page title claims a brand the URL doesn't match +30 (+15 with no password field) · password over HTTP +20 | |

Scores are capped at 100. **Safe** is 0–29, **Caution** is 30–69, and **Danger** is 70–100. Danger opens the red warning page. "Continue anyway" allows that domain until the browser closes.

When you hover over a link, the content script checks it. If the link text names one domain but the link goes somewhere else, or the link scores ≥30, a "Caution: this link doesn't go to …" tooltip appears (Figma Frame 6).

## Test

```bash
npm test        # scoring tests: real sites stay Safe, deck examples get caught
```

To try it safely in the browser, Google's official test pages should trigger Danger when the backend is on:
`https://testsafebrowsing.appspot.com/s/phishing.html`

To debug the popup in a full tab, open `chrome-extension://<id>/popup/popup.html?tab=<tabId>`.

## Limits worth mentioning in the presentation
- `registrableDomain` uses a short list of country suffixes instead of the full Public Suffix List.
- The brand list (`BRANDS` in `lib/heuristics.js`) is hand-picked. Add campus-specific brands there.
- Some checks run after the page starts loading, so the warning can appear about a second after a dangerous page opens.

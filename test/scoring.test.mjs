import { test } from "node:test";
import assert from "node:assert/strict";
import { scoreAll, urlHeuristics, registrableDomain, findImpersonation } from "../extension/lib/heuristics.js";

const level = (url, extra) => scoreAll(url, extra).level;

test("real sites score Safe", () => {
  for (const u of ["https://www.kean.edu/", "https://www.paypal.com/signin", "https://mail.google.com/",
    "https://login.microsoftonline.com/", "https://www.amazon.com/", "https://github.com/",
    "https://www.wikipedia.org/", "https://purchase.example.com/", "https://www.amazing-recipes.com/",
    "https://lh3.googleusercontent.com/a.png", "https://keen.com/"]) {
    assert.equal(level(u), "safe", `${u} → ${JSON.stringify(scoreAll(u))}`);
  }
});

test("lookalikes from the deck are caught", () => {
  assert.equal(findImpersonation("paypa1.com")?.brand, "paypal");
  assert.equal(findImpersonation("rnicrosoft.com")?.brand, "microsoft");
  assert.equal(findImpersonation("paypal-secure-login.com")?.brand, "paypal");
  assert.equal(findImpersonation("kean-edu-login.net")?.brand, "kean");
  assert.equal(findImpersonation("www.kean.edu"), null);
});

test("lookalike alone = Caution; plus new domain = Danger (deck's paypal mockup)", () => {
  assert.equal(level("https://paypa1.com/login"), "caution");
  assert.equal(level("https://paypal-secure-login.com/", { domain: { ageDays: 3 } }), "danger");
});

test("punycode, raw IP and @ tricks add risk", () => {
  assert.ok(urlHeuristics("https://xn--pypal-4ve.com/").score >= 30);
  assert.ok(urlHeuristics("http://192.168.4.20/login").score >= 30);
  assert.ok(urlHeuristics("https://google.com@evil.example/").score >= 25);
});

test("reputation hits force Danger regardless of URL", () => {
  assert.equal(level("https://plain-looking.example/", { rep: { safeBrowsing: true } }), "danger");
  assert.equal(level("https://plain-looking.example/", { rep: { openPhish: true } }), "danger");
  assert.equal(level("https://plain-looking.example/", { rep: { virusTotal: { malicious: 5 } } }), "danger");
  assert.equal(level("https://plain-looking.example/", { rep: { virusTotal: { malicious: 1 } } }), "safe");
});

test("page signals: login form posting to another domain", () => {
  const r = scoreAll("https://student-portal.example/", { page: { hasPassword: true, crossDomainForm: true, formTarget: "collect.evil.ru" } });
  assert.equal(r.level, "caution");
  const r2 = scoreAll("https://student-portal.example/", { page: { hasPassword: true, crossDomainForm: true, titleBrand: "microsoft" } });
  assert.equal(r2.level, "danger");
});

test("domain signals: very new domain with fresh cert is Caution", () => {
  assert.equal(level("https://brand-new-shop.example/", { domain: { ageDays: 2, certAgeDays: 1 } }), "caution");
});

test("score is capped at 100 and thresholds match deck (0–29 / 30–69 / 70–100)", () => {
  const r = scoreAll("http://paypa1-secure.xyz/login@x", { domain: { ageDays: 1, certAgeDays: 0 }, page: { hasPassword: true, crossDomainForm: true }, rep: { safeBrowsing: true } });
  assert.equal(r.score, 100);
  assert.equal(registrableDomain("a.b.example.co.uk"), "example.co.uk");
});

# Browser Fingerprint Collection Template
Use this template when collecting a site fingerprint via the in-app browser (Playwright through node_repl).
## 1. Initialize browser (once per session)
```js
if (globalThis.agent?.browsers == null) {
  const { setupBrowserRuntime } = await import("<plugin root>/scripts/browser-client.mjs");
  await setupBrowserRuntime({ globals: globalThis });
}
if (globalThis.browser == null) {
  globalThis.browser = await agent.browsers.getForUrl("https://TARGET_URL");
  nodeRepl.write(await browser.documentation());
}
// Read the documentation output before continuing
```
## 2. Open tab, navigate, collect
```js
var tab = await browser.tabs.getOrCreate({ url: "https://TARGET_URL" });
var page = tab.playwright;
var requests = [];
page.on("response", async (resp) => {
  try {
    var body = await resp.text();
    if (body && body.length < 500000) {
      requests.push({ url: resp.url(), method: resp.request().method(), status: resp.status(), contentType: resp.headers()["content-type"] || "", body: body });
    }
  } catch (e) {}
});
await page.goto("https://TARGET_URL", { waitUntil: "networkidle", timeout: 30000 });
await page.waitForTimeout(5000);
var html = await page.content();
var finalUrl = page.url();
var faviconB64 = "";
try {
  faviconB64 = await page.evaluate(async () => {
    var link = document.querySelector('link[rel*="icon"]');
    var url = link ? link.href : new URL("/favicon.ico", location.href).href;
    var resp = await fetch(url); var blob = await resp.blob();
    return new Promise(r => { var rd = new FileReader(); rd.onload = () => r(rd.result.split(",")[1] || ""); rd.readAsDataURL(blob); });
  });
} catch (e) {}
var result = { target: "TARGET_URL", final_url: finalUrl, rendered_html: html, network_requests: requests, favicon_data: faviconB64, dns: [], collected_at: new Date().toISOString() };
nodeRepl.write(JSON.stringify(result, null, 2));
```
## 3. Fingerprint from collected data
Save the JSON output, then:
```powershell
python scripts/fingerprint_site.py --from-browser collected.json
```

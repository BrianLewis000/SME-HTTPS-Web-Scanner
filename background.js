// Captures response headers for the main document of every tab.
// Only stores the FINAL response (skips 3xx redirect hops) so a
// http->https redirect doesn't leave you looking at the redirect's
// headers instead of the real page's.

const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);

chrome.webNavigation.onBeforeNavigate.addListener(
  (details) => {
    if (details.frameId !== 0) return;
    // Clear stale data the moment a new navigation starts, so the popup
    // never shows headers from the previous page while the new one loads.
    chrome.storage.session.remove(`tab_${details.tabId}`);
  },
  { url: [{ schemes: ["http", "https"] }] }
);

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type !== "main_frame") return;
    if (REDIRECT_CODES.has(details.statusCode)) return; // skip intermediate hops

    const headers = {};
    const setCookies = [];

    (details.responseHeaders || []).forEach((h) => {
      const name = h.name.toLowerCase();
      if (name === "set-cookie") {
        setCookies.push(h.value);
      } else {
        headers[name] = h.value;
      }
    });

    const record = {
      url: details.url,
      statusCode: details.statusCode,
      headers,
      setCookies,
      timestamp: Date.now(),
    };

    chrome.storage.session.set({ [`tab_${details.tabId}`]: record });
  },
  { urls: ["<all_urls>"], types: ["main_frame"] },
  ["responseHeaders", "extraHeaders"]
);

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove(`tab_${tabId}`);
});

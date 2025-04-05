// scripts/background.js
chrome.runtime.onInstalled.addListener(() => {
  console.log("✅ ThreatBlocker Installed - Background Service Active");
  chrome.storage.local.set({
    scanningEnabled: true,
    currentPageThreats: 0,
    totalThreats: 0,
    threatHistory: []
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "disableScanning") {
    chrome.storage.local.set({ scanningEnabled: false }, () => {
      sendResponse({ message: "Scanning disabled" });
    });
    return true;
  } else if (message.action === "enableScanning") {
    chrome.storage.local.set({ scanningEnabled: true }, () => {
      sendResponse({ message: "Scanning enabled" });
    });
    return true;
  } else if (message.action === "clearHistory") {
    chrome.storage.local.set({
      threatHistory: [],
      currentPageThreats: 0,
      totalThreats: 0
    }, () => {
      sendResponse({ message: "History cleared" });
    });
    return true;
  } else if (message.action === "blockSite") {
    blockSite(message.site, sendResponse);
    return true;
  } else if (message.action === "toggleAdBlock") {
    updateAdBlockingRules(message.enabled, sendResponse);
    return true;
  }
});

/**
 * Block a specific site by redirecting it to blocked.html.
 * We build a wildcard pattern "*://domain/*" for the URL filter.
 */
function blockSite(siteUrl, sendResponse) {
  if (!siteUrl) {
    console.error("No site provided for blocking.");
    sendResponse({ error: "No site provided for blocking." });
    return;
  }
  
  let urlObj;
  try {
    urlObj = new URL(siteUrl);
  } catch (e) {
    console.error("Invalid URL to block:", siteUrl, e);
    sendResponse({ error: "Invalid URL provided." });
    return;
  }
  
  const domain = urlObj.hostname;
  // Remove "www." if present to create a broader match
  const domainForPattern = domain.startsWith("www.") ? domain.substring(4) : domain;
  // Build a wildcard pattern for the rule, e.g., "*://example.com/*"
  const urlFilter = `*://${domainForPattern}/*`;
  const ruleId = Math.floor(Date.now() / 1000);

  console.log("Blocking domain:", domain, "with ruleId:", ruleId, "using urlFilter:", urlFilter);

  // Remove any existing rules that match this filter
  chrome.declarativeNetRequest.getDynamicRules((rules) => {
    const existingRuleIds = rules
      .filter(rule => rule.condition && rule.condition.urlFilter === urlFilter)
      .map(rule => rule.id);
    
    console.log("Existing rule IDs for", domain, ":", existingRuleIds);
    
    chrome.declarativeNetRequest.updateDynamicRules(
      {
        addRules: [
          {
            id: ruleId,
            priority: 1,
            action: {
              type: "redirect",
              redirect: {
                extensionPath: "/blocked.html"
              }
            },
            condition: {
              urlFilter: urlFilter
            }
          }
        ],
        removeRuleIds: existingRuleIds
      },
      () => {
        if (chrome.runtime.lastError) {
          console.error("Failed to add block (redirect) rule:", chrome.runtime.lastError);
          sendResponse({ error: chrome.runtime.lastError.message });
        } else {
          console.log(`⛔ Blocking site: ${domain} redirected to blocked.html (rule ID = ${ruleId})`);
          // Return success without any alert message
          sendResponse({});
        }
      }
    );
  });
}

/**
 * Dynamically add/remove rules to block known ad servers.
 */
function updateAdBlockingRules(enabled, sendResponse) {
  const adDomains = [
    "*://*.doubleclick.net/*",
    "*://*.googlesyndication.com/*",
    "*://*.googleadservices.com/*",
    "*://*.amazon-adsystem.com/*",
    "*://*.adnxs.com/*",
    "*://*.adsafeprotected.com/*",
    "*://*.adservice.google.com/*"
  ];

  let newRules = [];
  adDomains.forEach((domainPattern, index) => {
    newRules.push({
      id: 20000 + index,
      priority: 1,
      action: { type: "block" },
      condition: { urlFilter: domainPattern }
    });
  });

  let adRuleIds = newRules.map(r => r.id);

  if (enabled) {
    chrome.declarativeNetRequest.updateDynamicRules(
      {
        addRules: newRules,
        removeRuleIds: adRuleIds
      },
      () => {
        if (chrome.runtime.lastError) {
          console.error("Failed to add ad-block rules:", chrome.runtime.lastError);
          sendResponse({ error: chrome.runtime.lastError.message });
        } else {
          console.log("✅ Ad-block rules added.");
          sendResponse({ message: "Ad-blocking enabled." });
        }
      }
    );
  } else {
    chrome.declarativeNetRequest.updateDynamicRules(
      {
        addRules: [],
        removeRuleIds: adRuleIds
      },
      () => {
        if (chrome.runtime.lastError) {
          console.error("Failed to remove ad-block rules:", chrome.runtime.lastError);
          sendResponse({ error: chrome.runtime.lastError.message });
        } else {
          console.log("⛔ Ad-block rules removed.");
          sendResponse({ message: "Ad-blocking disabled." });
        }
      }
    );
  }
}

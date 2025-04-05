// scripts/content.js
console.log("🚀 ThreatBlocker content script running...");

// Store basic info about the current site
chrome.storage.local.set({
  currentSite: window.location.hostname,
  currentUrl: window.location.href,
  currentPageThreats: 0
});

function getSeverityFromConfidence(confidence) {
  if (confidence < 0.7) {
    return "High";
  } else if (confidence < 0.9) {
    return "Medium";
  } else {
    return "Low";
  }
}

/**
 * Analyze text via the Flask backend
 */
async function analyzeThreat(text) {
  try {
    let response = await fetch("http://127.0.0.1:5001/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: text, url: window.location.href })
    });
    let rawResult = await response.json();
    console.log("🔍 Text Analysis Raw Result:", rawResult);

    let resultArray = Array.isArray(rawResult) ? rawResult : [rawResult];

    return resultArray.map(item => {
      const severity = getSeverityFromConfidence(item.confidence);
      return {
        label: item.prediction || "Unknown Threat",
        severity: severity,
        type: item.prediction || "",
        subtype: "",
        timestamp: item.timestamp || new Date().toLocaleString()
      };
    });
  } catch (error) {
    console.error("❌ Error connecting to backend:", error);
    return [];
  }
}

/**
 * Analyze images via the Flask backend
 */
async function analyzeImages(imgUrls) {
  try {
    let response = await fetch("http://127.0.0.1:5001/analyzeImage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ images: imgUrls })
    });
    let rawResult = await response.json();
    console.log("🔍 Image Analysis Raw Result:", rawResult);

    let resultArray = Array.isArray(rawResult) ? rawResult : [rawResult];

    return resultArray.map(item => ({
      label: item.prediction || "Unknown Image Threat",
      severity: "High",
      type: item.prediction || "Image Threat",
      subtype: "",
      timestamp: item.timestamp || new Date().toLocaleString()
    }));
  } catch (error) {
    console.error("❌ Error connecting to backend for images:", error);
    return [];
  }
}

/**
 * Update threat data in Chrome storage
 */
function updateThreatData(threats) {
  chrome.storage.local.get(["totalThreats", "threatHistory", "currentPageThreats"], (data) => {
    let totalThreats = data.totalThreats || 0;
    let threatHistory = data.threatHistory || [];
    let currentPageThreats = data.currentPageThreats || 0;
    let timestamp = new Date().toLocaleString();

    if (!Array.isArray(threats)) {
      console.error("⚠️ Invalid threats data received:", threats);
      return;
    }

    threats.forEach(threat => {
      totalThreats++;
      currentPageThreats++;
      threatHistory.push({
        threat: threat.label,
        severity: threat.severity,
        type: threat.type || "",
        subtype: threat.subtype || "",
        timestamp,
        site: window.location.hostname
      });
    });

    chrome.storage.local.set({
      currentPageThreats,
      totalThreats,
      threatHistory
    }, () => {
      console.log(`✅ Updated: Current Page = ${currentPageThreats}, Total = ${totalThreats}`);
    });
  });
}

/**
 * Remove known ad elements from the DOM
 */
function removeAds() {
  // Common ad-related selectors. Expand these as needed.
  const adSelectors = [
    "[id^='ad_']",
    "[id^='ads_']",
    "[class*='ad-']",
    "[class*='ads-']",
    "[class*='ads ']",
    "[class*=' ads']",
    "[id*='banner']",
    ".adsbygoogle",
    "iframe[src*='adservice']",
    "iframe[src*='doubleclick']",
    "iframe[src*='googlesyndication']",
    "div[class*='adslot']",
    "div[data-ad-slot]",
    "div[data-adclient]"
  ];

  adSelectors.forEach(selector => {
    document.querySelectorAll(selector).forEach(elem => {
      elem.remove();
    });
  });

  console.log("🛑 Ads removed by ThreatBlocker (DOM cleanup).");
}

/**
 * Detect suspicious script patterns in the page source
 */
function analyzePageSource() {
  const html = document.documentElement.innerHTML;
  const patterns = [
    /eval\(/i,
    /unescape\(/i,
    /document\.write\(/i,
    /window\.location\.replace\(/i
  ];
  let score = 0;
  patterns.forEach(pattern => {
    if (pattern.test(html)) {
      score += 0.2;
    }
  });
  return score;
}

function showNotification(title, message) {
  if (Notification.permission === "granted") {
    new Notification(title, { body: message });
  } else if (Notification.permission !== "denied") {
    Notification.requestPermission().then(permission => {
      if (permission === "granted") {
        new Notification(title, { body: message });
      }
    });
  }
}

/**
 * Main scanning function
 */
async function scanPage() {
  try {
    console.log("🚨 Scanning page for threats...");
    chrome.storage.local.get(
      ["scanningEnabled", "pausedSites", "hideCookieWalls", "blockDistractions", "blockAds"],
      async (data) => {
        if (!data.scanningEnabled) {
          console.log("⏸️ Scanning is disabled globally.");
          return;
        }

        const pausedSites = data.pausedSites || [];
        if (pausedSites.includes(window.location.hostname)) {
          console.log(`ThreatBlocker is paused on ${window.location.hostname}.`);
          return;
        }

        // Remove existing ads in the DOM if blockAds is enabled
        if (data.blockAds) {
          removeAds();
        }

        // Analyze visible text
        let textThreats = await analyzeThreat(document.body.innerText);

        // Additional analysis: scan full HTML for suspicious patterns
        let sourceScore = analyzePageSource();
        if (sourceScore > 0.5) {
          textThreats.push({
            label: `Suspicious Script Patterns Detected (score: ${sourceScore.toFixed(2)})`,
            severity: sourceScore > 0.8 ? "High" : "Medium",
            type: "Script Analysis",
            subtype: "Obfuscated Code",
            timestamp: new Date().toLocaleString()
          });
        }
        updateThreatData(textThreats);

        // Analyze images
        let images = Array.from(document.getElementsByTagName("img"))
          .map(img => img.src)
          .filter(src => src && src.startsWith("http"));
        if (images.length > 0) {
          let imageThreats = await analyzeImages(images);
          updateThreatData(imageThreats);
        }

        // Show notification if threats are detected
        if (textThreats.length > 0) {
          showNotification("Threat Detected", `Found ${textThreats.length} threat(s) on ${window.location.hostname}`);
        }
      }
    );
  } catch (error) {
    console.error("Error in scanPage:", error);
  }
}

// Run the page scan once on load
scanPage();

function removeCookieBanners() {
  const banners = document.querySelectorAll(".cookie-banner, .cookie-consent, .cookieWall");
  banners.forEach(banner => banner.remove());
  console.log("🍪 Cookie banners removed.");
}

function removeFloatingVideos() {
  const floatingVideos = document.querySelectorAll(".floating-video, .video-overlay");
  floatingVideos.forEach(video => video.remove());
  console.log("📹 Floating videos removed.");
}

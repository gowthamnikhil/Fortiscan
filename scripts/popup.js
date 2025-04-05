// scripts/popup.js
document.addEventListener("DOMContentLoaded", () => {
  const siteNameElem = document.getElementById("siteName");
  const blockedThreatsCountElem = document.getElementById("blockedThreatsCount");
  const possibleThreatsCountElem = document.getElementById("possibleThreatsCount");
  const threatHistoryListElem = document.getElementById("threatHistoryList");

  // Buttons/toggles
  const toggleAdBlock = document.getElementById("toggleAdBlock");
  const toggleScanButton = document.getElementById("toggleScanning");
  const clearHistoryButton = document.getElementById("clearHistory");
  const exportHistoryButton = document.getElementById("exportHistory");
  const blockSiteButton = document.getElementById("blockSite");
  const toggleDarkModeButton = document.getElementById("toggleDarkMode");
  const reportThreatButton = document.getElementById("reportThreat");
  const syncHistoryButton = document.getElementById("syncHistory");

  function updateCurrentSiteInfo(callback) {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
      if (tabs.length === 0) {
        console.warn("No active tab found.");
        callback();
        return;
      }
      const url = tabs[0].url;
      try {
        const domain = new URL(url).hostname;
        chrome.storage.local.set({ currentSite: domain, currentUrl: url }, callback);
      } catch (e) {
        console.error("Error parsing current tab URL:", e);
        chrome.storage.local.set({ currentSite: "Unknown", currentUrl: url }, callback);
      }
    });
  }

  function updatePopup() {
    updateCurrentSiteInfo(() => {
      chrome.storage.local.get([
        "currentSite",
        "currentUrl",
        "currentPageThreats",
        "totalThreats",
        "threatHistory",
        "scanningEnabled",
        "blockAds"
      ], (data) => {
        const siteName = data.currentSite || "Unknown";
        siteNameElem.textContent = siteName;

        const pageThreats = data.currentPageThreats || 0;
        const totalThreats = data.totalThreats || 0;
        blockedThreatsCountElem.textContent = `Threats: ${pageThreats} (page) / ${totalThreats} (total)`;
        possibleThreatsCountElem.textContent = `Possible threats: ${pageThreats}`;

        toggleAdBlock.checked = data.blockAds || false;
        toggleScanButton.textContent = data.scanningEnabled ? "Disable Scanning" : "Enable Scanning";

        // Update the threat history list
        threatHistoryListElem.innerHTML = "";
        if (Array.isArray(data.threatHistory)) {
          // Show the last 10 threats, newest first
          data.threatHistory.slice(-10).reverse().forEach(entry => {
            const li = document.createElement("li");
            li.textContent = `[${entry.timestamp}] ${entry.site} - ${entry.threat} (${entry.severity}) - ${entry.type} / ${entry.subtype}`;

            // Add a small "False Positive" button
            const feedbackBtn = document.createElement("button");
            feedbackBtn.textContent = "False Positive";
            feedbackBtn.addEventListener("click", () => {
              chrome.storage.local.get("feedback", (storageData) => {
                const feedbackArray = storageData.feedback || [];
                feedbackArray.push({ entry, feedback: "false positive" });
                chrome.storage.local.set({ feedback: feedbackArray }, () => {
                  alert("Feedback submitted.");
                });
              });
            });

            li.appendChild(feedbackBtn);
            threatHistoryListElem.appendChild(li);
          });
        }
      });
    });
  }

  // Initial load + refresh every 5s
  updatePopup();
  setInterval(updatePopup, 5000);

  // Toggle Ad Blocking
  toggleAdBlock.addEventListener("change", () => {
    chrome.storage.local.set({ blockAds: toggleAdBlock.checked }, () => {
      chrome.runtime.sendMessage({
        action: "toggleAdBlock",
        enabled: toggleAdBlock.checked
      }, (response) => {
        if (response && response.error) {
          alert(`Error updating ad-block rules: ${response.error}`);
        } else if (response && response.message) {
          console.log(response.message);
          chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
            if (tabs[0]) chrome.tabs.reload(tabs[0].id);
          });
        }
      });
    });
  });

  // Toggle Scanning
  toggleScanButton.addEventListener("click", () => {
    chrome.storage.local.get("scanningEnabled", (data) => {
      const newState = !data.scanningEnabled;
      chrome.storage.local.set({ scanningEnabled: newState }, updatePopup);
    });
  });

  // Clear Threat History
  clearHistoryButton.addEventListener("click", () => {
    chrome.runtime.sendMessage({ action: "clearHistory" }, updatePopup);
  });

  // Export Threat History
  exportHistoryButton.addEventListener("click", () => {
    chrome.storage.local.get("threatHistory", (data) => {
      const history = data.threatHistory || [];
      const blob = new Blob([JSON.stringify(history, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "threat_history.json";
      a.click();
      URL.revokeObjectURL(url);
    });
  });

  // Block Current Website
  blockSiteButton.addEventListener("click", () => {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
      if (tabs.length === 0) return;
      const currentUrl = tabs[0].url;
      chrome.runtime.sendMessage({ action: "blockSite", site: currentUrl }, (response) => {
        // Simply reload the tab after a short delay to trigger the redirect rule.
        setTimeout(() => {
          chrome.tabs.reload();
        }, 300);
      });
    });
  });

  // Toggle Dark Mode
  toggleDarkModeButton.addEventListener("click", () => {
    document.body.classList.toggle("dark");
    toggleDarkModeButton.textContent = document.body.classList.contains("dark")
      ? "Disable Dark Mode"
      : "Enable Dark Mode";
  });

  // Report Threat (Updated to use /reportThreat endpoint)
  reportThreatButton.addEventListener("click", () => {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
      if (tabs.length === 0) return;
      let currentUrl = tabs[0].url;
      let domain = "Unknown";
      try {
        domain = new URL(currentUrl).hostname;
      } catch (e) {
        console.error("Error parsing URL for threat report:", e);
      }

      const threatDetails = {
        site: domain,
        url: currentUrl,
        details: "Threat detected on this page. (You can add more info here.)"
      };

      fetch("http://127.0.0.1:5001/reportThreat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ threatInfo: JSON.stringify(threatDetails, null, 2) })
      })
      .then(response => {
        if (!response.ok) {
          return response.text().then(text => { throw new Error(text); });
        }
        return response.json();
      })
      .then(result => {
        if (result.error) {
          alert(`Error: ${result.error}`);
        } else {
          alert(result.message);
        }
      })
      .catch(error => {
        console.error("Error reporting threat:", error);
        alert("An error occurred while sending the report.\n\n" + error);
      });
    });
  });

  // Sync local threat data to the Flask server
  syncHistoryButton.addEventListener("click", () => {
    chrome.storage.local.get("threatHistory", (data) => {
      const threatHistory = data.threatHistory || [];
      if (threatHistory.length === 0) {
        alert("No local threat data to sync.");
        return;
      }

      fetch("http://127.0.0.1:5001/submitHistory", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ threatHistory })
      })
      .then(response => response.json())
      .then(result => {
        console.log("Submitted to server:", result);
        alert("Threat history synced with dashboard!");
      })
      .catch(error => {
        console.error("Error syncing history:", error);
        alert("Error syncing history: " + error);
      });
    });
  });
});

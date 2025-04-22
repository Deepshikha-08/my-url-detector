let lastCheckedUrls = {}; 
let currentlyProcessing = {}; 
let dismissedUrls = {}; 

chrome.runtime.onStartup.addListener(() => {
    chrome.storage.local.clear(() => {
        console.log("Cache cleared on extension startup.");
    });
});

chrome.storage.local.get(["lastCheckedUrls", "dismissedUrls"], (data) => {
    if (chrome.runtime.lastError) {
        console.error("Storage error:", chrome.runtime.lastError.message);
        return;
    }

    data = data || {};
    lastCheckedUrls = data.lastCheckedUrls || {};
    dismissedUrls = data.dismissedUrls || {};

    console.log("Loaded cached data:", lastCheckedUrls);
});
function normalizeUrl(url) {
    try {
        let normalized = new URL(url);
        normalized.search = "";
        normalized.hash = "";
        return normalized.toString();
    } catch (e) {
        return url; 
    }
}
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url && tab.url.startsWith("http")) {
        let cleanUrl = normalizeUrl(tab.url);
        console.log("Checking URL:", cleanUrl);

        if (cleanUrl.startsWith("chrome-extension://")) return;

        if (currentlyProcessing[tabId]) return;
        currentlyProcessing[tabId] = true;

        checkUrlWithRetry(cleanUrl, tabId, 3);
    }
});

function checkUrlWithRetry(url, tabId, retries) {
    fetch("http://127.0.0.1:5000/store_extension_url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
    })
    .then(response => response.json())
    .then(data => {
        console.log("API Response:", JSON.stringify(data, null, 2));
        const validResults = ["safe", "suspicious", "malicious"];
        let result = validResults.includes(data.result?.toLowerCase()) ? data.result.toLowerCase() : "unknown";

        storeAndHandleResult(url, tabId, result);
    })
    .catch(err => {
        console.error("Error checking URL:", err);
        if (retries > 0) {
            console.log(`Retrying... (${3 - retries + 1}/3)`);
            setTimeout(() => checkUrlWithRetry(url, tabId, retries - 1), 2000);
        } else {
            storeAndHandleResult(url, tabId, "unknown");
        }
    })
    .finally(() => {
        delete currentlyProcessing[tabId];
    });
}

function storeAndHandleResult(url, tabId, result) {
    lastCheckedUrls[url] = { result, timestamp: Date.now() };
    chrome.storage.local.set({ lastCheckedUrls }, () => {
        if (chrome.runtime.lastError) console.error("Storage Error:", chrome.runtime.lastError.message);
    });
    handleResult(url, tabId, result);
}

function handleResult(url, tabId, result) {
    console.log(`Handling URL Result: ${url}, Tab=${tabId}, Result=${result}`);

    if (result === "malicious") {
        chrome.storage.local.set({ lastMaliciousUrl: url });

        chrome.tabs.update(tabId, { 
            url: chrome.runtime.getURL(`warning.html?blocked=${encodeURIComponent(url)}`) 
        }, () => {
            if (chrome.runtime.lastError) {
                console.error("Redirect Error:", chrome.runtime.lastError.message);
            }
        });

        chrome.notifications.create({
            type: "basic",
            iconUrl: chrome.runtime.getURL("icons/icon.png"),
            title: "Malicious Website Alert!",
            message: "This website has been flagged as malicious. Click to dismiss future warnings.",
            priority: 2,
            requireInteraction: true
        }, (notificationId) => {
            if (chrome.runtime.lastError) {
                console.error("Notification Error:", chrome.runtime.lastError.message);
            }
            dismissedUrls[url] = true;
            chrome.storage.local.set({ dismissedUrls });
        });
    } else if (result === "suspicious") {
        chrome.scripting.executeScript({
            target: { tabId: tabId },
            files: ["content.js"]
        }, () => {
            if (chrome.runtime.lastError) {
                console.error("Failed to inject content script:", chrome.runtime.lastError.message);
            } else {
                console.log("Content script injected successfully.");
            }

            chrome.tabs.sendMessage(tabId, { action: "showBanner", type: result }, (response) => {
                if (chrome.runtime.lastError) {
                    console.error("Error sending message:", chrome.runtime.lastError.message);
                } else {
                    console.log("Banner injected successfully.");
                }
            });
        });
    }
}

chrome.action.onClicked.addListener(() => {
    chrome.tabs.create({ url: chrome.runtime.getURL("warning.html") });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "handleSuspiciousUrl" || message.action === "handleMaliciousUrl") {
        console.log(`${message.action === "handleMaliciousUrl" ? "Malicious" : "Suspicious"} URL detected!`);

        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs.length === 0) return;

            let type = message.action === "handleMaliciousUrl" ? "malicious" : "suspicious";
            let warningMessage = type === "malicious"
                ? "🚨 This site is malicious! Avoid entering sensitive data."
                : "⚠️ This site is suspicious. Proceed with caution.";

            chrome.tabs.sendMessage(tabs[0].id, { action: "showBanner", type }, (response) => {
                if (chrome.runtime.lastError) {
                    console.error("Error sending message:", chrome.runtime.lastError.message);
                } else {
                    console.log("Banner injected successfully.");
                }
            });

            chrome.notifications.create({
                type: "basic",
                iconUrl: "icons/icon.png",
                title: "Security Alert",
                message: warningMessage,
                priority: 2
            });

            sendResponse({ success: true });
        });
    }
});

document.addEventListener("DOMContentLoaded", function () {
    const checkBtn = document.getElementById("check-btn");
    const manualUrlInput = document.getElementById("manual-url");
    const urlDisplay = document.getElementById("url-display");
    const resultMessage = document.getElementById("result-message");
    const loadingSpinner = document.getElementById("loading-spinner");

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs.length > 0) {
            const currentUrl = tabs[0].url;
            urlDisplay.textContent = currentUrl;  
            checkBtn.disabled = false;  
        }
    });

    checkBtn.addEventListener("click", async () => {
        const urlToCheck = urlDisplay.textContent || manualUrlInput.value;  

        if (urlToCheck) {
            await scanUrl(urlToCheck);  
        } else {
            resultMessage.innerHTML = "<p style='color: red;'>⚠️ Please enter a valid URL to scan.</p>";
        }
    });
    async function scanUrl(url) {
        checkBtn.disabled = true;
        resultMessage.innerHTML = "";
        loadingSpinner.style.opacity = "1";

        try {
            await sendUrlToServer(url);  
        } catch (error) {
            console.error("❌ Error checking the URL:", error);
            resultMessage.innerHTML = "<p style='color: red;'>⚠️ Error checking the URL. Please try again.</p>";
        }

        setTimeout(() => {
            loadingSpinner.style.opacity = "0";
            checkBtn.disabled = false;
        }, 500);
    }
    async function sendUrlToServer(url) {
        try {
            const response = await fetch("http://127.0.0.1:5000/check_url", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url, source: "popup" })
            });

            if (!response.ok) {
                throw new Error("Network error");
            }

            const data = await response.json();

            const validResults = ["safe", "suspicious", "malicious"];
            let result = validResults.includes(data.result?.toLowerCase()) ? data.result.toLowerCase() : "unknown";  // Fallback to 'unknown' if invalid

            chrome.storage.local.get("lastCheckedUrls", (storedData) => {
                let lastCheckedUrls = storedData.lastCheckedUrls || {};
                lastCheckedUrls[url] = { result, timestamp: Date.now() };
                chrome.storage.local.set({ lastCheckedUrls });
            });

            displayResult(result);  
        } catch (error) {
            console.error("❌ Error in sendUrlToServer:", error);
            throw error;
        }
    }
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]?.id) {
        chrome.tabs.sendMessage(tabs[0].id, {
            action: "showBanner",
            type: result 
        }, (response) => {
            if (chrome.runtime.lastError) {
                console.warn("Could not send message to content script:", chrome.runtime.lastError.message);
            } else {
                console.log("Message sent to content script:", response);
            }
        });
    }
});
    function displayResult(result) {
        const color = result === "malicious" ? "red" :
                      result === "suspicious" ? "orange" : 
                      result === "safe" ? "green" : "gray";  

        resultMessage.innerHTML = `<p style="color: ${color}; font-weight: bold;">🚨 This URL is ${result}.</p>`;
    }

});

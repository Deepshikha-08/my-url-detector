console.log(" Script loaded and running!");

document.addEventListener("DOMContentLoaded", function () {
    let form = document.getElementById("urlForm");
    let resultMessage = document.getElementById("result-message");
    let whoisInfo = document.getElementById("whois-info");
    let loadingSpinner = document.getElementById("loading-spinner");
    let checkBtn = document.getElementById("check-btn");

    console.log("Debugging Elements:");
    console.log("Form:", form, "Result Message:", resultMessage, "Whois Info:", whoisInfo, "Spinner:", loadingSpinner, "Button:", checkBtn);

    if (!form || !resultMessage || !whoisInfo || !loadingSpinner || !checkBtn) {
        console.error(" Error: One or more required elements not found!");
        return;
    }

    form.addEventListener("submit", async function (event) {
        event.preventDefault();
        console.log("Form Submitted!");

        let urlInput = document.getElementById("url-input").value.trim();
        if (!urlInput) {
            resultMessage.innerHTML = `<p style="color: red; font-weight: bold;">⚠️ Please enter a valid URL!</p>`;
            return;
        }

        checkBtn.disabled = true;
        loadingSpinner.style.display = "block";
        resultMessage.innerHTML = "";
        whoisInfo.innerHTML = "";

        let controller = new AbortController();
        let timeout = setTimeout(() => controller.abort(), 8000);

        try {
            let response = await fetch("/check_url", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: urlInput }),
                signal: controller.signal
            });

            clearTimeout(timeout);

            if (!response.ok) {
                throw new Error(`Server Error (${response.status}): ${response.statusText}`);
            }

            let data = await response.json();
            console.log("🔍 Server Response:", data);

            resultMessage.innerHTML = `<p style="color: ${getResultColor(data.result)}; font-weight: bold;">${getResultMessage(data.result)}</p>`;

            whoisInfo.innerHTML = data.whois_data && !data.whois_data.error
                ? getWhoisHtml(data.whois_data, data.whois_link)
                : `<p style="color: gray;"> WHOIS data not available.</p>`;
        } catch (error) {
            console.error("Fetch error:", error);
            resultMessage.innerHTML = `<p style="color: red; font-weight: bold;">${error.message}</p>`;
        } finally {
            checkBtn.disabled = false;
            loadingSpinner.style.display = "none";
        }
    });

    loadAnalytics();

}); 
document.addEventListener("DOMContentLoaded", function () {
    const searchForm = document.getElementById("searchForm");
    if (!searchForm) {
        console.error(" Error: Search form not found!");
        return;
    }
    searchForm.addEventListener("submit", function (event) {
        event.preventDefault();
        console.log("Search submitted!");
    });
});


async function loadAnalytics() {
    try {
        let response = await fetch('/analytics/data');

        if (!response.ok) {
            throw new Error(`Server Error (${response.status}): ${response.statusText}`);
        }

        let contentType = response.headers.get("content-type");
        if (!contentType || !contentType.includes("application/json")) {
            throw new Error("Unexpected response format (not JSON). Received HTML instead.");
        }

        let data = await response.json();
        console.log("Analytics Data:", data);

        document.getElementById("total-checks").innerText = data.total_checks;
        document.getElementById("safe-count").innerText = data.safe_count;
        document.getElementById("suspicious-count").innerText = data.suspicious_count;
        document.getElementById("malicious-count").innerText = data.malicious_count;

        updateChart(data.safe_count, data.suspicious_count, data.malicious_count);
    } catch (error) {
        console.error(" Error loading analytics:", error);
    }
}

function updateChart(safe, suspicious, malicious) {
    let ctx = document.getElementById("analyticsChart").getContext("2d");
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Safe', 'Suspicious', 'Malicious'],
            datasets: [{
                label: 'URL Categories',
                data: [safe, suspicious, malicious],
                backgroundColor: ['#28a745', '#ffc107', '#dc3545'],
                borderWidth: 1
            }]
        },
        options: {
            responsive: false,
            maintainAspectRatio: false,
            scales: { y: { beginAtZero: true } },
            animation: { duration: 0 }
        }
    });
}

async function handleSearch() {
    let query = document.getElementById("search-input").value.trim();
    let searchResultsDiv = document.getElementById("search-results");

    if (!query) {
        searchResultsDiv.innerHTML = "<p style='color: red;'>⚠️ Enter a search term!</p>";
        return;
    }

    try {
        let response = await fetch('/search', {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ query })
        });

        let data = await response.json();
        searchResultsDiv.innerHTML = "";

        if (data.results.length === 0) {
            searchResultsDiv.innerHTML = "<p>No results found.</p>";
            return;
        }

        let resultsHtml = "<ul>";
        data.results.forEach(entry => {
            resultsHtml += `<li><strong>${entry.url}</strong> - ${entry.result} (${entry.date})</li>`;
        });
        resultsHtml += "</ul>";

        searchResultsDiv.innerHTML = resultsHtml;
    } catch (error) {
        console.error(" Search error:", error);
        searchResultsDiv.innerHTML = "<p style='color: red;'> Error searching. Try again later.</p>";
    }
}

function getResultColor(result) {
    return {
        "safe": "#28a745",
        "suspicious": "#ffc107",
        "malicious": "#dc3545"
    }[result] || "#6c757d";
}

function getResultMessage(result) {
    return {
        "safe": " This URL is Safe!",
        "suspicious": " This URL is Suspicious!",
        "malicious": " Warning! This URL is Malicious!"
    }[result] || "Unexpected response from server.";
}

function getWhoisHtml(whoisData, whoisLink) {
    return `
        <div style="margin-top: 5px; padding: 1px; border: 0px ; border-radius: 0px; background:  #0c213c ;">
            <h3 style="color: white;">Check WhoIs Information 👇 </h3>
            <p><a href="${whoisLink}"  target="_blank" class="whois-link"> View Full WHOIS</a></p>
        </div>
    `;
};

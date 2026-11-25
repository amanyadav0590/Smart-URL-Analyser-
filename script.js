"use strict";

// ========================================
// SMART URL ANALYZER
// ========================================

const urlInput = document.getElementById("urlInput");
const analyzeBtn = document.getElementById("analyzeBtn");

// ---------- URL ANALYSIS ----------

function analyzeURL() {
    const rawInput = urlInput.value.trim();

    if (!rawInput) {
        showError("Please enter a URL first.");
        return;
    }

    let url;

    try {
        // Add protocol if user did not enter it
        let input = rawInput;

        if (!/^https?:\/\//i.test(input)) {
            input = "https://" + input;
        }

        url = new URL(input);

        // Only HTTP and HTTPS are accepted
        if (!["http:", "https:"].includes(url.protocol)) {
            showError("Only HTTP and HTTPS URLs are supported.");
            return;
        }

        if (!url.hostname || !url.hostname.includes(".")) {
            showError("Please enter a valid domain name.");
            return;
        }

    } catch (error) {
        showError("Invalid URL! Please enter a correct website link.");
        return;
    }

    const result = checkURL(url);

    displayResult(result);

    saveHistory({
        url: url.href,
        risk: result.score,
        level: result.level,
        date: new Date().toLocaleString()
    });
}


// ---------- URL CHECKING ----------

function checkURL(url) {

    let score = 0;
    let warnings = [];
    let checks = [];

    const hostname = url.hostname.toLowerCase();
    const fullURL = url.href.toLowerCase();
    const pathname = url.pathname.toLowerCase();

    // 1. HTTPS CHECK
    if (url.protocol === "https:") {
        checks.push("HTTPS encryption is enabled.");
    } else {
        score += 15;
        warnings.push("Website is using HTTP instead of HTTPS.");
    }

    // 2. IP ADDRESS CHECK
    const ipPattern =
        /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

    if (ipPattern.test(hostname)) {
        score += 20;
        warnings.push("Website uses an IP address instead of a domain.");
    } else {
        checks.push("Domain name detected.");
    }

    // 3. URL SHORTENER CHECK
    const shortDomains = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "shorturl.at",
        "rebrand.ly",
        "rb.gy",
        "ow.ly",
        "buff.ly"
    ];

    if (shortDomains.includes(hostname)) {
        score += 20;
        warnings.push("Shortened URL detected. Destination is hidden.");
    }

    // 4. SUSPICIOUS WORDS IN DOMAIN
    const suspiciousWords = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "password",
        "signin",
        "banking",
        "wallet",
        "confirm",
        "free-gift",
        "claim",
        "support"
    ];

    const foundWords = suspiciousWords.filter(word =>
        hostname.includes(word)
    );

    if (foundWords.length > 0) {
        score += Math.min(foundWords.length * 5, 15);

        warnings.push(
            "Suspicious words found in domain: " +
            foundWords.join(", ")
        );
    }

    // 5. @ SYMBOL
    if (url.href.includes("@") || url.username || url.password) {
        score += 25;
        warnings.push("URL contains an @ symbol or user credentials.");
    }

    // 6. PUNYCODE CHECK
    if (hostname.includes("xn--")) {
        score += 20;
        warnings.push("Internationalized domain (Punycode) detected.");
    }

    // 7. MANY SUBDOMAINS
    const parts = hostname.split(".");

    if (parts.length > 4) {
        score += 10;
        warnings.push("Unusually large number of subdomains.");
    }

    // 8. VERY LONG URL
    if (url.href.length > 150) {
        score += 10;
        warnings.push("URL is unusually long.");
    }

    // 9. MANY HYPHENS IN DOMAIN
    const hyphenCount = (hostname.match(/-/g) || []).length;

    if (hyphenCount >= 4) {
        score += 10;
        warnings.push("Domain contains many hyphens.");
    }

    // 10. SUSPICIOUS FILE
    const riskyFiles = [
        ".exe",
        ".apk",
        ".bat",
        ".cmd",
        ".scr",
        ".msi",
        ".vbs",
        ".jar"
    ];

    if (riskyFiles.some(ext => pathname.endsWith(ext))) {
        score += 20;
        warnings.push("URL points to a potentially risky file.");
    }

    // 11. REDIRECT PARAMETERS
    const redirectParams = [
        "redirect",
        "redirect_url",
        "return",
        "return_url",
        "next",
        "continue",
        "url",
        "target"
    ];

    let redirectFound = false;

    for (const param of redirectParams) {
        const value = url.searchParams.get(param);

        if (value && /^https?:\/\//i.test(value)) {
            redirectFound = true;
            break;
        }
    }

    if (redirectFound) {
        score += 15;
        warnings.push("External redirect parameter detected.");
    }

    // 12. LOCAL / PRIVATE ADDRESS
    if (
        hostname === "localhost" ||
        hostname.endsWith(".local") ||
        hostname.startsWith("127.") ||
        hostname.startsWith("192.168.") ||
        hostname.startsWith("10.")
    ) {
        score += 10;
        warnings.push("Local or private network address detected.");
    }

    // 13. ENCODED CHARACTERS
    if (/%[0-9a-f]{2}/i.test(url.href)) {
        checks.push("URL contains encoded characters.");
    }

    // 14. QUERY PARAMETERS
    if (url.searchParams.size > 8) {
        score += 5;
        warnings.push("URL contains many query parameters.");
    }

    // Limit score
    score = Math.min(score, 100);

    // ---------- RISK LEVEL ----------

    let level;
    let title;
    let description;

    if (score <= 20) {
        level = "Low";
        title = "Low Risk Indicators";
        description =
            "No major suspicious patterns were detected. " +
            "This does not guarantee that the website is safe.";
    } else if (score <= 50) {
        level = "Medium";
        title = "Suspicious Indicators Found";
        description =
            "Some suspicious URL patterns were detected. " +
            "Verify the website before trusting it.";
    } else {
        level = "High";
        title = "High Risk Indicators";
        description =
            "Multiple suspicious patterns were detected. " +
            "Avoid entering sensitive information.";
    }

    return {
        url: url.href,
        domain: hostname,
        https: url.protocol === "https:" ? "Yes" : "No",
        score,
        level,
        title,
        description,
        warnings,
        checks
    };
}


// ---------- DISPLAY RESULT ----------

function displayResult(result) {

    document.getElementById("resultTitle").textContent =
        result.title;

    document.getElementById("resultDescription").textContent =
        result.description;

    document.getElementById("domainResult").textContent =
        result.domain;

    document.getElementById("httpsResult").textContent =
        result.https;

    document.getElementById("statusResult").textContent =
        "Not checked";

    document.getElementById("typeResult").textContent =
        getURLType(result.url);

    document.getElementById("riskResult").textContent =
        result.level;

    document.getElementById("scoreResult").textContent =
        result.score + "%";

    document.getElementById("riskHeading").textContent =
        result.level + " Risk";

    document.getElementById("riskDescription").textContent =
        result.description;

    document.getElementById("reportDomain").textContent =
        result.domain;

    document.getElementById("reportHttps").textContent =
        result.https;

    document.getElementById("reportType").textContent =
        getURLType(result.url);

    document.getElementById("reportRisk").textContent =
        result.level;

    // Risk circle
    const circle = document.getElementById("riskCircle");

    circle.style.background =
        `conic-gradient(#16a34a ${result.score * 3.6}deg, #e5e7eb 0deg)`;

    // Safety card
    const card = document.getElementById("safetyCard");

    card.style.borderColor =
        result.level === "High" ? "#ef4444" :
        result.level === "Medium" ? "#f59e0b" :
        "#16a34a";

    // Shield icon
    document.getElementById("shieldIcon").textContent =
        result.level === "High" ? "⚠️" :
        result.level === "Medium" ? "🟠" : "🛡️";

    // Bottom message
    document.getElementById("messageTitle").textContent =
        result.level === "High" ? "Be Careful!" :
        result.level === "Medium" ? "Verification Recommended" :
        "No Major Warning Found";

    document.getElementById("messageText").textContent =
        result.warnings.length > 0
            ? result.warnings.join(" ")
            : "No major suspicious URL patterns were detected.";

    // Show report
    document.getElementById("bottomMessage").style.display =
        "block";

    // Scroll to results
    document.getElementById("safetyCard").scrollIntoView({
        behavior: "smooth",
        block: "center"
    });
}


// ---------- URL TYPE ----------

function getURLType(urlString) {

    try {
        const url = new URL(urlString);

        if (url.hostname === "localhost") {
            return "Local Website";
        }

        if (url.pathname === "/" && !url.search) {
            return "Website";
        }

        if (url.search) {
            return "Web Page / Query";
        }

        return "Web Page";

    } catch {
        return "Unknown";
    }
}


// ---------- ERROR MESSAGE ----------

function showError(message) {

    document.getElementById("resultTitle").textContent =
        "Invalid URL";

    document.getElementById("resultDescription").textContent =
        message;

    document.getElementById("domainResult").textContent =
        "-";

    document.getElementById("httpsResult").textContent =
        "-";

    document.getElementById("statusResult").textContent =
        "-";

    document.getElementById("typeResult").textContent =
        "-";

    document.getElementById("riskResult").textContent =
        "-";

    document.getElementById("scoreResult").textContent =
        "-";

    document.getElementById("riskHeading").textContent =
        "Analysis Failed";

    document.getElementById("riskDescription").textContent =
        message;

    document.getElementById("messageTitle").textContent =
        "Please Check URL";

    document.getElementById("messageText").textContent =
        message;

    document.getElementById("reportDomain").textContent =
        "-";

    document.getElementById("reportHttps").textContent =
        "-";

    document.getElementById("reportType").textContent =
        "-";

    document.getElementById("reportRisk").textContent =
        "-";
}


// ---------- HISTORY ----------

function saveHistory(item) {

    let history = JSON.parse(
        localStorage.getItem("urlHistory") || "[]"
    );

    // Remove duplicate URL
    history = history.filter(
        entry => entry.url !== item.url
    );

    history.unshift(item);

    // Keep last 20 entries
    history = history.slice(0, 20);

    localStorage.setItem(
        "urlHistory",
        JSON.stringify(history)
    );

    displayHistory();
}


function displayHistory() {

    const historyList =
        document.getElementById("historyList");

    if (!historyList) return;

    const history = JSON.parse(
        localStorage.getItem("urlHistory") || "[]"
    );

    historyList.innerHTML = "";

    if (history.length === 0) {
        historyList.textContent =
            "No analysis history available.";
        return;
    }

    history.forEach(item => {

        const div = document.createElement("div");
        div.className = "history-item";

        const title = document.createElement("p");
        title.textContent = item.url;

        const info = document.createElement("p");
        info.textContent =
            `Risk: ${item.level} | Score: ${item.risk}% | ${item.date}`;

        const button = document.createElement("button");
        button.textContent = "Analyze Again";

        button.addEventListener("click", () => {
            urlInput.value = item.url;

            switchPage("analyzer");

            analyzeURL();
        });

        div.appendChild(title);
        div.appendChild(info);
        div.appendChild(button);

        historyList.appendChild(div);
    });
}


// ---------- CLEAR HISTORY ----------

const clearHistoryBtn =
    document.getElementById("clearHistory");

if (clearHistoryBtn) {

    clearHistoryBtn.addEventListener("click", () => {

        if (confirm("Are you sure you want to clear history?")) {

            localStorage.removeItem("urlHistory");

            displayHistory();
        }
    });
}


// ---------- NAVIGATION ----------

function switchPage(pageName) {

    document.querySelectorAll(".page").forEach(page => {
        page.style.display = "none";
    });

    const selectedPage =
        document.getElementById(pageName);

    if (selectedPage) {
        selectedPage.style.display = "block";
    }

    document.querySelectorAll("[data-page]").forEach(btn => {
        btn.classList.remove("active");
    });

    const activeButton =
        document.querySelector(`[data-page="${pageName}"]`);

    if (activeButton) {
        activeButton.classList.add("active");
    }

    if (pageName === "history") {
        displayHistory();
    }
}


// ---------- NAV BUTTONS ----------

document.querySelectorAll("[data-page]").forEach(button => {

    button.addEventListener("click", () => {

        const pageName = button.dataset.page;

        switchPage(pageName);
    });
});


// ---------- ANALYZE BUTTON ----------

if (analyzeBtn) {
    analyzeBtn.addEventListener("click", analyzeURL);
}


// ---------- ENTER KEY ----------

if (urlInput) {

    urlInput.addEventListener("keydown", event => {

        if (event.key === "Enter") {
            analyzeURL();
        }
    });
}


// ---------- START ----------

displayHistory();
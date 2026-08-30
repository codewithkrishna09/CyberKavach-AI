// CyberKavach extension popup: local session, current-site result and feedback.
document.addEventListener("DOMContentLoaded", async () => {
    const API_URL = globalThis.CYBERKAVACH_API_URL;
    const DASHBOARD_URL = globalThis.CYBERKAVACH_DASHBOARD_URL;
    const ui = {
        statusIcon: document.getElementById("statusIcon"), verdict: document.getElementById("verdict"),
        urlDisplay: document.getElementById("url"), riskScore: document.getElementById("riskScore"),
        riskBar: document.getElementById("riskBar"), btnDashboard: document.getElementById("btnDashboard"),
        feedbackPanel: document.getElementById("feedbackPanel"), btnWrongAlert: document.getElementById("btnWrongAlert"),
        btnReportScam: document.getElementById("btnReportScam"), feedbackStatus: document.getElementById("feedbackStatus"),
    };
    let feedbackTarget = "";

    const makeSessionKey = () => {
        const bytes = crypto.getRandomValues(new Uint8Array(16));
        return "CK-LOCAL-" + Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
    };
    async function sessionKey() {
        const saved = await chrome.storage.local.get(["sessionKey"]);
        if (saved.sessionKey) return saved.sessionKey;
        const key = makeSessionKey();
        await chrome.storage.local.set({ sessionKey: key });
        return key;
    }
    const text = (element, value) => { if (element) element.textContent = value; };
    const style = (element, property, value) => { if (element) element.style[property] = value; };
    function showFeedback(available) {
        ui.feedbackPanel?.classList.toggle("hidden", !available);
        if (!available) text(ui.feedbackStatus, "");
    }
    function updateIcon(color, icon = "shield") {
        const content = icon === "alert"
            ? '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/>'
            : '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>';
        ui.statusIcon.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">${content}</svg>`;
    }
    function renderResult(data) {
        const score = Number(data.risk_score) || 0;
        text(ui.verdict, data.display_verdict || data.status || "SCAN COMPLETE");
        text(ui.riskScore, `${score}/100`);
        style(ui.riskBar, "width", `${Math.max(0, Math.min(score, 100))}%`);
        document.body.classList.remove("safe", "danger");
        const risky = data.status === "PHISHING" || data.status === "MALWARE" || data.status === "SUSPICIOUS" || score > 35;
        document.body.classList.add(risky ? "danger" : "safe");
        updateIcon(risky ? (score >= 65 ? "#ef4444" : "#f59e0b") : "#10b981", risky ? "alert" : "shield");
    }
    async function scanActiveTab() {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        showFeedback(false);
        if (!tab?.url || !tab.url.startsWith("http")) {
            feedbackTarget = "";
            text(ui.urlDisplay, "Open a website to scan");
            renderResult({ display_verdict: "READY TO SCAN", risk_score: 0 });
            return;
        }
        feedbackTarget = tab.url;
        text(ui.urlDisplay, new URL(tab.url).hostname);
        text(ui.verdict, "CHECKING SITE...");
        try {
            const response = await fetch(`${API_URL}/scan`, {
                method: "POST",
                headers: { "Content-Type": "application/json", "x-api-key": await sessionKey(), "x-scan-mode": "extension-background" },
                body: JSON.stringify({ url: tab.url }),
            });
            if (!response.ok) throw new Error("scan failed");
            renderResult(await response.json());
            showFeedback(true);
        } catch (_) {
            text(ui.verdict, "SERVER UNAVAILABLE");
            text(ui.urlDisplay, "Check the backend connection");
            updateIcon("#64748b", "shield");
        }
    }
    async function submitFeedback(feedbackType) {
        if (!feedbackTarget) return text(ui.feedbackStatus, "Open a website first.");
        const buttons = [ui.btnWrongAlert, ui.btnReportScam].filter(Boolean);
        buttons.forEach(button => { button.disabled = true; });
        text(ui.feedbackStatus, "Sending feedback...");
        try {
            const response = await fetch(`${API_URL}/scan-feedback`, {
                method: "POST", headers: { "Content-Type": "application/json", "x-api-key": await sessionKey() },
                body: JSON.stringify({ target: feedbackTarget, feedback_type: feedbackType }),
            });
            if (!response.ok) throw new Error("feedback failed");
            text(ui.feedbackStatus, "Feedback saved.");
        } catch (_) {
            text(ui.feedbackStatus, "Could not save feedback.");
        } finally {
            buttons.forEach(button => { button.disabled = false; });
        }
    }
    ui.btnWrongAlert?.addEventListener("click", () => submitFeedback("false_positive"));
    ui.btnReportScam?.addEventListener("click", () => submitFeedback("reported_scam"));
    ui.btnDashboard?.addEventListener("click", async () => {
        chrome.tabs.create({ url: `${DASHBOARD_URL}#key=${encodeURIComponent(await sessionKey())}` });
    });
    scanActiveTab();
});

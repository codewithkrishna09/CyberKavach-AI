// ==========================================
// 🛡️ CyberKavach AI - TITAN CORE (V26.0)
// ==========================================

importScripts("config.js");
const API_URL = globalThis.CYBERKAVACH_API_URL;
const BLOCK_PAGE = "blocked.html";
const createSessionKey = () => {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    return "CK-LOCAL-" + Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
};

// 🚀 NAVIGATION TRACKER (Prevents infinite loops & spam)
const LAST_SCANNED_URL = new Map();

// Legacy reference list. It is deliberately not used as a scan bypass: trusted
// brands can have compromised pages, and lookalike subdomains are common.
const SAFE_ROOTS = new Set([
    // 🌐 GLOBAL GIANTS & DEV TOOLS
    "google.com", "youtube.com", "facebook.com", "twitter.com", "x.com",
    "instagram.com", "linkedin.com", "amazon.com", "netflix.com", 
    "microsoft.com", "apple.com", "whatsapp.com", "github.com", 
    "stackoverflow.com", "reddit.com", "chatgpt.com", "openai.com", 
    "bing.com", "yahoo.com", "wikipedia.org", "zoom.us",
    
    // 🛒 INDIAN E-COMMERCE & QUICK COMMERCE
    "amazon.in", "flipkart.com", "myntra.com", "meesho.com", "ajio.com", 
    "snapdeal.com", "jiomart.com", "tatacliq.com", "nykaa.com", "lenskart.com",
    "zomato.com", "swiggy.com", "blinkit.com", "zepto.com", "bigbasket.com",
    
    // 🏦 INDIAN BANKING, UPI & FINANCE (High Priority)
    "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com", "axisbank.com", 
    "kotak.com", "pnbindia.in", "bankofbaroda.in", "paytm.com", "phonepe.com", 
    "cred.club", "groww.in", "upstox.com", "zerodha.com", "npci.org.in", "bseindia.com",

    // 🚂 INDIAN GOVT, UTILITIES & TRAVEL
    // Do not whitelist a public suffix such as gov.in: a compromised or hostile
    // subdomain must still be scanned. Keep only verified service domains here.
    "uidai.gov.in", "irctc.co.in", "incometax.gov.in", "cowin.gov.in",
    "digilocker.gov.in", "mca.gov.in", "epfindia.gov.in", "parivahan.gov.in",
    "makemytrip.com", "goibibo.com", "yatra.com", "cleartrip.com", "bookmyshow.com",

    // 🍿 ENTERTAINMENT & TELECOM
    "hotstar.com", "jiocinema.com", "sonyliv.com", "zee5.com",
    "jio.com", "airtel.in", "vi.com"
]);

// 🧠 NEURAL CACHE (Optimized Memory Management for Manifest V3)
const RESULTS_CACHE = new Map();
const CACHE_TTL = 15 * 60 * 1000; // 15 mins
const MAX_CACHE_SIZE = 1000;      // Safety limit
const MAX_SCAN_URL_LENGTH = 2048;
const TEMPORARY_ALLOWLIST = new Map();
const ALLOW_TTL = 10 * 60 * 1000;
const URL_SHORTENERS = new Set([
    "bit.ly", "bitly.com", "t.co", "tinyurl.com", "goo.gl", "is.gd",
    "cutt.ly", "shorturl.at", "rb.gy", "rebrand.ly", "tiny.cc"
]);
const RISKY_DOWNLOAD_EXTENSIONS = /\.(apk|exe|msi|dmg|pkg|scr|bat|cmd|ps1|js|vbs|jar|iso|zip|rar|7z)$/i;

function localUrlAssessment(url) {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();
    const signals = [];
    let score = 0;
    const isIpHost = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host);
    const labels = host.split('.').filter(Boolean);
    const branded = /(sbi|hdfc|icici|axis|paytm|phonepe|gpay|aadhaar|uidai|indiapost|amazon|flipkart)/.test(`${host}${parsed.pathname}`);
    const action = /(login|verify|update|kyc|secure|account|refund|wallet|blocked)/.test(`${host}${parsed.pathname}`);

    if (isIpHost) { score += 35; signals.push('IP address used instead of a domain'); }
    if (parsed.username || parsed.password || parsed.href.includes('@')) { score += 45; signals.push('URL contains credential-style @ redirection'); }
    if (host.includes('xn--')) { score += 35; signals.push('Punycode domain may impersonate another brand'); }
    if (labels.length > 4) { score += 20; signals.push('Excessive subdomains'); }
    // Search terms and tracking parameters can be long on normal sites. Score
    // only the visible domain/path structure, not an arbitrary query string.
    const structuralUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
    if (structuralUrl.length > 150) { score += 10; signals.push('Unusually long URL'); }
    if (branded && action) { score += 30; signals.push('Brand name paired with credential/urgency language'); }
    if (/\.(zip|mov|top|xyz|click|gq|tk|ml|ga|cf)$/.test(host)) { score += 15; signals.push('High-abuse domain suffix'); }
    if (parsed.protocol === 'http:' && action) { score += 25; signals.push('Sensitive action over unencrypted HTTP'); }
    if (URL_SHORTENERS.has(host) || [...URL_SHORTENERS].some(domain => host.endsWith(`.${domain}`))) {
        score += 15;
        signals.push('Short link hides the final destination');
    }
    if (labels.some(label => (label.match(/-/g) || []).length >= 2)) {
        score += 8;
        signals.push('Multiple hyphens in domain can indicate a lookalike link');
    }
    if (/%(?:2f|2e|5c|40|3f|23)/i.test(url)) {
        score += 10;
        signals.push('Encoded URL characters can hide the real destination');
    }
    let decodedPath = parsed.pathname;
    try { decodedPath = decodeURIComponent(parsed.pathname); } catch (_) { /* keep raw path */ }
    if (RISKY_DOWNLOAD_EXTENSIONS.test(decodedPath)) {
        score += 20;
        signals.push('Direct link to a potentially risky download');
    }
    for (const key of ['url', 'redirect', 'redirect_uri', 'next', 'return', 'continue', 'destination', 'target']) {
        const value = parsed.searchParams.get(key);
        if (!value) continue;
        try {
            const target = new URL(value);
            if (target.hostname !== host) {
                score += 12;
                signals.push('Redirect parameter points to another domain');
                break;
            }
        } catch (_) {
            // Non-URL values are harmless for this local, no-network check.
        }
    }
    return { score: Math.min(100, score), signals };
}

// ==========================================
// 🛠️ SYSTEM INITIALIZATION & MEMORY SWEEP
// ==========================================

chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: "cyberkavachScan",
        title: "🛡️ Run Deep Node Scan",
        contexts: ["link"]
    });
    
    // Create a local anonymous identifier only for separating local history.
    chrome.storage.local.get(['sessionKey'], (storage) => {
        if (!storage.sessionKey) {
            chrome.storage.local.set({ sessionKey: createSessionKey() });
        }
    });

    console.log("🚀 CyberKavach Titan Core : Online & Synced");
});

// Periodic Cache Cleanup (Prevents Chrome RAM spikes)
setInterval(() => {
    if (RESULTS_CACHE.size > MAX_CACHE_SIZE) {
        const now = Date.now();
        for (const [url, data] of RESULTS_CACHE.entries()) {
            if (now - data.timestamp > CACHE_TTL) RESULTS_CACHE.delete(url);
        }
    }
}, 5 * 60 * 1000); // Run every 5 mins

// Context Menu Action (Manual Deep Scan from Right-Click)
chrome.contextMenus.onClicked.addListener(async (info) => {
    if (info.menuItemId === "cyberkavachScan" && info.linkUrl) {
        const domain = new URL(info.linkUrl).hostname;
        
        chrome.notifications.create({ 
            type: 'basic', 
            iconUrl: 'icons/icon48.png', 
            title: '🔍 Titan Neural Handshake...', 
            message: `Analyzing node: ${domain}`
        });
        
        const data = await requestNeuralScan(info.linkUrl);
        
        const isSafe = data.status === 'SAFE';
        chrome.notifications.create({ 
            type: 'basic', 
            iconUrl: 'icons/icon48.png', 
            title: `${isSafe ? '✅' : '🚨'} Verdict: ${data.status}`, 
            message: `Risk Score: ${data.risk_score}% \nDetails: ${data.ai_analysis ? data.ai_analysis[0] : 'Scanned via Backend.'}`
        });
    }
});

// ==========================================
// 🕵️ TRAFFIC INTERCEPTOR (Thread Safe)
// ==========================================

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Only trigger when page actually starts loading a URL
    if (changeInfo.status === 'loading' && tab.url) {
        const url = tab.url;

        // 1. Only web navigations can be sent to the HTTP scanner. Browser,
        // extension, file and oversized URLs must never be treated as an API
        // outage or consume an unnecessary request.
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            updateBadge(tabId, "SKIP", "#64748b");
            return;
        }
        if (url.length > MAX_SCAN_URL_LENGTH || url.includes(BLOCK_PAGE)) {
            updateBadge(tabId, "SKIP", "#64748b");
            return;
        }

        // 2. Strict Debouncing (Stops redundant API calls if tab refreshes multiple times quickly)
        if (LAST_SCANNED_URL.get(tabId) === url) return;
        LAST_SCANNED_URL.set(tabId, url);

        // 3. Dispatch to Neural Pipeline
        executeSecurePipeline(tabId, url);
    }
});

// Memory Cleanup on Tab Close
chrome.tabs.onRemoved.addListener((tabId) => {
    LAST_SCANNED_URL.delete(tabId);
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.action === 'ALLOW_TEMPORARILY' && typeof message.url === 'string') {
        TEMPORARY_ALLOWLIST.set(message.url, Date.now() + ALLOW_TTL);
        sendResponse({ ok: true });
    }
    if (message?.action === 'PAGE_RISK' && _sender.tab?.id && _sender.tab.url) {
        // Content scripts report only structural signals (for example an HTTP
        // password form), never typed form data. This gives an early warning
        // while the server-side review is still running.
        applyVerdict(_sender.tab.id, _sender.tab.url, {
            status: 'SUSPICIOUS', risk_score: Number(message.score) || 0,
            ai_analysis: Array.isArray(message.reasons) ? message.reasons : [],
            user_message: 'Check this page before entering any information.'
        });
        sendResponse({ ok: true });
    }
});

// ==========================================
// 🚀 TITAN SECURE PIPELINE
// ==========================================

async function executeSecurePipeline(tabId, url) {
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname.toLowerCase();
        
        // 🛡️ LAYER 1: GOD MODE (Local/Dev Bypass)
        if (hostname === "localhost" || hostname === "127.0.0.1" || hostname.startsWith("192.168.") || hostname.startsWith("10.") || hostname.endsWith(".local")) {
            updateBadge(tabId, "DEV", "#64748b");
            return;
        }

        // 🛡️ LAYER 2: User-approved temporary exception. It expires in ten
        // minutes and is never a permanent blind spot.
        const allowUntil = TEMPORARY_ALLOWLIST.get(url);
        if (allowUntil && allowUntil > Date.now()) {
            updateBadge(tabId, "ALLOW", "#f59e0b");
            return;
        }
        TEMPORARY_ALLOWLIST.delete(url);

        // 🛡️ LAYER 3: Instant local checks protect even while the API is down.
        const local = localUrlAssessment(url);
        if (local.score >= 70) {
            applyVerdict(tabId, url, { status: "SUSPICIOUS", risk_score: local.score, ai_analysis: local.signals });
            return;
        }

        // 🛡️ LAYER 4: IN-MEMORY CACHE ACCELERATOR
        const cached = RESULTS_CACHE.get(url);
        if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
            applyVerdict(tabId, url, cached.data);
            return;
        }

        // 🛡️ LAYER 5: TITAN CLOUD SCAN (Backend API Call)
        updateBadge(tabId, "...", "#4f46e5"); // Indigo Scanning state
        const data = await requestNeuralScan(url);

        // Cache successful results so repeat navigation stays responsive.
        if (!data.error && data.status !== "OFFLINE") {
            RESULTS_CACHE.set(url, { data: data, timestamp: Date.now() });
        }
        
        applyVerdict(tabId, url, data);

    } catch (e) {
        console.error("Titan Pipeline Error:", e);
        updateBadge(tabId, "ERR", "#64748b");
    }
}

// --- API BRIDGE ---
async function requestNeuralScan(url) {
    const storage = await chrome.storage.local.get(["sessionKey"]);
    let apiKey = storage.sessionKey;
    if (!apiKey) {
        apiKey = createSessionKey();
        chrome.storage.local.set({ sessionKey: apiKey });
    }

    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), 6000); // Aggressive 6s timeout to prevent lag

    try {
        const response = await fetch(`${API_URL}/scan`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json', 
                'x-api-key': apiKey,
                // Marks a browser navigation scan for dashboard history only.
                'x-scan-mode': 'extension-background'
            },
            body: JSON.stringify({ url: url }),
            signal: controller.signal
        });
        
        clearTimeout(id);
        
        if (response.status === 422 || response.status === 400) {
            const details = await response.json().catch(() => ({}));
            return { status: "SKIPPED", risk_score: 0, reason: details.detail || "This browser URL cannot be scanned." };
        }
        if (!response.ok) throw new Error(`Server Error (${response.status})`);
        
        const responseData = await response.json();
        
        return responseData;

    } catch (error) {
        clearTimeout(id);
        return { error: true, status: "OFFLINE", risk_score: 0 };
    }
}

// --- VERDICT ENFORCER ---
function applyVerdict(tabId, url, data) {
    if (data.error || data.status === "OFFLINE") {
        updateBadge(tabId, "OFF", "#64748b"); // Slate
        return;
    }

    if (data.status === "SKIPPED" || data.status === "REJECTED") {
        updateBadge(tabId, "SKIP", "#64748b");
        return;
    }

    // Risk Parsing
    const isDangerous = data.status === "PHISHING" || data.status === "MALWARE" || data.risk_score >= 65;
    const isSuspicious = data.status === "SUSPICIOUS" || (data.risk_score > 35 && data.risk_score < 65);

    // Defense Activation
    if (isDangerous) {
        updateBadge(tabId, "BLOK", "#ef4444"); // Red Block
        const reason = (data.ai_analysis && data.ai_analysis.length > 0) ? data.ai_analysis[0] : "Malicious Signature Detected";
        const redirect = `${chrome.runtime.getURL(BLOCK_PAGE)}?target=${encodeURIComponent(url)}&reason=${encodeURIComponent(reason)}&score=${data.risk_score}`;
        chrome.tabs.update(tabId, { url: redirect });
    } 
    else if (isSuspicious) {
        updateBadge(tabId, "WARN", "#f59e0b"); // Orange Warning
        const reasons = data.ai_analysis || ["Heuristic Anomalies Found"];
        
        // 🚀 FIRE THE SENTINEL CONTENT SCRIPT 🚀
        // Tell content.js to show the Banner & Lock inputs
        chrome.tabs.sendMessage(tabId, {
            action: "ALERT_USER",
            risk_score: data.risk_score,
            reason: reasons,
            severity: "warn",
            message: data.user_message || "Check this page before entering any information."
        }).catch(err => {
            // Ignore error if content script hasn't loaded yet
            console.log("Could not trigger content script immediately.");
        });

    } else {
        updateBadge(tabId, "SAFE", "#10b981"); // Green Safe
    }
}

// --- UI UTILS ---
function updateBadge(tabId, text, color) {
    try {
        chrome.action.setBadgeText({ text, tabId });
        chrome.action.setBadgeBackgroundColor({ color, tabId });
    } catch (e) {
        // Suppress errors if tab was closed before API returned
    }
}

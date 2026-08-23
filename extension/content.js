// ==================================================
// 🛡️ CYBERKAVACH AI - SENTINEL CONTENT ENGINE (V12.5)
// ==================================================

// 🚀 CRITICAL: Dashboard, Localhost aur safe domains ko Sentinel se bahar rakho
const isInternalNode = () => {
    const { protocol, hostname } = window.location;
    return protocol === "chrome-extension:" ||
        hostname === "localhost" ||
        hostname === "127.0.0.1" ||
        hostname.endsWith(".localhost");
};

if (isInternalNode()) {
    console.log("%c🟢 CyberKavach: Internal Dashboard Detected. Sentinel Standby.", "color: #10b981; font-weight: bold;");
} else {
    console.log("%c⚡ CyberKavach AI: Sentinel Active & Monitoring", "color: #06b6d4; font-weight: bold; font-size: 12px;");

    // ==================================================
    // 1. LISTEN FOR REAL-TIME THREAT COMMANDS FROM BACKGROUND
    // ==================================================
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.action === "ALERT_USER") {
            // Double security check
            if (isInternalNode()) return;

            const shouldBlock = request.severity === "block" || Number(request.risk_score) >= 65;
            console.warn(`CyberKavach warning. Score: ${request.risk_score}`);

            // Only lock a page when evidence is strong. A warning should not
            // break legitimate sign-in pages that use third-party providers.
            if (shouldBlock) {
                lockSensitiveInputs();
                blurPageContent();
                highlightScamElements();
            }
            showShadowBanner(request.risk_score, request.reason, shouldBlock, request.message);

            sendResponse({status: shouldBlock ? "locked_down" : "warning_shown"});
        }
    });

    // ==================================================
    // 2. CLIENT-SIDE HEURISTICS (INSTANT CHECKS)
    // ==================================================
    // Check for HTTP Passwords
    document.addEventListener('focusin', (e) => {
        if (isInternalNode()) return;

        const target = e.target;
        if (target.type === 'password' && window.location.protocol === 'http:') {
            showToast("🚨 INSECURE CONNECTION: Passwords entered here can be intercepted by hackers.", "danger");
            target.style.outline = "4px solid #ef4444";
            target.style.animation = "pulseRed 1s infinite";
        }
    }, true);

    // This check runs locally before the cloud result returns. It never reads
    // typed values; it only inspects form destinations already visible in DOM.
    const reportedPageSignals = new Set();
    function reportPageRisk(score, reason) {
        if (reportedPageSignals.has(reason)) return;
        reportedPageSignals.add(reason);
        chrome.runtime.sendMessage({ action: "PAGE_RISK", score, reasons: [reason] }).catch(() => {});
    }
    function inspectCredentialForms() {
        const passwordFields = document.querySelectorAll("input[type='password']");
        if (!passwordFields.length) return;
        if (window.location.protocol === "http:") {
            reportPageRisk(85, "This page asks for a password over an insecure connection.");
        }
        for (const form of document.querySelectorAll("form")) {
            const action = form.getAttribute("action") || window.location.href;
            try {
                const actionUrl = new URL(action, window.location.href);
                if (actionUrl.hostname && actionUrl.hostname !== window.location.hostname) {
                    reportPageRisk(50, "This page sends sign-in information to a different domain.");
                }
            } catch (_) {
                // Invalid form actions are ignored here; the backend scanner
                // will provide a separate safe verdict if it can inspect them.
            }
        }
    }
    setTimeout(inspectCredentialForms, 300);

    // Disable Right Click & Copy on Suspicious Pages if commanded
    document.addEventListener('copy', (e) => {
        if(document.body.classList.contains('cyberkavach-locked')) {
            e.preventDefault();
            showToast("⚠️ Copying data from this malicious page is blocked.", "danger");
        }
    });
}

// ==================================================
// 🔒 3. INPUT LOCKDOWN (Prevent Data Exfiltration)
// ==================================================
function lockSensitiveInputs() {
    if (isInternalNode()) return; // Safety Lock
    
    document.body.classList.add('cyberkavach-locked');

    // Select all forms of sensitive inputs
    const selectors = [
        "input[type='password']", "input[type='email']", "input[name*='user']", 
        "input[name*='card']", "input[name*='cvv']", "input[name*='pin']",
        "input[id*='otp']", "input[name*='otp']", "textarea"
    ];
    
    const inputs = document.querySelectorAll(selectors.join(","));

    inputs.forEach(input => {
        input.setAttribute("disabled", "true");
        input.style.filter = "grayscale(100%) opacity(0.5)";
        input.style.border = "2px solid #ef4444 !important";
        input.style.cursor = "not-allowed";
        input.style.backgroundColor = "#fee2e2"; // Light red
        
        if(input.type !== "password") {
            input.value = "🔒 PROTECTED BY CYBERKAVACH";
        }
    });

    // Disable all submit/login buttons
    const killList = ["button", "input[type='submit']", "input[type='button']", "[role='button']"];
    document.querySelectorAll(killList.join(",")).forEach(btn => {
        const text = btn.innerText?.toLowerCase() || btn.value?.toLowerCase() || "";
        // Only block buttons that sound like action buttons to avoid breaking the whole page layout
        if (text.match(/(login|sign|pay|submit|verify|confirm|checkout|buy|update|kyc)/)) {
            btn.disabled = true;
            btn.style.pointerEvents = "none";
            btn.style.background = "#334155";
            btn.style.color = "#94a3b8";
            btn.style.border = "1px solid #475569";
            btn.innerText = "🚫 Action Blocked";
        }
    });
}

// ==================================================
// 🌑 4. UI MANIPULATION (Defensive Masking)
// ==================================================
function blurPageContent() {
    if (isInternalNode()) return;
    
    const style = document.createElement('style');
    style.id = "cyberkavach-blur-css";
    style.innerHTML = `
        body > *:not(#cyberkavach-host) {
            filter: blur(6px) grayscale(60%) !important;
            pointer-events: none !important;
            user-select: none !important;
            transition: filter 0.8s ease;
        }
        @keyframes pulseRed {
            0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }
            70% { box-shadow: 0 0 0 15px rgba(239, 68, 68, 0); }
            100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
        }
    `;
    document.head.appendChild(style);
}

function highlightScamElements() {
    if (isInternalNode()) return;

    // Highlight Urgency keywords
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
    let node;
    const regex = /(urgent|immediate|blocked|suspend|kyc|pan|adhar|reward|lottery|free)/gi;
    
    while (node = walker.nextNode()) {
        if (node.parentNode.nodeName !== 'SCRIPT' && node.parentNode.nodeName !== 'STYLE') {
            if (regex.test(node.nodeValue)) {
                // We wrap the text in a red border
                const span = document.createElement('span');
                span.style.borderBottom = "2px dashed #ef4444";
                span.style.backgroundColor = "rgba(239, 68, 68, 0.1)";
                span.style.color = "#ef4444";
                node.parentNode.insertBefore(span, node);
                span.appendChild(node);
            }
        }
    }
}

// ==================================================
// 🖥️ 5. SHADOW DOM BANNER (Unhackable UI)
// ==================================================
function showShadowBanner(score, reasons, isBlocking = false, userMessage = "") {
    if (isInternalNode()) return;
    score = Math.max(0, Math.min(100, Number(score) || 0));

    // If banner already exists, don't recreate
    if (document.getElementById('cyberkavach-host')) return;

    // 1. Create a Host Element
    const host = document.createElement('div');
    host.id = 'cyberkavach-host';
    host.style.position = 'fixed';
    host.style.top = '0';
    host.style.left = '0';
    host.style.width = '100%';
    host.style.height = '100%';
    host.style.zIndex = '2147483647'; // Max z-index possible
    host.style.pointerEvents = 'none'; // Let clicks pass through to banner buttons only
    document.body.appendChild(host);

    // 2. Attach Shadow DOM (This prevents website's CSS from breaking our banner)
    const shadowRoot = host.attachShadow({ mode: 'closed' });

    // Format Reasons for HTML
    let reasonsHtml = "";
    if (Array.isArray(reasons) && reasons.length > 0) {
        const escapeHtml = value => String(value).replace(/[&<>'"]/g, char => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
        })[char]);
        reasonsHtml = `<ul class="pg-reasons">` + reasons.map(r => `<li>> ${escapeHtml(r)}</li>`).join('') + `</ul>`;
    } else {
        reasonsHtml = `<p class="pg-reasons">> We found warning signs on this page.</p>`;
    }

    // 3. Inject CSS and HTML into Shadow DOM
    shadowRoot.innerHTML = `
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;700;900&display=swap');
            
            .pg-overlay {
                position: absolute;
                top: 20px;
                left: 50%;
                transform: translateX(-50%);
                width: 90%;
                max-width: 600px;
                background: #0f0f12;
                border: 2px solid #ef4444;
                border-top: 6px solid #ef4444;
                border-radius: 16px;
                box-shadow: 0 20px 50px rgba(239, 68, 68, 0.4), 0 0 0 100vw rgba(0,0,0,0.5);
                font-family: 'Inter', sans-serif;
                color: white;
                pointer-events: auto; /* Re-enable clicks for this box */
                animation: pgSlideDown 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275) forwards;
                overflow: hidden;
            }

            @keyframes pgSlideDown {
                from { top: -200px; opacity: 0; }
                to { top: 20px; opacity: 1; }
            }

            .pg-header {
                display: flex;
                align-items: center;
                gap: 15px;
                padding: 20px;
                background: rgba(239, 68, 68, 0.1);
                border-bottom: 1px solid rgba(239, 68, 68, 0.2);
            }

            .pg-icon {
                width: 40px; height: 40px;
                background: #ef4444;
                border-radius: 50%;
                display: flex; align-items: center; justify-content: center;
                font-size: 24px; font-weight: bold;
                animation: pgPulse 1.5s infinite;
            }

            @keyframes pgPulse {
                0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }
                70% { box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); }
                100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
            }

            .pg-title { margin: 0; font-size: 24px; font-weight: 900; color: #fca5a5; text-transform: uppercase; letter-spacing: 1px;}
            .pg-subtitle { margin: 5px 0 0 0; font-size: 14px; color: #cbd5e1; }

            .pg-body { padding: 20px; }
            
            .pg-reasons {
                background: #18181b;
                border: 1px solid #27272a;
                border-left: 4px solid #ef4444;
                padding: 15px 15px 15px 30px;
                margin: 0 0 20px 0;
                border-radius: 8px;
                font-family: monospace;
                color: #f87171;
                font-size: 13px;
                list-style: none;
            }
            .pg-reasons li { margin-bottom: 8px; }
            .pg-reasons li:last-child { margin-bottom: 0; }

            .pg-footer {
                padding: 15px 20px;
                background: #09090b;
                display: flex;
                justify-content: space-between;
                align-items: center;
                border-top: 1px solid #27272a;
            }

            .pg-score { font-size: 12px; color: #94a3b8; font-weight: bold; text-transform: uppercase;}
            .pg-score span { font-size: 18px; color: #ef4444; font-family: monospace;}

            .pg-btn {
                background: #ef4444;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 8px;
                font-weight: bold;
                font-size: 14px;
                cursor: pointer;
                transition: background 0.2s;
            }
            .pg-btn:hover { background: #dc2626; }
            
            .pg-link {
                color: #94a3b8;
                font-size: 12px;
                text-decoration: underline;
                cursor: pointer;
                background: none; border: none;
            }
            .pg-link:hover { color: white; }

        </style>

        <div class="pg-overlay">
            <div class="pg-header">
                <div class="pg-icon">!</div>
                <div>
                    <h1 class="pg-title">${isBlocking ? "SITE BLOCKED" : "BE CAREFUL"}</h1>
                    <p class="pg-subtitle">${isBlocking ? "We blocked this page to protect your information." : "Please verify this page before entering any details."}</p>
                </div>
            </div>
            
            <div class="pg-body">
                ${reasonsHtml}
                <p style="font-size: 13px; color: #94a3b8; margin: 0;">${userMessage || (isBlocking ? "Sign-in and payment fields are disabled for your safety." : "Do not share passwords, OTPs, card details, or UPI PINs until you confirm the site.")}</p>
            </div>

            <div class="pg-footer">
                <div class="pg-score">Risk Score: <span>${score}%</span></div>
                <div style="display: flex; gap: 15px; align-items: center;">
                    <button class="pg-link" id="pg-ignore">${isBlocking ? "Close warning" : "Continue carefully"}</button>
                    <button class="pg-btn" id="pg-safe">Go back</button>
                </div>
            </div>
        </div>
    `;

    // 4. Attach Event Listeners inside Shadow DOM
    const btnSafe = shadowRoot.getElementById('pg-safe');
    const btnIgnore = shadowRoot.getElementById('pg-ignore');

    btnSafe.addEventListener('click', () => {
        history.length > 1 ? history.back() : window.location.replace("https://www.google.com/");
    });

    btnIgnore.addEventListener('click', () => {
        // Closing a warning is always allowed. Strong blocks intentionally keep
        // form locks active; the user can still use the blocked-page flow.
        host.remove();
        showToast(isBlocking ? "This page remains blocked for your safety." : "Please continue carefully.", "danger");
    });
}

// ==================================================
// 🔔 6. TOAST NOTIFICATION SYSTEM
// ==================================================
function showToast(message, type = "info") {
    if (document.getElementById('cyberkavach-toast')) return;

    const toast = document.createElement('div');
    toast.id = "cyberkavach-toast";
    
    // Styling
    toast.style.position = "fixed";
    toast.style.bottom = "20px";
    toast.style.right = "20px";
    toast.style.padding = "15px 20px";
    toast.style.borderRadius = "8px";
    toast.style.fontFamily = "sans-serif";
    toast.style.fontSize = "14px";
    toast.style.fontWeight = "bold";
    toast.style.color = "#fff";
    toast.style.zIndex = "2147483647";
    toast.style.boxShadow = "0 10px 25px rgba(0,0,0,0.5)";
    toast.style.transform = "translateY(100px)";
    toast.style.opacity = "0";
    toast.style.transition = "all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275)";
    
    if (type === "danger") {
        toast.style.backgroundColor = "#ef4444";
        toast.style.borderLeft = "6px solid #991b1b";
    } else {
        toast.style.backgroundColor = "#3b82f6";
        toast.style.borderLeft = "6px solid #1e3a8a";
    }

    toast.innerText = message;
    document.body.appendChild(toast);

    // Animate In
    setTimeout(() => {
        toast.style.transform = "translateY(0)";
        toast.style.opacity = "1";
    }, 100);

    // Animate Out & Remove
    setTimeout(() => {
        toast.style.transform = "translateY(100px)";
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 400);
    }, 5000);
}

// ==========================================
// 🛡️ PHISHGUARD TITAN NODE - POPUP LOGIC
// ==========================================

document.addEventListener('DOMContentLoaded', async function() {
    const createFreeKey = () => {
        const bytes = crypto.getRandomValues(new Uint8Array(16));
        return "FREE-" + Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    };
    
    // ⚙️ 1. CONFIGURATION
    const API_URL = globalThis.CYBERKAVACH_API_URL;
    const DASHBOARD_URL = globalThis.CYBERKAVACH_DASHBOARD_URL;

    // 🏗️ 2. DOM MAPPING
    const ui = {
        authView: document.getElementById('authView'),
        dashView: document.getElementById('dashView'),
        planBadge: document.getElementById('planBadge'),
        statusIcon: document.getElementById('statusIcon'),
        verdict: document.getElementById('verdict'),
        urlDisplay: document.getElementById('url'),
        riskScore: document.getElementById('riskScore'),
        riskBar: document.getElementById('riskBar'),
        creditScore: document.getElementById('creditScore'),
        creditBar: document.getElementById('creditBar'),
        licenseInput: document.getElementById('licenseKey'),
        btnActivate: document.getElementById('btnActivate'),
        btnDashboard: document.getElementById('btnDashboard'),
        btnLogout: document.getElementById('btnLogout'),
        feedbackPanel: document.getElementById('feedbackPanel'),
        btnWrongAlert: document.getElementById('btnWrongAlert'),
        btnReportScam: document.getElementById('btnReportScam'),
        feedbackStatus: document.getElementById('feedbackStatus')
    };

    // Only the active HTTP(S) page is reported. We never send page content,
    // passwords, or browsing history as feedback.
    let feedbackTarget = '';

    // Helper Functions
    const setText = (el, text) => { if(el) el.innerText = text; };
    const setStyle = (el, prop, val) => { if(el) el.style[prop] = val; };

    function setFeedbackAvailable(available) {
        if (!ui.feedbackPanel) return;
        // Feedback makes sense only after we have a real website URL. Hiding
        // it on chrome:// and extension pages prevents misleading messages.
        ui.feedbackPanel.classList.toggle('hidden', !available);
        if (!available) setText(ui.feedbackStatus, '');
    }

    // ==========================================
    // 🕵️ 3. INITIALIZATION & IDENTITY CHECK
    // ==========================================
    
    // Read cached API Key from Chrome Storage
    const storage = await chrome.storage.local.get(['licenseKey', 'lastCreditCount', 'lastTotalLimit', 'lastPlan']);
    let savedKey = storage.licenseKey;
    
    // 🚀 THE FIX: Assign a Unique FREE ID if the user is new
    if (!savedKey || savedKey === "FREE" || savedKey === "GUEST_SESSION") {
        savedKey = createFreeKey();
        chrome.storage.local.set({ licenseKey: savedKey });
    }
    
    updateAuthUI(savedKey);

    // Render old cached quota instantly to prevent UI flickering
    if (storage.lastCreditCount !== undefined) {
        renderQuotaUI({
            url_remaining: storage.lastCreditCount,
            url_limit: storage.lastTotalLimit,
            plan: storage.lastPlan
        });
    }

    // Fire Backend Requests
    fetchUserQuota(savedKey);
    runSecurityAudit(savedKey);

    // ==========================================
    // 📡 4. BACKEND COMMUNICATION
    // ==========================================

    // Fetch live credits from backend
    async function fetchUserQuota(apiKey) {
        try {
            const res = await fetch(`${API_URL}/user-status`, {
                headers: { 'x-api-key': apiKey }
            });
            
            if (res.status === 401) {
                // 401 means the stored licence is invalid, not that the API is
                // down. Keep the message simple and allow the user to activate
                // a valid key again from this popup.
                setText(ui.creditScore, "Activate your key");
                setText(ui.verdict, "LICENSE NOT ACTIVE");
                return;
            }
            if (!res.ok) throw new Error("API unavailable");
            
            const data = await res.json();
            
            if (data && data.url_remaining !== undefined) {
                renderQuotaUI(data);
                
                // Cache this fresh quota so the next time popup opens, it's instant
                chrome.storage.local.set({ 
                    lastCreditCount: data.url_remaining,
                    lastTotalLimit: data.url_limit,
                    lastPlan: data.plan
                });
            }
        } catch (e) {
            console.error("Cyberkavach: Quota API Offline", e);
            setText(ui.creditScore, "SYSTEM OFFLINE");
            setStyle(ui.creditBar, 'width', '0%');
            setStyle(ui.creditBar, 'background', '#64748b');
        }
    }

    // Scan current tab
    async function runSecurityAudit(apiKey, retriedAfterInvalidKey = false) {
        const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
        feedbackTarget = '';
        setFeedbackAvailable(false);
        
        // Skip browser internal pages
        if(!tab || !tab.url || !tab.url.startsWith('http')) {
            setText(ui.urlDisplay, "Secure Local Node");
            setSafeState();
            return;
        }

        const domain = new URL(tab.url).hostname;
        feedbackTarget = tab.url;
        setFeedbackAvailable(true);
        setText(ui.urlDisplay, domain);
        setText(ui.verdict, "CHECKING SITE...");

        try {
            const response = await fetch(`${API_URL}/scan`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'x-api-key': apiKey,
                    // Popup reflects the browser-protection assessment and must
                    // not consume manual dashboard scan credits.
                    'x-scan-mode': 'extension-background'
                },
                body: JSON.stringify({ url: tab.url })
            });

            const data = await response.json();
            
            if (response.ok) {
                renderScanResults(data);
                // Refresh the displayed plan/quota without charging this check.
                fetchUserQuota(apiKey);
            } else if (response.status === 401 && !retriedAfterInvalidKey) {
                // Recover from a stale local demo key. This keeps protection
                // working and does not claim that the backend is offline.
                const replacementKey = createFreeKey();
                await chrome.storage.local.set({ licenseKey: replacementKey, lastPlan: "FREE" });
                updateAuthUI(replacementKey);
                fetchUserQuota(replacementKey);
                return runSecurityAudit(replacementKey, true);
            } else if (response.status === 429) {
                handleLimitReached();
            } else {
                handleOffline();
            }
        } catch (error) {
            handleOffline();
        }
    }

    // ==========================================
    // 🎨 5. UI RENDERING ENGINE
    // ==========================================

    function renderQuotaUI(data) {
        const rem = parseInt(data.url_remaining) || 0;
        const total = parseInt(data.url_limit) || 10;
        const plan = data.plan || "FREE";
        
        // Update Text & Badge
        setText(ui.creditScore, `${rem} Scans Left`);
        setText(ui.planBadge, plan === "PRO" ? "PRO" : "FREE");
        ui.planBadge.className = `badge ${plan === 'PRO' ? 'pro' : 'free'}`;
        
        // Update Progress Bar
        const percent = Math.max(0, Math.min((rem / total) * 100, 100));
        setStyle(ui.creditBar, 'width', `${percent}%`);
        
        // Warning Color Logic (Color syncs with light SaaS theme)
        if (rem <= (total * 0.1)) {
            setStyle(ui.creditBar, 'background', '#ef4444'); // Red if < 10% left
        } else if (plan === "PRO") {
            setStyle(ui.creditBar, 'background', '#4f46e5'); // Indigo 600 for PRO
        } else {
            setStyle(ui.creditBar, 'background', '#10b981'); // Emerald 500 for FREE
        }
    }

    function renderScanResults(data) {
        setText(ui.verdict, data.display_verdict || data.status);
        const score = data.risk_score || 0;
        setText(ui.riskScore, `${score}/100`);
        setStyle(ui.riskBar, 'width', `${score}%`);

        // Reset Body classes
        document.body.classList.remove('safe', 'danger');
        
        // Threat Engine Logic
        if (data.status === "PHISHING" || data.status === "MALWARE" || score >= 65) {
            document.body.classList.add('danger');
            updateIcon('#ef4444', 'alert-triangle');
        } else if (data.status === "SUSPICIOUS" || (score > 35 && score < 65)) {
            document.body.classList.add('danger');
            updateIcon('#f59e0b', 'alert-triangle'); // Orange for suspicious
        } else {
            document.body.classList.add('safe');
            updateIcon('#10b981', 'shield-check');
        }
    }

    function setSafeState() {
        document.body.classList.add('safe');
        setText(ui.verdict, "SECURE NODE");
        setText(ui.riskScore, "0/100");
        setStyle(ui.riskBar, 'width', '0%');
        updateIcon('#10b981', 'shield-check');
    }

    function handleLimitReached() {
        setText(ui.verdict, "DAILY LIMIT REACHED");
        setText(ui.creditScore, "0 scans left");
        setStyle(ui.creditBar, 'width', '0%');
        document.body.classList.add('danger');
        updateIcon('#ef4444', 'alert-triangle');
    }

    function handleOffline() {
        setText(ui.verdict, "SERVER UNAVAILABLE");
        setText(ui.urlDisplay, "Please try again shortly");
        updateIcon('#64748b', 'shield');
    }

    async function submitFeedback(feedbackType) {
        if (!feedbackTarget) {
            setText(ui.feedbackStatus, 'Open a website first.');
            return;
        }

        const buttons = [ui.btnWrongAlert, ui.btnReportScam].filter(Boolean);
        buttons.forEach(button => { button.disabled = true; });
        setText(ui.feedbackStatus, 'Sending feedback...');

        try {
            const { licenseKey } = await chrome.storage.local.get(['licenseKey']);
            const response = await fetch(`${API_URL}/scan-feedback`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': licenseKey || 'GUEST_SESSION'
                },
                body: JSON.stringify({ target: feedbackTarget, feedback_type: feedbackType })
            });
            if (!response.ok) throw new Error(`Feedback request failed (${response.status})`);
            setText(ui.feedbackStatus, 'Thanks — feedback saved.');
        } catch (_) {
            setText(ui.feedbackStatus, 'Could not save feedback. Try again.');
        } finally {
            buttons.forEach(button => { button.disabled = false; });
        }
    }

    // Dynamic SVG Morphing
    function updateIcon(color, iconType = 'shield') {
        if(!ui.statusIcon) return;
        
        let pathData = "";
        if (iconType === 'shield-check') {
            pathData = `<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>`;
        } else if (iconType === 'alert-triangle') {
            pathData = `<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/>`;
        } else {
            pathData = `<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>`;
        }

        ui.statusIcon.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">${pathData}</svg>`;
        ui.statusIcon.style.color = color;
    }

    // ==========================================
    // 🔐 6. AUTHENTICATION & ROUTING
    // ==========================================

    function updateAuthUI(key) {
        if (key && key.startsWith("CK-PRO-")) {
            if(ui.authView) ui.authView.classList.add('hidden');
            if(ui.dashView) ui.dashView.classList.remove('hidden');
        } else {
            if(ui.authView) ui.authView.classList.remove('hidden');
            if(ui.dashView) ui.dashView.classList.add('hidden');
        }
    }

    // Login (Verify PRO Key)
    if(ui.btnActivate) {
        ui.btnActivate.addEventListener('click', async () => {
            const key = ui.licenseInput.value.trim();
            if (!key) return;

            ui.btnActivate.innerText = "VERIFYING ENCRYPTION...";
            try {
                const res = await fetch(`${API_URL}/user-status`, {
                    headers: { 'x-api-key': key }
                });
                
                if(res.status === 401) {
                    alert("Invalid Titan License Key. Please check your email.");
                    ui.btnActivate.innerText = "Unlock Titan Elite";
                    return;
                }
                
                if(!res.ok) throw new Error("API Fault");
                
                const data = await res.json();

                if (data.plan === "PRO") {
                    chrome.storage.local.set({ licenseKey: key }, () => {
                        location.reload(); 
                    });
                } else {
                    alert("This key is not authorized for PRO access.");
                    ui.btnActivate.innerText = "Unlock Titan Elite";
                }
            } catch (e) {
                alert("Verification Server Offline. Is main.py running?");
                ui.btnActivate.innerText = "Unlock Titan Elite";
            }
        });
    }

    // Logout
    if(ui.btnLogout) {
        ui.btnLogout.addEventListener('click', () => {
            if(confirm("Are you sure you want to terminate the PRO session?")) {
                // Clear the PRO key, which will force the system to generate a new FREE key on next load
                chrome.storage.local.remove(['licenseKey', 'lastCreditCount', 'lastTotalLimit', 'lastPlan'], () => {
                    location.reload();
                });
            }
        });
    }

    if (ui.btnWrongAlert) {
        ui.btnWrongAlert.addEventListener('click', () => submitFeedback('false_positive'));
    }
    if (ui.btnReportScam) {
        ui.btnReportScam.addEventListener('click', () => submitFeedback('reported_scam'));
    }

    // Open Main Dashboard
    if(ui.btnDashboard) {
        ui.btnDashboard.addEventListener('click', () => {
            chrome.storage.local.get(['licenseKey'], (storage) => {
                const key = storage.licenseKey || "FREE";
                // URL fragments are not sent to the web server or access logs.
                chrome.tabs.create({ url: `${DASHBOARD_URL}#key=${encodeURIComponent(key)}` });
            });
        });
    }
});

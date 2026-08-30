/**
 * ======================================================================
 * CYBERKAVACH AI - ENTERPRISE FRONTEND LOGIC (index.html)
 * ======================================================================
 * This script handles all UI interactions, animations, API calls, 
 * and API calls for the main landing page.
 */

// Global Configuration
const API_URL = window.CYBERKAVACH_CONFIG?.API_URL || "http://127.0.0.1:8000";

function getOrCreateApiKey() {
    return CyberKavachIdentity.getOrCreateKey();
}

document.addEventListener("DOMContentLoaded", () => {
    
    // ==========================================
    // 1. INITIALIZE ICONS
    // ==========================================
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }

    // ==========================================
    // 2. PREMIUM FLOATING NAVBAR SCROLL EFFECT
    // ==========================================
    const navWrapper = document.getElementById('nav-wrapper');
    const navbar = document.getElementById('navbar');
    const navInner = document.getElementById('nav-inner');
    
    window.addEventListener('scroll', () => {
        if (window.scrollY > 30) {
            if(navWrapper) navWrapper.classList.add('nav-scrolled');
            if(navbar) navbar.classList.add('nav-scrolled');
            if(navInner) navInner.classList.add('nav-scrolled-inner');
        } else {
            if(navWrapper) navWrapper.classList.remove('nav-scrolled');
            if(navbar) navbar.classList.remove('nav-scrolled');
            if(navInner) navInner.classList.remove('nav-scrolled-inner');
        }
    });

      // 2. Select Elements using NEW IDs
    const openBtn = document.getElementById('mobileMenuBtn'); // Navbar hamburger
    const closeBtn = document.getElementById('closeDrawerBtn'); // Drawer X button
    const drawer = document.getElementById('newMobileDrawer');
    const overlay = document.getElementById('newMobileOverlay');
    
    // Safety check
    if (!openBtn || !drawer || !overlay || !closeBtn) {
        console.warn("Mobile Drawer elements missing. Check HTML IDs.");
        return;
    }

    // 3. The Open Function
    window.openMobileMenu = function() {
        // Activate Overlay
        overlay.classList.remove('pointer-events-none');
        overlay.classList.replace('opacity-0', 'opacity-100');
        
        // Slide Drawer In
        drawer.classList.remove('translate-x-full');
        
        // Trigger Staggered Link Animations
        drawer.classList.add('drawer-is-open');

        // Prevent body scrolling while menu is open
        document.body.style.overflow = 'hidden';
    }

    // 4. The Close Function
    window.closeMobileMenu = function() {
        // Hide Links (Reverses the animation)
        drawer.classList.remove('drawer-is-open');
        
        // Slide Drawer Out
        drawer.classList.add('translate-x-full');
        
        // Deactivate Overlay
        overlay.classList.replace('opacity-100', 'opacity-0');
        overlay.classList.add('pointer-events-none');

        // Restore body scrolling
        document.body.style.overflow = '';
    }

    // 5. Attach Click Events
    openBtn.addEventListener('click', openMobileMenu);
    closeBtn.addEventListener('click', closeMobileMenu);
    overlay.addEventListener('click', closeMobileMenu);

    // Auto-close when clicking any link inside the drawer
    const allLinks = drawer.querySelectorAll('.menu-item-anim');
    allLinks.forEach(link => {
        link.addEventListener('click', closeMobileMenu);
    });

});

    // ==========================================
    // 4. UNIVERSAL SCROLL ANIMATION OBSERVER
    // ==========================================
    // This single observer handles page fade-up animations.
    const fadeObserverOptions = {
        threshold: 0.15,
        rootMargin: "0px 0px -40px 0px"
    };

    const fadeObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => { 
            if (entry.isIntersecting) {
                entry.target.classList.add('visible'); 
                observer.unobserve(entry.target); // Run once per element
            }
        });
    }, fadeObserverOptions);

    const fadeClasses = [
        '.hero-fade-up', '.about-fade-up', '.module-fade-up',
        '.ext-fade-up', '.faq-fade-up',
        '.honesty-fade-up', '.cta-fade-up', '.platform-fade-up', '.fade-up'
    ];
    
    fadeClasses.forEach(selector => {
        document.querySelectorAll(selector).forEach(el => fadeObserver.observe(el));
    });

    // ==========================================
    // 5. ENHANCED HERO SCANNER UX & API LOGIC
    // ==========================================
    const scanInput = document.getElementById('scanInput');
    const scannerContainer = document.getElementById('scannerContainer');
    const scanForm = document.getElementById('scanForm');
    const scanBtnText = document.getElementById('scanBtnText');
    const scanBtnIcon = document.getElementById('scanBtnIcon');
    const resultBox = document.getElementById('scanResultBox');
    let lastScannedTarget = '';

    async function sendFeedback(feedbackType) {
        const status = document.getElementById('feedbackStatus');
        if (!lastScannedTarget) return;
        if (status) status.textContent = 'Sending feedback…';
        try {
            const response = await fetch(`${API_URL}/scan-feedback`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'x-api-key': getOrCreateApiKey() },
                body: JSON.stringify({ target: lastScannedTarget, feedback_type: feedbackType })
            });
            if (!response.ok) throw new Error('Feedback request failed');
            if (status) status.textContent = 'Thanks — feedback saved for review.';
        } catch {
            if (status) status.textContent = 'Feedback could not be sent. Please try again.';
        }
    }

    document.getElementById('falsePositiveBtn')?.addEventListener('click', () => sendFeedback('false_positive'));
    document.getElementById('reportScamBtn')?.addEventListener('click', () => sendFeedback('reported_scam'));

    // Add glowing focus ring effect around the scanner wrapper
    if(scanInput && scannerContainer) {
        scanInput.addEventListener('focus', () => scannerContainer.classList.add('scanner-focused'));
        scanInput.addEventListener('blur', () => scannerContainer.classList.remove('scanner-focused'));
    }

    if(scanForm) {
        scanForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const url = scanInput.value.trim();
            if(!url) return;

            // Trigger Loading State UI
            if(scanBtnText) scanBtnText.innerText = 'Scanning...';
            if(scanBtnIcon) {
                scanBtnIcon.setAttribute('data-lucide', 'loader-2');
                scanBtnIcon.classList.add('animate-spin');
            }
            if (typeof lucide !== 'undefined') lucide.createIcons();
            
            if(resultBox) resultBox.classList.add('hidden-state');
            const rDetails = document.getElementById('rDetails');
            if(rDetails) rDetails.classList.add('hidden-state');

            try {
                // UI simulated delay for enterprise feel (can remove in prod)
                await new Promise(resolve => setTimeout(resolve, 800)); 

                const res = await fetch(`${API_URL}/scan`, {
                    method: 'POST', 
                    headers: { 'Content-Type': 'application/json', 'x-api-key': getOrCreateApiKey() }, 
                    body: JSON.stringify({ url: url })
                });
                
                if(!res.ok) {
                    const details = await res.json().catch(() => ({}));
                    throw new Error(details.detail || `Scan request failed (${res.status})`);
                }
                const data = await res.json();
                lastScannedTarget = url;
                
                // Construct UI based on result
                const isSafe = data.status === "SAFE";
                const color = isSafe ? 'emerald' : 'red';
                
                document.getElementById('rTitle').innerText = data.display_verdict || data.status;
                document.getElementById('rTitle').className = `text-xl md:text-2xl font-black uppercase tracking-tight text-${color}-600`;
                document.getElementById('rScore').innerText = `${data.risk_score}%`;
                document.getElementById('rScore').className = `text-lg md:text-3xl font-mono font-black text-${color}-600`;
                document.getElementById('rConfidence').innerText = `${data.confidence_level || 'N/A'} (${data.assessment_confidence ?? 'N/A'}%)`;
                document.getElementById('rDisclaimer').textContent = data.user_message || data.disclaimer || 'This result is a risk assessment, not a guarantee of safety.';
                const feedbackStatus = document.getElementById('feedbackStatus');
                if (feedbackStatus) feedbackStatus.textContent = '';

                // The public scanner shows only a small useful summary. Full
                // evidence is stored with the scan and is available in OpsCenter.
                const quickDetails = document.getElementById('rQuickDetails');
                quickDetails?.replaceChildren();
                const urlSection = Array.isArray(data.details) ? data.details.find(section => section.title === 'URL details') : null;
                if (quickDetails && urlSection?.items) {
                    const wanted = new Set(['Final destination', 'Host', 'Redirects followed', 'Connection']);
                    urlSection.items.filter(item => wanted.has(item.label)).forEach(item => {
                        const card = document.createElement('div');
                        card.className = 'rounded-lg border border-slate-200 bg-white px-3 py-2';
                        const label = document.createElement('div');
                        label.className = 'text-[9px] font-bold uppercase tracking-wide text-slate-400';
                        label.textContent = item.label;
                        const value = document.createElement('div');
                        value.className = 'mt-0.5 break-all text-[11px] font-mono font-semibold text-slate-700';
                        value.textContent = item.value;
                        card.append(label, value);
                        quickDetails.appendChild(card);
                    });
                    quickDetails.classList.toggle('hidden', quickDetails.children.length === 0);
                }
                
                document.getElementById('rIconBox').className = `p-3 md:p-4 rounded-xl md:rounded-2xl bg-${color}-50 text-${color}-600 border border-${color}-100`;
                document.getElementById('rIcon').setAttribute('data-lucide', isSafe ? 'shield-check' : 'alert-triangle');
                document.getElementById('resultCard').className = `p-5 md:p-6 rounded-2xl md:rounded-3xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 md:gap-6 bg-${color}-50/20 border-${color}-200 shadow-xl`;

                if(data.ai_analysis && data.ai_analysis.length > 0) {
                    const list = document.getElementById('rFactorsList');
                    list.replaceChildren();
                    data.ai_analysis.forEach(reason => {
                        const item = document.createElement('li');
                        item.className = 'flex items-start gap-2';
                        const marker = document.createElement('span');
                        marker.className = `text-${color}-500 font-bold`;
                        marker.textContent = '↳';
                        const text = document.createElement('span');
                        text.textContent = String(reason);
                        item.append(marker, text);
                        list.appendChild(item);
                    });
                    if(rDetails) rDetails.classList.remove('hidden-state');
                }
                if(resultBox) resultBox.classList.remove('hidden-state');

            } catch (error) {
                alert(error.message || "Cannot connect to Titan AI Core backend.");
            } finally {
                // Reset Button State
                if(scanBtnText) scanBtnText.innerText = 'Run Audit';
                if(scanBtnIcon) {
                    scanBtnIcon.setAttribute('data-lucide', 'arrow-right');
                    scanBtnIcon.classList.remove('animate-spin');
                }
                if (typeof lucide !== 'undefined') lucide.createIcons();
            }
        });
    }

    // ==========================================
    // 6. NUMBER COUNTING ANIMATION
    // ==========================================
    const counters = document.querySelectorAll('.counter');
    const countSpeed = 100; 

    const counterObserver = new IntersectionObserver((entries, obs) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const counter = entry.target;
                const updateCount = () => {
                    const target = parseFloat(counter.getAttribute('data-target'));
                    const count = parseFloat(counter.innerText);
                    const inc = target / countSpeed;

                    if (count < target) {
                        if (target % 1 !== 0) counter.innerText = (count + inc).toFixed(1);
                        else counter.innerText = Math.ceil(count + inc);
                        setTimeout(updateCount, 20); 
                    } else {
                        counter.innerText = target; 
                    }
                };
                updateCount();
                obs.unobserve(counter); 
            }
        });
    }, { threshold: 0.5 });
    
    counters.forEach(counter => counterObserver.observe(counter));

    // ==========================================
    // 7. HONESTY PROTOCOL PROGRESS BAR
    // ==========================================
    const accuracyBar = document.getElementById('accuracy-bar-fill');
    const accuracyCounter = document.getElementById('accuracy-counter');
    let isBarAnimated = false;

    if (accuracyBar && accuracyCounter) {
        const accuracyObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting && !isBarAnimated) {
                    isBarAnimated = true; 
                    
                    // Fill CSS width
                    accuracyBar.style.width = '99.2%';

                    // Animate text digits
                    const target = 99.2;
                    let count = 0;
                    const duration = 1500; 
                    const frameRate = 1000 / 60; 
                    const totalFrames = Math.round(duration / frameRate);
                    const increment = target / totalFrames;

                    const counterInterval = setInterval(() => {
                        count += increment;
                        if (count >= target) {
                            accuracyCounter.innerText = target;
                            clearInterval(counterInterval);
                        } else {
                            accuracyCounter.innerText = count.toFixed(1);
                        }
                    }, frameRate);
                }
            });
        }, { threshold: 0.5 }); 
        accuracyObserver.observe(accuracyBar.parentElement);
    }

    // ==========================================
    // 8. FAQ ACCORDION LOGIC
    // ==========================================
    const faqBtns = document.querySelectorAll('.faq-btn');

    faqBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const card = btn.parentElement;
            const content = card.querySelector('.faq-content');
            const icon = card.querySelector('.faq-icon');
            const isOpen = card.classList.contains('active');

            // Close all other open accordions
            document.querySelectorAll('.faq-card').forEach(otherCard => {
                if (otherCard !== card) {
                    otherCard.classList.remove('active');
                    const otherBtn = otherCard.querySelector('.faq-btn');
                    const otherContent = otherCard.querySelector('.faq-content');
                    const otherIcon = otherCard.querySelector('.faq-icon');
                    
                    if(otherBtn) otherBtn.setAttribute('aria-expanded', 'false');
                    if(otherContent) otherContent.style.maxHeight = null;
                    if(otherIcon) otherIcon.style.transform = 'rotate(0deg)';
                }
            });

            // Toggle targeted accordion
            if (!isOpen) {
                card.classList.add('active');
                btn.setAttribute('aria-expanded', 'true');
                if(content) content.style.maxHeight = content.scrollHeight + "px";
                if(icon) icon.style.transform = 'rotate(180deg)'; // Plus to Cross
            } else {
                card.classList.remove('active');
                btn.setAttribute('aria-expanded', 'false');
                if(content) content.style.maxHeight = null;
                if(icon) icon.style.transform = 'rotate(0deg)';
            }
        });
    });


// BLOG SECTION ANIMATION LOGIC

// ==========================================

document.addEventListener("DOMContentLoaded", () => {

   

    // Ensure icons render if loaded dynamically

    if (typeof lucide !== 'undefined') {

        lucide.createIcons();

    }



    // Scroll Animation Observer for Blog Cards

    const blogObserverOptions = {

        threshold: 0.1,

        rootMargin: "0px 0px -50px 0px" // Triggers slightly before it enters the viewport

    };



    const blogObserver = new IntersectionObserver((entries, observer) => {

        entries.forEach(entry => {

            if (entry.isIntersecting) {

                entry.target.classList.add('visible');

                // Stop observing once animated for performance

                observer.unobserve(entry.target);

            }

        });

    }, blogObserverOptions);



    // Attach observer to all elements with .blog-fade-up

    document.querySelectorAll('.blog-fade-up').forEach(el => blogObserver.observe(el));

});



// HONESTY PROTOCOL ANIMATIONS

// ==========================================

document.addEventListener("DOMContentLoaded", () => {

   

    // Ensure icons load

    if (typeof lucide !== 'undefined') {

        lucide.createIcons();

    }



    // 1. Scroll fade-up for elements

    const honestyObserverOptions = {

        threshold: 0.15,

        rootMargin: "0px 0px -50px 0px"

    };



    const honestyObserver = new IntersectionObserver((entries, observer) => {

        entries.forEach(entry => {

            if (entry.isIntersecting) {

                entry.target.classList.add('visible');

                observer.unobserve(entry.target);

            }

        });

    }, honestyObserverOptions);



    document.querySelectorAll('.honesty-fade-up').forEach(el => honestyObserver.observe(el));



    // 2. Specific Observer for the 99.2% Accuracy Bar & Counter

    const accuracyBar = document.getElementById('accuracy-bar-fill');

    const accuracyCounter = document.getElementById('accuracy-counter');

    let hasAnimated = false;



    if (accuracyBar && accuracyCounter) {

        const accuracyObserver = new IntersectionObserver((entries) => {

            entries.forEach(entry => {

                if (entry.isIntersecting && !hasAnimated) {

                    hasAnimated = true; // Prevent running multiple times

                   

                    // Fill the bar visually

                    accuracyBar.style.width = '99.2%';



                    // Animate the number

                    const target = 99.2;

                    let count = 0;

                    const duration = 1500; // 1.5 seconds to match CSS transition

                    const frameRate = 1000 / 60; // 60fps

                    const totalFrames = Math.round(duration / frameRate);

                    const increment = target / totalFrames;



                    const counterInterval = setInterval(() => {

                        count += increment;

                        if (count >= target) {

                            accuracyCounter.innerText = target;

                            clearInterval(counterInterval);

                        } else {

                            // Show 1 decimal place

                            accuracyCounter.innerText = count.toFixed(1);

                        }

                    }, frameRate);

                }

            });

        }, { threshold: 0.5 }); // Trigger when 50% of the bar box is visible



        // Observe the parent container of the bar

        accuracyObserver.observe(accuracyBar.parentElement);

    }

});



//

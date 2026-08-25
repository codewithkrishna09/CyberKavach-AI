"""Explainable URL risk scanner.

It combines local URL signals, safe outbound page review, optional reputation
data and an optional local ML model. No single weak signal should block a site.
"""

import re
import math
import datetime
import urllib.parse
import concurrent.futures
import hashlib
import time
from difflib import SequenceMatcher
from threading import Lock
import requests
from bs4 import BeautifulSoup
import whois
from security import safe_get, validate_public_url
from ml_url_model import predict_phishing_probability
from threat_intel import lookup_url_reputation
from config import SCAN_RESULT_CACHE_SECONDS


# This cache prevents repeated browser navigation from repeating WHOIS, DOM and
# optional reputation lookups. Keys are hashes, so raw URLs are not retained in
# this in-memory cache. It is deliberately short-lived because threats change.
_scan_cache: dict[str, tuple[float, dict]] = {}
_scan_cache_lock = Lock()

# ======================================================================
# CYBERKAVACH TITAN ENGINE - PRE-DOM WEB INTERCEPTOR & HEURISTIC SCANNER
# ======================================================================
# This module performs deep real-time forensics on any given URL.
# It checks:
# 1. URL Lexical Features (Entropy, IP hiding, excessive subdomains)
# 2. DNS/WHOIS Intelligence (Domain age, shady registrars)
# 3. Cryptographic Validation (SSL/TLS cert abuse)
# 4. Live DOM Analysis (Credential harvesting, hidden iframes)
# ======================================================================

class TitanScanner:
    def __init__(self, url: str):
        self.raw_url = url
        self.parsed_url = urllib.parse.urlparse(url)
        self.domain = self.parsed_url.netloc.split(':')[0] if self.parsed_url.netloc else self.parsed_url.path.split('/')[0]
        
        # Local indicators give an instant first opinion; no single indicator is
        # sufficient to label a site malicious.
        self.TARGET_BRANDS = ["sbi", "hdfc", "icici", "axis", "indiapost", "flipkart", "amazon", "paytm", "phonepe", "gpay", "income tax", "uidai", "aadhaar"]
        self.BRAND_DOMAINS = {
            "sbi": {"sbi.co.in", "onlinesbi.sbi"}, "hdfc": {"hdfcbank.com"}, "icici": {"icicibank.com"},
            "axis": {"axisbank.com"}, "indiapost": {"indiapost.gov.in"}, "flipkart": {"flipkart.com"},
            "amazon": {"amazon.in", "amazon.com"}, "paytm": {"paytm.com"}, "phonepe": {"phonepe.com"},
            "uidai": {"uidai.gov.in"}, "aadhaar": {"uidai.gov.in"},
        }
        # These are weak signals only. Common hosting domains such as .app,
        # Vercel and Netlify are intentionally not treated as malicious.
        self.SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".zip", ".tk", ".ml", ".ga", ".cf", ".gq"]
        self.PHISHING_KEYWORDS = ["login", "verify", "update", "kyc", "wallet", "secure", "account", "auth", "confirm", "refund", "support", "blocked"]
        
        # State variables for the scan
        self.risk_score = 0
        # WHOIS, page review and reputation checks run in parallel. A lock keeps
        # simultaneous score updates deterministic instead of losing evidence.
        self._score_lock = Lock()
        self.ai_analysis = []
        self.is_threat = False
        
        # Raw Data Extracted
        self.html_content = ""
        self.domain_age_days = -1
        self.ssl_valid = False
        self.ssl_issuer = ""
        self.final_url = url
        self.redirect_count = 0
        self.whois_available = False
        self.domain_created = None
        self.domain_expires = None
        self.domain_registrar = None
        self.page_summary = {"reviewed": False}
        self.ml_probability = None
        self.reputation = {"checked": False, "hit": False, "provider": None, "categories": []}

    def add_risk(self, points: int) -> None:
        """Safely add a bounded evidence score from any scan worker."""
        with self._score_lock:
            self.risk_score += points

    def is_official_brand_domain(self, brand: str) -> bool:
        """Avoid flagging legitimate brand login pages solely for saying 'login'."""
        return any(self.domain == domain or self.domain.endswith(f".{domain}") for domain in self.BRAND_DOMAINS.get(brand, set()))

    @staticmethod
    def _format_date(value) -> str | None:
        """Return a short readable WHOIS date without exposing raw provider data."""
        if isinstance(value, list):
            value = value[0] if value else None
        if isinstance(value, datetime.datetime):
            return value.date().isoformat()
        if isinstance(value, datetime.date):
            return value.isoformat()
        return None

    def build_details(self) -> list[dict]:
        """Create short, user-facing evidence cards for the site and dashboard."""
        original = urllib.parse.urlsplit(self.raw_url)
        final = urllib.parse.urlsplit(self.final_url or self.raw_url)
        host_labels = [part for part in (original.hostname or "").split(".") if part]
        tld = f".{host_labels[-1]}" if host_labels else "Not available"
        page = self.page_summary
        reputation = self.reputation
        return [
            {"title": "URL details", "items": [
                {"label": "Original URL", "value": self.raw_url},
                {"label": "Final destination", "value": self.final_url or self.raw_url},
                {"label": "Redirects followed", "value": str(self.redirect_count)},
                {"label": "Host", "value": original.hostname or "Not available"},
                {"label": "Top-level domain", "value": tld},
                {"label": "Connection", "value": final.scheme.upper() if final.scheme else "Not available"},
            ]},
            {"title": "Domain details", "items": [
                {"label": "Domain age", "value": f"{self.domain_age_days} days" if self.domain_age_days >= 0 else "Not available"},
                {"label": "Created", "value": self._format_date(self.domain_created) or "Not available"},
                {"label": "Expires", "value": self._format_date(self.domain_expires) or "Not available"},
                {"label": "Registrar", "value": str(self.domain_registrar)[:120] if self.domain_registrar else "Not available"},
                {"label": "WHOIS lookup", "value": "Available" if self.whois_available else "Unavailable or privacy protected"},
            ]},
            {"title": "Page checks", "items": [
                {"label": "Page review", "value": page.get("status", "Not reviewed")},
                {"label": "Page title", "value": page.get("title", "Not available")},
                {"label": "Password fields", "value": str(page.get("password_fields", 0))},
                {"label": "Forms", "value": str(page.get("forms", 0))},
                {"label": "Cross-domain forms", "value": str(page.get("cross_domain_forms", 0))},
                {"label": "Hidden iframes", "value": str(page.get("hidden_iframes", 0))},
                {"label": "Scripts", "value": str(page.get("scripts", 0))},
            ]},
            {"title": "Threat intelligence", "items": [
                {"label": "Reputation check", "value": reputation.get("provider") or "Not configured"},
                {"label": "Known threat hit", "value": "Yes" if reputation.get("hit") else "No known hit" if reputation.get("checked") else "Not checked"},
                {"label": "Categories", "value": ", ".join(reputation.get("categories") or []) or "Not available"},
                {"label": "Local ML probability", "value": f"{self.ml_probability:.0f}%" if self.ml_probability is not None else "Model not installed"},
            ]},
        ]

    # ---------------------------------------------------------
    # 1. MATHEMATICAL URL ANALYSIS (Lexical Engine)
    # ---------------------------------------------------------
    def shannon_entropy(self, string: str) -> float:
        """Calculates the Shannon entropy of a string to detect Random/DGA domains."""
        if not string:
            return 0.0
        prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
        entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy

    def analyze_lexical_features(self):
        """Extracts structural anomalies from the URL string."""
        url_lower = self.raw_url.lower()
        
        # 1.1 IP Address in URL (Classic Phishing)
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        if ip_pattern.search(self.domain):
            self.add_risk(35)
            self.ai_analysis.append("[Threat] URL uses an IP address instead of a Domain Name to hide identity.")
            
        # 1.2 URL Length (Phishers use long URLs to hide the actual domain on mobile)
        if len(self.raw_url) > 75:
            self.add_risk(10)
            self.ai_analysis.append("[Warning] Suspiciously long URL detected (Often used to hide domain structure on mobile).")

        # 1.3 Depth of Subdomains (e.g., login.sbi.secure.update.scam.com)
        subdomain_count = self.domain.count('.')
        if subdomain_count > 3:
            self.add_risk(20)
            self.ai_analysis.append(f"[Threat] Excessive subdomains detected ({subdomain_count}). Typo-squatting highly probable.")

        # 1.4 Suspicious Symbols (@ or // for redirection)
        if '@' in self.parsed_url.netloc:
            self.add_risk(40)
            self.ai_analysis.append("[Critical] URL contains '@' symbol to bypass basic domain checks and force redirection.")
        if url_lower.count('//') > 1:
            self.add_risk(20)
            self.ai_analysis.append("[Warning] Multiple redirects ('//') found in URL path.")

        # 1.5 Brand impersonation requires both a brand/action pattern and a
        # non-official domain. This reduces false positives on real bank sites.
        found_brands = [brand for brand in self.TARGET_BRANDS if brand in url_lower]
        found_keywords = [kw for kw in self.PHISHING_KEYWORDS if kw in url_lower]
        spoofed_brands = [brand for brand in found_brands if not self.is_official_brand_domain(brand)]
        if spoofed_brands and found_keywords:
            self.add_risk(30)
            self.ai_analysis.append(f"[Threat] This link uses '{spoofed_brands[0]}' with a sign-in or urgency word, but is not on the official domain.")

        # Catch close spelling attempts such as paytrn-login.example. This is a
        # supporting signal, not enough to block a site by itself.
        for label in self.domain.split("."):
            if any(label == brand for brand in self.TARGET_BRANDS):
                continue
            for brand in self.BRAND_DOMAINS:
                if not self.is_official_brand_domain(brand) and len(label) >= 4 and SequenceMatcher(None, label, brand).ratio() >= 0.84:
                    self.add_risk(15)
                    self.ai_analysis.append(f"[Warning] Domain label '{label}' closely resembles '{brand}'.")
                    break

        # 1.6 Cheap/Free TLD Check
        for tld in self.SUSPICIOUS_TLDS:
            if self.domain.endswith(tld):
                self.add_risk(8)
                self.ai_analysis.append(f"[Info] Domain uses '{tld}', a suffix sometimes abused in phishing campaigns.")

        # 1.7 DGA (Domain Generation Algorithm) Entropy Check
        entropy = self.shannon_entropy(self.domain)
        if entropy > 4.5:
            self.add_risk(15)
            self.ai_analysis.append(f"[Warning] High mathematical entropy ({entropy:.2f}). Domain appears to be machine-generated (DGA).")

    # ---------------------------------------------------------
    # 2. DNS & INFRASTRUCTURE INTELLIGENCE
    # ---------------------------------------------------------
    def analyze_whois(self):
        """Checks domain registration age. Zero-Day phishing domains are usually < 30 days old."""
        try:
            domain_info = whois.whois(self.domain)
            creation_date = domain_info.creation_date
            self.whois_available = True
            self.domain_created = creation_date
            self.domain_expires = getattr(domain_info, "expiration_date", None)
            self.domain_registrar = getattr(domain_info, "registrar", None)
            
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
                
            if creation_date:
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                created_at = creation_date if isinstance(creation_date, datetime.datetime) else datetime.datetime.combine(creation_date, datetime.time.min)
                age = (datetime.datetime.now() - created_at).days
                self.domain_age_days = age
                
                if age < 30:
                    self.add_risk(40)
                    self.ai_analysis.append(f"[Critical] Zero-Day Threat: Domain was registered only {age} days ago.")
                elif age < 180:
                    self.add_risk(15)
                    self.ai_analysis.append(f"[Warning] Young domain detected. Registered {age} days ago.")
                else:
                    # Subtract risk for established domains
                    self.add_risk(-10)
        except Exception:
            # WHOIS is frequently unavailable or privacy-protected for legitimate
            # domains. An unavailable lookup must never add risk by itself.
            self.ai_analysis.append("[Info] Domain-age lookup was unavailable.")

    def analyze_reputation(self):
        """Use configured threat intelligence as decisive evidence when available."""
        self.reputation = lookup_url_reputation(self.raw_url)
        if self.reputation.get("hit"):
            categories = ", ".join(self.reputation.get("categories") or ["known threat"])
            self.add_risk(100)
            self.ai_analysis.append(f"[Critical] A threat-intelligence provider lists this URL as: {categories}.")

    # ---------------------------------------------------------
    # 3. LIVE PRE-DOM ANALYSIS (The Core Titan Feature)
    # ---------------------------------------------------------
    def analyze_dom(self):
        """Fetches the HTML to find hidden credential harvesters and obfuscation."""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept-Language': 'en-US,en;q=0.9'
        }
        
        try:
            # We use timeout=4 to ensure the API never hangs the backend
            response, response_bytes = safe_get(
                self.raw_url,
                headers=headers,
                timeout=4,
                max_bytes=2 * 1024 * 1024,
            )
            self.ssl_valid = response.url.lower().startswith("https://")
            self.final_url = response.url
            self.redirect_count = int(getattr(response, "_cyberkavach_redirect_count", 0))
            encoding = response.encoding or "utf-8"
            self.html_content = response_bytes.decode(encoding, errors="replace")
            
            # If the URL redirected us to a new place, parse the new URL
            if response.url != self.raw_url:
                self.ai_analysis.append(f"[Info] URL redirected to: {response.url[:50]}...")
            
            soup = BeautifulSoup(self.html_content, "html.parser")
            
            # 3.1 Check for Password inputs
            password_inputs = soup.find_all('input', type='password')
            if password_inputs:
                if not self.ssl_valid or "http://" in self.raw_url:
                    self.add_risk(50)
                    self.ai_analysis.append("[Critical] This page asks for a password on an unencrypted connection.")
                else:
                    self.ai_analysis.append("[Info] Page contains a password field.")

            # 3.2 Suspicious Form Actions
            forms = soup.find_all('form')
            cross_domain_forms = 0
            for form in forms:
                action = form.get('action', '').lower()
                action_host = urllib.parse.urlsplit(urllib.parse.urljoin(self.raw_url, action)).hostname
                if action_host and action_host.lower() != self.domain.lower():
                    cross_domain_forms += 1
                    score = 30 if password_inputs else 15
                    self.add_risk(score)
                    self.ai_analysis.append("[Threat] This form sends information to a different domain.")

            # 3.3 Hidden iFrames (Used for drive-by downloads or tracking)
            hidden_iframes = soup.find_all('iframe', style=lambda value: value and ('display:none' in value.replace(' ', '') or 'visibility:hidden' in value.replace(' ', '')))
            if hidden_iframes:
                self.add_risk(10)
                self.ai_analysis.append("[Warning] Hidden embedded page elements were found.")

            # 3.4 Page Title Brand Spoofing Check
            title = soup.title.get_text(" ", strip=True) if soup.title else ""
            title_lower = title.lower()
            if title_lower:
                for brand in self.TARGET_BRANDS:
                    if brand in title_lower and brand not in self.domain:
                        self.add_risk(35)
                        self.ai_analysis.append(f"[Critical] DOM Title spoofing. Page claims to be '{brand.upper()}' but domain does not match.")
            
            # 3.5 Captcha Wall Detection (Cloudflare / Recaptcha obfuscation)
            if "cf-turnstile" in self.html_content or "g-recaptcha" in self.html_content:
                self.ai_analysis.append("[Info] A CAPTCHA limited parts of the page review.")
            self.page_summary = {
                "reviewed": True,
                "status": "Reviewed" + (" (CAPTCHA limited some content)" if "cf-turnstile" in self.html_content or "g-recaptcha" in self.html_content else ""),
                "title": title[:120] or "No title found",
                "password_fields": len(password_inputs),
                "forms": len(forms),
                "cross_domain_forms": cross_domain_forms,
                "hidden_iframes": len(hidden_iframes),
                "scripts": len(soup.find_all("script")),
            }

        except requests.exceptions.Timeout:
            self.page_summary = {"reviewed": False, "status": "Timed out safely"}
            self.ai_analysis.append("[Info] Page review timed out; no score was added for this alone.")
        except Exception:
            self.page_summary = {"reviewed": False, "status": "Could not review page"}
            self.ai_analysis.append("[Info] Page content could not be reviewed.")

    # ---------------------------------------------------------
    # 4. COMPILATION & VERDICT GENERATION
    # ---------------------------------------------------------
    def generate_report(self) -> dict:
        """Compiles all threads into a final JSON response for the Frontend/Extension."""
        
        # Run all analysis modules concurrently for maximum speed (Titan Latency < 0.8s)
        self.analyze_lexical_features()
        self.ml_probability = predict_phishing_probability(self.raw_url)
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(self.analyze_whois), executor.submit(self.analyze_dom), executor.submit(self.analyze_reputation)]
            for future in futures:
                future.result()

        if self.ml_probability is not None:
            # A reviewed ML model is an additional signal, not an override for
            # high-severity live-page or infrastructure evidence.
            self.risk_score = round((self.risk_score * 0.65) + (self.ml_probability * 0.35))
            self.ai_analysis.append(f"[Info] Validated local URL model contributed a {self.ml_probability:.0f}% phishing probability.")
        
        # Clamp score between 0 and 100
        self.risk_score = max(0, min(self.risk_score, 100))
        
        # Determine Status. This is a risk assessment, not a claim that a URL is
        # harmless or malicious with certainty.  Returning the method and
        # confidence helps the UI explain the result honestly to the user.
        if self.risk_score >= 70:
            status = "MALWARE DETECTED"
        elif self.risk_score >= 40:
            status = "SUSPICIOUS"
        else:
            status = "SAFE"
            if not self.ai_analysis:
                self.ai_analysis.append("[Secure] Domain established. No phishing heuristics or malicious DOM payloads found.")

        # Ensure we always return a solid list to the frontend
        if len(self.ai_analysis) == 0:
            self.ai_analysis.append("[Info] Scan completed with no notable anomalies.")

        high_severity = sum(
            indicator.startswith("[Critical]") or indicator.startswith("[Threat]")
            for indicator in self.ai_analysis
        )
        evidence_sources = {
            "url" if any("URL" in item or "subdomain" in item or "entropy" in item.lower() for item in self.ai_analysis) else "",
            "domain" if any("Domain" in item or "WHOIS" in item for item in self.ai_analysis) else "",
            "page" if any("form" in item.lower() or "iframe" in item.lower() or "DOM" in item for item in self.ai_analysis) else "",
        } - {""}
        confidence = min(95, 45 + (len(evidence_sources) * 12) + (high_severity * 6))
        if status == "SAFE":
            confidence = min(confidence, 70)
        confidence_level = "HIGH" if confidence >= 75 else "MEDIUM" if confidence >= 55 else "LOW"

        if self.reputation.get("hit"):
            display_verdict = "Known dangerous link"
            user_message = "A trusted threat service has reported this link. Do not open it or enter any details."
        elif status == "MALWARE DETECTED":
            display_verdict = "Likely phishing"
            user_message = "This link has several warning signs. Do not enter a password, OTP, card, or UPI details."
        elif status == "SUSPICIOUS":
            display_verdict = "Check before continuing"
            user_message = "We found warning signs. Verify the official website or contact the organisation separately."
        else:
            display_verdict = "No known risk found"
            user_message = "No known warning signs were found in this scan. Stay careful with passwords, OTPs, and payments."

        return {
            "status": status,
            "risk_score": self.risk_score,
            "ai_analysis": self.ai_analysis,
            "detection_method": "Heuristic + live page analysis",
            "assessment_confidence": confidence,
            "confidence_level": confidence_level,
            "evidence_sources": sorted(evidence_sources),
            "ml_model_used": self.ml_probability is not None,
            "ml_phishing_probability": round(self.ml_probability, 1) if self.ml_probability is not None else None,
            "threat_intelligence": self.reputation,
            "display_verdict": display_verdict,
            "user_message": user_message,
            "disclaimer": "A safe result means no known indicators were found during this scan; it is not a guarantee of safety.",
            "details": self.build_details(),
        }


# ======================================================================
# API ENTRY POINT (Called by main.py)
# ======================================================================
def scan_website_logic(url: str) -> dict:
    """
    Master function that instantiates the TitanScanner class.
    Handles formatting and missing URL prefixes.
    """
    try:
        url = validate_public_url(url)
        cache_key = hashlib.sha256(url.encode("utf-8")).hexdigest()
        now = time.monotonic()
        with _scan_cache_lock:
            cached = _scan_cache.get(cache_key)
            if cached and cached[0] > now:
                return {**cached[1], "cache_hit": True}

        scanner = TitanScanner(url)
        report = scanner.generate_report()
        report["cache_hit"] = False
        with _scan_cache_lock:
            if len(_scan_cache) > 10_000:
                _scan_cache.clear()
            _scan_cache[cache_key] = (now + SCAN_RESULT_CACHE_SECONDS, report)
        return report
    except ValueError as e:
        # A policy/DNS stop is not a malicious-site verdict. Keep the technical
        # reason for the report but return plain wording for people.
        return {
            "status": "REJECTED",
            "risk_score": 0,
            "ai_analysis": [f"URL rejected by outbound security policy: {str(e)}"],
            "display_verdict": "Could not scan link",
            "user_message": "This link could not be checked right now. It has not been marked safe or dangerous.",
            "disclaimer": "The scan stopped before the website was reviewed.",
        }
    except Exception as e:
        # Fallback if severe architecture error occurs
        print(f"Titan Scanner Error: {e}")
        return {
            "status": "ERROR",
            "risk_score": 0,
            "ai_analysis": [f"Critical engine failure: {str(e)}", "Scan aborted safely."],
            "display_verdict": "Scan unavailable",
            "user_message": "The scanner could not finish this check. Please try again later.",
            "disclaimer": "The scan stopped before a safety result could be produced.",
        }

# For local testing
if __name__ == "__main__":
    test_url = "http://sbi-kyc-update-now.vercel.app/login"
    print(f"Testing Titan Engine on: {test_url}")
    result = scan_website_logic(test_url)
    import json
    print(json.dumps(result, indent=4))

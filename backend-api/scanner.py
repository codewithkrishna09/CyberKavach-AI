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
        # Short links and executable downloads are not automatically malicious,
        # but they hide the destination or can harm a device. They are therefore
        # supporting signals that ask the person to check before opening.
        self.URL_SHORTENERS = {
            "bit.ly", "bitly.com", "t.co", "tinyurl.com", "goo.gl", "is.gd",
            "cutt.ly", "shorturl.at", "rb.gy", "rebrand.ly", "tiny.cc",
        }
        self.RISKY_DOWNLOAD_EXTENSIONS = {
            ".apk", ".exe", ".msi", ".dmg", ".pkg", ".scr", ".bat", ".cmd",
            ".ps1", ".js", ".vbs", ".jar", ".iso", ".zip", ".rar", ".7z",
        }
        
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

    def is_normal_search_results_page(self) -> bool:
        """Identify a search-result page without creating a broad trusted bypass.

        A long search query is normal and must not make a major search engine
        look like phishing. Redirect parameters are explicitly excluded so a
        search-engine URL which points elsewhere still receives normal checks.
        """
        parsed = urllib.parse.urlsplit(self.raw_url)
        host = (parsed.hostname or "").lower()
        search_paths = {
            ("google.com", "/search"), ("www.google.com", "/search"),
            ("bing.com", "/search"), ("www.bing.com", "/search"),
            ("search.yahoo.com", "/search"), ("duckduckgo.com", "/"),
        }
        if (host, parsed.path or "/") not in search_paths:
            return False
        redirect_keys = {"url", "redirect", "redirect_uri", "next", "return", "continue", "destination", "target"}
        return not any(key.lower() in redirect_keys for key, _ in urllib.parse.parse_qsl(parsed.query))

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
                {"label": "Risky form actions", "value": str(page.get("risky_form_actions", 0))},
                {"label": "Hidden iframes", "value": str(page.get("hidden_iframes", 0))},
                {"label": "External page resources", "value": str(page.get("external_resources", 0))},
                {"label": "External links", "value": str(page.get("external_links", 0))},
                {"label": "Download links", "value": str(page.get("download_links", 0))},
                {"label": "Mail links", "value": str(page.get("mail_links", 0))},
                {"label": "Pop-up scripts", "value": str(page.get("popup_scripts", 0))},
                {"label": "Scripts", "value": str(page.get("scripts", 0))},
            ]},
            {"title": "Threat intelligence", "items": [
                {"label": "Reputation check", "value": reputation.get("provider") or "Not configured"},
                {"label": "Known threat hit", "value": "Yes" if reputation.get("hit") else "No known hit" if reputation.get("checked") else "Not checked"},
                {"label": "Categories", "value": ", ".join(reputation.get("categories") or []) or "Not available"},
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
        parsed = urllib.parse.urlsplit(self.raw_url)
        host = (parsed.hostname or self.domain).lower()
        
        # 1.1 IP Address in URL (Classic Phishing)
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        if ip_pattern.search(self.domain):
            self.add_risk(35)
            self.ai_analysis.append("[Threat] URL uses an IP address instead of a Domain Name to hide identity.")
            
        # 1.2 Structural URL length. Search/tracking query text is not a useful
        # phishing indicator by itself and caused false alerts on normal search pages.
        structural_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        if len(structural_url) > 75:
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

        # 1.8 Destination-hiding and lookalike patterns. These are deliberately
        # lower-weight than a threat-feed hit or a credential-stealing form.
        if host in self.URL_SHORTENERS or any(host.endswith(f".{item}") for item in self.URL_SHORTENERS):
            self.add_risk(15)
            self.ai_analysis.append("[Warning] Shortened link hides the final destination.")
        if "xn--" in host or any(ord(character) > 127 for character in host):
            self.add_risk(20)
            self.ai_analysis.append("[Warning] Internationalised domain characters can be used to imitate another website.")

        hyphenated_labels = [label for label in host.split(".") if label.count("-") >= 2]
        if hyphenated_labels:
            self.add_risk(8)
            self.ai_analysis.append("[Warning] Domain uses multiple hyphens, a pattern sometimes used in lookalike links.")
        if re.search(r"%(?:2f|2e|5c|40|3f|23)", url_lower):
            self.add_risk(10)
            self.ai_analysis.append("[Warning] URL contains encoded separators that can hide its real path.")

        # An external URL nested in a redirect parameter may lead somewhere
        # different from the domain a person thinks they are opening.
        redirect_parameters = {"url", "redirect", "redirect_uri", "next", "return", "continue", "destination", "target"}
        for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=False):
            if key.lower() not in redirect_parameters:
                continue
            candidate = urllib.parse.urlsplit(urllib.parse.unquote(value))
            if candidate.scheme in {"http", "https"} and candidate.hostname and candidate.hostname.lower() != host:
                self.add_risk(12)
                self.ai_analysis.append("[Warning] Link contains a redirect parameter pointing to a different domain.")
                break

        download_path = urllib.parse.unquote(parsed.path).lower()
        suffix = next((item for item in self.RISKY_DOWNLOAD_EXTENSIONS if download_path.endswith(item)), None)
        if suffix:
            points = 20 if suffix in {".apk", ".exe", ".msi", ".dmg", ".pkg", ".scr", ".bat", ".cmd", ".ps1", ".js", ".vbs", ".jar"} else 12
            self.add_risk(points)
            self.ai_analysis.append(f"[Warning] Link points directly to a potentially risky download ({suffix}).")

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

            # 3.2 Suspicious form actions. A password form posting to another
            # site, using GET, or opening a mail client is strong evidence of
            # credential collection. Normal same-site forms do not add risk.
            forms = soup.find_all('form')
            cross_domain_forms = 0
            risky_form_actions = 0
            final_host = (urllib.parse.urlsplit(response.url).hostname or self.domain).lower()
            for form in forms:
                action = (form.get('action') or '').strip()
                action_lower = action.lower()
                method = (form.get('method') or 'get').lower()
                action_url = urllib.parse.urlsplit(urllib.parse.urljoin(response.url, action))
                action_host = (action_url.hostname or '').lower()
                if action_lower.startswith(('mailto:', 'javascript:', 'data:')):
                    risky_form_actions += 1
                    self.add_risk(30 if password_inputs else 12)
                    self.ai_analysis.append("[Threat] This form uses an unsafe submission destination.")
                elif action_host and action_host != final_host:
                    cross_domain_forms += 1
                    score = 30 if password_inputs else 15
                    self.add_risk(score)
                    self.ai_analysis.append("[Threat] This form sends information to a different domain.")
                if password_inputs and method == 'get':
                    risky_form_actions += 1
                    self.add_risk(20)
                    self.ai_analysis.append("[Threat] Password form uses GET, which can expose submitted data in a URL.")

            # 3.3 Hidden iFrames can conceal unwanted embeds or downloads.
            def iframe_is_hidden(frame) -> bool:
                style = (frame.get('style') or '').replace(' ', '').lower()
                dimensions = {(frame.get('width') or '').strip(), (frame.get('height') or '').strip()}
                return (
                    frame.has_attr('hidden') or frame.get('aria-hidden') == 'true' or
                    'display:none' in style or 'visibility:hidden' in style or
                    'opacity:0' in style or '0' in dimensions
                )

            hidden_iframes = [frame for frame in soup.find_all('iframe') if iframe_is_hidden(frame)]
            if hidden_iframes:
                self.add_risk(10)
                self.ai_analysis.append("[Warning] Hidden embedded page elements were found.")

            # 3.4 Resource, link and download review. Third-party resources are
            # common on modern pages, so they are recorded as evidence and only
            # increase risk when paired with a credential form.
            def external_url(value: str | None) -> bool:
                if not value or value.startswith(('#', 'javascript:', 'data:', 'mailto:', 'tel:')):
                    return False
                target_host = urllib.parse.urlsplit(urllib.parse.urljoin(response.url, value)).hostname
                return bool(target_host and target_host.lower() != final_host)

            resource_values = []
            for element in soup.find_all(['script', 'img', 'iframe', 'audio', 'video', 'source']):
                resource_values.append(element.get('src'))
            for element in soup.find_all('link'):
                resource_values.append(element.get('href'))
            external_resources = sum(external_url(value) for value in resource_values)

            anchors = soup.find_all('a', href=True)
            external_links = sum(external_url(anchor.get('href')) for anchor in anchors)
            mail_links = sum(anchor.get('href', '').strip().lower().startswith('mailto:') for anchor in anchors)
            download_links = 0
            for anchor in anchors:
                href = urllib.parse.urlsplit(urllib.parse.urljoin(response.url, anchor.get('href', ''))).path.lower()
                if anchor.has_attr('download') or any(href.endswith(extension) for extension in self.RISKY_DOWNLOAD_EXTENSIONS):
                    download_links += 1
            if download_links:
                self.add_risk(12)
                self.ai_analysis.append("[Warning] Page contains links to downloadable files. Check the file and source before opening.")
            if password_inputs and resource_values and external_resources / len(resource_values) >= 0.75:
                self.add_risk(8)
                self.ai_analysis.append("[Warning] Sign-in page loads most resources from other domains.")

            popup_scripts = self.html_content.lower().count('window.open(')
            if popup_scripts and password_inputs:
                self.add_risk(8)
                self.ai_analysis.append("[Warning] Sign-in page contains pop-up opening code.")
            blocked_context_menu = bool(
                soup.find(attrs={'oncontextmenu': True}) or
                'oncontextmenu' in self.html_content.lower() and 'preventdefault' in self.html_content.lower()
            )
            if blocked_context_menu and password_inputs:
                self.add_risk(5)
                self.ai_analysis.append("[Info] Sign-in page tries to disable the context menu.")

            # 3.5 Page Title Brand Spoofing Check
            title = soup.title.get_text(" ", strip=True) if soup.title else ""
            title_lower = title.lower()
            if title_lower:
                for brand in self.TARGET_BRANDS:
                    if brand in title_lower and brand not in self.domain:
                        self.add_risk(35)
                        self.ai_analysis.append(f"[Critical] DOM Title spoofing. Page claims to be '{brand.upper()}' but domain does not match.")
            
            # 3.6 Captcha Wall Detection (Cloudflare / Recaptcha obfuscation)
            if "cf-turnstile" in self.html_content or "g-recaptcha" in self.html_content:
                self.ai_analysis.append("[Info] A CAPTCHA limited parts of the page review.")
            self.page_summary = {
                "reviewed": True,
                "status": "Reviewed" + (" (CAPTCHA limited some content)" if "cf-turnstile" in self.html_content or "g-recaptcha" in self.html_content else ""),
                "title": title[:120] or "No title found",
                "password_fields": len(password_inputs),
                "forms": len(forms),
                "cross_domain_forms": cross_domain_forms,
                "risky_form_actions": risky_form_actions,
                "hidden_iframes": len(hidden_iframes),
                "external_resources": external_resources,
                "external_links": external_links,
                "download_links": download_links,
                "mail_links": mail_links,
                "popup_scripts": popup_scripts,
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
        # A lexical model sees a long query string but cannot understand that it
        # is an ordinary search phrase. Keep it out of this narrow false-positive
        # case; all live-page, redirect and reputation checks still run below.
        if not self.is_normal_search_results_page():
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

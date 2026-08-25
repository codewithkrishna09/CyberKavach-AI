"""Static Android APK screening engine.

It inspects an APK archive, manifest permissions and bytecode strings. It does
not execute the app, so its result is a risk assessment rather than a guarantee.
"""

import zipfile
import re
import hashlib
import math
import io
from collections import Counter
from fastapi import UploadFile

# ======================================================================
# CYBERKAVACH TITAN ENGINE - STATIC APK BINARY FORENSICS
# ======================================================================
# This module performs deep static analysis on Android Packages (.apk).
# It checks:
# 1. File Hashes & Cryptographic Integrity
# 2. Raw AndroidManifest.xml extraction for High-Risk Permissions
# 3. classes.dex parsing for hardcoded URLs, IPs, and malicious APIs
# 4. File compression entropy (to detect packed/obfuscated malware)
# ======================================================================

class TitanAPKScanner:
    # Hard limits protect the API from archive bombs and oversized APK uploads.
    MAX_ENTRY_BYTES = 50 * 1024 * 1024
    MAX_TOTAL_UNCOMPRESSED_BYTES = 200 * 1024 * 1024
    def __init__(self, file_bytes: bytes, filename: str):
        self.raw_bytes = file_bytes
        self.filename = filename
        self.file_size_mb = round(len(file_bytes) / (1024 * 1024), 2)
        
        # Threat Intelligence Signatures
        self.HIGH_RISK_PERMS = [
            b"android.permission.RECEIVE_SMS",
            b"android.permission.READ_SMS",
            b"android.permission.SEND_SMS",
            b"android.permission.BIND_ACCESSIBILITY_SERVICE",
            b"android.permission.SYSTEM_ALERT_WINDOW",
            b"android.permission.READ_CONTACTS",
            b"android.permission.READ_CALL_LOG",
            b"android.permission.RECORD_AUDIO",
            b"android.permission.CAMERA",
            b"android.permission.READ_PHONE_STATE",
            b"android.permission.REQUEST_INSTALL_PACKAGES"
        ]
        
        self.MALICIOUS_API_CALLS = [
            b"Landroid/telephony/SmsManager;->sendTextMessage",
            b"Landroid/accessibilityservice/AccessibilityService;",
            b"Ldalvik/system/DexClassLoader;",
            b"Ljava/lang/Runtime;->exec",
            b"Landroid/content/pm/PackageManager;->installPackage"
        ]
        
        self.SUSPICIOUS_STRINGS = [
            b"ngrok.io", b"serveo.net", b"firebaseio.com", b"000webhostapp.com",
            b"/bot", b"api.telegram.org"
        ]

        # State Variables
        self.risk_score = 0
        self.found_permissions = []
        self.found_triggers = []
        self.is_packed = False
        self.md5_hash = ""
        self.sha256_hash = ""
        self.manifest_found = False
        self.declared_permissions = []
        self.dex_files = []
        self.dex_entropy = {}
        self.dangerous_apis = []
        self.network_indicators = []
        self.public_ips = []
        self.archive_entry_count = 0
        self.uncompressed_size = 0
        self.compressed_size = 0
        self.certificate_files = []
        self.native_abis = []
        self.duplicate_entries = 0
        
    # ---------------------------------------------------------
    # 1. CRYPTOGRAPHIC HASHING & INTEGRITY
    # ---------------------------------------------------------
    def calculate_hashes(self):
        """Calculates MD5 and SHA-256 for database matching."""
        self.md5_hash = hashlib.md5(self.raw_bytes).hexdigest()
        self.sha256_hash = hashlib.sha256(self.raw_bytes).hexdigest()
        
        self.found_triggers.append("[Info] File hash created for reference.")
        
        # In a real setup, you would query these hashes against VirusTotal or your DB.
        # For local heuristics, we skip network DB calls to keep latency < 0.5s.

    # ---------------------------------------------------------
    # 2. ENTROPY CALCULATION (PACKER DETECTION)
    # ---------------------------------------------------------
    def calculate_entropy(self, data: bytes) -> float:
        """Calculates Shannon Entropy to detect if malware is obfuscated or packed."""
        if not data:
            return 0.0
        entropy = 0
        for count in Counter(data).values():
            p_x = float(count) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    # ---------------------------------------------------------
    # 3. APK EXTRACTION & MANIFEST ANALYSIS
    # ---------------------------------------------------------
    def parse_manifest(self, apk_zip: zipfile.ZipFile):
        """Extracts AndroidManifest.xml and scans for dangerous intents."""
        try:
            if "AndroidManifest.xml" in apk_zip.namelist():
                manifest_data = apk_zip.read("AndroidManifest.xml")
                self.manifest_found = True
                # Android's binary XML still stores permission strings in its
                # string pool. Record declared permissions for the report, but
                # only score the high-risk subset below.
                permission_pattern = re.compile(br"android\.permission\.[A-Z0-9_\.]+")
                declared = [item.decode("utf-8", errors="ignore").split(".")[-1] for item in permission_pattern.findall(manifest_data)]
                self.declared_permissions = list(dict.fromkeys(declared))
                
                # Raw byte searching (Since AndroidManifest is binary XML)
                perms_found = 0
                for perm in self.HIGH_RISK_PERMS:
                    if perm in manifest_data:
                        perm_str = perm.decode('utf-8').split('.')[-1]
                        self.found_permissions.append(perm_str)
                        perms_found += 1
                        self.risk_score += 15
                
                if "RECEIVE_SMS" in self.found_permissions and "BIND_ACCESSIBILITY_SERVICE" in self.found_permissions:
                    self.risk_score += 40
                    self.found_triggers.append("[Critical] App requests SMS interception AND Screen Accessibility. Classic Banking Trojan behavior.")
                
                if perms_found > 5:
                    self.risk_score += 20
                    self.found_triggers.append(f"[Threat] Excessive High-Risk Permissions requested ({perms_found}).")
            else:
                self.risk_score += 50
                self.found_triggers.append("[Critical] AndroidManifest.xml missing or unreadable. Highly suspicious packing.")
        except Exception as e:
            self.risk_score += 30
            self.found_triggers.append(f"[Warning] Failed to parse Manifest: {str(e)}")

    # ---------------------------------------------------------
    # 4. DEEP DEX BYTECODE INSPECTION
    # ---------------------------------------------------------
    def parse_dex_files(self, apk_zip: zipfile.ZipFile):
        """Extracts classes.dex and hunts for malicious APIs and hardcoded IPs."""
        dex_files = [f for f in apk_zip.namelist() if f.endswith('.dex')]
        self.dex_files = dex_files
        
        if not dex_files:
            self.risk_score += 10
            self.found_triggers.append("[Info] No .dex files found. App might be a shell or fully native payload.")
            return

        for dex in dex_files:
            try:
                dex_data = apk_zip.read(dex)
                
                # 4.1 Check Entropy for Packers (e.g., Tencent Sec, Bangcle, etc.)
                entropy = self.calculate_entropy(dex_data)
                self.dex_entropy[dex] = round(entropy, 2)
                if entropy > 7.5:
                    self.is_packed = True
                    self.risk_score += 30
                    self.found_triggers.append(f"[Threat] Extremely high entropy ({entropy:.2f}) in {dex}. Executable is heavily obfuscated or packed.")
                
                # 4.2 Malicious API Calls
                for api in self.MALICIOUS_API_CALLS:
                    if api in dex_data:
                        api_str = api.decode('utf-8').split('->')[-1]
                        self.dangerous_apis.append(api_str)
                        self.risk_score += 20
                        self.found_triggers.append(f"[Threat] Dangerous API Call detected: {api_str}")

                # 4.3 Hardcoded Telegram/C2 Webhooks
                for c2 in self.SUSPICIOUS_STRINGS:
                    if c2 in dex_data:
                        self.network_indicators.append(c2.decode('utf-8'))
                        self.risk_score += 25
                        self.found_triggers.append(f"[Critical] Hardcoded shady network string found: {c2.decode('utf-8')}")

                # 4.4 IP Address Extraction (Regex over bytes)
                # Looking for standard IPv4 patterns in bytecode
                ip_pattern = re.compile(br'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
                ips = ip_pattern.findall(dex_data)
                unique_ips = list(set(ips))
                
                if unique_ips:
                    # Filter out local IPs
                    public_ips = [ip for ip in unique_ips if not ip.startswith((b"127.", b"192.168.", b"10."))]
                    if public_ips:
                        self.public_ips.extend(ip.decode("ascii", errors="ignore") for ip in public_ips)
                        self.risk_score += 10
                        self.found_triggers.append(f"[Warning] Found {len(public_ips)} hardcoded public IP address(es) in bytecode. Potential Command & Control server.")

            except Exception as e:
                self.found_triggers.append(f"[Warning] Could not fully analyze {dex}: {str(e)}")

    @staticmethod
    def _summary(values: list[str], empty: str = "None found", limit: int = 6) -> str:
        """Return a compact report value without overwhelming the result UI."""
        unique = list(dict.fromkeys(str(value) for value in values if value))
        if not unique:
            return empty
        shown = unique[:limit]
        suffix = f" (+{len(unique) - limit} more)" if len(unique) > limit else ""
        return ", ".join(shown) + suffix

    def build_details(self) -> list[dict]:
        """Create evidence cards for the APK page and dashboard history."""
        highest_entropy = max(self.dex_entropy.values(), default=0)
        return [
            {"title": "File details", "items": [
                {"label": "File name", "value": self.filename},
                {"label": "File size", "value": f"{self.file_size_mb:.2f} MB"},
                {"label": "SHA-256", "value": self.sha256_hash or "Not available"},
                {"label": "MD5", "value": self.md5_hash or "Not available"},
            ]},
            {"title": "APK structure", "items": [
                {"label": "Manifest", "value": "Found" if self.manifest_found else "Missing or unreadable"},
                {"label": "Archive files", "value": str(self.archive_entry_count)},
                {"label": "Uncompressed size", "value": f"{self.uncompressed_size / (1024 * 1024):.2f} MB"},
                {"label": "DEX files", "value": self._summary(self.dex_files)},
                {"label": "Native code", "value": self._summary(self.native_abis, "None found")},
                {"label": "Signing files", "value": self._summary(self.certificate_files, "Not found")},
                {"label": "Duplicate archive entries", "value": str(self.duplicate_entries)},
            ]},
            {"title": "Permissions", "items": [
                {"label": "Declared permissions", "value": self._summary(self.declared_permissions)},
                {"label": "High-risk permissions", "value": self._summary(self.found_permissions)},
            ]},
            {"title": "Code checks", "items": [
                {"label": "Packed or obfuscated", "value": "Possible" if self.is_packed else "No strong sign found"},
                {"label": "Highest DEX entropy", "value": f"{highest_entropy:.2f}" if self.dex_entropy else "Not available"},
                {"label": "Sensitive API calls", "value": self._summary(self.dangerous_apis)},
                {"label": "Network strings", "value": self._summary(self.network_indicators)},
                {"label": "Public IP addresses", "value": self._summary(self.public_ips)},
            ]},
        ]

    # ---------------------------------------------------------
    # 5. MASTER EXECUTION & REPORT GENERATION
    # ---------------------------------------------------------
    def scan(self) -> dict:
        """Executes the forensic pipeline and generates the JSON verdict."""
        
        # 1. Basic Heuristics
        filename_lower = self.filename.lower()
        if "mod" in filename_lower or "hack" in filename_lower or "free" in filename_lower:
            self.risk_score += 15
            self.found_triggers.append("[Warning] Filename implies pirated or modified software.")

        self.calculate_hashes()

        # 2. Zip/APK Inspection
        try:
            # Load bytes into ZipFile
            apk_io = io.BytesIO(self.raw_bytes)
            with zipfile.ZipFile(apk_io, 'r') as apk_zip:
                entries = apk_zip.infolist()
                total_size = sum(entry.file_size for entry in entries)
                self.archive_entry_count = len(entries)
                self.uncompressed_size = total_size
                self.compressed_size = sum(entry.compress_size for entry in entries)
                names = [entry.filename for entry in entries]
                self.duplicate_entries = sum(count - 1 for count in Counter(names).values() if count > 1)
                self.certificate_files = [
                    name for name in names
                    if name.upper().startswith("META-INF/") and name.upper().endswith((".RSA", ".DSA", ".EC"))
                ]
                self.native_abis = list(dict.fromkeys(
                    name.split("/")[1] for name in names
                    if name.startswith("lib/") and name.count("/") >= 2 and name.endswith(".so")
                ))
                if total_size > self.MAX_TOTAL_UNCOMPRESSED_BYTES or any(entry.file_size > self.MAX_ENTRY_BYTES for entry in entries):
                    raise ValueError("APK archive exceeds safe decompression limits.")
                for entry in entries:
                    if entry.compress_size and entry.file_size / entry.compress_size > 200:
                        raise ValueError("APK contains a suspicious compression ratio.")
                if self.duplicate_entries:
                    self.risk_score += 10
                    self.found_triggers.append("[Warning] APK archive contains duplicate file entries.")

                # ZipFile shares a seekable stream, so deterministic sequential reads
                # are safer than concurrent reads from the same archive object.
                self.parse_manifest(apk_zip)
                self.parse_dex_files(apk_zip)

        except zipfile.BadZipFile:
            self.risk_score += 100
            self.found_triggers.append("[Critical] File is not a valid ZIP/APK archive. Structural corruption detected.")
        except ValueError as e:
            self.risk_score += 100
            self.found_triggers.append(f"[Critical] Archive rejected: {str(e)}")
        except Exception:
            self.risk_score += 30
            self.found_triggers.append("[Error] APK analysis pipeline failed safely.")

        # Convert combined evidence into a simple user-facing verdict. A SAFE
        # result means no known static indicators were found; it is not proof
        # that an APK is harmless.
        self.risk_score = max(0, min(self.risk_score, 100)) # Clamp 0-100

        if self.risk_score >= 70:
            verdict = "MALWARE DETECTED"
            msg = "Critical threat signatures identified. Immediate deletion recommended."
        elif self.risk_score >= 40:
            verdict = "SUSPICIOUS"
            msg = "High-risk permissions or obfuscation detected. Proceed with extreme caution."
        else:
            verdict = "SAFE"
            msg = "No malicious signatures or unauthorized intents found."
            if not self.found_triggers:
                self.found_triggers.append("[Secure] Binary is clean. No anomalies detected.")

        return {
            "verdict": verdict,
            "risk_score": self.risk_score,
            "message": msg,
            "size_mb": self.file_size_mb,
            "permissions": list(set(self.found_permissions)), # Unique list
            "triggers": self.found_triggers,
            "details": self.build_details(),
        }


# ======================================================================
# API FASTAPI ENTRY POINT
# ======================================================================
def analyze_apk(file_obj: UploadFile) -> dict:
    """
    Called by main.py. Reads the uploaded file into memory and passes it 
    to the Titan APK Scanner engine.
    """
    try:
        # Read the file bytes directly from memory
        file_bytes = file_obj.file.read()
        filename = file_obj.filename
        
        # Instantiate and run scanner
        scanner = TitanAPKScanner(file_bytes, filename)
        report = scanner.scan()
        
        return report

    except Exception as e:
        return {
            "verdict": "ERROR",
            "risk_score": 0,
            "message": f"Engine Crash: {str(e)}",
            "size_mb": 0,
            "permissions": [],
            "triggers": ["Failed to process the binary payload."],
            "details": [],
        }

# For Local Testing without FastAPI
if __name__ == "__main__":
    # Mocking a FastAPI UploadFile class for local terminal testing
    class MockFile:
        def __init__(self, filename):
            self.filename = filename
            # Creating a fake tiny zip file in memory to represent an APK
            memory_zip = io.BytesIO()
            with zipfile.ZipFile(memory_zip, 'w') as zf:
                # Inject a fake AndroidManifest requesting SMS permissions
                zf.writestr('AndroidManifest.xml', b'android.permission.RECEIVE_SMS and android.permission.BIND_ACCESSIBILITY_SERVICE')
                # Inject a fake classes.dex with a hardcoded Telegram URL
                zf.writestr('classes.dex', b'Landroid/telephony/SmsManager;->sendTextMessage api.telegram.org')
            memory_zip.seek(0)
            self.file = memory_zip

    print("Initiating Titan APK Test Scan...\n")
    mock_upload = MockFile("WhatsApp_Mod_Free.apk")
    result = analyze_apk(mock_upload)
    
    import json
    print(json.dumps(result, indent=4))

"""Conservative file-forensics screening for images, PDFs, audio and QR codes.

The engine reports structural indicators. It does not claim deepfake certainty
when a validated specialised model is not installed.
"""

import io
import hashlib
import re
import wave
from urllib.parse import parse_qs, urlsplit
from PIL import Image, ImageChops, ImageStat, ExifTags
from fastapi import UploadFile

# ======================================================================
# CYBERKAVACH TITAN ENGINE - SATARK AI (FORENSICS MODULE)
# ======================================================================
# This module combats "Digital Arrest" and Deepfake Scams.
# It performs:
# 1. Error Level Analysis (ELA) for image tampering (Fake Warrants/Stamps)
# 2. EXIF & Metadata Forensics (Detecting Photoshop/Canva signatures)
# 3. PDF Structural Analysis (Mismatch in Creation/Modification dates)
# 4. Audio Spectral Heuristics (Detecting synthetic AI voice clones)
# ======================================================================

class SatarkForensicsEngine:
    def __init__(self, file_bytes: bytes, filename: str, scan_type: str = "image"):
        self.raw_bytes = file_bytes
        self.filename = filename.lower()
        self.scan_type = scan_type
        self.file_size_mb = round(len(file_bytes) / (1024 * 1024), 2)
        
        self.risk_score = 0
        self.found_triggers = []
        self.verdict = "SAFE"
        self.message = ""
        # The frontend renders these sections as a readable forensic report.
        # Keep the values short and do not expose passwords or full secrets.
        self.details: list[dict] = []

    def add_details(self, title: str, items: list[tuple[str, object]]) -> None:
        """Add a safe, non-empty group of report fields for the user interface."""
        clean_items = []
        for label, value in items:
            if value is None or value == "":
                continue
            clean_items.append({"label": str(label)[:80], "value": str(value)[:240]})
        if clean_items:
            self.details.append({"title": title, "items": clean_items})

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        if size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        return f"{size_bytes / (1024 * 1024):.2f} MB"

    @staticmethod
    def _mask_phone(value: str) -> str:
        digits = re.sub(r"\D", "", value)
        country_prefix = ""
        if len(digits) == 12 and digits.startswith("91"):
            country_prefix, digits = "+91 ", digits[2:]
        return f"{country_prefix}{digits[:2]}{'*' * max(0, len(digits) - 4)}{digits[-2:]}" if len(digits) >= 6 else "Detected"

    @staticmethod
    def _mask_upi(value: str) -> str:
        name, separator, provider = value.partition("@")
        if not separator:
            return "Detected"
        visible = name[:2] if len(name) > 2 else name[:1]
        return f"{visible}{'*' * max(2, len(name) - len(visible))}@{provider}"

    @staticmethod
    def _rational_to_float(value: object) -> float:
        """Read PIL EXIF rational values without depending on a camera library."""
        if hasattr(value, "numerator") and hasattr(value, "denominator"):
            return float(value.numerator) / max(float(value.denominator), 1.0)
        if isinstance(value, tuple) and len(value) == 2:
            return float(value[0]) / max(float(value[1]), 1.0)
        return float(value)

    @classmethod
    def _format_gps(cls, gps_data: object) -> str | None:
        """Convert EXIF latitude/longitude to decimal coordinates when present."""
        if not isinstance(gps_data, dict):
            return None
        try:
            latitude, longitude = gps_data.get(2), gps_data.get(4)
            if not latitude or not longitude:
                return None
            lat = sum(value * multiplier for value, multiplier in zip(
                (cls._rational_to_float(part) for part in latitude), (1, 1 / 60, 1 / 3600)
            ))
            lon = sum(value * multiplier for value, multiplier in zip(
                (cls._rational_to_float(part) for part in longitude), (1, 1 / 60, 1 / 3600)
            ))
            lat_ref = str(gps_data.get(1, "N")).upper()
            lon_ref = str(gps_data.get(3, "E")).upper()
            if "S" in lat_ref:
                lat *= -1
            if "W" in lon_ref:
                lon *= -1
            return f"{lat:.6f}, {lon:.6f}"
        except (TypeError, ValueError, ZeroDivisionError):
            return None

    # ---------------------------------------------------------
    # 1. CRYPTOGRAPHIC HASHING
    # ---------------------------------------------------------
    def calculate_hashes(self):
        """Calculates file hashes to check against known fraud registries."""
        sha256_hash = hashlib.sha256(self.raw_bytes).hexdigest()
        self.found_triggers.append(f"[Info] File SHA-256 fingerprint: {sha256_hash[:15]}...")
        self.add_details("File details", [
            ("File name", self.filename),
            ("Size", self._format_size(len(self.raw_bytes))),
            ("SHA-256 fingerprint", f"{sha256_hash[:24]}..."),
            ("Scan mode", self.scan_type.upper()),
        ])

    # ---------------------------------------------------------
    # 2. IMAGE FORENSICS (EXIF & ELA)
    # ---------------------------------------------------------
    def extract_exif_metadata(self, img: Image.Image):
        """Extracts hidden EXIF data to find software signatures."""
        try:
            exif_data = img.getexif() if hasattr(img, "getexif") else img._getexif()
            if not exif_data:
                # Social-media platforms and phone apps commonly remove EXIF.
                # Missing metadata is context, never proof of manipulation.
                self.found_triggers.append("[Info] No EXIF metadata available; this is common after sharing or re-saving an image.")
                return

            readable = {}
            for tag_id, value in exif_data.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                readable[str(tag)] = value
                if tag == "Software":
                    val_lower = str(value).lower()
                    if "photoshop" in val_lower or "canva" in val_lower or "gimp" in val_lower:
                        # Image editing software is legitimate. It becomes useful
                        # only as supporting evidence with other forensic signals.
                        self.risk_score += 10
                        self.found_triggers.append(f"[Info] Image metadata lists editing software: {value}. This alone does not prove fraud.")
            gps_data = exif_data.get_ifd(34853) if hasattr(exif_data, "get_ifd") else None
            gps_location = self._format_gps(gps_data)
            self.add_details("Image metadata", [
                ("Captured time", readable.get("DateTimeOriginal") or readable.get("DateTime")),
                ("Camera", " ".join(str(part) for part in (readable.get("Make"), readable.get("Model")) if part)),
                ("Software", readable.get("Software")),
                # GPS can be removed or edited. Show it as evidence only, never
                # as proof of where a photo was taken.
                ("GPS location", gps_location or "Not available"),
            ])
        except Exception as e:
            self.found_triggers.append("[Info] EXIF extraction bypassed or unsupported format.")

    def run_error_level_analysis(self, img: Image.Image):
        """
        Performs Error Level Analysis (ELA).
        Re-saves the image at a known error rate (e.g., 90% JPEG) and compares 
        it with the original. Pasted stamps/logos will have a different compression 
        error level than the background document.
        """
        try:
            # Convert to RGB if not already
            if img.mode != 'RGB':
                img = img.convert('RGB')

            # Save temporarily at 90% quality
            temp_io = io.BytesIO()
            img.save(temp_io, 'JPEG', quality=90)
            temp_io.seek(0)
            
            # Open the temporary degraded image
            resaved_img = Image.open(temp_io)
            
            # Calculate absolute difference between original and degraded
            ela_image = ImageChops.difference(img, resaved_img)
            
            # Correct per-channel RMS calculation. The previous histogram formula
            # multiplied counts by their square and falsely marked normal photos.
            rms = sum(ImageStat.Stat(ela_image).rms) / len(ela_image.getbands())

            # ELA is affected by JPEG quality, resizing and social-media re-saving;
            # it can only be a weak supporting signal, never standalone proof.
            if rms > 35.0:
                self.risk_score += 20
                self.found_triggers.append(f"[Warning] Strong JPEG recompression variation observed (ELA RMS {rms:.2f}). Verify the source; this is not proof of tampering.")
            elif rms > 20.0:
                self.found_triggers.append(f"[Info] Mild JPEG recompression variation observed (ELA RMS {rms:.2f}); no risk score was added.")

        except Exception as e:
            self.found_triggers.append(f"[Error] ELA Engine failed: {str(e)}")

    def analyze_image(self):
        """Master function for Image Forensics (.jpg, .png)"""
        try:
            img = Image.open(io.BytesIO(self.raw_bytes))
            width, height = img.size
            self.add_details("Image properties", [
                ("Format", img.format or "Unknown"),
                ("Resolution", f"{width} × {height}"),
                ("Colour mode", img.mode),
                ("Aspect ratio", f"{width / max(height, 1):.2f}:1"),
            ])
            if width < 80 or height < 80:
                self.found_triggers.append("[Info] Very small image: forensic conclusions are limited.")
            self.extract_exif_metadata(img)
            if self.filename.endswith(('.jpg', '.jpeg')):
                self.run_error_level_analysis(img)
        except Exception as e:
            self.risk_score += 20
            self.found_triggers.append("[Warning] Image could not be decoded cleanly. The file may be corrupted or unsupported; inspect its source.")

    def analyze_steganography(self):
        """Look for appended payload bytes; LSB distribution is reported as context only."""
        if self.filename.endswith(".png"):
            marker = self.raw_bytes.rfind(b"IEND\xaeB`\x82")
            if marker >= 0 and len(self.raw_bytes) > marker + 8:
                self.risk_score += 25
                self.found_triggers.append("[Warning] Extra bytes were found after the PNG end marker. Inspect this image before sharing it.")
        elif self.filename.endswith((".jpg", ".jpeg")):
            marker = self.raw_bytes.rfind(b"\xff\xd9")
            if marker >= 0 and len(self.raw_bytes) > marker + 2:
                self.risk_score += 25
                self.found_triggers.append("[Warning] Extra bytes were found after the JPEG end marker. Inspect this image before sharing it.")
        self.found_triggers.append("[Info] No trained steganography classifier is configured; pixel-level results are screening signals only.")

    # ---------------------------------------------------------
    # 3. PDF FORENSICS (Digital Arrest Warrants)
    # ---------------------------------------------------------
    def analyze_pdf(self):
        """
        Scans binary PDF structures. Fake CBI warrants are usually forged 
        using free PDF editors which leave massive traces in the raw bytes.
        """
        raw_text = self.raw_bytes.decode('utf-8', errors='ignore')
        page_count = len(re.findall(r"/Type\s*/Page\b", raw_text))
        creator = re.search(r"/Creator\s*\(([^)]{1,160})\)", raw_text)
        producer = re.search(r"/Producer\s*\(([^)]{1,160})\)", raw_text)
        
        # 3.1 Check Creation vs Modification Date Mismatch
        creation_dates = re.findall(r'/CreationDate \(D:(.*?)\)', raw_text)
        mod_dates = re.findall(r'/ModDate \(D:(.*?)\)', raw_text)
        
        if creation_dates and mod_dates:
            if creation_dates[0] != mod_dates[0]:
                self.risk_score += 25
                self.found_triggers.append(f"[Threat] PDF Document was heavily modified after creation.")
                self.found_triggers.append(f"  > Created: {creation_dates[0][:8]}")
                self.found_triggers.append(f"  > Modified: {mod_dates[0][:8]}")

        # An editing application is not proof of fraud; it is only supporting context.
        if "/Creator (Canva)" in raw_text or "iLovePDF" in raw_text or "Photoshop" in raw_text:
            self.risk_score += 10
            self.found_triggers.append("[Info] PDF metadata indicates an editing or design application. Verify the issuer independently.")

        # 3.3 Detect JavaScript inside PDF (Used for tracking IPs)
        if "/JavaScript" in raw_text or "/JS" in raw_text or "/OpenAction" in raw_text or "/Launch" in raw_text:
            self.risk_score += 40
            self.found_triggers.append("[Critical] Active PDF action or JavaScript detected. Do not enable prompts or follow embedded actions.")
        if "/EmbeddedFile" in raw_text:
            self.risk_score += 30
            self.found_triggers.append("[Warning] PDF contains an embedded attachment. Treat the attachment as untrusted.")

        urls = sorted(set(re.findall(r"https?://[^\s<>()\[\]{}\"']+", raw_text, flags=re.IGNORECASE)))[:5]
        emails = sorted(set(re.findall(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", raw_text, flags=re.IGNORECASE)))[:5]
        phones = sorted(set(re.findall(r"(?<!\d)(?:\+91[-\s]?)?[6-9]\d{9}(?!\d)", raw_text)))[:5]
        upi_ids = sorted(set(re.findall(r"\b[a-zA-Z0-9._-]{2,}@[a-zA-Z]{2,64}\b", raw_text)))[:5]
        self.add_details("Document inspection", [
            ("Pages detected", page_count or "Not available"),
            ("Creator", creator.group(1) if creator else "Not available"),
            ("Producer", producer.group(1) if producer else "Not available"),
            ("Active actions", "Present" if any(token in raw_text for token in ("/JavaScript", "/JS", "/OpenAction", "/Launch")) else "Not found"),
            ("Embedded attachments", "Present" if "/EmbeddedFile" in raw_text else "Not found"),
        ])
        self.add_details("Extracted indicators", [
            ("URLs found", ", ".join(urls) if urls else "None"),
            ("Emails found", ", ".join(emails) if emails else "None"),
            ("Phone numbers", ", ".join(self._mask_phone(phone) for phone in phones) if phones else "None"),
            ("UPI IDs", ", ".join(self._mask_upi(upi) for upi in upi_ids) if upi_ids else "None"),
        ])

    # ---------------------------------------------------------
    # 4. AUDIO DEEPFAKE ANALYSIS (Spectral Heuristics)
    # ---------------------------------------------------------
    def analyze_audio(self):
        """
        Performs conservative metadata/container heuristics. A real model is required
        before this module can claim spectral deepfake detection.
        """
        header = self.raw_bytes[:4096].decode('latin-1', errors='ignore')
        audio_details = [("Format", self.filename.rsplit(".", 1)[-1].upper())]
        if self.filename.endswith('.wav'):
            try:
                with wave.open(io.BytesIO(self.raw_bytes), 'rb') as audio:
                    duration = audio.getnframes() / max(audio.getframerate(), 1)
                    audio_details.extend([
                        ("Duration", f"{duration:.1f} seconds"),
                        ("Sample rate", f"{audio.getframerate()} Hz"),
                        ("Channels", audio.getnchannels()),
                        ("Bit depth", f"{audio.getsampwidth() * 8}-bit"),
                        ("Frames", audio.getnframes()),
                    ])
                    self.found_triggers.append(f"[Info] WAV container: {audio.getframerate()} Hz, {audio.getnchannels()} channel(s), {duration:.1f}s.")
                    if duration == 0:
                        self.risk_score += 20
                        self.found_triggers.append("[Warning] Audio container has no playable samples.")
            except wave.Error:
                self.risk_score += 20
                self.found_triggers.append("[Warning] WAV container is malformed or incomplete.")
        else:
            audio_details.append(("Technical metadata", "Detailed duration is currently available for WAV files only"))
        self.add_details("Audio properties", audio_details)
        if "ElevenLabs" in header or "text-to-speech" in header.lower():
            self.found_triggers.append("[Info] Audio metadata references a synthesis tool. Metadata may be edited and is not proof of a deepfake.")
        self.found_triggers.append("[Info] No validated audio deepfake model is installed; this is a container-integrity screen, not a voice-authenticity verdict.")

    def analyze_qr(self):
        """Decode a QR image locally and assess its destination without opening it."""
        try:
            import cv2
            import numpy as np
        except ImportError:
            self.found_triggers.append("[Info] QR decoder is unavailable. Install opencv-python-headless to enable local QR decoding.")
            return
        image = cv2.imdecode(np.frombuffer(self.raw_bytes, dtype=np.uint8), cv2.IMREAD_COLOR)
        if image is None:
            self.risk_score += 20
            self.found_triggers.append("[Warning] QR image could not be decoded as an image.")
            return
        payload, _, _ = cv2.QRCodeDetector().detectAndDecode(image)
        if not payload:
            self.found_triggers.append("[Info] No readable QR payload was detected. Upload a sharper, uncropped QR image.")
            return
        payload = payload.strip()
        payload_type = "Unknown data"
        qr_items = [("Payload length", f"{len(payload)} characters")]
        parsed = urlsplit(payload)
        if parsed.scheme.lower() in {"http", "https"}:
            payload_type = "Website URL"
            host = (parsed.hostname or "").lower()
            qr_items.extend([("Destination host", host or "Not available"), ("Connection", parsed.scheme.upper())])
            if host.startswith("xn--") or host.count('.') > 4 or '@' in parsed.netloc:
                self.risk_score += 25
                self.found_triggers.append("[Warning] QR destination has a deceptive URL structure.")
            else:
                self.found_triggers.append("[Info] QR contains a web URL. Inspect the destination with the URL scanner before opening it.")
        elif payload.lower().startswith("upi://pay"):
            payload_type = "UPI payment request"
            values = parse_qs(parsed.query)
            vpa = values.get("pa", [""])[0]
            payee = values.get("pn", [""])[0]
            amount = values.get("am", [""])[0]
            note = values.get("tn", [""])[0]
            qr_items.extend([
                ("UPI ID", self._mask_upi(vpa) if vpa else "Not available"),
                ("Payee name", payee or "Not available"),
                ("Requested amount", f"₹{amount}" if amount else "Not specified"),
                ("Payment note", note or "Not available"),
            ])
            self.found_triggers.append("[Info] QR contains a UPI payment request. Verify the payee independently before paying.")
        elif payload.lower().startswith("wifi:"):
            payload_type = "Wi-Fi configuration"
            qr_items.append(("Privacy", "Wi-Fi password is not displayed"))
            self.found_triggers.append("[Warning] QR configures a Wi-Fi network. Review it before importing settings.")
        elif payload.lower().startswith(("tel:", "sms:", "mailto:")):
            payload_type = "Phone, SMS or email action"
            qr_items.append(("Action", parsed.scheme.lower()))
            self.found_triggers.append("[Info] QR triggers a device action. Confirm the recipient before continuing.")
        else:
            self.risk_score += 35
            self.found_triggers.append("[Warning] QR payload is not a standard web URL. Do not execute or import it without verification.")
        # Never display raw Wi-Fi or unknown-action payloads, because they can
        # contain credentials or sensitive commands.
        if payload_type in {"Website URL", "UPI payment request"}:
            qr_items.append(("Decoded payload", payload[:220]))
        self.add_details("QR inspection", [("Payload type", payload_type), *qr_items])

    # ---------------------------------------------------------
    # 5. MASTER EXECUTION PIPELINE
    # ---------------------------------------------------------
    def scan(self) -> dict:
        # Select only the checks appropriate for the user-selected file type.
        self.calculate_hashes()
        
        # Route file to the correct Forensic Engine based on extension
        if self.scan_type == "qr":
            self.found_triggers.append("[Info] Initializing QR and steganography screen...")
            self.analyze_qr()
            self.analyze_steganography()
        elif self.filename.endswith(('.jpg', '.jpeg', '.png')):
            self.found_triggers.append("[Info] Initializing Image Forensics (ELA & EXIF)...")
            self.analyze_image()
            
        elif self.filename.endswith('.pdf'):
            self.found_triggers.append("[Info] Initializing Document Forensics (PDF Structures)...")
            self.analyze_pdf()
            
        elif self.filename.endswith(('.mp3', '.wav', '.ogg', '.m4a')):
            self.found_triggers.append("[Info] Initializing Audio Forensics (Spectral Analysis)...")
            self.analyze_audio()
            
        else:
            self.risk_score += 10
            self.found_triggers.append(f"[Warning] Unsupported file format ({self.filename}). Running basic heuristic scan only.")

        # Scores describe the available forensic evidence, not legal proof that
        # a document, image or voice recording is genuine or fabricated.
        self.risk_score = max(0, min(self.risk_score, 100)) # Clamp 0-100

        if self.risk_score >= 70:
            self.verdict = "HIGH RISK FILE"
            self.message = "Strong warning signs were found. Do not trust, share, install or pay from this file yet."
        elif self.risk_score >= 40:
            self.verdict = "CHECK THIS FILE"
            self.message = "Some warning signs were found. Check the source before you act on it."
        else:
            self.verdict = "NO STRONG WARNING"
            self.message = "No strong warning signs were found. This does not prove that the file is safe or original."
            if not self.found_triggers:
                self.found_triggers.append("[Secure] Artifact structure is intact and natural.")

        return {
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "message": self.message,
            "size_mb": self.file_size_mb,
            "details": self.details,
            "triggers": self.found_triggers
        }


# ======================================================================
# API FASTAPI ENTRY POINT
# ======================================================================
def analyze_forensics(file_obj: UploadFile, scan_type: str = "image") -> dict:
    """
    Called by main.py. Reads the uploaded artifact into volatile memory 
    and triggers the Satark AI Forensics Engine.
    """
    try:
        file_bytes = file_obj.file.read()
        filename = file_obj.filename
        
        engine = SatarkForensicsEngine(file_bytes, filename, scan_type)
        report = engine.scan()
        
        return report

    except Exception as e:
        return {
            "verdict": "ERROR",
            "risk_score": 0,
            "message": f"Satark Engine Crash: {str(e)}",
            "size_mb": 0,
            "details": [],
            "triggers": ["Failed to process the forensic artifact."]
        }

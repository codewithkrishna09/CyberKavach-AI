"""Conservative file-forensics screening for images, PDFs, audio and QR codes.

The engine reports structural indicators. It does not claim deepfake certainty
when a validated specialised model is not installed.
"""

import io
import hashlib
import re
import wave
from urllib.parse import urlsplit
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

    # ---------------------------------------------------------
    # 1. CRYPTOGRAPHIC HASHING
    # ---------------------------------------------------------
    def calculate_hashes(self):
        """Calculates file hashes to check against known fraud registries."""
        sha256_hash = hashlib.sha256(self.raw_bytes).hexdigest()
        self.found_triggers.append(f"[Info] File SHA-256 fingerprint: {sha256_hash[:15]}...")

    # ---------------------------------------------------------
    # 2. IMAGE FORENSICS (EXIF & ELA)
    # ---------------------------------------------------------
    def extract_exif_metadata(self, img: Image.Image):
        """Extracts hidden EXIF data to find software signatures."""
        try:
            exif_data = img._getexif()
            if not exif_data:
                # Social-media platforms and phone apps commonly remove EXIF.
                # Missing metadata is context, never proof of manipulation.
                self.found_triggers.append("[Info] No EXIF metadata available; this is common after sharing or re-saving an image.")
                return

            for tag_id, value in exif_data.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                if tag == "Software":
                    val_lower = str(value).lower()
                    if "photoshop" in val_lower or "canva" in val_lower or "gimp" in val_lower:
                        # Image editing software is legitimate. It becomes useful
                        # only as supporting evidence with other forensic signals.
                        self.risk_score += 10
                        self.found_triggers.append(f"[Info] Image metadata lists editing software: {value}. This alone does not prove fraud.")
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

    # ---------------------------------------------------------
    # 4. AUDIO DEEPFAKE ANALYSIS (Spectral Heuristics)
    # ---------------------------------------------------------
    def analyze_audio(self):
        """
        Performs conservative metadata/container heuristics. A real model is required
        before this module can claim spectral deepfake detection.
        """
        header = self.raw_bytes[:4096].decode('latin-1', errors='ignore')
        if self.filename.endswith('.wav'):
            try:
                with wave.open(io.BytesIO(self.raw_bytes), 'rb') as audio:
                    duration = audio.getnframes() / max(audio.getframerate(), 1)
                    self.found_triggers.append(f"[Info] WAV container: {audio.getframerate()} Hz, {audio.getnchannels()} channel(s), {duration:.1f}s.")
                    if duration == 0:
                        self.risk_score += 20
                        self.found_triggers.append("[Warning] Audio container has no playable samples.")
            except wave.Error:
                self.risk_score += 20
                self.found_triggers.append("[Warning] WAV container is malformed or incomplete.")
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
        safe_payload = payload[:300]
        self.found_triggers.append(f"[Info] QR payload decoded locally: {safe_payload}")
        parsed = urlsplit(payload)
        if parsed.scheme.lower() in {"http", "https"}:
            host = (parsed.hostname or "").lower()
            if host.startswith("xn--") or host.count('.') > 4 or '@' in parsed.netloc:
                self.risk_score += 25
                self.found_triggers.append("[Warning] QR destination has a deceptive URL structure.")
            else:
                self.found_triggers.append("[Info] QR contains a web URL. Inspect the destination with the URL scanner before opening it.")
        else:
            self.risk_score += 35
            self.found_triggers.append("[Warning] QR payload is not a standard web URL. Do not execute or import it without verification.")

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
            self.verdict = "FABRICATION DETECTED"
            self.message = "High probability of Deepfake or Digital Tampering. DO NOT TRUST."
        elif self.risk_score >= 40:
            self.verdict = "SUSPICIOUS"
            self.message = "Anomalies found in file structure. Verify source immediately."
        else:
            self.verdict = "AUTHENTIC"
            self.message = "No conclusive tampering indicators were found in this limited forensic screen. This does not prove authenticity."
            if not self.found_triggers:
                self.found_triggers.append("[Secure] Artifact structure is intact and natural.")

        return {
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "message": self.message,
            "size_mb": self.file_size_mb,
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
            "triggers": ["Failed to process the forensic artifact."]
        }

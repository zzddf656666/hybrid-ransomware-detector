#!/usr/bin/env python3
"""
Hybrid Ransomware Detection System - cross-platform scanner for documents.

This script scans documents (PDF, Word, and other Office formats) for potential
ransomware / malicious behaviour by fusing several independent detection layers:

  1. Cryptographic hashes (MD5 + SHA-256) checked against a local malware dataset
  2. Fuzzy / similarity hashing (TLSH + ssdeep) to catch polymorphic *families*
     by structural similarity instead of exact byte matches
  3. Static VBA/XLM macro analysis (olevba) to target the actual dropper
     mechanism in weaponised Office documents
  4. YARA pattern matching against a rules directory (structural IOCs)
  5. LLM semantic analysis of the document text - via a LOCAL model (Ollama) by
     default for OPSEC, with an optional cloud (OpenAI) fallback
  6. VirusTotal multi-engine reputation
  7. A transparent, weighted scoring matrix that fuses every signal into a
     0-100 risk score (+ legacy 0-10 severity) with a full evidence breakdown
  8. A comprehensive JSON + TXT report
  9. Optional automatic scanning at login (Windows, macOS, or Linux)

Every optional layer (fuzzy/macro/YARA/LLM/VirusTotal) degrades gracefully when
its dependency or API key is missing, so the core local-hash check always runs.
This tool is for DEFENSIVE and educational use - analysing suspect documents,
never executing or creating malware. No macro or payload is ever run.
"""

import os
import sys
import time
import json
import hashlib
import logging
import requests
from dotenv import load_dotenv
import schedule
import argparse
import platform
import subprocess
import shutil
try:
    import winreg  # Windows registry module (Windows only)
except ImportError:
    winreg = None  # Non-Windows: autostart features are disabled gracefully
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Union
from pdf2image import convert_from_path
import pytesseract
from PIL import Image
# For handling Word and PDF files
import docx
import PyPDF2

# Modular detection engines (each degrades gracefully if its dependency is
# missing). Importing the package never raises on absent third-party libs.
from detectors import (
    FuzzyHasher, FUZZY_AVAILABLE,
    MacroAnalyzer, OLEVBA_AVAILABLE,
    YaraEngine, YARA_AVAILABLE,
    build_llm_backend,
    ScoringMatrix,
)

# Resolve per-user paths dynamically so they adapt to the host OS (Windows/macOS/Linux)
USER_HOME = Path.home()
APP_DIR = USER_HOME / "RansomwareScanner"
DATA_DIR = APP_DIR / "data"
REPORT_DIR = APP_DIR / "scan_reports"
LOG_FILE = APP_DIR / "ransomware_scanner.log"

# Repo-relative assets that ship with the scanner (YARA rules, sample signatures).
SCRIPT_DIR = Path(__file__).resolve().parent
BUNDLED_RULES_DIR = SCRIPT_DIR / "rules"
BUNDLED_FUZZY_SIGS = SCRIPT_DIR / "fuzzy_signatures.sample.json"

# Create application directories if they don't exist
APP_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# For handling CSV database
import csv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("RansomwareScanner")

# Load API keys from a local .env file (NEVER commit real keys to source control)
load_dotenv()

# Configuration - paths derive from the user's home directory and adapt to the OS
CONFIG = {
    "scan_directories": [
        str(USER_HOME / "Downloads"),
        # Add more folders to scan as needed
    ],
    "file_extensions": [".pdf", ".docx", ".doc"],
    "kaggle_database_path": str(DATA_DIR / "data_file.csv"),

    # --- LLM semantic layer -------------------------------------------------
    # llm_provider: "auto" (prefer a reachable LOCAL Ollama for OPSEC, else fall
    # back to OpenAI if a key is set), "ollama", "openai", or "none".
    "llm_provider": os.getenv("LLM_PROVIDER", "auto"),
    "ollama_host": os.getenv("OLLAMA_HOST", "http://localhost:11434"),
    "ollama_model": os.getenv("OLLAMA_MODEL", "llama3.1"),
    "chatgpt_api_key": os.getenv("OPENAI_API_KEY", ""),
    "chatgpt_api_url": "https://api.openai.com/v1/chat/completions",
    "openai_model": os.getenv("OPENAI_MODEL", "gpt-4"),

    # --- Fuzzy / similarity hashing ----------------------------------------
    # Falls back to the bundled sample if no per-user DB exists.
    "fuzzy_signature_db": os.getenv("FUZZY_SIGNATURE_DB", str(DATA_DIR / "fuzzy_signatures.json")),
    "fuzzy_max_bytes": 20 * 1024 * 1024,   # don't fuzzy-hash files larger than this

    # --- YARA ---------------------------------------------------------------
    "yara_rules_dir": os.getenv("YARA_RULES_DIR", str(BUNDLED_RULES_DIR)),

    # --- VirusTotal ---------------------------------------------------------
    "virustotal_api_key": os.getenv("VIRUSTOTAL_API_KEY", ""),
    "virustotal_api_url": "https://www.virustotal.com/api/v3/files",

    "report_directory": str(REPORT_DIR),
    "scan_interval_hours": 6,  # Scan every 6 hours
}

def extract_suspicious_strings(file_path: str, min_len: int = 5, chunk_size: int = 4096) -> str:
    """Extract human-readable ASCII strings from a file using memory-efficient chunked reads."""
    strings = []
    current = bytearray()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                for byte in chunk:
                    if 32 <= byte <= 126:  # printable ASCII
                        current.append(byte)
                    else:
                        if len(current) >= min_len:
                            strings.append(current.decode(errors="ignore"))
                        current = bytearray()
            if len(current) >= min_len:
                strings.append(current.decode(errors="ignore"))
    except Exception as e:
        logger.error(f"Error extracting strings from {file_path}: {str(e)}")
    return "\n".join(strings)

class RansomwareScanner:
    """Main scanner class for detecting potential ransomware in PDF and Word files."""
    
    def __init__(self, config: Dict):
        """Initialize the scanner with configuration settings."""
        self.config = config
        self.scan_dirs = config["scan_directories"]  # Already expanded
        self.file_extensions = config["file_extensions"]
        self.kaggle_db_path = config["kaggle_database_path"]
        self.report_dir = config["report_directory"]
        
        # Ensure reports directory exists
        os.makedirs(self.report_dir, exist_ok=True)
        
        # Load Kaggle database
        self.hash_database = self._load_kaggle_database()

        # --- Initialise the modular detection engines -----------------------
        # Fuzzy hashing: prefer a per-user signature DB, else the bundled sample.
        fuzzy_db = config.get("fuzzy_signature_db")
        if not (fuzzy_db and os.path.exists(fuzzy_db)) and BUNDLED_FUZZY_SIGS.exists():
            fuzzy_db = str(BUNDLED_FUZZY_SIGS)
        self.fuzzy_hasher = FuzzyHasher(signature_db_path=fuzzy_db)
        self.fuzzy_max_bytes = int(config.get("fuzzy_max_bytes", 20 * 1024 * 1024))

        # Static macro analysis (olevba).
        self.macro_analyzer = MacroAnalyzer()

        # YARA engine over the configured rules directory.
        self.yara_engine = YaraEngine(rules_dir=config.get("yara_rules_dir"))

        # LLM backend (local Ollama by default; cloud OpenAI optional).
        self.llm_backend = build_llm_backend(config)

        # Weighted scoring matrix that fuses every layer's signals.
        self.scoring = ScoringMatrix()

        logger.info(f"Scanner initialized. Monitoring directories: {self.scan_dirs}")
        logger.info(
            "Detection layers -> fuzzy:%s  macro:%s  yara:%s(%d rule files)  "
            "llm:%s%s  virustotal:%s",
            "on" if FUZZY_AVAILABLE else "off (install python-tlsh/ppdeep)",
            "on" if OLEVBA_AVAILABLE else "off (install oletools)",
            "on" if YARA_AVAILABLE else "off (install yara-python)",
            getattr(self.yara_engine, "_rules_count", 0),
            self.llm_backend.name,
            " [LOCAL]" if getattr(self.llm_backend, "is_local", False) else
            (" [CLOUD]" if self.llm_backend.name == "openai" else ""),
            "on" if config.get("virustotal_api_key") else "off (no API key)",
        )
    
    def _load_kaggle_database(self) -> set:
        """Load malicious MD5 hashes into a memory-efficient set (streaming CSV, no pandas)."""
        malicious_hashes = set()
        try:
            if not os.path.exists(self.kaggle_db_path):
                logger.warning(f"Malware database not found at {self.kaggle_db_path}. "
                               f"Expected columns: FileName, md5Hash, Benign.")
                return malicious_hashes

            logger.info(f"Loading malware database from {self.kaggle_db_path}")
            with open(self.kaggle_db_path, mode="r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # A row is malicious when the 'Benign' flag is false/0/no
                    benign_value = str(row.get("Benign", "")).strip().lower()
                    is_malicious = benign_value in ["0", "false", "no", "n"]
                    if is_malicious:
                        md5 = row.get("md5Hash")
                        if md5:
                            malicious_hashes.add(md5.strip().lower())

            logger.info(f"Loaded {len(malicious_hashes)} malicious hashes into memory.")
            return malicious_hashes
        except Exception as e:
            logger.error(f"Error loading malware database: {str(e)}")
            return set()

    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate MD5 and SHA-256 using memory-efficient chunked reads.

        MD5 is kept for the local dataset lookup; SHA-256 is the modern
        identifier used for VirusTotal and as the canonical file hash.
        """
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
            return {"md5": md5_hash.hexdigest(), "sha256": sha256_hash.hexdigest()}
        except Exception as e:
            logger.error(f"Error calculating hashes for {file_path}: {str(e)}")
            return {"md5": "", "sha256": ""}

    def check_hash_in_database(self, file_hash: str) -> Tuple[bool, Dict]:
        """Check whether an MD5 hash is present in the local malicious-hash set."""
        if file_hash and file_hash.lower() in self.hash_database:
            return True, {"reason": "Identified as malicious in local hash database"}
        return False, {}
    
    def analyze_with_llm(self, file_path: str) -> Dict:
        """Send document content + embedded strings to the configured LLM backend.

        The backend is chosen once at init (local Ollama by default for OPSEC,
        cloud OpenAI optional). Prompt-injection hardening lives in the backend:
        analyst instructions in the system role, untrusted file content in the
        user role, temperature 0, JSON-only output.
        """
        try:
            # Extract visible content
            file_content = self._extract_text_from_file(file_path)

            # Extract strings (includes code/keywords/shell hints)
            embedded_strings = extract_suspicious_strings(file_path)

            # Skip empty results before spending an LLM call
            if not file_content.strip() and not embedded_strings.strip():
                logger.warning(f"No content or strings extracted from {file_path}. Skipping LLM analysis.")
                return {
                    "is_malicious": False,
                    "confidence": 0,
                    "details": "No content or strings to analyze.",
                    "suspicious_elements": []
                }

            # Combine both (truncated to keep the prompt bounded)
            combined = (
                "Visible Document Content:\n"
                f"{file_content[:3000]}\n\n"
                "Extracted Embedded Strings:\n"
                f"{embedded_strings[:2000]}"
            )

            return self.llm_backend.analyze(combined)
        except Exception as e:
            logger.error(f"Error in LLM analysis for {file_path}: {str(e)}")
            return {
                "is_malicious": False,
                "confidence": 0,
                "details": "LLM analysis failed.",
                "suspicious_elements": []
            }

    # Backward-compatible alias: older callers / docs reference analyze_with_chatgpt.
    def analyze_with_chatgpt(self, file_path: str) -> Dict:
        return self.analyze_with_llm(file_path)
    
    def _extract_text_from_file(self, file_path: str) -> str:
        """Extract text content from PDF or Word document."""
        file_ext = os.path.splitext(file_path)[1].lower()
        
        try:
            if file_ext == ".pdf":
                text = self._extract_text_from_pdf(file_path)
                if not text.strip():
                    logger.info(f"No text found in PDF. Using OCR fallback for {file_path}")
                    text = self._extract_text_with_ocr_from_pdf(file_path)
                return text
            elif file_ext in [".docx", ".doc"]:
                return self._extract_text_from_word(file_path)
            else:
                return "Unsupported file format"
        except Exception as e:
            logger.error(f"Error extracting text from {file_path}: {str(e)}")
            return f"Error extracting text: {str(e)}"
    
    def _extract_text_from_pdf(self, file_path: str) -> str:
        """Extract text from a PDF file."""
        text = ""
        try:
            with open(file_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                for page_num in range(len(pdf_reader.pages)):
                    text += pdf_reader.pages[page_num].extract_text() + "\n"
            return text
        except Exception as e:
            logger.error(f"Error extracting PDF text: {str(e)}")
            return f"Error extracting PDF text: {str(e)}"
    def _extract_text_with_ocr_from_pdf(self, file_path: str) -> str:
        """Extract text from a PDF file using OCR if it is image-based."""
        try:
            images = convert_from_path(file_path)
            text = ""
            for img in images:
                text += pytesseract.image_to_string(img)
            return text
        except Exception as e:
            logger.error(f"OCR failed for PDF {file_path}: {str(e)}")
            return ""
    
    def _extract_text_from_word(self, file_path: str) -> str:
        """Extract text from a Word document."""
        try:
            doc = docx.Document(file_path)
            return "\n".join([paragraph.text for paragraph in doc.paragraphs])
        except Exception as e:
            logger.error(f"Error extracting Word text: {str(e)}")
            return f"Error extracting Word text: {str(e)}"
    
    def scan_file_with_virustotal(self, file_path: str) -> Dict:
        """Upload file to VirusTotal and get analysis results."""
        if not self.config.get("virustotal_api_key"):
            return {"is_malicious": False, "detection_ratio": 0,
                    "malicious_detections": 0, "suspicious_detections": 0,
                    "total_engines": 0, "permalink": "",
                    "details": "VirusTotal API key not configured; reputation layer skipped."}
        try:
            # VirusTotal identifies files primarily by SHA-256
            hashes = self.calculate_hashes(file_path)
            file_hash = hashes["sha256"] or hashes["md5"]
            
            # Check if the file has already been analyzed
            headers = {
                "x-apikey": self.config["virustotal_api_key"]
            }
            
            # First, check if the file is already in VirusTotal database
            check_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            response = requests.get(check_url, headers=headers)
            
            # If file is not found in VirusTotal, upload it
            if response.status_code == 404:
                logger.info(f"File {file_path} not found in VirusTotal. Uploading...")

                # VirusTotal: files < 32 MB use the standard /files endpoint;
                # larger files require a dedicated one-time upload URL.
                file_size = os.path.getsize(file_path)
                MB_32 = 32 * 1024 * 1024
                if file_size < MB_32:
                    upload_url = "https://www.virustotal.com/api/v3/files"
                    logger.info("Using standard upload endpoint (file < 32 MB).")
                else:
                    logger.info("File >= 32 MB; requesting a dedicated upload URL...")
                    upload_url_response = requests.get(
                        "https://www.virustotal.com/api/v3/files/upload_url",
                        headers=headers,
                    )
                    if upload_url_response.status_code != 200:
                        logger.error(f"Error getting VirusTotal upload URL: {upload_url_response.status_code}")
                        upload_url = ""
                    else:
                        upload_url = upload_url_response.json().get("data", "")

                if upload_url:
                    with open(file_path, "rb") as file:
                        files = {"file": (os.path.basename(file_path), file)}
                        upload_response = requests.post(upload_url, headers=headers, files=files)

                    if upload_response.status_code == 200:
                        analysis_id = upload_response.json().get("data", {}).get("id", "")
                        logger.info(f"File uploaded to VirusTotal. Analysis ID: {analysis_id}")
                        logger.info("Waiting for VirusTotal analysis to complete...")

                        max_attempts = 10
                        attempt = 0
                        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                        while attempt < max_attempts:
                            time.sleep(15)  # Wait between status checks
                            analysis_response = requests.get(analysis_url, headers=headers)
                            if analysis_response.status_code == 200:
                                status = analysis_response.json().get("data", {}).get("attributes", {}).get("status")
                                if status == "completed":
                                    response = requests.get(check_url, headers=headers)
                                    break
                            attempt += 1
                    else:
                        logger.error(f"Error uploading file to VirusTotal: {upload_response.status_code}")

            # Process VirusTotal results
            if response.status_code == 200:
                result = response.json()
                attributes = result.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                
                # Calculate detection ratio
                total_engines = sum(stats.values())
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                detection_ratio = (malicious + suspicious) / total_engines if total_engines > 0 else 0
                
                return {
                    "is_malicious": (malicious + suspicious) > 0,
                    "detection_ratio": detection_ratio,
                    "malicious_detections": malicious,
                    "suspicious_detections": suspicious,
                    "total_engines": total_engines,
                    "permalink": f"https://www.virustotal.com/gui/file/{file_hash}/detection"
                }
            else:
                logger.error(f"VirusTotal API error: {response.status_code} - {response.text}")
                return {
                    "is_malicious": False,
                    "detection_ratio": 0,
                    "malicious_detections": 0,
                    "suspicious_detections": 0,
                    "total_engines": 0,
                    "permalink": "",
                    "error": f"API Error: {response.status_code}"
                }
                
        except Exception as e:
            logger.error(f"Error in VirusTotal scan for {file_path}: {str(e)}")
            return {
                "is_malicious": False,
                "detection_ratio": 0,
                "malicious_detections": 0,
                "suspicious_detections": 0,
                "total_engines": 0,
                "permalink": "",
                "error": str(e)
            }
    
    def scan_file(self, file_path: str) -> Dict:
        """Scan a single file for ransomware indicators using all available layers."""
        logger.info(f"Scanning file: {file_path}")

        file_size = os.path.getsize(file_path)
        # Initialize result structure
        result = {
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "file_size": file_size,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "is_malicious": False,
            "scan_results": {}
        }

        # 1. Cryptographic hashes (chunked / memory-efficient)
        hashes = self.calculate_hashes(file_path)
        file_hash = hashes["md5"]
        result["md5_hash"] = hashes["md5"]
        result["sha256_hash"] = hashes["sha256"]

        # 2. Fuzzy / similarity hashing (polymorphic family detection)
        if file_size <= self.fuzzy_max_bytes:
            fuzzy = self.fuzzy_hasher.analyze_file(file_path)
        else:
            from detectors.fuzzy_hash import FuzzyResult
            fuzzy = FuzzyResult(available=FUZZY_AVAILABLE,
                                detail=f"Skipped: file exceeds fuzzy_max_bytes "
                                       f"({self.fuzzy_max_bytes} bytes).")
        result["scan_results"]["fuzzy_hash"] = fuzzy.as_dict()

        # 3. Local cryptographic-hash database lookup (exact known-bad)
        is_known_malicious, malware_info = self.check_hash_in_database(file_hash)
        result["scan_results"]["local_database"] = {
            "is_malicious": is_known_malicious,
            "details": malware_info if is_known_malicious else "Not found in local database"
        }

        # 4. Static VBA/XLM macro analysis (Office dropper mechanism)
        macro = self.macro_analyzer.analyze_file(file_path)
        result["scan_results"]["macro_analysis"] = macro.as_dict()

        # 5. YARA pattern matching (structural IOCs)
        yara_res = self.yara_engine.scan_file(file_path)
        result["scan_results"]["yara"] = yara_res.as_dict()

        # 6. LLM semantic analysis (local-first for OPSEC)
        llm_result = self.analyze_with_llm(file_path)
        result["scan_results"]["chatgpt_analysis"] = llm_result  # legacy key name kept

        # 7. VirusTotal multi-engine reputation
        virustotal_result = self.scan_file_with_virustotal(file_path)
        result["scan_results"]["virustotal"] = virustotal_result

        # 8. Fuse every signal through the weighted scoring matrix
        signals = {
            "local_db_hit": is_known_malicious,
            "fuzzy": {
                "matched": fuzzy.matched,
                "best_confidence": fuzzy.best_confidence,
                "families": sorted({m.family for m in fuzzy.matches}),
            },
            "macro": {
                "has_macros": macro.has_macros,
                "autoexec": macro.autoexec,
                "critical": macro.critical,
                "suspicious": macro.suspicious,
            },
            "yara": {
                "matched": yara_res.matched,
                "top_severity": yara_res.top_severity or "medium",
                "rules": sorted({m.rule for m in yara_res.matches}),
            },
            "virustotal": {
                "malicious": virustotal_result.get("malicious_detections", 0),
                "suspicious": virustotal_result.get("suspicious_detections", 0),
                "total": virustotal_result.get("total_engines", 0),
                "ratio": virustotal_result.get("detection_ratio", 0),
            },
            "llm": {
                "is_suspicious": llm_result.get("is_malicious", False),
                "confidence": llm_result.get("confidence", 0),
                "elements": llm_result.get("suspicious_elements", []),
            },
        }
        score = self.scoring.score(signals)

        result["is_malicious"] = score.is_malicious
        result["severity_score"] = score.severity_score   # legacy 0-10 (DB hit => 10.0)
        result["risk_score"] = score.risk_score            # 0-100
        result["verdict"] = score.verdict                  # Clean|Low|Medium|High|Critical
        result["score_breakdown"] = score.as_dict()        # full evidence trail

        logger.info(
            "Scan completed for %s. Verdict: %s (risk %d/100, severity %.1f/10).",
            file_path, result["verdict"], result["risk_score"], result["severity_score"],
        )
        return result
    
    def _collect_target_files(self, directory: str) -> List[str]:
        """Walk a directory tree and return every file matching the configured extensions."""
        targets = []
        try:
            for root, _, files in os.walk(directory):
                for filename in files:
                    if any(filename.lower().endswith(ext) for ext in self.file_extensions):
                        targets.append(os.path.join(root, filename))
        except Exception as e:
            logger.error(f"Error walking directory {directory}: {str(e)}")
        return targets

    def _scan_targets(self, targets: List[str], progress_callback=None,
                      cancel_event=None) -> List[Dict]:
        """Scan a list of files, optionally reporting progress and honouring cancellation.

        progress_callback: optional callable(done, total, file_path, result) invoked
            after each file completes. Used by the GUI; CLI callers pass nothing.
        cancel_event: optional threading.Event-like object. When set, the scan stops
            cleanly after the file currently being scanned (a file mid-scan is never
            left half-analysed).
        """
        results = []
        total = len(targets)
        for index, file_path in enumerate(targets, start=1):
            if cancel_event is not None and cancel_event.is_set():
                logger.info(f"Scan cancelled by user after {len(results)}/{total} files.")
                break
            try:
                result = self.scan_file(file_path)
                results.append(result)
            except Exception as e:
                logger.error(f"Error scanning file {file_path}: {str(e)}")
                continue
            if progress_callback is not None:
                try:
                    progress_callback(index, total, file_path, result)
                except Exception as e:
                    logger.error(f"Progress callback error: {str(e)}")
        return results

    def scan_directory(self, directory: str, progress_callback=None,
                       cancel_event=None) -> List[Dict]:
        """Scan all PDF and Word files in a directory for ransomware indicators."""
        targets = self._collect_target_files(directory)
        return self._scan_targets(targets, progress_callback, cancel_event)
    
    def scan_all_directories(self, progress_callback=None,
                             cancel_event=None) -> List[Dict]:
        """Scan all configured directories for ransomware indicators."""
        targets = []
        
        for directory in self.scan_dirs:
            if os.path.exists(directory):
                logger.info(f"Scanning directory: {directory}")
                targets.extend(self._collect_target_files(directory))
            else:
                logger.warning(f"Directory does not exist: {directory}")
        
        return self._scan_targets(targets, progress_callback, cancel_event)
    
    def generate_report(self, results: List[Dict]) -> str:
        """Generate a comprehensive report based on scan results.

        The report now reflects the multi-layer engine: files are grouped by
        verdict band (Critical -> High -> Medium -> Low), and each flagged file
        lists the concrete evidence from every layer (fuzzy family match, macro
        primitives, YARA rules, reputation, semantic) plus the weighted
        score breakdown that explains *why* it scored what it did.

        Backward compatibility: the JSON report is still the full list of result
        dicts, and the legacy fields (md5_hash, severity_score) are still shown.
        """
        if not results:
            return "No files scanned."

        # Create a timestamp for the report file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(self.report_dir, f"ransomware_scan_{timestamp}.json")

        # Write detailed JSON report (full evidence trail, unchanged shape)
        with open(report_file, 'w') as f:
            json.dump(results, f, indent=4)

        total_files = len(results)
        flagged = [r for r in results if r.get("is_malicious")]
        malicious_files = len(flagged)

        # Group flagged files by verdict band, most severe first.
        band_order = ["Critical", "High", "Medium", "Low"]
        grouped: Dict[str, List[Dict]] = {b: [] for b in band_order}
        for r in flagged:
            verdict = r.get("verdict", "Low")
            grouped.setdefault(verdict, []).append(r)

        # Highest verdict reached across the whole scan (for the summary line).
        worst = "Clean"
        for b in band_order:
            if grouped.get(b):
                worst = b
                break

        report_text = f"""
Ransomware Scan Report
======================
Timestamp:              {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Total files scanned:    {total_files}
Files flagged:          {malicious_files}
Highest verdict:        {worst}
Detection layers used:  {self._active_layers_label()}
LLM posture:            {self._llm_posture_label()}
"""

        if malicious_files == 0:
            report_text += "\nNo suspicious files detected.\n"
        else:
            # Quick band breakdown line, e.g. "Critical: 1 | High: 2 | Medium: 0"
            breakdown = " | ".join(
                f"{b}: {len(grouped.get(b, []))}" for b in band_order
            )
            report_text += f"\nVerdict breakdown:  {breakdown}\n"

            for band in band_order:
                bucket = grouped.get(band, [])
                if not bucket:
                    continue
                report_text += f"\n{'=' * 60}\n{band.upper()} ({len(bucket)})\n{'=' * 60}\n"
                # Sort within a band by risk score, highest first.
                for result in sorted(
                    bucket, key=lambda r: r.get("risk_score", 0), reverse=True
                ):
                    report_text += self._format_file_finding(result)

        report_text += f"\nDetailed JSON report saved to: {report_file}\n"

        # Also save the text report
        text_report_file = os.path.join(self.report_dir, f"ransomware_scan_{timestamp}.txt")
        with open(text_report_file, 'w') as f:
            f.write(report_text)

        return report_text

    def _format_file_finding(self, result: Dict) -> str:
        """Render one flagged file's evidence block for the text report."""
        sr = result.get("scan_results", {})
        lines = [
            f"\n- File:     {result.get('file_path')}",
            f"  Verdict:  {result.get('verdict', 'n/a')} "
            f"(risk {result.get('risk_score', 0)}/100, "
            f"severity {result.get('severity_score', 0)}/10)",
            f"  MD5:      {result.get('md5_hash', 'n/a')}",
        ]

        # Local hash DB (exact known-bad)
        local_db = sr.get("local_database", {})
        if local_db.get("is_malicious"):
            lines.append("  [Local DB]  Exact hash match against known-bad database.")

        # Fuzzy / structural similarity
        fuzzy = sr.get("fuzzy_hash", {})
        if fuzzy.get("matched"):
            fams = sorted({m.get("family", "") for m in fuzzy.get("matches", [])
                           if m.get("family")}) or ["known family"]
            conf = fuzzy.get("best_confidence", 0) or 0
            lines.append(
                f"  [Fuzzy]     Structural similarity to {', '.join(fams)} "
                f"(confidence {conf:.2f})."
            )

        # Macro analysis (Office dropper mechanism)
        macro = sr.get("macro_analysis", {})
        if macro.get("has_macros"):
            autoexec = macro.get("autoexec", []) or []
            critical = macro.get("critical", []) or []
            suspicious = macro.get("suspicious", []) or []
            if autoexec:
                lines.append(f"  [Macro]     Auto-run trigger(s): {', '.join(autoexec)}.")
            if critical:
                lines.append(
                    f"  [Macro]     Execution/download primitive(s): "
                    f"{', '.join(critical)}."
                )
            elif suspicious:
                lines.append(
                    f"  [Macro]     Suspicious call(s): "
                    f"{', '.join(suspicious[:6])}."
                )
            if autoexec and critical:
                lines.append(
                    "  [Macro]     -> Auto-exec + exec primitive = classic "
                    "dropper pattern."
                )

        # YARA structural IOCs
        yara_res = sr.get("yara", {})
        if yara_res.get("matched"):
            rule_names = sorted({m.get("rule", "") for m in yara_res.get("matches", [])
                                 if m.get("rule")})
            rules = ", ".join(rule_names) if rule_names else "(unnamed)"
            lines.append(
                f"  [YARA]      Rule(s) matched [{rules}] "
                f"(top severity '{yara_res.get('top_severity', 'medium')}')."
            )

        # VirusTotal reputation
        vt = sr.get("virustotal", {})
        if vt.get("is_malicious"):
            lines.append(
                f"  [VT]        {vt.get('malicious_detections', 0)} malicious / "
                f"{vt.get('total_engines', 0)} engines."
            )
            if vt.get("permalink"):
                lines.append(f"              {vt.get('permalink')}")

        # LLM semantic opinion (capped low by the scoring matrix)
        llm = sr.get("chatgpt_analysis", {})
        if llm.get("is_malicious"):
            lines.append(
                f"  [Semantic]  LLM flagged the text "
                f"(confidence {llm.get('confidence', 0):.2f})."
            )
            elems = llm.get("suspicious_elements", []) or []
            if elems:
                lines.append(f"              Elements: {', '.join(elems)}.")

        # Weighted score breakdown (the "why")
        breakdown = result.get("score_breakdown", {})
        contribs = breakdown.get("contributions", []) or []
        if contribs:
            lines.append("  Score breakdown:")
            for c in contribs:
                lines.append(
                    f"    + {c.get('points', 0):>5.1f}  "
                    f"[{c.get('category', '?')}] {c.get('indicator', '?')}"
                )
            totals = breakdown.get("category_totals", {})
            if totals:
                totals_str = ", ".join(
                    f"{k}={v}" for k, v in totals.items() if v
                )
                if totals_str:
                    lines.append(f"    = category totals: {totals_str}")

        lines.append("")
        return "\n".join(lines)

    def _active_layers_label(self) -> str:
        """Human-readable list of which optional detection layers are active."""
        layers = ["hashes", "local-db"]
        if FUZZY_AVAILABLE:
            layers.append("fuzzy")
        if OLEVBA_AVAILABLE:
            layers.append("macro")
        if YARA_AVAILABLE:
            layers.append("yara")
        layers.append("llm")
        layers.append("virustotal")
        return ", ".join(layers)

    def _llm_posture_label(self) -> str:
        """Describe whether the active LLM backend keeps data local or sends it out."""
        backend = getattr(self, "llm_backend", None)
        if backend is None:
            return "none"
        name = backend.__class__.__name__
        if "Ollama" in name:
            return f"LOCAL ({getattr(backend, 'model', 'ollama')})"
        if "OpenAI" in name:
            return "CLOUD (OpenAI - documents leave the machine)"
        return "disabled"

    def run_scan(self) -> str:
        """Run a complete scan and generate a report."""
        logger.info("Starting scheduled ransomware scan...")
        results = self.scan_all_directories()
        report = self.generate_report(results)
        logger.info("Scan complete.")
        return report

# ---------------------------------------------------------------------------
# Cross-platform autostart  (run the scanner automatically at login/startup)
# ---------------------------------------------------------------------------

AUTOSTART_LABEL = "com.abdelrahman.ransomwarescanner"   # macOS launchd label
AUTOSTART_NAME = "RansomwareScanner"                     # Windows registry value
SYSTEMD_UNIT = "ransomware-scanner.service"             # Linux systemd unit
CRON_MARKER = "# RansomwareScanner autostart"           # Linux/macOS cron marker


def _resolve_python_and_script() -> Tuple[str, str]:
    """Return absolute paths to the current Python interpreter and this script."""
    python_exe = sys.executable or "python3"
    script_path = str(Path(__file__).resolve())
    return python_exe, script_path


def setup_windows_autostart() -> bool:
    """Register the scanner to run at login via the Windows registry (HKCU\\...\\Run)."""
    if winreg is None or os.name != "nt":
        print("ℹ️  Windows autostart is only available on Windows.")
        return False
    try:
        python_exe, script_path = _resolve_python_and_script()
        pythonw = python_exe.replace("python.exe", "pythonw.exe")  # no console window
        command = f'"{pythonw}" "{script_path}" --background'
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, AUTOSTART_NAME, 0, winreg.REG_SZ, command)
        logger.info("Added scanner to Windows startup registry.")
        print("✅ Configured to run at Windows login.")
        return True
    except Exception as e:
        logger.error(f"Windows autostart failed: {e}")
        print(f"❌ Windows autostart failed: {e}")
        return False


def setup_macos_autostart() -> bool:
    """Install a launchd LaunchAgent so the scanner runs at login on macOS."""
    try:
        python_exe, script_path = _resolve_python_and_script()
        agents_dir = Path.home() / "Library" / "LaunchAgents"
        agents_dir.mkdir(parents=True, exist_ok=True)
        plist_path = agents_dir / f"{AUTOSTART_LABEL}.plist"
        plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{AUTOSTART_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python_exe}</string>
        <string>{script_path}</string>
        <string>--background</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{LOG_FILE}</string>
    <key>StandardErrorPath</key>
    <string>{LOG_FILE}</string>
</dict>
</plist>
"""
        plist_path.write_text(plist)
        # Reload the agent (unload first in case it already exists)
        subprocess.run(["launchctl", "unload", str(plist_path)], capture_output=True, text=True)
        result = subprocess.run(["launchctl", "load", str(plist_path)], capture_output=True, text=True)
        if result.returncode != 0 and result.stderr.strip():
            logger.warning(f"launchctl load reported: {result.stderr.strip()}")
        logger.info(f"Installed launchd agent at {plist_path}")
        print(f"✅ Configured to run at macOS login (launchd agent: {plist_path}).")
        return True
    except Exception as e:
        logger.error(f"macOS autostart failed: {e}")
        print(f"❌ macOS autostart failed: {e}")
        return False


def _setup_systemd_autostart(python_exe: str, script_path: str) -> bool:
    """Install a systemd *user* service (preferred on modern Linux)."""
    if not shutil.which("systemctl"):
        return False
    try:
        unit_dir = Path.home() / ".config" / "systemd" / "user"
        unit_dir.mkdir(parents=True, exist_ok=True)
        unit_path = unit_dir / SYSTEMD_UNIT
        unit = f"""[Unit]
Description=Hybrid Ransomware Detection System (background scanner)
After=network-online.target

[Service]
Type=simple
ExecStart={python_exe} {script_path} --background
Restart=on-failure

[Install]
WantedBy=default.target
"""
        unit_path.write_text(unit)
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, text=True)
        result = subprocess.run(
            ["systemctl", "--user", "enable", "--now", SYSTEMD_UNIT],
            capture_output=True, text=True)
        if result.returncode != 0:
            logger.warning(f"systemctl enable reported: {result.stderr.strip()}")
        logger.info(f"Installed systemd user unit at {unit_path}")
        print(f"✅ Configured to run at Linux login (systemd user unit: {unit_path}).")
        print("   Tip: run 'loginctl enable-linger $USER' to keep it running without an active session.")
        return True
    except Exception as e:
        logger.error(f"systemd autostart failed: {e}")
        return False


def _setup_cron_autostart(python_exe: str, script_path: str) -> bool:
    """Fallback: add a @reboot crontab entry (Linux/macOS without systemd)."""
    if not shutil.which("crontab"):
        return False
    try:
        cron_line = f'@reboot {python_exe} "{script_path}" --background  {CRON_MARKER}'
        existing = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        current = existing.stdout if existing.returncode == 0 else ""
        if CRON_MARKER in current:
            print("ℹ️  Cron autostart entry already present.")
            return True
        sep = "\n" if current and not current.endswith("\n") else ""
        new_crontab = current + sep + cron_line + "\n"
        proc = subprocess.run(["crontab", "-"], input=new_crontab, text=True, capture_output=True)
        if proc.returncode != 0:
            logger.error(f"crontab update failed: {proc.stderr.strip()}")
            return False
        logger.info("Added @reboot crontab entry.")
        print("✅ Configured to run at startup via cron (@reboot).")
        return True
    except Exception as e:
        logger.error(f"cron autostart failed: {e}")
        return False


def setup_linux_autostart() -> bool:
    """Configure Linux autostart: systemd user service, falling back to cron."""
    python_exe, script_path = _resolve_python_and_script()
    if _setup_systemd_autostart(python_exe, script_path):
        return True
    print("ℹ️  systemd user service unavailable; falling back to cron.")
    if _setup_cron_autostart(python_exe, script_path):
        return True
    print("❌ Could not configure Linux autostart (neither systemd nor cron available).")
    return False


def setup_autostart() -> bool:
    """Dispatch to the correct autostart implementation for the current OS."""
    system = platform.system()
    if system == "Windows":
        return setup_windows_autostart()
    if system == "Darwin":
        return setup_macos_autostart()
    if system == "Linux":
        return setup_linux_autostart()
    print(f"ℹ️  Autostart is not supported on this platform: {system}")
    return False


def remove_autostart() -> bool:
    """Remove any autostart entry this scanner created on the current OS."""
    system = platform.system()
    try:
        if system == "Windows":
            if winreg is None:
                return False
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE) as key:
                try:
                    winreg.DeleteValue(key, AUTOSTART_NAME)
                except FileNotFoundError:
                    pass
            print("✅ Removed Windows autostart entry (if it existed).")
            return True

        if system == "Darwin":
            plist_path = Path.home() / "Library" / "LaunchAgents" / f"{AUTOSTART_LABEL}.plist"
            if plist_path.exists():
                subprocess.run(["launchctl", "unload", str(plist_path)], capture_output=True, text=True)
                plist_path.unlink()
                print(f"✅ Removed macOS launchd agent: {plist_path}")
            else:
                print("ℹ️  No macOS launchd agent found.")
            return True

        if system == "Linux":
            removed = False
            unit_path = Path.home() / ".config" / "systemd" / "user" / SYSTEMD_UNIT
            if unit_path.exists() and shutil.which("systemctl"):
                subprocess.run(["systemctl", "--user", "disable", "--now", SYSTEMD_UNIT],
                               capture_output=True, text=True)
                unit_path.unlink()
                subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, text=True)
                removed = True
            if shutil.which("crontab"):
                existing = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
                if existing.returncode == 0 and CRON_MARKER in existing.stdout:
                    filtered = "\n".join(l for l in existing.stdout.splitlines() if CRON_MARKER not in l)
                    filtered = (filtered + "\n") if filtered.strip() else ""
                    subprocess.run(["crontab", "-"], input=filtered, text=True, capture_output=True)
                    removed = True
            print("✅ Removed Linux autostart entry." if removed else "ℹ️  No Linux autostart entry found.")
            return True
    except Exception as e:
        logger.error(f"Failed to remove autostart: {e}")
        print(f"❌ Failed to remove autostart: {e}")
        return False
    print(f"ℹ️  Autostart removal is not supported on this platform: {system}")
    return False


def create_desktop_shortcut() -> bool:
    """Create a desktop shortcut/launcher (Windows .lnk or Linux .desktop)."""
    system = platform.system()
    python_exe, script_path = _resolve_python_and_script()

    if system == "Windows":
        try:
            import win32com.client
            shell = win32com.client.Dispatch("WScript.Shell")
            desktop = shell.SpecialFolders("Desktop")
            shortcut_path = os.path.join(desktop, "Ransomware Scanner.lnk")
            shortcut = shell.CreateShortCut(shortcut_path)
            shortcut.TargetPath = python_exe
            shortcut.Arguments = f'"{script_path}" --scan-now'
            shortcut.WorkingDirectory = os.path.dirname(script_path)
            shortcut.IconLocation = python_exe + ",0"
            shortcut.Description = "Run Ransomware Scanner"
            shortcut.Save()
            print(f"✅ Created desktop shortcut: {shortcut_path}")
            return True
        except Exception as e:
            print(f"❌ Failed to create shortcut: {e}")
            print("Note: install pywin32 for shortcut support:  pip install pywin32")
            return False

    if system == "Linux":
        try:
            desktop_dir = Path.home() / "Desktop"
            desktop_dir.mkdir(parents=True, exist_ok=True)
            launcher = desktop_dir / "ransomware-scanner.desktop"
            launcher.write_text(
                "[Desktop Entry]\n"
                "Type=Application\n"
                "Name=Ransomware Scanner\n"
                f'Exec={python_exe} "{script_path}" --scan-now\n'
                "Terminal=true\n"
                "Categories=Utility;Security;\n"
            )
            launcher.chmod(0o755)
            print(f"✅ Created desktop launcher: {launcher}")
            return True
        except Exception as e:
            print(f"❌ Failed to create launcher: {e}")
            return False

    print("ℹ️  Desktop shortcuts are supported on Windows and Linux only.")
    return False


def import_hash_database(source_path: str, destination_path: str = None) -> Dict:
    """Copy a malware-hash CSV into the app data directory and validate its format.

    Shared by the CLI (--import-database) and the GUI so both use one code path.
    Returns a dict:
        ok               True when the copy succeeded and all required columns exist
        error_kind       None | "missing_source" | "exception"
        message          human-readable status
        destination      final path of the database
        entries          number of data rows found
        missing_columns  required columns absent from the header
    """
    destination_path = destination_path or CONFIG["kaggle_database_path"]
    outcome = {"ok": False, "error_kind": None, "message": "",
               "destination": destination_path, "entries": 0, "missing_columns": []}

    if not os.path.exists(source_path):
        outcome["error_kind"] = "missing_source"
        outcome["message"] = f"Cannot find database file at {source_path}"
        return outcome

    try:
        shutil.copy2(source_path, destination_path)

        with open(destination_path, mode="r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            header = reader.fieldnames or []
            outcome["entries"] = sum(1 for _ in reader)

        required_columns = ['FileName', 'md5Hash', 'Benign']
        outcome["missing_columns"] = [col for col in required_columns if col not in header]
        outcome["ok"] = not outcome["missing_columns"]
        outcome["message"] = (
            f"Database format validated. Found {outcome['entries']} entries."
            if outcome["ok"]
            else f"Missing required columns: {', '.join(outcome['missing_columns'])}"
        )
        logger.info(f"Hash database imported from {source_path} -> {destination_path} "
                    f"({outcome['entries']} entries)")
        return outcome
    except Exception as e:
        outcome["error_kind"] = "exception"
        outcome["message"] = str(e)
        logger.error(f"Error importing database: {e}")
        return outcome


def _print_fuzzy_hash(path: str) -> None:
    """Print a file's fuzzy digests so the user can add them to a signature DB.

    This is the intended workflow for growing `fuzzy_signatures.json`: run this
    against a confirmed-malicious sample, then paste the TLSH (and/or ssdeep)
    value into a signature entry with the family name. Matching is then done by
    structural similarity, so polymorphic variants of that family are caught
    without an exact hash.
    """
    if not os.path.exists(path):
        print(f"Error: file not found: {path}")
        return
    if not FUZZY_AVAILABLE:
        print("Fuzzy hashing libraries are not installed.")
        print("Install them with:  pip install python-tlsh ppdeep")
        return

    hasher = FuzzyHasher()
    digests = hasher.hash_file(path)
    print(f"File:   {path}")
    print(f"Size:   {os.path.getsize(path)} bytes")
    print(f"TLSH:   {digests.get('tlsh') or '(unavailable - input too small/uniform)'}")
    print(f"ssdeep: {digests.get('ssdeep') or '(unavailable)'}")
    print()
    print("Add to your fuzzy_signatures.json like:")
    print(json.dumps({
        "family": "Example.Family.Name",
        "tlsh": digests.get("tlsh") or "",
        "ssdeep": digests.get("ssdeep") or "",
        "note": "describe the sample / source here"
    }, indent=2))


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Cross-platform Ransomware Scanner for PDF and Word Files")
    parser.add_argument("--scan-now", action="store_true",
                        help="Run a scan immediately")
    parser.add_argument("--background", action="store_true",
                        help="Run in the background with scheduled scans")
    parser.add_argument("--setup-autostart", action="store_true",
                        help="Run automatically at login/startup (Windows, macOS, or Linux)")
    parser.add_argument("--remove-autostart", action="store_true",
                        help="Remove the autostart entry created on this machine")
    parser.add_argument("--create-shortcut", action="store_true",
                        help="Create a desktop shortcut/launcher (Windows/Linux)")
    parser.add_argument("--import-database",
                        help="Import a malware-hash CSV database from the given path")
    parser.add_argument("--gui", action="store_true",
                        help="Launch the graphical interface")
    parser.add_argument("--scan-file", metavar="PATH",
                        help="Scan a single file and print its full verdict, then exit")
    parser.add_argument("--fuzzy-hash", metavar="PATH",
                        help="Print a file's TLSH and ssdeep digests (use these to "
                             "populate your fuzzy signature DB), then exit")
    parser.add_argument("--llm-provider", choices=["auto", "ollama", "openai", "none"],
                        help="Override the LLM backend for this run. 'auto' (default) "
                             "prefers a reachable local Ollama for OPSEC and only falls "
                             "back to OpenAI if a key is set; 'none' disables the layer.")

    args = parser.parse_args()

    # An explicit --llm-provider overrides config/env for this process.
    if args.llm_provider:
        CONFIG["llm_provider"] = args.llm_provider

    # --fuzzy-hash is a standalone utility: it needs no DB, no API keys, no banner.
    if args.fuzzy_hash:
        _print_fuzzy_hash(args.fuzzy_hash)
        return

    if args.gui:
        try:
            import gui
        except ImportError as e:
            print("The GUI needs the 'customtkinter' package. Install it with:")
            print("    pip install customtkinter")
            print(f"Details: {e}")
            return
        gui.main()
        return

    # Display a welcome banner for interactive use
    if not (args.background or args.setup_autostart or args.remove_autostart
            or args.create_shortcut or args.import_database):
        print("=" * 56)
        print("  HYBRID RANSOMWARE DETECTION SYSTEM")
        print("  Multi-layer PDF & Word document scanner")
        print("=" * 56)
        print(f"Platform:          {platform.system()} ({platform.machine()})")
        print(f"App directory:     {APP_DIR}")
        print(f"Log file:          {LOG_FILE}")
        print(f"Report directory:  {CONFIG['report_directory']}")
        print(f"Database path:     {CONFIG['kaggle_database_path']}")
        print("-" * 56)
        print("Detection layers:")
        print(f"  Cryptographic hashes ....... enabled")
        print(f"  Local hash database ........ enabled")
        print(f"  Fuzzy hashing (TLSH/ssdeep)  {'enabled' if FUZZY_AVAILABLE else 'unavailable (pip install python-tlsh ppdeep)'}")
        print(f"  VBA macro analysis ......... {'enabled' if OLEVBA_AVAILABLE else 'unavailable (pip install oletools)'}")
        print(f"  YARA structural rules ...... {'enabled' if YARA_AVAILABLE else 'unavailable (pip install yara-python)'}")
        print(f"  LLM semantic analysis ...... provider='{CONFIG.get('llm_provider', 'auto')}'")
        print(f"  VirusTotal reputation ...... {'key set' if CONFIG.get('virustotal_api_key') else 'no key (layer skipped)'}")
        print("=" * 56)

    if args.setup_autostart:
        setup_autostart()
        return

    if args.remove_autostart:
        remove_autostart()
        return

    if args.create_shortcut:
        create_desktop_shortcut()
        return

    if args.import_database:
        outcome = import_hash_database(args.import_database)
        if outcome["error_kind"] == "missing_source":
            print(f"Error: Cannot find database file at {args.import_database}")
            return
        if outcome["error_kind"] == "exception":
            print(f"❌ Error importing database: {outcome['message']}")
            return
        print(f"✅ Successfully imported database from {args.import_database}")
        print(f"   Database saved to {outcome['destination']}")
        if outcome["missing_columns"]:
            print(f"⚠️  Missing required columns: {', '.join(outcome['missing_columns'])}")
            print("   The scanner may not work properly without these columns.")
        else:
            print(f"✅ Database format validated. Found {outcome['entries']} entries.")
        return

    # Warn if API keys are not configured (set them in a local .env file)
    if not CONFIG["chatgpt_api_key"] or not CONFIG["virustotal_api_key"]:
        print("⚠️  One or more API keys are missing. Copy .env.example to .env and add your keys.")
        print("    The local hash-database check still works; the VirusTotal and LLM layers need keys.\n")

    scanner = RansomwareScanner(CONFIG)

    # --scan-file: analyse exactly one file, print its verdict, and exit.
    if args.scan_file:
        if not os.path.exists(args.scan_file):
            print(f"Error: file not found: {args.scan_file}")
            return
        result = scanner.scan_file(args.scan_file)
        print(scanner.generate_report([result]))
        return

    if args.scan_now:
        print("Starting scan. This may take some time depending on the number of files...")
        report = scanner.run_scan()
        print("\n" + "=" * 56)
        print(report)
        print("=" * 56)
        print(f"\nDetailed reports saved to: {CONFIG['report_directory']}")
        if not args.background:
            input("\nPress Enter to exit...")

    if args.background or not args.scan_now:
        if not os.path.exists(CONFIG['kaggle_database_path']):
            print(f"⚠️  Malware-hash database not found at {CONFIG['kaggle_database_path']}")
            print("   Import one with the --import-database option, e.g.:")
            print(f"   python {Path(__file__).name} --import-database /path/to/your/dataset.csv")
            if not args.background:
                input("\nPress Enter to continue anyway...")

        logger.info(f"Scheduling scans every {CONFIG['scan_interval_hours']} hours.")
        schedule.every(CONFIG['scan_interval_hours']).hours.do(scanner.run_scan)

        if not args.scan_now:
            scanner.run_scan()

        try:
            while True:
                schedule.run_pending()
                time.sleep(60)
        except KeyboardInterrupt:
            logger.info("Scanner stopped by user.")


if __name__ == "__main__":
    main()

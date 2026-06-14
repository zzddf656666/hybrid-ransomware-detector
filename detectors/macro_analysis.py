"""
VBA / XLM macro analysis for the Hybrid Ransomware Detection System.

WHY THIS EXISTS
---------------
The original scanner only looked at *visible* document text. But weaponised
Office documents rarely show their teeth in the body text - the malicious
behaviour lives in embedded VBA (or legacy Excel 4.0 / XLM) macros that run
automatically when the victim clicks "Enable Content". This module targets the
actual dropper mechanism instead of the lure.

It uses `oletools.olevba` (the industry-standard, pure-Python triage tool) to:
  1. detect whether a file even contains macros,
  2. extract the macro source (olevba also de-obfuscates common tricks such as
     Chr()/StrReverse() string building and Hex/Base64 blobs), and
  3. statically classify the findings into high-signal buckets:
       - AUTOEXEC triggers  (AutoOpen, Document_Open, Workbook_Open, AutoExec ...)
         => the macro runs without further user action,
       - SUSPICIOUS calls   (Shell, ShellExecute, CreateObject, powershell,
         WScript, URLDownloadToFile, environ ...)
         => process execution / payload download primitives,
       - IOCs               (URLs, IPv4s, executable names) pulled from the code.

`olevba` is optional. If it is not installed, the module degrades gracefully and
reports that the layer was skipped, so the rest of the scanner still runs.

NOTE: this is purely *static* analysis. No macro is ever executed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("RansomwareScanner.macro")

try:
    from oletools.olevba import VBA_Parser
    OLEVBA_AVAILABLE = True
except Exception:  # pragma: no cover - absence is a valid runtime state
    VBA_Parser = None  # type: ignore
    OLEVBA_AVAILABLE = False

# olevba's analyze_macros() tags each finding with one of these type strings.
TYPE_AUTOEXEC = "AutoExec"
TYPE_SUSPICIOUS = "Suspicious"
TYPE_IOC = "IOC"

# A subset of SUSPICIOUS keywords we consider *critical* execution/download
# primitives. A hit on any of these is the single strongest macro signal: it
# means the document can spawn a process or pull a remote payload. The scoring
# matrix weights these far above any text-based phishing cue.
CRITICAL_KEYWORDS = {
    "shell", "shellexecute", "wscript.shell", "wscript shell",
    "powershell", "cmd", "createobject", "urldownloadtofile",
    "winhttp", "msxml2.xmlhttp", "xmlhttp", "createprocess",
    "vba shell", "run", "exec",
}


@dataclass
class MacroResult:
    """Outcome of macro-analysing a single file."""
    available: bool
    has_macros: bool = False
    autoexec: List[str] = field(default_factory=list)      # auto-run triggers
    suspicious: List[str] = field(default_factory=list)    # all suspicious keywords
    critical: List[str] = field(default_factory=list)      # exec/download primitives
    iocs: List[str] = field(default_factory=list)          # urls / ips / exe names
    vba_code_size: int = 0
    detail: str = ""

    def as_dict(self) -> Dict:
        return {
            "available": self.available,
            "has_macros": self.has_macros,
            "autoexec": self.autoexec,
            "suspicious": self.suspicious,
            "critical": self.critical,
            "iocs": self.iocs,
            "vba_code_size": self.vba_code_size,
            "detail": self.detail,
        }


class MacroAnalyzer:
    """Static VBA/XLM macro triage via olevba."""

    # File types worth even attempting. olevba happily rejects others, but
    # short-circuiting avoids spurious warnings on PDFs etc.
    SUPPORTED_EXTS = {".doc", ".docm", ".dot", ".dotm",
                      ".xls", ".xlsm", ".xlsb", ".xlm", ".xltm",
                      ".ppt", ".pptm", ".potm",
                      ".docx", ".xlsx", ".pptx"}  # OOXML can still embed a vbaProject.bin

    def analyze_file(self, file_path: str) -> MacroResult:
        if not OLEVBA_AVAILABLE:
            return MacroResult(
                available=False,
                detail="Macro analysis skipped: install 'oletools' (olevba).",
            )

        # Only attempt macro analysis on Office document types. Without this
        # gate, olevba's VBA_Parser treats an arbitrary file (e.g. a .txt or a
        # plain .pdf) as candidate VBA *source* and detect_vba_macros() reports
        # a false positive. Restricting to real Office containers keeps the
        # layer accurate for the formats macros can actually live in.
        ext = Path(file_path).suffix.lower()
        if ext not in self.SUPPORTED_EXTS:
            return MacroResult(
                available=True, has_macros=False,
                detail="Not an Office document; macro analysis skipped.",
            )

        parser = None
        try:
            parser = VBA_Parser(file_path)
            if not parser.detect_vba_macros():
                return MacroResult(available=True, has_macros=False,
                                   detail="No VBA/XLM macros found.")

            # Force extraction so analyze_macros() has source to work with.
            code_size = 0
            try:
                for (_fname, _stream, _vba_name, vba_code) in parser.extract_all_macros():
                    if vba_code:
                        code_size += len(vba_code)
            except Exception as e:  # extraction can fail on damaged streams
                logger.debug("Macro extraction issue for %s: %s", file_path, e)

            autoexec: List[str] = []
            suspicious: List[str] = []
            critical: List[str] = []
            iocs: List[str] = []

            # analyze_macros() returns (type, keyword, description) tuples.
            for kind, keyword, _description in parser.analyze_macros():
                kw = (keyword or "").strip()
                if not kw:
                    continue
                if kind == TYPE_AUTOEXEC:
                    autoexec.append(kw)
                elif kind == TYPE_SUSPICIOUS:
                    suspicious.append(kw)
                    if kw.lower() in CRITICAL_KEYWORDS:
                        critical.append(kw)
                elif kind == TYPE_IOC:
                    iocs.append(kw)

            # De-duplicate while preserving order.
            autoexec = _dedup(autoexec)
            suspicious = _dedup(suspicious)
            critical = _dedup(critical)
            iocs = _dedup(iocs)

            detail = _summarise(autoexec, suspicious, critical)
            return MacroResult(
                available=True, has_macros=True,
                autoexec=autoexec, suspicious=suspicious, critical=critical,
                iocs=iocs, vba_code_size=code_size, detail=detail,
            )
        except Exception as e:
            logger.error("Macro analysis failed for %s: %s", file_path, e)
            return MacroResult(available=True, has_macros=False,
                               detail=f"Macro analysis error: {e}")
        finally:
            if parser is not None:
                try:
                    parser.close()
                except Exception:  # pragma: no cover
                    pass


def _dedup(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in items:
        key = x.lower()
        if key not in seen:
            seen.add(key)
            out.append(x)
    return out


def _summarise(autoexec: List[str], suspicious: List[str], critical: List[str]) -> str:
    parts = []
    if autoexec:
        parts.append(f"auto-run trigger(s): {', '.join(autoexec)}")
    if critical:
        parts.append(f"execution/download primitive(s): {', '.join(critical)}")
    elif suspicious:
        parts.append(f"suspicious call(s): {', '.join(suspicious[:6])}")
    if autoexec and critical:
        parts.append("classic auto-executing dropper pattern")
    return "; ".join(parts) if parts else "Macros present but no high-risk keywords flagged."

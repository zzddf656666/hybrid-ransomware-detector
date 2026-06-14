"""
YARA scanning engine for the Hybrid Ransomware Detection System.

WHY THIS EXISTS
---------------
Hashes match one exact file; fuzzy hashes match one family by structure. YARA
sits between and below both: it matches *patterns* - byte sequences, strings,
and their logical combinations - so a single rule can flag a whole class of
threats (e.g. "any file that contains a ransom-note vocabulary AND a Bitcoin
address regex"). YARA is the lingua franca for sharing structural Indicators of
Compromise (IOCs), which makes this layer the natural place to plug in
community or in-house rule packs.

This module compiles every `.yar` / `.yara` file found in a rules directory and
scans candidate files against them. Each match is returned with the rule name,
its tags, and a `severity` taken from the rule's `meta` (so analysts can tune
weighting without touching code). To respect both privacy and copyright, we
return *which* rule matched and the matched string identifiers - never raw dumps
of the user's document bytes.

`yara-python` is optional. Without it the layer degrades gracefully and the rest
of the scanner still runs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("RansomwareScanner.yara")

try:
    import yara as _yara  # yara-python
    YARA_AVAILABLE = True
except Exception:  # pragma: no cover - absence is a valid runtime state
    _yara = None
    YARA_AVAILABLE = False

# Severity strings ranked so we can pick the most serious match quickly.
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class YaraMatch:
    rule: str
    severity: str = "medium"
    tags: List[str] = field(default_factory=list)
    description: str = ""
    matched_strings: List[str] = field(default_factory=list)  # identifiers only, e.g. "$ransom_note"

    def as_dict(self) -> Dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "tags": self.tags,
            "description": self.description,
            "matched_strings": self.matched_strings,
        }


@dataclass
class YaraResult:
    available: bool
    rules_loaded: int = 0
    matched: bool = False
    matches: List[YaraMatch] = field(default_factory=list)
    top_severity: Optional[str] = None
    detail: str = ""

    def as_dict(self) -> Dict:
        return {
            "available": self.available,
            "rules_loaded": self.rules_loaded,
            "matched": self.matched,
            "matches": [m.as_dict() for m in self.matches],
            "top_severity": self.top_severity,
            "detail": self.detail,
        }


class YaraEngine:
    """Compiles a directory of YARA rules and scans files against them."""

    def __init__(self, rules_dir: Optional[str] = None):
        self.rules_dir = rules_dir
        self._rules = None          # compiled yara.Rules
        self._rules_count = 0
        if rules_dir:
            self._compile_rules(rules_dir)

    def _compile_rules(self, rules_dir: str) -> None:
        if not YARA_AVAILABLE:
            return
        d = Path(rules_dir)
        if not d.exists():
            logger.info("YARA rules directory not found at %s.", rules_dir)
            return
        rule_files = sorted([*d.glob("*.yar"), *d.glob("*.yara")])
        if not rule_files:
            logger.info("No .yar/.yara files in %s.", rules_dir)
            return
        # filepaths={namespace: path} lets multiple rule files coexist.
        sources = {p.stem: str(p) for p in rule_files}
        try:
            self._rules = _yara.compile(filepaths=sources)
            self._rules_count = len(rule_files)
            logger.info("Compiled %d YARA rule file(s) from %s.", self._rules_count, rules_dir)
        except Exception as e:
            # A syntax error in one rule file should be loud but non-fatal.
            logger.error("YARA compilation failed (%s). Scanning will skip YARA.", e)
            self._rules = None
            self._rules_count = 0

    def scan_file(self, file_path: str) -> YaraResult:
        if not YARA_AVAILABLE:
            return YaraResult(available=False,
                              detail="YARA scanning skipped: install 'yara-python'.")
        if self._rules is None:
            return YaraResult(available=True, rules_loaded=0,
                              detail="No YARA rules loaded.")
        try:
            raw_matches = self._rules.match(filepath=file_path, timeout=60)
        except Exception as e:
            logger.error("YARA scan failed for %s: %s", file_path, e)
            return YaraResult(available=True, rules_loaded=self._rules_count,
                              detail=f"YARA scan error: {e}")

        matches: List[YaraMatch] = []
        for m in raw_matches:
            meta = getattr(m, "meta", {}) or {}
            severity = str(meta.get("severity", "medium")).lower()
            if severity not in SEVERITY_ORDER:
                severity = "medium"
            # Collect only the string identifiers that fired (not the bytes).
            ids = _matched_identifiers(m)
            matches.append(YaraMatch(
                rule=m.rule,
                severity=severity,
                tags=list(getattr(m, "tags", []) or []),
                description=str(meta.get("description", "")),
                matched_strings=ids,
            ))

        if not matches:
            return YaraResult(available=True, rules_loaded=self._rules_count,
                              matched=False, detail="No YARA rules matched.")

        top = max(matches, key=lambda x: SEVERITY_ORDER.get(x.severity, 2)).severity
        names = ", ".join(sorted({m.rule for m in matches}))
        return YaraResult(
            available=True, rules_loaded=self._rules_count, matched=True,
            matches=matches, top_severity=top,
            detail=f"Matched rule(s): {names} (top severity: {top}).",
        )


def _matched_identifiers(match) -> List[str]:
    """Extract just the matched string identifiers across yara-python versions.

    yara-python changed its match.strings shape between releases; this handles
    both the legacy tuple form and the newer StringMatch objects, and never
    returns the raw matched bytes (privacy + copyright hygiene).
    """
    ids: List[str] = []
    try:
        for s in getattr(match, "strings", []) or []:
            ident = getattr(s, "identifier", None)
            if ident is None and isinstance(s, (tuple, list)) and len(s) >= 2:
                ident = s[1]  # legacy form: (offset, identifier, data)
            if ident:
                ids.append(str(ident))
    except Exception:  # pragma: no cover
        pass
    # De-duplicate, keep order.
    seen = set()
    out = []
    for i in ids:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out

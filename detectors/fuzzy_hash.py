"""
Fuzzy / similarity hashing for the Hybrid Ransomware Detection System.

WHY THIS EXISTS
---------------
Cryptographic hashes (MD5, SHA-256) change completely if a single byte changes.
That is exactly what polymorphic malware and ransomware *families* exploit: every
victim receives a slightly different build, so its SHA-256 is never in any
blocklist. Fuzzy hashing solves this by producing a digest that stays *similar*
when the input stays *structurally similar*, letting us cluster a new sample into
a known family even when its exact hash has never been seen before.

Two complementary algorithms are used:

* TLSH  (Trend Micro Locality Sensitive Hash) - robust, fixed-length digest.
        Comparison returns a *distance* (0 = identical, larger = more different).
        TLSH needs >= ~50 bytes of input with some byte variance, otherwise it
        returns the sentinel "TNULL".
* ssdeep (context-triggered piecewise hashing, via the pure-Python `ppdeep`).
        Comparison returns a *similarity* score from 0 to 100 (100 = identical).
        Pure-Python so it needs no C/libfuzzy build - important for the project's
        "installs with no compiler on Windows/macOS/Linux, x86_64 + ARM64" goal.

Both libraries are optional. If neither is installed the module degrades
gracefully and reports that the layer was skipped, so the core scanner still runs.

SIGNATURE DATABASE FORMAT  (JSON)
---------------------------------
    {
      "version": 1,
      "signatures": [
        {"family": "Acme.Locker", "tlsh": "T1<...>", "ssdeep": "3:<...>",
         "note": "human-readable provenance"}
      ]
    }

Populate it from the fuzzy hashes of *confirmed* malicious samples (run the
scanner with `--fuzzy-hash <sample>` to print the digests to paste in here).
Never ship live malware itself.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("RansomwareScanner.fuzzy")

# --- Optional dependencies: import defensively -----------------------------
try:
    import tlsh as _tlsh  # python-tlsh
except Exception:  # pragma: no cover - absence is a valid runtime state
    _tlsh = None

try:
    import ppdeep as _ppdeep  # pure-Python ssdeep
except Exception:  # pragma: no cover
    _ppdeep = None

# A TLSH digest below this distance is treated as the *same family*.
# 0 = identical; published guidance puts <50 as a strong match and <100 as
# related. We default to 100 (inclusive) and report the raw distance so an
# analyst can always see the evidence behind the verdict.
DEFAULT_TLSH_THRESHOLD = 100
TLSH_STRONG_DISTANCE = 50

# An ssdeep similarity at or above this (out of 100) is treated as a match.
DEFAULT_SSDEEP_THRESHOLD = 70

FUZZY_AVAILABLE = (_tlsh is not None) or (_ppdeep is not None)


@dataclass
class FuzzyMatch:
    """One signature-database hit for a scanned file."""
    family: str
    algorithm: str          # "tlsh" or "ssdeep"
    score: int              # tlsh: raw distance (lower=closer); ssdeep: 0-100 similarity
    confidence: float       # normalised 0.0-1.0 for the scoring matrix
    note: str = ""

    def as_dict(self) -> Dict:
        return {
            "family": self.family,
            "algorithm": self.algorithm,
            "score": self.score,
            "confidence": round(self.confidence, 3),
            "note": self.note,
        }


@dataclass
class FuzzyResult:
    """Outcome of fuzzy-hashing a single file."""
    available: bool
    tlsh: Optional[str] = None
    ssdeep: Optional[str] = None
    matched: bool = False
    best_confidence: float = 0.0
    matches: List[FuzzyMatch] = field(default_factory=list)
    detail: str = ""

    def as_dict(self) -> Dict:
        return {
            "available": self.available,
            "tlsh": self.tlsh,
            "ssdeep": self.ssdeep,
            "matched": self.matched,
            "best_confidence": round(self.best_confidence, 3),
            "matches": [m.as_dict() for m in self.matches],
            "detail": self.detail,
        }


def _tlsh_confidence(distance: int, threshold: int) -> float:
    """Map a TLSH distance to a 0-1 confidence.

    distance <= TLSH_STRONG_DISTANCE  -> 1.0   (near-identical structure)
    distance == threshold             -> 0.5   (boundary of "related")
    linear in between; 0 outside the threshold.
    """
    if distance <= TLSH_STRONG_DISTANCE:
        return 1.0
    if distance > threshold:
        return 0.0
    # Linear from 1.0 at the strong line down to 0.5 at the threshold.
    span = max(1, threshold - TLSH_STRONG_DISTANCE)
    return 1.0 - 0.5 * (distance - TLSH_STRONG_DISTANCE) / span


class FuzzyHasher:
    """Computes fuzzy hashes and matches them against a signature database."""

    def __init__(
        self,
        signature_db_path: Optional[str] = None,
        tlsh_threshold: int = DEFAULT_TLSH_THRESHOLD,
        ssdeep_threshold: int = DEFAULT_SSDEEP_THRESHOLD,
    ):
        self.signature_db_path = signature_db_path
        self.tlsh_threshold = tlsh_threshold
        self.ssdeep_threshold = ssdeep_threshold
        self.signatures: List[Dict] = []
        if signature_db_path:
            self._load_signatures(signature_db_path)

    # -- signature DB ------------------------------------------------------
    def _load_signatures(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            logger.info("Fuzzy signature DB not found at %s (no family matching).", path)
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            self.signatures = [s for s in data.get("signatures", []) if isinstance(s, dict)]
            logger.info("Loaded %d fuzzy signatures from %s.", len(self.signatures), path)
        except Exception as e:  # malformed DB must not crash a scan
            logger.error("Failed to read fuzzy signature DB %s: %s", path, e)
            self.signatures = []

    # -- hashing -----------------------------------------------------------
    @staticmethod
    def hash_bytes(data: bytes) -> Dict[str, Optional[str]]:
        """Return {'tlsh': ..., 'ssdeep': ...} for raw bytes (None where N/A)."""
        result: Dict[str, Optional[str]] = {"tlsh": None, "ssdeep": None}
        if _tlsh is not None:
            try:
                digest = _tlsh.hash(data)
                # python-tlsh returns "TNULL" for inputs that are too short
                # or too uniform to fingerprint meaningfully.
                if digest and digest != "TNULL":
                    result["tlsh"] = digest
            except Exception as e:  # pragma: no cover
                logger.debug("TLSH hashing failed: %s", e)
        if _ppdeep is not None:
            try:
                result["ssdeep"] = _ppdeep.hash(data)
            except Exception as e:  # pragma: no cover
                logger.debug("ssdeep hashing failed: %s", e)
        return result

    def hash_file(self, file_path: str) -> Dict[str, Optional[str]]:
        """Fuzzy-hash a file on disk (reads it fully; callers cap by file size)."""
        try:
            data = Path(file_path).read_bytes()
        except Exception as e:
            logger.error("Could not read %s for fuzzy hashing: %s", file_path, e)
            return {"tlsh": None, "ssdeep": None}
        return self.hash_bytes(data)

    # -- matching ----------------------------------------------------------
    def match(self, tlsh_digest: Optional[str], ssdeep_digest: Optional[str]) -> List[FuzzyMatch]:
        """Compare a file's fuzzy hashes against every signature in the DB."""
        matches: List[FuzzyMatch] = []
        for sig in self.signatures:
            family = sig.get("family", "unknown")
            note = sig.get("note", "")

            # TLSH distance comparison
            sig_tlsh = sig.get("tlsh")
            if tlsh_digest and sig_tlsh and _tlsh is not None:
                try:
                    distance = _tlsh.diff(tlsh_digest, sig_tlsh)
                    if distance <= self.tlsh_threshold:
                        matches.append(FuzzyMatch(
                            family=family, algorithm="tlsh", score=distance,
                            confidence=_tlsh_confidence(distance, self.tlsh_threshold),
                            note=note,
                        ))
                        continue  # one match per signature is enough
                except Exception as e:  # pragma: no cover
                    logger.debug("TLSH diff failed for family %s: %s", family, e)

            # ssdeep similarity comparison
            sig_ssdeep = sig.get("ssdeep")
            if ssdeep_digest and sig_ssdeep and _ppdeep is not None:
                try:
                    similarity = _ppdeep.compare(ssdeep_digest, sig_ssdeep)
                    if similarity >= self.ssdeep_threshold:
                        matches.append(FuzzyMatch(
                            family=family, algorithm="ssdeep", score=similarity,
                            confidence=min(1.0, similarity / 100.0),
                            note=note,
                        ))
                except Exception as e:  # pragma: no cover
                    logger.debug("ssdeep compare failed for family %s: %s", family, e)
        return matches

    def analyze_file(self, file_path: str, precomputed: Optional[Dict] = None) -> FuzzyResult:
        """Full pipeline: hash a file (or reuse precomputed hashes) and match it."""
        if not FUZZY_AVAILABLE:
            return FuzzyResult(
                available=False,
                detail="Fuzzy hashing skipped: install 'python-tlsh' and/or 'ppdeep'.",
            )

        digests = precomputed or self.hash_file(file_path)
        tlsh_digest = digests.get("tlsh")
        ssdeep_digest = digests.get("ssdeep")

        if not tlsh_digest and not ssdeep_digest:
            return FuzzyResult(
                available=True, tlsh=None, ssdeep=None,
                detail="File too small or too uniform to fuzzy-hash.",
            )

        matches = self.match(tlsh_digest, ssdeep_digest)
        best = max((m.confidence for m in matches), default=0.0)
        if matches:
            fam = ", ".join(sorted({m.family for m in matches}))
            detail = f"Structural match to known family/families: {fam}."
        else:
            detail = "No structural match in the fuzzy signature database."

        return FuzzyResult(
            available=True,
            tlsh=tlsh_digest,
            ssdeep=ssdeep_digest,
            matched=bool(matches),
            best_confidence=best,
            matches=matches,
            detail=detail,
        )

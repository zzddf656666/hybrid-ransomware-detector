"""
Weighted scoring matrix for the Hybrid Ransomware Detection System.

WHY THIS EXISTS
---------------
The original severity was a hardcoded equation:

    severity = 10*db_hit + 5*llm_confidence + 5*vt_ratio   (capped at 10)

That gives a *semantic* signal (the LLM's opinion of the text) the same weight
as multi-engine reputation, and offers no way to express that a structural
indicator - say a macro that calls `Shell` from `AutoOpen` - is far more
damning than a phishing-flavoured sentence. It is also opaque: the final number
explains nothing about *why* a file scored what it did.

This module replaces that with a transparent, weighted matrix. Every detection
signal contributes through an explicit rule with:
  * a CATEGORY  - technical | reputation | semantic,
  * a WEIGHT    - the points it contributes when fully triggered,
  * a DETAIL    - human-readable evidence for the report.

Design principles (these encode the requirement directly):

  1. TECHNICAL > SEMANTIC, mathematically.
     Technical indicators (local-DB hit, YARA, macro exec primitives, fuzzy
     family match) carry the heaviest weights. The SEMANTIC category (LLM text
     opinion) is capped low (SEMANTIC_CATEGORY_CAP) so a phishing lure can never
     by itself out-score a real structural indicator.

  2. SEMANTIC-ALONE CANNOT BE "HIGH".
     If *no* technical or reputation signal fired, the final band is clamped to
     at most MEDIUM, no matter how confident the LLM was about the prose.

  3. EXPLAINABILITY.
     score() returns a full per-indicator breakdown, so the report can show
     exactly which signals drove the verdict and by how much.

Two scores are produced:
  * risk_score   - 0-100, the modern, granular figure with verdict bands,
  * severity_score - the legacy 0-10 figure (risk_score/10, rounded) kept so
                     existing reports, the GUI, and tests keep working. A pure
                     local-DB hit still yields exactly 10.0; a clean file 0.0.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

# ---- Category weight ceilings ---------------------------------------------
# Each category's summed contribution is capped here, then categories are added
# and the total is clamped to MAX_RAW. Caps give diminishing returns when many
# weak signals of the same kind stack up.
TECHNICAL_CATEGORY_CAP = 100.0      # technical can drive the score on its own
REPUTATION_CATEGORY_CAP = 80.0
SEMANTIC_CATEGORY_CAP = 24.0        # deliberately < the MEDIUM band ceiling (49)

MAX_RAW = 100.0

# ---- Verdict bands (on the 0-100 risk score) ------------------------------
BANDS = [
    (0, 0, "Clean"),
    (1, 24, "Low"),
    (25, 49, "Medium"),
    (50, 79, "High"),
    (80, 100, "Critical"),
]
# A semantic-only result is clamped to the top of this band.
SEMANTIC_ONLY_MAX = 49      # => "Medium"


@dataclass
class Contribution:
    """One signal's contribution to the score (the explainable unit)."""
    indicator: str
    category: str          # technical | reputation | semantic
    points: float
    detail: str

    def as_dict(self) -> Dict:
        return {
            "indicator": self.indicator,
            "category": self.category,
            "points": round(self.points, 2),
            "detail": self.detail,
        }


@dataclass
class ScoreResult:
    risk_score: int                 # 0-100
    severity_score: float           # legacy 0-10
    verdict: str                    # Clean | Low | Medium | High | Critical
    is_malicious: bool
    contributions: List[Contribution] = field(default_factory=list)
    category_totals: Dict[str, float] = field(default_factory=dict)

    def as_dict(self) -> Dict:
        return {
            "risk_score": self.risk_score,
            "severity_score": self.severity_score,
            "verdict": self.verdict,
            "is_malicious": self.is_malicious,
            "category_totals": {k: round(v, 2) for k, v in self.category_totals.items()},
            "contributions": [c.as_dict() for c in self.contributions],
        }


def _band(score: int) -> str:
    for low, high, label in BANDS:
        if low <= score <= high:
            return label
    return "Critical"


class ScoringMatrix:
    """Turns the per-layer signals dict into a transparent weighted score.

    `signals` shape (every key optional; missing layers simply contribute 0):
        {
          "local_db_hit": bool,
          "fuzzy":  {"matched": bool, "best_confidence": 0..1, "families": [..]},
          "macro":  {"has_macros": bool, "autoexec": [..], "critical": [..],
                     "suspicious": [..]},
          "yara":   {"matched": bool, "top_severity": "low|medium|high|critical",
                     "rules": [..]},
          "virustotal": {"malicious": int, "suspicious": int, "total": int,
                         "ratio": 0..1},
          "llm":    {"is_suspicious": bool, "confidence": 0..1, "elements": [..]},
        }
    """

    # ---- per-indicator weights (points when fully triggered) --------------
    W_LOCAL_DB = 100.0              # exact known-bad hash => maximum
    W_YARA = {"critical": 90.0, "high": 65.0, "medium": 40.0, "low": 18.0}
    W_YARA_EXTRA = 8.0              # each additional rule beyond the top one
    W_FUZZY = 72.0                  # scaled by structural similarity confidence
    W_MACRO_AUTOEXEC = 22.0        # an auto-run trigger exists
    W_MACRO_CRITICAL = 40.0        # first exec/download primitive (Shell, etc.)
    W_MACRO_CRITICAL_EXTRA = 8.0   # each additional critical primitive
    W_MACRO_SUSPICIOUS = 10.0      # non-critical suspicious call(s), flat
    W_MACRO_DROPPER_SYNERGY = 20.0 # autoexec AND critical => classic dropper
    W_VT_RATIO = 80.0              # scaled by detection ratio
    W_VT_FLOOR = 35.0              # a few engines flag even at a low ratio
    W_LLM = 24.0                   # scaled by confidence (semantic, capped low)

    def score(self, signals: Dict) -> ScoreResult:
        contribs: List[Contribution] = []

        # ---------------- TECHNICAL ----------------
        if signals.get("local_db_hit"):
            contribs.append(Contribution(
                "local_db_hit", "technical", self.W_LOCAL_DB,
                "Exact hash present in local malicious-hash database."))

        yara = signals.get("yara") or {}
        if yara.get("matched"):
            top = str(yara.get("top_severity", "medium")).lower()
            base = self.W_YARA.get(top, self.W_YARA["medium"])
            rules = yara.get("rules", []) or []
            extra = max(0, len(rules) - 1) * self.W_YARA_EXTRA
            names = ", ".join(rules) if rules else "(unnamed)"
            contribs.append(Contribution(
                "yara_match", "technical", base + extra,
                f"YARA rule(s) matched [{names}], top severity '{top}'."))

        fuzzy = signals.get("fuzzy") or {}
        if fuzzy.get("matched"):
            conf = float(fuzzy.get("best_confidence", 0) or 0)
            fams = ", ".join(fuzzy.get("families", []) or []) or "known family"
            contribs.append(Contribution(
                "fuzzy_family_match", "technical", self.W_FUZZY * conf,
                f"Structural similarity to {fams} (confidence {conf:.2f})."))

        macro = signals.get("macro") or {}
        if macro.get("has_macros"):
            autoexec = macro.get("autoexec", []) or []
            critical = macro.get("critical", []) or []
            suspicious = macro.get("suspicious", []) or []

            if autoexec:
                contribs.append(Contribution(
                    "macro_autoexec", "technical", self.W_MACRO_AUTOEXEC,
                    f"Auto-run trigger(s): {', '.join(autoexec)}."))
            if critical:
                pts = self.W_MACRO_CRITICAL + max(0, len(critical) - 1) * self.W_MACRO_CRITICAL_EXTRA
                contribs.append(Contribution(
                    "macro_exec_primitive", "technical", pts,
                    f"Execution/download primitive(s): {', '.join(critical)}."))
            elif suspicious:
                contribs.append(Contribution(
                    "macro_suspicious", "technical", self.W_MACRO_SUSPICIOUS,
                    f"Suspicious macro call(s): {', '.join(suspicious[:6])}."))
            if autoexec and critical:
                contribs.append(Contribution(
                    "macro_dropper_synergy", "technical", self.W_MACRO_DROPPER_SYNERGY,
                    "Auto-executing macro combined with an exec/download "
                    "primitive (classic dropper pattern)."))

        # ---------------- REPUTATION ----------------
        vt = signals.get("virustotal") or {}
        vt_ratio = float(vt.get("ratio", 0) or 0)
        vt_flagged = int(vt.get("malicious", 0) or 0) + int(vt.get("suspicious", 0) or 0)
        if vt_flagged > 0:
            pts = max(self.W_VT_FLOOR, self.W_VT_RATIO * vt_ratio)
            contribs.append(Contribution(
                "virustotal", "reputation", pts,
                f"VirusTotal: {vt_flagged}/{vt.get('total', 0)} engines flagged "
                f"(ratio {vt_ratio:.2f})."))

        # ---------------- SEMANTIC ----------------
        llm = signals.get("llm") or {}
        if llm.get("is_suspicious"):
            conf = float(llm.get("confidence", 0) or 0)
            elems = ", ".join(llm.get("elements", []) or [])
            detail = f"LLM flagged the text as a likely lure (confidence {conf:.2f})."
            if elems:
                detail += f" Elements: {elems}."
            contribs.append(Contribution(
                "llm_semantic", "semantic", self.W_LLM * conf, detail))

        # ---------------- AGGREGATE with per-category caps -----------------
        caps = {
            "technical": TECHNICAL_CATEGORY_CAP,
            "reputation": REPUTATION_CATEGORY_CAP,
            "semantic": SEMANTIC_CATEGORY_CAP,
        }
        raw_totals = {"technical": 0.0, "reputation": 0.0, "semantic": 0.0}
        for c in contribs:
            raw_totals[c.category] = raw_totals.get(c.category, 0.0) + c.points
        category_totals = {cat: min(total, caps.get(cat, total))
                           for cat, total in raw_totals.items()}

        raw_score = min(MAX_RAW, sum(category_totals.values()))

        # Rule 2: semantic-only result cannot exceed MEDIUM.
        has_hard_signal = (category_totals.get("technical", 0) > 0
                           or category_totals.get("reputation", 0) > 0)
        if not has_hard_signal:
            raw_score = min(raw_score, SEMANTIC_ONLY_MAX)

        risk_score = int(round(raw_score))
        severity_score = round(risk_score / 10.0, 1)   # legacy 0-10
        verdict = _band(risk_score)

        # A file is "malicious" if any layer fired. (Mirrors the original
        # OR-of-layers behaviour; the score then expresses *how* malicious.)
        is_malicious = bool(contribs) and risk_score > 0

        return ScoreResult(
            risk_score=risk_score,
            severity_score=severity_score,
            verdict=verdict,
            is_malicious=is_malicious,
            contributions=contribs,
            category_totals=category_totals,
        )

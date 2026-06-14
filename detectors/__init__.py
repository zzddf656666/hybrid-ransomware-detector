"""
detectors - modular detection engines for the Hybrid Ransomware Detection System.

Each engine is independent, optional, and degrades gracefully when its
third-party dependency is not installed:

    fuzzy_hash      TLSH + ssdeep structural/similarity hashing (polymorphic
                    family detection)
    macro_analysis  olevba VBA/XLM macro extraction + static triage
    yara_engine     YARA pattern matching against a rules directory
    llm_backends    pluggable LLM (local Ollama / cloud OpenAI / none)
    scoring         transparent weighted scoring matrix
"""

from .fuzzy_hash import FuzzyHasher, FuzzyResult, FUZZY_AVAILABLE
from .macro_analysis import MacroAnalyzer, MacroResult, OLEVBA_AVAILABLE
from .yara_engine import YaraEngine, YaraResult, YARA_AVAILABLE
from .llm_backends import build_llm_backend, LLMBackend
from .scoring import ScoringMatrix, ScoreResult

__all__ = [
    "FuzzyHasher", "FuzzyResult", "FUZZY_AVAILABLE",
    "MacroAnalyzer", "MacroResult", "OLEVBA_AVAILABLE",
    "YaraEngine", "YaraResult", "YARA_AVAILABLE",
    "build_llm_backend", "LLMBackend",
    "ScoringMatrix", "ScoreResult",
]

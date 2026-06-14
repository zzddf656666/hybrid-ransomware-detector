"""Smoke test for the patched RansomwareScanner — verifies the GUI integration
points work AND that legacy (no-argument) call signatures still behave identically."""
import hashlib, csv, threading, tempfile, os
from pathlib import Path
import docx as docxlib
import RansomwareScanner as RS

tmp = Path(tempfile.mkdtemp())
scan_dir = tmp / "docs"; scan_dir.mkdir()

# 1. Create three real .docx files
paths = []
for i, text in enumerate(["hello world", "send bitcoin to decrypt key now", "quarterly report"]):
    d = docxlib.Document(); d.add_paragraph(text)
    p = scan_dir / f"file_{i}.docx"; d.save(p); paths.append(p)

# 2. Build a hash DB marking file_1 as malicious
md5_1 = hashlib.md5(paths[1].read_bytes()).hexdigest()
db = tmp / "dataset.csv"
with open(db, "w", newline="") as f:
    w = csv.writer(f); w.writerow(["FileName", "md5Hash", "Benign"])
    w.writerow(["evil.docx", md5_1, "0"])
    w.writerow(["good.docx", "ffffffffffffffffffffffffffffffff", "1"])

# 3. Test the shared import function
out = RS.import_hash_database(str(db), str(tmp / "imported.csv"))
assert out["ok"] and out["entries"] == 2 and not out["missing_columns"], out
miss = RS.import_hash_database(str(tmp / "nope.csv"))
assert miss["error_kind"] == "missing_source", miss
print("import_hash_database: OK")

# 4. Scanner with no API keys (VT + LLM skipped gracefully)
cfg = dict(RS.CONFIG)
cfg.update({"scan_directories": [str(scan_dir)], "kaggle_database_path": str(tmp / "imported.csv"),
            "report_directory": str(tmp / "reports"), "chatgpt_api_key": "", "virustotal_api_key": ""})
sc = RS.RansomwareScanner(cfg)
assert md5_1 in sc.hash_database

# 5. LEGACY signature (CLI path): scan_directory(dir) with no extra args
legacy = sc.scan_directory(str(scan_dir))
assert len(legacy) == 3, f"legacy scan returned {len(legacy)}"
flagged = [r for r in legacy if r["is_malicious"]]
assert len(flagged) == 1 and flagged[0]["severity_score"] == 10 and flagged[0]["md5_hash"] == md5_1
clean = [r for r in legacy if not r["is_malicious"]]
assert all(r["severity_score"] == 0 for r in clean)
print("legacy scan_directory (CLI path): OK — 3 files, 1 malicious @ severity 10")

# 6. NEW signature: progress callback receives (done, total, path, result)
events = []
res = sc.scan_all_directories(progress_callback=lambda d, t, p, r: events.append((d, t, os.path.basename(p))))
assert len(res) == 3 and [e[0] for e in events] == [1, 2, 3] and all(e[1] == 3 for e in events)
print(f"progress callback: OK — {events}")

# 7. Cancellation: cancel after first file -> exactly 1 result
ev = threading.Event()
def cb(done, total, path, result):
    if done == 1: ev.set()
partial = sc.scan_all_directories(progress_callback=cb, cancel_event=ev)
assert len(partial) == 1, f"expected 1 partial result, got {len(partial)}"
print("cancellation: OK — stopped after 1/3 files")

# 8. A failing progress callback must not break the scan
res2 = sc.scan_directory(str(scan_dir), progress_callback=lambda *a: 1 / 0)
assert len(res2) == 3
print("callback exception isolation: OK")

# 9. generate_report still writes JSON + TXT
report = sc.generate_report(legacy)
files = sorted(os.listdir(tmp / "reports"))
assert any(f.endswith(".json") for f in files) and any(f.endswith(".txt") for f in files)
assert "Files flagged:" in report                      # new multi-layer header
assert str(flagged[0]["file_path"]) in report          # the flagged file is listed
print("generate_report: OK —", files)

# ===========================================================================
# v4 NEW-LAYER COVERAGE — scoring matrix + fuzzy / macro / YARA engines
# ===========================================================================
from detectors import (
    ScoringMatrix, FuzzyHasher, MacroAnalyzer, YaraEngine,
    FUZZY_AVAILABLE, OLEVBA_AVAILABLE, YARA_AVAILABLE,
)

sm = ScoringMatrix()

# 10. Scoring — a pure local-DB hit is the maximum (legacy severity 10.0, Critical).
db_only = sm.score({"local_db_hit": True})
assert db_only.severity_score == 10.0 and db_only.risk_score == 100
assert db_only.verdict == "Critical", db_only.verdict
print("scoring/local-db: OK — severity 10.0 → Critical")

# 11. Scoring — no signals → clean 0.0, not malicious.
clean_score = sm.score({})
assert clean_score.severity_score == 0.0 and clean_score.risk_score == 0
assert clean_score.verdict == "Clean" and clean_score.is_malicious is False
print("scoring/clean: OK — severity 0.0 → Clean")

# 12. *** CORE REQUIREMENT *** — a technical indicator (auto-run macro invoking an
#     exec primitive) MUST mathematically outweigh a maximally-confident semantic
#     phishing flag. This is the whole point of the weighted matrix.
technical = sm.score({"macro": {"has_macros": True, "autoexec": ["AutoOpen"],
                                 "critical": ["Shell"], "suspicious": []}})
semantic = sm.score({"llm": {"is_suspicious": True, "confidence": 1.0,
                             "elements": ["urgent wire transfer", "overdue invoice"]}})
assert technical.risk_score > semantic.risk_score, (technical.risk_score, semantic.risk_score)
print(f"scoring/technical>semantic: OK — {technical.risk_score} (macro dropper) "
      f"> {semantic.risk_score} (phishing lure)")

# 13. Semantic-ALONE can never exceed the MEDIUM band, even at confidence 1.0.
assert semantic.risk_score <= 49 and semantic.verdict in ("Low", "Medium"), semantic.as_dict()
print(f"scoring/semantic-capped: OK — phishing-only stays '{semantic.verdict}' "
      f"(risk {semantic.risk_score} ≤ 49)")

# 14. Score breakdown is explainable — one labelled contribution per fired signal,
#     and the auto-exec + exec-primitive combo raises the dropper-synergy flag.
combo = sm.score({
    "yara": {"matched": True, "top_severity": "high",
             "rules": ["Office_Macro_AutoExec_Execution"]},
    "macro": {"has_macros": True, "autoexec": ["AutoOpen"], "critical": ["Shell"]},
})
indicators = {c.indicator for c in combo.contributions}
assert {"yara_match", "macro_autoexec", "macro_exec_primitive",
        "macro_dropper_synergy"} <= indicators, sorted(indicators)
print(f"scoring/breakdown: OK — {sorted(indicators)}")

# 15. Detector availability flags are real booleans; engines instantiate cleanly.
assert all(isinstance(f, bool) for f in (FUZZY_AVAILABLE, OLEVBA_AVAILABLE, YARA_AVAILABLE))
FuzzyHasher(); MacroAnalyzer()      # must not raise even if libs are absent
print(f"detectors/flags: OK — fuzzy={FUZZY_AVAILABLE}, macro={OLEVBA_AVAILABLE}, yara={YARA_AVAILABLE}")

# 16. A benign .docx carries no VBA — macro layer must report has_macros=False.
plain = scan_dir / "file_0.docx"    # the "hello world" document from step 1
macro_res = MacroAnalyzer().analyze_file(str(plain))
assert macro_res.has_macros is False, macro_res.as_dict()
print("detectors/macro-clean: OK — no macros on a benign .docx")

# 16b. Non-Office files must be skipped, not false-flagged. (Regression: olevba's
#      VBA_Parser otherwise reports phantom macros on plain .txt/.pdf input.)
txt = scan_dir / "note.txt"; txt.write_text("all your files are encrypted", encoding="utf-8")
txt_macro = MacroAnalyzer().analyze_file(str(txt))
assert txt_macro.has_macros is False and "Office" in txt_macro.detail, txt_macro.as_dict()
print("detectors/macro-non-office: OK — .txt skipped, no phantom macros")

# 17. YARA engine loads the bundled rules and clears a benign file (no false positive).
if YARA_AVAILABLE:
    ye = YaraEngine(rules_dir=str(RS.BUNDLED_RULES_DIR))
    benign_yara = ye.scan_file(str(plain))
    assert benign_yara.matched is False, benign_yara.as_dict()
    assert benign_yara.rules_loaded >= 1, benign_yara.as_dict()
    print(f"detectors/yara-clean: OK — {benign_yara.rules_loaded} rule file(s), benign clears")
else:
    print("detectors/yara-clean: SKIPPED — yara-python not installed")

print("\nALL SMOKE TESTS PASSED")

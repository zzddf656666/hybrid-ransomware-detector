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
assert "Malicious files detected: 1" in report
print("generate_report: OK —", files)

print("\nALL SMOKE TESTS PASSED")

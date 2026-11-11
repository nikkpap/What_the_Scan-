"""Release check: start the app (script, .exe, Linux binary or macOS app) in smoke mode and require that it
opens its window. Usage: python tools/smoke.py [--no-offscreen] <command...>"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

args = sys.argv[1:]
offscreen = True
if args and args[0] == "--no-offscreen":
    offscreen, args = False, args[1:]
report = Path(tempfile.gettempdir()) / "whatthescan-smoke.txt"
report.unlink(missing_ok=True)
env = dict(os.environ, WHATTHESCAN_SMOKE_TEST=str(report))
if offscreen:
    env["QT_QPA_PLATFORM"] = "offscreen"
try:
    code = subprocess.run(args, env=env, timeout=900).returncode
except subprocess.TimeoutExpired:
    code = "timeout"
text = report.read_text(encoding="utf-8") if report.exists() else "(no report written)"
print(text)
print(f"exit code: {code}")
ok = any(line.startswith("OK window started") for line in text.splitlines())
bad = [line for line in text.splitlines() if line.startswith(("SETUP FAILED", "ERROR"))]
if not ok or bad or code not in (0,):
    print("::error::The app did not start correctly. " + " | ".join(bad))
    sys.exit(1)
print("Smoke test passed.")

"""Build WhatTheScan-offline.zip: everything the app needs to install without internet, for every OS.

Reads the download addresses and checksums from WhatTheScan.pyw itself, so the package always
matches the app. Run from the repository root:  python tools/build_offline.py
"""
import ast
import hashlib
import json
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "WhatTheScan.pyw"
WORK = ROOT / "offline-build"
OUT = ROOT / "dist" / "WhatTheScan-offline.zip"

PYTHONS = ("3.10", "3.11", "3.12", "3.13", "3.14")
def _linux(arch, legacy):
    versions = ["2_39", "2_35", "2_34", "2_31", "2_28", "2_27", "2_17"]
    return [f"manylinux_{v}_{arch}" for v in versions] + [f"manylinux2014_{arch}"] + legacy


PLATFORMS = {  # pip expands the macOS tags to older versions; manylinux tags must be listed
    "Windows x64": ["win_amd64"],
    "Windows ARM64": ["win_arm64"],
    "macOS Apple Silicon": ["macosx_15_0_arm64"],
    "macOS Intel": ["macosx_15_0_x86_64"],
    "Linux x64": _linux("x86_64", ["manylinux_2_12_x86_64", "manylinux2010_x86_64",
                                   "manylinux_2_5_x86_64", "manylinux1_x86_64"]),
    "Linux ARM64": _linux("aarch64", []),
}


def constants():
    wanted = {"VERSION", "NAPS_URL", "NAPS_HASHES", "PYTHON_WIN_URL", "PIP_PACKAGES", "OCR_URL",
              "OCR_SHA256", "DRIVER_PACKAGES", "OFFLINE_NAME"}
    values = {}
    for node in ast.parse(APP.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id in wanted:
            values[node.targets[0].id] = ast.literal_eval(node.value)
    missing = wanted - values.keys()
    if missing:
        sys.exit(f"Missing constants in WhatTheScan.pyw: {sorted(missing)}")
    return values


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch(url, target, expected=None):
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.is_file():
        print(f"  ↓ {target.name}")
        request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 WhatTheScan-offline-builder"})
        with urllib.request.urlopen(request, timeout=300) as response, open(target, "wb") as out:
            shutil.copyfileobj(response, out, 1 << 20)
    if expected and sha256(target) != expected:
        target.unlink()
        sys.exit(f"Checksum mismatch for {target.name}")


def main():
    c = constants()
    shutil.rmtree(WORK, ignore_errors=True)
    files = {}

    print("Python packages (wheels)")
    wheels = WORK / "wheels"
    wheels.mkdir(parents=True)
    report = {}
    for label, tags in PLATFORMS.items():
        ok = []
        for version in PYTHONS:
            command = [sys.executable, "-m", "pip", "download", "--quiet", "--disable-pip-version-check",
                       "--only-binary=:all:", "--implementation", "cp", "--python-version", version,
                       "--dest", str(wheels), *sum((["--platform", t] for t in tags), []), *c["PIP_PACKAGES"]]
            if subprocess.run(command).returncode == 0:
                ok.append(version)
        report[label] = ok
        print(f"  {label}: Python {', '.join(ok) or 'none'}")
    if not report["Windows x64"] or not report["Linux x64"]:
        sys.exit("Could not download the wheels for Windows x64 / Linux x64.")
    files["wheels"] = sorted(p.name for p in wheels.glob("*.whl"))

    print("NAPS2 scanning engine")
    base = c["NAPS_URL"].rsplit("/", 1)[0]
    version = c["NAPS_URL"].rsplit("/", 1)[1].split("-")[1]
    for asset in ("win-x64.exe", "win-arm64.exe", *c["NAPS_HASHES"]):
        name = f"naps2-{version}-{asset}"
        fetch(f"{base}/{name}", WORK / "naps2" / name, c["NAPS_HASHES"].get(asset))

    print("64-bit Python for Windows")
    for arch in ("amd64", "arm64"):
        url = c["PYTHON_WIN_URL"].format(arch=arch)
        fetch(url, WORK / "python" / url.rsplit("/", 1)[1])

    print("Scanner drivers")
    for model, package in c["DRIVER_PACKAGES"].items():
        name = package.get("filename") or package["url"].rsplit("/", 1)[1]
        fetch(package["url"], WORK / "drivers" / name)

    print("OCR languages")
    for code, digest in c["OCR_SHA256"].items():
        fetch(c["OCR_URL"].format(code=code), WORK / "ocr" / f"{code}.traineddata.zip", digest)

    manifest = {"app": "What the Scan?!", "version": c["VERSION"], "pythons": PYTHONS, "wheels": report,
                "files": {str(p.relative_to(WORK)).replace("\\", "/"): sha256(p)
                          for p in sorted(WORK.rglob("*")) if p.is_file()}}
    (WORK / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (WORK / "README.txt").write_text(f"""What the Scan?! v{c['VERSION']} · offline package

Put this zip (or the unzipped folder, named {c['OFFLINE_NAME']}) in the same folder as
WhatTheScan.pyw, WhatTheScan-windows-x64.exe or WhatTheScan-linux-x64, then start the app.
It installs NAPS2, PyQt6 / PyMuPDF / python-docx, 64-bit Python (Windows), the Epson L14150 and
Canon TS3150 drivers and the OCR languages from here, with no internet.
Every file is still checked (publisher signature or SHA-256) exactly as when it is downloaded.
Without this package the app simply downloads what it needs.

Ελληνικά: βάλε αυτό το zip στον ίδιο φάκελο με την εφαρμογή και άνοιξέ την. Όλα εγκαθίστανται
από εδώ χωρίς internet. Χωρίς το zip η εφαρμογή κατεβάζει ό,τι χρειάζεται όπως πάντα.

Wheels: Python {', '.join(PYTHONS)} for Windows (x64/ARM64), macOS (Apple Silicon/Intel), Linux (x64/ARM64).
Note: on Linux the NAPS2 .deb/.rpm may still need system libraries from your distribution.
""", encoding="utf-8")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    print(f"Writing {OUT.name}")
    with zipfile.ZipFile(OUT, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
        for path in sorted(WORK.rglob("*")):
            if path.is_file():
                archive.write(path, f"{c['OFFLINE_NAME']}/{path.relative_to(WORK).as_posix()}")
    size = OUT.stat().st_size
    print(f"Done: {size / 1e6:.0f} MB")
    if size > 2_000_000_000:
        sys.exit("The package is larger than the 2 GB GitHub release limit.")


if __name__ == "__main__":
    main()

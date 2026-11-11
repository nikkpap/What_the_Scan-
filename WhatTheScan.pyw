import os
import shutil
import sys
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import ctypes
import getpass
import hashlib
import json
import platform
import re
import socket
import ssl
import time
import subprocess
import tempfile
import threading
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from queue import Empty, Queue

VERSION = "1.0.2"
# Change this one line to rename the app everywhere.
APP_NAME = "What the Scan?!"
APP_TAGLINE = "Scanner busy? Now you know who."
BRANDS = "Epson, Canon & HP"
WINDOWS = sys.platform == "win32"
MAC = sys.platform == "darwin"
LINUX = sys.platform.startswith("linux")
HIDDEN = getattr(subprocess, "CREATE_NO_WINDOW", 0)
# True when running as the built Windows .exe or Linux binary (PyInstaller).
FROZEN = bool(getattr(sys, "frozen", False))
# Release file names: the .exe / Linux binary built by GitHub Actions, or the .pyw script.
RELEASE_ASSET = ("WhatTheScan-windows-x64.exe" if WINDOWS else
                 "WhatTheScan-linux-x64" if LINUX else "WhatTheScan.pyw") if FROZEN else "WhatTheScan.pyw"
DRIVERS = (
    ("twain", "wia", "escl") if WINDOWS else
    ("apple", "escl") if MAC else ("sane", "escl")
)
# How many driver searches run at the same time. Set to 1 if a driver misbehaves
# when another one is enumerating devices in parallel.
DISCOVERY_PARALLEL = 3
DISCOVERY_TIMEOUT_MS = 15000
# Every copy of this app on the local network shares "scanner in use" state on this UDP port.
PRESENCE_PORT = 47391
PRESENCE_HEARTBEAT = 2.0
PRESENCE_EXPIRY = 8.0
RESTART_ENV = "NETWORK_SCAN_RESTARTED"
QT_CACHE = (Path.home() / ".epson-network-scan" /
            f"qt-{sys.implementation.cache_tag}-{platform.machine()}")
if QT_CACHE.is_dir():
    sys.path.insert(0, str(QT_CACHE))
# Over-the-air updates come from the GitHub releases of this repository.
REPO = "nikkpap/What_the_Scan-"
REPO_URL = f"https://github.com/{REPO}"
AUTHOR_URL = "https://github.com/nikkpap"
NAPS_URL = "https://github.com/cyanfish/naps2/releases/download/v8.6.0/naps2-8.6.0-win-x64.exe"
NAPS_HASHES = {
    "mac-univ.pkg": "8bd5635cae69336f781c418aabc012fddd7348c787bc3ff9940f11ce9bead538",
    "linux-arm64.deb": "5eeaf2a664c6749bb623ef42d0897dfe6a91eeb9260ce6db2ca8aeed29c96bd9",
    "linux-arm64.rpm": "6b7c37c2192c5a7fa26548391c1ebd121dd261797ead5f7063ba0b60282b78fb",
    "linux-x64.deb": "bc618ce0da3817409757e828b23c03992530951a769d1debe7291e48db9b3626",
    "linux-x64.rpm": "0ab6c7c012017ea4aba35f8eb4a4913a06bd4808f5f158191ffa3969fc3cc272",
}
PYTHON_WIN_URL = "https://www.python.org/ftp/python/3.14.10/python-3.14.10-{arch}.exe"
PIP_PACKAGES = ("PyQt6>=6.6,<7", "PyMuPDF>=1.24,<2", "python-docx>=1.1")
# NAPS2's own OCR language packs (tesseract 4 data) and their published SHA-256 checksums.
OCR_URL = "https://github.com/cyanfish/naps2-components/releases/download/tesseract-4.0.0b4/{code}.traineddata.zip"
OCR_SHA256 = {
    "ara": "24d2a74937150e6d41a69f2758aea3817d7f80ed53f780adaa492a83e249b62f",
    "bul": "75efd60898e3f6e254f3a9059d53548b92140ff14c603cbc3d46061d7a2d257d",
    "chi_sim": "21ebe92da47078c237b776d5ef79b3668b6a5b76f1ec527588e60d57230f097d",
    "deu": "134f41cb8a47e139cf988ea255f03a5b278d50eabad438204f708abf5a6442ce",
    "ell": "9dede46367708f74917386b88a08e7ca41829aa4278a0b187af594fc6a584ae8",
    "eng": "9d167994617c5fd827bf6b31f298e69cd05e6d30b9965715e78191df5606389e",
    "fra": "00b779d1373d837f927d34f1e66d9b99d0339ce5dba82d80b928c5eba431ad8a",
    "ita": "53136c0def889f2acad686e96e6f40b7a7d53e5537dfbbf956ba351892bbf8e6",
    "nld": "572f6fc496f7998f10e1a229ca103c0f6bb685d837648c04315efc98b98524c3",
    "pol": "c7a892bcb49f237159662865fa18703ccc03f0dd8d1573fd8ffc9057d664e962",
    "por": "0f8913e7e691237e0ff946ba993ed32a1c1eafcf7957263dc4a54f1b2a99411d",
    "ron": "79d51616c67ad813608b3a82dd10cfc1ee874463d5dce11cc61c12de3f48a58c",
    "rus": "0dd9b6ab808045a706ad312283b1841b1ba0c5e196287e7a773f66e1e629b5e6",
    "spa": "820a0ec5e083188b366ac3e5d79f02fa1bb51c274c3e01ce6943826bacc38981",
    "sqi": "063dc592eed9c5adc41b006b2b52fe84f0103f144499b1a6d4423bd301c375df",
    "srp": "13c63b4992906d5c016924ece6ab29d8b27cc1bf7111dd7243ccb680e799fac2",
    "tur": "7141de10ca977abdab21080afe5dc2025d6cec1661fba5803099bacc25033091",
    "ukr": "c14a794e98c24976c84f41f05217fba1155953f3a6062b9f63d6122e0936f6f7",
}
# Put this zip (or its unzipped folder) next to the app to install everything without internet.
OFFLINE_NAME = "WhatTheScan-offline"
CATALOG = {
    "Epson · 2024": ("DS-800WN", "DS-900WN"),
    "Epson · 2025": ("DS-1730", "DS-1760WN", "DS-530 II TAA", "DS-730N TAA", "DS-870 TAA"),
    "Epson · 2026": ("DS-530X", "DS-785W", "ES-550W", "ES-590W", "RR-620W"),
    "Epson · existing": ("L14150",),
    "Canon · existing": ("PIXMA TS3150",),
    "Canon PIXMA · 2025": ("TS4140i", "TS4150i", "TS4320", "TS6520", "TS6540i", "TS6550i",
                           "TS7550i", "TR7120"),
    "Canon MAXIFY · 2025": ("GX5150", "GX6150", "GX7150", "GX5170", "GX6170", "GX7170"),
    "Canon imageCLASS · 2025": ("MF460 II",),
    "Canon imageFORMULA · 2025": ("DR-C340", "DR-C350"),
    "Canon imageFORMULA · 2026": ("R40II",),
    "HP ScanJet Pro": ("2000 s2", "2600 f1", "3000 s4", "3600 f1", "N4000 snw1", "N4600 fnw1"),
    "HP ScanJet Enterprise Flow": ("5000 s5", "7000 s3", "N6600 fnw1", "N7000 snw1", "9000 s1", "N9120 fn2"),
}
# Names the drivers report for a model, when they differ from the model name.
# Canon drivers call the TS3150 "TS3100 series".
MODEL_ALIASES = {
    "PIXMA TS3150": ("ts3100", "ts3150", "ts3151", "ts3152"),
}
# Official driver installers the app can download, verify (Authenticode) and run on Windows.
# "check" is a file the driver leaves behind; without one the app asks before installing.
DRIVER_PACKAGES = {
    "L14150": {
        "label": "Epson L14150 driver",
        "url": "https://ftp.epson.com/latin/drivers/inkjet/L14150_EScan2_67700_LA.exe",
        "signer": "Epson America",
        "check": ("twain_32", "escndv2", "es020c.ds"),
    },
    "PIXMA TS3150": {
        "label": "Canon TS3150 driver (TS3100 series MP Drivers 1.03)",
        # Canon's own download redirect for "TS3100 series MP Drivers Ver.1.03 (Windows)".
        "url": "https://pdisp01.c-wss.com/gdl/WWUFORedirectTarget.do?id=MDEwMDAwODc1OTA1&cmp=ACM&lang=EN",
        "filename": "mpnp-win-ts3100-1_03-ea34_2.exe",
        "signer": "Canon",
        "check": None,
    },
}
GUIDE = """HOW TO SCAN (3 steps)
  1. Turn on the scanner and load the paper (glass or document feeder).
  2. Check the top card says  ✓ Connected to <your scanner>.
  3. Click  Scan.  It saves as PDF, JPG or PDF + JPG, as chosen in
     Settings › Scanning › Save as  (PDF by default).
     Tick "Also save an editable document" there and choose Word (.docx)
     or OpenDocument (.odt, LibreOffice on Mac / Linux).
     Files are saved automatically in Documents › What the Scan.

Everything is automatic by default:
  • The app finds every scanner on all drivers by itself (TWAIN, WIA, eSCL…).
  • Paper source "Auto" uses the document feeder when it has paper,
    otherwise the flatbed glass.
  • Want to change something? ⚙ Settings (Ctrl+,):
      Scanner   choose a different scanner, driver, model driver or network address
      Scanning  save as PDF / JPG / both, paper source, size, resolution,
                colour, save folder
      Text & translation   OCR languages (auto or chosen), .txt, auto translation
      General   language (EN / GR), theme (auto / light / dark), updates
  • OCR languages download automatically the first time.
  • The Text button shows the recognised text; translate it with Google
    Translate (free), MyMemory or your own LibreTranslate server.

STATUS LIGHT
  ● Green   Ready. The scanner is free, so you can scan.
  ● Yellow  Idle. Searching, no scanner selected, or the scanner is on standby.
  ● Red     In use. You or another person on the network is scanning.
            Wait until the light turns green. The app beeps when the scanner is free.
  Other PCs see that the scanner is busy only if they run this app too.
  If Windows Firewall asks, allow the app on private networks.

SHORTCUTS
  Ctrl+S  scan    Ctrl+P  preview    Ctrl+T  text & translation
  F5  search again    Ctrl+,  settings    F1  this guide    Esc  cancel

OFFLINE INSTALLATION
  Put WhatTheScan-offline.zip (from the GitHub release) next to the app.
  NAPS2, Python packages, drivers and OCR languages are then installed from it,
  with no internet. Without the zip everything is downloaded as usual.

DRIVERS
  Epson: Epson Scan 2 (Windows: add the scanner IP in Epson Scan 2 Utility).
  Canon: MP Drivers. Settings › Scanner › Driver setup installs the TS3150 driver.
  HP: HP Smart / HP Scan drivers.  macOS: Image Capture.  Linux: SANE."""


def normalize(text):
    return "".join(c for c in str(text).lower() if c.isalnum())


def local_broadcasts():
    """255.255.255.255 plus a /24 broadcast for each local IPv4 address (multi-NIC PCs)."""
    targets = ["255.255.255.255"]
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith(("127.", "169.254.")):
                target = ip.rsplit(".", 1)[0] + ".255"
                if target not in targets:
                    targets.append(target)
    except OSError:
        pass
    return targets


def discover_network(timeout=2.0):
    """Find Epson (ENPC, UDP 3289) and Canon (BJNP, UDP 8612) devices on the local network.
    Returns a sorted list of (ip, mac, reachable, brand)."""
    epson_request = bytes.fromhex("4550534f4e5000ff00000000000000")
    # BJNP header: "BJNP", device type 2 (scanner), command 1 (discover), seq 1, no payload.
    canon_request = b"BJNP" + bytes([2, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0])
    replies = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sent, last_error = 0, None
        for target in local_broadcasts():
            for request, port in ((epson_request, 3289), (canon_request, 8612)):
                try:
                    udp.sendto(request, (target, port))
                    sent += 1
                except OSError as exc:
                    last_error = exc
        if not sent:
            raise last_error or OSError("Could not send the discovery request.")
        deadline = time.monotonic() + timeout
        while (remaining := deadline - time.monotonic()) > 0:
            udp.settimeout(remaining)
            try:
                data, (ip, _) = udp.recvfrom(4096)
            except socket.timeout:
                break
            except OSError:
                # Windows reports ICMP "port unreachable" as a reset; keep listening.
                time.sleep(0.02)
                continue
            if data[:7] == b"EPSONp\x00":
                # This ENPC reply format exposes the NIC address in the identity record.
                mac = data[54:60].hex(":").upper() if len(data) == 76 else ""
                brand = "Epson"
            elif data[:4] == b"BJNP" and len(data) >= 6 and data[5] == 1 and data[4] & 0x80:
                # Discover reply: 16-byte header, 4 unknown bytes, mac/addr lengths, then the MAC.
                mac = data[22:28].hex(":").upper() if len(data) >= 28 and data[20] == 6 else ""
                brand = "Canon"
            else:
                continue
            old = replies.get(ip)
            replies[ip] = (mac or (old[0] if old else ""), brand)

    def reachable(item):
        ip, (_, brand) = item
        if brand == "Canon":
            return True  # it just answered on the scanner protocol
        try:
            with socket.create_connection((ip, 1865), timeout=1):
                return True
        except OSError:
            return False

    items = sorted(replies.items(), key=lambda item: socket.inet_aton(item[0]))
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=min(16, len(items))) as pool:
        states = list(pool.map(reachable, items))
    return [(ip, mac, state, brand) for (ip, (mac, brand)), state in zip(items, states)]


ESCL_STATE = re.compile(r"<(?:\w+:)?State>\s*(\w+)\s*</(?:\w+:)?State>")
_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_LAN_TLS = ssl.create_default_context()
_LAN_TLS.check_hostname = False
_LAN_TLS.verify_mode = ssl.CERT_NONE  # scanners use self-signed certificates on the LAN
_LAN_TLS_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                             urllib.request.HTTPSHandler(context=_LAN_TLS))


def escl_status(ip):
    """Return the scanner's own state (Idle, Processing, Testing, Stopped, Down) or None."""
    for scheme, opener in (("http", _NO_PROXY), ("https", _LAN_TLS_OPENER)):
        try:
            with opener.open(f"{scheme}://{ip}/eSCL/ScannerStatus", timeout=2) as response:
                match = ESCL_STATE.search(response.read(65536).decode("utf-8", "replace"))
                if match:
                    return match.group(1).capitalize()
        except (OSError, ValueError):
            continue
    return None


class LanPresence:
    """Shares "scanner in use" between copies of this app over UDP broadcast."""

    def __init__(self):
        self.id = uuid4().hex
        try:
            self.user = getpass.getuser()
        except Exception:
            self.user = "someone"
        self.host = socket.gethostname()
        self.lock = threading.Lock()
        self.remote = {}
        self.claim = None
        self.available = False
        self.running = True
        self.rx = None

    def start(self):
        try:
            rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT") and not LINUX:
                rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            rx.bind(("", PRESENCE_PORT))
            rx.settimeout(1.0)
            self.rx = rx
            self.available = True
        except OSError:
            self.available = False
        if self.available:
            threading.Thread(target=self._listen, daemon=True).start()
        threading.Thread(target=self._heartbeat, daemon=True).start()

    def take(self, device, ip):
        with self.lock:
            self.claim = {"device": device, "ip": ip or "", "since": time.time()}
        self._send("busy")

    def release(self):
        with self.lock:
            had_claim, self.claim = self.claim is not None, None
        if had_claim:
            self._send("free")

    def holder(self, device, ip):
        """Return the remote user that is scanning on this scanner, or None."""
        now = time.monotonic()
        with self.lock:
            for key in [k for k, v in self.remote.items() if now - v["seen"] > PRESENCE_EXPIRY]:
                del self.remote[key]
            for entry in self.remote.values():
                if same_scanner(device, ip, entry.get("device", ""), entry.get("ip", "")):
                    return dict(entry)
        return None

    def stop(self):
        self.release()
        self.running = False

    def _send(self, state):
        with self.lock:
            claim = dict(self.claim) if self.claim else {}
        payload = json.dumps({
            "app": "network-scan", "v": 1, "id": self.id, "user": self.user,
            "host": self.host, "state": state, **claim,
        }).encode()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tx:
                tx.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                for target in local_broadcasts():
                    try:
                        tx.sendto(payload, (target, PRESENCE_PORT))
                    except OSError:
                        pass
        except OSError:
            pass

    def _heartbeat(self):
        while self.running:
            time.sleep(PRESENCE_HEARTBEAT)
            if self.claim is not None:
                self._send("busy")

    def _listen(self):
        while self.running:
            try:
                data, _ = self.rx.recvfrom(4096)
                message = json.loads(data)
            except socket.timeout:
                continue
            except (OSError, ValueError):
                time.sleep(0.05)
                continue
            if not isinstance(message, dict) or message.get("app") != "network-scan":
                continue
            sender = message.get("id")
            if not sender or sender == self.id:
                continue
            with self.lock:
                if message.get("state") == "busy":
                    message["seen"] = time.monotonic()
                    self.remote[sender] = message
                else:
                    self.remote.pop(sender, None)


def same_scanner(device_a, ip_a, device_b, ip_b):
    if ip_a and ip_b and ip_a == ip_b:
        return True
    a = normalize(device_a).replace("series", "")
    b = normalize(device_b).replace("series", "")
    return len(a) >= 4 and len(b) >= 4 and (a in b or b in a)


def find_backend():
    if MAC:
        for folder in (Path("/Applications"), Path.home() / "Applications"):
            candidate = folder / "NAPS2.app/Contents/MacOS/NAPS2"
            if candidate.is_file():
                return [str(candidate), "console"]
    if not WINDOWS:
        native = shutil.which("naps2")
        if native:
            return [native, "console"]
        flatpak = shutil.which("flatpak") if LINUX else None
        if flatpak and run_hidden([flatpak, "info", "com.naps2.Naps2"],
                                  capture_output=True, timeout=10).returncode == 0:
            return [flatpak, "run", "com.naps2.Naps2", "console"]
        return []
    found = shutil.which("NAPS2.Console.exe")
    if found:
        return [found]
    for key in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
        base = os.environ.get(key)
        if base:
            folder = Path(base)
            if key == "LOCALAPPDATA":
                folder /= "Programs"
            candidate = folder / "NAPS2" / "NAPS2.Console.exe"
            if candidate.is_file():
                return [str(candidate)]
    return []


_BACKEND = None


def get_backend(refresh=False):
    """find_backend() can spawn flatpak; cache the answer for the GUI."""
    global _BACKEND
    if refresh or not _BACKEND:
        _BACKEND = find_backend()
    return _BACKEND


def run_hidden(args, **kwargs):
    return subprocess.run(args, creationflags=HIDDEN, **kwargs)


# ---------------------------------------------------------------- offline package
def offline_bundle():
    """The offline package next to the app: WhatTheScan-offline.zip or its unzipped folder, else None."""
    here = Path(sys.executable if FROZEN else __file__).resolve().parent
    for candidate in (here / f"{OFFLINE_NAME}.zip", here / OFFLINE_NAME):
        if candidate.is_file() or candidate.is_dir():
            return candidate
    return None


def offline_names():
    """{lower-case file name: member path} of every file in the offline package."""
    bundle = offline_bundle()
    if bundle is None:
        return {}
    if bundle.is_dir():
        return {p.name.lower(): str(p) for p in bundle.rglob("*") if p.is_file()}
    import zipfile
    try:
        with zipfile.ZipFile(bundle) as archive:
            return {Path(n).name.lower(): n for n in archive.namelist() if not n.endswith("/")}
    except (OSError, zipfile.BadZipFile):
        return {}


def offline_extract(name, target):
    """Copy the file called `name` from the offline package to `target`. True if it was there."""
    bundle = offline_bundle()
    member = offline_names().get(name.lower()) if bundle else None
    if not member:
        return False
    try:
        if bundle.is_dir():
            shutil.copyfile(member, target)
        else:
            import zipfile
            with zipfile.ZipFile(bundle) as archive, archive.open(member) as source, open(target, "wb") as out:
                shutil.copyfileobj(source, out, 1024 * 1024)
        return True
    except (OSError, KeyError):
        Path(target).unlink(missing_ok=True)
        return False


def naps2_ocr_folders(backend):
    """Where NAPS2 keeps OCR languages: <NAPS2 data>/components/tesseract4/{best,fast}/<code>.traineddata."""
    if WINDOWS:
        roots = [Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "NAPS2"]
    else:
        roots = [Path.home() / ".config" / "naps2"]
        if backend and "flatpak" in Path(backend[0]).name:
            roots.insert(0, Path.home() / ".var" / "app" / "com.naps2.Naps2" / "config" / "naps2")
    folders = []
    for root in roots:
        components = root / "components"
        legacy = components / "tesseract-4.0.0b4"
        current = components / "tesseract4"
        folders.append(legacy if legacy.is_dir() and not current.is_dir() else current)
    return folders


def install_ocr_offline(code, backend):
    """Install one OCR language from the offline package. True when done."""
    name = f"{code}.traineddata.zip"
    if name.lower() not in offline_names() or code not in OCR_SHA256:
        return False
    import zipfile
    with tempfile.TemporaryDirectory(prefix="WhatTheScan-ocr-") as folder:
        package = Path(folder) / name
        if not offline_extract(name, package) or sha256_file(package) != OCR_SHA256[code]:
            return False
        with zipfile.ZipFile(package) as archive:
            members = [m for m in archive.namelist()
                       if m in (f"best/{code}.traineddata", f"fast/{code}.traineddata")]
            if not members:
                return False
            for root in naps2_ocr_folders(backend):
                for member in members:
                    target = root / member
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(member) as source, open(target, "wb") as out:
                        shutil.copyfileobj(source, out, 1024 * 1024)
    return True


def offline_wheels():
    """Unpack the Python wheels of the offline package into a folder for pip. None if there are none."""
    bundle = offline_bundle()
    names = {n: m for n, m in offline_names().items() if n.endswith(".whl")}
    if not names:
        return None
    folder = QT_CACHE.parent / "offline-wheels"
    folder.mkdir(parents=True, exist_ok=True)
    for name in names:
        target = folder / name
        if not target.is_file():
            offline_extract(name, target)
    return folder


def download(url, target, report, label):
    """Fetch url into target, taking the file from the offline package when it is there.
    Callers verify every file (signature or checksum) the same way in both cases."""
    if offline_extract(Path(target).name, target):
        report(f"{label} (offline package)")
        return
    with urllib.request.urlopen(url, timeout=30) as response, target.open("wb") as out:
        if urllib.parse.urlsplit(response.url).scheme != "https":
            raise ValueError("Download redirected away from HTTPS.")
        total = int(response.headers.get("Content-Length", "0") or 0)
        received, shown = 0, -1
        report(label)
        while chunk := response.read(256 * 1024):
            out.write(chunk)
            received += len(chunk)
            if total:
                percent = received * 100 // total
                if percent != shown:
                    shown = percent
                    report(f"{label} {percent}%")


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def install_vendor(url, signer, flags, report, label, filename=None):
    with tempfile.TemporaryDirectory(prefix="EpsonScan-") as folder:
        installer = Path(folder) / (filename or Path(urllib.parse.urlsplit(url).path).name)
        download(url, installer, report, f"Downloading {label}…")
        env = dict(os.environ, EPSON_SCAN_PACKAGE=str(installer))
        signature = run_hidden([
            "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
            "$s=Get-AuthenticodeSignature -LiteralPath $env:EPSON_SCAN_PACKAGE; "
            "if ($s.Status -ne 'Valid') { exit 1 }; $s.SignerCertificate.Subject",
        ], env=env, capture_output=True, text=True, timeout=60)
        if signature.returncode or signer.lower() not in signature.stdout.lower():
            raise RuntimeError(f"Windows could not verify the publisher of {label}.")
        report(f"Installing {label}…")
        try:
            subprocess.run([str(installer), *flags], check=True, timeout=600)
        except OSError as exc:
            if getattr(exc, "winerror", None) != 740:
                raise
            report(f"Waiting for Windows approval to install {label}…")
            env.update(SCAN_INSTALL_FLAGS=subprocess.list2cmdline(flags))
            run_hidden([
                "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                "$ErrorActionPreference='Stop'; "
                "$p=Start-Process -FilePath $env:EPSON_SCAN_PACKAGE "
                "-ArgumentList $env:SCAN_INSTALL_FLAGS -Verb RunAs -Wait -PassThru; exit $p.ExitCode",
            ], env=env, check=True, timeout=600)


def install_native_naps(report):
    hashes = NAPS_HASHES
    manager = None
    if MAC:
        asset = "mac-univ.pkg"
    else:
        arch = {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64"}
        family = arch.get(platform.machine().lower())
        manager = shutil.which("apt-get") or shutil.which("dnf")
        if not family or not manager:
            raise RuntimeError("NAPS2 setup needs a supported processor and APT, DNF, or Flathub.")
        extension = "deb" if Path(manager).name == "apt-get" else "rpm"
        asset = f"linux-{family}.{extension}"
    with tempfile.TemporaryDirectory(prefix="NetworkScan-") as folder:
        package = Path(folder) / f"naps2-8.6.0-{asset}"
        download(NAPS_URL.rsplit("/", 1)[0] + "/" + package.name, package, report, "Downloading NAPS2…")
        if sha256_file(package) != hashes[asset]:
            raise RuntimeError("NAPS2 package checksum did not match the published release.")
        report("Waiting for system approval to install NAPS2…")
        if MAC:
            command = [
                "/usr/bin/osascript", "-e", "on run argv",
                "-e", 'do shell script ("/usr/sbin/installer -pkg " & quoted form of item 1 of argv & " -target /") with administrator privileges',
                "-e", "end run", str(package),
            ]
        else:
            command = [manager, "-y", "install", str(package)]
            if os.geteuid() != 0:
                pkexec = shutil.which("pkexec")
                if not pkexec:
                    raise RuntimeError("This Linux desktop needs PolicyKit or a configured Flathub.")
                command.insert(0, pkexec)
        run_hidden(command, stdin=subprocess.DEVNULL, check=True, timeout=600)


def install_naps(report):
    report("Installing NAPS2…")
    if WINDOWS:
        asset = NAPS_URL.replace("win-x64", "win-arm64") if platform.machine().lower() == "arm64" else NAPS_URL
        install_vendor(asset, "NAPS2 Software",
                       ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"], report, "NAPS2")
    elif LINUX and shutil.which("flatpak") and not any(n.startswith("naps2-") for n in offline_names()):
        result = run_hidden(["flatpak", "install", "--user", "--noninteractive", "-y",
                             "flathub", "com.naps2.Naps2"], timeout=600)
        if result.returncode != 0 or not find_backend():
            install_native_naps(report)
    else:
        install_native_naps(report)
    if not find_backend():
        raise RuntimeError("NAPS2 setup finished, but its scanner engine was not found.")


def windows_python(report):
    if not WINDOWS or sys.maxsize >= 2**32:
        return None

    report("Looking for 64-bit Python…")
    launcher = shutil.which("py.exe")
    if launcher:
        # Any installed 64-bit Python 3 is fine; try the generic selector first.
        for selector in ("-3-64", "-3.14", "-3.13", "-3.12"):
            try:
                probe = run_hidden([launcher, selector, "-c",
                                    "import sys; print(sys.executable) if sys.maxsize >= 2**32 else sys.exit(1)"],
                                   capture_output=True, text=True, timeout=20)
            except (OSError, subprocess.TimeoutExpired):
                continue
            if probe.returncode == 0 and probe.stdout.strip():
                candidate = Path(probe.stdout.strip()).with_name("pythonw.exe")
                if candidate.is_file():
                    return candidate

    local = Path(os.environ["LOCALAPPDATA"])
    target = local / "Programs" / "Python" / "Python314-Scan64"
    candidate = target / "pythonw.exe"
    if not candidate.is_file():
        architecture = os.environ.get("PROCESSOR_ARCHITEW6432", platform.machine()).lower()
        if architecture not in ("amd64", "x86_64", "arm64"):
            raise RuntimeError(f"{APP_NAME} needs 64-bit Windows for its scanner engine.")
        asset = "arm64" if architecture == "arm64" else "amd64"
        install_vendor(
            PYTHON_WIN_URL.format(arch=asset),
            "Python Software Foundation",
            ["/quiet", "InstallAllUsers=0", "Include_launcher=0", "Include_pip=1",
             "Include_tcltk=1", "Include_test=0", f"TargetDir={target}"],
            report, "64-bit Python",
        )
    if not candidate.is_file():
        raise RuntimeError("Python setup finished, but the 64-bit runtime was not found.")
    return candidate


def bootstrap(report):
    if not (WINDOWS or MAC or LINUX):
        raise RuntimeError("This app supports Windows, macOS and Linux.")
    if FROZEN:
        # The .exe / Linux binary already contains Python, PyQt6, PyMuPDF and python-docx.
        report("Checking NAPS2…")
        if not find_backend():
            install_naps(report)
        return False
    runtime = windows_python(report)
    if runtime is not None:
        return runtime
    report("Checking PyQt6, PyMuPDF and python-docx…")
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    probe = [sys.executable, "-c", "from PyQt6.QtWidgets import QApplication; import pymupdf, docx"]
    if run_hidden(probe, env=env, capture_output=True, timeout=30).returncode:
        if run_hidden([sys.executable, "-m", "pip", "--version"],
                      capture_output=True, timeout=30).returncode:
            run_hidden([sys.executable, "-m", "ensurepip"], check=True, timeout=180)
        command = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
                   "--no-input", "--only-binary=:all:", "--upgrade", "--target", str(QT_CACHE), *PIP_PACKAGES]
        wheels = offline_wheels()
        installed = False
        if wheels:
            report("Installing PyQt6, PyMuPDF and python-docx from the offline package…")
            installed = run_hidden(command[:4] + ["--no-index", "--find-links", str(wheels)] + command[4:],
                                   capture_output=True, timeout=300).returncode == 0
        if not installed:
            report("Installing PyQt6, PyMuPDF and python-docx (one time)…")
            run_hidden(command, check=True, timeout=300)
        if str(QT_CACHE) not in sys.path:
            sys.path.insert(0, str(QT_CACHE))
        env["PYTHONPATH"] = os.pathsep.join(sys.path)
        run_hidden(probe, env=env, check=True, timeout=30)
    report("Checking NAPS2…")
    if not find_backend():
        install_naps(report)
    # Updates are offered inside the app (Help > Check for updates), never forced here.
    return False


def setup_splash():
    try:
        import tkinter as tk
        from tkinter import ttk
        root = tk.Tk()
    except Exception as error:
        if not isinstance(error, ImportError) and error.__class__.__name__ != "TclError":
            raise
        try:
            return bootstrap(lambda value: print(value, file=sys.stderr))
        except Exception as exc:
            if WINDOWS:
                ctypes.windll.user32.MessageBoxW(None, str(exc), "Scanner setup", 0x10)
            else:
                print(f"Scanner setup: {exc}", file=sys.stderr)
            raise SystemExit(1)

    root.title(f"{APP_NAME} · Setup")
    root.configure(bg="#2e1065")
    width, height = 480, 240
    root.geometry(f"{width}x{height}+{(root.winfo_screenwidth()-width)//2}+{(root.winfo_screenheight()-height)//2}")
    root.resizable(False, False)
    root.protocol("WM_DELETE_WINDOW", lambda: None)
    logo = tk.Canvas(root, width=76, height=76, bg="#2e1065", highlightthickness=0)
    logo.pack(pady=(16, 2))
    logo.create_rectangle(4, 4, 72, 72, fill="#7e22ce", outline="")
    logo.create_rectangle(14, 32, 62, 44, fill="#1e0b36", outline="")
    logo.create_oval(23, 27, 36, 43, fill="white", outline="")
    logo.create_oval(39, 27, 52, 43, fill="white", outline="")
    logo.create_oval(27, 32, 33, 39, fill="#1e0b36", outline="")
    logo.create_oval(43, 32, 49, 39, fill="#1e0b36", outline="")
    logo.create_polygon(10, 30, 64, 20, 65, 26, 11, 36, fill="white", outline="")
    logo.create_rectangle(10, 42, 66, 62, fill="white", outline="")
    logo.create_oval(52, 48, 60, 56, fill="#22c55e", outline="")
    logo.create_text(20, 14, text="?!", fill="#fde047", font=("Segoe UI", 11, "bold"))
    tk.Label(root, text=APP_NAME, font=("Segoe UI", 22, "bold"),
             bg="#2e1065", fg="white").pack()
    status = tk.StringVar(value="Preparing scanner setup…")
    tk.Label(root, textvariable=status, font=("Segoe UI", 10), wraplength=435,
             bg="#2e1065", fg="#e9e2fb").pack(pady=8)
    progress = ttk.Progressbar(root, mode="indeterminate", length=405)
    progress.pack()
    progress.start()
    messages = Queue()
    updated = False
    failed = False

    def worker():
        try:
            messages.put(("done", bootstrap(lambda value: messages.put(("status", value)))))
        except Exception as exc:
            messages.put(("error", str(exc)))

    def poll():
        nonlocal updated, failed
        try:
            while True:
                kind, value = messages.get_nowait()
                if kind == "status":
                    status.set(value)
                elif kind == "done":
                    updated = value
                    root.destroy()
                    return
                else:
                    failed = True
                    progress.stop()
                    status.set(f"Setup could not finish. {value}")
                    ttk.Button(root, text="Close", command=root.destroy).pack()
                    root.protocol("WM_DELETE_WINDOW", root.destroy)
                    return
        except Empty:
            root.after(80, poll)

    threading.Thread(target=worker, daemon=True).start()
    root.after(80, poll)
    root.mainloop()
    if failed:
        raise SystemExit(1)
    return updated


if __name__ == "__main__":
    restart = setup_splash()
    if restart:
        executable = sys.executable if restart is True else str(restart)
        subprocess.Popen(
            [executable, str(Path(__file__).resolve()), *sys.argv[1:]],
            creationflags=HIDDEN, env=dict(os.environ, **{RESTART_ENV: "1"}),
        )
        raise SystemExit(0)


from string import Template

from PyQt6.QtCore import QPoint, QPointF, QProcess, QRect, QRectF, QSettings, QSize, QTimer, Qt, QUrl
from PyQt6.QtGui import (
    QBrush, QColor, QDesktopServices, QGuiApplication, QIcon, QImage, QKeySequence, QLinearGradient,
    QPainter, QPainterPath, QPalette, QPen, QPixmap, QRadialGradient, QShortcut,
)
from PyQt6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QFileDialog, QFormLayout, QFrame, QHBoxLayout,
    QListWidget, QListWidgetItem, QPlainTextEdit,
    QButtonGroup, QLabel, QLineEdit, QMenu, QMessageBox, QProgressBar, QPushButton, QRadioButton, QTabWidget,
    QVBoxLayout, QWidget, QToolButton, QScrollArea, QStackedWidget, QSizePolicy, QLayout,
)

LED_COLORS = {"ready": "#22c55e", "idle": "#f5b301", "busy": "#ef4444"}


class Led(QWidget):
    """Round status light: green = ready, yellow = idle, red = in use."""

    def __init__(self, size=18, parent=None):
        super().__init__(parent)
        self.state = "idle"
        self.setFixedSize(size, size)

    def set_state(self, state):
        if state != self.state:
            self.state = state
            self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(1.5, 1.5, self.width() - 3, self.height() - 3)
        base = QColor(LED_COLORS[self.state])
        glow = QRadialGradient(rect.center().x() - rect.width() * .18,
                               rect.center().y() - rect.height() * .22, rect.width() * .75)
        glow.setColorAt(0, base.lighter(165))
        glow.setColorAt(.55, base)
        glow.setColorAt(1, base.darker(135))
        painter.setBrush(QBrush(glow))
        painter.setPen(QPen(base.darker(160), 1.2))
        painter.drawEllipse(rect)


def draw_logo(size=256):
    """The app icon, drawn in code so the .pyw stays a single file.
    A surprised scanner peeking out from under its lid, with the green "ready" light."""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    p = QPainter(pixmap)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.scale(size / 256, size / 256)
    p.setPen(Qt.PenStyle.NoPen)
    tile = QLinearGradient(0, 0, 256, 256)
    tile.setColorAt(0, QColor("#a855f7"))
    tile.setColorAt(1, QColor("#3b0764"))
    p.setBrush(tile)
    p.drawRoundedRect(QRectF(8, 8, 240, 240), 54, 54)
    # "?!"
    font = p.font()
    font.setPixelSize(64)
    font.setBold(True)
    p.setFont(font)
    p.save()
    p.translate(76, 64)
    p.rotate(-12)
    p.setPen(QColor(0, 0, 0, 70))
    p.drawText(QRectF(-38, -42, 80, 80), Qt.AlignmentFlag.AlignCenter, "?!")
    p.setPen(QColor("#fde047"))
    p.drawText(QRectF(-41, -45, 80, 80), Qt.AlignmentFlag.AlignCenter, "?!")
    p.restore()
    p.setPen(Qt.PenStyle.NoPen)
    # dark gap under the lid, with a scan glow
    p.setBrush(QColor("#1e0b36"))
    p.drawRoundedRect(QRectF(44, 112, 168, 40), 12, 12)
    glow = QLinearGradient(0, 112, 0, 152)
    glow.setColorAt(0, QColor(127, 243, 255, 0))
    glow.setColorAt(1, QColor(127, 243, 255, 110))
    p.setBrush(glow)
    p.drawRoundedRect(QRectF(44, 112, 168, 40), 12, 12)
    # big cartoon eyes
    for x, pupil in ((80, 96), (134, 150)):
        p.setBrush(QColor("white"))
        p.drawEllipse(QRectF(x, 96, 44, 52))
        p.setBrush(QColor("#1e0b36"))
        p.drawEllipse(QRectF(pupil - 2, 112, 20, 24))
        p.setBrush(QColor("white"))
        p.drawEllipse(QRectF(pupil + 6, 116, 7, 7))
    # lid, popped open
    p.save()
    p.translate(126, 96)
    p.rotate(-11)
    lid = QLinearGradient(0, -14, 0, 12)
    lid.setColorAt(0, QColor("#ffffff"))
    lid.setColorAt(1, QColor("#ddd3f3"))
    p.setBrush(lid)
    p.drawRoundedRect(QRectF(-94, -14, 188, 24), 11, 11)
    p.restore()
    # scanner body
    body = QLinearGradient(0, 140, 0, 214)
    body.setColorAt(0, QColor("#ffffff"))
    body.setColorAt(1, QColor("#ddd3f3"))
    p.setBrush(body)
    p.drawRoundedRect(QRectF(34, 140, 188, 74), 20, 20)
    p.setBrush(QColor("#3b0764"))
    p.drawRoundedRect(QRectF(56, 184, 96, 9), 4.5, 4.5)
    # status light
    halo = QRadialGradient(192, 176, 26)
    halo.setColorAt(0, QColor(34, 197, 94, 150))
    halo.setColorAt(1, QColor(34, 197, 94, 0))
    p.setBrush(halo)
    p.drawEllipse(QRectF(166, 150, 52, 52))
    led = QRadialGradient(188, 172, 13)
    led.setColorAt(0, QColor("#b7f7cd"))
    led.setColorAt(1, QColor("#16a34a"))
    p.setBrush(led)
    p.drawEllipse(QRectF(180, 164, 24, 24))
    p.end()
    return pixmap


def app_icon():
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        icon.addPixmap(draw_logo(size))
    return icon


def decode(data):
    return bytes(data).decode("utf-8", errors="replace").strip()


def clean_old_previews():
    cutoff = time.time() - 3600
    try:
        for leftover in QT_CACHE.parent.glob("epson-preview-*.png"):
            try:
                if leftover.stat().st_mtime < cutoff:
                    leftover.unlink()
            except OSError:
                pass
    except OSError:
        pass


# ---------------------------------------------------------------- about / OTA
def about_html():
    greek = UI_LANG == "el"
    blurb = (f"Σάρωση σε PDF, JPG, Word και OpenDocument από σαρωτές {BRANDS}, με OCR, μετάφραση και φωτάκι που δείχνει "
             "πότε κάποιος άλλος στο δίκτυο χρησιμοποιεί τον σαρωτή.") if greek else (
             f"Scan to PDF, JPG, Word and OpenDocument from {BRANDS} scanners, with OCR, translation and a status light "
             "that shows when somebody else on the network is using the scanner.")
    maker = ("<b>Δημιουργός: Νικόλαος Κ. Παρίδης</b> (nikkpap)<br>ALU DEV TEAM · Πολιτικός μηχανικός &amp; "
             "developer εφαρμογών desktop και κινητού<br>Πτολεμαΐδα") if greek else (
             "<b>Made by Nikolaos K. Paridis</b> (nikkpap)<br>ALU DEV TEAM · Civil engineer &amp; developer of "
             "desktop and mobile tools<br>Ptolemaida, Greece")
    project = "Σελίδα &amp; ενημερώσεις" if greek else "Project page &amp; updates"
    more = "Περισσότερες εφαρμογές" if greek else "More apps"
    version = "Έκδοση" if greek else "Version"
    return f"""
<h2 style="margin-bottom:2px">{APP_NAME}</h2>
<p style="margin-top:0">{version} {VERSION} · {APP_TAGLINE}</p>
<p>{blurb}</p>
<p>{maker}</p>
<p>{project}: <a href="{REPO_URL}">{REPO_URL}</a><br>
{more}: <a href="{AUTHOR_URL}">{AUTHOR_URL}</a></p>
<p style="color:gray">NAPS2 (GPL) · Tesseract OCR · PyMuPDF · python-docx · PyQt6<br>
Google Translate · MyMemory · LibreTranslate</p>
"""


GUIDE_GR = """ΠΩΣ ΣΑΡΩΝΩ (3 βήματα)
  1. Άναψε τον σαρωτή και βάλε το χαρτί (στο τζάμι ή στον τροφοδότη).
  2. Έλεγξε ότι η πάνω κάρτα γράφει  ✓ Συνδέθηκε στο <σαρωτής σου>.
  3. Πάτα  Σάρωση.  Αποθηκεύει ως PDF, JPG ή PDF + JPG,
     όπως έχεις διαλέξει στις Ρυθμίσεις › Σάρωση › Αποθήκευση ως (PDF από προεπιλογή).
     Τσέκαρε εκεί «επεξεργάσιμο έγγραφο» και διάλεξε Word (.docx)
     ή OpenDocument (.odt, LibreOffice σε Mac / Linux).
     Τα αρχεία μπαίνουν αυτόματα στα Έγγραφα › What the Scan.

ΚΟΥΜΠΙΑ
  Προεπισκόπηση   γρήγορη ματιά στο τζάμι πριν τη σάρωση
  Κείμενο         το κείμενο που αναγνωρίστηκε (OCR), αντιγραφή και μετάφραση
  Άνοιγμα τελευταίου / Άνοιγμα φακέλου

Όλα είναι αυτόματα από προεπιλογή:
  • Η εφαρμογή βρίσκει μόνη της κάθε σαρωτή σε όλους τους drivers.
  • Πηγή χαρτιού «Αυτόματα»: τροφοδότης αν έχει χαρτί, αλλιώς τζάμι.
  • OCR: Αγγλικά + Ελληνικά + η γλώσσα του συστήματος. Οι γλώσσες κατεβαίνουν
    αυτόματα την πρώτη φορά.
  • Μετάφραση: Google Translate (δωρεάν), με εφεδρεία το MyMemory.

ΦΩΤΑΚΙ ΚΑΤΑΣΤΑΣΗΣ
  ● Πράσινο   Έτοιμο. Ο σαρωτής είναι ελεύθερος.
  ● Κίτρινο   Αναμονή. Αναζήτηση, κανένας σαρωτής ή ο σαρωτής σε αναμονή.
  ● Κόκκινο   Σε χρήση. Σαρώνεις εσύ ή κάποιος άλλος στο δίκτυο.
              Περίμενε να γίνει πράσινο. Η εφαρμογή κάνει ήχο όταν ελευθερωθεί.
  Τα άλλα PC το βλέπουν μόνο αν τρέχουν κι αυτά την εφαρμογή.
  Αν ρωτήσει το Τείχος προστασίας των Windows, επίτρεψέ την στα ιδιωτικά δίκτυα.

ΣΥΝΤΟΜΕΥΣΕΙΣ
  Ctrl+S σάρωση   Ctrl+P προεπισκόπηση   Ctrl+T κείμενο
  F5 νέα αναζήτηση   Ctrl+, ρυθμίσεις   F1 οδηγός   Esc ακύρωση

ΕΓΚΑΤΑΣΤΑΣΗ ΧΩΡΙΣ INTERNET
  Βάλε το WhatTheScan-offline.zip (από το release στο GitHub) δίπλα στην εφαρμογή.
  Το NAPS2, τα πακέτα Python, οι drivers και οι γλώσσες OCR εγκαθίστανται από
  εκεί, χωρίς internet. Χωρίς το zip όλα κατεβαίνουν όπως πάντα.

DRIVERS
  Epson: Epson Scan 2 (Windows: πρόσθεσε την IP στο Epson Scan 2 Utility).
  Canon: MP Drivers. Ρυθμίσεις › Σαρωτής › Εγκατάσταση driver για το TS3150.
  HP: HP Smart / HP Scan.  macOS: Image Capture.  Linux: SANE."""

UPDATE_HOSTS = ("github.com", "api.github.com", "objects.githubusercontent.com",
                "release-assets.githubusercontent.com", "github-releases.githubusercontent.com")


def version_tuple(text):
    numbers = [int(n) for n in re.findall(r"\d+", str(text))[:3]]
    return tuple(numbers + [0] * (3 - len(numbers))) if numbers else (0, 0, 0)


def _github_get(url, limit, accept="application/vnd.github+json"):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in UPDATE_HOSTS:
        raise ValueError("Updates must come from GitHub over HTTPS.")
    request = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": f"WhatTheScan/{VERSION}"})
    with urllib.request.urlopen(request, timeout=20) as response:
        final = urllib.parse.urlsplit(response.url)
        if final.scheme != "https" or final.hostname not in UPDATE_HOSTS:
            raise ValueError("The update download was redirected away from GitHub.")
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("The update file is unexpectedly large.")
    return data


def latest_release():
    """Return info about the newest GitHub release, or raise."""
    data = json.loads(_github_get(f"https://api.github.com/repos/{REPO}/releases/latest", 1_000_000))
    assets = {a.get("name", "").lower(): a for a in (data.get("assets") or [])}
    app = assets.get(RELEASE_ASSET.lower())
    if app is None and not FROZEN:
        app = next((a for n, a in assets.items() if n.endswith(".pyw")), None)
    checksum = assets.get(f"{RELEASE_ASSET.lower()}.sha256")
    return {
        "version": data.get("tag_name") or data.get("name") or "0",
        "notes": (data.get("body") or "").strip(),
        "page": data.get("html_url") or f"{REPO_URL}/releases",
        "asset": app,
        "checksum": checksum,
    }


def app_path():
    """The file to replace on update: the running .exe / binary, or this .pyw script."""
    return Path(sys.executable if FROZEN else __file__).resolve()


def clean_old_update():
    try:
        old = app_path().with_name(app_path().name + ".old")
        old.unlink(missing_ok=True)
    except OSError:
        pass


def install_release(info):
    """Download the release file for this platform, verify it, and replace the app. Returns the new path."""
    asset = info["asset"]
    if not asset:
        raise ValueError(f"This release has no {RELEASE_ASSET} file attached.")
    limit = 400 * 1024 * 1024 if FROZEN else 8 * 1024 * 1024
    payload = _github_get(asset["browser_download_url"], limit, "application/octet-stream")
    digest = hashlib.sha256(payload).hexdigest()
    expected = None
    if str(asset.get("digest", "")).startswith("sha256:"):
        expected = asset["digest"].split(":", 1)[1]
    elif info.get("checksum"):
        text = _github_get(info["checksum"]["browser_download_url"], 4096,
                           "application/octet-stream").decode("utf-8", "replace")
        expected = text.split()[0] if text.split() else None
    if expected and expected.lower() != digest:
        raise ValueError("The downloaded update failed its checksum. Nothing was changed.")
    if FROZEN:
        if WINDOWS and payload[:2] != b"MZ" or LINUX and payload[:4] != b"\x7fELF":
            raise ValueError("The downloaded file is not a program for this system. Nothing was changed.")
    else:
        compile(payload, "update.pyw", "exec")
        if b"APP_NAME" not in payload:
            raise ValueError("The downloaded file is not this app. Nothing was changed.")
    target = app_path()
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as staging:
        staged = Path(staging.name)
        staging.write(payload)
    try:
        if FROZEN:
            # A running program can't be overwritten on Windows, but it can be renamed out of the way.
            old = target.with_name(target.name + ".old")
            old.unlink(missing_ok=True)
            target.replace(old)
            staged.replace(target)
            if not WINDOWS:
                target.chmod(0o755)
        else:
            shutil.copy2(target, target.with_suffix(target.suffix + ".bak"))
            staged.replace(target)
    finally:
        staged.unlink(missing_ok=True)
    return target


# ---------------------------------------------------------------- PDF → JPG
def export_jpgs(pdf_path, base, dpi):
    """Write each page of the scanned PDF as a JPG. Keeps the scanner's own JPEG when possible."""
    import pymupdf as fitz  # PyMuPDF, installed by the launcher
    written = []
    with fitz.open(str(pdf_path)) as doc:
        count = len(doc)
        for number, page in enumerate(doc, start=1):
            target = base.with_suffix(".jpg") if count == 1 else base.with_name(f"{base.name}-p{number}.jpg")
            images = page.get_images(full=True)
            if len(images) == 1:
                info = doc.extract_image(images[0][0])
                if info and info.get("ext") in ("jpeg", "jpg"):
                    target.write_bytes(info["image"])
                    written.append(target)
                    continue
            pixmap = page.get_pixmap(dpi=int(dpi))
            image = QImage.fromData(pixmap.tobytes("png"), "PNG")
            if image.isNull() or not image.save(str(target), "JPG", 92):
                raise OSError(f"Could not write {target.name}.")
            written.append(target)
    return written


def unique_path(path):
    if not path.exists():
        return path
    for n in range(2, 1000):
        candidate = path.with_name(f"{path.stem} ({n}){path.suffix}")
        if not candidate.exists():
            return candidate
    return path


# ---------------------------------------------------------------- themes
THEMES = {
    "light": dict(
        bg="#f5f3fb", card="#ffffff", card2="#faf8ff", border="#e6e0f3", text="#1f1630", title="#24104f",
        muted="#6f6390", input="#fbfaff", input_border="#d9d0ee", hover="#f1ecfd", hover_border="#b9a6ec",
        focus="#8b5cf6", accent="#6d28d9", accent2="#a855f7", accent_hover="#5b21b6", accent_text="#6d28d9",
        dis_bg="#f0edf6", dis_fg="#a59cb8", dis_border="#e4def0", progress="#e9e2fa",
        chip_bg="#f0eafe", chip_fg="#4c1d95", nav_sel="#efe7ff",
        info_bg="#f0ecfc", info_border="#ddd3f6", info_fg="#2e1065",
        busy_bg="#fff8e6", busy_border="#f3d98f", busy_fg="#6b4e00",
        ok_bg="#e8f8f0", ok_border="#a6dfc4", ok_fg="#0b7a4b",
        error_bg="#fdeeee", error_border="#f2b7b7", error_fg="#a11d1d", tip_bg="#24104f",
    ),
    "dark": dict(
        bg="#121019", card="#1c1827", card2="#211c2e", border="#2c2640", text="#ece6fa", title="#f6f2ff",
        muted="#a397c2", input="#231e31", input_border="#3a3150", hover="#2a2340", hover_border="#6d5a99",
        focus="#a78bfa", accent="#7c3aed", accent2="#c026d3", accent_hover="#6d28d9", accent_text="#c4b5fd",
        dis_bg="#1a1623", dis_fg="#665c7d", dis_border="#262035", progress="#2a2340",
        chip_bg="#2a2240", chip_fg="#d9ccff", nav_sel="#2a2240",
        info_bg="#1f1a2d", info_border="#382f4f", info_fg="#d8cff0",
        busy_bg="#2e2610", busy_border="#5f501c", busy_fg="#f5d77a",
        ok_bg="#10251c", ok_border="#1f5a3f", ok_fg="#8ee0b5",
        error_bg="#311519", error_border="#73283a", error_fg="#ffb3b8", tip_bg="#3b2d5c",
    ),
}
THEME = dict(THEMES["light"])
STYLE_TEMPLATE = Template("""
    QWidget { background: $bg; color: $text; font: 10pt 'Segoe UI'; }
    QToolTip { background: $tip_bg; color: white; border: none; padding: 6px 8px; border-radius: 6px; }
    QLabel#title { font-size: 21pt; font-weight: 800; color: $title; }
    QLabel#subtitle { color: $muted; font-size: 9pt; letter-spacing: 0.5px; }
    QLabel#hint { color: $muted; font-size: 9pt; }
    QFrame#card, QFrame#hero, QFrame#section { background: $card; border: 1px solid $border; border-radius: 14px; }
    QFrame#card QLabel, QFrame#card QCheckBox, QFrame#card QRadioButton,
    QFrame#hero QLabel, QFrame#section QLabel, QFrame#section QCheckBox, QFrame#section QRadioButton,
    QFrame#section QWidget#plain, QFrame#hero QWidget#plain { background: transparent; }
    QFrame#accentStrip { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 $accent2, stop:1 $accent);
                         border: none; border-radius: 3px; }
    QLabel#cardTitle { font-size: 11.5pt; font-weight: 700; color: $title; }
    QLabel#sectionTitle { font-size: 10.5pt; font-weight: 700; color: $title; }
    QLabel#pageTitle { font-size: 17pt; font-weight: 800; color: $title; }
    QLabel#connTitle { font-size: 14pt; font-weight: 800; color: $title; }
    QLabel#connIcon { font-size: 20pt; font-weight: 800; border-radius: 24px;
                      min-width: 48px; max-width: 48px; min-height: 48px; max-height: 48px; }
    QFrame#hero QLabel#connIcon[kind="ok"] { background: $ok_bg; color: $ok_fg; }
    QFrame#hero QLabel#connIcon[kind="busy"] { background: $busy_bg; color: $busy_fg; }
    QFrame#hero QLabel#connIcon[kind="error"] { background: $error_bg; color: $error_fg; }
    QFrame#hero QLabel#chip, QLabel#chip { background: $chip_bg; color: $chip_fg; border: 1px solid $chip_bg; border-radius: 11px; padding: 3px 11px;
                  font-size: 9pt; font-weight: 600; }
    QFrame#ledBadge { background: $card; border: 1px solid $border; border-radius: 18px; }
    QFrame#ledBadge QLabel { background: transparent; }
    QLabel#ledText { font-weight: 700; }
    QPushButton, QComboBox, QLineEdit {
        background: $input; border: 1px solid $input_border; border-radius: 9px; padding: 7px 13px; color: $text;
    }
    QPushButton { font-weight: 600; }
    QPushButton::menu-indicator { width: 0px; }
    QPushButton:hover, QComboBox:hover { background: $hover; border-color: $hover_border; }
    QComboBox:focus, QPushButton:focus, QLineEdit:focus { border: 1px solid $focus; }
    QComboBox { padding-right: 34px; }
    QComboBox::drop-down { subcontrol-origin: padding; subcontrol-position: center right; width: 30px; border: none; }
    QComboBox::down-arrow { image: url($chevron); width: 12px; height: 12px; }
    QComboBox QAbstractItemView { background: $card; color: $text; border: 1px solid $border; padding: 4px;
                                  selection-background-color: $accent; selection-color: white; outline: none; }
    QPushButton#ghost { background: transparent; border: 1px solid transparent; }
    QPushButton#ghost:hover { background: $hover; border-color: $border; }
    QPushButton#scan, QPushButton#primary {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 $accent, stop:1 $accent2);
        color: white; font-weight: 800; border: none; border-radius: 12px; padding: 10px 20px;
    }
    QPushButton#scan { font-size: 13pt; }
    QPushButton#scan:hover, QPushButton#primary:hover {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 $accent_hover, stop:1 $accent);
    }
    QToolButton#tile { background: $card2; border: 1px solid $border; border-radius: 12px; padding: 8px 6px;
                       font-weight: 600; color: $text; }
    QToolButton#tile:hover { background: $hover; border-color: $hover_border; }
    QToolButton#tile:disabled { color: $dis_fg; background: $dis_bg; border-color: $dis_border; }
    QToolButton#cancelTile { background: $error_bg; border: 1px solid $error_border; border-radius: 12px;
                             padding: 8px 6px; font-weight: 700; color: $error_fg; }
    QPushButton:disabled, QPushButton#scan:disabled, QPushButton#primary:disabled,
    QComboBox:disabled, QLineEdit:disabled { background: $dis_bg; color: $dis_fg; border-color: $dis_border; }
    QProgressBar { border: none; border-radius: 2px; background: $progress; max-height: 4px; }
    QProgressBar::chunk { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 $accent, stop:1 $accent2);
                          border-radius: 2px; }
    QLabel#status { border-radius: 12px; padding: 11px 15px; background: $info_bg;
                    border: 1px solid $info_border; color: $info_fg; font-weight: 500; }
    QLabel#status[kind="busy"] { background: $busy_bg; border-color: $busy_border; color: $busy_fg; }
    QLabel#status[kind="ok"] { background: $ok_bg; border-color: $ok_border; color: $ok_fg; }
    QLabel#status[kind="error"] { background: $error_bg; border-color: $error_border; color: $error_fg; }
    QFrame#navPanel { background: $card; border: none; border-right: 1px solid $border; }
    QFrame#navPanel QLabel { background: transparent; }
    QListWidget#nav { background: transparent; border: none; outline: none; padding: 4px; }
    QListWidget#nav::item { padding: 10px 12px; margin: 2px 0; border-radius: 9px; color: $text; font-weight: 600; }
    QListWidget#nav::item:hover { background: $hover; }
    QListWidget#nav::item:selected { background: $nav_sel; color: $accent_text; }
    QScrollArea { border: none; background: transparent; }
    QWidget#page { background: $bg; }
    QPlainTextEdit, QListWidget { background: $input; border: 1px solid $input_border; border-radius: 10px;
                                  padding: 8px; color: $text; selection-background-color: $accent; }
    QListWidget::item { padding: 3px; }
    QCheckBox, QRadioButton { spacing: 9px; background: transparent; }
    QRadioButton::indicator { width: 14px; height: 14px; border-radius: 9px;
                              border: 2px solid $input_border; background: $input; }
    QRadioButton::indicator:hover, QCheckBox::indicator:hover { border-color: $focus; }
    QRadioButton::indicator:checked { border: 5px solid $accent; background: white; width: 8px; height: 8px; }
    QRadioButton:disabled, QCheckBox:disabled { color: $dis_fg; }
    QCheckBox::indicator { width: 16px; height: 16px; border-radius: 5px;
                           border: 2px solid $input_border; background: $input; }
    QCheckBox::indicator:checked { background: $accent; border-color: $accent; image: url($check); }
    QMenu { background: $card; border: 1px solid $border; padding: 5px; border-radius: 10px; }
    QMenu::item { padding: 8px 24px 8px 12px; border-radius: 6px; }
    QMenu::item:selected { background: $hover; color: $text; }
    QMenu::separator { height: 1px; background: $border; margin: 5px 8px; }
    QMessageBox QLabel { background: transparent; }
    QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
    QScrollBar::handle:vertical { background: $input_border; border-radius: 4px; min-height: 30px; }
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
""")


def draw_icon(name, color, size=24):
    """Small line icons drawn in code, so they look the same on Windows, macOS and Linux."""
    scale = 2
    pixmap = QPixmap(size * scale, size * scale)
    pixmap.fill(Qt.GlobalColor.transparent)
    p = QPainter(pixmap)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.scale(size * scale / 24, size * scale / 24)
    pen = QPen(QColor(color), 1.9)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    if name == "scan":
        p.drawRoundedRect(QRectF(7.5, 3, 9, 8), 1.2, 1.2)
        p.drawRoundedRect(QRectF(3, 11, 18, 9.5), 2.5, 2.5)
        p.drawLine(QPointF(1.8, 11), QPointF(22.2, 11))
        p.setBrush(QColor(color))
        p.drawEllipse(QPointF(17.2, 16), 1.2, 1.2)
    elif name == "eye":
        path = QPainterPath()
        path.moveTo(2, 12)
        path.quadTo(12, 3, 22, 12)
        path.quadTo(12, 21, 2, 12)
        p.drawPath(path)
        p.drawEllipse(QPointF(12, 12), 3.2, 3.2)
    elif name == "text":
        for y, width in ((5, 16), (9.7, 11), (14.3, 16), (19, 8)):
            p.drawLine(QPointF(4, y), QPointF(4 + width, y))
    elif name == "file":
        path = QPainterPath()
        path.moveTo(6, 2.8)
        path.lineTo(14, 2.8)
        path.lineTo(18.5, 7.3)
        path.lineTo(18.5, 21.2)
        path.lineTo(6, 21.2)
        path.closeSubpath()
        p.drawPath(path)
        p.drawPolyline([QPointF(14, 2.8), QPointF(14, 7.3), QPointF(18.5, 7.3)])
        p.drawLine(QPointF(9, 12.5), QPointF(15.5, 12.5))
        p.drawLine(QPointF(9, 16.5), QPointF(14, 16.5))
    elif name == "folder":
        path = QPainterPath()
        path.moveTo(2.8, 6.5)
        path.lineTo(9.5, 6.5)
        path.lineTo(11.5, 8.8)
        path.lineTo(21.2, 8.8)
        path.lineTo(21.2, 19.2)
        path.lineTo(2.8, 19.2)
        path.closeSubpath()
        p.drawPath(path)
    elif name == "cancel":
        p.drawLine(QPointF(6.5, 6.5), QPointF(17.5, 17.5))
        p.drawLine(QPointF(17.5, 6.5), QPointF(6.5, 17.5))
    elif name == "gear":
        p.drawEllipse(QPointF(12, 12), 3.2, 3.2)
        p.drawEllipse(QPointF(12, 12), 7, 7)
        import math
        for i in range(8):
            a = math.pi / 4 * i
            p.drawLine(QPointF(12 + 7 * math.cos(a), 12 + 7 * math.sin(a)),
                       QPointF(12 + 9.6 * math.cos(a), 12 + 9.6 * math.sin(a)))
    elif name == "help":
        p.drawEllipse(QPointF(12, 12), 9.2, 9.2)
        path = QPainterPath()
        path.moveTo(9.3, 9.6)
        path.cubicTo(9.3, 6.2, 14.9, 6.2, 14.9, 9.6)
        path.cubicTo(14.9, 11.8, 12, 11.8, 12, 14.2)
        p.drawPath(path)
        p.setBrush(QColor(color))
        p.drawEllipse(QPointF(12, 17.4), 1.1, 1.1)
    elif name == "refresh":
        p.drawArc(QRectF(4.5, 4.5, 15, 15), 40 * 16, 290 * 16)
        p.drawPolyline([QPointF(18.6, 3.6), QPointF(18.6, 8.2), QPointF(14, 8.2)])
    elif name == "translate":
        p.drawPolyline([QPointF(3, 5.5), QPointF(12, 5.5)])
        p.drawLine(QPointF(7.5, 3), QPointF(7.5, 5.5))
        p.drawPolyline([QPointF(10, 5.5), QPointF(8, 11), QPointF(4, 14.5)])
        p.drawLine(QPointF(6, 8.5), QPointF(11, 13.5))
        p.drawPolyline([QPointF(12.5, 21), QPointF(16.5, 11), QPointF(20.5, 21)])
        p.drawLine(QPointF(14, 17.5), QPointF(19, 17.5))
    elif name == "copy":
        p.drawRoundedRect(QRectF(8.5, 8.5, 12, 12.5), 2, 2)
        p.drawPolyline([QPointF(15.5, 5.5), QPointF(15.5, 3.5), QPointF(3.5, 3.5), QPointF(3.5, 16), QPointF(5.5, 16)])
    elif name == "save":
        p.drawLine(QPointF(12, 3.5), QPointF(12, 14.5))
        p.drawPolyline([QPointF(7.5, 10.5), QPointF(12, 15), QPointF(16.5, 10.5)])
        p.drawPolyline([QPointF(3.5, 15.5), QPointF(3.5, 20.5), QPointF(20.5, 20.5), QPointF(20.5, 15.5)])
    elif name == "chevron":
        pen.setWidthF(2.4)
        p.setPen(pen)
        p.drawPolyline([QPointF(5, 9), QPointF(12, 16), QPointF(19, 9)])
    elif name == "check":
        pen.setWidthF(3.2)
        p.setPen(pen)
        p.drawPolyline([QPointF(5, 12.5), QPointF(10, 17.5), QPointF(19.5, 6.5)])
    p.end()
    pixmap.setDevicePixelRatio(scale)
    return pixmap


def icon(name, color_key="text", color=None):
    return QIcon(draw_icon(name, color or THEME[color_key]))


class FlowLayout(QLayout):
    """Lays widgets out left to right and wraps to the next line (used for the setting chips)."""

    def __init__(self, parent=None, spacing=6):
        super().__init__(parent)
        self.items = []
        self.setSpacing(spacing)
        self.setContentsMargins(0, 0, 0, 0)

    def addItem(self, item):
        self.items.append(item)

    def count(self):
        return len(self.items)

    def itemAt(self, index):
        return self.items[index] if 0 <= index < len(self.items) else None

    def takeAt(self, index):
        return self.items.pop(index) if 0 <= index < len(self.items) else None

    def expandingDirections(self):
        return Qt.Orientation(0)

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, width):
        return self.arrange(QRect(0, 0, width, 0), True)

    def setGeometry(self, rect):
        super().setGeometry(rect)
        self.arrange(rect, False)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        size = QSize()
        for item in self.items:
            size = size.expandedTo(item.minimumSize())
        return size

    def arrange(self, rect, test):
        x, y, line = rect.x(), rect.y(), 0
        for item in self.items:
            if item.widget() and not item.widget().isVisible() and not test:
                item.setGeometry(QRect())
                continue
            if item.widget() and item.widget().isHidden():
                continue
            hint = item.sizeHint()
            if x + hint.width() > rect.right() and line:
                x = rect.x()
                y += line + self.spacing()
                line = 0
            if not test:
                item.setGeometry(QRect(QPoint(x, y), hint))
            x += hint.width() + self.spacing()
            line = max(line, hint.height())
        return y + line - rect.y()


def system_prefers_dark():
    hints = QGuiApplication.styleHints()
    scheme = getattr(hints, "colorScheme", None)
    if scheme is not None:
        return scheme() == Qt.ColorScheme.Dark
    return QGuiApplication.palette().color(QPalette.ColorRole.Window).lightness() < 128


THEME_LISTENERS = []


def apply_theme(mode):
    """mode: auto | light | dark. Returns the theme actually used."""
    resolved = ("dark" if system_prefers_dark() else "light") if mode == "auto" else mode
    colors = dict(THEMES.get(resolved, THEMES["light"]))
    THEME.clear()
    THEME.update(colors)
    folder = QT_CACHE.parent / "ui"
    paths = {}
    try:
        folder.mkdir(parents=True, exist_ok=True)
        for name, color in (("chevron", colors["muted"]), ("check", "#ffffff")):
            path = folder / f"{name}-{resolved}.png"
            draw_icon(name, color, 16).save(str(path))
            paths[name] = path.as_posix()
    except OSError:
        pass
    colors["chevron"] = paths.get("chevron", "")
    colors["check"] = paths.get("check", "")
    app = QApplication.instance()
    palette = QPalette()
    for role, key in ((QPalette.ColorRole.Window, "bg"), (QPalette.ColorRole.Base, "input"),
                      (QPalette.ColorRole.AlternateBase, "card"), (QPalette.ColorRole.Button, "input"),
                      (QPalette.ColorRole.WindowText, "text"), (QPalette.ColorRole.Text, "text"),
                      (QPalette.ColorRole.ButtonText, "text"), (QPalette.ColorRole.ToolTipBase, "tip_bg"),
                      (QPalette.ColorRole.Highlight, "accent"), (QPalette.ColorRole.Link, "accent_text"),
                      (QPalette.ColorRole.PlaceholderText, "muted")):
        palette.setColor(role, QColor(colors[key]))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("white"))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor("white"))
    app.setPalette(palette)
    app.setStyleSheet(STYLE_TEMPLATE.substitute(colors))
    for listener in list(THEME_LISTENERS):
        listener()
    return resolved


# ---------------------------------------------------------------- language (EN / GR)
UI_LANG = "en"

GR = {
    "Also save an editable document (text from OCR)":
        "Αποθήκευση και ως επεξεργάσιμο έγγραφο (κείμενο από OCR)",
    "Document": "Έγγραφο",
    "Word (.docx) · Microsoft Word": "Word (.docx) · Microsoft Word",
    "OpenDocument (.odt) · LibreOffice on Mac / Linux": "OpenDocument (.odt) · LibreOffice σε Mac / Linux",
    "Word export needs python-docx. Close and reopen the app to install it.":
        "Για Word χρειάζεται το python-docx. Κλείσε και ξανάνοιξε την εφαρμογή για να εγκατασταθεί.",
    "What to save, the paper and where the files go.": "Τι αποθηκεύεται, το χαρτί και πού πάνε τα αρχεία.",
    "Recognise text in your scans and translate it.": "Αναγνώριση κειμένου στις σαρώσεις και μετάφρασή του.",
    "Language, appearance and updates.": "Γλώσσα, εμφάνιση και ενημερώσεις.",
    "Output": "Αρχεία εξόδου", "Paper": "Χαρτί", "Saving": "Αποθήκευση",
    "Text recognition (OCR)": "Αναγνώριση κειμένου (OCR)", "Appearance": "Εμφάνιση", "Reset": "Επαναφορά",
    # main screen
    "Settings": "Ρυθμίσεις", "Help": "Βοήθεια", "Ready": "Έτοιμο", "Idle": "Αναμονή",
    "Scan": "Σάρωση", "Preview": "Προεπισκόπηση", "Text": "Κείμενο", "Open last": "Τελευταίο",
    "Open folder": "Φάκελος", "Cancel": "Ακύρωση", "Stop search": "Διακοπή αναζήτησης",
    "Search again": "Αναζήτηση ξανά", "Change…": "Αλλαγή…", "Starting…": "Εκκίνηση…",
    "Looking for scanners…": "Αναζήτηση σαρωτών…",
    "Checking every driver at the same time.": "Έλεγχος όλων των drivers ταυτόχρονα.",
    "Connected to {name}": "Συνδέθηκε στο {name}",
    "via {driver}": "μέσω {driver}",
    "{brand} at {ip}": "{brand} στο {ip}",
    "{count} more in Settings": "{count} ακόμη στις Ρυθμίσεις",
    "No scanner connected": "Δεν συνδέθηκε σαρωτής",
    "Turn the scanner on, check the USB cable or Wi-Fi, then click Search again.":
        "Άναψε τον σαρωτή, έλεγξε το καλώδιο USB ή το Wi-Fi και πάτα «Αναζήτηση ξανά».",
    "saves to {folder}": "αποθήκευση στο {folder}", "asks for a file name": "ρωτάει όνομα αρχείου",
    "OCR": "OCR", "OCR off": "Χωρίς OCR", "translate → {lang}": "μετάφραση → {lang}",
    "Scan and save in the format chosen in Settings (Ctrl+S)":
        "Σάρωση και αποθήκευση στη μορφή που διάλεξες στις Ρυθμίσεις (Ctrl+S)",
    "Quick low-resolution look at the flatbed (Ctrl+P)": "Γρήγορη προεπισκόπηση από το τζάμι (Ctrl+P)",
    "Recognised text and translation of the last scan (Ctrl+T)":
        "Αναγνωρισμένο κείμενο και μετάφραση της τελευταίας σάρωσης (Ctrl+T)",
    "Open the last scanned file": "Άνοιγμα του τελευταίου αρχείου",
    "Open the folder with your scans": "Άνοιγμα του φακέλου με τις σαρώσεις",
    "Stop the scan or search (Esc)": "Διακοπή σάρωσης ή αναζήτησης (Esc)",
    "Look for scanners again (F5)": "Νέα αναζήτηση σαρωτών (F5)",
    "Choose another scanner or change scan settings": "Άλλος σαρωτής ή αλλαγή ρυθμίσεων σάρωσης",
    "Scanner, scanning, text and appearance settings (Ctrl+,)":
        "Ρυθμίσεις σαρωτή, σάρωσης, κειμένου και εμφάνισης (Ctrl+,)",
    "Quick guide": "Γρήγορος οδηγός", "Check for updates…": "Έλεγχος για ενημερώσεις…",
    "Project page on GitHub": "Σελίδα του έργου στο GitHub", "About {app}": "Σχετικά με το {app}",
    "Update to {version}…": "Ενημέρωση σε {version}…",
    # LED
    "In use · scanning on this PC": "Σε χρήση · σάρωση σε αυτό το PC",
    "In use by {who}": "Σε χρήση από {who}", "{user} on {host}": "{user} στο {host}",
    "Started at {time}. Wait until the light turns green.": "Ξεκίνησε στις {time}. Περίμενε να γίνει πράσινο.",
    "In use · scanner is busy": "Σε χρήση · ο σαρωτής είναι απασχολημένος",
    "The scanner reports that it is scanning right now.": "Ο σαρωτής δηλώνει ότι σαρώνει αυτή τη στιγμή.",
    "Idle · searching…": "Αναμονή · αναζήτηση…", "Idle · no scanner": "Αναμονή · χωρίς σαρωτή",
    "No scanner is connected yet.": "Δεν έχει συνδεθεί ακόμη σαρωτής.",
    "Idle · scanner on standby": "Αναμονή · ο σαρωτής σε αναμονή",
    "The scanner reports that it is stopped or offline.": "Ο σαρωτής δηλώνει ότι είναι σταματημένος ή εκτός σύνδεσης.",
    "The scanner is free. You can scan.": "Ο σαρωτής είναι ελεύθερος. Μπορείς να σαρώσεις.",
    "Idle · installing OCR…": "Αναμονή · εγκατάσταση OCR…",
    "The scanner is free now. You can scan.": "Ο σαρωτής είναι πλέον ελεύθερος. Μπορείς να σαρώσεις.",
    "Scanner in use": "Ο σαρωτής είναι σε χρήση",
    "The scanner is in use right now.\n\n{text}.\n{tip}\n\nPlease wait until the light at the top turns green, then try again.\nThis app will beep when the scanner is free.":
        "Ο σαρωτής χρησιμοποιείται αυτή τη στιγμή.\n\n{text}.\n{tip}\n\nΠερίμενε να γίνει πράσινο το φωτάκι επάνω και δοκίμασε ξανά.\nΗ εφαρμογή θα κάνει ήχο μόλις ελευθερωθεί ο σαρωτής.",
    "Scanner in use: {text}. Wait for the green light.": "Ο σαρωτής είναι σε χρήση: {text}. Περίμενε το πράσινο φως.",
    # settings
    "Scanner": "Σαρωτής", "Scanning": "Σάρωση", "Text & translation": "Κείμενο & μετάφραση", "General": "Γενικά",
    "Done": "Τέλος", "Driver": "Driver", "Model": "Μοντέλο", "Network": "Δίκτυο",
    "Auto (all drivers)": "Αυτόματα (όλοι οι drivers)", "No scanner found yet": "Δεν βρέθηκε ακόμη σαρωτής",
    "Refresh": "Ανανέωση", "Driver setup": "Εγκατάσταση driver", "Find on network": "Εύρεση στο δίκτυο",
    "Web panel": "Σελίδα σαρωτή", "Find your model’s driver": "Βρες τον driver του μοντέλου σου",
    "No Epson or Canon network reply yet": "Καμία απάντηση Epson ή Canon στο δίκτυο ακόμη",
    "Everything here is found automatically. Change it only if the wrong scanner is chosen.":
        "Όλα εδώ βρίσκονται αυτόματα. Άλλαξέ τα μόνο αν επιλέχθηκε λάθος σαρωτής.",
    "Save as": "Αποθήκευση ως", "one PDF with every page": "ένα PDF με όλες τις σελίδες",
    "one JPG image per page": "μία εικόνα JPG ανά σελίδα",
    "the PDF and the JPG images from one scan": "το PDF και οι εικόνες JPG από μία σάρωση",
    "Paper source": "Πηγή χαρτιού", "Auto · feeder if loaded, else flatbed": "Αυτόματα · τροφοδότης αν έχει χαρτί, αλλιώς τζάμι",
    "Flatbed (glass)": "Τζάμι (flatbed)", "Document feeder": "Τροφοδότης εγγράφων",
    "Document feeder · both sides": "Τροφοδότης · διπλής όψης", "Paper size": "Μέγεθος χαρτιού",
    "Resolution": "Ανάλυση", "150 dpi · fast, small file": "150 dpi · γρήγορο, μικρό αρχείο",
    "300 dpi · recommended": "300 dpi · προτείνεται", "600 dpi · fine detail": "600 dpi · μεγάλη λεπτομέρεια",
    "Colour": "Χρώμα", "Greyscale": "Αποχρώσεις του γκρι", "Black and white": "Ασπρόμαυρο",
    "Save to": "Αποθήκευση σε", "Browse…": "Αναζήτηση…", "Ask for a file name every time": "Να ρωτάει όνομα αρχείου κάθε φορά",
    "Open the file after scanning": "Άνοιγμα του αρχείου μετά τη σάρωση",
    "Auto source": "Αυτόματη πηγή", "Flatbed": "Τζάμι", "Feeder": "Τροφοδότης", "Feeder · 2 sides": "Τροφοδότης · 2 όψεις",
    "Make PDFs searchable with OCR (text recognition)": "Αναζητήσιμα PDF με OCR (αναγνώριση κειμένου)",
    "OCR languages": "Γλώσσες OCR",
    "Auto · English + Greek + your system language": "Αυτόματα · Αγγλικά + Ελληνικά + γλώσσα συστήματος",
    "Choose languages": "Επιλογή γλωσσών",
    "Languages download automatically the first time they are used.":
        "Οι γλώσσες κατεβαίνουν αυτόματα την πρώτη φορά που χρησιμοποιούνται.",
    "Also save the text as a .txt file": "Αποθήκευση του κειμένου και ως αρχείο .txt",
    "Translate automatically to": "Αυτόματη μετάφραση σε", "Off": "Όχι",
    "Translation service": "Υπηρεσία μετάφρασης",
    "Google Translate (free)": "Google Translate (δωρεάν)", "MyMemory (free)": "MyMemory (δωρεάν)",
    "LibreTranslate (your server)": "LibreTranslate (δικός σου server)",
    "LibreTranslate server": "Server LibreTranslate", "API key (optional)": "Κλειδί API (προαιρετικό)",
    "Free services need internet. Google falls back to MyMemory if it fails.":
        "Οι δωρεάν υπηρεσίες χρειάζονται internet. Αν αποτύχει το Google, χρησιμοποιείται το MyMemory.",
    "Theme": "Θέμα", "Auto · follow Windows / system": "Αυτόματα · όπως τα Windows / το σύστημα",
    "Light": "Ανοιχτό", "Dark": "Σκούρο", "Language": "Γλώσσα",
    "Auto · system language": "Αυτόματα · γλώσσα συστήματος",
    "Updates": "Ενημερώσεις", "Check for updates automatically": "Αυτόματος έλεγχος για ενημερώσεις",
    "Check now": "Έλεγχος τώρα", "Reset everything to Auto": "Επαναφορά όλων σε Αυτόματα",
    "All settings are back to Auto.": "Όλες οι ρυθμίσεις επανήλθαν σε Αυτόματα.",
    "Restart to change the language?": "Επανεκκίνηση για αλλαγή γλώσσας;",
    "The new language is used after a restart. Restart now?":
        "Η νέα γλώσσα εφαρμόζεται μετά από επανεκκίνηση. Επανεκκίνηση τώρα;",
    "Save scans to": "Αποθήκευση σαρώσεων σε",
    # text dialog
    "Recognised text": "Αναγνωρισμένο κείμενο", "Translation": "Μετάφραση", "Translate": "Μετάφραση",
    "From": "Από", "To": "Σε", "Auto-detect": "Αυτόματη ανίχνευση", "Copy": "Αντιγραφή",
    "Save .txt": "Αποθήκευση .txt", "Close": "Κλείσιμο", "Copied.": "Αντιγράφηκε.",
    "Detected language: {lang}": "Ανιχνεύθηκε γλώσσα: {lang}",
    "Translating with {engine}…": "Μετάφραση με {engine}…",
    "Translated with {engine}. Detected: {lang}.": "Μεταφράστηκε με {engine}. Ανιχνεύθηκε: {lang}.",
    "Translation failed. {error}": "Η μετάφραση απέτυχε. {error}",
    "Saved {name}": "Αποθηκεύτηκε {name}",
    "No text yet. Turn on OCR in Settings › Text & translation, then scan again.":
        "Δεν υπάρχει κείμενο ακόμη. Ενεργοποίησε το OCR στις Ρυθμίσεις › Κείμενο & μετάφραση και σάρωσε ξανά.",
    "Text of {name}": "Κείμενο του {name}",
    # status messages
    "Looking for scanners ({drivers})…": "Αναζήτηση σαρωτών ({drivers})…",
    "Looking for scanners… {count} found so far.": "Αναζήτηση σαρωτών… βρέθηκαν {count} μέχρι τώρα.",
    "Ready. Load the paper and click Scan.": "Έτοιμο. Βάλε το χαρτί και πάτα Σάρωση.",
    "Search stopped. Click Search again when you are ready.": "Η αναζήτηση σταμάτησε. Πάτα «Αναζήτηση ξανά» όταν είσαι έτοιμος.",
    "No scanners found. Check the cable or Wi-Fi and the installed driver (Settings › Scanner › Driver setup).":
        "Δεν βρέθηκαν σαρωτές. Έλεγξε το καλώδιο ή το Wi-Fi και τον driver (Ρυθμίσεις › Σαρωτής › Εγκατάσταση driver).",
    "The NAPS2 scanner engine was not found. Close and reopen the app to install it automatically.":
        "Δεν βρέθηκε η μηχανή σάρωσης NAPS2. Κλείσε και ξανάνοιξε την εφαρμογή για να εγκατασταθεί αυτόματα.",
    "Scanning a quick low-resolution preview…": "Γρήγορη σάρωση προεπισκόπησης…",
    "Check the page placement, then scan at your chosen resolution.":
        "Έλεγξε τη θέση της σελίδας και μετά σάρωσε στην ανάλυση που διάλεξες.",
    "Flatbed preview": "Προεπισκόπηση από το τζάμι", "Back": "Πίσω", "Preview ready.": "Η προεπισκόπηση είναι έτοιμη.",
    "No preview was produced. Check the flatbed and scanner connection.":
        "Δεν δημιουργήθηκε προεπισκόπηση. Έλεγξε το τζάμι και τη σύνδεση του σαρωτή.",
    "Scanning from {where}… Keep the scanner on until the file is saved.":
        "Σάρωση από {where}… Κράτα τον σαρωτή ανοιχτό μέχρι να αποθηκευτεί το αρχείο.",
    "the flatbed": "το τζάμι", "the document feeder": "τον τροφοδότη",
    "the document feeder (both sides)": "τον τροφοδότη (διπλής όψης)",
    " Recognising text (OCR)…": " Αναγνώριση κειμένου (OCR)…",
    "Downloading OCR languages ({langs}). One time only…": "Λήψη γλωσσών OCR ({langs}). Μόνο την πρώτη φορά…",
    "OCR languages could not be installed ({langs}). Scanning without OCR.":
        "Δεν ήταν δυνατή η εγκατάσταση γλωσσών OCR ({langs}). Σάρωση χωρίς OCR.",
    "Scan cancelled.": "Η σάρωση ακυρώθηκε.",
    "The scanner is busy. Someone else may be using it. Wait a moment, then try again.":
        "Ο σαρωτής είναι απασχολημένος. Ίσως τον χρησιμοποιεί κάποιος άλλος. Περίμενε λίγο και δοκίμασε ξανά.",
    "Windows could not reach the Canon scanner. Turn it on, make sure it is on the same Wi-Fi, and check it in Canon IJ Scan Utility, then retry.":
        "Τα Windows δεν βρίσκουν τον σαρωτή Canon. Άναψέ τον, βεβαιώσου ότι είναι στο ίδιο Wi-Fi και έλεγξέ τον στο Canon IJ Scan Utility.",
    "Epson Scan 2 could not open the scanner. In Epson Scan 2 Utility, add or test its network address, then retry.":
        "Το Epson Scan 2 δεν άνοιξε τον σαρωτή. Στο Epson Scan 2 Utility πρόσθεσε ή δοκίμασε τη διεύθυνση δικτύου του.",
    "Scanner operation failed. {detail}": "Η σάρωση απέτυχε. {detail}",
    "No pages were scanned. Check the paper and the scanner connection.":
        "Δεν σαρώθηκαν σελίδες. Έλεγξε το χαρτί και τη σύνδεση του σαρωτή.",
    "Could not save the scan. {error}": "Δεν ήταν δυνατή η αποθήκευση. {error}",
    "The scan was kept as {path}": "Η σάρωση κρατήθηκε ως {path}",
    "✓ Saved {files} in {folder}": "✓ Αποθηκεύτηκε {files} στο {folder}",
    "{count} JPG pages": "{count} σελίδες JPG", "text": "κείμενο",
    "Translating the text to {lang}…": "Μετάφραση του κειμένου σε {lang}…",
    "✓ Translation saved: {name}": "✓ Η μετάφραση αποθηκεύτηκε: {name}",
    "Could not start NAPS2. {error}": "Δεν ξεκίνησε το NAPS2. {error}",
    "Could not create {folder}. {error}\nChoose another folder in Settings › Scanning.":
        "Δεν δημιουργήθηκε ο φάκελος {folder}. {error}\nΔιάλεξε άλλον φάκελο στις Ρυθμίσεις › Σάρωση.",
    "Save scan": "Αποθήκευση σάρωσης",
    "Scan in progress": "Σάρωση σε εξέλιξη",
    "A scan is running. Cancel it and close the app?": "Γίνεται σάρωση. Ακύρωση και κλείσιμο της εφαρμογής;",
    "JPG export needs PyMuPDF. Close and reopen the app to install it.":
        "Για JPG χρειάζεται το PyMuPDF. Κλείσε και ξανάνοιξε την εφαρμογή για να εγκατασταθεί.",
    # updates / drivers / network
    "Checking GitHub for a newer version…": "Έλεγχος στο GitHub για νεότερη έκδοση…",
    "Could not check for updates. {error}": "Δεν έγινε έλεγχος ενημερώσεων. {error}",
    "You have the latest version (v{version}).": "Έχεις την τελευταία έκδοση (v{version}).",
    "Update available": "Υπάρχει ενημέρωση",
    "{app} {version} is available (you have v{current}).\n\nWhat's new:\n{notes}\n\nDownload and install it now?":
        "Το {app} {version} είναι διαθέσιμο (έχεις v{current}).\n\nΤι νέο έχει:\n{notes}\n\nΛήψη και εγκατάσταση τώρα;",
    "No release notes.": "Χωρίς σημειώσεις έκδοσης.",
    "Update {version} is waiting in Help.": "Η ενημέρωση {version} περιμένει στη Βοήθεια.",
    "Finish the scan first, then install the update from Help.": "Τελείωσε πρώτα τη σάρωση και μετά εγκατάστησε την ενημέρωση από τη Βοήθεια.",
    "Downloading {version} from GitHub…": "Λήψη {version} από το GitHub…",
    "Update failed. {error}": "Η ενημέρωση απέτυχε. {error}", "Update failed": "Η ενημέρωση απέτυχε",
    "{error}\n\nOpen the release page to download it by hand?": "{error}\n\nΆνοιγμα της σελίδας για χειροκίνητη λήψη;",
    "Updated to {version}. Restarting…": "Ενημερώθηκε σε {version}. Επανεκκίνηση…",
    "Choose a model to find its driver.": "Διάλεξε μοντέλο για να βρεθεί ο driver του.",
    "Install driver": "Εγκατάσταση driver",
    "Download and install the official {label} now?\n\nWindows may ask for permission. Choose No to open the support page instead.":
        "Λήψη και εγκατάσταση του επίσημου {label} τώρα;\n\nΤα Windows ίσως ζητήσουν άδεια. Πάτα Όχι για να ανοίξει η σελίδα υποστήριξης.",
    "Preparing the official {label} installer…": "Προετοιμασία του επίσημου {label}…",
    "{label} installed. Looking for scanners…": "Εγκαταστάθηκε το {label}. Αναζήτηση σαρωτών…",
    "Driver setup failed. {error}\nThe support page is opening so you can install it by hand.":
        "Η εγκατάσταση του driver απέτυχε. {error}\nΑνοίγει η σελίδα υποστήριξης για χειροκίνητη εγκατάσταση.",
    "Searching the local network for Epson and Canon devices…": "Αναζήτηση συσκευών Epson και Canon στο τοπικό δίκτυο…",
    "Network discovery failed. {error}": "Η αναζήτηση στο δίκτυο απέτυχε. {error}",
    "Select your scanner's network address.": "Διάλεξε τη διεύθυνση δικτύου του σαρωτή σου.",
    "No Epson or Canon device replied on this local network.": "Καμία συσκευή Epson ή Canon δεν απάντησε σε αυτό το δίκτυο.",
    "answered as a Canon scanner ✓": "απάντησε ως σαρωτής Canon ✓",
    "responds on the scanner port ✓": "απαντά στη θύρα σαρωτή ✓",
    "did not respond on the scanner port": "δεν απάντησε στη θύρα σαρωτή",
    "{brand} {ip} {state}. Scanning uses the driver chosen above.":
        "{brand} {ip} {state}. Η σάρωση χρησιμοποιεί τον driver που επιλέχθηκε επάνω.",
}

LANG_NAMES = {  # code: (English, Greek, tesseract code)
    "el": ("Greek", "Ελληνικά", "ell"), "en": ("English", "Αγγλικά", "eng"),
    "de": ("German", "Γερμανικά", "deu"), "fr": ("French", "Γαλλικά", "fra"),
    "it": ("Italian", "Ιταλικά", "ita"), "es": ("Spanish", "Ισπανικά", "spa"),
    "pt": ("Portuguese", "Πορτογαλικά", "por"), "nl": ("Dutch", "Ολλανδικά", "nld"),
    "ru": ("Russian", "Ρωσικά", "rus"), "uk": ("Ukrainian", "Ουκρανικά", "ukr"),
    "bg": ("Bulgarian", "Βουλγαρικά", "bul"), "ro": ("Romanian", "Ρουμανικά", "ron"),
    "sq": ("Albanian", "Αλβανικά", "sqi"), "sr": ("Serbian", "Σερβικά", "srp"),
    "tr": ("Turkish", "Τουρκικά", "tur"), "pl": ("Polish", "Πολωνικά", "pol"),
    "ar": ("Arabic", "Αραβικά", "ara"), "zh-CN": ("Chinese", "Κινεζικά", "chi_sim"),
}


def tr(message, /, **values):
    result = GR.get(message, message) if UI_LANG == "el" else message
    return result.format(**values) if values else result


def lang_name(code):
    names = LANG_NAMES.get(code)
    if not names:
        return code or "?"
    return names[1] if UI_LANG == "el" else names[0]


def system_language():
    from PyQt6.QtCore import QLocale
    return QLocale.system().name().split("_")[0].lower()


def resolve_ui_language(setting):
    if setting in ("en", "el"):
        return setting
    return "el" if system_language() == "el" else "en"


# ---------------------------------------------------------------- text & translation
def guess_language(text):
    """Cheap offline guess from the alphabet used: el, ru/bg (Cyrillic), ar, zh-CN or en."""
    counts = {"el": 0, "cyr": 0, "ar": 0, "zh": 0, "lat": 0}
    for ch in text[:4000]:
        o = ord(ch)
        if 0x370 <= o <= 0x3FF or 0x1F00 <= o <= 0x1FFF:
            counts["el"] += 1
        elif 0x400 <= o <= 0x4FF:
            counts["cyr"] += 1
        elif 0x600 <= o <= 0x6FF:
            counts["ar"] += 1
        elif 0x4E00 <= o <= 0x9FFF:
            counts["zh"] += 1
        elif ch.isalpha():
            counts["lat"] += 1
    best = max(counts, key=counts.get)
    if not counts[best]:
        return ""
    return {"el": "el", "cyr": "ru", "ar": "ar", "zh": "zh-CN", "lat": "en"}[best]


def _chunks(text, limit):
    parts, current = [], ""
    for paragraph in text.replace("\r", "").split("\n"):
        while len(paragraph) > limit:
            cut = paragraph.rfind(" ", 0, limit)
            cut = cut if cut > limit // 2 else limit
            parts.append((current + "\n" if current else "") + paragraph[:cut]) if not current else None
            if current:
                parts.append(current)
                current = ""
                continue
            paragraph = paragraph[cut:].lstrip()
        candidate = f"{current}\n{paragraph}" if current else paragraph
        if len(candidate) > limit and current:
            parts.append(current)
            current = paragraph
        else:
            current = candidate
    if current:
        parts.append(current)
    return parts or [""]


def _web(url, data=None, headers=None, timeout=25):
    request = urllib.request.Request(url, data=data, headers={"User-Agent": "Mozilla/5.0 WhatTheScan", **(headers or {})})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read(4_000_000).decode("utf-8", "replace")


def translate_google(text, target, source="auto"):
    out, detected = [], source
    for chunk in _chunks(text, 4000):
        if not chunk.strip():
            out.append(chunk)
            continue
        query = urllib.parse.urlencode({"client": "gtx", "sl": source, "tl": target, "dt": "t"})
        data = json.loads(_web(f"https://translate.googleapis.com/translate_a/single?{query}",
                               urllib.parse.urlencode({"q": chunk}).encode(),
                               {"Content-Type": "application/x-www-form-urlencoded;charset=utf-8"}))
        out.append("".join(part[0] for part in (data[0] or []) if part and part[0]))
        if source == "auto" and len(data) > 2 and isinstance(data[2], str):
            detected = data[2]
    return "\n".join(out), detected


def translate_mymemory(text, target, source="auto"):
    if source == "auto":
        source = guess_language(text) or "en"
    out = []
    for chunk in _chunks(text, 450):
        if not chunk.strip():
            out.append(chunk)
            continue
        query = urllib.parse.urlencode({"q": chunk, "langpair": f"{source}|{target}"})
        data = json.loads(_web(f"https://api.mymemory.translated.net/get?{query}"))
        if int(data.get("responseStatus", 200)) != 200:
            raise RuntimeError(str(data.get("responseDetails", "MyMemory error"))[:200])
        out.append(data["responseData"]["translatedText"])
    return "\n".join(out), source


def translate_libre(text, target, source, server, key):
    if not server:
        raise RuntimeError("Set the LibreTranslate server address in Settings.")
    payload = {"q": text, "source": source, "target": target.split("-")[0], "format": "text"}
    if key:
        payload["api_key"] = key
    data = json.loads(_web(server.rstrip("/") + "/translate", json.dumps(payload).encode(),
                           {"Content-Type": "application/json"}, timeout=60))
    if "error" in data:
        raise RuntimeError(data["error"])
    detected = (data.get("detectedLanguage") or {}).get("language", source)
    return data.get("translatedText", ""), detected


def translate_text(text, target, source="auto", engine="google", server="", key=""):
    """Returns (translation, detected_source, engine_name). Google falls back to MyMemory."""
    if engine == "libre":
        result, detected = translate_libre(text, target, source, server, key)
        return result, detected, "LibreTranslate"
    if engine == "google":
        try:
            result, detected = translate_google(text, target, source)
            return result, detected, "Google Translate"
        except Exception:
            pass
    result, detected = translate_mymemory(text, target, source)
    return result, detected, "MyMemory"


def pdf_text(pdf_path):
    import pymupdf
    with pymupdf.open(str(pdf_path)) as doc:
        return "\n\n".join(page.get_text().strip() for page in doc).strip()


def export_docx(pdf_path, target, title):
    """Word file with the OCR text of every page; a page without text is added as a picture."""
    import pymupdf
    from docx import Document
    from docx.shared import Inches
    document = Document()
    document.core_properties.title = title
    document.core_properties.author = APP_NAME
    with pymupdf.open(str(pdf_path)) as doc:
        for number, page in enumerate(doc):
            if number:
                document.add_page_break()
            text = page.get_text().strip()
            if text:
                for block in page.get_text("blocks", sort=True):
                    paragraph = " ".join(block[4].split())
                    if paragraph:
                        document.add_paragraph(paragraph)
            else:
                image = Path(tempfile.gettempdir()) / f"wts-page-{uuid4().hex}.png"
                try:
                    page.get_pixmap(dpi=150).save(str(image))
                    document.add_picture(str(image), width=Inches(6.3))
                finally:
                    image.unlink(missing_ok=True)
    document.save(str(target))
    return target


def _page_content(pdf_path):
    """Yield (paragraphs, png_bytes, width_pt, height_pt) for each page: OCR text or, without text, an image."""
    import pymupdf
    with pymupdf.open(str(pdf_path)) as doc:
        for page in doc:
            paragraphs = [" ".join(block[4].split()) for block in page.get_text("blocks", sort=True)]
            paragraphs = [p for p in paragraphs if p]
            image = None if paragraphs else page.get_pixmap(dpi=150).tobytes("png")
            yield paragraphs, image, page.rect.width, page.rect.height


def export_odt(pdf_path, target, title):
    """OpenDocument Text (.odt) for LibreOffice / OpenOffice, written directly (no extra package)."""
    import zipfile
    from xml.sax.saxutils import escape
    body, pictures = [], []
    for number, (paragraphs, image, width, height) in enumerate(_page_content(pdf_path)):
        style = ' text:style-name="PageBreak"' if number else ""
        if image:
            name = f"Pictures/page{number + 1}.png"
            pictures.append((name, image))
            w_cm = 16.5
            h_cm = w_cm * height / width
            body.append(f'<text:p{style}><draw:frame draw:name="Page{number + 1}" text:anchor-type="as-char" '
                        f'svg:width="{w_cm:.2f}cm" svg:height="{h_cm:.2f}cm"><draw:image xlink:href="{name}" '
                        'xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/></draw:frame></text:p>')
        else:
            for index, paragraph in enumerate(paragraphs):
                body.append(f'<text:p{style if index == 0 else ""}>{escape(paragraph)}</text:p>')
    ns = ('xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
          'xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" '
          'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
          'xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" '
          'xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0" '
          'xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" '
          'xmlns:xlink="http://www.w3.org/1999/xlink" '
          'xmlns:dc="http://purl.org/dc/elements/1.1/" '
          'xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0"')
    content = (f'<?xml version="1.0" encoding="UTF-8"?><office:document-content {ns} office:version="1.3">'
               '<office:automatic-styles><style:style style:name="PageBreak" style:family="paragraph">'
               '<style:paragraph-properties fo:break-before="page"/></style:style></office:automatic-styles>'
               '<office:body><office:text>' + ("".join(body) or "<text:p/>") +
               '</office:text></office:body></office:document-content>')
    styles = (f'<?xml version="1.0" encoding="UTF-8"?><office:document-styles {ns} office:version="1.3">'
              '<office:styles><style:default-style style:family="paragraph"><style:text-properties '
              'fo:font-size="11pt"/><style:paragraph-properties fo:margin-bottom="0.2cm"/></style:default-style>'
              '</office:styles><office:automatic-styles><style:page-layout style:name="A4"><style:page-layout-properties '
              'fo:page-width="21cm" fo:page-height="29.7cm" fo:margin-top="2cm" fo:margin-bottom="2cm" '
              'fo:margin-left="2.25cm" fo:margin-right="2.25cm"/></style:page-layout></office:automatic-styles>'
              '<office:master-styles><style:master-page style:name="Standard" style:page-layout-name="A4"/>'
              '</office:master-styles></office:document-styles>')
    meta = (f'<?xml version="1.0" encoding="UTF-8"?><office:document-meta {ns} office:version="1.3"><office:meta>'
            f'<dc:title>{escape(title)}</dc:title><meta:generator>{escape(APP_NAME)} {VERSION}</meta:generator>'
            '</office:meta></office:document-meta>')
    manifest = ['<?xml version="1.0" encoding="UTF-8"?><manifest:manifest '
                'xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3">'
                '<manifest:file-entry manifest:full-path="/" manifest:version="1.3" '
                'manifest:media-type="application/vnd.oasis.opendocument.text"/>']
    for name in ("content.xml", "styles.xml", "meta.xml"):
        manifest.append(f'<manifest:file-entry manifest:full-path="{name}" manifest:media-type="text/xml"/>')
    for name, _ in pictures:
        manifest.append(f'<manifest:file-entry manifest:full-path="{name}" manifest:media-type="image/png"/>')
    manifest.append("</manifest:manifest>")
    with zipfile.ZipFile(str(target), "w") as odt:
        odt.writestr(zipfile.ZipInfo("mimetype"), "application/vnd.oasis.opendocument.text",
                     compress_type=zipfile.ZIP_STORED)
        for name, data in (("content.xml", content), ("styles.xml", styles), ("meta.xml", meta),
                           ("META-INF/manifest.xml", "".join(manifest))):
            odt.writestr(name, data, compress_type=zipfile.ZIP_DEFLATED)
        for name, data in pictures:
            odt.writestr(name, data, compress_type=zipfile.ZIP_STORED)
    return target


# ---------------------------------------------------------------- main window
SOURCES = [("Auto · feeder if loaded, else flatbed", "auto"), ("Flatbed (glass)", "glass"),
           ("Document feeder", "feeder"), ("Document feeder · both sides", "duplex")]
FORMATS = [("PDF", "pdf", "one PDF with every page"), ("JPG", "jpg", "one JPG image per page"),
           ("PDF + JPG", "both", "the PDF and the JPG images from one scan")]
FORMAT_SHORT = {"pdf": "PDF", "jpg": "JPG", "both": "PDF + JPG"}
SOURCE_SHORT = {"auto": "Auto source", "glass": "Flatbed", "feeder": "Feeder", "duplex": "Feeder · 2 sides"}
ENGINES = [("Google Translate (free)", "google"), ("MyMemory (free)", "mymemory"),
           ("LibreTranslate (your server)", "libre")]
ENGINE_NAMES = {"google": "Google Translate", "mymemory": "MyMemory", "libre": "LibreTranslate"}


class Scanner(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} · {BRANDS}")
        self.setWindowIcon(app_icon())
        self.setMinimumWidth(840)
        self.settings = QSettings("LocalTools", "EpsonNetworkScan")

        self.process = QProcess(self)
        self.process.finished.connect(self.finished)
        self.process.errorOccurred.connect(self.process_error)
        self.pending = None
        self.previewing = False
        self.job = None
        self.last_outputs = []
        self.last_text = ""
        self.last_text_base = None
        self.cancelled = False
        self.job_device = None
        self.installing_ocr = False

        self.discoveries = {}
        self.discovery_queue = []
        self.found = {}
        self.discovery_notes = []
        self.timed_out = set()
        self.search_stopped = False
        self.searched_once = False
        self.discovery_timer = QTimer(self)
        self.discovery_timer.setSingleShot(True)
        self.discovery_timer.timeout.connect(self.discovery_timeout)

        self.presence = LanPresence()
        self.presence.start()
        self.escl_ip = None
        self.escl_state = None
        self.waiting_for_free = False
        self.last_led = None
        threading.Thread(target=self.poll_escl, daemon=True).start()

        self.catalog_keys = []
        self.update_info = None
        self.text_dialog = None
        self.icon_widgets = []
        self.build_settings_dialog()
        self.build_ui()
        clean_old_previews()

        self.led_timer = QTimer(self)
        self.led_timer.setInterval(1000)
        self.led_timer.timeout.connect(self.update_led)
        self.led_timer.start()

        for keys, slot in (("F5", self.discover), ("Ctrl+S", self.start_scan), ("Ctrl+P", self.start_preview),
                           ("Ctrl+T", self.show_text), ("Ctrl+,", self.open_settings),
                           ("F1", self.show_guide), ("Esc", self.cancel_scan)):
            QShortcut(QKeySequence(keys), self, activated=slot)
        THEME_LISTENERS.append(self.refresh_icons)
        THEME_LISTENERS.append(self.refresh_nav_icons)
        self.update_summary()
        self.update_connection()
        self.update_controls()

    # ---------- small helpers ----------
    def background(self, func, done):
        """Run func in a thread; call done(ok, value) back on the GUI thread."""
        results = Queue()

        def work():
            try:
                results.put((True, func()))
            except Exception as exc:
                results.put((False, exc))

        timer = QTimer(self)
        timer.setInterval(100)

        def poll():
            try:
                ok, value = results.get_nowait()
            except Empty:
                return
            timer.stop()
            timer.deleteLater()
            done(ok, value)

        timer.timeout.connect(poll)
        timer.start()
        threading.Thread(target=work, daemon=True).start()

    @staticmethod
    def row(*widgets):
        box = QHBoxLayout()
        box.setSpacing(8)
        for index, widget in enumerate(widgets):
            box.addWidget(widget, 1 if index == 0 else 0)
        return box

    @staticmethod
    def left(*widgets):
        box = QHBoxLayout()
        box.setSpacing(8)
        for widget in widgets:
            box.addWidget(widget)
        box.addStretch()
        return box

    @staticmethod
    def card(parent_layout, title=None):
        frame = QFrame()
        frame.setObjectName("card")
        box = QVBoxLayout(frame)
        box.setContentsMargins(18, 14, 18, 16)
        box.setSpacing(10)
        if title:
            head = QLabel(title)
            head.setObjectName("cardTitle")
            box.addWidget(head)
        parent_layout.addWidget(frame)
        return box

    @staticmethod
    def form_page():
        page = QWidget()
        form = QFormLayout(page)
        form.setContentsMargins(16, 16, 16, 16)
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return page, form

    def choice(self, form, label, values, key, default=0):
        combo = QComboBox()
        for name, value in values:
            combo.addItem(tr(name), value)
        saved = combo.findData(self.settings.value(key, ""))
        combo.setCurrentIndex(saved if saved >= 0 else default)
        combo.currentIndexChanged.connect(lambda _: (self.settings.setValue(key, combo.currentData()),
                                                     self.update_summary()))
        if form is not None:
            form.addRow(tr(label), combo)
        return combo

    def check(self, form, text, key, default):
        box = QCheckBox(tr(text))
        box.setChecked(self.settings.value(key, default, type=bool))
        box.toggled.connect(lambda on: (self.settings.setValue(key, on), self.update_summary()))
        form.addRow("", box)
        return box

    @staticmethod
    def restyle(widget, kind):
        widget.setProperty("kind", kind)
        widget.style().unpolish(widget)
        widget.style().polish(widget)

    def output_folder(self):
        default = Path.home() / "Documents" / "What the Scan"
        return Path(self.settings.value("output_folder", str(default)) or default)

    def busy(self):
        return self.scanning() or bool(self.discoveries) or self.installing_ocr

    def set_status(self, text, kind="info"):
        marks = {"info": "ℹ", "busy": "⏳", "ok": "✓", "error": "⚠"}
        body = text[2:] if text.startswith("✓ ") else text
        self.status.setText(f"{marks.get(kind, 'ℹ')}   {body}")
        self.status.setProperty("kind", kind)
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)

    def status_text(self):
        return self.status.text().split("   ", 1)[-1]

    def iconize(self, widget, name, color_key="text", color=None):
        self.icon_widgets.append((widget, name, color_key, color))
        widget.setIcon(icon(name, color_key, color))

    def refresh_icons(self):
        for widget, name, color_key, color in self.icon_widgets:
            try:
                widget.setIcon(icon(name, color_key, color))
            except RuntimeError:
                pass

    # ---------- main screen ----------
    def build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 22, 26, 22)
        layout.setSpacing(16)

        header = QHBoxLayout()
        header.setSpacing(12)
        mark = QLabel()
        mark.setPixmap(draw_logo(112).scaled(56, 56, Qt.AspectRatioMode.KeepAspectRatio,
                                             Qt.TransformationMode.SmoothTransformation))
        mark.setFixedSize(56, 56)
        header.addWidget(mark, 0, Qt.AlignmentFlag.AlignVCenter)
        titles = QVBoxLayout()
        titles.setSpacing(0)
        title = QLabel(APP_NAME)
        title.setObjectName("title")
        subtitle = QLabel(f"{APP_TAGLINE}  ·  v{VERSION}")
        subtitle.setObjectName("subtitle")
        titles.addWidget(title)
        titles.addWidget(subtitle)
        header.addLayout(titles, 1)
        badge = QFrame()
        badge.setObjectName("ledBadge")
        badge_row = QHBoxLayout(badge)
        badge_row.setContentsMargins(13, 8, 15, 8)
        badge_row.setSpacing(9)
        self.led = Led(18)
        self.led_text = QLabel(tr("Idle"))
        self.led_text.setObjectName("ledText")
        badge_row.addWidget(self.led)
        badge_row.addWidget(self.led_text)
        self.led_badge = badge
        header.addWidget(badge, 0, Qt.AlignmentFlag.AlignVCenter)
        settings_button = QPushButton(tr("Settings"))
        settings_button.setObjectName("ghost")
        settings_button.setToolTip(tr("Scanner, scanning, text and appearance settings (Ctrl+,)"))
        settings_button.clicked.connect(lambda: self.open_settings())
        self.iconize(settings_button, "gear")
        header.addWidget(settings_button, 0, Qt.AlignmentFlag.AlignVCenter)
        self.help_button = QPushButton(tr("Help"))
        self.help_button.setObjectName("ghost")
        self.iconize(self.help_button, "help")
        help_menu = QMenu(self)
        help_menu.addAction(tr("Quick guide"), self.show_guide)
        self.update_action = help_menu.addAction(tr("Check for updates…"), lambda: self.check_updates(manual=True))
        help_menu.addAction(tr("Project page on GitHub"), lambda: QDesktopServices.openUrl(QUrl(REPO_URL)))
        help_menu.addSeparator()
        help_menu.addAction(tr("About {app}", app=APP_NAME), self.show_about)
        self.help_button.setMenu(help_menu)
        header.addWidget(self.help_button, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addLayout(header)

        # Hero: connection, live
        hero = QFrame()
        hero.setObjectName("hero")
        hero_row = QHBoxLayout(hero)
        hero_row.setContentsMargins(0, 0, 18, 0)
        hero_row.setSpacing(16)
        strip = QFrame()
        strip.setObjectName("accentStrip")
        strip.setFixedWidth(6)
        hero_row.addWidget(strip)
        inner = QHBoxLayout()
        inner.setContentsMargins(4, 18, 0, 18)
        inner.setSpacing(16)
        self.conn_icon = QLabel("…")
        self.conn_icon.setObjectName("connIcon")
        self.conn_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        inner.addWidget(self.conn_icon, 0, Qt.AlignmentFlag.AlignTop)
        texts = QVBoxLayout()
        texts.setSpacing(4)
        self.conn_title = QLabel(tr("Looking for scanners…"))
        self.conn_title.setObjectName("connTitle")
        self.conn_title.setWordWrap(True)
        self.conn_detail = QLabel("")
        self.conn_detail.setObjectName("hint")
        self.conn_detail.setWordWrap(True)
        texts.addWidget(self.conn_title)
        texts.addWidget(self.conn_detail)
        chips_host = QWidget()
        chips_host.setObjectName("plain")
        self.chips_layout = FlowLayout(chips_host, 6)
        self.chips = []
        for _ in range(9):
            chip = QLabel()
            chip.setObjectName("chip")
            chip.hide()
            self.chips_layout.addWidget(chip)
            self.chips.append(chip)
        texts.addSpacing(4)
        texts.addWidget(chips_host)
        inner.addLayout(texts, 1)
        side = QVBoxLayout()
        side.setSpacing(8)
        self.refresh = QPushButton(tr("Search again"))
        self.refresh.setToolTip(tr("Look for scanners again (F5)"))
        self.refresh.clicked.connect(self.discover)
        self.iconize(self.refresh, "refresh")
        change = QPushButton(tr("Change…"))
        change.setToolTip(tr("Choose another scanner or change scan settings"))
        change.clicked.connect(lambda: self.open_settings(0))
        self.iconize(change, "gear")
        side.addWidget(self.refresh)
        side.addWidget(change)
        side.addStretch()
        inner.addLayout(side)
        hero_row.addLayout(inner, 1)
        layout.addWidget(hero)

        # Actions, side by side
        bar = QFrame()
        bar.setObjectName("card")
        actions = QHBoxLayout(bar)
        actions.setContentsMargins(14, 14, 14, 14)
        actions.setSpacing(10)
        self.scan_button = QPushButton(tr("Scan"))
        self.scan_button.setObjectName("scan")
        self.scan_button.setMinimumHeight(84)
        self.scan_button.setIconSize(QSize(30, 30))
        self.scan_button.setToolTip(tr("Scan and save in the format chosen in Settings (Ctrl+S)"))
        self.scan_button.clicked.connect(lambda: self.start_scan())
        self.iconize(self.scan_button, "scan", color="#ffffff")
        actions.addWidget(self.scan_button, 2)
        self.preview = self.tool_button("eye", tr("Preview"), tr("Quick low-resolution look at the flatbed (Ctrl+P)"),
                                        self.start_preview)
        self.text_button = self.tool_button("translate", tr("Text"),
                                            tr("Recognised text and translation of the last scan (Ctrl+T)"),
                                            self.show_text)
        self.open_last_button = self.tool_button("file", tr("Open last"), tr("Open the last scanned file"),
                                                 self.open_last)
        self.open_folder = self.tool_button("folder", tr("Open folder"), tr("Open the folder with your scans"),
                                            self.open_output_folder)
        self.cancel = self.tool_button("cancel", tr("Cancel"), tr("Stop the scan or search (Esc)"),
                                       self.cancel_scan, "error_fg")
        self.cancel.setObjectName("cancelTile")
        for button in (self.preview, self.text_button, self.open_last_button, self.open_folder, self.cancel):
            actions.addWidget(button, 1)
        layout.addWidget(bar)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(4)
        layout.addWidget(self.progress)

        self.status = QLabel()
        self.status.setObjectName("status")
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        self.status.setMinimumHeight(48)
        layout.addWidget(self.status)
        layout.addStretch()
        self.set_status(tr("Starting…"), "busy")

    def tool_button(self, name, label, tip, slot, color_key="text"):
        button = QToolButton()
        button.setObjectName("tile")
        button.setText(label)
        button.setToolTip(tip)
        button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextUnderIcon)
        button.setIconSize(QSize(26, 26))
        button.setMinimumHeight(84)
        button.setMinimumWidth(max(96, button.fontMetrics().horizontalAdvance(label) + 34))
        button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        button.clicked.connect(lambda: slot())
        self.iconize(button, name, color_key)
        return button

    def doc_format(self):
        if not self.make_doc.isChecked():
            return None
        button = self.doc_group.checkedButton()
        return button.property("format") if button else "docx"

    def format_label(self):
        label = FORMAT_SHORT[self.save_format()]
        doc = self.doc_format()
        if doc:
            label += " + Word" if doc == "docx" else " + ODT"
        return label

    def update_summary(self):
        if not hasattr(self, "chips"):
            return
        label = self.format_label()
        self.scan_button.setText(f"  {tr('Scan')}  ·  {label}")
        folder = self.output_folder()
        chips = [label, tr(SOURCE_SHORT.get(self.source.currentData(), "")), self.size.currentText(),
                 self.dpi.currentData() + " dpi", self.color.currentText(),
                 tr("OCR") if (self.ocr_on.isChecked() or self.doc_format()) else tr("OCR off")]
        target = self.auto_translate.currentData()
        if target:
            chips.append(tr("translate → {lang}", lang=lang_name(target)))
        chips.append("📁 " + (tr("asks for a file name") if self.ask_name.isChecked() else folder.name))
        for chip, text in zip(self.chips, chips + [""] * len(self.chips)):
            chip.setText(text)
            chip.setVisible(bool(text))
        self.chips_layout.invalidate()
        self.folder_edit.setText(str(folder))
        for radio in self.doc_group.buttons():
            radio.setEnabled(self.make_doc.isChecked())
        self.ocr_list.setVisible(self.ocr_mode.currentData() == "manual")
        libre = self.engine.currentData() == "libre"
        self.libre_url.setEnabled(libre)
        self.libre_key.setEnabled(libre)

    def update_connection(self):
        data = self.device.currentData()
        network = self.network.currentData()
        if self.discoveries:
            self.conn_title.setText(tr("Looking for scanners…"))
            self.conn_detail.setText(tr("Checking every driver at the same time."))
            self.conn_icon.setText("…")
            self.restyle(self.conn_icon, "busy")
        elif data:
            name, driver = data
            self.conn_title.setText(tr("Connected to {name}", name=name))
            details = [tr("via {driver}", driver=driver.upper())]
            if network:
                details.append(tr("{brand} at {ip}", brand=network[3], ip=network[0]))
            if self.device.count() > 1:
                details.append(tr("{count} more in Settings", count=self.device.count() - 1))
            self.conn_detail.setText("  ·  ".join(details))
            self.conn_icon.setText("✓")
            self.restyle(self.conn_icon, "ok")
        else:
            self.conn_title.setText(tr("No scanner connected") if self.searched_once else tr("Starting…"))
            self.conn_detail.setText(tr("Turn the scanner on, check the USB cable or Wi-Fi, then click Search again.")
                                     if self.searched_once else "")
            self.conn_icon.setText("✕" if self.searched_once else "…")
            self.restyle(self.conn_icon, "error" if self.searched_once else "busy")

    # ---------- settings window (side menu + sections) ----------
    def settings_page(self, title, subtitle):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        page = QWidget()
        page.setObjectName("page")
        box = QVBoxLayout(page)
        box.setContentsMargins(26, 22, 26, 22)
        box.setSpacing(14)
        heading = QLabel(title)
        heading.setObjectName("pageTitle")
        box.addWidget(heading)
        note = QLabel(subtitle)
        note.setObjectName("hint")
        note.setWordWrap(True)
        box.addWidget(note)
        box.addSpacing(4)
        scroll.setWidget(page)
        self.settings_stack.addWidget(scroll)
        return page, box

    @staticmethod
    def section(box, title):
        frame = QFrame()
        frame.setObjectName("section")
        inner = QVBoxLayout(frame)
        inner.setContentsMargins(18, 14, 18, 16)
        inner.setSpacing(10)
        head = QLabel(title)
        head.setObjectName("sectionTitle")
        inner.addWidget(head)
        form = QFormLayout()
        form.setSpacing(10)
        form.setHorizontalSpacing(14)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        inner.addLayout(form)
        box.addWidget(frame)
        return form

    def build_settings_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle(f"{APP_NAME} · {tr('Settings')}")
        dialog.resize(860, 640)
        dialog.setMinimumSize(780, 520)
        outer = QHBoxLayout(dialog)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        panel = QFrame()
        panel.setObjectName("navPanel")
        panel.setFixedWidth(220)
        side = QVBoxLayout(panel)
        side.setContentsMargins(14, 20, 14, 16)
        side.setSpacing(10)
        head = QHBoxLayout()
        logo = QLabel()
        logo.setPixmap(draw_logo(96).scaled(34, 34, Qt.AspectRatioMode.KeepAspectRatio,
                                            Qt.TransformationMode.SmoothTransformation))
        head.addWidget(logo)
        name = QLabel(tr("Settings"))
        name.setObjectName("cardTitle")
        head.addWidget(name, 1)
        side.addLayout(head)
        side.addSpacing(6)
        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        self.nav.setIconSize(QSize(20, 20))
        side.addWidget(self.nav, 1)
        done = QPushButton(tr("Done"))
        done.setObjectName("primary")
        done.clicked.connect(dialog.accept)
        side.addWidget(done)
        outer.addWidget(panel)
        self.settings_stack = QStackedWidget()
        outer.addWidget(self.settings_stack, 1)
        self.nav.currentRowChanged.connect(self.settings_stack.setCurrentIndex)

        def nav_item(icon_name, label):
            item = QListWidgetItem(label)
            self.nav.addItem(item)
            self.nav_icons.append((item, icon_name))
            item.setIcon(icon(icon_name, "accent_text"))

        self.nav_icons = []

        # 1 · Scanner
        nav_item("scan", tr("Scanner"))
        page, box = self.settings_page(tr("Scanner"), tr(
            "Everything here is found automatically. Change it only if the wrong scanner is chosen."))
        form = self.section(box, tr("Scanner"))
        self.driver = self.choice(form, "Driver", [
            ("Auto (all drivers)", "auto"), *((name.upper(), name) for name in DRIVERS),
        ], "driver_choice")
        self.device = QComboBox()
        self.device.setPlaceholderText(tr("No scanner found yet"))
        self.settings_refresh = QPushButton(tr("Refresh"))
        self.iconize(self.settings_refresh, "refresh")
        self.settings_refresh.clicked.connect(self.discover)
        form.addRow(tr("Scanner"), self.row(self.device, self.settings_refresh))
        self.model = QComboBox()
        self.model.addItem(tr("Find your model’s driver"), None)
        for group, models in CATALOG.items():
            brand, _, detail = group.partition(" · ")
            for model in models:
                self.model.addItem(f"{brand} {model}" + (f"  ·  {detail}" if detail else ""), (brand, model))
                for key in (normalize(model), *MODEL_ALIASES.get(model, ())):
                    self.catalog_keys.append((self.model.count() - 1, normalize(brand.split()[0]), key))
        self.catalog_keys.sort(key=lambda item: -len(item[2]))
        support = QPushButton(tr("Driver setup"))
        self.iconize(support, "save")
        support.clicked.connect(self.open_model_support)
        form.addRow(tr("Model"), self.row(self.model, support))
        form = self.section(box, tr("Network"))
        self.network = QComboBox()
        self.network.setPlaceholderText(tr("No Epson or Canon network reply yet"))
        form.addRow(tr("Network"), self.network)
        self.find_network = QPushButton(tr("Find on network"))
        self.iconize(self.find_network, "refresh")
        self.find_network.clicked.connect(self.detect_network)
        self.web_panel = QPushButton(tr("Web panel"))
        self.iconize(self.web_panel, "eye")
        self.web_panel.clicked.connect(self.open_web_panel)
        buttons = QHBoxLayout()
        buttons.addWidget(self.find_network)
        buttons.addWidget(self.web_panel)
        buttons.addStretch()
        form.addRow("", buttons)
        self.network_status = QLabel()
        self.network_status.setObjectName("hint")
        self.network_status.setWordWrap(True)
        self.network_status.setTextFormat(Qt.TextFormat.PlainText)
        form.addRow("", self.network_status)
        box.addStretch()

        # 2 · Scanning
        nav_item("file", tr("Scanning"))
        page, box = self.settings_page(tr("Scanning"), tr("What to save, the paper and where the files go."))
        form = self.section(box, tr("Output"))
        formats = QVBoxLayout()
        formats.setSpacing(7)
        self.format_group = QButtonGroup(page)
        saved_format = self.settings.value("save_format", "pdf")
        if saved_format == "docx":  # older version had Word as a format
            saved_format = "pdf"
            self.settings.setValue("save_format", "pdf")
            self.settings.setValue("make_word", True)
        for label, value, hint in FORMATS:
            radio = QRadioButton(f"{label}   ·   {tr(hint)}")
            radio.setProperty("format", value)
            radio.setChecked(value == saved_format)
            self.format_group.addButton(radio)
            formats.addWidget(radio)
        if self.format_group.checkedButton() is None:
            self.format_group.buttons()[0].setChecked(True)
        self.format_group.buttonToggled.connect(self.format_changed)
        form.addRow(tr("Save as"), formats)
        if self.settings.contains("make_word") or self.settings.contains("make_odt"):
            if self.settings.value("make_odt", False, type=bool):
                self.settings.setValue("make_doc", True)
                self.settings.setValue("doc_format", "odt")
            elif self.settings.value("make_word", False, type=bool):
                self.settings.setValue("make_doc", True)
                self.settings.setValue("doc_format", "docx")
            self.settings.remove("make_word")
            self.settings.remove("make_odt")
        self.make_doc = self.check(form, "Also save an editable document (text from OCR)", "make_doc", False)
        docs = QVBoxLayout()
        docs.setSpacing(7)
        docs.setContentsMargins(26, 0, 0, 0)
        self.doc_group = QButtonGroup(page)
        saved_doc = self.settings.value("doc_format", "docx" if WINDOWS else "odt")
        for label, value in (("Word (.docx) · Microsoft Word", "docx"),
                             ("OpenDocument (.odt) · LibreOffice on Mac / Linux", "odt")):
            radio = QRadioButton(tr(label))
            radio.setProperty("format", value)
            radio.setChecked(value == saved_doc)
            self.doc_group.addButton(radio)
            docs.addWidget(radio)
        if self.doc_group.checkedButton() is None:
            self.doc_group.buttons()[0].setChecked(True)
        self.doc_group.buttonToggled.connect(
            lambda button, on: on and (self.settings.setValue("doc_format", button.property("format")),
                                       self.update_summary()))
        form.addRow(tr("Document"), docs)
        form = self.section(box, tr("Paper"))
        self.source = self.choice(form, "Paper source", SOURCES, "source")
        self.size = self.choice(form, "Paper size", [("A4", "a4"), ("Letter", "letter"), ("Legal", "legal")], "size")
        self.dpi = self.choice(form, "Resolution", [
            ("150 dpi · fast, small file", "150"), ("300 dpi · recommended", "300"), ("600 dpi · fine detail", "600"),
        ], "dpi", 1)
        self.color = self.choice(form, "Colour", [
            ("Colour", "color"), ("Greyscale", "gray"), ("Black and white", "bw"),
        ], "color")
        form = self.section(box, tr("Saving"))
        self.folder_edit = QLineEdit()
        self.folder_edit.setReadOnly(True)
        browse = QPushButton(tr("Browse…"))
        self.iconize(browse, "folder")
        browse.clicked.connect(self.choose_folder)
        form.addRow(tr("Save to"), self.row(self.folder_edit, browse))
        self.ask_name = self.check(form, "Ask for a file name every time", "ask_name", False)
        self.open_after = self.check(form, "Open the file after scanning", "open_after", False)
        box.addStretch()

        # 3 · Text & translation
        nav_item("translate", tr("Text & translation"))
        page, box = self.settings_page(tr("Text & translation"), tr("Recognise text in your scans and translate it."))
        form = self.section(box, tr("Text recognition (OCR)"))
        self.ocr_on = self.check(form, "Make PDFs searchable with OCR (text recognition)", "ocr_on", True)
        self.ocr_mode = self.choice(form, "OCR languages", [
            ("Auto · English + Greek + your system language", "auto"), ("Choose languages", "manual"),
        ], "ocr_mode")
        self.ocr_list = QListWidget()
        self.ocr_list.setMinimumHeight(150)
        chosen = set(str(self.settings.value("ocr_langs", "eng,ell")).split(","))
        for code, (english, greek, tess) in LANG_NAMES.items():
            item = QListWidgetItem(f"{greek if UI_LANG == 'el' else english}  ({tess})")
            item.setData(Qt.ItemDataRole.UserRole, tess)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked if tess in chosen else Qt.CheckState.Unchecked)
            self.ocr_list.addItem(item)
        self.ocr_list.itemChanged.connect(self.ocr_langs_changed)
        form.addRow("", self.ocr_list)
        hint = QLabel(tr("Languages download automatically the first time they are used."))
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        form.addRow("", hint)
        self.save_txt = self.check(form, "Also save the text as a .txt file", "save_txt", False)
        form = self.section(box, tr("Translation"))
        self.auto_translate = self.choice(form, "Translate automatically to",
                                          [("Off", "")] + [(lang_name(c), c) for c in LANG_NAMES], "auto_translate")
        self.engine = self.choice(form, "Translation service", ENGINES, "engine")
        self.libre_url = QLineEdit(self.settings.value("libre_url", ""))
        self.libre_url.setPlaceholderText("https://libretranslate.example.com")
        self.libre_url.textChanged.connect(lambda text: self.settings.setValue("libre_url", text.strip()))
        form.addRow(tr("LibreTranslate server"), self.libre_url)
        self.libre_key = QLineEdit(self.settings.value("libre_key", ""))
        self.libre_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.libre_key.textChanged.connect(lambda text: self.settings.setValue("libre_key", text.strip()))
        form.addRow(tr("API key (optional)"), self.libre_key)
        note = QLabel(tr("Free services need internet. Google falls back to MyMemory if it fails."))
        note.setObjectName("hint")
        note.setWordWrap(True)
        form.addRow("", note)
        box.addStretch()

        # 4 · General
        nav_item("gear", tr("General"))
        page, box = self.settings_page(tr("General"), tr("Language, appearance and updates."))
        form = self.section(box, tr("Appearance"))
        self.language = self.choice(form, "Language", [
            ("Auto · system language", "auto"), ("English", "en"), ("Ελληνικά", "el"),
        ], "ui_lang")
        self.language.currentIndexChanged.connect(self.language_changed)
        self.theme = self.choice(form, "Theme", [
            ("Auto · follow Windows / system", "auto"), ("Light", "light"), ("Dark", "dark"),
        ], "theme")
        self.theme.currentIndexChanged.connect(lambda _: apply_theme(self.theme.currentData()))
        form = self.section(box, tr("Updates"))
        self.auto_update = self.check(form, "Check for updates automatically", "auto_update", True)
        check_now = QPushButton(tr("Check now"))
        self.iconize(check_now, "refresh")
        check_now.clicked.connect(lambda: self.check_updates(manual=True))
        form.addRow("", self.left(check_now))
        form = self.section(box, tr("Reset"))
        reset = QPushButton(tr("Reset everything to Auto"))
        self.iconize(reset, "refresh")
        reset.clicked.connect(self.reset_settings)
        form.addRow("", self.left(reset))
        box.addStretch()

        self.nav.setCurrentRow(0)
        self.settings_dialog = dialog
        self.device.currentIndexChanged.connect(self.device_changed)
        self.source.currentIndexChanged.connect(self.update_controls)
        self.driver.currentIndexChanged.connect(lambda _: self.discover())
        self.network.currentIndexChanged.connect(self.remember_network)

    def open_settings(self, tab=None):
        if isinstance(tab, int):
            self.nav.setCurrentRow(tab)
        self.settings_dialog.show()
        self.settings_dialog.raise_()
        self.settings_dialog.activateWindow()

    def refresh_nav_icons(self):
        for item, name in getattr(self, "nav_icons", []):
            item.setIcon(icon(name, "accent_text"))

    def save_format(self):
        button = self.format_group.checkedButton()
        return button.property("format") if button else "pdf"

    def format_changed(self, button, checked):
        if checked:
            self.settings.setValue("save_format", button.property("format"))
            self.update_summary()

    def ocr_langs_changed(self):
        codes = [self.ocr_list.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.ocr_list.count())
                 if self.ocr_list.item(i).checkState() == Qt.CheckState.Checked]
        self.settings.setValue("ocr_langs", ",".join(codes))

    def ocr_languages(self):
        if self.ocr_mode.currentData() == "manual":
            codes = [c for c in str(self.settings.value("ocr_langs", "eng,ell")).split(",") if c]
            return codes or ["eng"]
        codes = ["eng", "ell"]
        system = LANG_NAMES.get(system_language())
        if system and system[2] not in codes:
            codes.append(system[2])
        return codes

    def choose_folder(self):
        folder = QFileDialog.getExistingDirectory(self, tr("Save scans to"), str(self.output_folder()))
        if folder:
            self.settings.setValue("output_folder", folder)
            self.update_summary()

    def language_changed(self):
        if resolve_ui_language(self.language.currentData()) == UI_LANG:
            return
        if QMessageBox.question(self.settings_dialog, tr("Restart to change the language?"),
                                tr("The new language is used after a restart. Restart now?")) \
                == QMessageBox.StandardButton.Yes:
            self.restart_app()

    def reset_settings(self):
        for combo, value in ((self.driver, "auto"), (self.source, "auto"), (self.size, "a4"),
                             (self.dpi, "300"), (self.color, "color"), (self.theme, "auto"),
                             (self.ocr_mode, "auto"), (self.auto_translate, ""), (self.engine, "google")):
            combo.setCurrentIndex(max(0, combo.findData(value)))
        self.settings.remove("output_folder")
        self.format_group.buttons()[0].setChecked(True)
        for box, value in ((self.ask_name, False), (self.open_after, False), (self.auto_update, True),
                           (self.ocr_on, True), (self.save_txt, False), (self.make_doc, False)):
            box.setChecked(value)
        self.update_summary()
        self.set_status(tr("All settings are back to Auto."), "ok")

    # ---------- help ----------
    def show_guide(self):
        QMessageBox.information(self, tr("Quick guide"), GUIDE_GR if UI_LANG == "el" else GUIDE)

    def show_about(self):
        box = QMessageBox(self)
        box.setWindowTitle(tr("About {app}", app=APP_NAME))
        box.setIconPixmap(draw_logo(192).scaled(96, 96, Qt.AspectRatioMode.KeepAspectRatio,
                                                Qt.TransformationMode.SmoothTransformation))
        box.setTextFormat(Qt.TextFormat.RichText)
        box.setText(about_html())
        box.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        for label in box.findChildren(QLabel):
            label.setOpenExternalLinks(True)
        box.exec()

    def check_updates(self, manual=False):
        if manual:
            self.set_status(tr("Checking GitHub for a newer version…"), "busy")

        def done(ok, info):
            if not ok:
                if manual:
                    self.set_status(tr("Could not check for updates. {error}", error=info), "error")
                return
            if version_tuple(info["version"]) <= version_tuple(VERSION):
                if manual:
                    self.set_status(tr("You have the latest version (v{version}).", version=VERSION), "ok")
                return
            self.update_info = info
            self.update_action.setText(tr("Update to {version}…", version=info["version"]))
            self.help_button.setText("? " + tr("Help") + "  ●")
            self.offer_update(info)

        self.background(latest_release, done)

    def offer_update(self, info):
        answer = QMessageBox.question(self, tr("Update available"), tr(
            "{app} {version} is available (you have v{current}).\n\nWhat's new:\n{notes}\n\nDownload and install it now?",
            app=APP_NAME, version=info["version"], current=VERSION, notes=info["notes"][:700] or tr("No release notes.")))
        if answer != QMessageBox.StandardButton.Yes:
            self.set_status(tr("Update {version} is waiting in Help.", version=info["version"]), "info")
            return
        if self.busy():
            self.set_status(tr("Finish the scan first, then install the update from Help."), "info")
            return
        self.set_status(tr("Downloading {version} from GitHub…", version=info["version"]), "busy")

        def done(ok, value):
            if not ok:
                self.set_status(tr("Update failed. {error}", error=value), "error")
                if QMessageBox.question(self, tr("Update failed"), tr(
                        "{error}\n\nOpen the release page to download it by hand?", error=value)) \
                        == QMessageBox.StandardButton.Yes:
                    QDesktopServices.openUrl(QUrl(info["page"]))
                return
            self.set_status(tr("Updated to {version}. Restarting…", version=info["version"]), "ok")
            QTimer.singleShot(600, self.restart_app)

        self.background(lambda: install_release(info), done)

    def restart_app(self):
        if self.scanning():
            return
        command = [str(app_path())] if FROZEN else [sys.executable, str(app_path())]
        subprocess.Popen(command + sys.argv[1:], creationflags=HIDDEN, env=dict(os.environ, **{RESTART_ENV: "1"}))
        self.close()

    # ---------- status light ----------
    def scanning(self):
        return self.process.state() != QProcess.ProcessState.NotRunning

    def current_scanner(self):
        data = self.device.currentData()
        network = self.network.currentData()
        return (data[0] if data else ""), (network[0] if network else "")

    def led_state(self):
        if self.scanning():
            return "busy", tr("In use · scanning on this PC"), ""
        name, ip = self.current_scanner()
        holder = self.presence.holder(name, ip) if name or ip else None
        if holder:
            since = datetime.fromtimestamp(holder.get("since", time.time())).strftime("%H:%M")
            who = tr("{user} on {host}", user=holder.get("user", "?"), host=holder.get("host", "?"))
            return "busy", tr("In use by {who}", who=who), tr("Started at {time}. Wait until the light turns green.",
                                                               time=since)
        if self.escl_state in ("Processing", "Testing"):
            return "busy", tr("In use · scanner is busy"), tr("The scanner reports that it is scanning right now.")
        if self.installing_ocr:
            return "idle", tr("Idle · installing OCR…"), ""
        if self.discoveries:
            return "idle", tr("Idle · searching…"), ""
        if not name:
            return "idle", tr("Idle · no scanner"), tr("No scanner is connected yet.")
        if self.escl_state in ("Stopped", "Down"):
            return "idle", tr("Idle · scanner on standby"), tr("The scanner reports that it is stopped or offline.")
        return "ready", tr("Ready"), tr("The scanner is free. You can scan.")

    def update_led(self):
        state, text, tip = self.led_state()
        self.led.set_state(state)
        self.led_text.setText(text)
        self.led_badge.setToolTip(tip or text)
        if state == "ready" and self.last_led == "busy" and self.waiting_for_free:
            self.waiting_for_free = False
            QApplication.beep()
            QApplication.alert(self)
            self.set_status(tr("The scanner is free now. You can scan."), "ok")
        self.last_led = state
        if not self.scanning():
            self.update_controls()

    def poll_escl(self):
        while True:
            ip = self.escl_ip
            self.escl_state = escl_status(ip) if ip else None
            time.sleep(4 if ip else 1)

    def scanner_in_use_elsewhere(self):
        state, text, tip = self.led_state()
        if state != "busy":
            return False
        self.waiting_for_free = True
        QMessageBox.warning(self, tr("Scanner in use"), tr(
            "The scanner is in use right now.\n\n{text}.\n{tip}\n\nPlease wait until the light at the top turns green, then try again.\nThis app will beep when the scanner is free.",
            text=text, tip=tip))
        self.set_status(tr("Scanner in use: {text}. Wait for the green light.", text=text), "error")
        return True

    # ---------- catalog / drivers / network ----------
    def device_changed(self):
        self.select_catalog_model()
        self.update_connection()
        self.update_controls()
        self.update_led()

    def select_catalog_model(self):
        device = self.device.currentData()
        if device is None:
            return
        name = normalize(device[0]).replace("pixma", "")
        fallback = None
        for index, brand, key in self.catalog_keys:
            if key.replace("pixma", "") in name:
                if brand in name:
                    self.model.setCurrentIndex(index)
                    return
                if fallback is None and len(key) >= 5:
                    fallback = index
        self.model.setCurrentIndex(fallback or 0)

    def open_model_support(self):
        entry = self.model.currentData()
        if entry is None:
            self.set_status(tr("Choose a model to find its driver."), "info")
            return
        brand, model = entry
        package = DRIVER_PACKAGES.get(model)
        if WINDOWS and package:
            check = package.get("check")
            installed = check and Path(os.environ.get("WINDIR", r"C:\Windows")).joinpath(*check).is_file()
            if not installed:
                if check or QMessageBox.question(self.settings_dialog, tr("Install driver"), tr(
                        "Download and install the official {label} now?\n\nWindows may ask for permission. Choose No to open the support page instead.",
                        label=package["label"])) == QMessageBox.StandardButton.Yes:
                    self.install_driver(package, brand, model)
                    return
        QDesktopServices.openUrl(QUrl(self.support_url(brand, model)))

    @staticmethod
    def support_url(brand, model):
        if brand == "Epson":
            return "https://download-center.epson.com/softwares/?" + urllib.parse.urlencode(
                {"device_id": f"{model} Series"})
        if brand == "Canon":
            return "https://www.canon-europe.com/search/?" + urllib.parse.urlencode({"q": model})
        return "https://support.hp.com/drivers/scanners"

    def install_driver(self, package, brand, model):
        if getattr(self, "model_install_running", False):
            return
        self.model_install_running = True
        events = Queue()
        label = package["label"]
        check = package.get("check")
        self.set_status(tr("Preparing the official {label} installer…", label=label), "busy")

        def work():
            install_vendor(package["url"], package["signer"], package.get("flags", []),
                           lambda message: events.put(message), label, filename=package.get("filename"))
            if check and not Path(os.environ.get("WINDIR", r"C:\Windows")).joinpath(*check).is_file():
                raise RuntimeError("The installer finished but did not register the driver.")

        progress = QTimer(self)
        progress.setInterval(150)

        def show_progress():
            while not events.empty():
                self.set_status(events.get_nowait(), "busy")

        progress.timeout.connect(show_progress)
        progress.start()

        def done(ok, value):
            progress.stop()
            progress.deleteLater()
            self.model_install_running = False
            if ok:
                self.set_status(tr("{label} installed. Looking for scanners…", label=label), "ok")
                self.discover()
            else:
                self.set_status(tr("Driver setup failed. {error}\nThe support page is opening so you can install it by hand.",
                                   error=value), "error")
                QDesktopServices.openUrl(QUrl(self.support_url(brand, model)))

        self.background(work, done)

    def detect_network(self):
        if not self.find_network.isEnabled():
            return
        self.find_network.setEnabled(False)
        self.network_status.setText(tr("Searching the local network for Epson and Canon devices…"))

        def done(ok, devices):
            self.find_network.setEnabled(True)
            if not ok:
                self.network_status.setText(tr("Network discovery failed. {error}", error=devices))
                return
            preferred = self.settings.value("network_mac", "")
            self.network.blockSignals(True)
            self.network.clear()
            selection = -1
            for index, (ip, mac, reachable, brand) in enumerate(devices):
                self.network.addItem(f"{brand}  ·  {ip}" + (f"  ·  {mac}" if mac else ""),
                                     (ip, mac, reachable, brand))
                if mac and mac == preferred:
                    selection = index
            self.network.setCurrentIndex(0 if len(devices) == 1 else selection)
            self.network.blockSignals(False)
            if self.network.currentIndex() >= 0:
                self.remember_network()
            else:
                self.escl_ip = None
                self.network_status.setText(tr("Select your scanner's network address.") if devices else
                                            tr("No Epson or Canon device replied on this local network."))
            self.update_connection()
            self.update_controls()

        self.background(discover_network, done)

    def remember_network(self):
        device = self.network.currentData()
        if not device:
            self.escl_ip = None
            return
        ip, mac, reachable, brand = device
        if mac:
            self.settings.setValue("network_mac", mac)
        self.escl_ip = ip
        if brand == "Canon":
            state = tr("answered as a Canon scanner ✓")
        else:
            state = tr("responds on the scanner port ✓") if reachable else tr("did not respond on the scanner port")
        self.network_status.setText(tr("{brand} {ip} {state}. Scanning uses the driver chosen above.",
                                       brand=brand, ip=ip, state=state))
        self.update_connection()
        self.update_controls()

    def open_web_panel(self):
        device = self.network.currentData()
        if device:
            QDesktopServices.openUrl(QUrl(f"http://{device[0]}/"))

    # ---------- controls ----------
    def update_controls(self):
        scanning = self.scanning()
        searching = bool(self.discoveries)
        busy = scanning or searching or self.installing_ocr
        for widget in (self.refresh, self.settings_refresh, self.driver, self.device, self.source,
                       self.size, self.dpi, self.color):
            widget.setEnabled(not busy)
        ready = not busy and self.device.currentData() is not None
        self.scan_button.setEnabled(ready)
        self.preview.setEnabled(ready and self.source.currentData() in ("glass", "auto"))
        self.progress.setVisible(busy)
        self.cancel.setVisible(scanning or searching)
        self.cancel.setText(tr("Stop search") if searching and not scanning else tr("Cancel"))
        self.open_last_button.setEnabled(any(path.exists() for path in self.last_outputs))
        self.text_button.setEnabled(bool(self.last_text) or bool(self.last_outputs))
        self.web_panel.setEnabled(self.network.currentData() is not None)

    # ---------- discovery (all drivers in parallel) ----------
    def startup(self):
        self.detect_network()
        self.discover()
        if self.settings.value("auto_update", True, type=bool) and not os.environ.get(RESTART_ENV):
            QTimer.singleShot(4000, self.check_updates)

    def discover(self):
        if self.scanning() or self.discoveries or self.installing_ocr:
            return
        backend = get_backend(refresh=True)
        self.device.clear()
        if not backend:
            self.searched_once = True
            self.set_status(tr("The NAPS2 scanner engine was not found. Close and reopen the app to install it automatically."),
                            "error")
            self.update_connection()
            self.update_controls()
            return
        choice = self.driver.currentData()
        drivers = list(DRIVERS) if choice == "auto" else [choice]
        self.found = {driver: [] for driver in drivers}
        self.discovery_notes = []
        self.timed_out = set()
        self.search_stopped = False
        self.discovery_queue = drivers
        self.set_status(tr("Looking for scanners ({drivers})…", drivers=", ".join(d.upper() for d in drivers)), "busy")
        while self.discovery_queue and len(self.discoveries) < max(1, DISCOVERY_PARALLEL):
            self.start_discovery(backend, self.discovery_queue.pop(0))
        self.discovery_timer.start(DISCOVERY_TIMEOUT_MS)
        self.update_connection()
        self.update_controls()
        self.update_led()

    def start_discovery(self, backend, driver):
        process = QProcess(self)
        self.discoveries[process] = driver
        process.finished.connect(lambda code, status, p=process: self.discovery_finished(p, code, status))
        process.errorOccurred.connect(lambda error, p=process: self.discovery_error(p, error))
        process.start(backend[0], backend[1:] + ["--listdevices", "--driver", driver])

    def discovery_finished(self, process, code, status):
        driver = self.discoveries.pop(process, None)
        if driver is None:
            return
        output = decode(process.readAllStandardOutput())
        error = decode(process.readAllStandardError())
        if code == 0 and status == QProcess.ExitStatus.NormalExit:
            self.found[driver] = list(dict.fromkeys(line.strip() for line in output.splitlines() if line.strip()))
        elif driver in self.timed_out:
            self.discovery_notes.append(f"{driver.upper()} timed out")
        elif not self.search_stopped:
            last = (error or output).splitlines()[-1:] or [f"exit code {code}"]
            self.discovery_notes.append(f"{driver.upper()}: {last[0][:160]}")
        process.deleteLater()
        self.discovery_step()

    def discovery_error(self, process, error):
        if error != QProcess.ProcessError.FailedToStart:
            return
        driver = self.discoveries.pop(process, None)
        if driver is None:
            return
        self.discovery_notes.append(f"{driver.upper()}: could not start NAPS2 ({process.errorString()})")
        process.deleteLater()
        self.discovery_step()

    def discovery_step(self):
        if self.discovery_queue and not self.search_stopped:
            backend = get_backend()
            if backend:
                self.start_discovery(backend, self.discovery_queue.pop(0))
        if self.discoveries:
            count = sum(len(names) for names in self.found.values())
            self.set_status(tr("Looking for scanners… {count} found so far.", count=count), "busy")
            return
        self.finish_discovery()

    def discovery_timeout(self):
        for process, driver in list(self.discoveries.items()):
            self.timed_out.add(driver)
            process.kill()
        for driver in self.discovery_queue:
            self.discovery_notes.append(f"{driver.upper()} skipped (time limit)")
        self.discovery_queue = []

    def stop_discovery(self):
        self.search_stopped = True
        self.discovery_queue = []
        for process in list(self.discoveries):
            process.kill()

    def finish_discovery(self):
        self.discovery_timer.stop()
        self.searched_once = True
        auto = self.driver.currentData() == "auto"
        self.device.blockSignals(True)
        self.device.clear()
        for driver, names in self.found.items():
            for name in names:
                self.device.addItem(f"{name}  ·  {driver.upper()}" if auto else name, (name, driver))
        options = [self.device.itemData(i) for i in range(self.device.count())]
        saved = (self.settings.value("device", ""), self.settings.value("driver", ""))
        preferred = next((i for i, option in enumerate(options) if tuple(option) == saved), -1)
        if preferred < 0:
            preferred = next((i for i, (name, _) in enumerate(options)
                              if any(k in normalize(name) for k in ("l14150", "ts3100", "ts3150"))), -1)
        if preferred < 0 and options:
            preferred = 0
        self.device.setCurrentIndex(preferred)
        self.device.blockSignals(False)
        self.select_catalog_model()
        if options:
            self.set_status(tr("Ready. Load the paper and click Scan."), "ok")
        elif self.search_stopped:
            self.set_status(tr("Search stopped. Click Search again when you are ready."), "info")
        else:
            detail = "\n" + "; ".join(self.discovery_notes)[-400:] if self.discovery_notes else ""
            self.set_status(tr("No scanners found. Check the cable or Wi-Fi and the installed driver (Settings › Scanner › Driver setup).")
                            + detail, "error")
        self.search_stopped = False
        self.update_connection()
        self.update_controls()
        self.update_led()

    # ---------- scanning ----------
    def run_job(self, args, message):
        backend = get_backend()
        if not backend:
            self.set_status(tr("The NAPS2 scanner engine was not found. Close and reopen the app to install it automatically."),
                            "error")
            self.clear_pending()
            return
        name, ip = self.current_scanner()
        self.job_device = self.device.currentData()
        self.cancelled = False
        self.presence.take(name, ip)
        self.set_status(message, "busy")
        self.process.start(backend[0], backend[1:] + args)
        self.update_controls()
        self.update_led()

    def scan_args(self, output, source, dpi=None, ocr=None):
        name, driver = self.device.currentData()
        args = ["-o", str(output), "--noprofile", "--driver", driver, "--device", name,
                "--source", source, "--pagesize", self.size.currentData(),
                "--dpi", dpi or self.dpi.currentData(), "--bitdepth", self.color.currentData()]
        args += ["--ocrlang", "+".join(ocr)] if ocr else ["--disableocr"]
        return args

    def start_preview(self):
        if not self.preview.isEnabled() or self.scanner_in_use_elsewhere():
            return
        preview_folder = QT_CACHE.parent
        try:
            preview_folder.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self.set_status(str(exc), "error")
            return
        self.previewing = True
        self.pending = preview_folder / f"epson-preview-{uuid4().hex}.png"
        self.run_job(self.scan_args(self.pending, "glass", "100"), tr("Scanning a quick low-resolution preview…"))

    def show_preview(self, pixmap):
        dialog = QDialog(self)
        dialog.setWindowTitle(tr("Flatbed preview"))
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)
        heading = QLabel(tr("Flatbed preview"))
        heading.setObjectName("pageTitle")
        layout.addWidget(heading)
        note = QLabel(tr("Check the page placement, then scan at your chosen resolution."))
        note.setObjectName("hint")
        layout.addWidget(note)
        frame = QFrame()
        frame.setObjectName("card")
        inner = QVBoxLayout(frame)
        inner.setContentsMargins(14, 14, 14, 14)
        image = QLabel()
        image.setAlignment(Qt.AlignmentFlag.AlignCenter)
        screen = self.screen().availableGeometry()
        image.setPixmap(pixmap.scaled(min(760, screen.width() - 120), min(700, screen.height() - 240),
                                      Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        inner.addWidget(image)
        layout.addWidget(frame, 1)
        buttons = QHBoxLayout()
        buttons.addStretch()
        back = QPushButton(tr("Back"))
        back.clicked.connect(dialog.reject)
        buttons.addWidget(back)
        scan = QPushButton(f"{tr('Scan')}  ·  {self.format_label()}")
        scan.setObjectName("primary")
        scan.setIcon(icon("scan", color="#ffffff"))
        scan.setDefault(True)
        scan.clicked.connect(dialog.accept)
        buttons.addWidget(scan)
        layout.addLayout(buttons)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.start_scan(source="glass")

    def start_scan(self, kind=None, source=None):
        kind = kind or self.save_format()
        if self.device.currentData() is None or self.busy():
            return
        if self.scanner_in_use_elsewhere():
            return
        stamp = datetime.now().strftime("Scan-%Y%m%d-%H%M%S")
        if self.ask_name.isChecked():
            folder = Path(self.settings.value("last_folder", str(self.output_folder())))
            if not folder.is_dir():
                folder = Path.home()
            suffix = ".jpg" if kind == "jpg" else ".pdf"
            pattern = "JPG (*.jpg)" if kind == "jpg" else "PDF (*.pdf)"
            filename, _ = QFileDialog.getSaveFileName(self, tr("Save scan"), str(folder / (stamp + suffix)), pattern)
            if not filename:
                return
            base = Path(filename)
            base = base.with_suffix("") if base.suffix.lower() in (".pdf", ".jpg", ".jpeg", ".docx") else base
            self.settings.setValue("last_folder", str(base.parent))
            replace = True
            if self.scanner_in_use_elsewhere():
                return
        else:
            folder = self.output_folder()
            try:
                folder.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                self.set_status(tr("Could not create {folder}. {error}\nChoose another folder in Settings › Scanning.",
                                   folder=folder, error=exc), "error")
                return
            base = folder / stamp
            replace = False
        source = source or self.source.currentData()
        # Word always needs the text, so it turns OCR on for that scan.
        doc = self.doc_format()
        ocr = self.ocr_languages() if self.ocr_on.isChecked() or doc else []
        self.job = {"kind": kind, "base": base, "replace": replace, "auto": source == "auto",
                    "source": "feeder" if source == "auto" else source, "ocr": ocr, "doc": doc}
        name, driver = self.device.currentData()
        self.settings.setValue("device", name)
        self.settings.setValue("driver", driver)
        self.ensure_ocr(ocr, self.run_scan_attempt)

    def ensure_ocr(self, languages, then):
        """Download missing OCR languages through NAPS2 (one time), then continue."""
        installed = set(str(self.settings.value("ocr_installed", "")).split(","))
        missing = [code for code in languages if code not in installed]
        backend = get_backend()
        if not missing or not backend:
            then()
            return
        self.installing_ocr = True
        self.set_status(tr("Downloading OCR languages ({langs}). One time only…", langs=", ".join(missing)), "busy")
        self.update_controls()
        self.update_led()

        def work():
            failed = []
            for code in missing:
                try:
                    if install_ocr_offline(code, backend):
                        continue
                except (OSError, ValueError):
                    pass
                try:
                    result = run_hidden(backend + ["--install", f"ocr-{code}"], capture_output=True, timeout=600)
                    if result.returncode:
                        failed.append(code)
                except (OSError, subprocess.TimeoutExpired):
                    failed.append(code)
            return failed

        def done(ok, failed):
            self.installing_ocr = False
            failed = failed if ok else missing
            good = installed | {c for c in missing if c not in failed}
            self.settings.setValue("ocr_installed", ",".join(sorted(c for c in good if c)))
            if failed and self.job:
                self.job["ocr"] = [c for c in self.job["ocr"] if c not in failed]
                self.set_status(tr("OCR languages could not be installed ({langs}). Scanning without OCR.",
                                   langs=", ".join(failed)), "error")
            self.update_controls()
            if self.job:
                then()

        self.background(work, done)

    def run_scan_attempt(self):
        job = self.job
        if not job or self.device.currentData() is None:
            self.clear_pending()
            return
        self.pending = job["base"].parent / f".scan-{uuid4().hex}.pdf"
        where = {"glass": tr("the flatbed"), "feeder": tr("the document feeder"),
                 "duplex": tr("the document feeder (both sides)")}[job["source"]]
        message = tr("Scanning from {where}… Keep the scanner on until the file is saved.", where=where)
        if job["ocr"]:
            message += tr(" Recognising text (OCR)…")
        self.run_job(self.scan_args(self.pending, job["source"], ocr=job["ocr"]), message)

    def finished(self, code, exit_status):
        self.presence.release()
        output = decode(self.process.readAllStandardOutput())
        error = decode(self.process.readAllStandardError())
        driver = self.job_device[1] if self.job_device else ""
        produced = bool(self.pending and self.pending.is_file() and self.pending.stat().st_size)
        failed = code or exit_status != QProcess.ExitStatus.NormalExit
        if (not self.cancelled and not self.previewing and self.job and self.job["auto"]
                and self.job["source"] == "feeder" and (failed or not produced)):
            self.clear_temp()
            self.job["source"] = "glass"
            self.run_scan_attempt()
            return
        if self.cancelled:
            self.set_status(tr("Scan cancelled."), "info")
        elif failed:
            detail = (error or output or f"NAPS2 exited with code {code}.")[-700:]
            lowered = detail.lower()
            if any(word in lowered for word in ("busy", "in use", "being used")):
                self.waiting_for_free = True
                self.set_status(tr("The scanner is busy. Someone else may be using it. Wait a moment, then try again."),
                                "error")
            elif "canon" in normalize(self.job_device[0] if self.job_device else "") and (
                    "not found" in lowered or "offline" in lowered or "communicat" in lowered):
                self.set_status(tr("Windows could not reach the Canon scanner. Turn it on, make sure it is on the same Wi-Fi, and check it in Canon IJ Scan Utility, then retry."),
                                "error")
            elif WINDOWS and "offline" in lowered and driver == "twain":
                self.set_status(tr("Epson Scan 2 could not open the scanner. In Epson Scan 2 Utility, add or test its network address, then retry."),
                                "error")
            else:
                self.set_status(tr("Scanner operation failed. {detail}", detail=detail), "error")
        elif self.previewing:
            pixmap = QPixmap(str(self.pending)) if self.pending else QPixmap()
            if pixmap.isNull():
                self.set_status(tr("No preview was produced. Check the flatbed and scanner connection."), "error")
            else:
                self.set_status(tr("Preview ready."), "ok")
                self.clear_pending()
                QTimer.singleShot(0, lambda: self.show_preview(pixmap))
                return
        elif self.job is not None:
            self.deliver()
        self.clear_pending()

    def deliver(self):
        job = self.job
        base = job["base"]
        try:
            if not self.pending or not self.pending.is_file() or not self.pending.stat().st_size:
                raise OSError(tr("No pages were scanned. Check the paper and the scanner connection."))
            text = ""
            if job["ocr"]:
                try:
                    text = pdf_text(self.pending)
                except Exception:
                    text = ""
            outputs = []
            if job["kind"] in ("jpg", "both"):
                jpg_base = base if job["replace"] else unique_path(base.with_suffix(".jpg")).with_suffix("")
                outputs += export_jpgs(self.pending, jpg_base, self.dpi.currentData())
            doc_file = None
            if job.get("doc"):
                doc_file = base.with_suffix("." + job["doc"])
                doc_file = doc_file if job["replace"] else unique_path(doc_file)
                (export_docx if job["doc"] == "docx" else export_odt)(self.pending, doc_file, base.name)
            if job["kind"] in ("pdf", "both"):
                pdf = base.with_suffix(".pdf")
                pdf = pdf if job["replace"] else unique_path(pdf)
                self.pending.replace(pdf)
                outputs.insert(0, pdf)
            if doc_file:
                outputs.append(doc_file)
            text_base = outputs[0].with_suffix("") if outputs else base
            if text and self.save_txt.isChecked():
                txt = unique_path(text_base.with_suffix(".txt"))
                txt.write_text(text, encoding="utf-8")
                outputs.append(txt)
        except ImportError as exc:
            needs = "python-docx" if "docx" in str(exc) else "PyMuPDF"
            self.set_status(tr("Word export needs python-docx. Close and reopen the app to install it.")
                            if needs == "python-docx" else
                            tr("JPG export needs PyMuPDF. Close and reopen the app to install it."), "error")
            return
        except Exception as exc:
            message = tr("Could not save the scan. {error}", error=exc)
            if self.pending and self.pending.is_file() and job["kind"] != "jpg":
                kept = unique_path(base.with_suffix(".pdf"))
                try:
                    self.pending.replace(kept)
                    message += "\n" + tr("The scan was kept as {path}", path=kept)
                except OSError:
                    pass
            self.set_status(message, "error")
            return
        self.last_outputs = outputs
        self.last_text = text
        self.last_text_base = text_base
        pdfs = [p for p in outputs if p.suffix == ".pdf"]
        jpgs = [p for p in outputs if p.suffix == ".jpg"]
        parts = []
        if pdfs:
            parts.append(pdfs[0].name)
        if jpgs:
            parts.append(jpgs[0].name if len(jpgs) == 1 else tr("{count} JPG pages", count=len(jpgs)))
        parts += [p.name for p in outputs if p.suffix in (".docx", ".odt")]
        if any(p.suffix == ".txt" for p in outputs):
            parts.append(tr("text"))
        self.set_status(tr("✓ Saved {files} in {folder}", files=" + ".join(parts), folder=outputs[0].parent.name),
                        "ok")
        if self.open_after.isChecked():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(outputs[0])))
        target = self.auto_translate.currentData()
        if text and target:
            self.translate_to_file(text, target, text_base)

    def translate_to_file(self, text, target, base):
        self.set_status(f"{self.status_text()}\n" + tr("Translating the text to {lang}…", lang=lang_name(target)), "ok")
        engine, server, key = self.engine.currentData(), self.libre_url.text().strip(), self.libre_key.text().strip()

        def done(ok, value):
            if not ok:
                self.set_status(tr("Translation failed. {error}", error=value), "error")
                return
            translation, detected, used = value
            path = unique_path(base.with_name(f"{base.name}-{target}.txt"))
            try:
                path.write_text(translation, encoding="utf-8")
            except OSError as exc:
                self.set_status(tr("Translation failed. {error}", error=exc), "error")
                return
            self.last_outputs.append(path)
            self.set_status(tr("✓ Translation saved: {name}", name=path.name) + f"  ({used})", "ok")

        self.background(lambda: translate_text(text, target, "auto", engine, server, key), done)

    # ---------- text & translation window ----------
    def show_text(self):
        if not self.last_text and self.last_outputs:
            pdf = next((p for p in self.last_outputs if p.suffix == ".pdf" and p.exists()), None)
            if pdf:
                try:
                    self.last_text = pdf_text(pdf)
                except Exception:
                    pass
        dialog = QDialog(self)
        name = self.last_outputs[0].name if self.last_outputs else ""
        dialog.setWindowTitle(tr("Text of {name}", name=name) if name else tr("Text"))
        dialog.resize(980, 620)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(22, 18, 22, 18)
        layout.setSpacing(14)
        top = QHBoxLayout()
        heading = QVBoxLayout()
        heading.setSpacing(2)
        title = QLabel(tr("Text & translation"))
        title.setObjectName("pageTitle")
        heading.addWidget(title)
        subtitle = QLabel(name or tr("Text"))
        subtitle.setObjectName("hint")
        heading.addWidget(subtitle)
        top.addLayout(heading, 1)
        layout.addLayout(top)

        toolbar = QFrame()
        toolbar.setObjectName("card")
        bar = QHBoxLayout(toolbar)
        bar.setContentsMargins(14, 10, 14, 10)
        bar.setSpacing(10)
        source = QComboBox()
        source.addItem(tr("Auto-detect"), "auto")
        target = QComboBox()
        for code in LANG_NAMES:
            source.addItem(lang_name(code), code)
            target.addItem(lang_name(code), code)
        default_target = self.auto_translate.currentData() or ("el" if UI_LANG == "el" else "en")
        target.setCurrentIndex(max(0, target.findData(default_target)))
        engine = self.choice(None, "Translation service", ENGINES, "engine")
        go = QPushButton(tr("Translate"))
        go.setObjectName("primary")
        go.setIcon(icon("translate", color="#ffffff"))
        for widget in (QLabel(tr("From")), source, QLabel("→"), QLabel(tr("To")), target, engine):
            bar.addWidget(widget)
        bar.addStretch()
        bar.addWidget(go)
        layout.addWidget(toolbar)

        panes = QHBoxLayout()
        panes.setSpacing(14)
        original = QPlainTextEdit(self.last_text or "")
        original.setPlaceholderText(tr("No text yet. Turn on OCR in Settings › Text & translation, then scan again."))
        translated = QPlainTextEdit()
        for heading_text, editor in ((tr("Recognised text"), original), (tr("Translation"), translated)):
            card = QFrame()
            card.setObjectName("card")
            column = QVBoxLayout(card)
            column.setContentsMargins(14, 12, 14, 14)
            column.setSpacing(8)
            head = QLabel(heading_text)
            head.setObjectName("cardTitle")
            column.addWidget(head)
            column.addWidget(editor, 1)
            panes.addWidget(card, 1)
        layout.addLayout(panes, 1)

        bottom = QHBoxLayout()
        info = QLabel()
        info.setObjectName("hint")
        guess = guess_language(original.toPlainText())
        if guess:
            info.setText(tr("Detected language: {lang}", lang=lang_name(guess)))
        bottom.addWidget(info, 1)
        copy = QPushButton(tr("Copy"))
        copy.setIcon(icon("copy"))
        save = QPushButton(tr("Save .txt"))
        save.setIcon(icon("save"))
        close = QPushButton(tr("Close"))
        for button in (copy, save, close):
            bottom.addWidget(button)
        layout.addLayout(bottom)

        def run_translation():
            text = original.toPlainText().strip()
            if not text:
                return
            go.setEnabled(False)
            used = engine.currentData()
            info.setText(tr("Translating with {engine}…", engine=ENGINE_NAMES[used]))

            def done(ok, value):
                go.setEnabled(True)
                if not ok:
                    info.setText(tr("Translation failed. {error}", error=value))
                    return
                result, detected, name_used = value
                translated.setPlainText(result)
                info.setText(tr("Translated with {engine}. Detected: {lang}.", engine=name_used,
                                lang=lang_name(detected)))

            self.background(lambda: translate_text(text, target.currentData(), source.currentData(), used,
                                                   self.libre_url.text().strip(), self.libre_key.text().strip()), done)

        def copy_text():
            QGuiApplication.clipboard().setText(translated.toPlainText() or original.toPlainText())
            info.setText(tr("Copied."))

        def save_text():
            base = self.last_text_base or (self.output_folder() / datetime.now().strftime("Scan-%Y%m%d-%H%M%S"))
            if translated.toPlainText().strip():
                path = unique_path(base.with_name(f"{base.name}-{target.currentData()}.txt"))
                content = translated.toPlainText()
            else:
                path = unique_path(base.with_suffix(".txt"))
                content = original.toPlainText()
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
                info.setText(tr("Saved {name}", name=path.name))
            except OSError as exc:
                info.setText(str(exc))

        go.clicked.connect(run_translation)
        copy.clicked.connect(copy_text)
        save.clicked.connect(save_text)
        close.clicked.connect(dialog.accept)
        self.text_dialog = dialog
        dialog.show()

    # ---------- misc ----------
    def process_error(self, error):
        if error == QProcess.ProcessError.FailedToStart:
            self.presence.release()
            self.set_status(tr("Could not start NAPS2. {error}", error=self.process.errorString()), "error")
            self.clear_pending()

    def clear_temp(self):
        if self.pending:
            try:
                self.pending.unlink(missing_ok=True)
            except OSError:
                pass
        self.pending = None

    def clear_pending(self):
        self.clear_temp()
        self.previewing = False
        self.job = None
        self.job_device = None
        self.update_controls()
        self.update_led()

    def cancel_scan(self):
        if self.scanning():
            self.cancelled = True
            self.process.kill()
        elif self.discoveries:
            self.stop_discovery()

    def open_last(self):
        existing = [path for path in self.last_outputs if path.exists()]
        if existing:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(existing[0])))

    def open_output_folder(self):
        folder = self.last_outputs[0].parent if self.last_outputs else self.output_folder()
        folder.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))

    def closeEvent(self, event):
        if self.scanning():
            answer = QMessageBox.question(self, tr("Scan in progress"),
                                          tr("A scan is running. Cancel it and close the app?"))
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self.cancelled = True
            self.process.kill()
            self.process.waitForFinished(3000)
        for process in list(self.discoveries):
            process.finished.disconnect()
            process.errorOccurred.disconnect()
            process.kill()
            process.waitForFinished(1000)
        self.discoveries.clear()
        self.presence.stop()
        self.settings_dialog.close()
        if self.text_dialog:
            self.text_dialog.close()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setApplicationName(APP_NAME)
    app.setWindowIcon(app_icon())
    store = QSettings("LocalTools", "EpsonNetworkScan")
    UI_LANG = resolve_ui_language(store.value("ui_lang", "auto"))
    apply_theme(store.value("theme", "auto"))
    hints = QGuiApplication.styleHints()
    if hasattr(hints, "colorSchemeChanged"):
        hints.colorSchemeChanged.connect(
            lambda *_: apply_theme("auto") if store.value("theme", "auto") == "auto" else None)
    clean_old_update()
    window = Scanner()
    window.resize(900, 520)
    window.show()
    QTimer.singleShot(0, window.startup)
    sys.exit(app.exec())

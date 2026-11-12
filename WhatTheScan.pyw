import os
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import ctypes
import getpass
import hashlib
import json
import mimetypes
import platform
import re
import secrets
import socket
import ssl
import struct
import time
import subprocess
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from concurrent.futures import ThreadPoolExecutor
from queue import Empty, Queue

VERSION = "1.0.11"
# Change this one line to rename the app everywhere.
APP_NAME = "What the Scan?!"
APP_TAGLINE = "Scanner busy? Now you know who."
BRANDS = "Epson, Canon, HP & Brother"
WINDOWS = sys.platform == "win32"
MAC = sys.platform == "darwin"
LINUX = sys.platform.startswith("linux")
HIDDEN = getattr(subprocess, "CREATE_NO_WINDOW", 0)
# True when running as the built Windows .exe or Linux binary (PyInstaller).
FROZEN = bool(getattr(sys, "frozen", False))
# Release file names: the .exe / Linux binary built by GitHub Actions, or the .pyw script.
RELEASE_ASSET = ("WhatTheScan-windows-x64.exe" if WINDOWS else
                 "WhatTheScan-linux-x64" if LINUX else
                 f"WhatTheScan-macos-{'arm64' if platform.machine() == 'arm64' else 'x64'}.zip"
                 ) if FROZEN else "WhatTheScan.pyw"
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
# Release checks: set to a file path and the app writes its progress there, opens the window, looks for
# scanners, writes "OK window started" and closes by itself (no dialogs, no update check).
SMOKE_FILE = os.environ.get("WHATTHESCAN_SMOKE_TEST", "")


def smoke(line):
    if SMOKE_FILE:
        try:
            with open(SMOKE_FILE, "a", encoding="utf-8") as out:
                out.write(f"{line}\n")
        except OSError:
            pass
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
    "win-x64.exe": "684e26d2145bceab5199971b8620dd715cbeb824ecdc080fe122912b1486da22",
    "win-arm64.exe": "b646a4d85a4d59208f21466a0ced4de29663f852f87462921265c67813f98a5b",
}
PYTHON_WIN_URL = "https://www.python.org/ftp/python/3.14.10/python-3.14.10-{arch}.exe"
PIP_PACKAGES = ("PyQt6>=6.6,<7", "PyMuPDF>=1.24,<2", "python-docx>=1.1", "certifi", "segno>=1.6", "cryptography>=42")
# NAPS2's own OCR language packs (tesseract 4 data) and their published SHA-256 checksums.
OCR_URL = "https://github.com/cyanfish/naps2-components/releases/download/tesseract-4.0.0b4/{code}.traineddata.zip"
OCR_SHA256 = {
    "ces": "fd9eb6ec0e646f48c2786bdc508b8a9e59d3d1ca034eff1dfbc930e1864fe9ba",
    "jpn": "7ce9a993f7fb67099483d126820352768001ca356975ba4a691c23fe7c3e2245",
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
    "HP Smart Tank": ("520", "525", "580", "585", "720", "750", "790", "5101", "5105", "5106", "6001",
                      "6005", "6006", "7001", "7005", "7006", "7301", "7305", "7306", "7602", "7605"),
    "HP ScanJet Pro": ("2000 s2", "2600 f1", "3000 s4", "3600 f1", "N4000 snw1", "N4600 fnw1"),
    "HP ScanJet Enterprise Flow": ("5000 s5", "7000 s3", "N6600 fnw1", "N7000 snw1", "9000 s1", "N9120 fn2"),
    # Brother all-in-ones and scanners launched from 2024. They scan over the network with no driver
    # (AirPrint / eSCL), or with Brother's driver package (TWAIN / WIA, brscan on Linux).
    "Brother · 2024 · laser": ("MFC-L2800DW", "MFC-L2820DW", "MFC-L2880DW", "MFC-L2900DW", "MFC-L2920DW",
                               "MFC-L2960DW", "MFC-L2980DW", "DCP-L2640DW", "HL-L2480DW", "DCP-L5510DW",
                               "MFC-L5710DN", "MFC-L5710DW", "MFC-L5915DW", "MFC-L6710DW", "MFC-L6910DN"),
    "Brother · 2024 · colour laser": ("DCP-L3520CDW", "DCP-L3560CDW", "MFC-L3755CDW", "MFC-L3760CDW",
                                      "MFC-L8390CDW"),
    "Brother · 2025": ("MFC-J4355DW", "MFC-J4555DW", "MFC-J6760DW", "MFC-J6960DW", "MFC-L8730CDW",
                       "MFC-L8930CDW", "MFC-EX575", "DCP-J1260W"),
    "Brother · 2026": ("MFC-J3660DW", "MFC-J3960DW", "MFC-J6560DW", "MFC-J6975DW"),
    "Brother · ADS scanners": ("ADS-1300", "ADS-1800W"),
}
# Names the drivers report for a model, when they differ from the model name.
# Canon drivers call the TS3150 "TS3100 series".
# Paper sources a model has, when known: glass (flatbed), feeder (ADF), duplex (ADF both sides).
# Scanners on the network report this themselves (eSCL), which takes priority.
MODEL_SOURCES = {
    "HP Smart Tank 750": ("glass", "feeder"),
    "HP Smart Tank 7001": ("glass",),
    "HP Smart Tank 7005": ("glass",),
    "Canon PIXMA TS3150": ("glass",),
    "Brother ADS-1300": ("feeder", "duplex"),
    "Brother ADS-1800W": ("feeder", "duplex"),
}
MODEL_ALIASES = {
    "PIXMA TS3150": ("ts3100", "ts3150", "ts3151", "ts3152"),
}
# Official driver installers the app can download, verify (Authenticode) and run on Windows.
# "check" is a file the driver leaves behind; without one the app asks before installing.
DRIVER_PACKAGES = {
    "L14150": {
        "label": "Epson L14150 driver (Epson Scan 2)",
        # Epson Download Center, Europe (Greece): "Scanner Driver and Epson Scan 2 Utility" 6.7.70.0.
        "url": "https://download3.ebz.epson.net/dsc/f/03/00/16/20/65/0356115901ee788b1381abd50372549c13943fac/"
               "EpsonScan2_L14150_67700_41_Signed.exe",
        # Same driver version from Epson's Latin America server, used if the first one cannot be reached.
        "mirrors": ("https://ftp.epson.com/latin/drivers/inkjet/L14150_EScan2_67700_LA.exe",),
        "signer": "Epson",  # Authenticode publisher must be valid and contain "Epson" (Seiko Epson / Epson America)
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
GUIDES = {
    'en': """HOW TO SCAN (3 steps)
  1. Turn on the scanner and load the paper (glass or document feeder).
  2. Check that the top card says  ✓ Connected to <your scanner>.
  3. Click  Scan.  It saves as PDF, JPG or PDF + JPG, as chosen in
     Settings › Scanning (PDF by default). Tick "Also save an editable document"
     there for Word (.docx) or OpenDocument (.odt).
     Files go to Documents › What the Scan.

BUTTONS
  Preview     quick look at the glass before scanning
  Phone       send the scan to your phone, or receive photos from it
  Text        recognised text (OCR), copy and translate
  Open last / Open folder

Everything is automatic by default:
  • The app finds every scanner on all drivers by itself (TWAIN, WIA, eSCL…).
    If a scanner answers on the network but its driver is missing, the app
    offers to install the official driver.
  • Paper source "Auto": document feeder if it has paper, otherwise the glass.
  • OCR: English + Greek + your system language; languages download the first time.
  • Translation: Google Translate (free), MyMemory as a fallback.

PHONE (same Wi-Fi)
  • Phones with the free LocalSend app appear by themselves: pick one, press Send.
  • No LocalSend? Scan the QR code: a page opens to download the scan or send photos.
  • From the phone: in LocalSend choose "What the Scan · <this PC>", or use the QR page.
  • On a Mac, AirDrop sends the scan to an iPhone or another Mac.

STATUS LIGHT
  ● Green   Ready. The scanner is free.
  ● Yellow  Idle. Searching, no scanner, or the scanner is on standby.
  ● Red     In use. You or someone else on the network is scanning.
            Wait for green; the app beeps when the scanner is free.

SHORTCUTS
  Ctrl+S scan   Ctrl+P preview   Ctrl+T text   F5 search again
  Ctrl+, settings   F1 this guide   Esc cancel

OFFLINE INSTALLATION
  Put WhatTheScan-offline.zip (from the GitHub release) next to the app: NAPS2,
  Python packages, drivers and OCR languages install from it with no internet.

DRIVERS
  Epson: Epson Scan 2.  Canon: MP Drivers.  HP (incl. Smart Tank): works over the
  network with no driver (AirPrint / eSCL).  macOS: Image Capture.  Linux: SANE.
  Brother (2024+ MFC / DCP / ADS): over the network with no driver (AirPrint / eSCL),
  or with Brother's Full Driver & Software Package (TWAIN / WIA).""",
    'el': """ΠΩΣ ΣΑΡΩΝΩ (3 βήματα)
  1. Άναψε τον σαρωτή και βάλε το χαρτί (στο τζάμι ή στον τροφοδότη).
  2. Έλεγξε ότι η πάνω κάρτα γράφει  ✓ Συνδέθηκε με <σαρωτής σου>.
  3. Πάτα  Σάρωση.  Αποθηκεύει ως PDF, JPG ή PDF + JPG, όπως έχεις διαλέξει στις
     Ρυθμίσεις › Σάρωση (PDF από προεπιλογή). Τσέκαρε εκεί «επεξεργάσιμο έγγραφο»
     για Word (.docx) ή OpenDocument (.odt).
     Τα αρχεία μπαίνουν στα Έγγραφα › What the Scan.

ΚΟΥΜΠΙΑ
  Προεπισκόπηση   γρήγορη ματιά στο τζάμι πριν τη σάρωση
  Κινητό          στείλε τη σάρωση στο κινητό ή πάρε φωτογραφίες από αυτό
  Κείμενο         το κείμενο που αναγνωρίστηκε (OCR), αντιγραφή και μετάφραση
  Τελευταίο / Φάκελος

Όλα είναι αυτόματα από προεπιλογή:
  • Η εφαρμογή βρίσκει μόνη της κάθε σαρωτή σε όλους τους drivers.
    Αν ένας σαρωτής απαντά στο δίκτυο αλλά λείπει ο driver του, προτείνει
    εγκατάσταση του επίσημου driver.
  • Πηγή χαρτιού «Αυτόματα»: τροφοδότης αν έχει χαρτί, αλλιώς τζάμι.
  • OCR: Αγγλικά + Ελληνικά + η γλώσσα του συστήματος· κατεβαίνουν την πρώτη φορά.
  • Μετάφραση: Google Translate (δωρεάν), με εφεδρεία το MyMemory.

ΚΙΝΗΤΟ (ίδιο Wi-Fi)
  • Τα κινητά με τη δωρεάν εφαρμογή LocalSend εμφανίζονται μόνα τους: διάλεξε, «Αποστολή».
  • Χωρίς LocalSend; Σκάναρε το QR code: ανοίγει σελίδα για λήψη ή αποστολή φωτογραφιών.
  • Από το κινητό: στο LocalSend διάλεξε «What the Scan · <αυτό το PC>» ή τη σελίδα του QR.
  • Σε Mac, το AirDrop στέλνει τη σάρωση σε iPhone ή άλλο Mac.

ΦΩΤΑΚΙ ΚΑΤΑΣΤΑΣΗΣ
  ● Πράσινο   Έτοιμο. Ο σαρωτής είναι ελεύθερος.
  ● Κίτρινο   Αναμονή. Αναζήτηση, κανένας σαρωτής ή ο σαρωτής σε αναμονή.
  ● Κόκκινο   Σε χρήση. Σαρώνεις εσύ ή κάποιος άλλος στο δίκτυο.
              Περίμενε το πράσινο· η εφαρμογή κάνει ήχο όταν ελευθερωθεί.

ΣΥΝΤΟΜΕΥΣΕΙΣ
  Ctrl+S σάρωση   Ctrl+P προεπισκόπηση   Ctrl+T κείμενο   F5 νέα αναζήτηση
  Ctrl+, ρυθμίσεις   F1 οδηγός   Esc ακύρωση

ΕΓΚΑΤΑΣΤΑΣΗ ΧΩΡΙΣ INTERNET
  Βάλε το WhatTheScan-offline.zip (από το release στο GitHub) δίπλα στην εφαρμογή:
  NAPS2, πακέτα Python, drivers και γλώσσες OCR εγκαθίστανται από εκεί.

DRIVERS
  Epson: Epson Scan 2.  Canon: MP Drivers.  HP (και Smart Tank): δουλεύει μέσω
  δικτύου χωρίς driver (AirPrint / eSCL).  macOS: Image Capture.  Linux: SANE.
  Brother (MFC / DCP / ADS από 2024): μέσω δικτύου χωρίς driver (AirPrint / eSCL)
  ή με το Full Driver & Software Package της Brother (TWAIN / WIA).""",
    'fr': """NUMÉRISER (3 étapes)
  1. Allumez le scanner et placez le papier (vitre ou chargeur de documents).
  2. Vérifiez que la carte du haut indique  ✓ Connecté à <votre scanner>.
  3. Cliquez sur  Numériser.  Enregistre en PDF, JPG ou PDF + JPG, selon
     Paramètres › Numérisation (PDF par défaut). Cochez « document modifiable »
     pour Word (.docx) ou OpenDocument (.odt).
     Les fichiers vont dans Documents › What the Scan.

BOUTONS
  Aperçu      coup d’œil rapide sur la vitre avant de numériser
  Téléphone   envoyer la numérisation au téléphone, ou en recevoir des photos
  Texte       texte reconnu (OCR), copier et traduire
  Dernier fichier / Dossier

Tout est automatique par défaut :
  • L’application trouve seule chaque scanner, sur tous les pilotes.
    Si un scanner répond sur le réseau mais que son pilote manque,
    elle propose d’installer le pilote officiel.
  • Source du papier « Auto » : chargeur s’il contient du papier, sinon vitre.
  • OCR : anglais + grec + la langue du système ; téléchargé la première fois.
  • Traduction : Google Traduction (gratuit), MyMemory en secours.

TÉLÉPHONE (même Wi-Fi)
  • Les téléphones avec l’application gratuite LocalSend apparaissent seuls : choisissez, Envoyer.
  • Pas de LocalSend ? Scannez le code QR : une page s’ouvre pour télécharger ou envoyer des photos.
  • Depuis le téléphone : dans LocalSend, choisissez « What the Scan · <ce PC> » ou la page QR.
  • Sur Mac, AirDrop envoie la numérisation vers un iPhone ou un autre Mac.

VOYANT D’ÉTAT
  ● Vert    Prêt. Le scanner est libre.
  ● Jaune   Inactif. Recherche, aucun scanner, ou scanner en veille.
  ● Rouge   Occupé. Vous ou quelqu’un d’autre sur le réseau numérise.
            Attendez le vert ; l’application émet un bip quand il est libre.

RACCOURCIS
  Ctrl+S numériser   Ctrl+P aperçu   Ctrl+T texte   F5 rechercher
  Ctrl+, paramètres   F1 ce guide   Échap annuler

INSTALLATION HORS LIGNE
  Placez WhatTheScan-offline.zip (version GitHub) à côté de l’application : NAPS2,
  paquets Python, pilotes et langues OCR s’installent sans Internet.

PILOTES
  Epson : Epson Scan 2.  Canon : MP Drivers.  HP (y compris Smart Tank) : en réseau
  sans pilote (AirPrint / eSCL).  macOS : Transfert d’images.  Linux : SANE.
  Brother (MFC / DCP / ADS depuis 2024) : en réseau sans pilote (AirPrint / eSCL),
  ou avec le Full Driver & Software Package de Brother (TWAIN / WIA).""",
    'de': """SO SCANNEN SIE (3 Schritte)
  1. Scanner einschalten und Papier einlegen (Glasplatte oder Einzug).
  2. Prüfen Sie, dass oben  ✓ Verbunden mit <Ihr Scanner>  steht.
  3. Klicken Sie auf  Scannen.  Gespeichert wird als PDF, JPG oder PDF + JPG, wie
     unter Einstellungen › Scannen gewählt (Standard: PDF). Für Word (.docx) oder
     OpenDocument (.odt) dort „bearbeitbares Dokument“ ankreuzen.
     Die Dateien landen in Dokumente › What the Scan.

SCHALTFLÄCHEN
  Vorschau    schneller Blick auf die Glasplatte vor dem Scan
  Handy       Scan ans Handy senden oder Fotos davon empfangen
  Text        erkannter Text (OCR), kopieren und übersetzen
  Letzte öffnen / Ordner öffnen

Standardmäßig ist alles automatisch:
  • Die App findet jeden Scanner über alle Treiber selbst.
    Antwortet ein Scanner im Netzwerk, aber sein Treiber fehlt,
    bietet die App die Installation des offiziellen Treibers an.
  • Papierquelle „Auto“: Einzug, wenn Papier drin ist, sonst Glasplatte.
  • OCR: Englisch + Griechisch + Systemsprache; Download beim ersten Mal.
  • Übersetzung: Google Übersetzer (kostenlos), MyMemory als Ersatz.

HANDY (gleiches WLAN)
  • Handys mit der kostenlosen App LocalSend erscheinen von selbst: wählen, Senden.
  • Kein LocalSend? QR-Code scannen: eine Seite zum Herunterladen oder Senden von Fotos öffnet sich.
  • Vom Handy: in LocalSend „What the Scan · <dieser PC>“ wählen oder die QR-Seite nutzen.
  • Auf dem Mac sendet AirDrop den Scan an ein iPhone oder einen anderen Mac.

STATUSLICHT
  ● Grün    Bereit. Der Scanner ist frei.
  ● Gelb    Leerlauf. Suche, kein Scanner oder Scanner im Standby.
  ● Rot     Belegt. Sie oder jemand anderes im Netzwerk scannt.
            Warten Sie auf Grün; die App piept, wenn der Scanner frei ist.

TASTENKÜRZEL
  Strg+S scannen   Strg+P Vorschau   Strg+T Text   F5 erneut suchen
  Strg+, Einstellungen   F1 diese Anleitung   Esc abbrechen

OFFLINE-INSTALLATION
  WhatTheScan-offline.zip (aus dem GitHub-Release) neben die App legen: NAPS2,
  Python-Pakete, Treiber und OCR-Sprachen werden ohne Internet installiert.

TREIBER
  Epson: Epson Scan 2.  Canon: MP Drivers.  HP (auch Smart Tank): im Netzwerk ohne
  Treiber (AirPrint / eSCL).  macOS: Digitale Bilder.  Linux: SANE.
  Brother (MFC / DCP / ADS ab 2024): im Netzwerk ohne Treiber (AirPrint / eSCL)
  oder mit Brothers Full Driver & Software Package (TWAIN / WIA).""",
    'it': """COME ACQUISIRE (3 passi)
  1. Accendi lo scanner e inserisci la carta (piano o alimentatore).
  2. Controlla che la scheda in alto dica  ✓ Connesso a <il tuo scanner>.
  3. Fai clic su  Scansiona.  Salva in PDF, JPG o PDF + JPG, come scelto in
     Impostazioni › Scansione (PDF di default). Spunta «documento modificabile»
     per Word (.docx) o OpenDocument (.odt).
     I file vanno in Documenti › What the Scan.

PULSANTI
  Anteprima   rapida occhiata al piano prima di acquisire
  Telefono    invia la scansione al telefono o ricevi foto da esso
  Testo       testo riconosciuto (OCR), copia e traduci
  Apri ultimo / Apri cartella

Tutto è automatico di default:
  • L’app trova da sola ogni scanner, su tutti i driver.
    Se uno scanner risponde in rete ma manca il suo driver,
    l’app propone di installare il driver ufficiale.
  • Origine carta «Auto»: alimentatore se ha carta, altrimenti piano.
  • OCR: inglese + greco + lingua di sistema; scaricate la prima volta.
  • Traduzione: Google Traduttore (gratis), MyMemory come riserva.

TELEFONO (stessa Wi-Fi)
  • I telefoni con l’app gratuita LocalSend compaiono da soli: scegli, Invia.
  • Niente LocalSend? Scansiona il codice QR: si apre una pagina per scaricare o inviare foto.
  • Dal telefono: in LocalSend scegli «What the Scan · <questo PC>» o usa la pagina QR.
  • Su Mac, AirDrop invia la scansione a un iPhone o a un altro Mac.

SPIA DI STATO
  ● Verde    Pronto. Lo scanner è libero.
  ● Giallo   Inattivo. Ricerca, nessuno scanner o scanner in standby.
  ● Rosso    In uso. Tu o qualcun altro in rete state acquisendo.
             Attendi il verde; l’app emette un suono quando è libero.

SCORCIATOIE
  Ctrl+S scansiona   Ctrl+P anteprima   Ctrl+T testo   F5 cerca di nuovo
  Ctrl+, impostazioni   F1 questa guida   Esc annulla

INSTALLAZIONE OFFLINE
  Metti WhatTheScan-offline.zip (dalla release su GitHub) accanto all’app: NAPS2,
  pacchetti Python, driver e lingue OCR si installano senza Internet.

DRIVER
  Epson: Epson Scan 2.  Canon: MP Drivers.  HP (anche Smart Tank): in rete senza
  driver (AirPrint / eSCL).  macOS: Acquisizione Immagine.  Linux: SANE.
  Brother (MFC / DCP / ADS dal 2024): in rete senza driver (AirPrint / eSCL)
  o con il Full Driver & Software Package di Brother (TWAIN / WIA).""",
    'es': """CÓMO ESCANEAR (3 pasos)
  1. Enciende el escáner y coloca el papel (cristal o alimentador).
  2. Comprueba que la tarjeta superior diga  ✓ Conectado a <tu escáner>.
  3. Haz clic en  Escanear.  Guarda en PDF, JPG o PDF + JPG, según
     Ajustes › Escaneo (PDF por defecto). Marca «documento editable»
     para Word (.docx) u OpenDocument (.odt).
     Los archivos van a Documentos › What the Scan.

BOTONES
  Vista previa   vistazo rápido al cristal antes de escanear
  Móvil          envía el escaneo al móvil o recibe fotos de él
  Texto          texto reconocido (OCR), copiar y traducir
  Abrir último / Abrir carpeta

Todo es automático por defecto:
  • La app encuentra sola cada escáner, en todos los controladores.
    Si un escáner responde en la red pero falta su controlador,
    la app ofrece instalar el controlador oficial.
  • Origen del papel «Auto»: alimentador si tiene papel, si no, cristal.
  • OCR: inglés + griego + idioma del sistema; se descargan la primera vez.
  • Traducción: Google Traductor (gratis), MyMemory como respaldo.

MÓVIL (misma Wi-Fi)
  • Los móviles con la app gratuita LocalSend aparecen solos: elige uno, Enviar.
  • ¿Sin LocalSend? Escanea el código QR: se abre una página para descargar o enviar fotos.
  • Desde el móvil: en LocalSend elige «What the Scan · <este PC>» o usa la página QR.
  • En Mac, AirDrop envía el escaneo a un iPhone u otro Mac.

LUZ DE ESTADO
  ● Verde      Listo. El escáner está libre.
  ● Amarillo   Inactivo. Buscando, sin escáner o escáner en espera.
  ● Rojo       En uso. Tú u otra persona de la red está escaneando.
               Espera al verde; la app pita cuando queda libre.

ATAJOS
  Ctrl+S escanear   Ctrl+P vista previa   Ctrl+T texto   F5 buscar de nuevo
  Ctrl+, ajustes   F1 esta guía   Esc cancelar

INSTALACIÓN SIN CONEXIÓN
  Pon WhatTheScan-offline.zip (de la versión en GitHub) junto a la app: NAPS2,
  paquetes de Python, controladores e idiomas OCR se instalan sin Internet.

CONTROLADORES
  Epson: Epson Scan 2.  Canon: MP Drivers.  HP (incl. Smart Tank): en red sin
  controlador (AirPrint / eSCL).  macOS: Captura de Imagen.  Linux: SANE.
  Brother (MFC / DCP / ADS desde 2024): en red sin controlador (AirPrint / eSCL)
  o con el Full Driver & Software Package de Brother (TWAIN / WIA).""",
    'ro': """CUM SCANAȚI (3 pași)
  1. Porniți scannerul și puneți hârtia (pe geam sau în alimentator).
  2. Verificați că sus scrie  ✓ Conectat la <scannerul dvs.>.
  3. Faceți clic pe  Scanează.  Salvează ca PDF, JPG sau PDF + JPG, după
     Setări › Scanare (implicit PDF). Bifați acolo „document editabil”
     pentru Word (.docx) sau OpenDocument (.odt).
     Fișierele ajung în Documente › What the Scan.

BUTOANE
  Previzualizare   privire rapidă pe geam înainte de scanare
  Telefon          trimiteți scanarea pe telefon sau primiți fotografii de la el
  Text             textul recunoscut (OCR), copiere și traducere
  Deschide ultimul / Deschide dosarul

Totul este automat implicit:
  • Aplicația găsește singură fiecare scanner, pe toate driverele.
    Dacă un scanner răspunde în rețea dar îi lipsește driverul,
    aplicația propune instalarea driverului oficial.
  • Sursa hârtiei „Auto”: alimentatorul dacă are hârtie, altfel geamul.
  • OCR: engleză + greacă + limba sistemului; se descarcă prima dată.
  • Traducere: Google Traducere (gratuit), MyMemory ca rezervă.

TELEFON (aceeași rețea Wi-Fi)
  • Telefoanele cu aplicația gratuită LocalSend apar singure: alegeți, Trimite.
  • Nu aveți LocalSend? Scanați codul QR: se deschide o pagină pentru descărcare sau trimitere poze.
  • De pe telefon: în LocalSend alegeți „What the Scan · <acest PC>” sau pagina QR.
  • Pe Mac, AirDrop trimite scanarea către un iPhone sau alt Mac.

LUMINA DE STARE
  ● Verde     Gata. Scannerul este liber.
  ● Galben    Inactiv. Căutare, niciun scanner sau scanner în așteptare.
  ● Roșu      Ocupat. Dvs. sau altcineva din rețea scanează.
              Așteptați verdele; aplicația emite un sunet când e liber.

SCURTĂTURI
  Ctrl+S scanare   Ctrl+P previzualizare   Ctrl+T text   F5 caută din nou
  Ctrl+, setări   F1 acest ghid   Esc anulare

INSTALARE OFFLINE
  Puneți WhatTheScan-offline.zip (din release-ul GitHub) lângă aplicație: NAPS2,
  pachetele Python, driverele și limbile OCR se instalează fără internet.

DRIVERE
  Epson: Epson Scan 2.  Canon: MP Drivers.  HP (inclusiv Smart Tank): în rețea fără
  driver (AirPrint / eSCL).  macOS: Captură imagine.  Linux: SANE.
  Brother (MFC / DCP / ADS din 2024): în rețea fără driver (AirPrint / eSCL)
  sau cu Full Driver & Software Package de la Brother (TWAIN / WIA).""",
    'cs': """JAK SKENOVAT (3 kroky)
  1. Zapněte skener a vložte papír (na sklo nebo do podavače).
  2. Zkontrolujte, že horní karta ukazuje  ✓ Připojeno k <váš skener>.
  3. Klikněte na  Skenovat.  Uloží se jako PDF, JPG nebo PDF + JPG podle
     Nastavení › Skenování (výchozí PDF). Pro Word (.docx) nebo OpenDocument
     (.odt) tam zaškrtněte „upravitelný dokument“.
     Soubory se ukládají do Dokumenty › What the Scan.

TLAČÍTKA
  Náhled      rychlý pohled na sklo před skenováním
  Telefon     poslat sken do telefonu nebo z něj přijmout fotky
  Text        rozpoznaný text (OCR), kopírování a překlad
  Otevřít poslední / Otevřít složku

Vše je ve výchozím stavu automatické:
  • Aplikace sama najde každý skener přes všechny ovladače.
    Pokud skener odpovídá v síti, ale chybí jeho ovladač,
    aplikace nabídne instalaci oficiálního ovladače.
  • Zdroj papíru „Auto“: podavač, je-li v něm papír, jinak sklo.
  • OCR: angličtina + řečtina + jazyk systému; stáhne se poprvé.
  • Překlad: Překladač Google (zdarma), záložně MyMemory.

TELEFON (stejná Wi-Fi)
  • Telefony s bezplatnou aplikací LocalSend se objeví samy: vyberte, Odeslat.
  • Nemáte LocalSend? Naskenujte QR kód: otevře se stránka pro stažení nebo odeslání fotek.
  • Z telefonu: v LocalSend vyberte „What the Scan · <tento PC>“ nebo stránku z QR.
  • Na Macu pošle AirDrop sken do iPhonu nebo jiného Macu.

STAVOVÁ KONTROLKA
  ● Zelená    Připraveno. Skener je volný.
  ● Žlutá     Nečinný. Hledání, žádný skener nebo skener v pohotovosti.
  ● Červená   Používá se. Skenujete vy nebo někdo jiný v síti.
              Počkejte na zelenou; aplikace pípne, až bude volný.

ZKRATKY
  Ctrl+S skenovat   Ctrl+P náhled   Ctrl+T text   F5 hledat znovu
  Ctrl+, nastavení   F1 tento návod   Esc zrušit

INSTALACE BEZ INTERNETU
  Dejte WhatTheScan-offline.zip (z vydání na GitHubu) vedle aplikace: NAPS2,
  balíčky Pythonu, ovladače a jazyky OCR se nainstalují bez internetu.

OVLADAČE
  Epson: Epson Scan 2.  Canon: MP Drivers.  HP (i Smart Tank): po síti bez
  ovladače (AirPrint / eSCL).  macOS: Digitální fotografie.  Linux: SANE.
  Brother (MFC / DCP / ADS od 2024): po síti bez ovladače (AirPrint / eSCL)
  nebo s balíčkem Full Driver & Software Package od Brother (TWAIN / WIA).""",
    'ru': """КАК СКАНИРОВАТЬ (3 шага)
  1. Включите сканер и положите бумагу (на стекло или в податчик).
  2. Убедитесь, что вверху написано  ✓ Подключено к <ваш сканер>.
  3. Нажмите  Сканировать.  Сохраняется в PDF, JPG или PDF + JPG, как выбрано в
     Настройки › Сканирование (по умолчанию PDF). Для Word (.docx) или
     OpenDocument (.odt) отметьте там «редактируемый документ».
     Файлы сохраняются в Документы › What the Scan.

КНОПКИ
  Предпросмотр   быстрый взгляд на стекло перед сканированием
  Телефон        отправить скан на телефон или получить с него фото
  Текст          распознанный текст (OCR), копирование и перевод
  Последний файл / Открыть папку

По умолчанию всё автоматически:
  • Приложение само находит каждый сканер через все драйверы.
    Если сканер отвечает в сети, но нет его драйвера,
    приложение предложит установить официальный драйвер.
  • Источник бумаги «Авто»: податчик, если в нём есть бумага, иначе стекло.
  • OCR: английский + греческий + язык системы; скачиваются при первом запуске.
  • Перевод: Google Переводчик (бесплатно), запасной вариант MyMemory.

ТЕЛЕФОН (одна Wi-Fi)
  • Телефоны с бесплатным приложением LocalSend появляются сами: выберите, «Отправить».
  • Нет LocalSend? Отсканируйте QR-код: откроется страница для скачивания или отправки фото.
  • С телефона: в LocalSend выберите «What the Scan · <этот ПК>» или страницу QR.
  • На Mac AirDrop отправит скан на iPhone или другой Mac.

ИНДИКАТОР СОСТОЯНИЯ
  ● Зелёный   Готов. Сканер свободен.
  ● Жёлтый    Ожидание. Поиск, нет сканера или сканер в режиме ожидания.
  ● Красный   Занят. Сканируете вы или кто-то другой в сети.
              Дождитесь зелёного; приложение подаст сигнал, когда он освободится.

СОЧЕТАНИЯ КЛАВИШ
  Ctrl+S сканировать   Ctrl+P предпросмотр   Ctrl+T текст   F5 искать снова
  Ctrl+, настройки   F1 это руководство   Esc отмена

УСТАНОВКА БЕЗ ИНТЕРНЕТА
  Положите WhatTheScan-offline.zip (из выпуска на GitHub) рядом с приложением:
  NAPS2, пакеты Python, драйверы и языки OCR установятся без интернета.

ДРАЙВЕРЫ
  Epson: Epson Scan 2.  Canon: MP Drivers.  HP (включая Smart Tank): по сети без
  драйвера (AirPrint / eSCL).  macOS: Захват изображений.  Linux: SANE.
  Brother (MFC / DCP / ADS с 2024 г.): по сети без драйвера (AirPrint / eSCL)
  или с пакетом Brother Full Driver & Software Package (TWAIN / WIA).""",
    'ja': """スキャンの手順（3 ステップ）
  1. スキャナーの電源を入れ、用紙をセットします（原稿台または ADF）。
  2. 上のカードに  ✓ <スキャナー> に接続しました  と表示されていることを確認します。
  3. 「スキャン」をクリック。設定 › スキャン で選んだ形式（既定は PDF）で
     PDF、JPG、または PDF + JPG として保存します。Word (.docx) や
     OpenDocument (.odt) が必要なら「編集可能な文書」にチェックを入れます。
     ファイルは 書類 › What the Scan に保存されます。

ボタン
  プレビュー   スキャン前に原稿台をすばやく確認
  スマホ       スキャンをスマートフォンに送る／スマートフォンから写真を受け取る
  テキスト     認識したテキスト (OCR)、コピーと翻訳
  最後のファイル / フォルダーを開く

既定ではすべて自動です:
  • すべてのドライバーでスキャナーを自動で見つけます。
    ネットワーク上で応答するのにドライバーがない場合は、
    公式ドライバーのインストールを提案します。
  • 給紙「自動」: ADF に用紙があれば ADF、なければ原稿台。
  • OCR: 英語 + ギリシャ語 + システムの言語。初回に自動ダウンロード。
  • 翻訳: Google 翻訳（無料）、予備に MyMemory。

スマートフォン（同じ Wi-Fi）
  • 無料アプリ LocalSend のあるスマートフォンは自動で表示されます。選んで「送信」。
  • LocalSend がない場合: QR コードを読み取ると、ダウンロード／写真送信用のページが開きます。
  • スマートフォンから: LocalSend で「What the Scan · <この PC>」を選ぶか、QR ページを使います。
  • Mac では AirDrop で iPhone や別の Mac に送れます。

状態ランプ
  ● 緑   準備完了。スキャナーは空いています。
  ● 黄   待機中。検索中、スキャナーなし、またはスタンバイ。
  ● 赤   使用中。自分またはネットワーク上の誰かがスキャン中です。
         緑になるまでお待ちください。空くと音でお知らせします。

ショートカット
  Ctrl+S スキャン   Ctrl+P プレビュー   Ctrl+T テキスト   F5 再検索
  Ctrl+, 設定   F1 このガイド   Esc キャンセル

オフラインインストール
  WhatTheScan-offline.zip（GitHub のリリース）をアプリの隣に置くと、NAPS2、
  Python パッケージ、ドライバー、OCR 言語がインターネットなしでインストールされます。

ドライバー
  Epson: Epson Scan 2。Canon: MP Drivers。HP（Smart Tank を含む）: ドライバーなしで
  ネットワーク経由 (AirPrint / eSCL)。macOS: イメージキャプチャ。Linux: SANE。
  Brother（2024 年以降の MFC / DCP / ADS）: ドライバーなしでネットワーク経由 (AirPrint / eSCL)、
  または Brother の Full Driver & Software Package (TWAIN / WIA)。""",
    'zh': """如何扫描（3 步）
  1. 打开扫描仪并放好纸张（平板或自动进纸器）。
  2. 确认顶部卡片显示  ✓ 已连接到 <你的扫描仪>。
  3. 点击“扫描”。按 设置 › 扫描 中的选择保存为 PDF、JPG 或 PDF + JPG
     （默认 PDF）。如需 Word (.docx) 或 OpenDocument (.odt)，
     请在那里勾选“可编辑文档”。
     文件保存在 文档 › What the Scan。

按钮
  预览         扫描前快速查看平板
  手机         把扫描件发送到手机，或从手机接收照片
  文字         识别的文字 (OCR)，复制和翻译
  打开最近 / 打开文件夹

默认一切自动：
  • 应用会通过所有驱动自动查找每台扫描仪。
    如果扫描仪在网络上有响应但缺少驱动，
    应用会提示安装官方驱动。
  • 纸张来源“自动”：进纸器有纸时用进纸器，否则用平板。
  • OCR：英语 + 希腊语 + 系统语言；首次使用时自动下载。
  • 翻译：Google 翻译（免费），备用 MyMemory。

手机（同一 Wi-Fi）
  • 装有免费应用 LocalSend 的手机会自动出现：选择后点“发送”。
  • 没有 LocalSend？扫描二维码，会打开一个用于下载或发送照片的页面。
  • 从手机发送：在 LocalSend 中选择“What the Scan · <这台电脑>”，或使用二维码页面。
  • 在 Mac 上，可通过隔空投送 (AirDrop) 发送到 iPhone 或其他 Mac。

状态指示灯
  ● 绿色   就绪。扫描仪空闲。
  ● 黄色   空闲。正在搜索、没有扫描仪或扫描仪待机。
  ● 红色   使用中。你或网络上的其他人正在扫描。
           请等待变绿；扫描仪空闲时应用会发出提示音。

快捷键
  Ctrl+S 扫描   Ctrl+P 预览   Ctrl+T 文字   F5 重新搜索
  Ctrl+, 设置   F1 本指南   Esc 取消

离线安装
  将 WhatTheScan-offline.zip（GitHub 发布页）放在应用旁边：NAPS2、
  Python 包、驱动和 OCR 语言都会在无网络情况下安装。

驱动
  Epson：Epson Scan 2。Canon：MP Drivers。HP（含 Smart Tank）：无需驱动即可通过
  网络使用 (AirPrint / eSCL)。macOS：图像捕捉。Linux：SANE。
  Brother（2024 年起的 MFC / DCP / ADS）：无需驱动即可通过网络使用 (AirPrint / eSCL)，
  或使用 Brother 的 Full Driver & Software Package (TWAIN / WIA)。""",
}


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


def _dns_name(data, offset):
    """Read a (possibly compressed) DNS name. Returns (labels, offset after the name)."""
    labels, jumped, end, guard = [], False, offset, 0
    while offset < len(data) and guard < 64:
        guard += 1
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            jumped, offset = True, pointer
            continue
        labels.append(data[offset + 1: offset + 1 + length].decode("utf-8", "replace"))
        offset += 1 + length
    return labels, (end if jumped else offset)


def discover_mdns(timeout=2.0):
    """Find network scanners that announce eSCL (AirPrint/Mopria scanning) over mDNS: HP, Canon, Epson,
    Brother… Returns {ip: device name}."""
    services = ("_uscan._tcp.local", "_uscans._tcp.local")
    query = struct.pack("!HHHHHH", 0, 0, len(services), 0, 0, 0)
    for service in services:
        query += b"".join(bytes([len(p)]) + p.encode() for p in service.split(".")) + b"\0"
        query += struct.pack("!HH", 12, 1)  # PTR, IN
    found = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        try:
            sock.sendto(query, ("224.0.0.251", 5353))  # legacy unicast query: replies come to this port
        except OSError:
            return found
        deadline = time.monotonic() + timeout
        while (remaining := deadline - time.monotonic()) > 0:
            sock.settimeout(remaining)
            try:
                data, (ip, _) = sock.recvfrom(9000)
            except socket.timeout:
                break
            except OSError:
                time.sleep(0.02)
                continue
            try:
                _, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
                offset = 12
                for _ in range(qd):
                    _, offset = _dns_name(data, offset)
                    offset += 4
                for _ in range(an + ns + ar):
                    name, offset = _dns_name(data, offset)
                    rtype, _, _, length = struct.unpack("!HHIH", data[offset: offset + 10])
                    offset += 10
                    if rtype == 12 and ".".join(name[-3:]).lower() in ("_uscan._tcp.local", "_uscans._tcp.local"):
                        target, _ = _dns_name(data, offset)
                        if target:
                            found.setdefault(ip, target[0])
                    offset += length
            except (struct.error, IndexError):
                continue
    return found


def brand_of(name):
    lowered = name.lower()
    for brand in ("HP", "Epson", "Canon", "Brother", "Kyocera", "Ricoh", "Xerox", "Samsung", "Lexmark"):
        if lowered.startswith(brand.lower()) or f" {brand.lower()} " in f" {lowered} ":
            return brand
    return "eSCL"


def discover_network(timeout=2.0):
    """Find scanners on the local network: Epson (ENPC, UDP 3289), Canon (BJNP, UDP 8612) and every
    eSCL scanner (mDNS, e.g. HP Smart Tank). Returns a sorted list of (ip, mac, reachable, brand, name)."""
    mdns_pool = ThreadPoolExecutor(max_workers=1)
    mdns = mdns_pool.submit(discover_mdns, timeout)
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

    try:
        escl_names = mdns.result(timeout + 3)
    except Exception:
        escl_names = {}
    mdns_pool.shutdown(wait=False)
    for ip, name in escl_names.items():
        if ip not in replies:
            replies[ip] = ("", brand_of(name))

    def reachable(item):
        ip, (_, brand) = item
        if brand != "Epson":
            return True  # it just answered on its scanner protocol
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
    return [(ip, mac, state, brand, escl_names.get(ip, "")) for (ip, (mac, brand)), state in zip(items, states)]


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


def escl_capabilities(ip):
    """Paper sources the scanner reports over eSCL: a set of glass / feeder / duplex, or None."""
    for scheme, opener in (("http", _NO_PROXY), ("https", _LAN_TLS_OPENER)):
        try:
            with opener.open(f"{scheme}://{ip}/eSCL/ScannerCapabilities", timeout=3) as response:
                text = response.read(400000).decode("utf-8", "replace")
        except (OSError, ValueError):
            continue
        if "ScannerCapabilities" not in text:
            continue
        sources = set()
        if re.search(r"<(?:\w+:)?Platen\b", text):
            sources.add("glass")
        if re.search(r"<(?:\w+:)?Adf\b", text):
            sources.add("feeder")
            if re.search(r"<(?:\w+:)?AdfDuplexInputCaps\b", text):
                sources.add("duplex")
        return sources or None
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


_INTERNET_TLS = None


def internet_context():
    """HTTPS settings for GitHub, downloads and translation: the system certificates PLUS certifi's list.
    Python from python.org on macOS (and some frozen apps) ships with no certificates at all, which made
    every HTTPS request fail with CERTIFICATE_VERIFY_FAILED."""
    global _INTERNET_TLS
    if _INTERNET_TLS is None:
        context = ssl.create_default_context()
        bundle = None
        try:
            import certifi
            bundle = certifi.where()
        except ImportError:
            try:
                from pip._vendor import certifi as pip_certifi  # pip always carries a copy
                bundle = pip_certifi.where()
            except ImportError:
                pass
        if bundle and os.path.isfile(bundle):
            try:
                context.load_verify_locations(cafile=bundle)
            except (OSError, ssl.SSLError):
                pass
        _INTERNET_TLS = context
    return _INTERNET_TLS


def app_path():
    """What an update replaces: the .app bundle (macOS), the .exe / binary, or this .pyw script."""
    if FROZEN and MAC:
        return Path(sys.executable).resolve().parents[2]  # …/What the Scan.app/Contents/MacOS/<exe>
    return Path(sys.executable if FROZEN else __file__).resolve()


def clean_old_update():
    try:
        old = app_path().with_name(app_path().name + ".old")
        if old.is_dir():
            shutil.rmtree(old, ignore_errors=True)
        else:
            old.unlink(missing_ok=True)
    except OSError:
        pass


# ---------------------------------------------------------------- offline package
def offline_bundle():
    """The offline package next to the app: WhatTheScan-offline.zip or its unzipped folder, else None."""
    here = app_path().parent
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
    with urllib.request.urlopen(url, timeout=30, context=internet_context()) as response, target.open("wb") as out:
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


def install_vendor(url, signer, flags, report, label, filename=None, sha256=None):
    with tempfile.TemporaryDirectory(prefix="EpsonScan-") as folder:
        installer = Path(folder) / (filename or Path(urllib.parse.urlsplit(url).path).name)
        download(url, installer, report, f"Downloading {label}…")
        env = dict(os.environ, EPSON_SCAN_PACKAGE=str(installer))
        # PowerShell 7 (or a terminal started from it) leaves its own PSModulePath behind, and then
        # Windows PowerShell cannot load Get-AuthenticodeSignature. Let it use its default modules.
        env.pop("PSModulePath", None)
        if not (sha256 and sha256_file(installer) == sha256):
            signature = run_hidden([
                "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                "$s=Get-AuthenticodeSignature -LiteralPath $env:EPSON_SCAN_PACKAGE; "
                "if ($s.Status -ne 'Valid') { Write-Output $s.Status; exit 1 }; $s.SignerCertificate.Subject",
            ], env=env, capture_output=True, text=True, timeout=60)
            if signature.returncode or signer.lower() not in signature.stdout.lower():
                detail = (signature.stdout or signature.stderr).strip().splitlines()[-1:] or ["no answer"]
                raise RuntimeError(f"Windows could not verify the publisher of {label} ({detail[0][:120]}).")
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
        arm = platform.machine().lower() == "arm64"
        asset = NAPS_URL.replace("win-x64", "win-arm64") if arm else NAPS_URL
        install_vendor(asset, "NAPS2 Software",
                       ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"], report, "NAPS2",
                       sha256=NAPS_HASHES["win-arm64.exe" if arm else "win-x64.exe"])
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


LINUX_QT_LIBS = {  # system libraries PyQt6 (Qt 6) needs on Linux
    "apt-get": ["libegl1", "libgl1", "libglib2.0-0", "libfreetype6", "libfontconfig1", "libdbus-1-3",
                "libxkbcommon0", "libxkbcommon-x11-0", "libx11-6", "libx11-xcb1", "libxcb1", "libxcb-cursor0",
                "libxcb-icccm4", "libxcb-image0", "libxcb-keysyms1", "libxcb-randr0", "libxcb-render-util0",
                "libxcb-shape0", "libxcb-xinerama0", "libxcb-xkb1", "libxrender1", "libxi6", "libsm6",
                "libice6", "libxext6"],
    "dnf": ["mesa-libEGL", "mesa-libGL", "glib2", "freetype", "fontconfig", "dbus-libs", "libxkbcommon",
            "libxkbcommon-x11", "libX11", "libX11-xcb", "libxcb", "xcb-util-cursor", "xcb-util-wm",
            "xcb-util-image", "xcb-util-keysyms", "xcb-util-renderutil", "libXrender", "libXi", "libSM",
            "libICE", "libXext"],
}


def missing_library(text):
    match = re.search(r"([\w.+-]+\.so[\w.]*): cannot open shared object file", text or "")
    return match.group(1) if match else ""


def install_linux_qt_libs(report, library):
    """Install the system libraries Qt needs (asks for the administrator password)."""
    return linux_system_install(LINUX_QT_LIBS, report, f"system libraries for the window ({library})")


def linux_qt_hint(library):
    manager = "apt-get" if shutil.which("apt-get") or not shutil.which("dnf") else "dnf"
    tool = "apt" if manager == "apt-get" else "dnf"
    return (f"The window library PyQt6 needs a system file that is missing ({library}). "
            f"Install it with:  sudo {tool} install {' '.join(LINUX_QT_LIBS[manager])}")


LINUX_PIP_PACKAGES = {"apt-get": ["python3-pip", "python3-tk"], "dnf": ["python3-pip", "python3-tkinter"]}


def linux_system_install(packages_by_manager, report, label):
    """Install distribution packages with apt-get or dnf (asks for the administrator password)."""
    manager = shutil.which("apt-get") or shutil.which("dnf")
    if not manager:
        return False
    report(f"Installing {label}…")
    command = [manager, "-y", "install", *packages_by_manager[Path(manager).name]]
    if os.geteuid() != 0:
        pkexec = shutil.which("pkexec")
        if not pkexec:
            return False
        command.insert(0, pkexec)
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")

    def run(args, timeout=900):
        try:
            return run_hidden(args, stdin=subprocess.DEVNULL, capture_output=True, env=env,
                              timeout=timeout).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    if Path(manager).name == "apt-get" and os.geteuid() == 0:
        run([manager, "update", "-qq"], 600)
    if run(command):
        return True
    # One unknown package name (they differ between distributions) fails the whole command:
    # install what exists one by one.
    prefix = command[:command.index("install") + 1]
    results = [run(prefix + [package], 600) for package in packages_by_manager[Path(manager).name]]
    return any(results)


def pip_works():
    try:
        return run_hidden([sys.executable, "-m", "pip", "--version"], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def ensure_pip(report):
    """pip is needed to install PyQt6 & co. Debian/Ubuntu's system Python often has no pip and disables ensurepip."""
    if pip_works():
        return
    report("Preparing pip…")
    try:
        run_hidden([sys.executable, "-m", "ensurepip", "--upgrade"], capture_output=True, timeout=180)
    except (OSError, subprocess.TimeoutExpired):
        pass
    if pip_works():
        return
    if LINUX and linux_system_install(LINUX_PIP_PACKAGES, report, "pip for Python") and pip_works():
        return
    hint = "sudo apt install python3-pip" if shutil.which("apt-get") else "sudo dnf install python3-pip"
    raise RuntimeError(f"Python's package installer (pip) is missing. Install it with:  {hint}")


def bootstrap(report):
    if not (WINDOWS or MAC or LINUX):
        raise RuntimeError("This app supports Windows, macOS and Linux.")
    if FROZEN:
        # The .exe / Linux binary already contains Python, PyQt6, PyMuPDF and python-docx.
        if LINUX:
            try:
                import PyQt6.QtWidgets  # noqa: F401  (needs a few system libraries)
            except ImportError as exc:
                library = missing_library(str(exc))
                if not library:
                    raise
                if not install_linux_qt_libs(report, library):
                    raise RuntimeError(linux_qt_hint(library))
        report("Checking NAPS2…")
        if not find_backend():
            install_naps(report)
        return False
    runtime = windows_python(report)
    if runtime is not None:
        return runtime
    report("Checking PyQt6, PyMuPDF and python-docx…")
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    probe = [sys.executable, "-c", "from PyQt6.QtWidgets import QApplication; import pymupdf, docx, segno, cryptography"]
    if run_hidden(probe, env=env, capture_output=True, timeout=30).returncode:
        ensure_pip(report)
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
        result = run_hidden(probe, env=env, capture_output=True, text=True, timeout=30)
        library = missing_library(result.stderr) if result.returncode and LINUX else ""
        if library:
            if install_linux_qt_libs(report, library):
                result = run_hidden(probe, env=env, capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise RuntimeError(linux_qt_hint(missing_library(result.stderr) or library))
        if result.returncode:
            last = (result.stderr or "").strip().splitlines()[-1:]
            raise RuntimeError("PyQt6, PyMuPDF or python-docx could not be loaded. " + (last[0] if last else ""))
    report("Checking NAPS2…")
    if not find_backend():
        install_naps(report)
    # Updates are offered inside the app (Help > Check for updates), never forced here.
    return False


def text_progress():
    """Setup progress when tkinter is missing: a desktop progress window (zenity) on Linux, else the terminal."""
    zenity = shutil.which("zenity") if LINUX and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")) else None
    window = None
    if zenity:
        try:
            window = subprocess.Popen([zenity, "--progress", "--pulsate", "--auto-close", "--no-cancel",
                                       "--width=420", f"--title={APP_NAME} · Setup", "--text=Preparing…"],
                                      stdin=subprocess.PIPE, text=True)
        except OSError:
            window = None

    def report(value):
        print(value, file=sys.stderr)
        if window and window.poll() is None:
            try:
                window.stdin.write(f"# {value}\n")
                window.stdin.flush()
            except OSError:
                pass

    def close():
        if window and window.poll() is None:
            try:
                window.stdin.close()
                window.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                window.kill()

    def fail(message):
        if WINDOWS:
            ctypes.windll.user32.MessageBoxW(None, message, "Scanner setup", 0x10)
            return
        print(f"Scanner setup: {message}", file=sys.stderr)
        if zenity:
            subprocess.run([zenity, "--error", f"--title={APP_NAME} · Setup", f"--text={message}"], check=False)

    return report, close, fail


def setup_splash():
    if SMOKE_FILE:
        smoke(f"start v{VERSION} on {sys.platform} {platform.machine()} (frozen={FROZEN})")
        try:
            result = bootstrap(lambda value: (print(value, file=sys.stderr), smoke(value)))
        except Exception as exc:
            smoke(f"SETUP FAILED: {exc}")
            raise SystemExit(1)
        smoke("setup done")
        return result
    try:
        import tkinter as tk
        from tkinter import ttk
        root = tk.Tk()
    except Exception as error:
        if not isinstance(error, ImportError) and error.__class__.__name__ != "TclError":
            raise
        report, close, fail = text_progress()
        try:
            result = bootstrap(report)
        except Exception as exc:
            close()
            fail(str(exc))
            raise SystemExit(1)
        close()
        return result

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

from PyQt6.QtCore import (
    QObject, QPoint, QPointF, QProcess, QRect, QRectF, QSettings, QSize, QStandardPaths, QTimer, Qt, QUrl, pyqtSignal,
)
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
    blurb, maker, project, more, version = ABOUT.get(UI_LANG, ABOUT["en"])
    blurb = blurb.format(brands=BRANDS)
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


ABOUT = {
    'en': ("Scan to PDF, JPG, Word and OpenDocument from {brands} scanners, with OCR, translation, sending to your phone and a status light that shows when somebody else on the network is using the scanner.", "<b>Made by Nikolaos K. Paridis</b> (nikkpap)<br>ALU DEV TEAM · Civil engineer &amp; developer of desktop and mobile tools<br>Ptolemaida, Greece", "Project page &amp; updates", "More apps", "Version"),
    'el': ("Σάρωση σε PDF, JPG, Word και OpenDocument από σαρωτές {brands}, με OCR, μετάφραση, αποστολή στο κινητό και φωτάκι που δείχνει πότε κάποιος άλλος στο δίκτυο χρησιμοποιεί τον σαρωτή.", "<b>Δημιουργός: Νικόλαος Κ. Παρίδης</b> (nikkpap)<br>ALU DEV TEAM · Πολιτικός μηχανικός &amp; developer εφαρμογών desktop και κινητού<br>Πτολεμαΐδα", "Σελίδα &amp; ενημερώσεις", "Περισσότερες εφαρμογές", "Έκδοση"),
    'fr': ("Numérisez en PDF, JPG, Word et OpenDocument depuis les scanners {brands}, avec OCR, traduction, envoi vers le téléphone et un voyant qui indique quand quelqu’un d’autre sur le réseau utilise le scanner.", "<b>Créé par Nikolaos K. Paridis</b> (nikkpap)<br>ALU DEV TEAM · Ingénieur civil &amp; développeur d’outils pour ordinateur et mobile<br>Ptolemaïda, Grèce", "Page du projet &amp; mises à jour", "Autres applications", "Version"),
    'de': ("Scannen in PDF, JPG, Word und OpenDocument mit {brands}-Scannern, mit OCR, Übersetzung, Senden ans Handy und einem Statuslicht, das zeigt, wenn jemand anderes im Netzwerk den Scanner benutzt.", "<b>Entwickelt von Nikolaos K. Paridis</b> (nikkpap)<br>ALU DEV TEAM · Bauingenieur &amp; Entwickler von Desktop- und Mobil-Tools<br>Ptolemaida, Griechenland", "Projektseite &amp; Updates", "Weitere Apps", "Version"),
    'it': ("Acquisisci in PDF, JPG, Word e OpenDocument dagli scanner {brands}, con OCR, traduzione, invio al telefono e una spia che mostra quando qualcun altro in rete usa lo scanner.", "<b>Realizzato da Nikolaos K. Paridis</b> (nikkpap)<br>ALU DEV TEAM · Ingegnere civile &amp; sviluppatore di strumenti desktop e mobile<br>Ptolemaida, Grecia", "Pagina del progetto &amp; aggiornamenti", "Altre app", "Versione"),
    'es': ("Escanea a PDF, JPG, Word y OpenDocument desde escáneres {brands}, con OCR, traducción, envío al móvil y una luz que indica cuándo otra persona de la red está usando el escáner.", "<b>Creado por Nikolaos K. Paridis</b> (nikkpap)<br>ALU DEV TEAM · Ingeniero civil &amp; desarrollador de herramientas de escritorio y móviles<br>Ptolemaida, Grecia", "Página del proyecto &amp; actualizaciones", "Más apps", "Versión"),
    'ro': ("Scanare în PDF, JPG, Word și OpenDocument de pe scannere {brands}, cu OCR, traducere, trimitere pe telefon și o lumină care arată când altcineva din rețea folosește scannerul.", "<b>Creat de Nikolaos K. Paridis</b> (nikkpap)<br>ALU DEV TEAM · Inginer constructor &amp; dezvoltator de aplicații desktop și mobile<br>Ptolemaida, Grecia", "Pagina proiectului &amp; actualizări", "Mai multe aplicații", "Versiune"),
    'cs': ("Skenování do PDF, JPG, Wordu a OpenDocumentu ze skenerů {brands}, s OCR, překladem, odesíláním do telefonu a kontrolkou, která ukazuje, když skener v síti používá někdo jiný.", "<b>Vytvořil Nikolaos K. Paridis</b> (nikkpap)<br>ALU DEV TEAM · Stavební inženýr &amp; vývojář aplikací pro počítač a mobil<br>Ptolemaida, Řecko", "Stránka projektu &amp; aktualizace", "Další aplikace", "Verze"),
    'ru': ("Сканирование в PDF, JPG, Word и OpenDocument со сканеров {brands}, с OCR, переводом, отправкой на телефон и индикатором, который показывает, когда сканером пользуется кто-то другой в сети.", "<b>Автор: Николаос К. Паридис</b> (nikkpap)<br>ALU DEV TEAM · Инженер-строитель &amp; разработчик приложений для ПК и телефона<br>Птолемаида, Греция", "Страница проекта &amp; обновления", "Другие приложения", "Версия"),
    'ja': ("{brands} のスキャナーから PDF、JPG、Word、OpenDocument にスキャン。OCR、翻訳、スマートフォンへの送信、ネットワーク上で他の人がスキャナーを使っているときに分かる状態ランプ付き。", "<b>制作: Nikolaos K. Paridis</b> (nikkpap)<br>ALU DEV TEAM · 土木技術者 &amp; デスクトップ／モバイルツール開発者<br>ギリシャ、プトレマイダ", "プロジェクトページ &amp; アップデート", "ほかのアプリ", "バージョン"),
    'zh': ("从 {brands} 扫描仪扫描为 PDF、JPG、Word 和 OpenDocument，支持 OCR、翻译、发送到手机，以及显示网络上是否有其他人正在使用扫描仪的状态指示灯。", "<b>作者：Nikolaos K. Paridis</b> (nikkpap)<br>ALU DEV TEAM · 土木工程师 &amp; 桌面与移动工具开发者<br>希腊托勒迈达", "项目页面 &amp; 更新", "更多应用", "版本"),
}  # blurb, maker, project, more, version

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
    with urllib.request.urlopen(request, timeout=20, context=internet_context()) as response:
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


UPDATE_TRANSLOCATED = ("macOS is running the app from a temporary read-only copy. Drag What the Scan into "
                       "Applications, open it from there, then update again.")
UPDATE_NO_PERMISSION = "The app's folder can't be written to. Move the app to a folder you own (or Applications) and update again."


def install_mac_bundle(payload):
    """Replace the running .app bundle with the one in the downloaded zip (keeps symlinks and permissions)."""
    target = app_path()
    if "/AppTranslocation/" in str(target):
        raise ValueError(UPDATE_TRANSLOCATED)
    if not os.access(target.parent, os.W_OK):
        raise ValueError(UPDATE_NO_PERMISSION)
    with tempfile.TemporaryDirectory(prefix="WhatTheScan-update-") as folder:
        archive = Path(folder) / "update.zip"
        archive.write_bytes(payload)
        unpacked = Path(folder) / "app"
        subprocess.run(["/usr/bin/ditto", "-x", "-k", str(archive), str(unpacked)], check=True, timeout=300)
        new = next(unpacked.glob("*.app"), None)
        if new is None:
            raise ValueError("The downloaded update has no .app inside. Nothing was changed.")
        old = target.with_name(target.name + ".old")
        shutil.rmtree(old, ignore_errors=True)
        target.rename(old)
        try:
            shutil.move(str(new), str(target))
        except OSError:
            old.rename(target)
            raise
    return target


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
        expected_start = b"MZ" if WINDOWS else b"\x7fELF" if LINUX else b"PK"
        if not payload.startswith(expected_start):
            raise ValueError("The downloaded file is not a program for this system. Nothing was changed.")
        if MAC:
            return install_mac_bundle(payload)
    else:
        compile(payload, "update.pyw", "exec")
        if b"APP_NAME" not in payload:
            raise ValueError("The downloaded file is not this app. Nothing was changed.")
    target = app_path()
    if not os.access(target.parent, os.W_OK):
        raise ValueError(UPDATE_NO_PERMISSION)
    staged = None
    try:
        # (os.access can't see Windows folder permissions, e.g. Program Files: PermissionError lands below.)
        with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as staging:
            staged = Path(staging.name)
            staging.write(payload)
        if FROZEN:
            # A running program can't be overwritten on Windows, but it can be renamed out of the way.
            old = target.with_name(target.name + ".old")
            old.unlink(missing_ok=True)
            target.replace(old)
            try:
                staged.replace(target)
            except OSError:
                old.replace(target)  # put the working program back
                raise
            if not WINDOWS:
                target.chmod(0o755)
        else:
            shutil.copy2(target, target.with_suffix(target.suffix + ".bak"))
            staged.replace(target)
    except PermissionError:
        raise ValueError(UPDATE_NO_PERMISSION)
    finally:
        if staged is not None:
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
    QComboBox::down-arrow { image: url("$chevron"); width: 12px; height: 12px; }
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
    QCheckBox::indicator:checked { background: $accent; border-color: $accent; image: url("$check"); }
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
    elif name == "phone":
        p.drawRoundedRect(QRectF(6.5, 2.5, 11, 19), 2.4, 2.4)
        p.drawLine(QPointF(10.5, 18.2), QPointF(13.5, 18.2))
        p.drawLine(QPointF(10.8, 5.2), QPointF(13.2, 5.2))
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
    "Brother's download page is opening. The model {model} is copied: paste it in the search box (Ctrl+V). Most Brother models also scan with no driver over the network.":
        "Ανοίγει η σελίδα λήψεων της Brother. Το μοντέλο {model} αντιγράφηκε: επικόλλησέ το στην αναζήτηση (Ctrl+V). Τα περισσότερα μοντέλα Brother σαρώνουν και χωρίς driver μέσω δικτύου.",
    "Connect Epson Scan 2 to the scanner":
        "Σύνδεση του Epson Scan 2 με τον σαρωτή",
    "Epson Scan 2 does not know your scanner's network address yet. This happens after the driver is (re)installed. One time only:":
        "Το Epson Scan 2 δεν ξέρει ακόμα τη διεύθυνση δικτύου του σαρωτή. Συμβαίνει μετά από (επαν)εγκατάσταση του driver. Μόνο μία φορά:",
    "1. Click “Open Epson Scan 2 Utility” below.\n2. At the top, in “Scanner”, choose “Settings”.\n3. Click “Add”, choose “Enter address”, press Ctrl+V (the address {ip} is already copied) and click OK.\n4. Click OK, close the utility and press Scan again.":
        "1. Πάτα «Άνοιγμα Epson Scan 2 Utility» παρακάτω.\n2. Πάνω, στο «Scanner», διάλεξε «Settings».\n3. Πάτα «Add», διάλεξε «Enter address», πάτα Ctrl+V (η διεύθυνση {ip} έχει ήδη αντιγραφεί) και OK.\n4. Πάτα OK, κλείσε το utility και ξαναπάτα Σάρωση.",
    "Open Epson Scan 2 Utility":
        "Άνοιγμα Epson Scan 2 Utility",
    "Could not open Epson Scan 2 Utility. {error}":
        "Δεν άνοιξε το Epson Scan 2 Utility. {error}",
    "{phone} (browser)": "{phone} (browser)",
    "AirDrop":
        "AirDrop",
    "Send with AirDrop to an iPhone, iPad or Mac nearby":
        "Αποστολή με AirDrop σε κοντινό iPhone, iPad ή Mac",
    "AirDrop is open: choose the iPhone or Mac.":
        "Το AirDrop άνοιξε: διάλεξε το iPhone ή το Mac.",
    "AirDrop is not available on this Mac. Turn on Wi-Fi and Bluetooth.":
        "Το AirDrop δεν είναι διαθέσιμο σε αυτό το Mac. Άνοιξε το Wi-Fi και το Bluetooth.",
    "So that your phone can send to this computer, Windows Firewall must let it in.\n\nAllow it now? Windows asks for permission once (only phones on your own network, only the ports of {app}).":
        "Για να μπορεί το κινητό να στέλνει σε αυτόν τον υπολογιστή, πρέπει να το επιτρέψει το Τείχος προστασίας των Windows.\n\nΝα επιτραπεί τώρα; Τα Windows ζητούν άδεια μία φορά (μόνο για κινητά του δικού σου δικτύου, μόνο στις θύρες του {app}).",
    "Waiting for Windows permission (firewall)…":
        "Περιμένω την άδεια των Windows (τείχος προστασίας)…",
    "✓ Windows Firewall lets your phone in now.":
        "✓ Το Τείχος προστασίας των Windows αφήνει πλέον το κινητό να συνδεθεί.",
    "Windows Firewall was not changed, so the phone may not be able to send to this computer.":
        "Το Τείχος προστασίας των Windows δεν άλλαξε, οπότε το κινητό ίσως δεν μπορεί να στείλει σε αυτόν τον υπολογιστή.",
    "LocalSend for the phone":
        "LocalSend για το κινητό",
    "Trying Epson's other download server…":
        "Δοκιμή από τον άλλο server λήψεων της Epson…",
    "{name} answers on the network ({ip}), but its scanner driver is not installed.":
        "Το {name} απαντά στο δίκτυο ({ip}), αλλά ο driver του σαρωτή δεν είναι εγκατεστημένος.",
    "Scanner driver missing":
        "Λείπει ο driver του σαρωτή",
    "{name} was found on the network ({ip}), but its scanner driver is not installed, so the app cannot scan with it.\n\nInstall the official {label} now? It is downloaded and installed automatically (a few minutes; Windows may ask for permission).":
        "Βρέθηκε το {name} στο δίκτυο ({ip}), αλλά ο driver του σαρωτή δεν είναι εγκατεστημένος, οπότε η εφαρμογή δεν μπορεί να σαρώσει.\n\nΝα εγκατασταθεί τώρα ο επίσημος {label}; Κατεβαίνει και εγκαθίσταται αυτόματα (λίγα λεπτά· τα Windows μπορεί να ζητήσουν άδεια).",
    "Phone":
        "Κινητό",
    "Send to your phone or receive photos from it, on the same Wi-Fi (LocalSend app or QR code)":
        "Στείλε στο κινητό ή πάρε φωτογραφίες από αυτό, στο ίδιο Wi-Fi (εφαρμογή LocalSend ή QR code)",
    "Send scans to your phone and receive photos from it, on the same Wi-Fi.":
        "Στείλε σαρώσεις στο κινητό και πάρε φωτογραφίες από αυτό, στο ίδιο Wi-Fi.",
    "Receiving from the phone":
        "Λήψη από κινητό",
    "Keep receiving on while the app is open":
        "Λήψη πάντα ανοιχτή όσο τρέχει η εφαρμογή",
    "When this is off, receiving opens for {minutes} minutes each time you press Phone.":
        "Όταν είναι ανενεργό, η λήψη ανοίγει για {minutes} λεπτά κάθε φορά που πατάς «Κινητό».",
    "Phone photos":
        "Φωτογραφίες κινητού",
    "Just save them in the scans folder":
        "Απλή αποθήκευση στον φάκελο σαρώσεων",
    "Make a PDF, like a scan (OCR, Word)":
        "Μετατροπή σε PDF σαν σάρωση (OCR, Word)",
    "Name on the phone":
        "Όνομα στο κινητό",
    "How it works":
        "Πώς δουλεύει",
    "1. Phone and computer on the same Wi-Fi.\n2. Install the free LocalSend app on the phone, or simply scan the QR code.\n3. Press Phone, next to Preview, choose the phone and Send.\n4. To send from the phone: in LocalSend choose “{name}”, or use the QR page.":
        "1. Κινητό και υπολογιστής στο ίδιο Wi-Fi.\n2. Εγκατέστησε τη δωρεάν εφαρμογή LocalSend στο κινητό ή απλά σκάναρε το QR code.\n3. Πάτα «Κινητό», δίπλα στην Προεπισκόπηση, διάλεξε το κινητό και «Αποστολή».\n4. Για αποστολή από το κινητό: στο LocalSend διάλεξε «{name}» ή χρησιμοποίησε τη σελίδα του QR.",
    "Get LocalSend":
        "Κατέβασε το LocalSend",
    "Idle · making a PDF from phone photos":
        "Αδρανές · φτιάχνω PDF από φωτογραφίες κινητού",
    "✓ Made {file} from {count} phone photo(s)":
        "✓ Δημιουργήθηκε το {file} από {count} φωτογραφίες κινητού",
    "Windows may now ask whether {app} can use the network.\n\nTick “Private networks” and click Allow, so your phone can reach this computer.":
        "Τα Windows μπορεί τώρα να ρωτήσουν αν το {app} μπορεί να χρησιμοποιεί το δίκτυο.\n\nΤσέκαρε «Ιδιωτικά δίκτυα» και πάτα «Να επιτρέπεται», ώστε το κινητό να βλέπει τον υπολογιστή.",
    "The phone connection could not start. Another program may be using the network ports {ports}.":
        "Η σύνδεση με το κινητό δεν ξεκίνησε. Κάποιο άλλο πρόγραμμα μπορεί να χρησιμοποιεί τις θύρες δικτύου {ports}.",
    "Receiving is off. Press Phone to open it again.":
        "Η λήψη είναι κλειστή. Πάτα «Κινητό» για να ανοίξει ξανά.",
    "Receiving is on: the phone can send files to “{name}”.":
        "Η λήψη είναι ανοιχτή: το κινητό μπορεί να στείλει αρχεία στο «{name}».",
    "Receiving is on for {time}: the phone can send files to “{name}”.":
        "Η λήψη είναι ανοιχτή για {time}: το κινητό μπορεί να στείλει αρχεία στο «{name}».",
    "… and {count} more":
        "… και {count} ακόμη",
    "Files from a phone":
        "Αρχεία από κινητό",
    "“{sender}” wants to send {count} file(s):":
        "Το «{sender}» θέλει να στείλει {count} αρχεία:",
    "They will be saved in {folder}.":
        "Θα αποθηκευτούν στο {folder}.",
    "Accept":
        "Αποδοχή",
    "Decline":
        "Απόρριψη",
    "Receiving files from {sender}…":
        "Λήψη αρχείων από {sender}…",
    "✓ Received {count} file(s) from {sender} in {folder}":
        "✓ Ελήφθησαν {count} αρχεία από {sender} στο {folder}",
    "The photos were saved as they are, because a scan is running.":
        "Οι φωτογραφίες αποθηκεύτηκαν όπως είναι, γιατί τρέχει σάρωση.",
    "Making a PDF from {count} phone photo(s)…":
        "Φτιάχνω PDF από {count} φωτογραφίες κινητού…",
    "This link has expired. Scan the QR code again.":
        "Ο σύνδεσμος έληξε. Σκάναρε ξανά το QR code.",
    "No scan yet. Scan something first, then reload this page.":
        "Δεν υπάρχει ακόμη σάρωση. Σκάναρε πρώτα και μετά ανανέωσε τη σελίδα.",
    "Waiting for the computer to accept…":
        "Περιμένω να πατηθεί «Αποδοχή» στον υπολογιστή…",
    "The computer declined the files.":
        "Ο υπολογιστής απέρριψε τα αρχεία.",
    "The computer is receiving other files. Try again in a moment.":
        "Ο υπολογιστής λαμβάνει άλλα αρχεία. Δοκίμασε ξανά σε λίγο.",
    "Sending failed. Check that the phone is on the same Wi-Fi and try again.":
        "Η αποστολή απέτυχε. Έλεγξε ότι το κινητό είναι στο ίδιο Wi-Fi και δοκίμασε ξανά.",
    "Sending {name}…":
        "Αποστολή {name}…",
    "✓ Sent! The files are on the computer.":
        "✓ Στάλθηκαν! Τα αρχεία είναι στον υπολογιστή.",
    "1 · Get the scan on this phone":
        "1 · Πάρε τη σάρωση σε αυτό το κινητό",
    "Reload":
        "Ανανέωση",
    "2 · Send photos or files to the computer":
        "2 · Στείλε φωτογραφίες ή αρχεία στον υπολογιστή",
    "Take a photo or choose files":
        "Βγάλε φωτογραφία ή διάλεξε αρχεία",
    "Send to your phone":
        "Στείλε στο κινητό",
    "Phone and computer must be on the same Wi-Fi.":
        "Κινητό και υπολογιστής πρέπει να είναι στο ίδιο Wi-Fi.",
    "Choose other files…":
        "Άλλα αρχεία…",
    "Phones with LocalSend":
        "Κινητά με LocalSend",
    "Send":
        "Αποστολή",
    "No LocalSend? Scan this":
        "Χωρίς LocalSend; Σκάναρε αυτό",
    "Point the phone camera at the code. A page opens where you can download the scan and send photos to this computer.":
        "Στρέψε την κάμερα του κινητού στον κωδικό. Ανοίγει μια σελίδα για να κατεβάσεις τη σάρωση και να στείλεις φωτογραφίες σε αυτόν τον υπολογιστή.",
    "QR code not available.":
        "Το QR code δεν είναι διαθέσιμο.",
    "To send: {names}  ({size})":
        "Για αποστολή: {names}  ({size})",
    "Nothing to send yet. Scan first, or choose files.":
        "Τίποτα για αποστολή ακόμη. Σκάναρε πρώτα ή διάλεξε αρχεία.",
    "Choose files for the phone":
        "Διάλεξε αρχεία για το κινητό",
    "Looking for phones… Open LocalSend on the phone.":
        "Ψάχνω κινητά… Άνοιξε το LocalSend στο κινητό.",
    "No phone found.\n1. Is the phone on the same Wi-Fi?\n2. Open the LocalSend app on the phone (free, Play Store / App Store).\n3. Or simply scan the QR code on the right.":
        "Δεν βρέθηκε κινητό.\n1. Είναι το κινητό στο ίδιο Wi-Fi;\n2. Άνοιξε την εφαρμογή LocalSend στο κινητό (δωρεάν, Play Store / App Store).\n3. Ή απλά σκάναρε το QR code δεξιά.",
    "Waiting for {phone} to accept… Tap Accept on the phone.":
        "Περιμένω το {phone} να δεχτεί… Πάτα «Αποδοχή» στο κινητό.",
    "Sending to {phone}… {value}%":
        "Αποστολή στο {phone}… {value}%",
    "{phone} declined the files.":
        "Το {phone} απέρριψε τα αρχεία.",
    "{phone} is busy with another transfer. Try again in a moment.":
        "Το {phone} κάνει άλλη μεταφορά. Δοκίμασε ξανά σε λίγο.",
    "{phone} asks for a PIN. Turn off the PIN in LocalSend settings on the phone.":
        "Το {phone} ζητά PIN. Απενεργοποίησε το PIN στις ρυθμίσεις του LocalSend στο κινητό.",
    "Could not reach {phone}. Is LocalSend open and on the same Wi-Fi?":
        "Δεν βρέθηκε το {phone}. Είναι ανοιχτό το LocalSend και στο ίδιο Wi-Fi;",
    "Sending cancelled.":
        "Η αποστολή ακυρώθηκε.",
    "✓ Sent {count} file(s) to {phone}.":
        "✓ Στάλθηκαν {count} αρχεία στο {phone}.",
    "Sending failed. {error}":
        "Η αποστολή απέτυχε. {error}",
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
    "No network reply yet": "Καμία απάντηση από το δίκτυο ακόμη",
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
    "Update failed. {error}": "Η ενημέρωση απέτυχε. {error}",
    "macOS is running the app from a temporary read-only copy. Drag What the Scan into Applications, open it from there, then update again.":
        "Το macOS τρέχει την εφαρμογή από προσωρινό αντίγραφο μόνο για ανάγνωση. Σύρε το What the Scan στις "
        "Εφαρμογές, άνοιξέ το από εκεί και κάνε ξανά ενημέρωση.",
    "The app's folder can't be written to. Move the app to a folder you own (or Applications) and update again.":
        "Ο φάκελος της εφαρμογής δεν επιτρέπει αλλαγές. Μετάφερε την εφαρμογή σε δικό σου φάκελο (ή στις "
        "Εφαρμογές) και κάνε ξανά ενημέρωση.", "Update failed": "Η ενημέρωση απέτυχε",
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
    "Searching the local network for scanners (Epson, Canon, HP, AirPrint)…":
        "Αναζήτηση σαρωτών στο τοπικό δίκτυο (Epson, Canon, HP, AirPrint)…",
    "answered as a network (eSCL) scanner ✓": "απάντησε ως σαρωτής δικτύου (eSCL) ✓",
    "This scanner has: {sources}": "Αυτός ο σαρωτής έχει: {sources}",
    "Network discovery failed. {error}": "Η αναζήτηση στο δίκτυο απέτυχε. {error}",
    "Select your scanner's network address.": "Διάλεξε τη διεύθυνση δικτύου του σαρωτή σου.",
    "No scanner replied on this local network.": "Κανένας σαρωτής δεν απάντησε σε αυτό το δίκτυο.",
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
    "cs": ("Czech", "Τσεχικά", "ces"), "ja": ("Japanese", "Ιαπωνικά", "jpn"),
}


# Other interface languages (keys are the English texts, like GR above).
UI_FR = {
    "Brother's download page is opening. The model {model} is copied: paste it in the search box (Ctrl+V). Most Brother models also scan with no driver over the network.":
        "La page de téléchargement de Brother s’ouvre. Le modèle {model} est copié : collez-le dans la recherche (Ctrl+V). La plupart des modèles Brother numérisent aussi sans pilote en réseau.",
    "Connect Epson Scan 2 to the scanner":
        "Connecter Epson Scan 2 au scanner",
    "Epson Scan 2 does not know your scanner's network address yet. This happens after the driver is (re)installed. One time only:":
        "Epson Scan 2 ne connaît pas encore l’adresse réseau de votre scanner. Cela arrive après une (ré)installation du pilote. Une seule fois :",
    "1. Click “Open Epson Scan 2 Utility” below.\n2. At the top, in “Scanner”, choose “Settings”.\n3. Click “Add”, choose “Enter address”, press Ctrl+V (the address {ip} is already copied) and click OK.\n4. Click OK, close the utility and press Scan again.":
        "1. Cliquez sur « Ouvrir Epson Scan 2 Utility » ci-dessous.\n2. En haut, dans « Scanner », choisissez « Settings ».\n3. Cliquez sur « Add », choisissez « Enter address », appuyez sur Ctrl+V (l’adresse {ip} est déjà copiée) et cliquez sur OK.\n4. Cliquez sur OK, fermez l’utilitaire et appuyez à nouveau sur Numériser.",
    "Open Epson Scan 2 Utility":
        "Ouvrir Epson Scan 2 Utility",
    "Could not open Epson Scan 2 Utility. {error}":
        "Impossible d’ouvrir Epson Scan 2 Utility. {error}",
    "{phone} (browser)": "{phone} (navigateur)",
    "AirDrop":
        "AirDrop",
    "Send with AirDrop to an iPhone, iPad or Mac nearby":
        "Envoyer avec AirDrop vers un iPhone, iPad ou Mac à proximité",
    "AirDrop is open: choose the iPhone or Mac.":
        "AirDrop est ouvert : choisissez l’iPhone ou le Mac.",
    "AirDrop is not available on this Mac. Turn on Wi-Fi and Bluetooth.":
        "AirDrop n’est pas disponible sur ce Mac. Activez le Wi-Fi et le Bluetooth.",
    "So that your phone can send to this computer, Windows Firewall must let it in.\n\nAllow it now? Windows asks for permission once (only phones on your own network, only the ports of {app}).":
        "Pour que votre téléphone puisse envoyer des fichiers à cet ordinateur, le pare-feu Windows doit l’autoriser.\n\nL’autoriser maintenant ? Windows demande l’autorisation une seule fois (uniquement les téléphones de votre réseau, uniquement les ports de {app}).",
    "Waiting for Windows permission (firewall)…":
        "En attente de l’autorisation de Windows (pare-feu)…",
    "✓ Windows Firewall lets your phone in now.":
        "✓ Le pare-feu Windows laisse maintenant passer votre téléphone.",
    "Windows Firewall was not changed, so the phone may not be able to send to this computer.":
        "Le pare-feu Windows n’a pas été modifié : le téléphone ne pourra peut-être pas envoyer de fichiers à cet ordinateur.",
    "LocalSend for the phone":
        "LocalSend pour le téléphone",
    "Trying Epson's other download server…":
        "Essai avec l’autre serveur de téléchargement d’Epson…",
    "{name} answers on the network ({ip}), but its scanner driver is not installed.":
        "{name} répond sur le réseau ({ip}), mais son pilote de scanner n’est pas installé.",
    "Scanner driver missing":
        "Pilote de scanner manquant",
    "{name} was found on the network ({ip}), but its scanner driver is not installed, so the app cannot scan with it.\n\nInstall the official {label} now? It is downloaded and installed automatically (a few minutes; Windows may ask for permission).":
        "{name} a été trouvé sur le réseau ({ip}), mais son pilote de scanner n’est pas installé : l’application ne peut donc pas numériser avec.\n\nInstaller maintenant le pilote officiel {label} ? Il est téléchargé et installé automatiquement (quelques minutes ; Windows peut demander l’autorisation).",
    "Phone":
        "Téléphone",
    "Send to your phone or receive photos from it, on the same Wi-Fi (LocalSend app or QR code)":
        "Envoyer vers votre téléphone ou en recevoir des photos, sur le même Wi-Fi (application LocalSend ou code QR)",
    "Send scans to your phone and receive photos from it, on the same Wi-Fi.":
        "Envoyez vos numérisations vers votre téléphone et recevez-en des photos, sur le même Wi-Fi.",
    "Receiving from the phone":
        "Réception depuis le téléphone",
    "Keep receiving on while the app is open":
        "Garder la réception active tant que l’application est ouverte",
    "When this is off, receiving opens for {minutes} minutes each time you press Phone.":
        "Si cette option est désactivée, la réception s’ouvre pour {minutes} minutes à chaque appui sur Téléphone.",
    "Phone photos":
        "Photos du téléphone",
    "Just save them in the scans folder":
        "Les enregistrer simplement dans le dossier des numérisations",
    "Make a PDF, like a scan (OCR, Word)":
        "En faire un PDF, comme une numérisation (OCR, Word)",
    "Name on the phone":
        "Nom sur le téléphone",
    "How it works":
        "Fonctionnement",
    "1. Phone and computer on the same Wi-Fi.\n2. Install the free LocalSend app on the phone, or simply scan the QR code.\n3. Press Phone, next to Preview, choose the phone and Send.\n4. To send from the phone: in LocalSend choose “{name}”, or use the QR page.":
        "1. Téléphone et ordinateur sur le même Wi-Fi.\n2. Installez l’application gratuite LocalSend sur le téléphone, ou scannez simplement le code QR.\n3. Appuyez sur Téléphone, à côté d’Aperçu, choisissez le téléphone puis Envoyer.\n4. Pour envoyer depuis le téléphone : dans LocalSend, choisissez « {name} », ou utilisez la page du code QR.",
    "Get LocalSend":
        "Obtenir LocalSend",
    "Idle · making a PDF from phone photos":
        "Inactif · création d’un PDF à partir des photos du téléphone",
    "✓ Made {file} from {count} phone photo(s)":
        "✓ {file} créé à partir de {count} photo(s) du téléphone",
    "Windows may now ask whether {app} can use the network.\n\nTick “Private networks” and click Allow, so your phone can reach this computer.":
        "Windows va peut-être demander si {app} peut utiliser le réseau.\n\nCochez « Réseaux privés » et cliquez sur Autoriser, pour que votre téléphone puisse joindre cet ordinateur.",
    "The phone connection could not start. Another program may be using the network ports {ports}.":
        "La connexion au téléphone n’a pas pu démarrer. Un autre programme utilise peut-être les ports réseau {ports}.",
    "Receiving is off. Press Phone to open it again.":
        "La réception est désactivée. Appuyez sur Téléphone pour la rouvrir.",
    "Receiving is on: the phone can send files to “{name}”.":
        "La réception est active : le téléphone peut envoyer des fichiers à « {name} ».",
    "Receiving is on for {time}: the phone can send files to “{name}”.":
        "La réception est active pendant {time} : le téléphone peut envoyer des fichiers à « {name} ».",
    "… and {count} more":
        "… et {count} de plus",
    "Files from a phone":
        "Fichiers d’un téléphone",
    "“{sender}” wants to send {count} file(s):":
        "« {sender} » veut envoyer {count} fichier(s) :",
    "They will be saved in {folder}.":
        "Ils seront enregistrés dans {folder}.",
    "Accept":
        "Accepter",
    "Decline":
        "Refuser",
    "Receiving files from {sender}…":
        "Réception des fichiers de {sender}…",
    "✓ Received {count} file(s) from {sender} in {folder}":
        "✓ {count} fichier(s) reçu(s) de {sender} dans {folder}",
    "The photos were saved as they are, because a scan is running.":
        "Les photos ont été enregistrées telles quelles, car une numérisation est en cours.",
    "Making a PDF from {count} phone photo(s)…":
        "Création d’un PDF à partir de {count} photo(s) du téléphone…",
    "This link has expired. Scan the QR code again.":
        "Ce lien a expiré. Scannez à nouveau le code QR.",
    "No scan yet. Scan something first, then reload this page.":
        "Aucune numérisation pour l’instant. Numérisez d’abord, puis rechargez cette page.",
    "Waiting for the computer to accept…":
        "En attente de l’acceptation par l’ordinateur…",
    "The computer declined the files.":
        "L’ordinateur a refusé les fichiers.",
    "The computer is receiving other files. Try again in a moment.":
        "L’ordinateur reçoit d’autres fichiers. Réessayez dans un instant.",
    "Sending failed. Check that the phone is on the same Wi-Fi and try again.":
        "L’envoi a échoué. Vérifiez que le téléphone est sur le même Wi-Fi et réessayez.",
    "Sending {name}…":
        "Envoi de {name}…",
    "✓ Sent! The files are on the computer.":
        "✓ Envoyé ! Les fichiers sont sur l’ordinateur.",
    "1 · Get the scan on this phone":
        "1 · Récupérer la numérisation sur ce téléphone",
    "Reload":
        "Recharger",
    "2 · Send photos or files to the computer":
        "2 · Envoyer des photos ou des fichiers à l’ordinateur",
    "Take a photo or choose files":
        "Prendre une photo ou choisir des fichiers",
    "Send to your phone":
        "Envoyer vers votre téléphone",
    "Phone and computer must be on the same Wi-Fi.":
        "Le téléphone et l’ordinateur doivent être sur le même Wi-Fi.",
    "Choose other files…":
        "Choisir d’autres fichiers…",
    "Phones with LocalSend":
        "Téléphones avec LocalSend",
    "Send":
        "Envoyer",
    "No LocalSend? Scan this":
        "Pas de LocalSend ? Scannez ceci",
    "Point the phone camera at the code. A page opens where you can download the scan and send photos to this computer.":
        "Pointez l’appareil photo du téléphone vers le code. Une page s’ouvre pour télécharger la numérisation et envoyer des photos à cet ordinateur.",
    "QR code not available.":
        "Code QR non disponible.",
    "To send: {names}  ({size})":
        "À envoyer : {names}  ({size})",
    "Nothing to send yet. Scan first, or choose files.":
        "Rien à envoyer pour l’instant. Numérisez d’abord, ou choisissez des fichiers.",
    "Choose files for the phone":
        "Choisir des fichiers pour le téléphone",
    "Looking for phones… Open LocalSend on the phone.":
        "Recherche de téléphones… Ouvrez LocalSend sur le téléphone.",
    "No phone found.\n1. Is the phone on the same Wi-Fi?\n2. Open the LocalSend app on the phone (free, Play Store / App Store).\n3. Or simply scan the QR code on the right.":
        "Aucun téléphone trouvé.\n1. Le téléphone est-il sur le même Wi-Fi ?\n2. Ouvrez l’application LocalSend sur le téléphone (gratuite, Play Store / App Store).\n3. Ou scannez simplement le code QR à droite.",
    "Waiting for {phone} to accept… Tap Accept on the phone.":
        "En attente de l’acceptation par {phone}… Appuyez sur Accepter sur le téléphone.",
    "Sending to {phone}… {value}%":
        "Envoi vers {phone}… {value} %",
    "{phone} declined the files.":
        "{phone} a refusé les fichiers.",
    "{phone} is busy with another transfer. Try again in a moment.":
        "{phone} est occupé par un autre transfert. Réessayez dans un instant.",
    "{phone} asks for a PIN. Turn off the PIN in LocalSend settings on the phone.":
        "{phone} demande un code PIN. Désactivez le PIN dans les paramètres de LocalSend sur le téléphone.",
    "Could not reach {phone}. Is LocalSend open and on the same Wi-Fi?":
        "Impossible de joindre {phone}. LocalSend est-il ouvert et sur le même Wi-Fi ?",
    "Sending cancelled.":
        "Envoi annulé.",
    "✓ Sent {count} file(s) to {phone}.":
        "✓ {count} fichier(s) envoyé(s) à {phone}.",
    "Sending failed. {error}":
        "L’envoi a échoué. {error}",
    "Also save an editable document (text from OCR)":
        "Enregistrer aussi un document modifiable (texte issu de l’OCR)",
    "Document":
        "Document",
    "Word (.docx) · Microsoft Word":
        "Word (.docx) · Microsoft Word",
    "OpenDocument (.odt) · LibreOffice on Mac / Linux":
        "OpenDocument (.odt) · LibreOffice sur Mac / Linux",
    "Word export needs python-docx. Close and reopen the app to install it.":
        "L’export Word nécessite python-docx. Fermez et rouvrez l’application pour l’installer.",
    "What to save, the paper and where the files go.":
        "Quoi enregistrer, le papier et l’emplacement des fichiers.",
    "Recognise text in your scans and translate it.":
        "Reconnaître le texte de vos numérisations et le traduire.",
    "Language, appearance and updates.":
        "Langue, apparence et mises à jour.",
    "Output":
        "Sortie",
    "Paper":
        "Papier",
    "Saving":
        "Enregistrement",
    "Text recognition (OCR)":
        "Reconnaissance de texte (OCR)",
    "Appearance":
        "Apparence",
    "Reset":
        "Réinitialiser",
    "Settings":
        "Paramètres",
    "Help":
        "Aide",
    "Ready":
        "Prêt",
    "Idle":
        "Inactif",
    "Scan":
        "Numériser",
    "Preview":
        "Aperçu",
    "Text":
        "Texte",
    "Open last":
        "Dernier fichier",
    "Open folder":
        "Dossier",
    "Cancel":
        "Annuler",
    "Stop search":
        "Arrêter la recherche",
    "Search again":
        "Rechercher à nouveau",
    "Change…":
        "Modifier…",
    "Starting…":
        "Démarrage…",
    "Looking for scanners…":
        "Recherche de scanners…",
    "Checking every driver at the same time.":
        "Vérification de tous les pilotes en même temps.",
    "Connected to {name}":
        "Connecté à {name}",
    "via {driver}":
        "via {driver}",
    "{brand} at {ip}":
        "{brand} à {ip}",
    "{count} more in Settings":
        "{count} autre(s) dans les Paramètres",
    "No scanner connected":
        "Aucun scanner connecté",
    "Turn the scanner on, check the USB cable or Wi-Fi, then click Search again.":
        "Allumez le scanner, vérifiez le câble USB ou le Wi-Fi, puis cliquez sur Rechercher à nouveau.",
    "saves to {folder}":
        "enregistre dans {folder}",
    "asks for a file name":
        "demande un nom de fichier",
    "OCR":
        "OCR",
    "OCR off":
        "OCR désactivé",
    "translate → {lang}":
        "traduire → {lang}",
    "Scan and save in the format chosen in Settings (Ctrl+S)":
        "Numériser et enregistrer au format choisi dans les Paramètres (Ctrl+S)",
    "Quick low-resolution look at the flatbed (Ctrl+P)":
        "Aperçu rapide basse résolution de la vitre (Ctrl+P)",
    "Recognised text and translation of the last scan (Ctrl+T)":
        "Texte reconnu et traduction de la dernière numérisation (Ctrl+T)",
    "Open the last scanned file":
        "Ouvrir le dernier fichier numérisé",
    "Open the folder with your scans":
        "Ouvrir le dossier de vos numérisations",
    "Stop the scan or search (Esc)":
        "Arrêter la numérisation ou la recherche (Échap)",
    "Look for scanners again (F5)":
        "Rechercher à nouveau les scanners (F5)",
    "Choose another scanner or change scan settings":
        "Choisir un autre scanner ou modifier les paramètres de numérisation",
    "Scanner, scanning, text and appearance settings (Ctrl+,)":
        "Paramètres du scanner, de la numérisation, du texte et de l’apparence (Ctrl+,)",
    "Quick guide":
        "Guide rapide",
    "Check for updates…":
        "Rechercher des mises à jour…",
    "Project page on GitHub":
        "Page du projet sur GitHub",
    "About {app}":
        "À propos de {app}",
    "Update to {version}…":
        "Mettre à jour vers {version}…",
    "In use · scanning on this PC":
        "Occupé · numérisation sur ce PC",
    "In use by {who}":
        "Utilisé par {who}",
    "{user} on {host}":
        "{user} sur {host}",
    "Started at {time}. Wait until the light turns green.":
        "Commencé à {time}. Attendez que le voyant passe au vert.",
    "In use · scanner is busy":
        "Occupé · le scanner travaille",
    "The scanner reports that it is scanning right now.":
        "Le scanner indique qu’il numérise en ce moment.",
    "Idle · searching…":
        "Inactif · recherche…",
    "Idle · no scanner":
        "Inactif · aucun scanner",
    "No scanner is connected yet.":
        "Aucun scanner n’est encore connecté.",
    "Idle · scanner on standby":
        "Inactif · scanner en veille",
    "The scanner reports that it is stopped or offline.":
        "Le scanner indique qu’il est arrêté ou hors ligne.",
    "The scanner is free. You can scan.":
        "Le scanner est libre. Vous pouvez numériser.",
    "Idle · installing OCR…":
        "Inactif · installation de l’OCR…",
    "The scanner is free now. You can scan.":
        "Le scanner est maintenant libre. Vous pouvez numériser.",
    "Scanner in use":
        "Scanner occupé",
    "The scanner is in use right now.\n\n{text}.\n{tip}\n\nPlease wait until the light at the top turns green, then try again.\nThis app will beep when the scanner is free.":
        "Le scanner est utilisé en ce moment.\n\n{text}.\n{tip}\n\nAttendez que le voyant en haut passe au vert, puis réessayez.\nL’application émettra un bip quand le scanner sera libre.",
    "Scanner in use: {text}. Wait for the green light.":
        "Scanner occupé : {text}. Attendez le voyant vert.",
    "Scanner":
        "Scanner",
    "Scanning":
        "Numérisation",
    "Text & translation":
        "Texte et traduction",
    "General":
        "Général",
    "Done":
        "Terminé",
    "Driver":
        "Pilote",
    "Model":
        "Modèle",
    "Network":
        "Réseau",
    "Auto (all drivers)":
        "Auto (tous les pilotes)",
    "No scanner found yet":
        "Aucun scanner trouvé pour l’instant",
    "Refresh":
        "Actualiser",
    "Driver setup":
        "Installer le pilote",
    "Find on network":
        "Rechercher sur le réseau",
    "Web panel":
        "Panneau web",
    "Find your model’s driver":
        "Trouver le pilote de votre modèle",
    "No network reply yet":
        "Pas encore de réponse du réseau",
    "Everything here is found automatically. Change it only if the wrong scanner is chosen.":
        "Tout ici est détecté automatiquement. Ne le modifiez que si le mauvais scanner est choisi.",
    "Save as":
        "Enregistrer en",
    "one PDF with every page":
        "un PDF avec toutes les pages",
    "one JPG image per page":
        "une image JPG par page",
    "the PDF and the JPG images from one scan":
        "le PDF et les images JPG d’une même numérisation",
    "Paper source":
        "Source du papier",
    "Auto · feeder if loaded, else flatbed":
        "Auto · chargeur s’il contient du papier, sinon vitre",
    "Flatbed (glass)":
        "Vitre (à plat)",
    "Document feeder":
        "Chargeur de documents",
    "Document feeder · both sides":
        "Chargeur de documents · recto verso",
    "Paper size":
        "Format du papier",
    "Resolution":
        "Résolution",
    "150 dpi · fast, small file":
        "150 dpi · rapide, petit fichier",
    "300 dpi · recommended":
        "300 dpi · recommandé",
    "600 dpi · fine detail":
        "600 dpi · détails fins",
    "Colour":
        "Couleur",
    "Greyscale":
        "Niveaux de gris",
    "Black and white":
        "Noir et blanc",
    "Save to":
        "Enregistrer dans",
    "Browse…":
        "Parcourir…",
    "Ask for a file name every time":
        "Demander un nom de fichier à chaque fois",
    "Open the file after scanning":
        "Ouvrir le fichier après la numérisation",
    "Auto source":
        "Source auto",
    "Flatbed":
        "Vitre",
    "Feeder":
        "Chargeur",
    "Feeder · 2 sides":
        "Chargeur · recto verso",
    "Make PDFs searchable with OCR (text recognition)":
        "Rendre les PDF consultables avec l’OCR (reconnaissance de texte)",
    "OCR languages":
        "Langues de l’OCR",
    "Auto · English + Greek + your system language":
        "Auto · anglais + grec + la langue de votre système",
    "Choose languages":
        "Choisir les langues",
    "Languages download automatically the first time they are used.":
        "Les langues se téléchargent automatiquement à la première utilisation.",
    "Also save the text as a .txt file":
        "Enregistrer aussi le texte dans un fichier .txt",
    "Translate automatically to":
        "Traduire automatiquement en",
    "Off":
        "Désactivé",
    "Translation service":
        "Service de traduction",
    "Google Translate (free)":
        "Google Traduction (gratuit)",
    "MyMemory (free)":
        "MyMemory (gratuit)",
    "LibreTranslate (your server)":
        "LibreTranslate (votre serveur)",
    "LibreTranslate server":
        "Serveur LibreTranslate",
    "API key (optional)":
        "Clé API (facultative)",
    "Free services need internet. Google falls back to MyMemory if it fails.":
        "Les services gratuits nécessitent Internet. Google bascule sur MyMemory en cas d’échec.",
    "Theme":
        "Thème",
    "Auto · follow Windows / system":
        "Auto · suivre Windows / le système",
    "Light":
        "Clair",
    "Dark":
        "Sombre",
    "Language":
        "Langue",
    "Auto · system language":
        "Auto · langue du système",
    "Updates":
        "Mises à jour",
    "Check for updates automatically":
        "Rechercher automatiquement les mises à jour",
    "Check now":
        "Vérifier maintenant",
    "Reset everything to Auto":
        "Tout remettre en Auto",
    "All settings are back to Auto.":
        "Tous les paramètres sont revenus en Auto.",
    "Restart to change the language?":
        "Redémarrer pour changer de langue ?",
    "The new language is used after a restart. Restart now?":
        "La nouvelle langue est utilisée après un redémarrage. Redémarrer maintenant ?",
    "Save scans to":
        "Enregistrer les numérisations dans",
    "Recognised text":
        "Texte reconnu",
    "Translation":
        "Traduction",
    "Translate":
        "Traduire",
    "From":
        "De",
    "To":
        "Vers",
    "Auto-detect":
        "Détection automatique",
    "Copy":
        "Copier",
    "Save .txt":
        "Enregistrer .txt",
    "Close":
        "Fermer",
    "Copied.":
        "Copié.",
    "Detected language: {lang}":
        "Langue détectée : {lang}",
    "Translating with {engine}…":
        "Traduction avec {engine}…",
    "Translated with {engine}. Detected: {lang}.":
        "Traduit avec {engine}. Détecté : {lang}.",
    "Translation failed. {error}":
        "La traduction a échoué. {error}",
    "Saved {name}":
        "{name} enregistré",
    "No text yet. Turn on OCR in Settings › Text & translation, then scan again.":
        "Pas encore de texte. Activez l’OCR dans Paramètres › Texte et traduction, puis numérisez à nouveau.",
    "Text of {name}":
        "Texte de {name}",
    "Looking for scanners ({drivers})…":
        "Recherche de scanners ({drivers})…",
    "Looking for scanners… {count} found so far.":
        "Recherche de scanners… {count} trouvé(s) jusqu’ici.",
    "Ready. Load the paper and click Scan.":
        "Prêt. Placez le papier et cliquez sur Numériser.",
    "Search stopped. Click Search again when you are ready.":
        "Recherche arrêtée. Cliquez sur Rechercher à nouveau quand vous êtes prêt.",
    "No scanners found. Check the cable or Wi-Fi and the installed driver (Settings › Scanner › Driver setup).":
        "Aucun scanner trouvé. Vérifiez le câble ou le Wi-Fi et le pilote installé (Paramètres › Scanner › Installer le pilote).",
    "The NAPS2 scanner engine was not found. Close and reopen the app to install it automatically.":
        "Le moteur de numérisation NAPS2 est introuvable. Fermez et rouvrez l’application pour l’installer automatiquement.",
    "Scanning a quick low-resolution preview…":
        "Aperçu rapide basse résolution en cours…",
    "Check the page placement, then scan at your chosen resolution.":
        "Vérifiez la position de la page, puis numérisez à la résolution choisie.",
    "Flatbed preview":
        "Aperçu de la vitre",
    "Back":
        "Retour",
    "Preview ready.":
        "Aperçu prêt.",
    "No preview was produced. Check the flatbed and scanner connection.":
        "Aucun aperçu n’a été produit. Vérifiez la vitre et la connexion du scanner.",
    "Scanning from {where}… Keep the scanner on until the file is saved.":
        "Numérisation depuis {where}… Laissez le scanner allumé jusqu’à l’enregistrement du fichier.",
    "the flatbed":
        "la vitre",
    "the document feeder":
        "le chargeur de documents",
    "the document feeder (both sides)":
        "le chargeur de documents (recto verso)",
    " Recognising text (OCR)…":
        " Reconnaissance du texte (OCR)…",
    "Downloading OCR languages ({langs}). One time only…":
        "Téléchargement des langues de l’OCR ({langs}). Une seule fois…",
    "OCR languages could not be installed ({langs}). Scanning without OCR.":
        "Les langues de l’OCR n’ont pas pu être installées ({langs}). Numérisation sans OCR.",
    "Scan cancelled.":
        "Numérisation annulée.",
    "The scanner is busy. Someone else may be using it. Wait a moment, then try again.":
        "Le scanner est occupé. Quelqu’un d’autre l’utilise peut-être. Patientez un instant, puis réessayez.",
    "Windows could not reach the Canon scanner. Turn it on, make sure it is on the same Wi-Fi, and check it in Canon IJ Scan Utility, then retry.":
        "Windows n’a pas pu joindre le scanner Canon. Allumez-le, vérifiez qu’il est sur le même Wi-Fi et contrôlez-le dans Canon IJ Scan Utility, puis réessayez.",
    "Epson Scan 2 could not open the scanner. In Epson Scan 2 Utility, add or test its network address, then retry.":
        "Epson Scan 2 n’a pas pu ouvrir le scanner. Dans Epson Scan 2 Utility, ajoutez ou testez son adresse réseau, puis réessayez.",
    "Scanner operation failed. {detail}":
        "L’opération du scanner a échoué. {detail}",
    "No pages were scanned. Check the paper and the scanner connection.":
        "Aucune page n’a été numérisée. Vérifiez le papier et la connexion du scanner.",
    "Could not save the scan. {error}":
        "Impossible d’enregistrer la numérisation. {error}",
    "The scan was kept as {path}":
        "La numérisation a été conservée sous {path}",
    "✓ Saved {files} in {folder}":
        "✓ {files} enregistré(s) dans {folder}",
    "{count} JPG pages":
        "{count} pages JPG",
    "text":
        "texte",
    "Translating the text to {lang}…":
        "Traduction du texte en {lang}…",
    "✓ Translation saved: {name}":
        "✓ Traduction enregistrée : {name}",
    "Could not start NAPS2. {error}":
        "Impossible de démarrer NAPS2. {error}",
    "Could not create {folder}. {error}\nChoose another folder in Settings › Scanning.":
        "Impossible de créer {folder}. {error}\nChoisissez un autre dossier dans Paramètres › Numérisation.",
    "Save scan":
        "Enregistrer la numérisation",
    "Scan in progress":
        "Numérisation en cours",
    "A scan is running. Cancel it and close the app?":
        "Une numérisation est en cours. L’annuler et fermer l’application ?",
    "JPG export needs PyMuPDF. Close and reopen the app to install it.":
        "L’export JPG nécessite PyMuPDF. Fermez et rouvrez l’application pour l’installer.",
    "Checking GitHub for a newer version…":
        "Recherche d’une version plus récente sur GitHub…",
    "Could not check for updates. {error}":
        "Impossible de vérifier les mises à jour. {error}",
    "You have the latest version (v{version}).":
        "Vous avez la dernière version (v{version}).",
    "Update available":
        "Mise à jour disponible",
    "{app} {version} is available (you have v{current}).\n\nWhat's new:\n{notes}\n\nDownload and install it now?":
        "{app} {version} est disponible (vous avez la v{current}).\n\nNouveautés :\n{notes}\n\nLa télécharger et l’installer maintenant ?",
    "No release notes.":
        "Pas de notes de version.",
    "Update {version} is waiting in Help.":
        "La mise à jour {version} vous attend dans Aide.",
    "Finish the scan first, then install the update from Help.":
        "Terminez d’abord la numérisation, puis installez la mise à jour depuis Aide.",
    "Downloading {version} from GitHub…":
        "Téléchargement de {version} depuis GitHub…",
    "Update failed. {error}":
        "La mise à jour a échoué. {error}",
    "macOS is running the app from a temporary read-only copy. Drag What the Scan into Applications, open it from there, then update again.":
        "macOS exécute l’application depuis une copie temporaire en lecture seule. Faites glisser What the Scan dans Applications, ouvrez-la depuis là, puis mettez à jour à nouveau.",
    "The app's folder can't be written to. Move the app to a folder you own (or Applications) and update again.":
        "Le dossier de l’application n’est pas accessible en écriture. Déplacez l’application dans un dossier qui vous appartient (ou dans Applications) et mettez à jour à nouveau.",
    "Update failed":
        "Échec de la mise à jour",
    "{error}\n\nOpen the release page to download it by hand?":
        "{error}\n\nOuvrir la page de la version pour la télécharger manuellement ?",
    "Updated to {version}. Restarting…":
        "Mis à jour vers {version}. Redémarrage…",
    "Choose a model to find its driver.":
        "Choisissez un modèle pour trouver son pilote.",
    "Install driver":
        "Installer le pilote",
    "Download and install the official {label} now?\n\nWindows may ask for permission. Choose No to open the support page instead.":
        "Télécharger et installer maintenant le pilote officiel {label} ?\n\nWindows peut demander l’autorisation. Choisissez Non pour ouvrir plutôt la page d’assistance.",
    "Preparing the official {label} installer…":
        "Préparation du programme d’installation officiel {label}…",
    "{label} installed. Looking for scanners…":
        "{label} installé. Recherche de scanners…",
    "Driver setup failed. {error}\nThe support page is opening so you can install it by hand.":
        "L’installation du pilote a échoué. {error}\nLa page d’assistance s’ouvre pour que vous puissiez l’installer manuellement.",
    "Searching the local network for scanners (Epson, Canon, HP, AirPrint)…":
        "Recherche de scanners sur le réseau local (Epson, Canon, HP, AirPrint)…",
    "answered as a network (eSCL) scanner ✓":
        "a répondu comme scanner réseau (eSCL) ✓",
    "This scanner has: {sources}":
        "Ce scanner dispose de : {sources}",
    "Network discovery failed. {error}":
        "La recherche sur le réseau a échoué. {error}",
    "Select your scanner's network address.":
        "Sélectionnez l’adresse réseau de votre scanner.",
    "No scanner replied on this local network.":
        "Aucun scanner n’a répondu sur ce réseau local.",
    "answered as a Canon scanner ✓":
        "a répondu comme scanner Canon ✓",
    "responds on the scanner port ✓":
        "répond sur le port du scanner ✓",
    "did not respond on the scanner port":
        "n’a pas répondu sur le port du scanner",
    "{brand} {ip} {state}. Scanning uses the driver chosen above.":
        "{brand} {ip} {state}. La numérisation utilise le pilote choisi ci-dessus.",
}

UI_DE = {
    "Brother's download page is opening. The model {model} is copied: paste it in the search box (Ctrl+V). Most Brother models also scan with no driver over the network.":
        "Die Download-Seite von Brother öffnet sich. Das Modell {model} ist kopiert: Fügen Sie es in die Suche ein (Strg+V). Die meisten Brother-Modelle scannen auch ohne Treiber über das Netzwerk.",
    "Connect Epson Scan 2 to the scanner":
        "Epson Scan 2 mit dem Scanner verbinden",
    "Epson Scan 2 does not know your scanner's network address yet. This happens after the driver is (re)installed. One time only:":
        "Epson Scan 2 kennt die Netzwerkadresse Ihres Scanners noch nicht. Das passiert nach einer (Neu-)Installation des Treibers. Nur einmal:",
    "1. Click “Open Epson Scan 2 Utility” below.\n2. At the top, in “Scanner”, choose “Settings”.\n3. Click “Add”, choose “Enter address”, press Ctrl+V (the address {ip} is already copied) and click OK.\n4. Click OK, close the utility and press Scan again.":
        "1. Klicken Sie unten auf „Epson Scan 2 Utility öffnen“.\n2. Wählen Sie oben bei „Scanner“ den Eintrag „Settings“.\n3. Klicken Sie auf „Add“, wählen Sie „Enter address“, drücken Sie Strg+V (die Adresse {ip} ist schon kopiert) und klicken Sie auf OK.\n4. Klicken Sie auf OK, schließen Sie das Programm und drücken Sie erneut Scannen.",
    "Open Epson Scan 2 Utility":
        "Epson Scan 2 Utility öffnen",
    "Could not open Epson Scan 2 Utility. {error}":
        "Epson Scan 2 Utility konnte nicht geöffnet werden. {error}",
    "{phone} (browser)": "{phone} (Browser)",
    "AirDrop":
        "AirDrop",
    "Send with AirDrop to an iPhone, iPad or Mac nearby":
        "Mit AirDrop an ein iPhone, iPad oder einen Mac in der Nähe senden",
    "AirDrop is open: choose the iPhone or Mac.":
        "AirDrop ist geöffnet: Wählen Sie das iPhone oder den Mac.",
    "AirDrop is not available on this Mac. Turn on Wi-Fi and Bluetooth.":
        "AirDrop ist auf diesem Mac nicht verfügbar. Schalten Sie WLAN und Bluetooth ein.",
    "So that your phone can send to this computer, Windows Firewall must let it in.\n\nAllow it now? Windows asks for permission once (only phones on your own network, only the ports of {app}).":
        "Damit Ihr Handy Dateien an diesen Computer senden kann, muss die Windows-Firewall es zulassen.\n\nJetzt zulassen? Windows fragt einmal nach der Berechtigung (nur Handys in Ihrem eigenen Netzwerk, nur die Ports von {app}).",
    "Waiting for Windows permission (firewall)…":
        "Warte auf die Windows-Berechtigung (Firewall)…",
    "✓ Windows Firewall lets your phone in now.":
        "✓ Die Windows-Firewall lässt Ihr Handy jetzt durch.",
    "Windows Firewall was not changed, so the phone may not be able to send to this computer.":
        "Die Windows-Firewall wurde nicht geändert, daher kann das Handy eventuell keine Dateien an diesen Computer senden.",
    "LocalSend for the phone":
        "LocalSend fürs Handy",
    "Trying Epson's other download server…":
        "Versuche den anderen Download-Server von Epson…",
    "{name} answers on the network ({ip}), but its scanner driver is not installed.":
        "{name} antwortet im Netzwerk ({ip}), aber der Scannertreiber ist nicht installiert.",
    "Scanner driver missing":
        "Scannertreiber fehlt",
    "{name} was found on the network ({ip}), but its scanner driver is not installed, so the app cannot scan with it.\n\nInstall the official {label} now? It is downloaded and installed automatically (a few minutes; Windows may ask for permission).":
        "{name} wurde im Netzwerk gefunden ({ip}), aber der Scannertreiber ist nicht installiert, daher kann die App damit nicht scannen.\n\nDen offiziellen {label} jetzt installieren? Er wird automatisch heruntergeladen und installiert (einige Minuten; Windows fragt eventuell nach der Berechtigung).",
    "Phone":
        "Handy",
    "Send to your phone or receive photos from it, on the same Wi-Fi (LocalSend app or QR code)":
        "An Ihr Handy senden oder Fotos davon empfangen, im selben WLAN (LocalSend-App oder QR-Code)",
    "Send scans to your phone and receive photos from it, on the same Wi-Fi.":
        "Senden Sie Scans an Ihr Handy und empfangen Sie Fotos davon, im selben WLAN.",
    "Receiving from the phone":
        "Empfang vom Handy",
    "Keep receiving on while the app is open":
        "Empfang eingeschaltet lassen, solange die App geöffnet ist",
    "When this is off, receiving opens for {minutes} minutes each time you press Phone.":
        "Ist dies aus, wird der Empfang bei jedem Druck auf Handy für {minutes} Minuten geöffnet.",
    "Phone photos":
        "Handyfotos",
    "Just save them in the scans folder":
        "Nur im Scan-Ordner speichern",
    "Make a PDF, like a scan (OCR, Word)":
        "Ein PDF daraus machen, wie ein Scan (OCR, Word)",
    "Name on the phone":
        "Name auf dem Handy",
    "How it works":
        "So funktioniert es",
    "1. Phone and computer on the same Wi-Fi.\n2. Install the free LocalSend app on the phone, or simply scan the QR code.\n3. Press Phone, next to Preview, choose the phone and Send.\n4. To send from the phone: in LocalSend choose “{name}”, or use the QR page.":
        "1. Handy und Computer im selben WLAN.\n2. Installieren Sie die kostenlose LocalSend-App auf dem Handy oder scannen Sie einfach den QR-Code.\n3. Drücken Sie Handy neben Vorschau, wählen Sie das Handy und Senden.\n4. Senden vom Handy: Wählen Sie in LocalSend „{name}“ oder nutzen Sie die QR-Seite.",
    "Get LocalSend":
        "LocalSend holen",
    "Idle · making a PDF from phone photos":
        "Bereit · erstelle ein PDF aus Handyfotos",
    "✓ Made {file} from {count} phone photo(s)":
        "✓ {file} aus {count} Handyfoto(s) erstellt",
    "Windows may now ask whether {app} can use the network.\n\nTick “Private networks” and click Allow, so your phone can reach this computer.":
        "Windows fragt jetzt eventuell, ob {app} das Netzwerk nutzen darf.\n\nAktivieren Sie „Private Netzwerke“ und klicken Sie auf Zulassen, damit Ihr Handy diesen Computer erreicht.",
    "The phone connection could not start. Another program may be using the network ports {ports}.":
        "Die Handyverbindung konnte nicht starten. Eventuell nutzt ein anderes Programm die Netzwerkports {ports}.",
    "Receiving is off. Press Phone to open it again.":
        "Der Empfang ist aus. Drücken Sie Handy, um ihn wieder zu öffnen.",
    "Receiving is on: the phone can send files to “{name}”.":
        "Der Empfang ist an: Das Handy kann Dateien an „{name}“ senden.",
    "Receiving is on for {time}: the phone can send files to “{name}”.":
        "Der Empfang ist für {time} an: Das Handy kann Dateien an „{name}“ senden.",
    "… and {count} more":
        "… und {count} weitere",
    "Files from a phone":
        "Dateien von einem Handy",
    "“{sender}” wants to send {count} file(s):":
        "„{sender}“ möchte {count} Datei(en) senden:",
    "They will be saved in {folder}.":
        "Sie werden in {folder} gespeichert.",
    "Accept":
        "Annehmen",
    "Decline":
        "Ablehnen",
    "Receiving files from {sender}…":
        "Empfange Dateien von {sender}…",
    "✓ Received {count} file(s) from {sender} in {folder}":
        "✓ {count} Datei(en) von {sender} in {folder} empfangen",
    "The photos were saved as they are, because a scan is running.":
        "Die Fotos wurden unverändert gespeichert, weil gerade ein Scan läuft.",
    "Making a PDF from {count} phone photo(s)…":
        "Erstelle ein PDF aus {count} Handyfoto(s)…",
    "This link has expired. Scan the QR code again.":
        "Dieser Link ist abgelaufen. Scannen Sie den QR-Code erneut.",
    "No scan yet. Scan something first, then reload this page.":
        "Noch kein Scan. Scannen Sie zuerst etwas und laden Sie dann diese Seite neu.",
    "Waiting for the computer to accept…":
        "Warte, bis der Computer annimmt…",
    "The computer declined the files.":
        "Der Computer hat die Dateien abgelehnt.",
    "The computer is receiving other files. Try again in a moment.":
        "Der Computer empfängt gerade andere Dateien. Versuchen Sie es gleich noch einmal.",
    "Sending failed. Check that the phone is on the same Wi-Fi and try again.":
        "Senden fehlgeschlagen. Prüfen Sie, ob das Handy im selben WLAN ist, und versuchen Sie es erneut.",
    "Sending {name}…":
        "Sende {name}…",
    "✓ Sent! The files are on the computer.":
        "✓ Gesendet! Die Dateien sind auf dem Computer.",
    "1 · Get the scan on this phone":
        "1 · Den Scan auf dieses Handy holen",
    "Reload":
        "Neu laden",
    "2 · Send photos or files to the computer":
        "2 · Fotos oder Dateien an den Computer senden",
    "Take a photo or choose files":
        "Foto aufnehmen oder Dateien wählen",
    "Send to your phone":
        "An Ihr Handy senden",
    "Phone and computer must be on the same Wi-Fi.":
        "Handy und Computer müssen im selben WLAN sein.",
    "Choose other files…":
        "Andere Dateien wählen…",
    "Phones with LocalSend":
        "Handys mit LocalSend",
    "Send":
        "Senden",
    "No LocalSend? Scan this":
        "Kein LocalSend? Scannen Sie das hier",
    "Point the phone camera at the code. A page opens where you can download the scan and send photos to this computer.":
        "Richten Sie die Handykamera auf den Code. Es öffnet sich eine Seite, auf der Sie den Scan herunterladen und Fotos an diesen Computer senden können.",
    "QR code not available.":
        "QR-Code nicht verfügbar.",
    "To send: {names}  ({size})":
        "Zu senden: {names}  ({size})",
    "Nothing to send yet. Scan first, or choose files.":
        "Noch nichts zu senden. Scannen Sie zuerst oder wählen Sie Dateien.",
    "Choose files for the phone":
        "Dateien für das Handy wählen",
    "Looking for phones… Open LocalSend on the phone.":
        "Suche Handys… Öffnen Sie LocalSend auf dem Handy.",
    "No phone found.\n1. Is the phone on the same Wi-Fi?\n2. Open the LocalSend app on the phone (free, Play Store / App Store).\n3. Or simply scan the QR code on the right.":
        "Kein Handy gefunden.\n1. Ist das Handy im selben WLAN?\n2. Öffnen Sie die LocalSend-App auf dem Handy (kostenlos, Play Store / App Store).\n3. Oder scannen Sie einfach den QR-Code rechts.",
    "Waiting for {phone} to accept… Tap Accept on the phone.":
        "Warte, bis {phone} annimmt… Tippen Sie auf dem Handy auf Annehmen.",
    "Sending to {phone}… {value}%":
        "Sende an {phone}… {value} %",
    "{phone} declined the files.":
        "{phone} hat die Dateien abgelehnt.",
    "{phone} is busy with another transfer. Try again in a moment.":
        "{phone} ist mit einer anderen Übertragung beschäftigt. Versuchen Sie es gleich noch einmal.",
    "{phone} asks for a PIN. Turn off the PIN in LocalSend settings on the phone.":
        "{phone} verlangt eine PIN. Schalten Sie die PIN in den LocalSend-Einstellungen auf dem Handy aus.",
    "Could not reach {phone}. Is LocalSend open and on the same Wi-Fi?":
        "{phone} ist nicht erreichbar. Ist LocalSend geöffnet und im selben WLAN?",
    "Sending cancelled.":
        "Senden abgebrochen.",
    "✓ Sent {count} file(s) to {phone}.":
        "✓ {count} Datei(en) an {phone} gesendet.",
    "Sending failed. {error}":
        "Senden fehlgeschlagen. {error}",
    "Also save an editable document (text from OCR)":
        "Zusätzlich ein bearbeitbares Dokument speichern (Text aus OCR)",
    "Document":
        "Dokument",
    "Word (.docx) · Microsoft Word":
        "Word (.docx) · Microsoft Word",
    "OpenDocument (.odt) · LibreOffice on Mac / Linux":
        "OpenDocument (.odt) · LibreOffice auf Mac / Linux",
    "Word export needs python-docx. Close and reopen the app to install it.":
        "Für den Word-Export wird python-docx benötigt. Schließen und öffnen Sie die App erneut, um es zu installieren.",
    "What to save, the paper and where the files go.":
        "Was gespeichert wird, das Papier und wohin die Dateien kommen.",
    "Recognise text in your scans and translate it.":
        "Text in Ihren Scans erkennen und übersetzen.",
    "Language, appearance and updates.":
        "Sprache, Darstellung und Updates.",
    "Output":
        "Ausgabe",
    "Paper":
        "Papier",
    "Saving":
        "Speichern",
    "Text recognition (OCR)":
        "Texterkennung (OCR)",
    "Appearance":
        "Darstellung",
    "Reset":
        "Zurücksetzen",
    "Settings":
        "Einstellungen",
    "Help":
        "Hilfe",
    "Ready":
        "Bereit",
    "Idle":
        "Leerlauf",
    "Scan":
        "Scannen",
    "Preview":
        "Vorschau",
    "Text":
        "Text",
    "Open last":
        "Letzte öffnen",
    "Open folder":
        "Ordner öffnen",
    "Cancel":
        "Abbrechen",
    "Stop search":
        "Suche stoppen",
    "Search again":
        "Erneut suchen",
    "Change…":
        "Ändern…",
    "Starting…":
        "Startet…",
    "Looking for scanners…":
        "Suche Scanner…",
    "Checking every driver at the same time.":
        "Prüfe alle Treiber gleichzeitig.",
    "Connected to {name}":
        "Verbunden mit {name}",
    "via {driver}":
        "über {driver}",
    "{brand} at {ip}":
        "{brand} unter {ip}",
    "{count} more in Settings":
        "{count} weitere in den Einstellungen",
    "No scanner connected":
        "Kein Scanner verbunden",
    "Turn the scanner on, check the USB cable or Wi-Fi, then click Search again.":
        "Schalten Sie den Scanner ein, prüfen Sie das USB-Kabel oder das WLAN und klicken Sie dann auf Erneut suchen.",
    "saves to {folder}":
        "speichert in {folder}",
    "asks for a file name":
        "fragt nach einem Dateinamen",
    "OCR":
        "OCR",
    "OCR off":
        "OCR aus",
    "translate → {lang}":
        "übersetzen → {lang}",
    "Scan and save in the format chosen in Settings (Ctrl+S)":
        "Scannen und im in den Einstellungen gewählten Format speichern (Strg+S)",
    "Quick low-resolution look at the flatbed (Ctrl+P)":
        "Schnelle Vorschau der Glasplatte in niedriger Auflösung (Strg+P)",
    "Recognised text and translation of the last scan (Ctrl+T)":
        "Erkannter Text und Übersetzung des letzten Scans (Strg+T)",
    "Open the last scanned file":
        "Die zuletzt gescannte Datei öffnen",
    "Open the folder with your scans":
        "Den Ordner mit Ihren Scans öffnen",
    "Stop the scan or search (Esc)":
        "Scan oder Suche stoppen (Esc)",
    "Look for scanners again (F5)":
        "Erneut nach Scannern suchen (F5)",
    "Choose another scanner or change scan settings":
        "Anderen Scanner wählen oder Scaneinstellungen ändern",
    "Scanner, scanning, text and appearance settings (Ctrl+,)":
        "Einstellungen für Scanner, Scannen, Text und Darstellung (Strg+,)",
    "Quick guide":
        "Kurzanleitung",
    "Check for updates…":
        "Nach Updates suchen…",
    "Project page on GitHub":
        "Projektseite auf GitHub",
    "About {app}":
        "Über {app}",
    "Update to {version}…":
        "Auf {version} aktualisieren…",
    "In use · scanning on this PC":
        "Belegt · scannt auf diesem PC",
    "In use by {who}":
        "Belegt durch {who}",
    "{user} on {host}":
        "{user} auf {host}",
    "Started at {time}. Wait until the light turns green.":
        "Begonnen um {time}. Warten Sie, bis das Licht grün wird.",
    "In use · scanner is busy":
        "Belegt · Scanner ist beschäftigt",
    "The scanner reports that it is scanning right now.":
        "Der Scanner meldet, dass er gerade scannt.",
    "Idle · searching…":
        "Leerlauf · suche…",
    "Idle · no scanner":
        "Leerlauf · kein Scanner",
    "No scanner is connected yet.":
        "Es ist noch kein Scanner verbunden.",
    "Idle · scanner on standby":
        "Leerlauf · Scanner im Standby",
    "The scanner reports that it is stopped or offline.":
        "Der Scanner meldet, dass er angehalten oder offline ist.",
    "The scanner is free. You can scan.":
        "Der Scanner ist frei. Sie können scannen.",
    "Idle · installing OCR…":
        "Leerlauf · installiere OCR…",
    "The scanner is free now. You can scan.":
        "Der Scanner ist jetzt frei. Sie können scannen.",
    "Scanner in use":
        "Scanner belegt",
    "The scanner is in use right now.\n\n{text}.\n{tip}\n\nPlease wait until the light at the top turns green, then try again.\nThis app will beep when the scanner is free.":
        "Der Scanner wird gerade benutzt.\n\n{text}.\n{tip}\n\nBitte warten Sie, bis das Licht oben grün wird, und versuchen Sie es dann erneut.\nDie App piept, wenn der Scanner frei ist.",
    "Scanner in use: {text}. Wait for the green light.":
        "Scanner belegt: {text}. Warten Sie auf das grüne Licht.",
    "Scanner":
        "Scanner",
    "Scanning":
        "Scannen",
    "Text & translation":
        "Text & Übersetzung",
    "General":
        "Allgemein",
    "Done":
        "Fertig",
    "Driver":
        "Treiber",
    "Model":
        "Modell",
    "Network":
        "Netzwerk",
    "Auto (all drivers)":
        "Auto (alle Treiber)",
    "No scanner found yet":
        "Noch kein Scanner gefunden",
    "Refresh":
        "Aktualisieren",
    "Driver setup":
        "Treiber installieren",
    "Find on network":
        "Im Netzwerk suchen",
    "Web panel":
        "Web-Oberfläche",
    "Find your model’s driver":
        "Treiber für Ihr Modell finden",
    "No network reply yet":
        "Noch keine Antwort aus dem Netzwerk",
    "Everything here is found automatically. Change it only if the wrong scanner is chosen.":
        "Alles hier wird automatisch erkannt. Ändern Sie es nur, wenn der falsche Scanner gewählt ist.",
    "Save as":
        "Speichern als",
    "one PDF with every page":
        "ein PDF mit allen Seiten",
    "one JPG image per page":
        "ein JPG-Bild pro Seite",
    "the PDF and the JPG images from one scan":
        "das PDF und die JPG-Bilder aus einem Scan",
    "Paper source":
        "Papierquelle",
    "Auto · feeder if loaded, else flatbed":
        "Auto · Einzug, wenn Papier eingelegt ist, sonst Glasplatte",
    "Flatbed (glass)":
        "Glasplatte (Flachbett)",
    "Document feeder":
        "Dokumenteneinzug",
    "Document feeder · both sides":
        "Dokumenteneinzug · beidseitig",
    "Paper size":
        "Papierformat",
    "Resolution":
        "Auflösung",
    "150 dpi · fast, small file":
        "150 dpi · schnell, kleine Datei",
    "300 dpi · recommended":
        "300 dpi · empfohlen",
    "600 dpi · fine detail":
        "600 dpi · feine Details",
    "Colour":
        "Farbe",
    "Greyscale":
        "Graustufen",
    "Black and white":
        "Schwarzweiß",
    "Save to":
        "Speichern in",
    "Browse…":
        "Durchsuchen…",
    "Ask for a file name every time":
        "Jedes Mal nach einem Dateinamen fragen",
    "Open the file after scanning":
        "Datei nach dem Scannen öffnen",
    "Auto source":
        "Auto-Quelle",
    "Flatbed":
        "Glasplatte",
    "Feeder":
        "Einzug",
    "Feeder · 2 sides":
        "Einzug · beidseitig",
    "Make PDFs searchable with OCR (text recognition)":
        "PDFs per OCR durchsuchbar machen (Texterkennung)",
    "OCR languages":
        "OCR-Sprachen",
    "Auto · English + Greek + your system language":
        "Auto · Englisch + Griechisch + Ihre Systemsprache",
    "Choose languages":
        "Sprachen wählen",
    "Languages download automatically the first time they are used.":
        "Sprachen werden bei der ersten Verwendung automatisch heruntergeladen.",
    "Also save the text as a .txt file":
        "Text zusätzlich als .txt-Datei speichern",
    "Translate automatically to":
        "Automatisch übersetzen nach",
    "Off":
        "Aus",
    "Translation service":
        "Übersetzungsdienst",
    "Google Translate (free)":
        "Google Übersetzer (kostenlos)",
    "MyMemory (free)":
        "MyMemory (kostenlos)",
    "LibreTranslate (your server)":
        "LibreTranslate (Ihr Server)",
    "LibreTranslate server":
        "LibreTranslate-Server",
    "API key (optional)":
        "API-Schlüssel (optional)",
    "Free services need internet. Google falls back to MyMemory if it fails.":
        "Kostenlose Dienste brauchen Internet. Fällt Google aus, wird MyMemory verwendet.",
    "Theme":
        "Design",
    "Auto · follow Windows / system":
        "Auto · Windows / System folgen",
    "Light":
        "Hell",
    "Dark":
        "Dunkel",
    "Language":
        "Sprache",
    "Auto · system language":
        "Auto · Systemsprache",
    "Updates":
        "Updates",
    "Check for updates automatically":
        "Automatisch nach Updates suchen",
    "Check now":
        "Jetzt prüfen",
    "Reset everything to Auto":
        "Alles auf Auto zurücksetzen",
    "All settings are back to Auto.":
        "Alle Einstellungen sind wieder auf Auto.",
    "Restart to change the language?":
        "Neu starten, um die Sprache zu wechseln?",
    "The new language is used after a restart. Restart now?":
        "Die neue Sprache wird nach einem Neustart verwendet. Jetzt neu starten?",
    "Save scans to":
        "Scans speichern in",
    "Recognised text":
        "Erkannter Text",
    "Translation":
        "Übersetzung",
    "Translate":
        "Übersetzen",
    "From":
        "Von",
    "To":
        "Nach",
    "Auto-detect":
        "Automatisch erkennen",
    "Copy":
        "Kopieren",
    "Save .txt":
        ".txt speichern",
    "Close":
        "Schließen",
    "Copied.":
        "Kopiert.",
    "Detected language: {lang}":
        "Erkannte Sprache: {lang}",
    "Translating with {engine}…":
        "Übersetze mit {engine}…",
    "Translated with {engine}. Detected: {lang}.":
        "Mit {engine} übersetzt. Erkannt: {lang}.",
    "Translation failed. {error}":
        "Übersetzung fehlgeschlagen. {error}",
    "Saved {name}":
        "{name} gespeichert",
    "No text yet. Turn on OCR in Settings › Text & translation, then scan again.":
        "Noch kein Text. Schalten Sie OCR unter Einstellungen › Text & Übersetzung ein und scannen Sie erneut.",
    "Text of {name}":
        "Text von {name}",
    "Looking for scanners ({drivers})…":
        "Suche Scanner ({drivers})…",
    "Looking for scanners… {count} found so far.":
        "Suche Scanner… bisher {count} gefunden.",
    "Ready. Load the paper and click Scan.":
        "Bereit. Legen Sie das Papier ein und klicken Sie auf Scannen.",
    "Search stopped. Click Search again when you are ready.":
        "Suche gestoppt. Klicken Sie auf Erneut suchen, wenn Sie bereit sind.",
    "No scanners found. Check the cable or Wi-Fi and the installed driver (Settings › Scanner › Driver setup).":
        "Keine Scanner gefunden. Prüfen Sie Kabel oder WLAN und den installierten Treiber (Einstellungen › Scanner › Treiber installieren).",
    "The NAPS2 scanner engine was not found. Close and reopen the app to install it automatically.":
        "Die Scan-Engine NAPS2 wurde nicht gefunden. Schließen und öffnen Sie die App erneut, um sie automatisch zu installieren.",
    "Scanning a quick low-resolution preview…":
        "Scanne eine schnelle Vorschau in niedriger Auflösung…",
    "Check the page placement, then scan at your chosen resolution.":
        "Prüfen Sie die Lage der Seite und scannen Sie dann in der gewählten Auflösung.",
    "Flatbed preview":
        "Vorschau der Glasplatte",
    "Back":
        "Zurück",
    "Preview ready.":
        "Vorschau fertig.",
    "No preview was produced. Check the flatbed and scanner connection.":
        "Es wurde keine Vorschau erstellt. Prüfen Sie die Glasplatte und die Scannerverbindung.",
    "Scanning from {where}… Keep the scanner on until the file is saved.":
        "Scanne von {where}… Lassen Sie den Scanner an, bis die Datei gespeichert ist.",
    "the flatbed":
        "der Glasplatte",
    "the document feeder":
        "dem Dokumenteneinzug",
    "the document feeder (both sides)":
        "dem Dokumenteneinzug (beidseitig)",
    " Recognising text (OCR)…":
        " Erkenne Text (OCR)…",
    "Downloading OCR languages ({langs}). One time only…":
        "Lade OCR-Sprachen herunter ({langs}). Nur einmal…",
    "OCR languages could not be installed ({langs}). Scanning without OCR.":
        "OCR-Sprachen konnten nicht installiert werden ({langs}). Scanne ohne OCR.",
    "Scan cancelled.":
        "Scan abgebrochen.",
    "The scanner is busy. Someone else may be using it. Wait a moment, then try again.":
        "Der Scanner ist beschäftigt. Eventuell benutzt ihn jemand anderes. Warten Sie einen Moment und versuchen Sie es dann erneut.",
    "Windows could not reach the Canon scanner. Turn it on, make sure it is on the same Wi-Fi, and check it in Canon IJ Scan Utility, then retry.":
        "Windows konnte den Canon-Scanner nicht erreichen. Schalten Sie ihn ein, stellen Sie sicher, dass er im selben WLAN ist, prüfen Sie ihn im Canon IJ Scan Utility und versuchen Sie es erneut.",
    "Epson Scan 2 could not open the scanner. In Epson Scan 2 Utility, add or test its network address, then retry.":
        "Epson Scan 2 konnte den Scanner nicht öffnen. Fügen Sie im Epson Scan 2 Utility seine Netzwerkadresse hinzu oder testen Sie sie, und versuchen Sie es erneut.",
    "Scanner operation failed. {detail}":
        "Scannervorgang fehlgeschlagen. {detail}",
    "No pages were scanned. Check the paper and the scanner connection.":
        "Es wurden keine Seiten gescannt. Prüfen Sie das Papier und die Scannerverbindung.",
    "Could not save the scan. {error}":
        "Der Scan konnte nicht gespeichert werden. {error}",
    "The scan was kept as {path}":
        "Der Scan wurde als {path} behalten",
    "✓ Saved {files} in {folder}":
        "✓ {files} in {folder} gespeichert",
    "{count} JPG pages":
        "{count} JPG-Seiten",
    "text":
        "Text",
    "Translating the text to {lang}…":
        "Übersetze den Text nach {lang}…",
    "✓ Translation saved: {name}":
        "✓ Übersetzung gespeichert: {name}",
    "Could not start NAPS2. {error}":
        "NAPS2 konnte nicht gestartet werden. {error}",
    "Could not create {folder}. {error}\nChoose another folder in Settings › Scanning.":
        "{folder} konnte nicht erstellt werden. {error}\nWählen Sie unter Einstellungen › Scannen einen anderen Ordner.",
    "Save scan":
        "Scan speichern",
    "Scan in progress":
        "Scan läuft",
    "A scan is running. Cancel it and close the app?":
        "Ein Scan läuft. Abbrechen und die App schließen?",
    "JPG export needs PyMuPDF. Close and reopen the app to install it.":
        "Für den JPG-Export wird PyMuPDF benötigt. Schließen und öffnen Sie die App erneut, um es zu installieren.",
    "Checking GitHub for a newer version…":
        "Suche auf GitHub nach einer neueren Version…",
    "Could not check for updates. {error}":
        "Updates konnten nicht geprüft werden. {error}",
    "You have the latest version (v{version}).":
        "Sie haben die neueste Version (v{version}).",
    "Update available":
        "Update verfügbar",
    "{app} {version} is available (you have v{current}).\n\nWhat's new:\n{notes}\n\nDownload and install it now?":
        "{app} {version} ist verfügbar (Sie haben v{current}).\n\nNeu:\n{notes}\n\nJetzt herunterladen und installieren?",
    "No release notes.":
        "Keine Versionshinweise.",
    "Update {version} is waiting in Help.":
        "Update {version} wartet unter Hilfe.",
    "Finish the scan first, then install the update from Help.":
        "Beenden Sie zuerst den Scan und installieren Sie das Update dann über Hilfe.",
    "Downloading {version} from GitHub…":
        "Lade {version} von GitHub herunter…",
    "Update failed. {error}":
        "Update fehlgeschlagen. {error}",
    "macOS is running the app from a temporary read-only copy. Drag What the Scan into Applications, open it from there, then update again.":
        "macOS führt die App aus einer temporären, schreibgeschützten Kopie aus. Ziehen Sie What the Scan in Programme, öffnen Sie es dort und aktualisieren Sie erneut.",
    "The app's folder can't be written to. Move the app to a folder you own (or Applications) and update again.":
        "In den Ordner der App kann nicht geschrieben werden. Verschieben Sie die App in einen eigenen Ordner (oder Programme) und aktualisieren Sie erneut.",
    "Update failed":
        "Update fehlgeschlagen",
    "{error}\n\nOpen the release page to download it by hand?":
        "{error}\n\nDie Release-Seite öffnen, um es manuell herunterzuladen?",
    "Updated to {version}. Restarting…":
        "Auf {version} aktualisiert. Starte neu…",
    "Choose a model to find its driver.":
        "Wählen Sie ein Modell, um seinen Treiber zu finden.",
    "Install driver":
        "Treiber installieren",
    "Download and install the official {label} now?\n\nWindows may ask for permission. Choose No to open the support page instead.":
        "Den offiziellen {label} jetzt herunterladen und installieren?\n\nWindows fragt eventuell nach der Berechtigung. Wählen Sie Nein, um stattdessen die Support-Seite zu öffnen.",
    "Preparing the official {label} installer…":
        "Bereite das offizielle {label}-Installationsprogramm vor…",
    "{label} installed. Looking for scanners…":
        "{label} installiert. Suche Scanner…",
    "Driver setup failed. {error}\nThe support page is opening so you can install it by hand.":
        "Treiberinstallation fehlgeschlagen. {error}\nDie Support-Seite wird geöffnet, damit Sie ihn manuell installieren können.",
    "Searching the local network for scanners (Epson, Canon, HP, AirPrint)…":
        "Suche im lokalen Netzwerk nach Scannern (Epson, Canon, HP, AirPrint)…",
    "answered as a network (eSCL) scanner ✓":
        "hat als Netzwerkscanner (eSCL) geantwortet ✓",
    "This scanner has: {sources}":
        "Dieser Scanner hat: {sources}",
    "Network discovery failed. {error}":
        "Netzwerksuche fehlgeschlagen. {error}",
    "Select your scanner's network address.":
        "Wählen Sie die Netzwerkadresse Ihres Scanners.",
    "No scanner replied on this local network.":
        "Kein Scanner hat in diesem lokalen Netzwerk geantwortet.",
    "answered as a Canon scanner ✓":
        "hat als Canon-Scanner geantwortet ✓",
    "responds on the scanner port ✓":
        "antwortet auf dem Scanner-Port ✓",
    "did not respond on the scanner port":
        "hat auf dem Scanner-Port nicht geantwortet",
    "{brand} {ip} {state}. Scanning uses the driver chosen above.":
        "{brand} {ip} {state}. Gescannt wird mit dem oben gewählten Treiber.",
}

UI_IT = {
    "Brother's download page is opening. The model {model} is copied: paste it in the search box (Ctrl+V). Most Brother models also scan with no driver over the network.":
        "Si apre la pagina di download di Brother. Il modello {model} è copiato: incollalo nella ricerca (Ctrl+V). La maggior parte dei modelli Brother acquisisce anche senza driver in rete.",
    "Connect Epson Scan 2 to the scanner":
        "Collega Epson Scan 2 allo scanner",
    "Epson Scan 2 does not know your scanner's network address yet. This happens after the driver is (re)installed. One time only:":
        "Epson Scan 2 non conosce ancora l’indirizzo di rete dello scanner. Succede dopo la (re)installazione del driver. Solo una volta:",
    "1. Click “Open Epson Scan 2 Utility” below.\n2. At the top, in “Scanner”, choose “Settings”.\n3. Click “Add”, choose “Enter address”, press Ctrl+V (the address {ip} is already copied) and click OK.\n4. Click OK, close the utility and press Scan again.":
        "1. Fai clic su «Apri Epson Scan 2 Utility» qui sotto.\n2. In alto, in «Scanner», scegli «Settings».\n3. Fai clic su «Add», scegli «Enter address», premi Ctrl+V (l’indirizzo {ip} è già copiato) e fai clic su OK.\n4. Fai clic su OK, chiudi l’utility e premi di nuovo Scansiona.",
    "Open Epson Scan 2 Utility":
        "Apri Epson Scan 2 Utility",
    "Could not open Epson Scan 2 Utility. {error}":
        "Impossibile aprire Epson Scan 2 Utility. {error}",
    "{phone} (browser)": "{phone} (browser)",
    "AirDrop":
        "AirDrop",
    "Send with AirDrop to an iPhone, iPad or Mac nearby":
        "Invia con AirDrop a un iPhone, iPad o Mac vicino",
    "AirDrop is open: choose the iPhone or Mac.":
        "AirDrop è aperto: scegli l’iPhone o il Mac.",
    "AirDrop is not available on this Mac. Turn on Wi-Fi and Bluetooth.":
        "AirDrop non è disponibile su questo Mac. Attiva Wi-Fi e Bluetooth.",
    "So that your phone can send to this computer, Windows Firewall must let it in.\n\nAllow it now? Windows asks for permission once (only phones on your own network, only the ports of {app}).":
        "Perché il telefono possa inviare file a questo computer, Windows Firewall deve consentirlo.\n\nConsentire ora? Windows chiede l’autorizzazione una sola volta (solo i telefoni della tua rete, solo le porte di {app}).",
    "Waiting for Windows permission (firewall)…":
        "In attesa dell’autorizzazione di Windows (firewall)…",
    "✓ Windows Firewall lets your phone in now.":
        "✓ Ora Windows Firewall lascia passare il tuo telefono.",
    "Windows Firewall was not changed, so the phone may not be able to send to this computer.":
        "Windows Firewall non è stato modificato, quindi il telefono potrebbe non riuscire a inviare file a questo computer.",
    "LocalSend for the phone":
        "LocalSend per il telefono",
    "Trying Epson's other download server…":
        "Provo l’altro server di download di Epson…",
    "{name} answers on the network ({ip}), but its scanner driver is not installed.":
        "{name} risponde in rete ({ip}), ma il suo driver dello scanner non è installato.",
    "Scanner driver missing":
        "Driver dello scanner mancante",
    "{name} was found on the network ({ip}), but its scanner driver is not installed, so the app cannot scan with it.\n\nInstall the official {label} now? It is downloaded and installed automatically (a few minutes; Windows may ask for permission).":
        "{name} è stato trovato in rete ({ip}), ma il suo driver dello scanner non è installato, quindi l’app non può acquisire con esso.\n\nInstallare ora il driver ufficiale {label}? Viene scaricato e installato automaticamente (pochi minuti; Windows potrebbe chiedere l’autorizzazione).",
    "Phone":
        "Telefono",
    "Send to your phone or receive photos from it, on the same Wi-Fi (LocalSend app or QR code)":
        "Invia al telefono o ricevi foto da esso, sulla stessa rete Wi-Fi (app LocalSend o codice QR)",
    "Send scans to your phone and receive photos from it, on the same Wi-Fi.":
        "Invia le scansioni al telefono e ricevi foto da esso, sulla stessa rete Wi-Fi.",
    "Receiving from the phone":
        "Ricezione dal telefono",
    "Keep receiving on while the app is open":
        "Mantieni attiva la ricezione finché l’app è aperta",
    "When this is off, receiving opens for {minutes} minutes each time you press Phone.":
        "Se disattivato, la ricezione si apre per {minutes} minuti ogni volta che premi Telefono.",
    "Phone photos":
        "Foto dal telefono",
    "Just save them in the scans folder":
        "Salvale semplicemente nella cartella delle scansioni",
    "Make a PDF, like a scan (OCR, Word)":
        "Crea un PDF, come una scansione (OCR, Word)",
    "Name on the phone":
        "Nome sul telefono",
    "How it works":
        "Come funziona",
    "1. Phone and computer on the same Wi-Fi.\n2. Install the free LocalSend app on the phone, or simply scan the QR code.\n3. Press Phone, next to Preview, choose the phone and Send.\n4. To send from the phone: in LocalSend choose “{name}”, or use the QR page.":
        "1. Telefono e computer sulla stessa rete Wi-Fi.\n2. Installa l’app gratuita LocalSend sul telefono, oppure scansiona semplicemente il codice QR.\n3. Premi Telefono, accanto ad Anteprima, scegli il telefono e Invia.\n4. Per inviare dal telefono: in LocalSend scegli «{name}», oppure usa la pagina del codice QR.",
    "Get LocalSend":
        "Scarica LocalSend",
    "Idle · making a PDF from phone photos":
        "Inattivo · creazione di un PDF dalle foto del telefono",
    "✓ Made {file} from {count} phone photo(s)":
        "✓ Creato {file} da {count} foto del telefono",
    "Windows may now ask whether {app} can use the network.\n\nTick “Private networks” and click Allow, so your phone can reach this computer.":
        "Windows potrebbe ora chiedere se {app} può usare la rete.\n\nSpunta «Reti private» e fai clic su Consenti, così il telefono può raggiungere questo computer.",
    "The phone connection could not start. Another program may be using the network ports {ports}.":
        "Impossibile avviare la connessione con il telefono. Un altro programma potrebbe usare le porte di rete {ports}.",
    "Receiving is off. Press Phone to open it again.":
        "La ricezione è disattivata. Premi Telefono per riaprirla.",
    "Receiving is on: the phone can send files to “{name}”.":
        "La ricezione è attiva: il telefono può inviare file a «{name}».",
    "Receiving is on for {time}: the phone can send files to “{name}”.":
        "La ricezione è attiva per {time}: il telefono può inviare file a «{name}».",
    "… and {count} more":
        "… e altri {count}",
    "Files from a phone":
        "File da un telefono",
    "“{sender}” wants to send {count} file(s):":
        "«{sender}» vuole inviare {count} file:",
    "They will be saved in {folder}.":
        "Verranno salvati in {folder}.",
    "Accept":
        "Accetta",
    "Decline":
        "Rifiuta",
    "Receiving files from {sender}…":
        "Ricezione dei file da {sender}…",
    "✓ Received {count} file(s) from {sender} in {folder}":
        "✓ Ricevuti {count} file da {sender} in {folder}",
    "The photos were saved as they are, because a scan is running.":
        "Le foto sono state salvate così come sono, perché è in corso una scansione.",
    "Making a PDF from {count} phone photo(s)…":
        "Creazione di un PDF da {count} foto del telefono…",
    "This link has expired. Scan the QR code again.":
        "Questo link è scaduto. Scansiona di nuovo il codice QR.",
    "No scan yet. Scan something first, then reload this page.":
        "Nessuna scansione per ora. Prima acquisisci qualcosa, poi ricarica questa pagina.",
    "Waiting for the computer to accept…":
        "In attesa che il computer accetti…",
    "The computer declined the files.":
        "Il computer ha rifiutato i file.",
    "The computer is receiving other files. Try again in a moment.":
        "Il computer sta ricevendo altri file. Riprova tra un momento.",
    "Sending failed. Check that the phone is on the same Wi-Fi and try again.":
        "Invio non riuscito. Verifica che il telefono sia sulla stessa rete Wi-Fi e riprova.",
    "Sending {name}…":
        "Invio di {name}…",
    "✓ Sent! The files are on the computer.":
        "✓ Inviati! I file sono sul computer.",
    "1 · Get the scan on this phone":
        "1 · Ricevi la scansione su questo telefono",
    "Reload":
        "Ricarica",
    "2 · Send photos or files to the computer":
        "2 · Invia foto o file al computer",
    "Take a photo or choose files":
        "Scatta una foto o scegli dei file",
    "Send to your phone":
        "Invia al telefono",
    "Phone and computer must be on the same Wi-Fi.":
        "Telefono e computer devono essere sulla stessa rete Wi-Fi.",
    "Choose other files…":
        "Scegli altri file…",
    "Phones with LocalSend":
        "Telefoni con LocalSend",
    "Send":
        "Invia",
    "No LocalSend? Scan this":
        "Niente LocalSend? Scansiona questo",
    "Point the phone camera at the code. A page opens where you can download the scan and send photos to this computer.":
        "Inquadra il codice con la fotocamera del telefono. Si apre una pagina da cui scaricare la scansione e inviare foto a questo computer.",
    "QR code not available.":
        "Codice QR non disponibile.",
    "To send: {names}  ({size})":
        "Da inviare: {names}  ({size})",
    "Nothing to send yet. Scan first, or choose files.":
        "Ancora niente da inviare. Prima acquisisci, oppure scegli dei file.",
    "Choose files for the phone":
        "Scegli i file per il telefono",
    "Looking for phones… Open LocalSend on the phone.":
        "Ricerca dei telefoni… Apri LocalSend sul telefono.",
    "No phone found.\n1. Is the phone on the same Wi-Fi?\n2. Open the LocalSend app on the phone (free, Play Store / App Store).\n3. Or simply scan the QR code on the right.":
        "Nessun telefono trovato.\n1. Il telefono è sulla stessa rete Wi-Fi?\n2. Apri l’app LocalSend sul telefono (gratuita, Play Store / App Store).\n3. Oppure scansiona semplicemente il codice QR a destra.",
    "Waiting for {phone} to accept… Tap Accept on the phone.":
        "In attesa che {phone} accetti… Tocca Accetta sul telefono.",
    "Sending to {phone}… {value}%":
        "Invio a {phone}… {value}%",
    "{phone} declined the files.":
        "{phone} ha rifiutato i file.",
    "{phone} is busy with another transfer. Try again in a moment.":
        "{phone} è occupato con un altro trasferimento. Riprova tra un momento.",
    "{phone} asks for a PIN. Turn off the PIN in LocalSend settings on the phone.":
        "{phone} chiede un PIN. Disattiva il PIN nelle impostazioni di LocalSend sul telefono.",
    "Could not reach {phone}. Is LocalSend open and on the same Wi-Fi?":
        "Impossibile raggiungere {phone}. LocalSend è aperto e sulla stessa rete Wi-Fi?",
    "Sending cancelled.":
        "Invio annullato.",
    "✓ Sent {count} file(s) to {phone}.":
        "✓ Inviati {count} file a {phone}.",
    "Sending failed. {error}":
        "Invio non riuscito. {error}",
    "Also save an editable document (text from OCR)":
        "Salva anche un documento modificabile (testo dall’OCR)",
    "Document":
        "Documento",
    "Word (.docx) · Microsoft Word":
        "Word (.docx) · Microsoft Word",
    "OpenDocument (.odt) · LibreOffice on Mac / Linux":
        "OpenDocument (.odt) · LibreOffice su Mac / Linux",
    "Word export needs python-docx. Close and reopen the app to install it.":
        "L’esportazione in Word richiede python-docx. Chiudi e riapri l’app per installarlo.",
    "What to save, the paper and where the files go.":
        "Cosa salvare, la carta e dove vanno i file.",
    "Recognise text in your scans and translate it.":
        "Riconosci il testo nelle scansioni e traducilo.",
    "Language, appearance and updates.":
        "Lingua, aspetto e aggiornamenti.",
    "Output":
        "Uscita",
    "Paper":
        "Carta",
    "Saving":
        "Salvataggio",
    "Text recognition (OCR)":
        "Riconoscimento del testo (OCR)",
    "Appearance":
        "Aspetto",
    "Reset":
        "Ripristina",
    "Settings":
        "Impostazioni",
    "Help":
        "Aiuto",
    "Ready":
        "Pronto",
    "Idle":
        "Inattivo",
    "Scan":
        "Scansiona",
    "Preview":
        "Anteprima",
    "Text":
        "Testo",
    "Open last":
        "Apri ultimo",
    "Open folder":
        "Apri cartella",
    "Cancel":
        "Annulla",
    "Stop search":
        "Ferma ricerca",
    "Search again":
        "Cerca di nuovo",
    "Change…":
        "Cambia…",
    "Starting…":
        "Avvio…",
    "Looking for scanners…":
        "Ricerca degli scanner…",
    "Checking every driver at the same time.":
        "Controllo di tutti i driver contemporaneamente.",
    "Connected to {name}":
        "Connesso a {name}",
    "via {driver}":
        "tramite {driver}",
    "{brand} at {ip}":
        "{brand} su {ip}",
    "{count} more in Settings":
        "altri {count} nelle Impostazioni",
    "No scanner connected":
        "Nessuno scanner collegato",
    "Turn the scanner on, check the USB cable or Wi-Fi, then click Search again.":
        "Accendi lo scanner, controlla il cavo USB o il Wi-Fi, poi fai clic su Cerca di nuovo.",
    "saves to {folder}":
        "salva in {folder}",
    "asks for a file name":
        "chiede un nome file",
    "OCR":
        "OCR",
    "OCR off":
        "OCR disattivato",
    "translate → {lang}":
        "traduci → {lang}",
    "Scan and save in the format chosen in Settings (Ctrl+S)":
        "Acquisisci e salva nel formato scelto nelle Impostazioni (Ctrl+S)",
    "Quick low-resolution look at the flatbed (Ctrl+P)":
        "Rapida anteprima a bassa risoluzione del piano (Ctrl+P)",
    "Recognised text and translation of the last scan (Ctrl+T)":
        "Testo riconosciuto e traduzione dell’ultima scansione (Ctrl+T)",
    "Open the last scanned file":
        "Apri l’ultimo file acquisito",
    "Open the folder with your scans":
        "Apri la cartella con le tue scansioni",
    "Stop the scan or search (Esc)":
        "Ferma la scansione o la ricerca (Esc)",
    "Look for scanners again (F5)":
        "Cerca di nuovo gli scanner (F5)",
    "Choose another scanner or change scan settings":
        "Scegli un altro scanner o cambia le impostazioni di scansione",
    "Scanner, scanning, text and appearance settings (Ctrl+,)":
        "Impostazioni di scanner, scansione, testo e aspetto (Ctrl+,)",
    "Quick guide":
        "Guida rapida",
    "Check for updates…":
        "Cerca aggiornamenti…",
    "Project page on GitHub":
        "Pagina del progetto su GitHub",
    "About {app}":
        "Informazioni su {app}",
    "Update to {version}…":
        "Aggiorna a {version}…",
    "In use · scanning on this PC":
        "In uso · scansione su questo PC",
    "In use by {who}":
        "In uso da {who}",
    "{user} on {host}":
        "{user} su {host}",
    "Started at {time}. Wait until the light turns green.":
        "Iniziata alle {time}. Attendi che la luce diventi verde.",
    "In use · scanner is busy":
        "In uso · lo scanner è occupato",
    "The scanner reports that it is scanning right now.":
        "Lo scanner segnala che sta acquisendo in questo momento.",
    "Idle · searching…":
        "Inattivo · ricerca…",
    "Idle · no scanner":
        "Inattivo · nessuno scanner",
    "No scanner is connected yet.":
        "Nessuno scanner è ancora collegato.",
    "Idle · scanner on standby":
        "Inattivo · scanner in standby",
    "The scanner reports that it is stopped or offline.":
        "Lo scanner segnala di essere fermo o non in linea.",
    "The scanner is free. You can scan.":
        "Lo scanner è libero. Puoi acquisire.",
    "Idle · installing OCR…":
        "Inattivo · installazione dell’OCR…",
    "The scanner is free now. You can scan.":
        "Ora lo scanner è libero. Puoi acquisire.",
    "Scanner in use":
        "Scanner in uso",
    "The scanner is in use right now.\n\n{text}.\n{tip}\n\nPlease wait until the light at the top turns green, then try again.\nThis app will beep when the scanner is free.":
        "Lo scanner è in uso in questo momento.\n\n{text}.\n{tip}\n\nAttendi che la luce in alto diventi verde, poi riprova.\nL’app emetterà un segnale acustico quando lo scanner sarà libero.",
    "Scanner in use: {text}. Wait for the green light.":
        "Scanner in uso: {text}. Attendi la luce verde.",
    "Scanner":
        "Scanner",
    "Scanning":
        "Scansione",
    "Text & translation":
        "Testo e traduzione",
    "General":
        "Generale",
    "Done":
        "Fatto",
    "Driver":
        "Driver",
    "Model":
        "Modello",
    "Network":
        "Rete",
    "Auto (all drivers)":
        "Auto (tutti i driver)",
    "No scanner found yet":
        "Nessuno scanner trovato per ora",
    "Refresh":
        "Aggiorna",
    "Driver setup":
        "Installa driver",
    "Find on network":
        "Cerca in rete",
    "Web panel":
        "Pannello web",
    "Find your model’s driver":
        "Trova il driver del tuo modello",
    "No network reply yet":
        "Ancora nessuna risposta dalla rete",
    "Everything here is found automatically. Change it only if the wrong scanner is chosen.":
        "Qui tutto viene rilevato automaticamente. Modificalo solo se è scelto lo scanner sbagliato.",
    "Save as":
        "Salva come",
    "one PDF with every page":
        "un PDF con tutte le pagine",
    "one JPG image per page":
        "un’immagine JPG per pagina",
    "the PDF and the JPG images from one scan":
        "il PDF e le immagini JPG da un’unica scansione",
    "Paper source":
        "Origine carta",
    "Auto · feeder if loaded, else flatbed":
        "Auto · alimentatore se caricato, altrimenti piano",
    "Flatbed (glass)":
        "Piano (vetro)",
    "Document feeder":
        "Alimentatore documenti",
    "Document feeder · both sides":
        "Alimentatore documenti · fronte/retro",
    "Paper size":
        "Formato carta",
    "Resolution":
        "Risoluzione",
    "150 dpi · fast, small file":
        "150 dpi · veloce, file piccolo",
    "300 dpi · recommended":
        "300 dpi · consigliato",
    "600 dpi · fine detail":
        "600 dpi · dettagli fini",
    "Colour":
        "Colore",
    "Greyscale":
        "Scala di grigi",
    "Black and white":
        "Bianco e nero",
    "Save to":
        "Salva in",
    "Browse…":
        "Sfoglia…",
    "Ask for a file name every time":
        "Chiedi ogni volta un nome file",
    "Open the file after scanning":
        "Apri il file dopo la scansione",
    "Auto source":
        "Origine auto",
    "Flatbed":
        "Piano",
    "Feeder":
        "Alimentatore",
    "Feeder · 2 sides":
        "Alimentatore · fronte/retro",
    "Make PDFs searchable with OCR (text recognition)":
        "Rendi i PDF ricercabili con l’OCR (riconoscimento del testo)",
    "OCR languages":
        "Lingue OCR",
    "Auto · English + Greek + your system language":
        "Auto · inglese + greco + la lingua del sistema",
    "Choose languages":
        "Scegli le lingue",
    "Languages download automatically the first time they are used.":
        "Le lingue si scaricano automaticamente al primo utilizzo.",
    "Also save the text as a .txt file":
        "Salva anche il testo in un file .txt",
    "Translate automatically to":
        "Traduci automaticamente in",
    "Off":
        "Disattivato",
    "Translation service":
        "Servizio di traduzione",
    "Google Translate (free)":
        "Google Traduttore (gratuito)",
    "MyMemory (free)":
        "MyMemory (gratuito)",
    "LibreTranslate (your server)":
        "LibreTranslate (il tuo server)",
    "LibreTranslate server":
        "Server LibreTranslate",
    "API key (optional)":
        "Chiave API (facoltativa)",
    "Free services need internet. Google falls back to MyMemory if it fails.":
        "I servizi gratuiti richiedono Internet. Se Google non funziona si passa a MyMemory.",
    "Theme":
        "Tema",
    "Auto · follow Windows / system":
        "Auto · segui Windows / sistema",
    "Light":
        "Chiaro",
    "Dark":
        "Scuro",
    "Language":
        "Lingua",
    "Auto · system language":
        "Auto · lingua del sistema",
    "Updates":
        "Aggiornamenti",
    "Check for updates automatically":
        "Cerca aggiornamenti automaticamente",
    "Check now":
        "Controlla ora",
    "Reset everything to Auto":
        "Riporta tutto su Auto",
    "All settings are back to Auto.":
        "Tutte le impostazioni sono tornate su Auto.",
    "Restart to change the language?":
        "Riavviare per cambiare lingua?",
    "The new language is used after a restart. Restart now?":
        "La nuova lingua viene usata dopo il riavvio. Riavviare ora?",
    "Save scans to":
        "Salva le scansioni in",
    "Recognised text":
        "Testo riconosciuto",
    "Translation":
        "Traduzione",
    "Translate":
        "Traduci",
    "From":
        "Da",
    "To":
        "A",
    "Auto-detect":
        "Rilevamento automatico",
    "Copy":
        "Copia",
    "Save .txt":
        "Salva .txt",
    "Close":
        "Chiudi",
    "Copied.":
        "Copiato.",
    "Detected language: {lang}":
        "Lingua rilevata: {lang}",
    "Translating with {engine}…":
        "Traduzione con {engine}…",
    "Translated with {engine}. Detected: {lang}.":
        "Tradotto con {engine}. Rilevato: {lang}.",
    "Translation failed. {error}":
        "Traduzione non riuscita. {error}",
    "Saved {name}":
        "{name} salvato",
    "No text yet. Turn on OCR in Settings › Text & translation, then scan again.":
        "Ancora nessun testo. Attiva l’OCR in Impostazioni › Testo e traduzione, poi acquisisci di nuovo.",
    "Text of {name}":
        "Testo di {name}",
    "Looking for scanners ({drivers})…":
        "Ricerca degli scanner ({drivers})…",
    "Looking for scanners… {count} found so far.":
        "Ricerca degli scanner… {count} trovati finora.",
    "Ready. Load the paper and click Scan.":
        "Pronto. Inserisci la carta e fai clic su Scansiona.",
    "Search stopped. Click Search again when you are ready.":
        "Ricerca interrotta. Fai clic su Cerca di nuovo quando sei pronto.",
    "No scanners found. Check the cable or Wi-Fi and the installed driver (Settings › Scanner › Driver setup).":
        "Nessuno scanner trovato. Controlla il cavo o il Wi-Fi e il driver installato (Impostazioni › Scanner › Installa driver).",
    "The NAPS2 scanner engine was not found. Close and reopen the app to install it automatically.":
        "Il motore di scansione NAPS2 non è stato trovato. Chiudi e riapri l’app per installarlo automaticamente.",
    "Scanning a quick low-resolution preview…":
        "Acquisizione di un’anteprima rapida a bassa risoluzione…",
    "Check the page placement, then scan at your chosen resolution.":
        "Controlla la posizione della pagina, poi acquisisci alla risoluzione scelta.",
    "Flatbed preview":
        "Anteprima del piano",
    "Back":
        "Indietro",
    "Preview ready.":
        "Anteprima pronta.",
    "No preview was produced. Check the flatbed and scanner connection.":
        "Nessuna anteprima prodotta. Controlla il piano e il collegamento dello scanner.",
    "Scanning from {where}… Keep the scanner on until the file is saved.":
        "Acquisizione da {where}… Tieni acceso lo scanner finché il file non è salvato.",
    "the flatbed":
        "piano",
    "the document feeder":
        "alimentatore documenti",
    "the document feeder (both sides)":
        "alimentatore documenti (fronte/retro)",
    " Recognising text (OCR)…":
        " Riconoscimento del testo (OCR)…",
    "Downloading OCR languages ({langs}). One time only…":
        "Download delle lingue OCR ({langs}). Solo la prima volta…",
    "OCR languages could not be installed ({langs}). Scanning without OCR.":
        "Impossibile installare le lingue OCR ({langs}). Acquisizione senza OCR.",
    "Scan cancelled.":
        "Scansione annullata.",
    "The scanner is busy. Someone else may be using it. Wait a moment, then try again.":
        "Lo scanner è occupato. Forse lo sta usando qualcun altro. Attendi un momento, poi riprova.",
    "Windows could not reach the Canon scanner. Turn it on, make sure it is on the same Wi-Fi, and check it in Canon IJ Scan Utility, then retry.":
        "Windows non è riuscito a raggiungere lo scanner Canon. Accendilo, verifica che sia sulla stessa rete Wi-Fi e controllalo in Canon IJ Scan Utility, poi riprova.",
    "Epson Scan 2 could not open the scanner. In Epson Scan 2 Utility, add or test its network address, then retry.":
        "Epson Scan 2 non è riuscito ad aprire lo scanner. In Epson Scan 2 Utility aggiungi o verifica il suo indirizzo di rete, poi riprova.",
    "Scanner operation failed. {detail}":
        "Operazione dello scanner non riuscita. {detail}",
    "No pages were scanned. Check the paper and the scanner connection.":
        "Nessuna pagina acquisita. Controlla la carta e il collegamento dello scanner.",
    "Could not save the scan. {error}":
        "Impossibile salvare la scansione. {error}",
    "The scan was kept as {path}":
        "La scansione è stata conservata come {path}",
    "✓ Saved {files} in {folder}":
        "✓ Salvato {files} in {folder}",
    "{count} JPG pages":
        "{count} pagine JPG",
    "text":
        "testo",
    "Translating the text to {lang}…":
        "Traduzione del testo in {lang}…",
    "✓ Translation saved: {name}":
        "✓ Traduzione salvata: {name}",
    "Could not start NAPS2. {error}":
        "Impossibile avviare NAPS2. {error}",
    "Could not create {folder}. {error}\nChoose another folder in Settings › Scanning.":
        "Impossibile creare {folder}. {error}\nScegli un’altra cartella in Impostazioni › Scansione.",
    "Save scan":
        "Salva scansione",
    "Scan in progress":
        "Scansione in corso",
    "A scan is running. Cancel it and close the app?":
        "È in corso una scansione. Annullarla e chiudere l’app?",
    "JPG export needs PyMuPDF. Close and reopen the app to install it.":
        "L’esportazione in JPG richiede PyMuPDF. Chiudi e riapri l’app per installarlo.",
    "Checking GitHub for a newer version…":
        "Ricerca di una versione più recente su GitHub…",
    "Could not check for updates. {error}":
        "Impossibile cercare aggiornamenti. {error}",
    "You have the latest version (v{version}).":
        "Hai l’ultima versione (v{version}).",
    "Update available":
        "Aggiornamento disponibile",
    "{app} {version} is available (you have v{current}).\n\nWhat's new:\n{notes}\n\nDownload and install it now?":
        "{app} {version} è disponibile (hai la v{current}).\n\nNovità:\n{notes}\n\nScaricarla e installarla ora?",
    "No release notes.":
        "Nessuna nota di rilascio.",
    "Update {version} is waiting in Help.":
        "L’aggiornamento {version} ti aspetta in Aiuto.",
    "Finish the scan first, then install the update from Help.":
        "Termina prima la scansione, poi installa l’aggiornamento da Aiuto.",
    "Downloading {version} from GitHub…":
        "Download di {version} da GitHub…",
    "Update failed. {error}":
        "Aggiornamento non riuscito. {error}",
    "macOS is running the app from a temporary read-only copy. Drag What the Scan into Applications, open it from there, then update again.":
        "macOS esegue l’app da una copia temporanea di sola lettura. Trascina What the Scan in Applicazioni, aprila da lì, poi aggiorna di nuovo.",
    "The app's folder can't be written to. Move the app to a folder you own (or Applications) and update again.":
        "Non è possibile scrivere nella cartella dell’app. Sposta l’app in una cartella tua (o in Applicazioni) e aggiorna di nuovo.",
    "Update failed":
        "Aggiornamento non riuscito",
    "{error}\n\nOpen the release page to download it by hand?":
        "{error}\n\nAprire la pagina della versione per scaricarla manualmente?",
    "Updated to {version}. Restarting…":
        "Aggiornato a {version}. Riavvio…",
    "Choose a model to find its driver.":
        "Scegli un modello per trovarne il driver.",
    "Install driver":
        "Installa driver",
    "Download and install the official {label} now?\n\nWindows may ask for permission. Choose No to open the support page instead.":
        "Scaricare e installare ora il driver ufficiale {label}?\n\nWindows potrebbe chiedere l’autorizzazione. Scegli No per aprire invece la pagina di supporto.",
    "Preparing the official {label} installer…":
        "Preparazione del programma di installazione ufficiale {label}…",
    "{label} installed. Looking for scanners…":
        "{label} installato. Ricerca degli scanner…",
    "Driver setup failed. {error}\nThe support page is opening so you can install it by hand.":
        "Installazione del driver non riuscita. {error}\nSi apre la pagina di supporto per installarlo manualmente.",
    "Searching the local network for scanners (Epson, Canon, HP, AirPrint)…":
        "Ricerca di scanner nella rete locale (Epson, Canon, HP, AirPrint)…",
    "answered as a network (eSCL) scanner ✓":
        "ha risposto come scanner di rete (eSCL) ✓",
    "This scanner has: {sources}":
        "Questo scanner ha: {sources}",
    "Network discovery failed. {error}":
        "Ricerca in rete non riuscita. {error}",
    "Select your scanner's network address.":
        "Seleziona l’indirizzo di rete del tuo scanner.",
    "No scanner replied on this local network.":
        "Nessuno scanner ha risposto su questa rete locale.",
    "answered as a Canon scanner ✓":
        "ha risposto come scanner Canon ✓",
    "responds on the scanner port ✓":
        "risponde sulla porta dello scanner ✓",
    "did not respond on the scanner port":
        "non ha risposto sulla porta dello scanner",
    "{brand} {ip} {state}. Scanning uses the driver chosen above.":
        "{brand} {ip} {state}. La scansione usa il driver scelto sopra.",
}

UI_ES = {
    "Brother's download page is opening. The model {model} is copied: paste it in the search box (Ctrl+V). Most Brother models also scan with no driver over the network.":
        "Se abre la página de descargas de Brother. El modelo {model} está copiado: pégalo en la búsqueda (Ctrl+V). La mayoría de modelos Brother también escanean sin controlador por la red.",
    "Connect Epson Scan 2 to the scanner":
        "Conectar Epson Scan 2 con el escáner",
    "Epson Scan 2 does not know your scanner's network address yet. This happens after the driver is (re)installed. One time only:":
        "Epson Scan 2 todavía no conoce la dirección de red de tu escáner. Pasa tras (re)instalar el controlador. Solo una vez:",
    "1. Click “Open Epson Scan 2 Utility” below.\n2. At the top, in “Scanner”, choose “Settings”.\n3. Click “Add”, choose “Enter address”, press Ctrl+V (the address {ip} is already copied) and click OK.\n4. Click OK, close the utility and press Scan again.":
        "1. Haz clic en «Abrir Epson Scan 2 Utility» abajo.\n2. Arriba, en «Scanner», elige «Settings».\n3. Haz clic en «Add», elige «Enter address», pulsa Ctrl+V (la dirección {ip} ya está copiada) y haz clic en OK.\n4. Haz clic en OK, cierra la utilidad y pulsa Escanear de nuevo.",
    "Open Epson Scan 2 Utility":
        "Abrir Epson Scan 2 Utility",
    "Could not open Epson Scan 2 Utility. {error}":
        "No se pudo abrir Epson Scan 2 Utility. {error}",
    "{phone} (browser)": "{phone} (navegador)",
    "AirDrop":
        "AirDrop",
    "Send with AirDrop to an iPhone, iPad or Mac nearby":
        "Enviar con AirDrop a un iPhone, iPad o Mac cercano",
    "AirDrop is open: choose the iPhone or Mac.":
        "AirDrop está abierto: elige el iPhone o el Mac.",
    "AirDrop is not available on this Mac. Turn on Wi-Fi and Bluetooth.":
        "AirDrop no está disponible en este Mac. Activa la Wi-Fi y el Bluetooth.",
    "So that your phone can send to this computer, Windows Firewall must let it in.\n\nAllow it now? Windows asks for permission once (only phones on your own network, only the ports of {app}).":
        "Para que tu móvil pueda enviar archivos a este ordenador, el Firewall de Windows debe permitirlo.\n\n¿Permitirlo ahora? Windows pide permiso una sola vez (solo móviles de tu propia red, solo los puertos de {app}).",
    "Waiting for Windows permission (firewall)…":
        "Esperando el permiso de Windows (firewall)…",
    "✓ Windows Firewall lets your phone in now.":
        "✓ El Firewall de Windows ya deja pasar a tu móvil.",
    "Windows Firewall was not changed, so the phone may not be able to send to this computer.":
        "El Firewall de Windows no se ha cambiado, así que el móvil quizá no pueda enviar archivos a este ordenador.",
    "LocalSend for the phone":
        "LocalSend para el móvil",
    "Trying Epson's other download server…":
        "Probando el otro servidor de descargas de Epson…",
    "{name} answers on the network ({ip}), but its scanner driver is not installed.":
        "{name} responde en la red ({ip}), pero su controlador de escáner no está instalado.",
    "Scanner driver missing":
        "Falta el controlador del escáner",
    "{name} was found on the network ({ip}), but its scanner driver is not installed, so the app cannot scan with it.\n\nInstall the official {label} now? It is downloaded and installed automatically (a few minutes; Windows may ask for permission).":
        "Se encontró {name} en la red ({ip}), pero su controlador de escáner no está instalado, así que la aplicación no puede escanear con él.\n\n¿Instalar ahora el controlador oficial {label}? Se descarga e instala automáticamente (unos minutos; Windows puede pedir permiso).",
    "Phone":
        "Móvil",
    "Send to your phone or receive photos from it, on the same Wi-Fi (LocalSend app or QR code)":
        "Enviar al móvil o recibir fotos de él, en la misma Wi-Fi (app LocalSend o código QR)",
    "Send scans to your phone and receive photos from it, on the same Wi-Fi.":
        "Envía escaneos a tu móvil y recibe fotos de él, en la misma Wi-Fi.",
    "Receiving from the phone":
        "Recepción desde el móvil",
    "Keep receiving on while the app is open":
        "Mantener la recepción activa mientras la app esté abierta",
    "When this is off, receiving opens for {minutes} minutes each time you press Phone.":
        "Si está desactivado, la recepción se abre durante {minutes} minutos cada vez que pulsas Móvil.",
    "Phone photos":
        "Fotos del móvil",
    "Just save them in the scans folder":
        "Solo guardarlas en la carpeta de escaneos",
    "Make a PDF, like a scan (OCR, Word)":
        "Hacer un PDF, como un escaneo (OCR, Word)",
    "Name on the phone":
        "Nombre en el móvil",
    "How it works":
        "Cómo funciona",
    "1. Phone and computer on the same Wi-Fi.\n2. Install the free LocalSend app on the phone, or simply scan the QR code.\n3. Press Phone, next to Preview, choose the phone and Send.\n4. To send from the phone: in LocalSend choose “{name}”, or use the QR page.":
        "1. Móvil y ordenador en la misma Wi-Fi.\n2. Instala la app gratuita LocalSend en el móvil, o simplemente escanea el código QR.\n3. Pulsa Móvil, junto a Vista previa, elige el móvil y Enviar.\n4. Para enviar desde el móvil: en LocalSend elige «{name}», o usa la página del código QR.",
    "Get LocalSend":
        "Obtener LocalSend",
    "Idle · making a PDF from phone photos":
        "Inactivo · creando un PDF con las fotos del móvil",
    "✓ Made {file} from {count} phone photo(s)":
        "✓ Se creó {file} a partir de {count} foto(s) del móvil",
    "Windows may now ask whether {app} can use the network.\n\nTick “Private networks” and click Allow, so your phone can reach this computer.":
        "Puede que Windows pregunte ahora si {app} puede usar la red.\n\nMarca «Redes privadas» y haz clic en Permitir, para que tu móvil pueda llegar a este ordenador.",
    "The phone connection could not start. Another program may be using the network ports {ports}.":
        "No se pudo iniciar la conexión con el móvil. Puede que otro programa esté usando los puertos de red {ports}.",
    "Receiving is off. Press Phone to open it again.":
        "La recepción está desactivada. Pulsa Móvil para abrirla de nuevo.",
    "Receiving is on: the phone can send files to “{name}”.":
        "La recepción está activa: el móvil puede enviar archivos a «{name}».",
    "Receiving is on for {time}: the phone can send files to “{name}”.":
        "La recepción está activa durante {time}: el móvil puede enviar archivos a «{name}».",
    "… and {count} more":
        "… y {count} más",
    "Files from a phone":
        "Archivos de un móvil",
    "“{sender}” wants to send {count} file(s):":
        "«{sender}» quiere enviar {count} archivo(s):",
    "They will be saved in {folder}.":
        "Se guardarán en {folder}.",
    "Accept":
        "Aceptar",
    "Decline":
        "Rechazar",
    "Receiving files from {sender}…":
        "Recibiendo archivos de {sender}…",
    "✓ Received {count} file(s) from {sender} in {folder}":
        "✓ Se recibieron {count} archivo(s) de {sender} en {folder}",
    "The photos were saved as they are, because a scan is running.":
        "Las fotos se guardaron tal cual, porque hay un escaneo en curso.",
    "Making a PDF from {count} phone photo(s)…":
        "Creando un PDF con {count} foto(s) del móvil…",
    "This link has expired. Scan the QR code again.":
        "Este enlace ha caducado. Vuelve a escanear el código QR.",
    "No scan yet. Scan something first, then reload this page.":
        "Todavía no hay escaneo. Escanea algo primero y luego recarga esta página.",
    "Waiting for the computer to accept…":
        "Esperando a que el ordenador acepte…",
    "The computer declined the files.":
        "El ordenador rechazó los archivos.",
    "The computer is receiving other files. Try again in a moment.":
        "El ordenador está recibiendo otros archivos. Inténtalo de nuevo en un momento.",
    "Sending failed. Check that the phone is on the same Wi-Fi and try again.":
        "El envío falló. Comprueba que el móvil esté en la misma Wi-Fi e inténtalo de nuevo.",
    "Sending {name}…":
        "Enviando {name}…",
    "✓ Sent! The files are on the computer.":
        "✓ ¡Enviado! Los archivos están en el ordenador.",
    "1 · Get the scan on this phone":
        "1 · Recibe el escaneo en este móvil",
    "Reload":
        "Recargar",
    "2 · Send photos or files to the computer":
        "2 · Envía fotos o archivos al ordenador",
    "Take a photo or choose files":
        "Hacer una foto o elegir archivos",
    "Send to your phone":
        "Enviar al móvil",
    "Phone and computer must be on the same Wi-Fi.":
        "El móvil y el ordenador deben estar en la misma Wi-Fi.",
    "Choose other files…":
        "Elegir otros archivos…",
    "Phones with LocalSend":
        "Móviles con LocalSend",
    "Send":
        "Enviar",
    "No LocalSend? Scan this":
        "¿Sin LocalSend? Escanea esto",
    "Point the phone camera at the code. A page opens where you can download the scan and send photos to this computer.":
        "Apunta la cámara del móvil al código. Se abre una página donde puedes descargar el escaneo y enviar fotos a este ordenador.",
    "QR code not available.":
        "Código QR no disponible.",
    "To send: {names}  ({size})":
        "Para enviar: {names}  ({size})",
    "Nothing to send yet. Scan first, or choose files.":
        "Aún no hay nada que enviar. Escanea primero o elige archivos.",
    "Choose files for the phone":
        "Elegir archivos para el móvil",
    "Looking for phones… Open LocalSend on the phone.":
        "Buscando móviles… Abre LocalSend en el móvil.",
    "No phone found.\n1. Is the phone on the same Wi-Fi?\n2. Open the LocalSend app on the phone (free, Play Store / App Store).\n3. Or simply scan the QR code on the right.":
        "No se encontró ningún móvil.\n1. ¿Está el móvil en la misma Wi-Fi?\n2. Abre la app LocalSend en el móvil (gratis, Play Store / App Store).\n3. O simplemente escanea el código QR de la derecha.",
    "Waiting for {phone} to accept… Tap Accept on the phone.":
        "Esperando a que {phone} acepte… Pulsa Aceptar en el móvil.",
    "Sending to {phone}… {value}%":
        "Enviando a {phone}… {value}%",
    "{phone} declined the files.":
        "{phone} rechazó los archivos.",
    "{phone} is busy with another transfer. Try again in a moment.":
        "{phone} está ocupado con otra transferencia. Inténtalo de nuevo en un momento.",
    "{phone} asks for a PIN. Turn off the PIN in LocalSend settings on the phone.":
        "{phone} pide un PIN. Desactiva el PIN en los ajustes de LocalSend del móvil.",
    "Could not reach {phone}. Is LocalSend open and on the same Wi-Fi?":
        "No se pudo conectar con {phone}. ¿Está LocalSend abierto y en la misma Wi-Fi?",
    "Sending cancelled.":
        "Envío cancelado.",
    "✓ Sent {count} file(s) to {phone}.":
        "✓ Se enviaron {count} archivo(s) a {phone}.",
    "Sending failed. {error}":
        "El envío falló. {error}",
    "Also save an editable document (text from OCR)":
        "Guardar también un documento editable (texto del OCR)",
    "Document":
        "Documento",
    "Word (.docx) · Microsoft Word":
        "Word (.docx) · Microsoft Word",
    "OpenDocument (.odt) · LibreOffice on Mac / Linux":
        "OpenDocument (.odt) · LibreOffice en Mac / Linux",
    "Word export needs python-docx. Close and reopen the app to install it.":
        "Exportar a Word requiere python-docx. Cierra y vuelve a abrir la app para instalarlo.",
    "What to save, the paper and where the files go.":
        "Qué guardar, el papel y dónde van los archivos.",
    "Recognise text in your scans and translate it.":
        "Reconoce el texto de tus escaneos y tradúcelo.",
    "Language, appearance and updates.":
        "Idioma, apariencia y actualizaciones.",
    "Output":
        "Salida",
    "Paper":
        "Papel",
    "Saving":
        "Guardado",
    "Text recognition (OCR)":
        "Reconocimiento de texto (OCR)",
    "Appearance":
        "Apariencia",
    "Reset":
        "Restablecer",
    "Settings":
        "Ajustes",
    "Help":
        "Ayuda",
    "Ready":
        "Listo",
    "Idle":
        "Inactivo",
    "Scan":
        "Escanear",
    "Preview":
        "Vista previa",
    "Text":
        "Texto",
    "Open last":
        "Abrir último",
    "Open folder":
        "Abrir carpeta",
    "Cancel":
        "Cancelar",
    "Stop search":
        "Detener búsqueda",
    "Search again":
        "Buscar de nuevo",
    "Change…":
        "Cambiar…",
    "Starting…":
        "Iniciando…",
    "Looking for scanners…":
        "Buscando escáneres…",
    "Checking every driver at the same time.":
        "Comprobando todos los controladores a la vez.",
    "Connected to {name}":
        "Conectado a {name}",
    "via {driver}":
        "mediante {driver}",
    "{brand} at {ip}":
        "{brand} en {ip}",
    "{count} more in Settings":
        "{count} más en Ajustes",
    "No scanner connected":
        "Ningún escáner conectado",
    "Turn the scanner on, check the USB cable or Wi-Fi, then click Search again.":
        "Enciende el escáner, comprueba el cable USB o la Wi-Fi y haz clic en Buscar de nuevo.",
    "saves to {folder}":
        "guarda en {folder}",
    "asks for a file name":
        "pide un nombre de archivo",
    "OCR":
        "OCR",
    "OCR off":
        "OCR desactivado",
    "translate → {lang}":
        "traducir → {lang}",
    "Scan and save in the format chosen in Settings (Ctrl+S)":
        "Escanear y guardar en el formato elegido en Ajustes (Ctrl+S)",
    "Quick low-resolution look at the flatbed (Ctrl+P)":
        "Vista rápida en baja resolución del cristal (Ctrl+P)",
    "Recognised text and translation of the last scan (Ctrl+T)":
        "Texto reconocido y traducción del último escaneo (Ctrl+T)",
    "Open the last scanned file":
        "Abrir el último archivo escaneado",
    "Open the folder with your scans":
        "Abrir la carpeta con tus escaneos",
    "Stop the scan or search (Esc)":
        "Detener el escaneo o la búsqueda (Esc)",
    "Look for scanners again (F5)":
        "Buscar escáneres de nuevo (F5)",
    "Choose another scanner or change scan settings":
        "Elegir otro escáner o cambiar los ajustes de escaneo",
    "Scanner, scanning, text and appearance settings (Ctrl+,)":
        "Ajustes de escáner, escaneo, texto y apariencia (Ctrl+,)",
    "Quick guide":
        "Guía rápida",
    "Check for updates…":
        "Buscar actualizaciones…",
    "Project page on GitHub":
        "Página del proyecto en GitHub",
    "About {app}":
        "Acerca de {app}",
    "Update to {version}…":
        "Actualizar a {version}…",
    "In use · scanning on this PC":
        "En uso · escaneando en este PC",
    "In use by {who}":
        "En uso por {who}",
    "{user} on {host}":
        "{user} en {host}",
    "Started at {time}. Wait until the light turns green.":
        "Empezó a las {time}. Espera a que la luz se ponga verde.",
    "In use · scanner is busy":
        "En uso · el escáner está ocupado",
    "The scanner reports that it is scanning right now.":
        "El escáner indica que está escaneando ahora mismo.",
    "Idle · searching…":
        "Inactivo · buscando…",
    "Idle · no scanner":
        "Inactivo · sin escáner",
    "No scanner is connected yet.":
        "Todavía no hay ningún escáner conectado.",
    "Idle · scanner on standby":
        "Inactivo · escáner en espera",
    "The scanner reports that it is stopped or offline.":
        "El escáner indica que está detenido o sin conexión.",
    "The scanner is free. You can scan.":
        "El escáner está libre. Puedes escanear.",
    "Idle · installing OCR…":
        "Inactivo · instalando OCR…",
    "The scanner is free now. You can scan.":
        "El escáner ya está libre. Puedes escanear.",
    "Scanner in use":
        "Escáner en uso",
    "The scanner is in use right now.\n\n{text}.\n{tip}\n\nPlease wait until the light at the top turns green, then try again.\nThis app will beep when the scanner is free.":
        "El escáner está en uso ahora mismo.\n\n{text}.\n{tip}\n\nEspera a que la luz de arriba se ponga verde y vuelve a intentarlo.\nLa app emitirá un pitido cuando el escáner esté libre.",
    "Scanner in use: {text}. Wait for the green light.":
        "Escáner en uso: {text}. Espera la luz verde.",
    "Scanner":
        "Escáner",
    "Scanning":
        "Escaneo",
    "Text & translation":
        "Texto y traducción",
    "General":
        "General",
    "Done":
        "Listo",
    "Driver":
        "Controlador",
    "Model":
        "Modelo",
    "Network":
        "Red",
    "Auto (all drivers)":
        "Auto (todos los controladores)",
    "No scanner found yet":
        "Aún no se ha encontrado ningún escáner",
    "Refresh":
        "Actualizar",
    "Driver setup":
        "Instalar controlador",
    "Find on network":
        "Buscar en la red",
    "Web panel":
        "Panel web",
    "Find your model’s driver":
        "Busca el controlador de tu modelo",
    "No network reply yet":
        "Aún no hay respuesta de la red",
    "Everything here is found automatically. Change it only if the wrong scanner is chosen.":
        "Todo aquí se detecta automáticamente. Cámbialo solo si se ha elegido el escáner equivocado.",
    "Save as":
        "Guardar como",
    "one PDF with every page":
        "un PDF con todas las páginas",
    "one JPG image per page":
        "una imagen JPG por página",
    "the PDF and the JPG images from one scan":
        "el PDF y las imágenes JPG de un mismo escaneo",
    "Paper source":
        "Origen del papel",
    "Auto · feeder if loaded, else flatbed":
        "Auto · alimentador si tiene papel, si no, cristal",
    "Flatbed (glass)":
        "Cristal (plano)",
    "Document feeder":
        "Alimentador de documentos",
    "Document feeder · both sides":
        "Alimentador de documentos · doble cara",
    "Paper size":
        "Tamaño del papel",
    "Resolution":
        "Resolución",
    "150 dpi · fast, small file":
        "150 ppp · rápido, archivo pequeño",
    "300 dpi · recommended":
        "300 ppp · recomendado",
    "600 dpi · fine detail":
        "600 ppp · detalle fino",
    "Colour":
        "Color",
    "Greyscale":
        "Escala de grises",
    "Black and white":
        "Blanco y negro",
    "Save to":
        "Guardar en",
    "Browse…":
        "Examinar…",
    "Ask for a file name every time":
        "Pedir un nombre de archivo cada vez",
    "Open the file after scanning":
        "Abrir el archivo después de escanear",
    "Auto source":
        "Origen auto",
    "Flatbed":
        "Cristal",
    "Feeder":
        "Alimentador",
    "Feeder · 2 sides":
        "Alimentador · 2 caras",
    "Make PDFs searchable with OCR (text recognition)":
        "Hacer los PDF buscables con OCR (reconocimiento de texto)",
    "OCR languages":
        "Idiomas del OCR",
    "Auto · English + Greek + your system language":
        "Auto · inglés + griego + el idioma de tu sistema",
    "Choose languages":
        "Elegir idiomas",
    "Languages download automatically the first time they are used.":
        "Los idiomas se descargan automáticamente la primera vez que se usan.",
    "Also save the text as a .txt file":
        "Guardar también el texto como archivo .txt",
    "Translate automatically to":
        "Traducir automáticamente a",
    "Off":
        "Desactivado",
    "Translation service":
        "Servicio de traducción",
    "Google Translate (free)":
        "Google Traductor (gratis)",
    "MyMemory (free)":
        "MyMemory (gratis)",
    "LibreTranslate (your server)":
        "LibreTranslate (tu servidor)",
    "LibreTranslate server":
        "Servidor LibreTranslate",
    "API key (optional)":
        "Clave API (opcional)",
    "Free services need internet. Google falls back to MyMemory if it fails.":
        "Los servicios gratuitos necesitan Internet. Si Google falla, se usa MyMemory.",
    "Theme":
        "Tema",
    "Auto · follow Windows / system":
        "Auto · seguir Windows / el sistema",
    "Light":
        "Claro",
    "Dark":
        "Oscuro",
    "Language":
        "Idioma",
    "Auto · system language":
        "Auto · idioma del sistema",
    "Updates":
        "Actualizaciones",
    "Check for updates automatically":
        "Buscar actualizaciones automáticamente",
    "Check now":
        "Comprobar ahora",
    "Reset everything to Auto":
        "Volver todo a Auto",
    "All settings are back to Auto.":
        "Todos los ajustes han vuelto a Auto.",
    "Restart to change the language?":
        "¿Reiniciar para cambiar el idioma?",
    "The new language is used after a restart. Restart now?":
        "El nuevo idioma se usa tras reiniciar. ¿Reiniciar ahora?",
    "Save scans to":
        "Guardar escaneos en",
    "Recognised text":
        "Texto reconocido",
    "Translation":
        "Traducción",
    "Translate":
        "Traducir",
    "From":
        "De",
    "To":
        "A",
    "Auto-detect":
        "Detectar automáticamente",
    "Copy":
        "Copiar",
    "Save .txt":
        "Guardar .txt",
    "Close":
        "Cerrar",
    "Copied.":
        "Copiado.",
    "Detected language: {lang}":
        "Idioma detectado: {lang}",
    "Translating with {engine}…":
        "Traduciendo con {engine}…",
    "Translated with {engine}. Detected: {lang}.":
        "Traducido con {engine}. Detectado: {lang}.",
    "Translation failed. {error}":
        "La traducción falló. {error}",
    "Saved {name}":
        "{name} guardado",
    "No text yet. Turn on OCR in Settings › Text & translation, then scan again.":
        "Aún no hay texto. Activa el OCR en Ajustes › Texto y traducción y vuelve a escanear.",
    "Text of {name}":
        "Texto de {name}",
    "Looking for scanners ({drivers})…":
        "Buscando escáneres ({drivers})…",
    "Looking for scanners… {count} found so far.":
        "Buscando escáneres… {count} encontrados hasta ahora.",
    "Ready. Load the paper and click Scan.":
        "Listo. Coloca el papel y haz clic en Escanear.",
    "Search stopped. Click Search again when you are ready.":
        "Búsqueda detenida. Haz clic en Buscar de nuevo cuando estés listo.",
    "No scanners found. Check the cable or Wi-Fi and the installed driver (Settings › Scanner › Driver setup).":
        "No se encontraron escáneres. Comprueba el cable o la Wi-Fi y el controlador instalado (Ajustes › Escáner › Instalar controlador).",
    "The NAPS2 scanner engine was not found. Close and reopen the app to install it automatically.":
        "No se encontró el motor de escaneo NAPS2. Cierra y vuelve a abrir la app para instalarlo automáticamente.",
    "Scanning a quick low-resolution preview…":
        "Escaneando una vista previa rápida en baja resolución…",
    "Check the page placement, then scan at your chosen resolution.":
        "Comprueba la posición de la página y escanea con la resolución elegida.",
    "Flatbed preview":
        "Vista previa del cristal",
    "Back":
        "Atrás",
    "Preview ready.":
        "Vista previa lista.",
    "No preview was produced. Check the flatbed and scanner connection.":
        "No se generó ninguna vista previa. Comprueba el cristal y la conexión del escáner.",
    "Scanning from {where}… Keep the scanner on until the file is saved.":
        "Escaneando desde {where}… Mantén el escáner encendido hasta que se guarde el archivo.",
    "the flatbed":
        "el cristal",
    "the document feeder":
        "el alimentador de documentos",
    "the document feeder (both sides)":
        "el alimentador de documentos (doble cara)",
    " Recognising text (OCR)…":
        " Reconociendo texto (OCR)…",
    "Downloading OCR languages ({langs}). One time only…":
        "Descargando idiomas del OCR ({langs}). Solo una vez…",
    "OCR languages could not be installed ({langs}). Scanning without OCR.":
        "No se pudieron instalar los idiomas del OCR ({langs}). Escaneando sin OCR.",
    "Scan cancelled.":
        "Escaneo cancelado.",
    "The scanner is busy. Someone else may be using it. Wait a moment, then try again.":
        "El escáner está ocupado. Puede que otra persona lo esté usando. Espera un momento y vuelve a intentarlo.",
    "Windows could not reach the Canon scanner. Turn it on, make sure it is on the same Wi-Fi, and check it in Canon IJ Scan Utility, then retry.":
        "Windows no pudo conectar con el escáner Canon. Enciéndelo, comprueba que esté en la misma Wi-Fi y revísalo en Canon IJ Scan Utility; luego vuelve a intentarlo.",
    "Epson Scan 2 could not open the scanner. In Epson Scan 2 Utility, add or test its network address, then retry.":
        "Epson Scan 2 no pudo abrir el escáner. En Epson Scan 2 Utility, añade o prueba su dirección de red y vuelve a intentarlo.",
    "Scanner operation failed. {detail}":
        "La operación del escáner falló. {detail}",
    "No pages were scanned. Check the paper and the scanner connection.":
        "No se escaneó ninguna página. Comprueba el papel y la conexión del escáner.",
    "Could not save the scan. {error}":
        "No se pudo guardar el escaneo. {error}",
    "The scan was kept as {path}":
        "El escaneo se conservó como {path}",
    "✓ Saved {files} in {folder}":
        "✓ Se guardó {files} en {folder}",
    "{count} JPG pages":
        "{count} páginas JPG",
    "text":
        "texto",
    "Translating the text to {lang}…":
        "Traduciendo el texto a {lang}…",
    "✓ Translation saved: {name}":
        "✓ Traducción guardada: {name}",
    "Could not start NAPS2. {error}":
        "No se pudo iniciar NAPS2. {error}",
    "Could not create {folder}. {error}\nChoose another folder in Settings › Scanning.":
        "No se pudo crear {folder}. {error}\nElige otra carpeta en Ajustes › Escaneo.",
    "Save scan":
        "Guardar escaneo",
    "Scan in progress":
        "Escaneo en curso",
    "A scan is running. Cancel it and close the app?":
        "Hay un escaneo en curso. ¿Cancelarlo y cerrar la app?",
    "JPG export needs PyMuPDF. Close and reopen the app to install it.":
        "Exportar a JPG requiere PyMuPDF. Cierra y vuelve a abrir la app para instalarlo.",
    "Checking GitHub for a newer version…":
        "Buscando una versión más nueva en GitHub…",
    "Could not check for updates. {error}":
        "No se pudieron buscar actualizaciones. {error}",
    "You have the latest version (v{version}).":
        "Tienes la última versión (v{version}).",
    "Update available":
        "Actualización disponible",
    "{app} {version} is available (you have v{current}).\n\nWhat's new:\n{notes}\n\nDownload and install it now?":
        "{app} {version} está disponible (tienes la v{current}).\n\nNovedades:\n{notes}\n\n¿Descargarla e instalarla ahora?",
    "No release notes.":
        "Sin notas de la versión.",
    "Update {version} is waiting in Help.":
        "La actualización {version} te espera en Ayuda.",
    "Finish the scan first, then install the update from Help.":
        "Termina primero el escaneo y luego instala la actualización desde Ayuda.",
    "Downloading {version} from GitHub…":
        "Descargando {version} desde GitHub…",
    "Update failed. {error}":
        "La actualización falló. {error}",
    "macOS is running the app from a temporary read-only copy. Drag What the Scan into Applications, open it from there, then update again.":
        "macOS está ejecutando la app desde una copia temporal de solo lectura. Arrastra What the Scan a Aplicaciones, ábrela desde allí y vuelve a actualizar.",
    "The app's folder can't be written to. Move the app to a folder you own (or Applications) and update again.":
        "No se puede escribir en la carpeta de la app. Mueve la app a una carpeta tuya (o a Aplicaciones) y vuelve a actualizar.",
    "Update failed":
        "La actualización falló",
    "{error}\n\nOpen the release page to download it by hand?":
        "{error}\n\n¿Abrir la página de la versión para descargarla manualmente?",
    "Updated to {version}. Restarting…":
        "Actualizado a {version}. Reiniciando…",
    "Choose a model to find its driver.":
        "Elige un modelo para buscar su controlador.",
    "Install driver":
        "Instalar controlador",
    "Download and install the official {label} now?\n\nWindows may ask for permission. Choose No to open the support page instead.":
        "¿Descargar e instalar ahora el controlador oficial {label}?\n\nWindows puede pedir permiso. Elige No para abrir la página de soporte en su lugar.",
    "Preparing the official {label} installer…":
        "Preparando el instalador oficial de {label}…",
    "{label} installed. Looking for scanners…":
        "{label} instalado. Buscando escáneres…",
    "Driver setup failed. {error}\nThe support page is opening so you can install it by hand.":
        "La instalación del controlador falló. {error}\nSe abre la página de soporte para que puedas instalarlo manualmente.",
    "Searching the local network for scanners (Epson, Canon, HP, AirPrint)…":
        "Buscando escáneres en la red local (Epson, Canon, HP, AirPrint)…",
    "answered as a network (eSCL) scanner ✓":
        "respondió como escáner de red (eSCL) ✓",
    "This scanner has: {sources}":
        "Este escáner tiene: {sources}",
    "Network discovery failed. {error}":
        "La búsqueda en la red falló. {error}",
    "Select your scanner's network address.":
        "Selecciona la dirección de red de tu escáner.",
    "No scanner replied on this local network.":
        "Ningún escáner respondió en esta red local.",
    "answered as a Canon scanner ✓":
        "respondió como escáner Canon ✓",
    "responds on the scanner port ✓":
        "responde en el puerto del escáner ✓",
    "did not respond on the scanner port":
        "no respondió en el puerto del escáner",
    "{brand} {ip} {state}. Scanning uses the driver chosen above.":
        "{brand} {ip} {state}. El escaneo usa el controlador elegido arriba.",
}

UI_RO = {
    "Brother's download page is opening. The model {model} is copied: paste it in the search box (Ctrl+V). Most Brother models also scan with no driver over the network.":
        "Se deschide pagina de descărcări Brother. Modelul {model} este copiat: lipiți-l în căutare (Ctrl+V). Majoritatea modelelor Brother scanează și fără driver prin rețea.",
    "Connect Epson Scan 2 to the scanner":
        "Conectați Epson Scan 2 la scanner",
    "Epson Scan 2 does not know your scanner's network address yet. This happens after the driver is (re)installed. One time only:":
        "Epson Scan 2 nu cunoaște încă adresa de rețea a scannerului. Se întâmplă după (re)instalarea driverului. O singură dată:",
    "1. Click “Open Epson Scan 2 Utility” below.\n2. At the top, in “Scanner”, choose “Settings”.\n3. Click “Add”, choose “Enter address”, press Ctrl+V (the address {ip} is already copied) and click OK.\n4. Click OK, close the utility and press Scan again.":
        "1. Faceți clic pe „Deschide Epson Scan 2 Utility” mai jos.\n2. Sus, la „Scanner”, alegeți „Settings”.\n3. Faceți clic pe „Add”, alegeți „Enter address”, apăsați Ctrl+V (adresa {ip} este deja copiată) și faceți clic pe OK.\n4. Faceți clic pe OK, închideți utilitarul și apăsați din nou Scanează.",
    "Open Epson Scan 2 Utility":
        "Deschide Epson Scan 2 Utility",
    "Could not open Epson Scan 2 Utility. {error}":
        "Epson Scan 2 Utility nu s-a putut deschide. {error}",
    "{phone} (browser)": "{phone} (browser)",
    "AirDrop":
        "AirDrop",
    "Send with AirDrop to an iPhone, iPad or Mac nearby":
        "Trimiteți cu AirDrop către un iPhone, iPad sau Mac din apropiere",
    "AirDrop is open: choose the iPhone or Mac.":
        "AirDrop este deschis: alegeți iPhone-ul sau Mac-ul.",
    "AirDrop is not available on this Mac. Turn on Wi-Fi and Bluetooth.":
        "AirDrop nu este disponibil pe acest Mac. Porniți Wi-Fi și Bluetooth.",
    "So that your phone can send to this computer, Windows Firewall must let it in.\n\nAllow it now? Windows asks for permission once (only phones on your own network, only the ports of {app}).":
        "Ca telefonul să poată trimite fișiere către acest computer, Windows Firewall trebuie să-l permită.\n\nPermiteți acum? Windows cere permisiunea o singură dată (doar telefoane din rețeaua dvs., doar porturile {app}).",
    "Waiting for Windows permission (firewall)…":
        "Se așteaptă permisiunea Windows (firewall)…",
    "✓ Windows Firewall lets your phone in now.":
        "✓ Windows Firewall lasă acum telefonul să se conecteze.",
    "Windows Firewall was not changed, so the phone may not be able to send to this computer.":
        "Windows Firewall nu a fost modificat, așa că telefonul s-ar putea să nu poată trimite fișiere către acest computer.",
    "LocalSend for the phone":
        "LocalSend pentru telefon",
    "Trying Epson's other download server…":
        "Se încearcă celălalt server de descărcare Epson…",
    "{name} answers on the network ({ip}), but its scanner driver is not installed.":
        "{name} răspunde în rețea ({ip}), dar driverul său de scanner nu este instalat.",
    "Scanner driver missing":
        "Lipsește driverul scannerului",
    "{name} was found on the network ({ip}), but its scanner driver is not installed, so the app cannot scan with it.\n\nInstall the official {label} now? It is downloaded and installed automatically (a few minutes; Windows may ask for permission).":
        "{name} a fost găsit în rețea ({ip}), dar driverul său de scanner nu este instalat, deci aplicația nu poate scana cu el.\n\nInstalați acum driverul oficial {label}? Se descarcă și se instalează automat (câteva minute; Windows poate cere permisiunea).",
    "Phone":
        "Telefon",
    "Send to your phone or receive photos from it, on the same Wi-Fi (LocalSend app or QR code)":
        "Trimiteți către telefon sau primiți fotografii de la el, în aceeași rețea Wi-Fi (aplicația LocalSend sau cod QR)",
    "Send scans to your phone and receive photos from it, on the same Wi-Fi.":
        "Trimiteți scanări către telefon și primiți fotografii de la el, în aceeași rețea Wi-Fi.",
    "Receiving from the phone":
        "Primire de la telefon",
    "Keep receiving on while the app is open":
        "Primirea rămâne activă cât timp aplicația este deschisă",
    "When this is off, receiving opens for {minutes} minutes each time you press Phone.":
        "Când este dezactivat, primirea se deschide pentru {minutes} minute de fiecare dată când apăsați Telefon.",
    "Phone photos":
        "Fotografii de pe telefon",
    "Just save them in the scans folder":
        "Doar salvați-le în dosarul cu scanări",
    "Make a PDF, like a scan (OCR, Word)":
        "Faceți un PDF, ca o scanare (OCR, Word)",
    "Name on the phone":
        "Nume pe telefon",
    "How it works":
        "Cum funcționează",
    "1. Phone and computer on the same Wi-Fi.\n2. Install the free LocalSend app on the phone, or simply scan the QR code.\n3. Press Phone, next to Preview, choose the phone and Send.\n4. To send from the phone: in LocalSend choose “{name}”, or use the QR page.":
        "1. Telefonul și computerul în aceeași rețea Wi-Fi.\n2. Instalați aplicația gratuită LocalSend pe telefon sau scanați pur și simplu codul QR.\n3. Apăsați Telefon, lângă Previzualizare, alegeți telefonul și Trimite.\n4. Pentru a trimite de pe telefon: în LocalSend alegeți „{name}” sau folosiți pagina codului QR.",
    "Get LocalSend":
        "Obțineți LocalSend",
    "Idle · making a PDF from phone photos":
        "Inactiv · se creează un PDF din fotografiile telefonului",
    "✓ Made {file} from {count} phone photo(s)":
        "✓ S-a creat {file} din {count} fotografii de pe telefon",
    "Windows may now ask whether {app} can use the network.\n\nTick “Private networks” and click Allow, so your phone can reach this computer.":
        "Windows poate întreba acum dacă {app} poate folosi rețeaua.\n\nBifați „Rețele private” și faceți clic pe Permiteți, ca telefonul să poată ajunge la acest computer.",
    "The phone connection could not start. Another program may be using the network ports {ports}.":
        "Conexiunea cu telefonul nu a putut porni. Poate alt program folosește porturile de rețea {ports}.",
    "Receiving is off. Press Phone to open it again.":
        "Primirea este oprită. Apăsați Telefon pentru a o redeschide.",
    "Receiving is on: the phone can send files to “{name}”.":
        "Primirea este activă: telefonul poate trimite fișiere către „{name}”.",
    "Receiving is on for {time}: the phone can send files to “{name}”.":
        "Primirea este activă pentru {time}: telefonul poate trimite fișiere către „{name}”.",
    "… and {count} more":
        "… și încă {count}",
    "Files from a phone":
        "Fișiere de pe un telefon",
    "“{sender}” wants to send {count} file(s):":
        "„{sender}” vrea să trimită {count} fișier(e):",
    "They will be saved in {folder}.":
        "Vor fi salvate în {folder}.",
    "Accept":
        "Acceptă",
    "Decline":
        "Refuză",
    "Receiving files from {sender}…":
        "Se primesc fișiere de la {sender}…",
    "✓ Received {count} file(s) from {sender} in {folder}":
        "✓ S-au primit {count} fișier(e) de la {sender} în {folder}",
    "The photos were saved as they are, because a scan is running.":
        "Fotografiile au fost salvate așa cum sunt, deoarece rulează o scanare.",
    "Making a PDF from {count} phone photo(s)…":
        "Se creează un PDF din {count} fotografii de pe telefon…",
    "This link has expired. Scan the QR code again.":
        "Acest link a expirat. Scanați din nou codul QR.",
    "No scan yet. Scan something first, then reload this page.":
        "Încă nu există nicio scanare. Scanați mai întâi ceva, apoi reîncărcați pagina.",
    "Waiting for the computer to accept…":
        "Se așteaptă acceptarea de către computer…",
    "The computer declined the files.":
        "Computerul a refuzat fișierele.",
    "The computer is receiving other files. Try again in a moment.":
        "Computerul primește alte fișiere. Încercați din nou peste puțin timp.",
    "Sending failed. Check that the phone is on the same Wi-Fi and try again.":
        "Trimiterea a eșuat. Verificați că telefonul este în aceeași rețea Wi-Fi și încercați din nou.",
    "Sending {name}…":
        "Se trimite {name}…",
    "✓ Sent! The files are on the computer.":
        "✓ Trimis! Fișierele sunt pe computer.",
    "1 · Get the scan on this phone":
        "1 · Luați scanarea pe acest telefon",
    "Reload":
        "Reîncarcă",
    "2 · Send photos or files to the computer":
        "2 · Trimiteți fotografii sau fișiere către computer",
    "Take a photo or choose files":
        "Faceți o fotografie sau alegeți fișiere",
    "Send to your phone":
        "Trimiteți către telefon",
    "Phone and computer must be on the same Wi-Fi.":
        "Telefonul și computerul trebuie să fie în aceeași rețea Wi-Fi.",
    "Choose other files…":
        "Alegeți alte fișiere…",
    "Phones with LocalSend":
        "Telefoane cu LocalSend",
    "Send":
        "Trimite",
    "No LocalSend? Scan this":
        "Nu aveți LocalSend? Scanați asta",
    "Point the phone camera at the code. A page opens where you can download the scan and send photos to this computer.":
        "Îndreptați camera telefonului spre cod. Se deschide o pagină de unde puteți descărca scanarea și trimite fotografii către acest computer.",
    "QR code not available.":
        "Codul QR nu este disponibil.",
    "To send: {names}  ({size})":
        "De trimis: {names}  ({size})",
    "Nothing to send yet. Scan first, or choose files.":
        "Încă nu e nimic de trimis. Scanați mai întâi sau alegeți fișiere.",
    "Choose files for the phone":
        "Alegeți fișiere pentru telefon",
    "Looking for phones… Open LocalSend on the phone.":
        "Se caută telefoane… Deschideți LocalSend pe telefon.",
    "No phone found.\n1. Is the phone on the same Wi-Fi?\n2. Open the LocalSend app on the phone (free, Play Store / App Store).\n3. Or simply scan the QR code on the right.":
        "Nu s-a găsit niciun telefon.\n1. Telefonul este în aceeași rețea Wi-Fi?\n2. Deschideți aplicația LocalSend pe telefon (gratuită, Play Store / App Store).\n3. Sau scanați pur și simplu codul QR din dreapta.",
    "Waiting for {phone} to accept… Tap Accept on the phone.":
        "Se așteaptă acceptarea de către {phone}… Atingeți Acceptă pe telefon.",
    "Sending to {phone}… {value}%":
        "Se trimite către {phone}… {value}%",
    "{phone} declined the files.":
        "{phone} a refuzat fișierele.",
    "{phone} is busy with another transfer. Try again in a moment.":
        "{phone} este ocupat cu alt transfer. Încercați din nou peste puțin timp.",
    "{phone} asks for a PIN. Turn off the PIN in LocalSend settings on the phone.":
        "{phone} cere un PIN. Dezactivați PIN-ul în setările LocalSend de pe telefon.",
    "Could not reach {phone}. Is LocalSend open and on the same Wi-Fi?":
        "{phone} nu a putut fi contactat. Este LocalSend deschis și în aceeași rețea Wi-Fi?",
    "Sending cancelled.":
        "Trimiterea a fost anulată.",
    "✓ Sent {count} file(s) to {phone}.":
        "✓ S-au trimis {count} fișier(e) către {phone}.",
    "Sending failed. {error}":
        "Trimiterea a eșuat. {error}",
    "Also save an editable document (text from OCR)":
        "Salvați și un document editabil (text din OCR)",
    "Document":
        "Document",
    "Word (.docx) · Microsoft Word":
        "Word (.docx) · Microsoft Word",
    "OpenDocument (.odt) · LibreOffice on Mac / Linux":
        "OpenDocument (.odt) · LibreOffice pe Mac / Linux",
    "Word export needs python-docx. Close and reopen the app to install it.":
        "Exportul în Word necesită python-docx. Închideți și redeschideți aplicația pentru a-l instala.",
    "What to save, the paper and where the files go.":
        "Ce se salvează, hârtia și unde ajung fișierele.",
    "Recognise text in your scans and translate it.":
        "Recunoașteți textul din scanări și traduceți-l.",
    "Language, appearance and updates.":
        "Limbă, aspect și actualizări.",
    "Output":
        "Ieșire",
    "Paper":
        "Hârtie",
    "Saving":
        "Salvare",
    "Text recognition (OCR)":
        "Recunoaștere text (OCR)",
    "Appearance":
        "Aspect",
    "Reset":
        "Resetare",
    "Settings":
        "Setări",
    "Help":
        "Ajutor",
    "Ready":
        "Gata",
    "Idle":
        "Inactiv",
    "Scan":
        "Scanează",
    "Preview":
        "Previzualizare",
    "Text":
        "Text",
    "Open last":
        "Deschide ultimul",
    "Open folder":
        "Deschide dosarul",
    "Cancel":
        "Anulează",
    "Stop search":
        "Oprește căutarea",
    "Search again":
        "Caută din nou",
    "Change…":
        "Schimbă…",
    "Starting…":
        "Se pornește…",
    "Looking for scanners…":
        "Se caută scannere…",
    "Checking every driver at the same time.":
        "Se verifică toate driverele în același timp.",
    "Connected to {name}":
        "Conectat la {name}",
    "via {driver}":
        "prin {driver}",
    "{brand} at {ip}":
        "{brand} la {ip}",
    "{count} more in Settings":
        "încă {count} în Setări",
    "No scanner connected":
        "Niciun scanner conectat",
    "Turn the scanner on, check the USB cable or Wi-Fi, then click Search again.":
        "Porniți scannerul, verificați cablul USB sau Wi-Fi-ul, apoi faceți clic pe Caută din nou.",
    "saves to {folder}":
        "salvează în {folder}",
    "asks for a file name":
        "cere un nume de fișier",
    "OCR":
        "OCR",
    "OCR off":
        "OCR oprit",
    "translate → {lang}":
        "traducere → {lang}",
    "Scan and save in the format chosen in Settings (Ctrl+S)":
        "Scanați și salvați în formatul ales în Setări (Ctrl+S)",
    "Quick low-resolution look at the flatbed (Ctrl+P)":
        "Privire rapidă la rezoluție mică pe geamul scannerului (Ctrl+P)",
    "Recognised text and translation of the last scan (Ctrl+T)":
        "Textul recunoscut și traducerea ultimei scanări (Ctrl+T)",
    "Open the last scanned file":
        "Deschideți ultimul fișier scanat",
    "Open the folder with your scans":
        "Deschideți dosarul cu scanările",
    "Stop the scan or search (Esc)":
        "Opriți scanarea sau căutarea (Esc)",
    "Look for scanners again (F5)":
        "Căutați din nou scannere (F5)",
    "Choose another scanner or change scan settings":
        "Alegeți alt scanner sau schimbați setările de scanare",
    "Scanner, scanning, text and appearance settings (Ctrl+,)":
        "Setări pentru scanner, scanare, text și aspect (Ctrl+,)",
    "Quick guide":
        "Ghid rapid",
    "Check for updates…":
        "Căutați actualizări…",
    "Project page on GitHub":
        "Pagina proiectului pe GitHub",
    "About {app}":
        "Despre {app}",
    "Update to {version}…":
        "Actualizați la {version}…",
    "In use · scanning on this PC":
        "Ocupat · se scanează pe acest PC",
    "In use by {who}":
        "Folosit de {who}",
    "{user} on {host}":
        "{user} pe {host}",
    "Started at {time}. Wait until the light turns green.":
        "A început la {time}. Așteptați până când lumina devine verde.",
    "In use · scanner is busy":
        "Ocupat · scannerul lucrează",
    "The scanner reports that it is scanning right now.":
        "Scannerul raportează că scanează chiar acum.",
    "Idle · searching…":
        "Inactiv · se caută…",
    "Idle · no scanner":
        "Inactiv · niciun scanner",
    "No scanner is connected yet.":
        "Încă nu este conectat niciun scanner.",
    "Idle · scanner on standby":
        "Inactiv · scanner în așteptare",
    "The scanner reports that it is stopped or offline.":
        "Scannerul raportează că este oprit sau offline.",
    "The scanner is free. You can scan.":
        "Scannerul este liber. Puteți scana.",
    "Idle · installing OCR…":
        "Inactiv · se instalează OCR…",
    "The scanner is free now. You can scan.":
        "Scannerul este liber acum. Puteți scana.",
    "Scanner in use":
        "Scanner ocupat",
    "The scanner is in use right now.\n\n{text}.\n{tip}\n\nPlease wait until the light at the top turns green, then try again.\nThis app will beep when the scanner is free.":
        "Scannerul este folosit chiar acum.\n\n{text}.\n{tip}\n\nAșteptați până când lumina de sus devine verde, apoi încercați din nou.\nAplicația va emite un sunet când scannerul este liber.",
    "Scanner in use: {text}. Wait for the green light.":
        "Scanner ocupat: {text}. Așteptați lumina verde.",
    "Scanner":
        "Scanner",
    "Scanning":
        "Scanare",
    "Text & translation":
        "Text și traducere",
    "General":
        "General",
    "Done":
        "Gata",
    "Driver":
        "Driver",
    "Model":
        "Model",
    "Network":
        "Rețea",
    "Auto (all drivers)":
        "Auto (toate driverele)",
    "No scanner found yet":
        "Încă nu s-a găsit niciun scanner",
    "Refresh":
        "Reîmprospătează",
    "Driver setup":
        "Instalare driver",
    "Find on network":
        "Caută în rețea",
    "Web panel":
        "Panou web",
    "Find your model’s driver":
        "Găsiți driverul modelului dvs.",
    "No network reply yet":
        "Încă niciun răspuns din rețea",
    "Everything here is found automatically. Change it only if the wrong scanner is chosen.":
        "Totul aici se detectează automat. Schimbați doar dacă a fost ales scannerul greșit.",
    "Save as":
        "Salvează ca",
    "one PDF with every page":
        "un PDF cu toate paginile",
    "one JPG image per page":
        "o imagine JPG pe pagină",
    "the PDF and the JPG images from one scan":
        "PDF-ul și imaginile JPG dintr-o singură scanare",
    "Paper source":
        "Sursa hârtiei",
    "Auto · feeder if loaded, else flatbed":
        "Auto · alimentator dacă are hârtie, altfel geam",
    "Flatbed (glass)":
        "Geam (flatbed)",
    "Document feeder":
        "Alimentator de documente",
    "Document feeder · both sides":
        "Alimentator de documente · față-verso",
    "Paper size":
        "Format hârtie",
    "Resolution":
        "Rezoluție",
    "150 dpi · fast, small file":
        "150 dpi · rapid, fișier mic",
    "300 dpi · recommended":
        "300 dpi · recomandat",
    "600 dpi · fine detail":
        "600 dpi · detalii fine",
    "Colour":
        "Culoare",
    "Greyscale":
        "Tonuri de gri",
    "Black and white":
        "Alb-negru",
    "Save to":
        "Salvează în",
    "Browse…":
        "Răsfoiește…",
    "Ask for a file name every time":
        "Cere de fiecare dată un nume de fișier",
    "Open the file after scanning":
        "Deschide fișierul după scanare",
    "Auto source":
        "Sursă auto",
    "Flatbed":
        "Geam",
    "Feeder":
        "Alimentator",
    "Feeder · 2 sides":
        "Alimentator · 2 fețe",
    "Make PDFs searchable with OCR (text recognition)":
        "Faceți PDF-urile căutabile cu OCR (recunoaștere text)",
    "OCR languages":
        "Limbi OCR",
    "Auto · English + Greek + your system language":
        "Auto · engleză + greacă + limba sistemului",
    "Choose languages":
        "Alegeți limbile",
    "Languages download automatically the first time they are used.":
        "Limbile se descarcă automat la prima utilizare.",
    "Also save the text as a .txt file":
        "Salvați și textul ca fișier .txt",
    "Translate automatically to":
        "Traducere automată în",
    "Off":
        "Oprit",
    "Translation service":
        "Serviciu de traducere",
    "Google Translate (free)":
        "Google Traducere (gratuit)",
    "MyMemory (free)":
        "MyMemory (gratuit)",
    "LibreTranslate (your server)":
        "LibreTranslate (serverul dvs.)",
    "LibreTranslate server":
        "Server LibreTranslate",
    "API key (optional)":
        "Cheie API (opțională)",
    "Free services need internet. Google falls back to MyMemory if it fails.":
        "Serviciile gratuite au nevoie de internet. Dacă Google eșuează, se folosește MyMemory.",
    "Theme":
        "Temă",
    "Auto · follow Windows / system":
        "Auto · urmează Windows / sistemul",
    "Light":
        "Luminoasă",
    "Dark":
        "Întunecată",
    "Language":
        "Limbă",
    "Auto · system language":
        "Auto · limba sistemului",
    "Updates":
        "Actualizări",
    "Check for updates automatically":
        "Caută automat actualizări",
    "Check now":
        "Verifică acum",
    "Reset everything to Auto":
        "Readuce totul la Auto",
    "All settings are back to Auto.":
        "Toate setările au revenit la Auto.",
    "Restart to change the language?":
        "Reporniți pentru a schimba limba?",
    "The new language is used after a restart. Restart now?":
        "Noua limbă se folosește după repornire. Reporniți acum?",
    "Save scans to":
        "Salvează scanările în",
    "Recognised text":
        "Text recunoscut",
    "Translation":
        "Traducere",
    "Translate":
        "Tradu",
    "From":
        "Din",
    "To":
        "În",
    "Auto-detect":
        "Detectare automată",
    "Copy":
        "Copiază",
    "Save .txt":
        "Salvează .txt",
    "Close":
        "Închide",
    "Copied.":
        "Copiat.",
    "Detected language: {lang}":
        "Limbă detectată: {lang}",
    "Translating with {engine}…":
        "Se traduce cu {engine}…",
    "Translated with {engine}. Detected: {lang}.":
        "Tradus cu {engine}. Detectat: {lang}.",
    "Translation failed. {error}":
        "Traducerea a eșuat. {error}",
    "Saved {name}":
        "{name} salvat",
    "No text yet. Turn on OCR in Settings › Text & translation, then scan again.":
        "Încă nu există text. Activați OCR în Setări › Text și traducere, apoi scanați din nou.",
    "Text of {name}":
        "Textul din {name}",
    "Looking for scanners ({drivers})…":
        "Se caută scannere ({drivers})…",
    "Looking for scanners… {count} found so far.":
        "Se caută scannere… {count} găsite până acum.",
    "Ready. Load the paper and click Scan.":
        "Gata. Puneți hârtia și faceți clic pe Scanează.",
    "Search stopped. Click Search again when you are ready.":
        "Căutare oprită. Faceți clic pe Caută din nou când sunteți gata.",
    "No scanners found. Check the cable or Wi-Fi and the installed driver (Settings › Scanner › Driver setup).":
        "Nu s-au găsit scannere. Verificați cablul sau Wi-Fi-ul și driverul instalat (Setări › Scanner › Instalare driver).",
    "The NAPS2 scanner engine was not found. Close and reopen the app to install it automatically.":
        "Motorul de scanare NAPS2 nu a fost găsit. Închideți și redeschideți aplicația pentru a-l instala automat.",
    "Scanning a quick low-resolution preview…":
        "Se scanează o previzualizare rapidă la rezoluție mică…",
    "Check the page placement, then scan at your chosen resolution.":
        "Verificați poziția paginii, apoi scanați la rezoluția aleasă.",
    "Flatbed preview":
        "Previzualizare geam",
    "Back":
        "Înapoi",
    "Preview ready.":
        "Previzualizare gata.",
    "No preview was produced. Check the flatbed and scanner connection.":
        "Nu s-a produs nicio previzualizare. Verificați geamul și conexiunea scannerului.",
    "Scanning from {where}… Keep the scanner on until the file is saved.":
        "Se scanează de pe {where}… Lăsați scannerul pornit până se salvează fișierul.",
    "the flatbed":
        "geam",
    "the document feeder":
        "alimentatorul de documente",
    "the document feeder (both sides)":
        "alimentatorul de documente (față-verso)",
    " Recognising text (OCR)…":
        " Se recunoaște textul (OCR)…",
    "Downloading OCR languages ({langs}). One time only…":
        "Se descarcă limbile OCR ({langs}). Doar o dată…",
    "OCR languages could not be installed ({langs}). Scanning without OCR.":
        "Limbile OCR nu au putut fi instalate ({langs}). Se scanează fără OCR.",
    "Scan cancelled.":
        "Scanare anulată.",
    "The scanner is busy. Someone else may be using it. Wait a moment, then try again.":
        "Scannerul este ocupat. Poate îl folosește altcineva. Așteptați puțin, apoi încercați din nou.",
    "Windows could not reach the Canon scanner. Turn it on, make sure it is on the same Wi-Fi, and check it in Canon IJ Scan Utility, then retry.":
        "Windows nu a putut contacta scannerul Canon. Porniți-l, verificați că este în aceeași rețea Wi-Fi și verificați-l în Canon IJ Scan Utility, apoi reîncercați.",
    "Epson Scan 2 could not open the scanner. In Epson Scan 2 Utility, add or test its network address, then retry.":
        "Epson Scan 2 nu a putut deschide scannerul. În Epson Scan 2 Utility, adăugați sau testați adresa sa de rețea, apoi reîncercați.",
    "Scanner operation failed. {detail}":
        "Operația scannerului a eșuat. {detail}",
    "No pages were scanned. Check the paper and the scanner connection.":
        "Nu s-a scanat nicio pagină. Verificați hârtia și conexiunea scannerului.",
    "Could not save the scan. {error}":
        "Scanarea nu a putut fi salvată. {error}",
    "The scan was kept as {path}":
        "Scanarea a fost păstrată ca {path}",
    "✓ Saved {files} in {folder}":
        "✓ S-a salvat {files} în {folder}",
    "{count} JPG pages":
        "{count} pagini JPG",
    "text":
        "text",
    "Translating the text to {lang}…":
        "Se traduce textul în {lang}…",
    "✓ Translation saved: {name}":
        "✓ Traducere salvată: {name}",
    "Could not start NAPS2. {error}":
        "NAPS2 nu a putut porni. {error}",
    "Could not create {folder}. {error}\nChoose another folder in Settings › Scanning.":
        "{folder} nu a putut fi creat. {error}\nAlegeți alt dosar în Setări › Scanare.",
    "Save scan":
        "Salvează scanarea",
    "Scan in progress":
        "Scanare în curs",
    "A scan is running. Cancel it and close the app?":
        "Rulează o scanare. O anulați și închideți aplicația?",
    "JPG export needs PyMuPDF. Close and reopen the app to install it.":
        "Exportul JPG necesită PyMuPDF. Închideți și redeschideți aplicația pentru a-l instala.",
    "Checking GitHub for a newer version…":
        "Se caută pe GitHub o versiune mai nouă…",
    "Could not check for updates. {error}":
        "Nu s-au putut căuta actualizări. {error}",
    "You have the latest version (v{version}).":
        "Aveți cea mai nouă versiune (v{version}).",
    "Update available":
        "Actualizare disponibilă",
    "{app} {version} is available (you have v{current}).\n\nWhat's new:\n{notes}\n\nDownload and install it now?":
        "{app} {version} este disponibilă (aveți v{current}).\n\nCe este nou:\n{notes}\n\nO descărcați și o instalați acum?",
    "No release notes.":
        "Fără note de versiune.",
    "Update {version} is waiting in Help.":
        "Actualizarea {version} vă așteaptă în Ajutor.",
    "Finish the scan first, then install the update from Help.":
        "Terminați mai întâi scanarea, apoi instalați actualizarea din Ajutor.",
    "Downloading {version} from GitHub…":
        "Se descarcă {version} de pe GitHub…",
    "Update failed. {error}":
        "Actualizarea a eșuat. {error}",
    "macOS is running the app from a temporary read-only copy. Drag What the Scan into Applications, open it from there, then update again.":
        "macOS rulează aplicația dintr-o copie temporară doar în citire. Trageți What the Scan în Aplicații, deschideți-o de acolo, apoi actualizați din nou.",
    "The app's folder can't be written to. Move the app to a folder you own (or Applications) and update again.":
        "Nu se poate scrie în dosarul aplicației. Mutați aplicația într-un dosar al dvs. (sau în Aplicații) și actualizați din nou.",
    "Update failed":
        "Actualizarea a eșuat",
    "{error}\n\nOpen the release page to download it by hand?":
        "{error}\n\nDeschideți pagina versiunii pentru a o descărca manual?",
    "Updated to {version}. Restarting…":
        "Actualizat la {version}. Se repornește…",
    "Choose a model to find its driver.":
        "Alegeți un model pentru a-i găsi driverul.",
    "Install driver":
        "Instalare driver",
    "Download and install the official {label} now?\n\nWindows may ask for permission. Choose No to open the support page instead.":
        "Descărcați și instalați acum driverul oficial {label}?\n\nWindows poate cere permisiunea. Alegeți Nu pentru a deschide în schimb pagina de asistență.",
    "Preparing the official {label} installer…":
        "Se pregătește programul oficial de instalare {label}…",
    "{label} installed. Looking for scanners…":
        "{label} instalat. Se caută scannere…",
    "Driver setup failed. {error}\nThe support page is opening so you can install it by hand.":
        "Instalarea driverului a eșuat. {error}\nSe deschide pagina de asistență ca să-l puteți instala manual.",
    "Searching the local network for scanners (Epson, Canon, HP, AirPrint)…":
        "Se caută scannere în rețeaua locală (Epson, Canon, HP, AirPrint)…",
    "answered as a network (eSCL) scanner ✓":
        "a răspuns ca scanner de rețea (eSCL) ✓",
    "This scanner has: {sources}":
        "Acest scanner are: {sources}",
    "Network discovery failed. {error}":
        "Căutarea în rețea a eșuat. {error}",
    "Select your scanner's network address.":
        "Selectați adresa de rețea a scannerului.",
    "No scanner replied on this local network.":
        "Niciun scanner nu a răspuns în această rețea locală.",
    "answered as a Canon scanner ✓":
        "a răspuns ca scanner Canon ✓",
    "responds on the scanner port ✓":
        "răspunde pe portul scannerului ✓",
    "did not respond on the scanner port":
        "nu a răspuns pe portul scannerului",
    "{brand} {ip} {state}. Scanning uses the driver chosen above.":
        "{brand} {ip} {state}. Scanarea folosește driverul ales mai sus.",
}

UI_CS = {
    "Brother's download page is opening. The model {model} is copied: paste it in the search box (Ctrl+V). Most Brother models also scan with no driver over the network.":
        "Otevírá se stránka ke stažení Brother. Model {model} je zkopírovaný: vložte ho do hledání (Ctrl+V). Většina modelů Brother skenuje i bez ovladače po síti.",
    "Connect Epson Scan 2 to the scanner":
        "Připojit Epson Scan 2 ke skeneru",
    "Epson Scan 2 does not know your scanner's network address yet. This happens after the driver is (re)installed. One time only:":
        "Epson Scan 2 zatím nezná síťovou adresu vašeho skeneru. Stává se to po (pře)instalaci ovladače. Jen jednou:",
    "1. Click “Open Epson Scan 2 Utility” below.\n2. At the top, in “Scanner”, choose “Settings”.\n3. Click “Add”, choose “Enter address”, press Ctrl+V (the address {ip} is already copied) and click OK.\n4. Click OK, close the utility and press Scan again.":
        "1. Klikněte níže na „Otevřít Epson Scan 2 Utility“.\n2. Nahoře v poli „Scanner“ vyberte „Settings“.\n3. Klikněte na „Add“, vyberte „Enter address“, stiskněte Ctrl+V (adresa {ip} je už zkopírovaná) a klikněte na OK.\n4. Klikněte na OK, zavřete nástroj a znovu stiskněte Skenovat.",
    "Open Epson Scan 2 Utility":
        "Otevřít Epson Scan 2 Utility",
    "Could not open Epson Scan 2 Utility. {error}":
        "Epson Scan 2 Utility se nepodařilo otevřít. {error}",
    "{phone} (browser)": "{phone} (prohlížeč)",
    "AirDrop":
        "AirDrop",
    "Send with AirDrop to an iPhone, iPad or Mac nearby":
        "Odeslat přes AirDrop do iPhonu, iPadu nebo Macu v okolí",
    "AirDrop is open: choose the iPhone or Mac.":
        "AirDrop je otevřený: vyberte iPhone nebo Mac.",
    "AirDrop is not available on this Mac. Turn on Wi-Fi and Bluetooth.":
        "AirDrop není na tomto Macu k dispozici. Zapněte Wi-Fi a Bluetooth.",
    "So that your phone can send to this computer, Windows Firewall must let it in.\n\nAllow it now? Windows asks for permission once (only phones on your own network, only the ports of {app}).":
        "Aby mohl telefon posílat soubory do tohoto počítače, musí to povolit brána Windows Firewall.\n\nPovolit nyní? Windows požádá o oprávnění jen jednou (jen telefony ve vaší síti, jen porty aplikace {app}).",
    "Waiting for Windows permission (firewall)…":
        "Čekám na oprávnění Windows (firewall)…",
    "✓ Windows Firewall lets your phone in now.":
        "✓ Brána Windows Firewall nyní telefon propouští.",
    "Windows Firewall was not changed, so the phone may not be able to send to this computer.":
        "Brána Windows Firewall nebyla změněna, takže telefon možná nebude moci posílat soubory do tohoto počítače.",
    "LocalSend for the phone":
        "LocalSend pro telefon",
    "Trying Epson's other download server…":
        "Zkouším druhý server pro stahování Epson…",
    "{name} answers on the network ({ip}), but its scanner driver is not installed.":
        "{name} odpovídá v síti ({ip}), ale jeho ovladač skeneru není nainstalován.",
    "Scanner driver missing":
        "Chybí ovladač skeneru",
    "{name} was found on the network ({ip}), but its scanner driver is not installed, so the app cannot scan with it.\n\nInstall the official {label} now? It is downloaded and installed automatically (a few minutes; Windows may ask for permission).":
        "{name} byl nalezen v síti ({ip}), ale jeho ovladač skeneru není nainstalován, takže s ním aplikace nemůže skenovat.\n\nNainstalovat nyní oficiální {label}? Stáhne se a nainstaluje automaticky (pár minut; Windows může požádat o oprávnění).",
    "Phone":
        "Telefon",
    "Send to your phone or receive photos from it, on the same Wi-Fi (LocalSend app or QR code)":
        "Odeslat do telefonu nebo z něj přijmout fotky, ve stejné Wi-Fi (aplikace LocalSend nebo QR kód)",
    "Send scans to your phone and receive photos from it, on the same Wi-Fi.":
        "Posílejte skeny do telefonu a přijímejte z něj fotky, ve stejné Wi-Fi.",
    "Receiving from the phone":
        "Příjem z telefonu",
    "Keep receiving on while the app is open":
        "Nechat příjem zapnutý, dokud je aplikace otevřená",
    "When this is off, receiving opens for {minutes} minutes each time you press Phone.":
        "Když je vypnuto, příjem se otevře na {minutes} minut při každém stisku Telefon.",
    "Phone photos":
        "Fotky z telefonu",
    "Just save them in the scans folder":
        "Jen je uložit do složky se skeny",
    "Make a PDF, like a scan (OCR, Word)":
        "Vytvořit PDF jako sken (OCR, Word)",
    "Name on the phone":
        "Název v telefonu",
    "How it works":
        "Jak to funguje",
    "1. Phone and computer on the same Wi-Fi.\n2. Install the free LocalSend app on the phone, or simply scan the QR code.\n3. Press Phone, next to Preview, choose the phone and Send.\n4. To send from the phone: in LocalSend choose “{name}”, or use the QR page.":
        "1. Telefon a počítač ve stejné Wi-Fi.\n2. Nainstalujte do telefonu bezplatnou aplikaci LocalSend, nebo jen naskenujte QR kód.\n3. Stiskněte Telefon vedle Náhledu, vyberte telefon a Odeslat.\n4. Odeslání z telefonu: v LocalSend vyberte „{name}“, nebo použijte stránku z QR kódu.",
    "Get LocalSend":
        "Získat LocalSend",
    "Idle · making a PDF from phone photos":
        "Nečinný · vytvářím PDF z fotek z telefonu",
    "✓ Made {file} from {count} phone photo(s)":
        "✓ Vytvořeno {file} z {count} fotek z telefonu",
    "Windows may now ask whether {app} can use the network.\n\nTick “Private networks” and click Allow, so your phone can reach this computer.":
        "Windows se teď možná zeptá, zda smí {app} používat síť.\n\nZaškrtněte „Soukromé sítě“ a klikněte na Povolit, aby se telefon dostal k tomuto počítači.",
    "The phone connection could not start. Another program may be using the network ports {ports}.":
        "Spojení s telefonem se nepodařilo spustit. Síťové porty {ports} možná používá jiný program.",
    "Receiving is off. Press Phone to open it again.":
        "Příjem je vypnutý. Stiskněte Telefon pro jeho opětovné otevření.",
    "Receiving is on: the phone can send files to “{name}”.":
        "Příjem je zapnutý: telefon může posílat soubory do „{name}“.",
    "Receiving is on for {time}: the phone can send files to “{name}”.":
        "Příjem je zapnutý ještě {time}: telefon může posílat soubory do „{name}“.",
    "… and {count} more":
        "… a dalších {count}",
    "Files from a phone":
        "Soubory z telefonu",
    "“{sender}” wants to send {count} file(s):":
        "„{sender}“ chce poslat {count} soubor(ů):",
    "They will be saved in {folder}.":
        "Budou uloženy do {folder}.",
    "Accept":
        "Přijmout",
    "Decline":
        "Odmítnout",
    "Receiving files from {sender}…":
        "Přijímám soubory od {sender}…",
    "✓ Received {count} file(s) from {sender} in {folder}":
        "✓ Přijato {count} soubor(ů) od {sender} do {folder}",
    "The photos were saved as they are, because a scan is running.":
        "Fotky byly uloženy tak, jak jsou, protože právě probíhá skenování.",
    "Making a PDF from {count} phone photo(s)…":
        "Vytvářím PDF z {count} fotek z telefonu…",
    "This link has expired. Scan the QR code again.":
        "Platnost tohoto odkazu vypršela. Naskenujte QR kód znovu.",
    "No scan yet. Scan something first, then reload this page.":
        "Zatím žádný sken. Nejprve něco naskenujte a pak tuto stránku obnovte.",
    "Waiting for the computer to accept…":
        "Čekám, až počítač přijme…",
    "The computer declined the files.":
        "Počítač soubory odmítl.",
    "The computer is receiving other files. Try again in a moment.":
        "Počítač právě přijímá jiné soubory. Zkuste to za chvíli znovu.",
    "Sending failed. Check that the phone is on the same Wi-Fi and try again.":
        "Odeslání selhalo. Zkontrolujte, že je telefon ve stejné Wi-Fi, a zkuste to znovu.",
    "Sending {name}…":
        "Odesílám {name}…",
    "✓ Sent! The files are on the computer.":
        "✓ Odesláno! Soubory jsou v počítači.",
    "1 · Get the scan on this phone":
        "1 · Stáhnout sken do tohoto telefonu",
    "Reload":
        "Obnovit",
    "2 · Send photos or files to the computer":
        "2 · Poslat fotky nebo soubory do počítače",
    "Take a photo or choose files":
        "Vyfotit nebo vybrat soubory",
    "Send to your phone":
        "Odeslat do telefonu",
    "Phone and computer must be on the same Wi-Fi.":
        "Telefon a počítač musí být ve stejné Wi-Fi.",
    "Choose other files…":
        "Vybrat jiné soubory…",
    "Phones with LocalSend":
        "Telefony s LocalSend",
    "Send":
        "Odeslat",
    "No LocalSend? Scan this":
        "Nemáte LocalSend? Naskenujte tohle",
    "Point the phone camera at the code. A page opens where you can download the scan and send photos to this computer.":
        "Namiřte fotoaparát telefonu na kód. Otevře se stránka, kde můžete stáhnout sken a poslat fotky do tohoto počítače.",
    "QR code not available.":
        "QR kód není k dispozici.",
    "To send: {names}  ({size})":
        "K odeslání: {names}  ({size})",
    "Nothing to send yet. Scan first, or choose files.":
        "Zatím není co odeslat. Nejprve skenujte, nebo vyberte soubory.",
    "Choose files for the phone":
        "Vyberte soubory pro telefon",
    "Looking for phones… Open LocalSend on the phone.":
        "Hledám telefony… Otevřete v telefonu LocalSend.",
    "No phone found.\n1. Is the phone on the same Wi-Fi?\n2. Open the LocalSend app on the phone (free, Play Store / App Store).\n3. Or simply scan the QR code on the right.":
        "Nebyl nalezen žádný telefon.\n1. Je telefon ve stejné Wi-Fi?\n2. Otevřete v telefonu aplikaci LocalSend (zdarma, Play Store / App Store).\n3. Nebo jen naskenujte QR kód vpravo.",
    "Waiting for {phone} to accept… Tap Accept on the phone.":
        "Čekám, až {phone} přijme… Klepněte v telefonu na Přijmout.",
    "Sending to {phone}… {value}%":
        "Odesílám do {phone}… {value} %",
    "{phone} declined the files.":
        "{phone} soubory odmítl.",
    "{phone} is busy with another transfer. Try again in a moment.":
        "{phone} má rozpracovaný jiný přenos. Zkuste to za chvíli znovu.",
    "{phone} asks for a PIN. Turn off the PIN in LocalSend settings on the phone.":
        "{phone} žádá PIN. Vypněte PIN v nastavení LocalSend v telefonu.",
    "Could not reach {phone}. Is LocalSend open and on the same Wi-Fi?":
        "{phone} není dostupný. Je LocalSend otevřený a ve stejné Wi-Fi?",
    "Sending cancelled.":
        "Odesílání zrušeno.",
    "✓ Sent {count} file(s) to {phone}.":
        "✓ Odesláno {count} soubor(ů) do {phone}.",
    "Sending failed. {error}":
        "Odeslání selhalo. {error}",
    "Also save an editable document (text from OCR)":
        "Uložit také upravitelný dokument (text z OCR)",
    "Document":
        "Dokument",
    "Word (.docx) · Microsoft Word":
        "Word (.docx) · Microsoft Word",
    "OpenDocument (.odt) · LibreOffice on Mac / Linux":
        "OpenDocument (.odt) · LibreOffice na Macu / Linuxu",
    "Word export needs python-docx. Close and reopen the app to install it.":
        "Export do Wordu potřebuje python-docx. Zavřete a znovu otevřete aplikaci, aby se nainstaloval.",
    "What to save, the paper and where the files go.":
        "Co ukládat, papír a kam jdou soubory.",
    "Recognise text in your scans and translate it.":
        "Rozpoznejte text ve skenech a přeložte ho.",
    "Language, appearance and updates.":
        "Jazyk, vzhled a aktualizace.",
    "Output":
        "Výstup",
    "Paper":
        "Papír",
    "Saving":
        "Ukládání",
    "Text recognition (OCR)":
        "Rozpoznávání textu (OCR)",
    "Appearance":
        "Vzhled",
    "Reset":
        "Obnovit výchozí",
    "Settings":
        "Nastavení",
    "Help":
        "Nápověda",
    "Ready":
        "Připraveno",
    "Idle":
        "Nečinný",
    "Scan":
        "Skenovat",
    "Preview":
        "Náhled",
    "Text":
        "Text",
    "Open last":
        "Otevřít poslední",
    "Open folder":
        "Otevřít složku",
    "Cancel":
        "Zrušit",
    "Stop search":
        "Zastavit hledání",
    "Search again":
        "Hledat znovu",
    "Change…":
        "Změnit…",
    "Starting…":
        "Spouštím…",
    "Looking for scanners…":
        "Hledám skenery…",
    "Checking every driver at the same time.":
        "Kontroluji všechny ovladače najednou.",
    "Connected to {name}":
        "Připojeno k {name}",
    "via {driver}":
        "přes {driver}",
    "{brand} at {ip}":
        "{brand} na {ip}",
    "{count} more in Settings":
        "dalších {count} v Nastavení",
    "No scanner connected":
        "Není připojen žádný skener",
    "Turn the scanner on, check the USB cable or Wi-Fi, then click Search again.":
        "Zapněte skener, zkontrolujte kabel USB nebo Wi-Fi a klikněte na Hledat znovu.",
    "saves to {folder}":
        "ukládá do {folder}",
    "asks for a file name":
        "ptá se na název souboru",
    "OCR":
        "OCR",
    "OCR off":
        "OCR vypnuto",
    "translate → {lang}":
        "přeložit → {lang}",
    "Scan and save in the format chosen in Settings (Ctrl+S)":
        "Naskenovat a uložit ve formátu zvoleném v Nastavení (Ctrl+S)",
    "Quick low-resolution look at the flatbed (Ctrl+P)":
        "Rychlý náhled skla v nízkém rozlišení (Ctrl+P)",
    "Recognised text and translation of the last scan (Ctrl+T)":
        "Rozpoznaný text a překlad posledního skenu (Ctrl+T)",
    "Open the last scanned file":
        "Otevřít naposledy naskenovaný soubor",
    "Open the folder with your scans":
        "Otevřít složku se skeny",
    "Stop the scan or search (Esc)":
        "Zastavit skenování nebo hledání (Esc)",
    "Look for scanners again (F5)":
        "Znovu hledat skenery (F5)",
    "Choose another scanner or change scan settings":
        "Vybrat jiný skener nebo změnit nastavení skenování",
    "Scanner, scanning, text and appearance settings (Ctrl+,)":
        "Nastavení skeneru, skenování, textu a vzhledu (Ctrl+,)",
    "Quick guide":
        "Stručný návod",
    "Check for updates…":
        "Zkontrolovat aktualizace…",
    "Project page on GitHub":
        "Stránka projektu na GitHubu",
    "About {app}":
        "O aplikaci {app}",
    "Update to {version}…":
        "Aktualizovat na {version}…",
    "In use · scanning on this PC":
        "Používá se · skenuje se na tomto PC",
    "In use by {who}":
        "Používá {who}",
    "{user} on {host}":
        "{user} na {host}",
    "Started at {time}. Wait until the light turns green.":
        "Začalo v {time}. Počkejte, až kontrolka zezelená.",
    "In use · scanner is busy":
        "Používá se · skener je zaneprázdněn",
    "The scanner reports that it is scanning right now.":
        "Skener hlásí, že právě skenuje.",
    "Idle · searching…":
        "Nečinný · hledám…",
    "Idle · no scanner":
        "Nečinný · žádný skener",
    "No scanner is connected yet.":
        "Zatím není připojen žádný skener.",
    "Idle · scanner on standby":
        "Nečinný · skener v pohotovosti",
    "The scanner reports that it is stopped or offline.":
        "Skener hlásí, že je zastavený nebo offline.",
    "The scanner is free. You can scan.":
        "Skener je volný. Můžete skenovat.",
    "Idle · installing OCR…":
        "Nečinný · instaluji OCR…",
    "The scanner is free now. You can scan.":
        "Skener je teď volný. Můžete skenovat.",
    "Scanner in use":
        "Skener se používá",
    "The scanner is in use right now.\n\n{text}.\n{tip}\n\nPlease wait until the light at the top turns green, then try again.\nThis app will beep when the scanner is free.":
        "Skener se právě používá.\n\n{text}.\n{tip}\n\nPočkejte, až kontrolka nahoře zezelená, a zkuste to znovu.\nAplikace pípne, až bude skener volný.",
    "Scanner in use: {text}. Wait for the green light.":
        "Skener se používá: {text}. Počkejte na zelenou kontrolku.",
    "Scanner":
        "Skener",
    "Scanning":
        "Skenování",
    "Text & translation":
        "Text a překlad",
    "General":
        "Obecné",
    "Done":
        "Hotovo",
    "Driver":
        "Ovladač",
    "Model":
        "Model",
    "Network":
        "Síť",
    "Auto (all drivers)":
        "Auto (všechny ovladače)",
    "No scanner found yet":
        "Zatím nebyl nalezen žádný skener",
    "Refresh":
        "Obnovit",
    "Driver setup":
        "Instalace ovladače",
    "Find on network":
        "Najít v síti",
    "Web panel":
        "Webový panel",
    "Find your model’s driver":
        "Najděte ovladač pro svůj model",
    "No network reply yet":
        "Zatím žádná odpověď ze sítě",
    "Everything here is found automatically. Change it only if the wrong scanner is chosen.":
        "Vše zde se zjistí automaticky. Měňte to jen tehdy, je-li vybrán špatný skener.",
    "Save as":
        "Uložit jako",
    "one PDF with every page":
        "jedno PDF se všemi stránkami",
    "one JPG image per page":
        "jeden obrázek JPG na stránku",
    "the PDF and the JPG images from one scan":
        "PDF i obrázky JPG z jednoho skenu",
    "Paper source":
        "Zdroj papíru",
    "Auto · feeder if loaded, else flatbed":
        "Auto · podavač, je-li v něm papír, jinak sklo",
    "Flatbed (glass)":
        "Sklo (plochý skener)",
    "Document feeder":
        "Podavač dokumentů",
    "Document feeder · both sides":
        "Podavač dokumentů · oboustranně",
    "Paper size":
        "Velikost papíru",
    "Resolution":
        "Rozlišení",
    "150 dpi · fast, small file":
        "150 dpi · rychlé, malý soubor",
    "300 dpi · recommended":
        "300 dpi · doporučeno",
    "600 dpi · fine detail":
        "600 dpi · jemné detaily",
    "Colour":
        "Barva",
    "Greyscale":
        "Odstíny šedi",
    "Black and white":
        "Černobíle",
    "Save to":
        "Uložit do",
    "Browse…":
        "Procházet…",
    "Ask for a file name every time":
        "Pokaždé se ptát na název souboru",
    "Open the file after scanning":
        "Po naskenování soubor otevřít",
    "Auto source":
        "Auto zdroj",
    "Flatbed":
        "Sklo",
    "Feeder":
        "Podavač",
    "Feeder · 2 sides":
        "Podavač · 2 strany",
    "Make PDFs searchable with OCR (text recognition)":
        "Umožnit vyhledávání v PDF pomocí OCR (rozpoznávání textu)",
    "OCR languages":
        "Jazyky OCR",
    "Auto · English + Greek + your system language":
        "Auto · angličtina + řečtina + jazyk vašeho systému",
    "Choose languages":
        "Vybrat jazyky",
    "Languages download automatically the first time they are used.":
        "Jazyky se stáhnou automaticky při prvním použití.",
    "Also save the text as a .txt file":
        "Uložit text také jako soubor .txt",
    "Translate automatically to":
        "Automaticky překládat do",
    "Off":
        "Vypnuto",
    "Translation service":
        "Překladová služba",
    "Google Translate (free)":
        "Překladač Google (zdarma)",
    "MyMemory (free)":
        "MyMemory (zdarma)",
    "LibreTranslate (your server)":
        "LibreTranslate (váš server)",
    "LibreTranslate server":
        "Server LibreTranslate",
    "API key (optional)":
        "Klíč API (volitelný)",
    "Free services need internet. Google falls back to MyMemory if it fails.":
        "Bezplatné služby potřebují internet. Když Google selže, použije se MyMemory.",
    "Theme":
        "Motiv",
    "Auto · follow Windows / system":
        "Auto · podle Windows / systému",
    "Light":
        "Světlý",
    "Dark":
        "Tmavý",
    "Language":
        "Jazyk",
    "Auto · system language":
        "Auto · jazyk systému",
    "Updates":
        "Aktualizace",
    "Check for updates automatically":
        "Automaticky kontrolovat aktualizace",
    "Check now":
        "Zkontrolovat nyní",
    "Reset everything to Auto":
        "Vrátit vše na Auto",
    "All settings are back to Auto.":
        "Všechna nastavení jsou zpět na Auto.",
    "Restart to change the language?":
        "Restartovat kvůli změně jazyka?",
    "The new language is used after a restart. Restart now?":
        "Nový jazyk se použije po restartu. Restartovat nyní?",
    "Save scans to":
        "Ukládat skeny do",
    "Recognised text":
        "Rozpoznaný text",
    "Translation":
        "Překlad",
    "Translate":
        "Přeložit",
    "From":
        "Z",
    "To":
        "Do",
    "Auto-detect":
        "Rozpoznat automaticky",
    "Copy":
        "Kopírovat",
    "Save .txt":
        "Uložit .txt",
    "Close":
        "Zavřít",
    "Copied.":
        "Zkopírováno.",
    "Detected language: {lang}":
        "Rozpoznaný jazyk: {lang}",
    "Translating with {engine}…":
        "Překládám pomocí {engine}…",
    "Translated with {engine}. Detected: {lang}.":
        "Přeloženo pomocí {engine}. Rozpoznáno: {lang}.",
    "Translation failed. {error}":
        "Překlad selhal. {error}",
    "Saved {name}":
        "Uloženo {name}",
    "No text yet. Turn on OCR in Settings › Text & translation, then scan again.":
        "Zatím žádný text. Zapněte OCR v Nastavení › Text a překlad a skenujte znovu.",
    "Text of {name}":
        "Text z {name}",
    "Looking for scanners ({drivers})…":
        "Hledám skenery ({drivers})…",
    "Looking for scanners… {count} found so far.":
        "Hledám skenery… zatím nalezeno {count}.",
    "Ready. Load the paper and click Scan.":
        "Připraveno. Vložte papír a klikněte na Skenovat.",
    "Search stopped. Click Search again when you are ready.":
        "Hledání zastaveno. Až budete připraveni, klikněte na Hledat znovu.",
    "No scanners found. Check the cable or Wi-Fi and the installed driver (Settings › Scanner › Driver setup).":
        "Nebyly nalezeny žádné skenery. Zkontrolujte kabel nebo Wi-Fi a nainstalovaný ovladač (Nastavení › Skener › Instalace ovladače).",
    "The NAPS2 scanner engine was not found. Close and reopen the app to install it automatically.":
        "Skenovací jádro NAPS2 nebylo nalezeno. Zavřete a znovu otevřete aplikaci, aby se nainstalovalo automaticky.",
    "Scanning a quick low-resolution preview…":
        "Skenuji rychlý náhled v nízkém rozlišení…",
    "Check the page placement, then scan at your chosen resolution.":
        "Zkontrolujte umístění stránky a pak skenujte ve zvoleném rozlišení.",
    "Flatbed preview":
        "Náhled skla",
    "Back":
        "Zpět",
    "Preview ready.":
        "Náhled je připraven.",
    "No preview was produced. Check the flatbed and scanner connection.":
        "Náhled se nevytvořil. Zkontrolujte sklo a připojení skeneru.",
    "Scanning from {where}… Keep the scanner on until the file is saved.":
        "Skenuji z {where}… Nechte skener zapnutý, dokud se soubor neuloží.",
    "the flatbed":
        "skla",
    "the document feeder":
        "podavače dokumentů",
    "the document feeder (both sides)":
        "podavače dokumentů (oboustranně)",
    " Recognising text (OCR)…":
        " Rozpoznávám text (OCR)…",
    "Downloading OCR languages ({langs}). One time only…":
        "Stahuji jazyky OCR ({langs}). Jen jednou…",
    "OCR languages could not be installed ({langs}). Scanning without OCR.":
        "Jazyky OCR se nepodařilo nainstalovat ({langs}). Skenuji bez OCR.",
    "Scan cancelled.":
        "Skenování zrušeno.",
    "The scanner is busy. Someone else may be using it. Wait a moment, then try again.":
        "Skener je zaneprázdněn. Možná ho používá někdo jiný. Chvíli počkejte a zkuste to znovu.",
    "Windows could not reach the Canon scanner. Turn it on, make sure it is on the same Wi-Fi, and check it in Canon IJ Scan Utility, then retry.":
        "Windows se nepodařilo spojit se skenerem Canon. Zapněte ho, ověřte, že je ve stejné Wi-Fi, zkontrolujte ho v Canon IJ Scan Utility a zkuste to znovu.",
    "Epson Scan 2 could not open the scanner. In Epson Scan 2 Utility, add or test its network address, then retry.":
        "Epson Scan 2 nemohl otevřít skener. V Epson Scan 2 Utility přidejte nebo otestujte jeho síťovou adresu a zkuste to znovu.",
    "Scanner operation failed. {detail}":
        "Operace skeneru selhala. {detail}",
    "No pages were scanned. Check the paper and the scanner connection.":
        "Nebyly naskenovány žádné stránky. Zkontrolujte papír a připojení skeneru.",
    "Could not save the scan. {error}":
        "Sken se nepodařilo uložit. {error}",
    "The scan was kept as {path}":
        "Sken byl ponechán jako {path}",
    "✓ Saved {files} in {folder}":
        "✓ Uloženo {files} do {folder}",
    "{count} JPG pages":
        "{count} stránek JPG",
    "text":
        "text",
    "Translating the text to {lang}…":
        "Překládám text do jazyka {lang}…",
    "✓ Translation saved: {name}":
        "✓ Překlad uložen: {name}",
    "Could not start NAPS2. {error}":
        "NAPS2 se nepodařilo spustit. {error}",
    "Could not create {folder}. {error}\nChoose another folder in Settings › Scanning.":
        "Nelze vytvořit {folder}. {error}\nVyberte jinou složku v Nastavení › Skenování.",
    "Save scan":
        "Uložit sken",
    "Scan in progress":
        "Probíhá skenování",
    "A scan is running. Cancel it and close the app?":
        "Probíhá skenování. Zrušit ho a zavřít aplikaci?",
    "JPG export needs PyMuPDF. Close and reopen the app to install it.":
        "Export do JPG potřebuje PyMuPDF. Zavřete a znovu otevřete aplikaci, aby se nainstaloval.",
    "Checking GitHub for a newer version…":
        "Hledám na GitHubu novější verzi…",
    "Could not check for updates. {error}":
        "Aktualizace nelze zkontrolovat. {error}",
    "You have the latest version (v{version}).":
        "Máte nejnovější verzi (v{version}).",
    "Update available":
        "Je k dispozici aktualizace",
    "{app} {version} is available (you have v{current}).\n\nWhat's new:\n{notes}\n\nDownload and install it now?":
        "{app} {version} je k dispozici (máte v{current}).\n\nNovinky:\n{notes}\n\nStáhnout a nainstalovat nyní?",
    "No release notes.":
        "Bez poznámek k verzi.",
    "Update {version} is waiting in Help.":
        "Aktualizace {version} čeká v Nápovědě.",
    "Finish the scan first, then install the update from Help.":
        "Nejprve dokončete skenování, pak nainstalujte aktualizaci z Nápovědy.",
    "Downloading {version} from GitHub…":
        "Stahuji {version} z GitHubu…",
    "Update failed. {error}":
        "Aktualizace selhala. {error}",
    "macOS is running the app from a temporary read-only copy. Drag What the Scan into Applications, open it from there, then update again.":
        "macOS spouští aplikaci z dočasné kopie jen pro čtení. Přetáhněte What the Scan do Aplikací, otevřete ji odtud a aktualizujte znovu.",
    "The app's folder can't be written to. Move the app to a folder you own (or Applications) and update again.":
        "Do složky aplikace nelze zapisovat. Přesuňte aplikaci do své složky (nebo do Aplikací) a aktualizujte znovu.",
    "Update failed":
        "Aktualizace selhala",
    "{error}\n\nOpen the release page to download it by hand?":
        "{error}\n\nOtevřít stránku vydání a stáhnout ji ručně?",
    "Updated to {version}. Restarting…":
        "Aktualizováno na {version}. Restartuji…",
    "Choose a model to find its driver.":
        "Vyberte model, abyste našli jeho ovladač.",
    "Install driver":
        "Instalace ovladače",
    "Download and install the official {label} now?\n\nWindows may ask for permission. Choose No to open the support page instead.":
        "Stáhnout a nainstalovat nyní oficiální {label}?\n\nWindows může požádat o oprávnění. Zvolte Ne, chcete-li místo toho otevřít stránku podpory.",
    "Preparing the official {label} installer…":
        "Připravuji oficiální instalátor {label}…",
    "{label} installed. Looking for scanners…":
        "{label} nainstalován. Hledám skenery…",
    "Driver setup failed. {error}\nThe support page is opening so you can install it by hand.":
        "Instalace ovladače selhala. {error}\nOtevírá se stránka podpory, abyste ho mohli nainstalovat ručně.",
    "Searching the local network for scanners (Epson, Canon, HP, AirPrint)…":
        "Hledám skenery v místní síti (Epson, Canon, HP, AirPrint)…",
    "answered as a network (eSCL) scanner ✓":
        "odpověděl jako síťový skener (eSCL) ✓",
    "This scanner has: {sources}":
        "Tento skener má: {sources}",
    "Network discovery failed. {error}":
        "Hledání v síti selhalo. {error}",
    "Select your scanner's network address.":
        "Vyberte síťovou adresu svého skeneru.",
    "No scanner replied on this local network.":
        "V této místní síti neodpověděl žádný skener.",
    "answered as a Canon scanner ✓":
        "odpověděl jako skener Canon ✓",
    "responds on the scanner port ✓":
        "odpovídá na portu skeneru ✓",
    "did not respond on the scanner port":
        "neodpověděl na portu skeneru",
    "{brand} {ip} {state}. Scanning uses the driver chosen above.":
        "{brand} {ip} {state}. Skenování používá ovladač zvolený výše.",
}

UI_RU = {
    "Brother's download page is opening. The model {model} is copied: paste it in the search box (Ctrl+V). Most Brother models also scan with no driver over the network.":
        "Открывается страница загрузок Brother. Модель {model} скопирована: вставьте её в поиск (Ctrl+V). Большинство моделей Brother сканируют и без драйвера по сети.",
    "Connect Epson Scan 2 to the scanner":
        "Подключить Epson Scan 2 к сканеру",
    "Epson Scan 2 does not know your scanner's network address yet. This happens after the driver is (re)installed. One time only:":
        "Epson Scan 2 ещё не знает сетевой адрес сканера. Так бывает после (пере)установки драйвера. Только один раз:",
    "1. Click “Open Epson Scan 2 Utility” below.\n2. At the top, in “Scanner”, choose “Settings”.\n3. Click “Add”, choose “Enter address”, press Ctrl+V (the address {ip} is already copied) and click OK.\n4. Click OK, close the utility and press Scan again.":
        "1. Нажмите ниже «Открыть Epson Scan 2 Utility».\n2. Вверху в поле «Scanner» выберите «Settings».\n3. Нажмите «Add», выберите «Enter address», нажмите Ctrl+V (адрес {ip} уже скопирован) и OK.\n4. Нажмите OK, закройте утилиту и снова нажмите «Сканировать».",
    "Open Epson Scan 2 Utility":
        "Открыть Epson Scan 2 Utility",
    "Could not open Epson Scan 2 Utility. {error}":
        "Не удалось открыть Epson Scan 2 Utility. {error}",
    "{phone} (browser)": "{phone} (браузер)",
    "AirDrop":
        "AirDrop",
    "Send with AirDrop to an iPhone, iPad or Mac nearby":
        "Отправить через AirDrop на iPhone, iPad или Mac поблизости",
    "AirDrop is open: choose the iPhone or Mac.":
        "AirDrop открыт: выберите iPhone или Mac.",
    "AirDrop is not available on this Mac. Turn on Wi-Fi and Bluetooth.":
        "AirDrop недоступен на этом Mac. Включите Wi-Fi и Bluetooth.",
    "So that your phone can send to this computer, Windows Firewall must let it in.\n\nAllow it now? Windows asks for permission once (only phones on your own network, only the ports of {app}).":
        "Чтобы телефон мог отправлять файлы на этот компьютер, это должен разрешить брандмауэр Windows.\n\nРазрешить сейчас? Windows запросит разрешение один раз (только телефоны в вашей сети, только порты {app}).",
    "Waiting for Windows permission (firewall)…":
        "Ожидание разрешения Windows (брандмауэр)…",
    "✓ Windows Firewall lets your phone in now.":
        "✓ Брандмауэр Windows теперь пропускает ваш телефон.",
    "Windows Firewall was not changed, so the phone may not be able to send to this computer.":
        "Брандмауэр Windows не изменён, поэтому телефон, возможно, не сможет отправлять файлы на этот компьютер.",
    "LocalSend for the phone":
        "LocalSend для телефона",
    "Trying Epson's other download server…":
        "Пробую другой сервер загрузки Epson…",
    "{name} answers on the network ({ip}), but its scanner driver is not installed.":
        "{name} отвечает в сети ({ip}), но драйвер сканера не установлен.",
    "Scanner driver missing":
        "Нет драйвера сканера",
    "{name} was found on the network ({ip}), but its scanner driver is not installed, so the app cannot scan with it.\n\nInstall the official {label} now? It is downloaded and installed automatically (a few minutes; Windows may ask for permission).":
        "{name} найден в сети ({ip}), но драйвер сканера не установлен, поэтому приложение не может с ним сканировать.\n\nУстановить официальный {label} сейчас? Он скачается и установится автоматически (несколько минут; Windows может запросить разрешение).",
    "Phone":
        "Телефон",
    "Send to your phone or receive photos from it, on the same Wi-Fi (LocalSend app or QR code)":
        "Отправить на телефон или получить с него фото в той же Wi-Fi (приложение LocalSend или QR-код)",
    "Send scans to your phone and receive photos from it, on the same Wi-Fi.":
        "Отправляйте сканы на телефон и получайте с него фото в той же Wi-Fi.",
    "Receiving from the phone":
        "Приём с телефона",
    "Keep receiving on while the app is open":
        "Держать приём включённым, пока приложение открыто",
    "When this is off, receiving opens for {minutes} minutes each time you press Phone.":
        "Если выключено, приём открывается на {minutes} мин. при каждом нажатии «Телефон».",
    "Phone photos":
        "Фото с телефона",
    "Just save them in the scans folder":
        "Просто сохранять в папку сканов",
    "Make a PDF, like a scan (OCR, Word)":
        "Делать PDF, как скан (OCR, Word)",
    "Name on the phone":
        "Имя на телефоне",
    "How it works":
        "Как это работает",
    "1. Phone and computer on the same Wi-Fi.\n2. Install the free LocalSend app on the phone, or simply scan the QR code.\n3. Press Phone, next to Preview, choose the phone and Send.\n4. To send from the phone: in LocalSend choose “{name}”, or use the QR page.":
        "1. Телефон и компьютер в одной Wi-Fi.\n2. Установите на телефон бесплатное приложение LocalSend или просто отсканируйте QR-код.\n3. Нажмите «Телефон» рядом с «Предпросмотром», выберите телефон и «Отправить».\n4. Отправка с телефона: в LocalSend выберите «{name}» или используйте страницу QR-кода.",
    "Get LocalSend":
        "Скачать LocalSend",
    "Idle · making a PDF from phone photos":
        "Ожидание · создаю PDF из фото с телефона",
    "✓ Made {file} from {count} phone photo(s)":
        "✓ Создан {file} из фото с телефона: {count}",
    "Windows may now ask whether {app} can use the network.\n\nTick “Private networks” and click Allow, so your phone can reach this computer.":
        "Windows может спросить, можно ли {app} использовать сеть.\n\nОтметьте «Частные сети» и нажмите «Разрешить», чтобы телефон мог подключиться к этому компьютеру.",
    "The phone connection could not start. Another program may be using the network ports {ports}.":
        "Не удалось запустить связь с телефоном. Возможно, сетевые порты {ports} заняты другой программой.",
    "Receiving is off. Press Phone to open it again.":
        "Приём выключен. Нажмите «Телефон», чтобы открыть его снова.",
    "Receiving is on: the phone can send files to “{name}”.":
        "Приём включён: телефон может отправлять файлы на «{name}».",
    "Receiving is on for {time}: the phone can send files to “{name}”.":
        "Приём включён ещё {time}: телефон может отправлять файлы на «{name}».",
    "… and {count} more":
        "… и ещё {count}",
    "Files from a phone":
        "Файлы с телефона",
    "“{sender}” wants to send {count} file(s):":
        "«{sender}» хочет отправить файлов: {count}",
    "They will be saved in {folder}.":
        "Они будут сохранены в {folder}.",
    "Accept":
        "Принять",
    "Decline":
        "Отклонить",
    "Receiving files from {sender}…":
        "Получение файлов от {sender}…",
    "✓ Received {count} file(s) from {sender} in {folder}":
        "✓ Получено файлов от {sender}: {count}, в {folder}",
    "The photos were saved as they are, because a scan is running.":
        "Фото сохранены как есть, потому что идёт сканирование.",
    "Making a PDF from {count} phone photo(s)…":
        "Создаю PDF из фото с телефона: {count}…",
    "This link has expired. Scan the QR code again.":
        "Срок действия ссылки истёк. Отсканируйте QR-код снова.",
    "No scan yet. Scan something first, then reload this page.":
        "Сканов пока нет. Сначала отсканируйте что-нибудь, затем обновите страницу.",
    "Waiting for the computer to accept…":
        "Ждём, пока компьютер примет…",
    "The computer declined the files.":
        "Компьютер отклонил файлы.",
    "The computer is receiving other files. Try again in a moment.":
        "Компьютер принимает другие файлы. Повторите через минуту.",
    "Sending failed. Check that the phone is on the same Wi-Fi and try again.":
        "Отправка не удалась. Проверьте, что телефон в той же Wi-Fi, и повторите.",
    "Sending {name}…":
        "Отправка {name}…",
    "✓ Sent! The files are on the computer.":
        "✓ Отправлено! Файлы на компьютере.",
    "1 · Get the scan on this phone":
        "1 · Получить скан на этот телефон",
    "Reload":
        "Обновить",
    "2 · Send photos or files to the computer":
        "2 · Отправить фото или файлы на компьютер",
    "Take a photo or choose files":
        "Сделать фото или выбрать файлы",
    "Send to your phone":
        "Отправить на телефон",
    "Phone and computer must be on the same Wi-Fi.":
        "Телефон и компьютер должны быть в одной Wi-Fi.",
    "Choose other files…":
        "Выбрать другие файлы…",
    "Phones with LocalSend":
        "Телефоны с LocalSend",
    "Send":
        "Отправить",
    "No LocalSend? Scan this":
        "Нет LocalSend? Отсканируйте это",
    "Point the phone camera at the code. A page opens where you can download the scan and send photos to this computer.":
        "Наведите камеру телефона на код. Откроется страница, где можно скачать скан и отправить фото на этот компьютер.",
    "QR code not available.":
        "QR-код недоступен.",
    "To send: {names}  ({size})":
        "К отправке: {names}  ({size})",
    "Nothing to send yet. Scan first, or choose files.":
        "Пока нечего отправлять. Сначала отсканируйте или выберите файлы.",
    "Choose files for the phone":
        "Выберите файлы для телефона",
    "Looking for phones… Open LocalSend on the phone.":
        "Ищу телефоны… Откройте LocalSend на телефоне.",
    "No phone found.\n1. Is the phone on the same Wi-Fi?\n2. Open the LocalSend app on the phone (free, Play Store / App Store).\n3. Or simply scan the QR code on the right.":
        "Телефон не найден.\n1. Телефон в той же Wi-Fi?\n2. Откройте на телефоне приложение LocalSend (бесплатно, Play Store / App Store).\n3. Или просто отсканируйте QR-код справа.",
    "Waiting for {phone} to accept… Tap Accept on the phone.":
        "Ждём, пока {phone} примет… Нажмите «Принять» на телефоне.",
    "Sending to {phone}… {value}%":
        "Отправка на {phone}… {value}%",
    "{phone} declined the files.":
        "{phone} отклонил файлы.",
    "{phone} is busy with another transfer. Try again in a moment.":
        "{phone} занят другой передачей. Повторите через минуту.",
    "{phone} asks for a PIN. Turn off the PIN in LocalSend settings on the phone.":
        "{phone} просит PIN-код. Отключите PIN в настройках LocalSend на телефоне.",
    "Could not reach {phone}. Is LocalSend open and on the same Wi-Fi?":
        "Не удалось связаться с {phone}. LocalSend открыт и в той же Wi-Fi?",
    "Sending cancelled.":
        "Отправка отменена.",
    "✓ Sent {count} file(s) to {phone}.":
        "✓ Отправлено файлов на {phone}: {count}.",
    "Sending failed. {error}":
        "Отправка не удалась. {error}",
    "Also save an editable document (text from OCR)":
        "Сохранять также редактируемый документ (текст из OCR)",
    "Document":
        "Документ",
    "Word (.docx) · Microsoft Word":
        "Word (.docx) · Microsoft Word",
    "OpenDocument (.odt) · LibreOffice on Mac / Linux":
        "OpenDocument (.odt) · LibreOffice на Mac / Linux",
    "Word export needs python-docx. Close and reopen the app to install it.":
        "Для экспорта в Word нужен python-docx. Закройте и снова откройте приложение, чтобы установить его.",
    "What to save, the paper and where the files go.":
        "Что сохранять, бумага и куда идут файлы.",
    "Recognise text in your scans and translate it.":
        "Распознавание текста в сканах и его перевод.",
    "Language, appearance and updates.":
        "Язык, оформление и обновления.",
    "Output":
        "Вывод",
    "Paper":
        "Бумага",
    "Saving":
        "Сохранение",
    "Text recognition (OCR)":
        "Распознавание текста (OCR)",
    "Appearance":
        "Оформление",
    "Reset":
        "Сброс",
    "Settings":
        "Настройки",
    "Help":
        "Справка",
    "Ready":
        "Готов",
    "Idle":
        "Ожидание",
    "Scan":
        "Сканировать",
    "Preview":
        "Предпросмотр",
    "Text":
        "Текст",
    "Open last":
        "Последний файл",
    "Open folder":
        "Открыть папку",
    "Cancel":
        "Отмена",
    "Stop search":
        "Остановить поиск",
    "Search again":
        "Искать снова",
    "Change…":
        "Изменить…",
    "Starting…":
        "Запуск…",
    "Looking for scanners…":
        "Поиск сканеров…",
    "Checking every driver at the same time.":
        "Проверяю все драйверы одновременно.",
    "Connected to {name}":
        "Подключено к {name}",
    "via {driver}":
        "через {driver}",
    "{brand} at {ip}":
        "{brand} по адресу {ip}",
    "{count} more in Settings":
        "ещё {count} в Настройках",
    "No scanner connected":
        "Сканер не подключён",
    "Turn the scanner on, check the USB cable or Wi-Fi, then click Search again.":
        "Включите сканер, проверьте кабель USB или Wi-Fi, затем нажмите «Искать снова».",
    "saves to {folder}":
        "сохраняет в {folder}",
    "asks for a file name":
        "спрашивает имя файла",
    "OCR":
        "OCR",
    "OCR off":
        "OCR выкл.",
    "translate → {lang}":
        "перевод → {lang}",
    "Scan and save in the format chosen in Settings (Ctrl+S)":
        "Сканировать и сохранить в формате, выбранном в Настройках (Ctrl+S)",
    "Quick low-resolution look at the flatbed (Ctrl+P)":
        "Быстрый просмотр стекла в низком разрешении (Ctrl+P)",
    "Recognised text and translation of the last scan (Ctrl+T)":
        "Распознанный текст и перевод последнего скана (Ctrl+T)",
    "Open the last scanned file":
        "Открыть последний отсканированный файл",
    "Open the folder with your scans":
        "Открыть папку со сканами",
    "Stop the scan or search (Esc)":
        "Остановить сканирование или поиск (Esc)",
    "Look for scanners again (F5)":
        "Снова искать сканеры (F5)",
    "Choose another scanner or change scan settings":
        "Выбрать другой сканер или изменить настройки сканирования",
    "Scanner, scanning, text and appearance settings (Ctrl+,)":
        "Настройки сканера, сканирования, текста и оформления (Ctrl+,)",
    "Quick guide":
        "Краткое руководство",
    "Check for updates…":
        "Проверить обновления…",
    "Project page on GitHub":
        "Страница проекта на GitHub",
    "About {app}":
        "О программе {app}",
    "Update to {version}…":
        "Обновить до {version}…",
    "In use · scanning on this PC":
        "Занят · сканирование на этом ПК",
    "In use by {who}":
        "Занят: {who}",
    "{user} on {host}":
        "{user} на {host}",
    "Started at {time}. Wait until the light turns green.":
        "Начато в {time}. Подождите, пока индикатор станет зелёным.",
    "In use · scanner is busy":
        "Занят · сканер работает",
    "The scanner reports that it is scanning right now.":
        "Сканер сообщает, что сейчас сканирует.",
    "Idle · searching…":
        "Ожидание · поиск…",
    "Idle · no scanner":
        "Ожидание · нет сканера",
    "No scanner is connected yet.":
        "Сканер ещё не подключён.",
    "Idle · scanner on standby":
        "Ожидание · сканер в режиме ожидания",
    "The scanner reports that it is stopped or offline.":
        "Сканер сообщает, что остановлен или не в сети.",
    "The scanner is free. You can scan.":
        "Сканер свободен. Можно сканировать.",
    "Idle · installing OCR…":
        "Ожидание · установка OCR…",
    "The scanner is free now. You can scan.":
        "Сканер освободился. Можно сканировать.",
    "Scanner in use":
        "Сканер занят",
    "The scanner is in use right now.\n\n{text}.\n{tip}\n\nPlease wait until the light at the top turns green, then try again.\nThis app will beep when the scanner is free.":
        "Сканер сейчас используется.\n\n{text}.\n{tip}\n\nПодождите, пока индикатор вверху станет зелёным, и повторите.\nПриложение подаст сигнал, когда сканер освободится.",
    "Scanner in use: {text}. Wait for the green light.":
        "Сканер занят: {text}. Дождитесь зелёного индикатора.",
    "Scanner":
        "Сканер",
    "Scanning":
        "Сканирование",
    "Text & translation":
        "Текст и перевод",
    "General":
        "Общие",
    "Done":
        "Готово",
    "Driver":
        "Драйвер",
    "Model":
        "Модель",
    "Network":
        "Сеть",
    "Auto (all drivers)":
        "Авто (все драйверы)",
    "No scanner found yet":
        "Сканер пока не найден",
    "Refresh":
        "Обновить",
    "Driver setup":
        "Установка драйвера",
    "Find on network":
        "Найти в сети",
    "Web panel":
        "Веб-панель",
    "Find your model’s driver":
        "Найдите драйвер своей модели",
    "No network reply yet":
        "Пока нет ответа из сети",
    "Everything here is found automatically. Change it only if the wrong scanner is chosen.":
        "Здесь всё определяется автоматически. Меняйте только если выбран не тот сканер.",
    "Save as":
        "Сохранять как",
    "one PDF with every page":
        "один PDF со всеми страницами",
    "one JPG image per page":
        "одно изображение JPG на страницу",
    "the PDF and the JPG images from one scan":
        "PDF и изображения JPG из одного скана",
    "Paper source":
        "Источник бумаги",
    "Auto · feeder if loaded, else flatbed":
        "Авто · податчик, если в нём есть бумага, иначе стекло",
    "Flatbed (glass)":
        "Стекло (планшет)",
    "Document feeder":
        "Податчик документов",
    "Document feeder · both sides":
        "Податчик документов · двусторонний",
    "Paper size":
        "Размер бумаги",
    "Resolution":
        "Разрешение",
    "150 dpi · fast, small file":
        "150 dpi · быстро, маленький файл",
    "300 dpi · recommended":
        "300 dpi · рекомендуется",
    "600 dpi · fine detail":
        "600 dpi · мелкие детали",
    "Colour":
        "Цвет",
    "Greyscale":
        "Оттенки серого",
    "Black and white":
        "Чёрно-белый",
    "Save to":
        "Сохранять в",
    "Browse…":
        "Обзор…",
    "Ask for a file name every time":
        "Каждый раз спрашивать имя файла",
    "Open the file after scanning":
        "Открывать файл после сканирования",
    "Auto source":
        "Авто-источник",
    "Flatbed":
        "Стекло",
    "Feeder":
        "Податчик",
    "Feeder · 2 sides":
        "Податчик · 2 стороны",
    "Make PDFs searchable with OCR (text recognition)":
        "Делать PDF доступными для поиска с помощью OCR (распознавание текста)",
    "OCR languages":
        "Языки OCR",
    "Auto · English + Greek + your system language":
        "Авто · английский + греческий + язык системы",
    "Choose languages":
        "Выбрать языки",
    "Languages download automatically the first time they are used.":
        "Языки скачиваются автоматически при первом использовании.",
    "Also save the text as a .txt file":
        "Сохранять текст также в файл .txt",
    "Translate automatically to":
        "Автоматически переводить на",
    "Off":
        "Выкл.",
    "Translation service":
        "Сервис перевода",
    "Google Translate (free)":
        "Google Переводчик (бесплатно)",
    "MyMemory (free)":
        "MyMemory (бесплатно)",
    "LibreTranslate (your server)":
        "LibreTranslate (ваш сервер)",
    "LibreTranslate server":
        "Сервер LibreTranslate",
    "API key (optional)":
        "Ключ API (необязательно)",
    "Free services need internet. Google falls back to MyMemory if it fails.":
        "Бесплатным сервисам нужен интернет. Если Google не работает, используется MyMemory.",
    "Theme":
        "Тема",
    "Auto · follow Windows / system":
        "Авто · как в Windows / системе",
    "Light":
        "Светлая",
    "Dark":
        "Тёмная",
    "Language":
        "Язык",
    "Auto · system language":
        "Авто · язык системы",
    "Updates":
        "Обновления",
    "Check for updates automatically":
        "Автоматически проверять обновления",
    "Check now":
        "Проверить сейчас",
    "Reset everything to Auto":
        "Вернуть всё в Авто",
    "All settings are back to Auto.":
        "Все настройки возвращены в Авто.",
    "Restart to change the language?":
        "Перезапустить для смены языка?",
    "The new language is used after a restart. Restart now?":
        "Новый язык будет использоваться после перезапуска. Перезапустить сейчас?",
    "Save scans to":
        "Сохранять сканы в",
    "Recognised text":
        "Распознанный текст",
    "Translation":
        "Перевод",
    "Translate":
        "Перевести",
    "From":
        "С",
    "To":
        "На",
    "Auto-detect":
        "Автоопределение",
    "Copy":
        "Копировать",
    "Save .txt":
        "Сохранить .txt",
    "Close":
        "Закрыть",
    "Copied.":
        "Скопировано.",
    "Detected language: {lang}":
        "Определён язык: {lang}",
    "Translating with {engine}…":
        "Перевожу с помощью {engine}…",
    "Translated with {engine}. Detected: {lang}.":
        "Переведено с помощью {engine}. Определено: {lang}.",
    "Translation failed. {error}":
        "Перевод не удался. {error}",
    "Saved {name}":
        "Сохранено: {name}",
    "No text yet. Turn on OCR in Settings › Text & translation, then scan again.":
        "Текста пока нет. Включите OCR в Настройки › Текст и перевод и отсканируйте снова.",
    "Text of {name}":
        "Текст {name}",
    "Looking for scanners ({drivers})…":
        "Поиск сканеров ({drivers})…",
    "Looking for scanners… {count} found so far.":
        "Поиск сканеров… найдено: {count}.",
    "Ready. Load the paper and click Scan.":
        "Готов. Положите бумагу и нажмите «Сканировать».",
    "Search stopped. Click Search again when you are ready.":
        "Поиск остановлен. Нажмите «Искать снова», когда будете готовы.",
    "No scanners found. Check the cable or Wi-Fi and the installed driver (Settings › Scanner › Driver setup).":
        "Сканеры не найдены. Проверьте кабель или Wi-Fi и установленный драйвер (Настройки › Сканер › Установка драйвера).",
    "The NAPS2 scanner engine was not found. Close and reopen the app to install it automatically.":
        "Модуль сканирования NAPS2 не найден. Закройте и снова откройте приложение, чтобы установить его автоматически.",
    "Scanning a quick low-resolution preview…":
        "Сканирую быстрый предпросмотр в низком разрешении…",
    "Check the page placement, then scan at your chosen resolution.":
        "Проверьте положение страницы, затем сканируйте в выбранном разрешении.",
    "Flatbed preview":
        "Предпросмотр стекла",
    "Back":
        "Назад",
    "Preview ready.":
        "Предпросмотр готов.",
    "No preview was produced. Check the flatbed and scanner connection.":
        "Предпросмотр не получен. Проверьте стекло и подключение сканера.",
    "Scanning from {where}… Keep the scanner on until the file is saved.":
        "Сканирую с {where}… Не выключайте сканер, пока файл не сохранится.",
    "the flatbed":
        "стекла",
    "the document feeder":
        "податчика документов",
    "the document feeder (both sides)":
        "податчика документов (двусторонне)",
    " Recognising text (OCR)…":
        " Распознаю текст (OCR)…",
    "Downloading OCR languages ({langs}). One time only…":
        "Скачиваю языки OCR ({langs}). Только один раз…",
    "OCR languages could not be installed ({langs}). Scanning without OCR.":
        "Не удалось установить языки OCR ({langs}). Сканирую без OCR.",
    "Scan cancelled.":
        "Сканирование отменено.",
    "The scanner is busy. Someone else may be using it. Wait a moment, then try again.":
        "Сканер занят. Возможно, им пользуется кто-то другой. Подождите немного и повторите.",
    "Windows could not reach the Canon scanner. Turn it on, make sure it is on the same Wi-Fi, and check it in Canon IJ Scan Utility, then retry.":
        "Windows не удалось связаться со сканером Canon. Включите его, убедитесь, что он в той же Wi-Fi, проверьте его в Canon IJ Scan Utility и повторите.",
    "Epson Scan 2 could not open the scanner. In Epson Scan 2 Utility, add or test its network address, then retry.":
        "Epson Scan 2 не удалось открыть сканер. В Epson Scan 2 Utility добавьте или проверьте его сетевой адрес и повторите.",
    "Scanner operation failed. {detail}":
        "Операция сканера не удалась. {detail}",
    "No pages were scanned. Check the paper and the scanner connection.":
        "Страницы не отсканированы. Проверьте бумагу и подключение сканера.",
    "Could not save the scan. {error}":
        "Не удалось сохранить скан. {error}",
    "The scan was kept as {path}":
        "Скан сохранён как {path}",
    "✓ Saved {files} in {folder}":
        "✓ Сохранено {files} в {folder}",
    "{count} JPG pages":
        "Страниц JPG: {count}",
    "text":
        "текст",
    "Translating the text to {lang}…":
        "Перевожу текст на {lang}…",
    "✓ Translation saved: {name}":
        "✓ Перевод сохранён: {name}",
    "Could not start NAPS2. {error}":
        "Не удалось запустить NAPS2. {error}",
    "Could not create {folder}. {error}\nChoose another folder in Settings › Scanning.":
        "Не удалось создать {folder}. {error}\nВыберите другую папку в Настройки › Сканирование.",
    "Save scan":
        "Сохранить скан",
    "Scan in progress":
        "Идёт сканирование",
    "A scan is running. Cancel it and close the app?":
        "Идёт сканирование. Отменить его и закрыть приложение?",
    "JPG export needs PyMuPDF. Close and reopen the app to install it.":
        "Для экспорта в JPG нужен PyMuPDF. Закройте и снова откройте приложение, чтобы установить его.",
    "Checking GitHub for a newer version…":
        "Проверяю на GitHub наличие новой версии…",
    "Could not check for updates. {error}":
        "Не удалось проверить обновления. {error}",
    "You have the latest version (v{version}).":
        "У вас последняя версия (v{version}).",
    "Update available":
        "Доступно обновление",
    "{app} {version} is available (you have v{current}).\n\nWhat's new:\n{notes}\n\nDownload and install it now?":
        "Доступна {app} {version} (у вас v{current}).\n\nЧто нового:\n{notes}\n\nСкачать и установить сейчас?",
    "No release notes.":
        "Нет описания изменений.",
    "Update {version} is waiting in Help.":
        "Обновление {version} ждёт в Справке.",
    "Finish the scan first, then install the update from Help.":
        "Сначала завершите сканирование, затем установите обновление из Справки.",
    "Downloading {version} from GitHub…":
        "Скачиваю {version} с GitHub…",
    "Update failed. {error}":
        "Обновление не удалось. {error}",
    "macOS is running the app from a temporary read-only copy. Drag What the Scan into Applications, open it from there, then update again.":
        "macOS запускает приложение из временной копии только для чтения. Перетащите What the Scan в «Программы», откройте оттуда и обновите снова.",
    "The app's folder can't be written to. Move the app to a folder you own (or Applications) and update again.":
        "В папку приложения нельзя записывать. Переместите приложение в свою папку (или в «Программы») и обновите снова.",
    "Update failed":
        "Обновление не удалось",
    "{error}\n\nOpen the release page to download it by hand?":
        "{error}\n\nОткрыть страницу выпуска, чтобы скачать вручную?",
    "Updated to {version}. Restarting…":
        "Обновлено до {version}. Перезапуск…",
    "Choose a model to find its driver.":
        "Выберите модель, чтобы найти её драйвер.",
    "Install driver":
        "Установка драйвера",
    "Download and install the official {label} now?\n\nWindows may ask for permission. Choose No to open the support page instead.":
        "Скачать и установить официальный {label} сейчас?\n\nWindows может запросить разрешение. Выберите «Нет», чтобы открыть страницу поддержки.",
    "Preparing the official {label} installer…":
        "Подготовка официального установщика {label}…",
    "{label} installed. Looking for scanners…":
        "{label} установлен. Поиск сканеров…",
    "Driver setup failed. {error}\nThe support page is opening so you can install it by hand.":
        "Установка драйвера не удалась. {error}\nОткрывается страница поддержки, чтобы вы могли установить его вручную.",
    "Searching the local network for scanners (Epson, Canon, HP, AirPrint)…":
        "Поиск сканеров в локальной сети (Epson, Canon, HP, AirPrint)…",
    "answered as a network (eSCL) scanner ✓":
        "ответил как сетевой сканер (eSCL) ✓",
    "This scanner has: {sources}":
        "У этого сканера есть: {sources}",
    "Network discovery failed. {error}":
        "Поиск в сети не удался. {error}",
    "Select your scanner's network address.":
        "Выберите сетевой адрес своего сканера.",
    "No scanner replied on this local network.":
        "В этой локальной сети не ответил ни один сканер.",
    "answered as a Canon scanner ✓":
        "ответил как сканер Canon ✓",
    "responds on the scanner port ✓":
        "отвечает на порту сканера ✓",
    "did not respond on the scanner port":
        "не ответил на порту сканера",
    "{brand} {ip} {state}. Scanning uses the driver chosen above.":
        "{brand} {ip} {state}. Сканирование использует драйвер, выбранный выше.",
}

UI_JA = {
    "Brother's download page is opening. The model {model} is copied: paste it in the search box (Ctrl+V). Most Brother models also scan with no driver over the network.":
        "Brother のダウンロードページを開きます。モデル {model} はコピー済みです。検索欄に貼り付けてください (Ctrl+V)。ほとんどの Brother モデルはドライバーなしでもネットワーク経由でスキャンできます。",
    "Connect Epson Scan 2 to the scanner":
        "Epson Scan 2 をスキャナーに接続",
    "Epson Scan 2 does not know your scanner's network address yet. This happens after the driver is (re)installed. One time only:":
        "Epson Scan 2 はまだスキャナーのネットワークアドレスを知りません。ドライバーを（再）インストールした後に起こります。最初の一度だけ:",
    "1. Click “Open Epson Scan 2 Utility” below.\n2. At the top, in “Scanner”, choose “Settings”.\n3. Click “Add”, choose “Enter address”, press Ctrl+V (the address {ip} is already copied) and click OK.\n4. Click OK, close the utility and press Scan again.":
        "1. 下の「Epson Scan 2 Utility を開く」をクリックします。\n2. 上部の「Scanner」で「Settings」を選びます。\n3. 「Add」をクリックし、「Enter address」を選んで Ctrl+V を押し（アドレス {ip} はコピー済み）、OK をクリックします。\n4. OK をクリックしてユーティリティを閉じ、もう一度「スキャン」を押します。",
    "Open Epson Scan 2 Utility":
        "Epson Scan 2 Utility を開く",
    "Could not open Epson Scan 2 Utility. {error}":
        "Epson Scan 2 Utility を開けませんでした。{error}",
    "{phone} (browser)": "{phone}（ブラウザー）",
    "AirDrop":
        "AirDrop",
    "Send with AirDrop to an iPhone, iPad or Mac nearby":
        "AirDrop で近くの iPhone、iPad、Mac に送信",
    "AirDrop is open: choose the iPhone or Mac.":
        "AirDrop を開きました。iPhone または Mac を選んでください。",
    "AirDrop is not available on this Mac. Turn on Wi-Fi and Bluetooth.":
        "この Mac では AirDrop を使用できません。Wi-Fi と Bluetooth をオンにしてください。",
    "So that your phone can send to this computer, Windows Firewall must let it in.\n\nAllow it now? Windows asks for permission once (only phones on your own network, only the ports of {app}).":
        "スマートフォンからこのコンピューターにファイルを送るには、Windows ファイアウォールで許可する必要があります。\n\n今すぐ許可しますか？ Windows が一度だけ許可を求めます（自分のネットワーク内のスマートフォンのみ、{app} のポートのみ）。",
    "Waiting for Windows permission (firewall)…":
        "Windows の許可を待っています（ファイアウォール）…",
    "✓ Windows Firewall lets your phone in now.":
        "✓ Windows ファイアウォールがスマートフォンの接続を許可しました。",
    "Windows Firewall was not changed, so the phone may not be able to send to this computer.":
        "Windows ファイアウォールは変更されていないため、スマートフォンからこのコンピューターに送信できない可能性があります。",
    "LocalSend for the phone":
        "スマートフォン用 LocalSend",
    "Trying Epson's other download server…":
        "Epson の別のダウンロードサーバーを試しています…",
    "{name} answers on the network ({ip}), but its scanner driver is not installed.":
        "{name} はネットワーク上で応答しています ({ip}) が、スキャナードライバーがインストールされていません。",
    "Scanner driver missing":
        "スキャナードライバーがありません",
    "{name} was found on the network ({ip}), but its scanner driver is not installed, so the app cannot scan with it.\n\nInstall the official {label} now? It is downloaded and installed automatically (a few minutes; Windows may ask for permission).":
        "{name} がネットワーク上で見つかりました ({ip}) が、スキャナードライバーがインストールされていないため、このアプリではスキャンできません。\n\n公式の {label} を今すぐインストールしますか？ 自動でダウンロードしてインストールします（数分。Windows が許可を求める場合があります）。",
    "Phone":
        "スマホ",
    "Send to your phone or receive photos from it, on the same Wi-Fi (LocalSend app or QR code)":
        "同じ Wi-Fi でスマートフォンに送信、またはスマートフォンから写真を受信（LocalSend アプリまたは QR コード）",
    "Send scans to your phone and receive photos from it, on the same Wi-Fi.":
        "同じ Wi-Fi で、スキャンをスマートフォンに送信し、スマートフォンから写真を受信します。",
    "Receiving from the phone":
        "スマートフォンからの受信",
    "Keep receiving on while the app is open":
        "アプリを開いている間は常に受信をオンにする",
    "When this is off, receiving opens for {minutes} minutes each time you press Phone.":
        "オフの場合、「スマホ」を押すたびに {minutes} 分間だけ受信が開きます。",
    "Phone photos":
        "スマートフォンの写真",
    "Just save them in the scans folder":
        "スキャンフォルダーにそのまま保存",
    "Make a PDF, like a scan (OCR, Word)":
        "スキャンと同じように PDF にする（OCR、Word）",
    "Name on the phone":
        "スマートフォンに表示される名前",
    "How it works":
        "使い方",
    "1. Phone and computer on the same Wi-Fi.\n2. Install the free LocalSend app on the phone, or simply scan the QR code.\n3. Press Phone, next to Preview, choose the phone and Send.\n4. To send from the phone: in LocalSend choose “{name}”, or use the QR page.":
        "1. スマートフォンとコンピューターを同じ Wi-Fi に接続します。\n2. スマートフォンに無料の LocalSend アプリを入れるか、QR コードを読み取るだけです。\n3. 「プレビュー」の隣の「スマホ」を押し、スマートフォンを選んで「送信」。\n4. スマートフォンから送るには: LocalSend で「{name}」を選ぶか、QR コードのページを使います。",
    "Get LocalSend":
        "LocalSend を入手",
    "Idle · making a PDF from phone photos":
        "待機中 · スマートフォンの写真から PDF を作成中",
    "✓ Made {file} from {count} phone photo(s)":
        "✓ スマートフォンの写真 {count} 枚から {file} を作成しました",
    "Windows may now ask whether {app} can use the network.\n\nTick “Private networks” and click Allow, so your phone can reach this computer.":
        "{app} がネットワークを使用してよいか、Windows が確認する場合があります。\n\n「プライベート ネットワーク」にチェックを入れて「許可」をクリックすると、スマートフォンからこのコンピューターに接続できます。",
    "The phone connection could not start. Another program may be using the network ports {ports}.":
        "スマートフォンとの接続を開始できませんでした。別のプログラムがネットワークポート {ports} を使用している可能性があります。",
    "Receiving is off. Press Phone to open it again.":
        "受信はオフです。もう一度開くには「スマホ」を押してください。",
    "Receiving is on: the phone can send files to “{name}”.":
        "受信中: スマートフォンから「{name}」にファイルを送れます。",
    "Receiving is on for {time}: the phone can send files to “{name}”.":
        "残り {time} 受信中: スマートフォンから「{name}」にファイルを送れます。",
    "… and {count} more":
        "… ほか {count} 件",
    "Files from a phone":
        "スマートフォンからのファイル",
    "“{sender}” wants to send {count} file(s):":
        "「{sender}」が {count} 個のファイルを送ろうとしています:",
    "They will be saved in {folder}.":
        "{folder} に保存されます。",
    "Accept":
        "受け入れる",
    "Decline":
        "拒否",
    "Receiving files from {sender}…":
        "{sender} からファイルを受信中…",
    "✓ Received {count} file(s) from {sender} in {folder}":
        "✓ {sender} から {count} 個のファイルを {folder} に受信しました",
    "The photos were saved as they are, because a scan is running.":
        "スキャン中のため、写真はそのまま保存されました。",
    "Making a PDF from {count} phone photo(s)…":
        "スマートフォンの写真 {count} 枚から PDF を作成中…",
    "This link has expired. Scan the QR code again.":
        "このリンクは期限切れです。もう一度 QR コードを読み取ってください。",
    "No scan yet. Scan something first, then reload this page.":
        "まだスキャンがありません。先にスキャンしてから、このページを再読み込みしてください。",
    "Waiting for the computer to accept…":
        "コンピューターが受け入れるのを待っています…",
    "The computer declined the files.":
        "コンピューターがファイルを拒否しました。",
    "The computer is receiving other files. Try again in a moment.":
        "コンピューターは別のファイルを受信中です。少ししてからもう一度お試しください。",
    "Sending failed. Check that the phone is on the same Wi-Fi and try again.":
        "送信に失敗しました。スマートフォンが同じ Wi-Fi にあることを確認して、もう一度お試しください。",
    "Sending {name}…":
        "{name} を送信中…",
    "✓ Sent! The files are on the computer.":
        "✓ 送信しました！ ファイルはコンピューターにあります。",
    "1 · Get the scan on this phone":
        "1 · このスマートフォンにスキャンを取り込む",
    "Reload":
        "再読み込み",
    "2 · Send photos or files to the computer":
        "2 · 写真やファイルをコンピューターに送る",
    "Take a photo or choose files":
        "写真を撮る、またはファイルを選ぶ",
    "Send to your phone":
        "スマートフォンに送信",
    "Phone and computer must be on the same Wi-Fi.":
        "スマートフォンとコンピューターは同じ Wi-Fi に接続してください。",
    "Choose other files…":
        "ほかのファイルを選ぶ…",
    "Phones with LocalSend":
        "LocalSend のあるスマートフォン",
    "Send":
        "送信",
    "No LocalSend? Scan this":
        "LocalSend がない場合はこちらを読み取り",
    "Point the phone camera at the code. A page opens where you can download the scan and send photos to this computer.":
        "スマートフォンのカメラをコードに向けてください。スキャンのダウンロードや、このコンピューターへの写真送信ができるページが開きます。",
    "QR code not available.":
        "QR コードは利用できません。",
    "To send: {names}  ({size})":
        "送信するファイル: {names}  ({size})",
    "Nothing to send yet. Scan first, or choose files.":
        "まだ送るものがありません。先にスキャンするか、ファイルを選んでください。",
    "Choose files for the phone":
        "スマートフォンに送るファイルを選ぶ",
    "Looking for phones… Open LocalSend on the phone.":
        "スマートフォンを探しています… スマートフォンで LocalSend を開いてください。",
    "No phone found.\n1. Is the phone on the same Wi-Fi?\n2. Open the LocalSend app on the phone (free, Play Store / App Store).\n3. Or simply scan the QR code on the right.":
        "スマートフォンが見つかりません。\n1. スマートフォンは同じ Wi-Fi に接続していますか？\n2. スマートフォンで LocalSend アプリを開いてください（無料、Play ストア / App Store）。\n3. または右側の QR コードを読み取るだけでも OK です。",
    "Waiting for {phone} to accept… Tap Accept on the phone.":
        "{phone} が受け入れるのを待っています… スマートフォンで「受け入れる」をタップしてください。",
    "Sending to {phone}… {value}%":
        "{phone} に送信中… {value}%",
    "{phone} declined the files.":
        "{phone} がファイルを拒否しました。",
    "{phone} is busy with another transfer. Try again in a moment.":
        "{phone} は別の転送中です。少ししてからもう一度お試しください。",
    "{phone} asks for a PIN. Turn off the PIN in LocalSend settings on the phone.":
        "{phone} が PIN を求めています。スマートフォンの LocalSend 設定で PIN をオフにしてください。",
    "Could not reach {phone}. Is LocalSend open and on the same Wi-Fi?":
        "{phone} に接続できません。LocalSend が開いていて、同じ Wi-Fi にありますか？",
    "Sending cancelled.":
        "送信をキャンセルしました。",
    "✓ Sent {count} file(s) to {phone}.":
        "✓ {phone} に {count} 個のファイルを送信しました。",
    "Sending failed. {error}":
        "送信に失敗しました。{error}",
    "Also save an editable document (text from OCR)":
        "編集可能な文書も保存する（OCR のテキスト）",
    "Document":
        "文書",
    "Word (.docx) · Microsoft Word":
        "Word (.docx) · Microsoft Word",
    "OpenDocument (.odt) · LibreOffice on Mac / Linux":
        "OpenDocument (.odt) · Mac / Linux の LibreOffice",
    "Word export needs python-docx. Close and reopen the app to install it.":
        "Word への書き出しには python-docx が必要です。アプリを閉じて開き直すとインストールされます。",
    "What to save, the paper and where the files go.":
        "保存する内容、用紙、ファイルの保存先。",
    "Recognise text in your scans and translate it.":
        "スキャンの文字を認識して翻訳します。",
    "Language, appearance and updates.":
        "言語、外観、アップデート。",
    "Output":
        "出力",
    "Paper":
        "用紙",
    "Saving":
        "保存",
    "Text recognition (OCR)":
        "文字認識 (OCR)",
    "Appearance":
        "外観",
    "Reset":
        "リセット",
    "Settings":
        "設定",
    "Help":
        "ヘルプ",
    "Ready":
        "準備完了",
    "Idle":
        "待機中",
    "Scan":
        "スキャン",
    "Preview":
        "プレビュー",
    "Text":
        "テキスト",
    "Open last":
        "最後のファイル",
    "Open folder":
        "フォルダーを開く",
    "Cancel":
        "キャンセル",
    "Stop search":
        "検索を停止",
    "Search again":
        "再検索",
    "Change…":
        "変更…",
    "Starting…":
        "起動中…",
    "Looking for scanners…":
        "スキャナーを検索中…",
    "Checking every driver at the same time.":
        "すべてのドライバーを同時に確認しています。",
    "Connected to {name}":
        "{name} に接続しました",
    "via {driver}":
        "{driver} 経由",
    "{brand} at {ip}":
        "{brand} ({ip})",
    "{count} more in Settings":
        "ほか {count} 台は設定で",
    "No scanner connected":
        "スキャナーが接続されていません",
    "Turn the scanner on, check the USB cable or Wi-Fi, then click Search again.":
        "スキャナーの電源を入れ、USB ケーブルまたは Wi-Fi を確認してから「再検索」をクリックしてください。",
    "saves to {folder}":
        "{folder} に保存",
    "asks for a file name":
        "ファイル名を確認",
    "OCR":
        "OCR",
    "OCR off":
        "OCR オフ",
    "translate → {lang}":
        "翻訳 → {lang}",
    "Scan and save in the format chosen in Settings (Ctrl+S)":
        "設定で選んだ形式でスキャンして保存 (Ctrl+S)",
    "Quick low-resolution look at the flatbed (Ctrl+P)":
        "原稿台を低解像度ですばやく確認 (Ctrl+P)",
    "Recognised text and translation of the last scan (Ctrl+T)":
        "最後のスキャンの認識テキストと翻訳 (Ctrl+T)",
    "Open the last scanned file":
        "最後にスキャンしたファイルを開く",
    "Open the folder with your scans":
        "スキャンの保存フォルダーを開く",
    "Stop the scan or search (Esc)":
        "スキャンまたは検索を停止 (Esc)",
    "Look for scanners again (F5)":
        "スキャナーを再検索 (F5)",
    "Choose another scanner or change scan settings":
        "別のスキャナーを選ぶ、またはスキャン設定を変更",
    "Scanner, scanning, text and appearance settings (Ctrl+,)":
        "スキャナー、スキャン、テキスト、外観の設定 (Ctrl+,)",
    "Quick guide":
        "クイックガイド",
    "Check for updates…":
        "アップデートを確認…",
    "Project page on GitHub":
        "GitHub のプロジェクトページ",
    "About {app}":
        "{app} について",
    "Update to {version}…":
        "{version} にアップデート…",
    "In use · scanning on this PC":
        "使用中 · この PC でスキャン中",
    "In use by {who}":
        "使用中: {who}",
    "{user} on {host}":
        "{host} の {user}",
    "Started at {time}. Wait until the light turns green.":
        "{time} に開始。ランプが緑になるまでお待ちください。",
    "In use · scanner is busy":
        "使用中 · スキャナーが動作中",
    "The scanner reports that it is scanning right now.":
        "スキャナーは現在スキャン中です。",
    "Idle · searching…":
        "待機中 · 検索中…",
    "Idle · no scanner":
        "待機中 · スキャナーなし",
    "No scanner is connected yet.":
        "まだスキャナーが接続されていません。",
    "Idle · scanner on standby":
        "待機中 · スキャナーはスタンバイ",
    "The scanner reports that it is stopped or offline.":
        "スキャナーは停止中またはオフラインです。",
    "The scanner is free. You can scan.":
        "スキャナーは空いています。スキャンできます。",
    "Idle · installing OCR…":
        "待機中 · OCR をインストール中…",
    "The scanner is free now. You can scan.":
        "スキャナーが空きました。スキャンできます。",
    "Scanner in use":
        "スキャナー使用中",
    "The scanner is in use right now.\n\n{text}.\n{tip}\n\nPlease wait until the light at the top turns green, then try again.\nThis app will beep when the scanner is free.":
        "スキャナーは現在使用中です。\n\n{text}。\n{tip}\n\n上部のランプが緑になるまで待ってから、もう一度お試しください。\nスキャナーが空くとアプリが音でお知らせします。",
    "Scanner in use: {text}. Wait for the green light.":
        "スキャナー使用中: {text}。緑のランプをお待ちください。",
    "Scanner":
        "スキャナー",
    "Scanning":
        "スキャン",
    "Text & translation":
        "テキストと翻訳",
    "General":
        "一般",
    "Done":
        "完了",
    "Driver":
        "ドライバー",
    "Model":
        "モデル",
    "Network":
        "ネットワーク",
    "Auto (all drivers)":
        "自動（すべてのドライバー）",
    "No scanner found yet":
        "まだスキャナーが見つかりません",
    "Refresh":
        "更新",
    "Driver setup":
        "ドライバーのセットアップ",
    "Find on network":
        "ネットワークで検索",
    "Web panel":
        "Web パネル",
    "Find your model’s driver":
        "お使いのモデルのドライバーを探す",
    "No network reply yet":
        "まだネットワークから応答がありません",
    "Everything here is found automatically. Change it only if the wrong scanner is chosen.":
        "ここはすべて自動で検出されます。間違ったスキャナーが選ばれた場合のみ変更してください。",
    "Save as":
        "保存形式",
    "one PDF with every page":
        "全ページを 1 つの PDF に",
    "one JPG image per page":
        "1 ページごとに 1 枚の JPG 画像",
    "the PDF and the JPG images from one scan":
        "1 回のスキャンから PDF と JPG 画像の両方",
    "Paper source":
        "給紙方法",
    "Auto · feeder if loaded, else flatbed":
        "自動 · 用紙があれば ADF、なければ原稿台",
    "Flatbed (glass)":
        "原稿台（フラットベッド）",
    "Document feeder":
        "ADF（自動原稿送り装置）",
    "Document feeder · both sides":
        "ADF · 両面",
    "Paper size":
        "用紙サイズ",
    "Resolution":
        "解像度",
    "150 dpi · fast, small file":
        "150 dpi · 高速、小さいファイル",
    "300 dpi · recommended":
        "300 dpi · 推奨",
    "600 dpi · fine detail":
        "600 dpi · 高精細",
    "Colour":
        "カラー",
    "Greyscale":
        "グレースケール",
    "Black and white":
        "白黒",
    "Save to":
        "保存先",
    "Browse…":
        "参照…",
    "Ask for a file name every time":
        "毎回ファイル名を確認する",
    "Open the file after scanning":
        "スキャン後にファイルを開く",
    "Auto source":
        "自動給紙",
    "Flatbed":
        "原稿台",
    "Feeder":
        "ADF",
    "Feeder · 2 sides":
        "ADF · 両面",
    "Make PDFs searchable with OCR (text recognition)":
        "OCR（文字認識）で PDF を検索可能にする",
    "OCR languages":
        "OCR の言語",
    "Auto · English + Greek + your system language":
        "自動 · 英語 + ギリシャ語 + システムの言語",
    "Choose languages":
        "言語を選ぶ",
    "Languages download automatically the first time they are used.":
        "言語は初めて使うときに自動でダウンロードされます。",
    "Also save the text as a .txt file":
        "テキストを .txt ファイルとしても保存する",
    "Translate automatically to":
        "自動で翻訳する言語",
    "Off":
        "オフ",
    "Translation service":
        "翻訳サービス",
    "Google Translate (free)":
        "Google 翻訳（無料）",
    "MyMemory (free)":
        "MyMemory（無料）",
    "LibreTranslate (your server)":
        "LibreTranslate（自分のサーバー）",
    "LibreTranslate server":
        "LibreTranslate サーバー",
    "API key (optional)":
        "API キー（任意）",
    "Free services need internet. Google falls back to MyMemory if it fails.":
        "無料サービスにはインターネットが必要です。Google が失敗した場合は MyMemory を使います。",
    "Theme":
        "テーマ",
    "Auto · follow Windows / system":
        "自動 · Windows / システムに合わせる",
    "Light":
        "ライト",
    "Dark":
        "ダーク",
    "Language":
        "言語",
    "Auto · system language":
        "自動 · システムの言語",
    "Updates":
        "アップデート",
    "Check for updates automatically":
        "アップデートを自動で確認する",
    "Check now":
        "今すぐ確認",
    "Reset everything to Auto":
        "すべて自動に戻す",
    "All settings are back to Auto.":
        "すべての設定を自動に戻しました。",
    "Restart to change the language?":
        "言語を変更するために再起動しますか？",
    "The new language is used after a restart. Restart now?":
        "新しい言語は再起動後に使われます。今すぐ再起動しますか？",
    "Save scans to":
        "スキャンの保存先",
    "Recognised text":
        "認識されたテキスト",
    "Translation":
        "翻訳",
    "Translate":
        "翻訳する",
    "From":
        "翻訳元",
    "To":
        "翻訳先",
    "Auto-detect":
        "自動検出",
    "Copy":
        "コピー",
    "Save .txt":
        ".txt を保存",
    "Close":
        "閉じる",
    "Copied.":
        "コピーしました。",
    "Detected language: {lang}":
        "検出された言語: {lang}",
    "Translating with {engine}…":
        "{engine} で翻訳中…",
    "Translated with {engine}. Detected: {lang}.":
        "{engine} で翻訳しました。検出: {lang}。",
    "Translation failed. {error}":
        "翻訳に失敗しました。{error}",
    "Saved {name}":
        "{name} を保存しました",
    "No text yet. Turn on OCR in Settings › Text & translation, then scan again.":
        "まだテキストがありません。設定 › テキストと翻訳 で OCR をオンにして、もう一度スキャンしてください。",
    "Text of {name}":
        "{name} のテキスト",
    "Looking for scanners ({drivers})…":
        "スキャナーを検索中 ({drivers})…",
    "Looking for scanners… {count} found so far.":
        "スキャナーを検索中… これまでに {count} 台見つかりました。",
    "Ready. Load the paper and click Scan.":
        "準備完了。用紙をセットして「スキャン」をクリックしてください。",
    "Search stopped. Click Search again when you are ready.":
        "検索を停止しました。準備ができたら「再検索」をクリックしてください。",
    "No scanners found. Check the cable or Wi-Fi and the installed driver (Settings › Scanner › Driver setup).":
        "スキャナーが見つかりません。ケーブルまたは Wi-Fi と、インストール済みのドライバーを確認してください（設定 › スキャナー › ドライバーのセットアップ）。",
    "The NAPS2 scanner engine was not found. Close and reopen the app to install it automatically.":
        "スキャンエンジン NAPS2 が見つかりません。アプリを閉じて開き直すと自動でインストールされます。",
    "Scanning a quick low-resolution preview…":
        "低解像度のクイックプレビューをスキャン中…",
    "Check the page placement, then scan at your chosen resolution.":
        "ページの位置を確認してから、選んだ解像度でスキャンしてください。",
    "Flatbed preview":
        "原稿台のプレビュー",
    "Back":
        "戻る",
    "Preview ready.":
        "プレビューの準備ができました。",
    "No preview was produced. Check the flatbed and scanner connection.":
        "プレビューを作成できませんでした。原稿台とスキャナーの接続を確認してください。",
    "Scanning from {where}… Keep the scanner on until the file is saved.":
        "{where}からスキャン中… ファイルが保存されるまでスキャナーの電源を切らないでください。",
    "the flatbed":
        "原稿台",
    "the document feeder":
        "ADF",
    "the document feeder (both sides)":
        "ADF（両面）",
    " Recognising text (OCR)…":
        " 文字を認識中 (OCR)…",
    "Downloading OCR languages ({langs}). One time only…":
        "OCR の言語をダウンロード中 ({langs})。初回のみ…",
    "OCR languages could not be installed ({langs}). Scanning without OCR.":
        "OCR の言語をインストールできませんでした ({langs})。OCR なしでスキャンします。",
    "Scan cancelled.":
        "スキャンをキャンセルしました。",
    "The scanner is busy. Someone else may be using it. Wait a moment, then try again.":
        "スキャナーは使用中です。ほかの人が使っている可能性があります。少し待ってから、もう一度お試しください。",
    "Windows could not reach the Canon scanner. Turn it on, make sure it is on the same Wi-Fi, and check it in Canon IJ Scan Utility, then retry.":
        "Windows が Canon スキャナーに接続できませんでした。電源を入れ、同じ Wi-Fi にあることを確認し、Canon IJ Scan Utility で確認してから再試行してください。",
    "Epson Scan 2 could not open the scanner. In Epson Scan 2 Utility, add or test its network address, then retry.":
        "Epson Scan 2 がスキャナーを開けませんでした。Epson Scan 2 Utility でネットワークアドレスを追加またはテストしてから再試行してください。",
    "Scanner operation failed. {detail}":
        "スキャナーの操作に失敗しました。{detail}",
    "No pages were scanned. Check the paper and the scanner connection.":
        "ページがスキャンされませんでした。用紙とスキャナーの接続を確認してください。",
    "Could not save the scan. {error}":
        "スキャンを保存できませんでした。{error}",
    "The scan was kept as {path}":
        "スキャンは {path} として保存されました",
    "✓ Saved {files} in {folder}":
        "✓ {files} を {folder} に保存しました",
    "{count} JPG pages":
        "JPG {count} ページ",
    "text":
        "テキスト",
    "Translating the text to {lang}…":
        "テキストを{lang}に翻訳中…",
    "✓ Translation saved: {name}":
        "✓ 翻訳を保存しました: {name}",
    "Could not start NAPS2. {error}":
        "NAPS2 を起動できませんでした。{error}",
    "Could not create {folder}. {error}\nChoose another folder in Settings › Scanning.":
        "{folder} を作成できませんでした。{error}\n設定 › スキャン で別のフォルダーを選んでください。",
    "Save scan":
        "スキャンを保存",
    "Scan in progress":
        "スキャン中",
    "A scan is running. Cancel it and close the app?":
        "スキャン中です。キャンセルしてアプリを閉じますか？",
    "JPG export needs PyMuPDF. Close and reopen the app to install it.":
        "JPG への書き出しには PyMuPDF が必要です。アプリを閉じて開き直すとインストールされます。",
    "Checking GitHub for a newer version…":
        "GitHub で新しいバージョンを確認中…",
    "Could not check for updates. {error}":
        "アップデートを確認できませんでした。{error}",
    "You have the latest version (v{version}).":
        "最新バージョンです (v{version})。",
    "Update available":
        "アップデートがあります",
    "{app} {version} is available (you have v{current}).\n\nWhat's new:\n{notes}\n\nDownload and install it now?":
        "{app} {version} が利用できます（現在は v{current}）。\n\n新機能:\n{notes}\n\n今すぐダウンロードしてインストールしますか？",
    "No release notes.":
        "リリースノートはありません。",
    "Update {version} is waiting in Help.":
        "アップデート {version} がヘルプで待っています。",
    "Finish the scan first, then install the update from Help.":
        "先にスキャンを終えてから、ヘルプからアップデートをインストールしてください。",
    "Downloading {version} from GitHub…":
        "GitHub から {version} をダウンロード中…",
    "Update failed. {error}":
        "アップデートに失敗しました。{error}",
    "macOS is running the app from a temporary read-only copy. Drag What the Scan into Applications, open it from there, then update again.":
        "macOS が一時的な読み取り専用のコピーからアプリを実行しています。What the Scan を「アプリケーション」にドラッグし、そこから開いてもう一度アップデートしてください。",
    "The app's folder can't be written to. Move the app to a folder you own (or Applications) and update again.":
        "アプリのフォルダーに書き込めません。アプリを自分のフォルダー（または「アプリケーション」）に移動して、もう一度アップデートしてください。",
    "Update failed":
        "アップデートに失敗しました",
    "{error}\n\nOpen the release page to download it by hand?":
        "{error}\n\nリリースページを開いて手動でダウンロードしますか？",
    "Updated to {version}. Restarting…":
        "{version} にアップデートしました。再起動中…",
    "Choose a model to find its driver.":
        "ドライバーを探すモデルを選んでください。",
    "Install driver":
        "ドライバーのインストール",
    "Download and install the official {label} now?\n\nWindows may ask for permission. Choose No to open the support page instead.":
        "公式の {label} を今すぐダウンロードしてインストールしますか？\n\nWindows が許可を求める場合があります。代わりにサポートページを開くには「いいえ」を選んでください。",
    "Preparing the official {label} installer…":
        "公式の {label} インストーラーを準備中…",
    "{label} installed. Looking for scanners…":
        "{label} をインストールしました。スキャナーを検索中…",
    "Driver setup failed. {error}\nThe support page is opening so you can install it by hand.":
        "ドライバーのセットアップに失敗しました。{error}\n手動でインストールできるようにサポートページを開きます。",
    "Searching the local network for scanners (Epson, Canon, HP, AirPrint)…":
        "ローカルネットワークでスキャナーを検索中（Epson、Canon、HP、AirPrint）…",
    "answered as a network (eSCL) scanner ✓":
        "ネットワークスキャナー (eSCL) として応答しました ✓",
    "This scanner has: {sources}":
        "このスキャナーの給紙: {sources}",
    "Network discovery failed. {error}":
        "ネットワーク検索に失敗しました。{error}",
    "Select your scanner's network address.":
        "スキャナーのネットワークアドレスを選んでください。",
    "No scanner replied on this local network.":
        "このローカルネットワークで応答したスキャナーはありません。",
    "answered as a Canon scanner ✓":
        "Canon スキャナーとして応答しました ✓",
    "responds on the scanner port ✓":
        "スキャナーのポートで応答しています ✓",
    "did not respond on the scanner port":
        "スキャナーのポートで応答しませんでした",
    "{brand} {ip} {state}. Scanning uses the driver chosen above.":
        "{brand} {ip} {state}。スキャンには上で選んだドライバーを使います。",
}

UI_ZH = {
    "Brother's download page is opening. The model {model} is copied: paste it in the search box (Ctrl+V). Most Brother models also scan with no driver over the network.":
        "正在打开 Brother 下载页面。型号 {model} 已复制：请粘贴到搜索框 (Ctrl+V)。大多数 Brother 型号也可以无需驱动通过网络扫描。",
    "Connect Epson Scan 2 to the scanner":
        "将 Epson Scan 2 连接到扫描仪",
    "Epson Scan 2 does not know your scanner's network address yet. This happens after the driver is (re)installed. One time only:":
        "Epson Scan 2 还不知道扫描仪的网络地址。这通常发生在（重新）安装驱动之后。只需设置一次：",
    "1. Click “Open Epson Scan 2 Utility” below.\n2. At the top, in “Scanner”, choose “Settings”.\n3. Click “Add”, choose “Enter address”, press Ctrl+V (the address {ip} is already copied) and click OK.\n4. Click OK, close the utility and press Scan again.":
        "1. 点击下方的“打开 Epson Scan 2 Utility”。\n2. 在顶部的“Scanner”中选择“Settings”。\n3. 点击“Add”，选择“Enter address”，按 Ctrl+V（地址 {ip} 已复制），然后点击 OK。\n4. 点击 OK，关闭该工具，再次按“扫描”。",
    "Open Epson Scan 2 Utility":
        "打开 Epson Scan 2 Utility",
    "Could not open Epson Scan 2 Utility. {error}":
        "无法打开 Epson Scan 2 Utility。{error}",
    "{phone} (browser)": "{phone}（浏览器）",
    "AirDrop":
        "隔空投送",
    "Send with AirDrop to an iPhone, iPad or Mac nearby":
        "通过隔空投送发送到附近的 iPhone、iPad 或 Mac",
    "AirDrop is open: choose the iPhone or Mac.":
        "隔空投送已打开：请选择 iPhone 或 Mac。",
    "AirDrop is not available on this Mac. Turn on Wi-Fi and Bluetooth.":
        "此 Mac 无法使用隔空投送。请打开 Wi-Fi 和蓝牙。",
    "So that your phone can send to this computer, Windows Firewall must let it in.\n\nAllow it now? Windows asks for permission once (only phones on your own network, only the ports of {app}).":
        "要让手机能向这台电脑发送文件，需要 Windows 防火墙允许。\n\n现在允许吗？Windows 只会请求一次权限（仅限你自己网络中的手机，仅限 {app} 的端口）。",
    "Waiting for Windows permission (firewall)…":
        "正在等待 Windows 授权（防火墙）…",
    "✓ Windows Firewall lets your phone in now.":
        "✓ Windows 防火墙现在允许你的手机连接。",
    "Windows Firewall was not changed, so the phone may not be able to send to this computer.":
        "Windows 防火墙未更改，手机可能无法向这台电脑发送文件。",
    "LocalSend for the phone":
        "手机版 LocalSend",
    "Trying Epson's other download server…":
        "正在尝试 Epson 的另一个下载服务器…",
    "{name} answers on the network ({ip}), but its scanner driver is not installed.":
        "{name} 在网络上有响应（{ip}），但未安装其扫描仪驱动。",
    "Scanner driver missing":
        "缺少扫描仪驱动",
    "{name} was found on the network ({ip}), but its scanner driver is not installed, so the app cannot scan with it.\n\nInstall the official {label} now? It is downloaded and installed automatically (a few minutes; Windows may ask for permission).":
        "在网络上找到了 {name}（{ip}），但未安装其扫描仪驱动，因此本应用无法用它扫描。\n\n现在安装官方 {label} 吗？将自动下载并安装（几分钟；Windows 可能会请求权限）。",
    "Phone":
        "手机",
    "Send to your phone or receive photos from it, on the same Wi-Fi (LocalSend app or QR code)":
        "在同一 Wi-Fi 下发送到手机或从手机接收照片（LocalSend 应用或二维码）",
    "Send scans to your phone and receive photos from it, on the same Wi-Fi.":
        "在同一 Wi-Fi 下把扫描件发送到手机，并从手机接收照片。",
    "Receiving from the phone":
        "从手机接收",
    "Keep receiving on while the app is open":
        "应用打开期间始终开启接收",
    "When this is off, receiving opens for {minutes} minutes each time you press Phone.":
        "关闭时，每次按“手机”都会开启接收 {minutes} 分钟。",
    "Phone photos":
        "手机照片",
    "Just save them in the scans folder":
        "仅保存到扫描文件夹",
    "Make a PDF, like a scan (OCR, Word)":
        "像扫描一样生成 PDF（OCR、Word）",
    "Name on the phone":
        "手机上显示的名称",
    "How it works":
        "使用方法",
    "1. Phone and computer on the same Wi-Fi.\n2. Install the free LocalSend app on the phone, or simply scan the QR code.\n3. Press Phone, next to Preview, choose the phone and Send.\n4. To send from the phone: in LocalSend choose “{name}”, or use the QR page.":
        "1. 手机和电脑连接同一 Wi-Fi。\n2. 在手机上安装免费的 LocalSend 应用，或直接扫描二维码。\n3. 按“预览”旁边的“手机”，选择手机后点“发送”。\n4. 从手机发送：在 LocalSend 中选择“{name}”，或使用二维码页面。",
    "Get LocalSend":
        "获取 LocalSend",
    "Idle · making a PDF from phone photos":
        "空闲 · 正在用手机照片生成 PDF",
    "✓ Made {file} from {count} phone photo(s)":
        "✓ 已用 {count} 张手机照片生成 {file}",
    "Windows may now ask whether {app} can use the network.\n\nTick “Private networks” and click Allow, so your phone can reach this computer.":
        "Windows 现在可能会询问 {app} 是否可以使用网络。\n\n勾选“专用网络”并点击“允许”，手机才能连接到这台电脑。",
    "The phone connection could not start. Another program may be using the network ports {ports}.":
        "无法启动手机连接。可能有其他程序正在使用网络端口 {ports}。",
    "Receiving is off. Press Phone to open it again.":
        "接收已关闭。按“手机”可重新开启。",
    "Receiving is on: the phone can send files to “{name}”.":
        "接收已开启：手机可以向“{name}”发送文件。",
    "Receiving is on for {time}: the phone can send files to “{name}”.":
        "接收开启中，剩余 {time}：手机可以向“{name}”发送文件。",
    "… and {count} more":
        "… 另外 {count} 个",
    "Files from a phone":
        "来自手机的文件",
    "“{sender}” wants to send {count} file(s):":
        "“{sender}”想发送 {count} 个文件：",
    "They will be saved in {folder}.":
        "文件将保存到 {folder}。",
    "Accept":
        "接受",
    "Decline":
        "拒绝",
    "Receiving files from {sender}…":
        "正在接收来自 {sender} 的文件…",
    "✓ Received {count} file(s) from {sender} in {folder}":
        "✓ 已从 {sender} 接收 {count} 个文件到 {folder}",
    "The photos were saved as they are, because a scan is running.":
        "由于正在扫描，照片已按原样保存。",
    "Making a PDF from {count} phone photo(s)…":
        "正在用 {count} 张手机照片生成 PDF…",
    "This link has expired. Scan the QR code again.":
        "此链接已过期。请重新扫描二维码。",
    "No scan yet. Scan something first, then reload this page.":
        "还没有扫描件。请先扫描，然后刷新此页面。",
    "Waiting for the computer to accept…":
        "正在等待电脑接受…",
    "The computer declined the files.":
        "电脑拒绝了这些文件。",
    "The computer is receiving other files. Try again in a moment.":
        "电脑正在接收其他文件。请稍后再试。",
    "Sending failed. Check that the phone is on the same Wi-Fi and try again.":
        "发送失败。请确认手机连接的是同一 Wi-Fi，然后重试。",
    "Sending {name}…":
        "正在发送 {name}…",
    "✓ Sent! The files are on the computer.":
        "✓ 已发送！文件已在电脑上。",
    "1 · Get the scan on this phone":
        "1 · 在这部手机上获取扫描件",
    "Reload":
        "刷新",
    "2 · Send photos or files to the computer":
        "2 · 向电脑发送照片或文件",
    "Take a photo or choose files":
        "拍照或选择文件",
    "Send to your phone":
        "发送到手机",
    "Phone and computer must be on the same Wi-Fi.":
        "手机和电脑必须连接同一 Wi-Fi。",
    "Choose other files…":
        "选择其他文件…",
    "Phones with LocalSend":
        "装有 LocalSend 的手机",
    "Send":
        "发送",
    "No LocalSend? Scan this":
        "没有 LocalSend？扫描这里",
    "Point the phone camera at the code. A page opens where you can download the scan and send photos to this computer.":
        "将手机摄像头对准二维码，会打开一个页面，可以下载扫描件并向这台电脑发送照片。",
    "QR code not available.":
        "二维码不可用。",
    "To send: {names}  ({size})":
        "待发送：{names}  （{size}）",
    "Nothing to send yet. Scan first, or choose files.":
        "暂无可发送内容。请先扫描或选择文件。",
    "Choose files for the phone":
        "选择要发送到手机的文件",
    "Looking for phones… Open LocalSend on the phone.":
        "正在查找手机… 请在手机上打开 LocalSend。",
    "No phone found.\n1. Is the phone on the same Wi-Fi?\n2. Open the LocalSend app on the phone (free, Play Store / App Store).\n3. Or simply scan the QR code on the right.":
        "未找到手机。\n1. 手机是否连接同一 Wi-Fi？\n2. 在手机上打开 LocalSend 应用（免费，Play 商店 / App Store）。\n3. 或者直接扫描右侧的二维码。",
    "Waiting for {phone} to accept… Tap Accept on the phone.":
        "正在等待 {phone} 接受… 请在手机上点“接受”。",
    "Sending to {phone}… {value}%":
        "正在发送到 {phone}… {value}%",
    "{phone} declined the files.":
        "{phone} 拒绝了这些文件。",
    "{phone} is busy with another transfer. Try again in a moment.":
        "{phone} 正在进行其他传输。请稍后再试。",
    "{phone} asks for a PIN. Turn off the PIN in LocalSend settings on the phone.":
        "{phone} 要求输入 PIN。请在手机的 LocalSend 设置中关闭 PIN。",
    "Could not reach {phone}. Is LocalSend open and on the same Wi-Fi?":
        "无法连接 {phone}。LocalSend 是否已打开并连接同一 Wi-Fi？",
    "Sending cancelled.":
        "已取消发送。",
    "✓ Sent {count} file(s) to {phone}.":
        "✓ 已向 {phone} 发送 {count} 个文件。",
    "Sending failed. {error}":
        "发送失败。{error}",
    "Also save an editable document (text from OCR)":
        "同时保存可编辑文档（来自 OCR 的文字）",
    "Document":
        "文档",
    "Word (.docx) · Microsoft Word":
        "Word (.docx) · Microsoft Word",
    "OpenDocument (.odt) · LibreOffice on Mac / Linux":
        "OpenDocument (.odt) · Mac / Linux 上的 LibreOffice",
    "Word export needs python-docx. Close and reopen the app to install it.":
        "导出 Word 需要 python-docx。关闭并重新打开应用即可自动安装。",
    "What to save, the paper and where the files go.":
        "保存什么、纸张以及文件保存位置。",
    "Recognise text in your scans and translate it.":
        "识别扫描件中的文字并翻译。",
    "Language, appearance and updates.":
        "语言、外观和更新。",
    "Output":
        "输出",
    "Paper":
        "纸张",
    "Saving":
        "保存",
    "Text recognition (OCR)":
        "文字识别 (OCR)",
    "Appearance":
        "外观",
    "Reset":
        "重置",
    "Settings":
        "设置",
    "Help":
        "帮助",
    "Ready":
        "就绪",
    "Idle":
        "空闲",
    "Scan":
        "扫描",
    "Preview":
        "预览",
    "Text":
        "文字",
    "Open last":
        "打开最近",
    "Open folder":
        "打开文件夹",
    "Cancel":
        "取消",
    "Stop search":
        "停止搜索",
    "Search again":
        "重新搜索",
    "Change…":
        "更改…",
    "Starting…":
        "正在启动…",
    "Looking for scanners…":
        "正在查找扫描仪…",
    "Checking every driver at the same time.":
        "正在同时检查所有驱动。",
    "Connected to {name}":
        "已连接到 {name}",
    "via {driver}":
        "通过 {driver}",
    "{brand} at {ip}":
        "{brand}，地址 {ip}",
    "{count} more in Settings":
        "设置中还有 {count} 台",
    "No scanner connected":
        "未连接扫描仪",
    "Turn the scanner on, check the USB cable or Wi-Fi, then click Search again.":
        "请打开扫描仪，检查 USB 线或 Wi-Fi，然后点击“重新搜索”。",
    "saves to {folder}":
        "保存到 {folder}",
    "asks for a file name":
        "询问文件名",
    "OCR":
        "OCR",
    "OCR off":
        "OCR 关闭",
    "translate → {lang}":
        "翻译 → {lang}",
    "Scan and save in the format chosen in Settings (Ctrl+S)":
        "扫描并按“设置”中选择的格式保存 (Ctrl+S)",
    "Quick low-resolution look at the flatbed (Ctrl+P)":
        "以低分辨率快速预览扫描平板 (Ctrl+P)",
    "Recognised text and translation of the last scan (Ctrl+T)":
        "最近一次扫描的识别文字和翻译 (Ctrl+T)",
    "Open the last scanned file":
        "打开最近扫描的文件",
    "Open the folder with your scans":
        "打开扫描件所在文件夹",
    "Stop the scan or search (Esc)":
        "停止扫描或搜索 (Esc)",
    "Look for scanners again (F5)":
        "重新查找扫描仪 (F5)",
    "Choose another scanner or change scan settings":
        "选择其他扫描仪或更改扫描设置",
    "Scanner, scanning, text and appearance settings (Ctrl+,)":
        "扫描仪、扫描、文字和外观设置 (Ctrl+,)",
    "Quick guide":
        "快速指南",
    "Check for updates…":
        "检查更新…",
    "Project page on GitHub":
        "GitHub 项目页面",
    "About {app}":
        "关于 {app}",
    "Update to {version}…":
        "更新到 {version}…",
    "In use · scanning on this PC":
        "使用中 · 正在本机扫描",
    "In use by {who}":
        "{who} 正在使用",
    "{user} on {host}":
        "{host} 上的 {user}",
    "Started at {time}. Wait until the light turns green.":
        "开始于 {time}。请等待指示灯变绿。",
    "In use · scanner is busy":
        "使用中 · 扫描仪忙碌",
    "The scanner reports that it is scanning right now.":
        "扫描仪报告正在扫描。",
    "Idle · searching…":
        "空闲 · 正在搜索…",
    "Idle · no scanner":
        "空闲 · 无扫描仪",
    "No scanner is connected yet.":
        "尚未连接扫描仪。",
    "Idle · scanner on standby":
        "空闲 · 扫描仪待机中",
    "The scanner reports that it is stopped or offline.":
        "扫描仪报告已停止或离线。",
    "The scanner is free. You can scan.":
        "扫描仪空闲，可以扫描。",
    "Idle · installing OCR…":
        "空闲 · 正在安装 OCR…",
    "The scanner is free now. You can scan.":
        "扫描仪现在空闲了，可以扫描。",
    "Scanner in use":
        "扫描仪使用中",
    "The scanner is in use right now.\n\n{text}.\n{tip}\n\nPlease wait until the light at the top turns green, then try again.\nThis app will beep when the scanner is free.":
        "扫描仪正在被使用。\n\n{text}。\n{tip}\n\n请等待顶部指示灯变绿后再试。\n扫描仪空闲时应用会发出提示音。",
    "Scanner in use: {text}. Wait for the green light.":
        "扫描仪使用中：{text}。请等待绿灯。",
    "Scanner":
        "扫描仪",
    "Scanning":
        "扫描",
    "Text & translation":
        "文字与翻译",
    "General":
        "常规",
    "Done":
        "完成",
    "Driver":
        "驱动",
    "Model":
        "型号",
    "Network":
        "网络",
    "Auto (all drivers)":
        "自动（所有驱动）",
    "No scanner found yet":
        "尚未找到扫描仪",
    "Refresh":
        "刷新",
    "Driver setup":
        "安装驱动",
    "Find on network":
        "在网络上查找",
    "Web panel":
        "网页面板",
    "Find your model’s driver":
        "查找你的型号的驱动",
    "No network reply yet":
        "网络尚无响应",
    "Everything here is found automatically. Change it only if the wrong scanner is chosen.":
        "这里的一切都会自动检测。只有选错扫描仪时才需要更改。",
    "Save as":
        "保存为",
    "one PDF with every page":
        "一个包含所有页面的 PDF",
    "one JPG image per page":
        "每页一张 JPG 图片",
    "the PDF and the JPG images from one scan":
        "同一次扫描的 PDF 和 JPG 图片",
    "Paper source":
        "纸张来源",
    "Auto · feeder if loaded, else flatbed":
        "自动 · 进纸器有纸时用进纸器，否则用平板",
    "Flatbed (glass)":
        "平板（玻璃）",
    "Document feeder":
        "自动进纸器",
    "Document feeder · both sides":
        "自动进纸器 · 双面",
    "Paper size":
        "纸张大小",
    "Resolution":
        "分辨率",
    "150 dpi · fast, small file":
        "150 dpi · 快速，文件小",
    "300 dpi · recommended":
        "300 dpi · 推荐",
    "600 dpi · fine detail":
        "600 dpi · 精细细节",
    "Colour":
        "彩色",
    "Greyscale":
        "灰度",
    "Black and white":
        "黑白",
    "Save to":
        "保存到",
    "Browse…":
        "浏览…",
    "Ask for a file name every time":
        "每次都询问文件名",
    "Open the file after scanning":
        "扫描后打开文件",
    "Auto source":
        "自动来源",
    "Flatbed":
        "平板",
    "Feeder":
        "进纸器",
    "Feeder · 2 sides":
        "进纸器 · 双面",
    "Make PDFs searchable with OCR (text recognition)":
        "用 OCR（文字识别）使 PDF 可搜索",
    "OCR languages":
        "OCR 语言",
    "Auto · English + Greek + your system language":
        "自动 · 英语 + 希腊语 + 系统语言",
    "Choose languages":
        "选择语言",
    "Languages download automatically the first time they are used.":
        "语言会在首次使用时自动下载。",
    "Also save the text as a .txt file":
        "同时将文字保存为 .txt 文件",
    "Translate automatically to":
        "自动翻译为",
    "Off":
        "关闭",
    "Translation service":
        "翻译服务",
    "Google Translate (free)":
        "Google 翻译（免费）",
    "MyMemory (free)":
        "MyMemory（免费）",
    "LibreTranslate (your server)":
        "LibreTranslate（你的服务器）",
    "LibreTranslate server":
        "LibreTranslate 服务器",
    "API key (optional)":
        "API 密钥（可选）",
    "Free services need internet. Google falls back to MyMemory if it fails.":
        "免费服务需要联网。Google 失败时会改用 MyMemory。",
    "Theme":
        "主题",
    "Auto · follow Windows / system":
        "自动 · 跟随 Windows / 系统",
    "Light":
        "浅色",
    "Dark":
        "深色",
    "Language":
        "语言",
    "Auto · system language":
        "自动 · 系统语言",
    "Updates":
        "更新",
    "Check for updates automatically":
        "自动检查更新",
    "Check now":
        "立即检查",
    "Reset everything to Auto":
        "全部恢复为自动",
    "All settings are back to Auto.":
        "所有设置已恢复为自动。",
    "Restart to change the language?":
        "重新启动以更改语言？",
    "The new language is used after a restart. Restart now?":
        "新语言将在重新启动后生效。现在重新启动吗？",
    "Save scans to":
        "扫描件保存到",
    "Recognised text":
        "识别的文字",
    "Translation":
        "翻译",
    "Translate":
        "翻译",
    "From":
        "从",
    "To":
        "到",
    "Auto-detect":
        "自动检测",
    "Copy":
        "复制",
    "Save .txt":
        "保存 .txt",
    "Close":
        "关闭",
    "Copied.":
        "已复制。",
    "Detected language: {lang}":
        "检测到的语言：{lang}",
    "Translating with {engine}…":
        "正在使用 {engine} 翻译…",
    "Translated with {engine}. Detected: {lang}.":
        "已使用 {engine} 翻译。检测到：{lang}。",
    "Translation failed. {error}":
        "翻译失败。{error}",
    "Saved {name}":
        "已保存 {name}",
    "No text yet. Turn on OCR in Settings › Text & translation, then scan again.":
        "还没有文字。请在 设置 › 文字与翻译 中开启 OCR，然后重新扫描。",
    "Text of {name}":
        "{name} 的文字",
    "Looking for scanners ({drivers})…":
        "正在查找扫描仪（{drivers}）…",
    "Looking for scanners… {count} found so far.":
        "正在查找扫描仪… 已找到 {count} 台。",
    "Ready. Load the paper and click Scan.":
        "就绪。放好纸张后点击“扫描”。",
    "Search stopped. Click Search again when you are ready.":
        "已停止搜索。准备好后点击“重新搜索”。",
    "No scanners found. Check the cable or Wi-Fi and the installed driver (Settings › Scanner › Driver setup).":
        "未找到扫描仪。请检查线缆或 Wi-Fi 以及已安装的驱动（设置 › 扫描仪 › 安装驱动）。",
    "The NAPS2 scanner engine was not found. Close and reopen the app to install it automatically.":
        "未找到扫描引擎 NAPS2。关闭并重新打开应用即可自动安装。",
    "Scanning a quick low-resolution preview…":
        "正在扫描低分辨率快速预览…",
    "Check the page placement, then scan at your chosen resolution.":
        "检查页面位置，然后以所选分辨率扫描。",
    "Flatbed preview":
        "平板预览",
    "Back":
        "返回",
    "Preview ready.":
        "预览已就绪。",
    "No preview was produced. Check the flatbed and scanner connection.":
        "未生成预览。请检查平板和扫描仪连接。",
    "Scanning from {where}… Keep the scanner on until the file is saved.":
        "正在从{where}扫描… 文件保存前请勿关闭扫描仪。",
    "the flatbed":
        "平板",
    "the document feeder":
        "自动进纸器",
    "the document feeder (both sides)":
        "自动进纸器（双面）",
    " Recognising text (OCR)…":
        " 正在识别文字 (OCR)…",
    "Downloading OCR languages ({langs}). One time only…":
        "正在下载 OCR 语言（{langs}）。仅需一次…",
    "OCR languages could not be installed ({langs}). Scanning without OCR.":
        "无法安装 OCR 语言（{langs}）。将不使用 OCR 进行扫描。",
    "Scan cancelled.":
        "已取消扫描。",
    "The scanner is busy. Someone else may be using it. Wait a moment, then try again.":
        "扫描仪忙。可能有其他人正在使用。请稍候再试。",
    "Windows could not reach the Canon scanner. Turn it on, make sure it is on the same Wi-Fi, and check it in Canon IJ Scan Utility, then retry.":
        "Windows 无法连接 Canon 扫描仪。请打开扫描仪，确认它连接同一 Wi-Fi，并在 Canon IJ Scan Utility 中检查，然后重试。",
    "Epson Scan 2 could not open the scanner. In Epson Scan 2 Utility, add or test its network address, then retry.":
        "Epson Scan 2 无法打开扫描仪。请在 Epson Scan 2 Utility 中添加或测试其网络地址，然后重试。",
    "Scanner operation failed. {detail}":
        "扫描仪操作失败。{detail}",
    "No pages were scanned. Check the paper and the scanner connection.":
        "未扫描任何页面。请检查纸张和扫描仪连接。",
    "Could not save the scan. {error}":
        "无法保存扫描件。{error}",
    "The scan was kept as {path}":
        "扫描件已保留为 {path}",
    "✓ Saved {files} in {folder}":
        "✓ 已将 {files} 保存到 {folder}",
    "{count} JPG pages":
        "{count} 页 JPG",
    "text":
        "文字",
    "Translating the text to {lang}…":
        "正在将文字翻译为{lang}…",
    "✓ Translation saved: {name}":
        "✓ 翻译已保存：{name}",
    "Could not start NAPS2. {error}":
        "无法启动 NAPS2。{error}",
    "Could not create {folder}. {error}\nChoose another folder in Settings › Scanning.":
        "无法创建 {folder}。{error}\n请在 设置 › 扫描 中选择其他文件夹。",
    "Save scan":
        "保存扫描件",
    "Scan in progress":
        "正在扫描",
    "A scan is running. Cancel it and close the app?":
        "正在扫描。要取消扫描并关闭应用吗？",
    "JPG export needs PyMuPDF. Close and reopen the app to install it.":
        "导出 JPG 需要 PyMuPDF。关闭并重新打开应用即可自动安装。",
    "Checking GitHub for a newer version…":
        "正在 GitHub 上检查新版本…",
    "Could not check for updates. {error}":
        "无法检查更新。{error}",
    "You have the latest version (v{version}).":
        "你使用的是最新版本 (v{version})。",
    "Update available":
        "有可用更新",
    "{app} {version} is available (you have v{current}).\n\nWhat's new:\n{notes}\n\nDownload and install it now?":
        "{app} {version} 已推出（你的版本是 v{current}）。\n\n新内容：\n{notes}\n\n现在下载并安装吗？",
    "No release notes.":
        "没有发行说明。",
    "Update {version} is waiting in Help.":
        "更新 {version} 正在“帮助”中等你。",
    "Finish the scan first, then install the update from Help.":
        "请先完成扫描，再从“帮助”安装更新。",
    "Downloading {version} from GitHub…":
        "正在从 GitHub 下载 {version}…",
    "Update failed. {error}":
        "更新失败。{error}",
    "macOS is running the app from a temporary read-only copy. Drag What the Scan into Applications, open it from there, then update again.":
        "macOS 正在从临时的只读副本运行本应用。请将 What the Scan 拖到“应用程序”，从那里打开，然后再次更新。",
    "The app's folder can't be written to. Move the app to a folder you own (or Applications) and update again.":
        "无法写入应用所在文件夹。请将应用移到你自己的文件夹（或“应用程序”）后再次更新。",
    "Update failed":
        "更新失败",
    "{error}\n\nOpen the release page to download it by hand?":
        "{error}\n\n打开发布页面手动下载吗？",
    "Updated to {version}. Restarting…":
        "已更新到 {version}。正在重新启动…",
    "Choose a model to find its driver.":
        "请选择型号以查找其驱动。",
    "Install driver":
        "安装驱动",
    "Download and install the official {label} now?\n\nWindows may ask for permission. Choose No to open the support page instead.":
        "现在下载并安装官方 {label} 吗？\n\nWindows 可能会请求权限。选择“否”可改为打开支持页面。",
    "Preparing the official {label} installer…":
        "正在准备官方 {label} 安装程序…",
    "{label} installed. Looking for scanners…":
        "{label} 已安装。正在查找扫描仪…",
    "Driver setup failed. {error}\nThe support page is opening so you can install it by hand.":
        "驱动安装失败。{error}\n正在打开支持页面，以便你手动安装。",
    "Searching the local network for scanners (Epson, Canon, HP, AirPrint)…":
        "正在本地网络中查找扫描仪（Epson、Canon、HP、AirPrint）…",
    "answered as a network (eSCL) scanner ✓":
        "以网络扫描仪 (eSCL) 身份响应 ✓",
    "This scanner has: {sources}":
        "此扫描仪支持：{sources}",
    "Network discovery failed. {error}":
        "网络搜索失败。{error}",
    "Select your scanner's network address.":
        "请选择扫描仪的网络地址。",
    "No scanner replied on this local network.":
        "此本地网络中没有扫描仪响应。",
    "answered as a Canon scanner ✓":
        "以 Canon 扫描仪身份响应 ✓",
    "responds on the scanner port ✓":
        "扫描仪端口有响应 ✓",
    "did not respond on the scanner port":
        "扫描仪端口无响应",
    "{brand} {ip} {state}. Scanning uses the driver chosen above.":
        "{brand} {ip} {state}。扫描使用上面选择的驱动。",
}

TRANSLATIONS = {"el": GR, "fr": UI_FR, "de": UI_DE, "it": UI_IT, "es": UI_ES, "ro": UI_RO, "cs": UI_CS,
                "ru": UI_RU, "ja": UI_JA, "zh": UI_ZH}
UI_LANGUAGES = (("en", "English"), ("el", "Ελληνικά"), ("fr", "Français"), ("de", "Deutsch"),
                ("it", "Italiano"), ("es", "Español"), ("ro", "Română"), ("cs", "Čeština"),
                ("ru", "Русский"), ("ja", "日本語"), ("zh", "中文 (简体)"))

def tr(message, /, **values):
    result = TRANSLATIONS[UI_LANG].get(message, message) if UI_LANG in TRANSLATIONS else message
    return result.format(**values) if values else result


def lang_name(code):
    names = LANG_NAMES.get(code)
    if not names:
        return code or "?"
    if UI_LANG == "el":
        return names[1]
    if UI_LANG != "en":
        from PyQt6.QtCore import QLocale
        native = "English" if code == "en" else QLocale(code.replace("-", "_")).nativeLanguageName()
        if native:
            return native[:1].upper() + native[1:]
    return names[0]


def system_language():
    from PyQt6.QtCore import QLocale
    return QLocale.system().name().split("_")[0].lower()


def resolve_ui_language(setting):
    supported = {code for code, _ in UI_LANGUAGES}
    if setting in supported:
        return setting
    system = system_language()
    return system if system in supported else "en"


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
    with urllib.request.urlopen(request, timeout=timeout, context=internet_context()) as response:
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


# ---------------------------------------------------------------- phone: LocalSend + QR web page
# Send scans to a phone and receive photos/files from it on the same Wi-Fi. Phones with the free LocalSend
# app see this computer like any other LocalSend device (protocol v2: multicast discovery, HTTPS REST upload).
# Phones without it scan a QR code and use a small web page in their browser.
LOCALSEND_GROUP = "224.0.0.167"
LOCALSEND_PORT = 53317
PHONE_WEB_PORT = 53320
PHONE_OPEN_MINUTES = 5
PHONE_ASK_SECONDS = 75
PHONE_IMAGES = {".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff"}
LOCALSEND_URL = "https://localsend.org/download"
PHONE_MIME = {
    ".pdf": "application/pdf", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
    ".txt": "text/plain", ".odt": "application/vnd.oasis.opendocument.text",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}
DEVICE_MODEL = "Windows" if WINDOWS else "macOS" if MAC else "Linux"


class PhoneError(Exception):
    pass


def mime_type(path):
    suffix = Path(path).suffix.lower()
    return PHONE_MIME.get(suffix) or mimetypes.guess_type(str(path))[0] or "application/octet-stream"


def lan_ip():
    """This computer's address on the Wi-Fi / LAN (no packet is sent)."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("10.255.255.255", 1))
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


def safe_file_name(name):
    name = Path(str(name or "").replace("\\", "/")).name
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip(" .")
    if not name:
        return "file"
    stem, suffix = os.path.splitext(name)
    return stem[:140] + suffix[:12]


def readable_size(size):
    size = float(size or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024


def phone_certificate(folder):
    """LocalSend talks HTTPS with a self-signed certificate. Made once, kept next to the app's data.
    Returns (cert file, key file, fingerprint) or None when the cryptography package is missing."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
    except ImportError:
        return None
    cert, key = folder / "localsend-cert.pem", folder / "localsend-key.pem"
    if not (cert.is_file() and key.is_file()):
        folder.mkdir(parents=True, exist_ok=True)
        private = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "What the Scan")])
        now = datetime.now(timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                       .public_key(private.public_key()).serial_number(x509.random_serial_number())
                       .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=3650))
                       .sign(private, hashes.SHA256()))
        key.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
        cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    der = ssl.PEM_cert_to_DER_cert(cert.read_text(encoding="ascii"))
    return cert, key, hashlib.sha256(der).hexdigest().upper()


class _Counting:
    """File wrapper that reports how many bytes were read (upload progress)."""

    def __init__(self, source, report):
        self.source, self.report = source, report

    def read(self, size=-1):
        chunk = self.source.read(size if size and size > 0 else 256 * 1024)
        if chunk:
            self.report(len(chunk))
        return chunk


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = not WINDOWS  # on Windows this would let two programs share the port

    def handle_error(self, request, client_address):
        pass  # phones that disappear mid-request are normal


class PhoneLink:
    """Background part: LocalSend server + multicast discovery + the QR web page. Thread-safe; the window
    receives events through `events` (device_found, ask_user, files_received), called from server threads."""

    def __init__(self, alias, data_folder, events):
        self.alias = alias
        self.data_folder = data_folder
        self.events = events
        self.lock = threading.Lock()
        self.devices = {}
        self.session = None
        self.servers = []
        self.running = False
        self.port = LOCALSEND_PORT
        self.web_port = None
        self.protocol = "http"
        self.fingerprint = uuid4().hex
        self.token = secrets.token_urlsafe(9)
        self.save_folder = Path.home()
        self.shared = []
        self.multicast = None
        self.last_error = ""
        self.opener = self._opener(None)

    @staticmethod
    def _opener(certificate):
        """LAN only, never through a system proxy. Phones use self-signed certificates, so they are not
        verified; our own certificate is presented as the client certificate, because LocalSend 1.18+
        receivers with encryption on ask for one (mutual TLS) and drop the connection without it."""
        context = ssl._create_unverified_context()
        if certificate:
            context.load_cert_chain(str(certificate[0]), str(certificate[1]))
        return urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                           urllib.request.HTTPSHandler(context=context))

    # ----- identity
    def info(self):
        return {"alias": self.alias, "version": "2.1", "deviceModel": DEVICE_MODEL, "deviceType": "desktop",
                "fingerprint": self.fingerprint, "port": self.port, "protocol": self.protocol, "download": False}

    def web_url(self):
        return f"http://{lan_ip()}:{self.web_port}/?t={self.token}" if self.web_port else ""

    # ----- start / stop
    def start(self):
        if self.running:
            return True
        try:
            certificate = phone_certificate(self.data_folder)
        except Exception:
            certificate = None
        server = None
        for port in (LOCALSEND_PORT, *range(LOCALSEND_PORT + 1, LOCALSEND_PORT + 3)):
            try:
                server = _Server(("", port), _localsend_handler(self))
                break
            except OSError:
                continue
        web = None
        for port in range(PHONE_WEB_PORT, PHONE_WEB_PORT + 10):
            try:
                web = _Server(("", port), _web_handler(self))
                break
            except OSError:
                continue
        if server is None and web is None:
            return False
        if server is not None:
            self.port = server.server_address[1]
            if certificate:
                self.opener = self._opener(certificate)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(str(certificate[0]), str(certificate[1]))
                server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
                self.protocol, self.fingerprint = "https", certificate[2]
            self.servers.append(server)
        if web is not None:
            self.web_port = web.server_address[1]
            self.servers.append(web)
        self.running = True
        for item in self.servers:
            threading.Thread(target=item.serve_forever, kwargs={"poll_interval": 0.5}, daemon=True).start()
        if server is not None:
            threading.Thread(target=self._listen_multicast, daemon=True).start()
            self.announce()
        return True

    def stop(self):
        self.running = False
        for server in self.servers:
            threading.Thread(target=lambda s=server: (s.shutdown(), s.server_close()), daemon=True).start()
        self.servers = []
        self.web_port = None
        with self.lock:
            self.session = None
        if self.multicast:
            try:
                self.multicast.close()
            except OSError:
                pass
            self.multicast = None

    # ----- discovery
    def _listen_multicast(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT") and not LINUX:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.bind(("", LOCALSEND_PORT))
            for interface in dict.fromkeys((lan_ip(), "0.0.0.0")):
                try:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                    socket.inet_aton(LOCALSEND_GROUP) + socket.inet_aton(interface))
                except OSError:
                    pass
            sock.settimeout(1.0)
        except OSError:
            return
        self.multicast = sock
        while self.running:
            try:
                data, address = sock.recvfrom(65535)
                message = json.loads(data.decode("utf-8"))
            except socket.timeout:
                continue
            except (OSError, ValueError):
                if not self.running:
                    break
                continue
            if not isinstance(message, dict) or message.get("fingerprint") == self.fingerprint:
                continue
            self.add_device(message, address[0])
            if message.get("announce") or message.get("announcement"):
                threading.Thread(target=self._answer, args=(address[0], message), daemon=True).start()

    def _answer(self, ip, message):
        device = {"ip": ip, "port": int(message.get("port") or LOCALSEND_PORT),
                  "protocol": message.get("protocol") or "https"}
        try:
            self.request(device, "register", self.info(), timeout=3)
        except Exception:
            self._multicast_send(announce=False)

    def _multicast_send(self, announce=True):
        payload = dict(self.info(), announce=announce, announcement=announce)
        try:
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sender.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            try:
                sender.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(lan_ip()))
            except OSError:
                pass
            sender.sendto(json.dumps(payload).encode(), (LOCALSEND_GROUP, LOCALSEND_PORT))
            sender.close()
        except OSError:
            pass

    def announce(self):
        if self.running:
            self._multicast_send(announce=True)

    def scan_network(self):
        """Fallback for Wi-Fi routers that block multicast: ask every address on the local /24 network."""
        own = lan_ip()
        if own.startswith("127."):
            return
        prefix = own.rsplit(".", 1)[0]

        def probe(host):
            if not self.running:
                return
            for protocol in ("https", "http"):
                device = {"ip": host, "port": LOCALSEND_PORT, "protocol": protocol}
                try:
                    status, body = self.request(device, "register", self.info(), timeout=1.5)
                except Exception:
                    continue
                if status == 200:
                    try:
                        self.add_device(dict(json.loads(body or b"{}"), protocol=protocol, port=LOCALSEND_PORT), host)
                    except ValueError:
                        pass
                    return

        with ThreadPoolExecutor(max_workers=48) as pool:
            list(pool.map(probe, [f"{prefix}.{n}" for n in range(1, 255) if f"{prefix}.{n}" != own]))

    def add_device(self, message, ip):
        if not isinstance(message, dict) or message.get("fingerprint") == self.fingerprint:
            return
        device = {"alias": str(message.get("alias") or ip)[:60], "deviceModel": str(message.get("deviceModel") or ""),
                  "deviceType": str(message.get("deviceType") or ""), "ip": ip,
                  "port": int(message.get("port") or LOCALSEND_PORT),
                  "protocol": message.get("protocol") if message.get("protocol") in ("http", "https") else "https",
                  "fingerprint": str(message.get("fingerprint") or ip)}
        with self.lock:
            known = self.devices.get(device["fingerprint"])
            self.devices[device["fingerprint"]] = device
        if known != device:
            self.events.device_found(device)

    # ----- sending (computer -> phone)
    def request(self, device, route, body=None, stream=None, length=0, query=None, timeout=10):
        url = f"{device['protocol']}://{device['ip']}:{device['port']}/api/localsend/v2/{route}"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        if stream is not None:
            data, headers = stream, {"Content-Type": "application/octet-stream", "Content-Length": str(length)}
        else:
            data = json.dumps(body if body is not None else {}).encode()
            headers = {"Content-Type": "application/json"}
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with self.opener.open(req, timeout=timeout) as answer:
                return answer.status, answer.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def send(self, device, paths, progress, cancelled):
        files, by_id = {}, {}
        for path in paths:
            file_id = uuid4().hex
            by_id[file_id] = path
            files[file_id] = {"id": file_id, "fileName": path.name, "size": path.stat().st_size,
                              "fileType": mime_type(path)}
        progress(0, "ask")
        try:
            status, body = self.request(device, "prepare-upload", {"info": self.info(), "files": files},
                                        timeout=PHONE_ASK_SECONDS + 30)
        except (OSError, ValueError) as exc:
            reason = getattr(exc, "reason", None) or exc
            self.last_error = f"{type(reason).__name__}: {reason}"[:160]
            raise PhoneError("unreachable") from exc
        if status == 204:
            return
        if status in (401, 403, 409, 429):
            raise PhoneError({401: "pin", 403: "declined", 409: "busy", 429: "busy"}[status])
        if status != 200:
            raise PhoneError(f"HTTP {status}")
        answer = json.loads(body or b"{}")
        session, tokens = answer.get("sessionId"), answer.get("files") or {}
        total = sum(files[f]["size"] for f in tokens if f in files) or 1
        sent = [0]

        def counted(count):
            sent[0] += count
            progress(int(sent[0] * 100 / total), "send")
            if cancelled():
                raise PhoneError("cancelled")

        try:
            for file_id, token in tokens.items():
                path = by_id.get(file_id)
                if path is None:
                    continue
                with path.open("rb") as source:
                    status, _ = self.request(device, "upload", stream=_Counting(source, counted),
                                             length=files[file_id]["size"], timeout=60,
                                             query={"sessionId": session, "fileId": file_id, "token": token})
                if status != 200:
                    raise PhoneError(f"HTTP {status}")
        except Exception:
            try:
                self.request(device, "cancel", query={"sessionId": session}, timeout=3)
            except Exception:
                pass
            raise

    # ----- receiving (phone -> computer)
    def prepare(self, sender, files, ip):
        """Ask the user, then open an upload session. Returns (HTTP status, JSON answer)."""
        if not isinstance(files, dict) or not files or len(files) > 500:
            return 400, None
        with self.lock:
            busy = self.session and time.monotonic() - self.session["touched"] < 600
        if busy:
            return 409, {"message": "Another transfer is running"}
        wanted = [(safe_file_name(item.get("fileName")), int(item.get("size") or 0))
                  for item in files.values() if isinstance(item, dict)]
        name = str((sender or {}).get("alias") or ip)[:60]
        if not self.events.ask_user(name, wanted):
            return 403, {"message": "Declined"}
        folder = Path(self.save_folder)
        folder.mkdir(parents=True, exist_ok=True)
        taken, entries = set(), {}
        for file_id, item in files.items():
            target = unique_path(folder / safe_file_name(item.get("fileName")))
            number = 2
            while target in taken:
                base = folder / safe_file_name(item.get("fileName"))
                target = unique_path(base.with_name(f"{base.stem} ({number}){base.suffix}"))
                number += 1
            taken.add(target)
            entries[str(file_id)] = {"target": target, "token": secrets.token_hex(16), "done": False,
                                     "size": int(item.get("size") or 0)}
        session = {"id": uuid4().hex, "files": entries, "sender": name, "touched": time.monotonic()}
        with self.lock:
            self.session = session
        return 200, {"sessionId": session["id"], "files": {k: v["token"] for k, v in entries.items()}}

    def store(self, session_id, file_id, token, source, length, chunked=False):
        with self.lock:
            session = self.session
        if not session or session["id"] != session_id:
            return 403
        entry = session["files"].get(str(file_id))
        if not entry or not secrets.compare_digest(entry["token"], str(token or "")) or entry["done"]:
            return 403
        if length < 0 and not chunked:
            return 411
        part = entry["target"].with_name(entry["target"].name + ".part")
        remaining = length
        try:
            with part.open("wb") as out:
                if chunked:  # Transfer-Encoding: chunked (no Content-Length)
                    remaining = 0
                    while True:
                        size = int(source.readline(100).split(b";")[0].strip() or b"0", 16)
                        if size == 0:
                            while source.readline(1000).strip():
                                pass  # trailer lines
                            break
                        while size > 0:
                            chunk = source.read(min(size, 256 * 1024))
                            if not chunk:
                                raise OSError("incomplete")
                            out.write(chunk)
                            size -= len(chunk)
                            session["touched"] = time.monotonic()
                        source.readline(10)
                while remaining > 0:
                    chunk = source.read(min(remaining, 256 * 1024))
                    if not chunk:
                        break
                    out.write(chunk)
                    remaining -= len(chunk)
                    session["touched"] = time.monotonic()
            if remaining:
                raise OSError("incomplete")
            part.replace(entry["target"])
        except OSError:
            part.unlink(missing_ok=True)
            return 500
        entry["done"] = True
        finished = False
        with self.lock:
            if self.session is session and all(item["done"] for item in session["files"].values()):
                self.session, finished = None, True
        if finished:
            self.events.files_received([item["target"] for item in session["files"].values()], session["sender"])
        return 200

    def cancel(self, session_id):
        with self.lock:
            session = self.session
            if not session or session["id"] != session_id:
                return
            self.session = None
        done = [item["target"] for item in session["files"].values() if item["done"]]
        if done:
            self.events.files_received(done, session["sender"])


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "WhatTheScan"
    link = None

    def setup(self):
        self.request.settimeout(60)
        if isinstance(self.request, ssl.SSLSocket):
            self.request.do_handshake()
        super().setup()

    def log_message(self, *args):
        pass

    def reply(self, code, payload=None, content_type="application/json", extra=None):
        if payload is None:
            body = b""
        elif isinstance(payload, bytes):
            body = payload
        else:
            body = json.dumps(payload).encode()
        self.close_connection = True
        self.send_response(code)
        if body:
            self.send_header("Content-Type", content_type)
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def json_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if not 0 <= length <= 4_000_000:
            raise ValueError("body too large")
        return json.loads(self.rfile.read(length) or b"{}")

    def route(self):
        parts = urllib.parse.urlsplit(self.path)
        return parts.path, dict(urllib.parse.parse_qsl(parts.query))


def _localsend_handler(link):
    class LocalSendHandler(_Handler):
        def do_GET(self):
            path, _ = self.route()
            self.reply(200, link.info()) if path.endswith("/info") else self.reply(404)

        def do_POST(self):
            path, query = self.route()
            try:
                if path.endswith("/register"):
                    link.add_device(self.json_body(), self.client_address[0])
                    self.reply(200, link.info())
                elif path == "/api/localsend/v2/prepare-upload":
                    data = self.json_body()
                    self.reply(*link.prepare(data.get("info"), data.get("files"), self.client_address[0]))
                elif path == "/api/localsend/v2/upload":
                    self.reply(link.store(query.get("sessionId"), query.get("fileId"), query.get("token"),
                                          self.rfile, int(self.headers.get("Content-Length") or -1),
                                          "chunked" in self.headers.get("Transfer-Encoding", "").lower()))
                elif path == "/api/localsend/v2/cancel":
                    link.cancel(query.get("sessionId"))
                    self.reply(200)
                else:
                    self.reply(404)
            except (ValueError, TypeError, AttributeError):
                self.reply(400)

    return LocalSendHandler


def _web_handler(link):
    class WebHandler(_Handler):
        def allowed(self, query):
            return secrets.compare_digest(str(query.get("t", "")), link.token)

        def do_GET(self):
            path, query = self.route()
            if not self.allowed(query):
                self.reply(403, tr("This link has expired. Scan the QR code again.").encode(), "text/plain; charset=utf-8")
            elif path == "/":
                self.reply(200, phone_page(link).encode(), "text/html; charset=utf-8",
                           {"Cache-Control": "no-store"})
            elif path.startswith("/file/"):
                try:
                    target = list(link.shared)[int(path.rsplit("/", 1)[1])]
                    size = target.stat().st_size
                except (ValueError, IndexError, OSError):
                    self.reply(404)
                    return
                self.close_connection = True
                self.send_response(200)
                self.send_header("Content-Type", mime_type(target))
                self.send_header("Content-Length", str(size))
                self.send_header("Content-Disposition",
                                 f"attachment; filename*=UTF-8''{urllib.parse.quote(target.name)}")
                self.send_header("Connection", "close")
                self.end_headers()
                with target.open("rb") as source:
                    shutil.copyfileobj(source, self.wfile, 256 * 1024)
            else:
                self.reply(404)

        def do_POST(self):
            path, query = self.route()
            if not self.allowed(query):
                self.reply(403)
                return
            try:
                if path == "/prepare":
                    data = self.json_body()
                    files = {str(n): {"fileName": item.get("name"), "size": item.get("size")}
                             for n, item in enumerate(data.get("files") or [])}
                    agent = self.headers.get("User-Agent", "")
                    phone = "iPhone" if "iPhone" in agent else "Android" if "Android" in agent else tr("Phone")
                    self.reply(*link.prepare({"alias": tr("{phone} (browser)", phone=phone)}, files,
                                             self.client_address[0]))
                elif path == "/upload":
                    self.reply(link.store(query.get("s"), query.get("f"), query.get("k"), self.rfile,
                                          int(self.headers.get("Content-Length") or -1),
                                          "chunked" in self.headers.get("Transfer-Encoding", "").lower()))
                elif path == "/cancel":
                    link.cancel(query.get("s"))
                    self.reply(200)
                else:
                    self.reply(404)
            except (ValueError, TypeError, AttributeError):
                self.reply(400)

    return WebHandler


def phone_page(link):
    """The page a phone without LocalSend opens from the QR code: download the scan, send photos."""
    def esc(text):
        return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))

    files = [path for path in link.shared if path.exists()]
    rows = "".join(
        f'<a class="file" href="/file/{n}?t={link.token}"><span>⬇</span><b>{esc(path.name)}</b>'
        f'<small>{readable_size(path.stat().st_size)}</small></a>'
        for n, path in enumerate(link.shared) if path in files
    ) or f'<p class="muted">{esc(tr("No scan yet. Scan something first, then reload this page."))}</p>'
    messages = json.dumps({
        "wait": tr("Waiting for the computer to accept…"), "declined": tr("The computer declined the files."),
        "busy": tr("The computer is receiving other files. Try again in a moment."),
        "error": tr("Sending failed. Check that the phone is on the same Wi-Fi and try again."),
        "sending": tr("Sending {name}…", name="%s"), "done": tr("✓ Sent! The files are on the computer."),
    })
    lang = UI_LANG
    return f"""<!DOCTYPE html><html lang="{lang}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{esc(APP_NAME)}</title>
<style>
:root{{--bg:#f5f3ff;--card:#fff;--text:#1f1b2e;--muted:#6b6880;--accent:#6d28d9;--line:#e4e0f2}}
@media (prefers-color-scheme:dark){{:root{{--bg:#14121c;--card:#1f1c2b;--text:#f1eefb;--muted:#a19cb8;--line:#2f2a40}}}}
*{{box-sizing:border-box}}body{{margin:0;font:16px/1.45 -apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text)}}
main{{max-width:560px;margin:auto;padding:22px 16px 40px}}h1{{font-size:22px;margin:4px 0 2px}}
.muted{{color:var(--muted)}}section{{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:16px;margin-top:16px}}
h2{{font-size:17px;margin:0 0 10px}}.file{{display:flex;gap:12px;align-items:center;padding:14px;border-radius:14px;
background:var(--bg);color:var(--text);text-decoration:none;margin-top:8px;border:1px solid var(--line)}}
.file span{{font-size:20px;color:var(--accent)}}.file b{{flex:1;word-break:break-all;font-weight:600}}
label.pick{{display:block;text-align:center;padding:18px;border-radius:14px;background:var(--accent);color:#fff;font-weight:700;font-size:18px}}
input{{display:none}}progress{{width:100%;height:10px;margin-top:12px;display:none}}#status{{margin-top:10px;font-weight:600}}
a.reload{{color:var(--accent)}}
</style></head><body><main>
<h1>📄 {esc(APP_NAME)}</h1><div class="muted">{esc(tr("Connected to {name}", name=link.alias))}</div>
<section><h2>{esc(tr("1 · Get the scan on this phone"))}</h2>{rows}
<p class="muted"><a class="reload" href="?t={link.token}">↻ {esc(tr("Reload"))}</a></p></section>
<section><h2>{esc(tr("2 · Send photos or files to the computer"))}</h2>
<label class="pick" for="pick">📷 {esc(tr("Take a photo or choose files"))}</label>
<input id="pick" type="file" multiple accept="image/*,application/pdf">
<progress id="bar" max="100" value="0"></progress><div id="status"></div></section>
</main><script>
const M={messages},T=new URLSearchParams(location.search).get('t'),bar=document.getElementById('bar'),
st=document.getElementById('status');
function put(url,file,done,total){{return new Promise((ok,fail)=>{{const x=new XMLHttpRequest();x.open('POST',url);
x.upload.onprogress=e=>{{bar.value=Math.round((done+e.loaded)*100/total)}};
x.onload=()=>x.status==200?ok():fail(x.status);x.onerror=()=>fail(0);x.send(file)}})}}
document.getElementById('pick').onchange=async e=>{{const files=[...e.target.files];if(!files.length)return;
st.textContent=M.wait;bar.style.display='none';
try{{const r=await fetch('/prepare?t='+T,{{method:'POST',headers:{{'Content-Type':'application/json'}},
body:JSON.stringify({{files:files.map(f=>({{name:f.name,size:f.size}}))}})}});
if(r.status==403){{st.textContent=M.declined;return}}if(r.status==409){{st.textContent=M.busy;return}}
if(!r.ok)throw 0;const s=await r.json(),total=files.reduce((a,f)=>a+f.size,0)||1;let done=0;bar.style.display='block';
for(let i=0;i<files.length;i++){{st.textContent=M.sending.replace('%s',files[i].name);
await put('/upload?t='+T+'&s='+s.sessionId+'&f='+i+'&k='+s.files[i],files[i],done,total);done+=files[i].size}}
bar.value=100;st.textContent=M.done}}catch(x){{st.textContent=M.error}}e.target.value=''}};
</script></body></html>"""


def qr_pixmap(text, size=220):
    """QR code drawn with Qt from segno's matrix; None if segno is missing."""
    try:
        import segno
    except ImportError:
        return None
    rows = [list(row) for row in segno.make(text, error="m", micro=False).matrix_iter(scale=1, border=3)]
    count = len(rows)
    cell = max(2, size // count)
    pixmap = QPixmap(cell * count, cell * count)
    pixmap.fill(QColor("#ffffff"))
    painter = QPainter(pixmap)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor("#111111"))
    for y, row in enumerate(rows):
        for x, dark in enumerate(row):
            if dark:
                painter.drawRect(x * cell, y * cell, cell, cell)
    painter.end()
    return pixmap


_AIRDROP_KEEP = []


def airdrop(paths, check_only=False):
    """macOS: open the system AirDrop window for these files (Apple's own NSSharingService, called through
    the Objective-C runtime, so nothing extra to install). Returns False when AirDrop is not available."""
    if not MAC:
        return False
    import ctypes
    import ctypes.util
    objc = ctypes.cdll.LoadLibrary(ctypes.util.find_library("objc"))
    ctypes.cdll.LoadLibrary("/System/Library/Frameworks/AppKit.framework/AppKit")
    objc.objc_getClass.restype = ctypes.c_void_p
    objc.objc_getClass.argtypes = [ctypes.c_char_p]
    objc.sel_registerName.restype = ctypes.c_void_p
    objc.sel_registerName.argtypes = [ctypes.c_char_p]
    send = objc.objc_msgSend

    def call(target, selector, *args, restype=ctypes.c_void_p, argtypes=()):
        send.restype = restype
        send.argtypes = [ctypes.c_void_p, ctypes.c_void_p, *argtypes]
        return send(target, objc.sel_registerName(selector.encode()), *args)

    def cls(name):
        return objc.objc_getClass(name.encode())

    def text(value):
        return call(cls("NSString"), "stringWithUTF8String:", str(value).encode("utf-8"),
                    argtypes=[ctypes.c_char_p])

    items = call(cls("NSMutableArray"), "array")
    for path in paths:
        url = call(cls("NSURL"), "fileURLWithPath:", text(path), argtypes=[ctypes.c_void_p])
        call(items, "addObject:", url, argtypes=[ctypes.c_void_p])
    service = call(cls("NSSharingService"), "sharingServiceNamed:", text("com.apple.share.AirDrop.send"),
                   argtypes=[ctypes.c_void_p])
    if not service or not call(service, "canPerformWithItems:", items, restype=ctypes.c_bool,
                               argtypes=[ctypes.c_void_p]):
        return False
    if check_only:
        return True
    _AIRDROP_KEEP[:] = [call(service, "retain"), call(items, "retain")]  # alive while the window is open
    call(service, "performWithItems:", items, restype=None, argtypes=[ctypes.c_void_p])
    return True


class PhoneBridge(QObject):
    """Moves PhoneLink events from its threads to the GUI thread."""
    device = pyqtSignal(dict)
    asked = pyqtSignal(object)
    received = pyqtSignal(list, str)
    send_progress = pyqtSignal(int, str)
    send_done = pyqtSignal(str)

    def device_found(self, device):
        self.device.emit(device)

    def ask_user(self, sender, files):
        request = {"sender": sender, "files": files, "event": threading.Event(), "ok": False}
        self.asked.emit(request)
        request["event"].wait(PHONE_ASK_SECONDS + 5)
        return request["ok"]

    def files_received(self, paths, sender):
        self.received.emit([str(path) for path in paths], sender)


class PhoneDialog(QDialog):
    def __init__(self, window):
        super().__init__(window)
        self.main = window
        self.setWindowTitle(f"{APP_NAME} · {tr('Phone')}")
        self.setMinimumWidth(780)
        self.files = []
        self.sending = False
        self.cancel_send = False
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 20, 24, 18)
        outer.setSpacing(12)
        heading = QLabel(tr("Send to your phone"))
        heading.setObjectName("pageTitle")
        outer.addWidget(heading)
        note = QLabel(tr("Phone and computer must be on the same Wi-Fi."))
        note.setObjectName("hint")
        outer.addWidget(note)

        what = QFrame()
        what.setObjectName("section")
        what_row = QHBoxLayout(what)
        what_row.setContentsMargins(16, 12, 16, 12)
        self.what_label = QLabel()
        self.what_label.setWordWrap(True)
        self.what_label.setTextFormat(Qt.TextFormat.PlainText)
        what_row.addWidget(self.what_label, 1)
        choose = QPushButton(tr("Choose other files…"))
        window.iconize(choose, "folder")
        choose.clicked.connect(self.choose_files)
        what_row.addWidget(choose)
        if MAC:
            self.airdrop_button = QPushButton(tr("AirDrop"))
            self.airdrop_button.setToolTip(tr("Send with AirDrop to an iPhone, iPad or Mac nearby"))
            window.iconize(self.airdrop_button, "phone")
            self.airdrop_button.clicked.connect(self.send_airdrop)
            what_row.addWidget(self.airdrop_button)
        outer.addWidget(what)

        columns = QHBoxLayout()
        columns.setSpacing(14)
        left = QFrame()
        left.setObjectName("section")
        box = QVBoxLayout(left)
        box.setContentsMargins(16, 14, 16, 14)
        title = QLabel(tr("Phones with LocalSend"))
        title.setObjectName("sectionTitle")
        box.addWidget(title)
        self.devices = QListWidget()
        self.devices.setIconSize(QSize(22, 22))
        self.devices.setMinimumHeight(150)
        self.devices.itemDoubleClicked.connect(lambda _: self.send())
        self.devices.currentRowChanged.connect(lambda _: self.update_buttons())
        box.addWidget(self.devices, 1)
        self.empty_hint = QLabel()
        self.empty_hint.setObjectName("hint")
        self.empty_hint.setWordWrap(True)
        box.addWidget(self.empty_hint)
        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(6)
        self.bar.hide()
        box.addWidget(self.bar)
        self.send_status = QLabel()
        self.send_status.setWordWrap(True)
        self.send_status.setTextFormat(Qt.TextFormat.PlainText)
        box.addWidget(self.send_status)
        buttons = QHBoxLayout()
        self.search_button = QPushButton(tr("Search again"))
        window.iconize(self.search_button, "refresh")
        self.search_button.clicked.connect(self.search)
        self.send_button = QPushButton(tr("Send"))
        self.send_button.setObjectName("primary")
        window.iconize(self.send_button, "phone", color="#ffffff")
        self.send_button.clicked.connect(self.send)
        buttons.addWidget(self.search_button)
        buttons.addStretch()
        buttons.addWidget(self.send_button)
        box.addLayout(buttons)
        columns.addWidget(left, 3)

        right = QFrame()
        right.setObjectName("section")
        box = QVBoxLayout(right)
        box.setContentsMargins(16, 14, 16, 14)
        title = QLabel(tr("No LocalSend? Scan this"))
        title.setObjectName("sectionTitle")
        box.addWidget(title)
        self.qr = QLabel()
        self.qr.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.qr.setMinimumSize(220, 220)
        box.addWidget(self.qr, 0, Qt.AlignmentFlag.AlignHCenter)
        self.url = QLabel()
        self.url.setObjectName("hint")
        self.url.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.url.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.url.setWordWrap(True)
        box.addWidget(self.url)
        hint = QLabel(tr("Point the phone camera at the code. A page opens where you can download the scan "
                         "and send photos to this computer."))
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        box.addWidget(hint)
        box.addStretch()
        columns.addWidget(right, 2)
        outer.addLayout(columns, 1)

        footer = QHBoxLayout()
        self.receive_label = QLabel()
        self.receive_label.setObjectName("hint")
        self.receive_label.setWordWrap(True)
        footer.addWidget(self.receive_label, 1)
        get_app = QPushButton(tr("LocalSend for the phone"))
        get_app.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(LOCALSEND_URL)))
        close = QPushButton(tr("Close"))
        close.clicked.connect(self.close)
        footer.addWidget(get_app)
        footer.addWidget(close)
        outer.addLayout(footer)

    def present(self, files):
        self.files = [path for path in files if path.exists()]
        self.refresh_files()
        url = self.main.phone_link.web_url() if self.main.phone_link else ""
        pixmap = qr_pixmap(url) if url else None
        if pixmap is not None:
            self.qr.setPixmap(pixmap)
            self.qr.setFixedSize(pixmap.size())
        else:
            self.qr.setText(tr("QR code not available.") if not url else url)
        self.url.setText(url)
        self.devices.clear()
        for device in self.main.phone_devices.values():
            self.add_device(device)
        self.show()
        self.raise_()
        self.activateWindow()
        self.search()

    def refresh_files(self):
        if self.files:
            names = ", ".join(path.name for path in self.files[:4]) + (" …" if len(self.files) > 4 else "")
            size = readable_size(sum(path.stat().st_size for path in self.files if path.exists()))
            self.what_label.setText(tr("To send: {names}  ({size})", names=names, size=size))
        else:
            self.what_label.setText(tr("Nothing to send yet. Scan first, or choose files."))
        if self.main.phone_link:
            self.main.phone_link.shared = list(self.files)
        self.update_buttons()

    def send_airdrop(self):
        if not self.files:
            return
        try:
            ok = airdrop(self.files)
        except Exception as exc:
            ok, detail = False, str(exc)
        else:
            detail = ""
        self.send_status.setText(tr("AirDrop is open: choose the iPhone or Mac.") if ok else
                                 "⚠ " + tr("AirDrop is not available on this Mac. Turn on Wi-Fi and Bluetooth.")
                                 + (f" ({detail})" if detail else ""))

    def choose_files(self):
        start = str(self.files[0].parent if self.files else self.main.output_folder())
        names, _ = QFileDialog.getOpenFileNames(self, tr("Choose files for the phone"), start)
        if names:
            self.files = [Path(name) for name in names]
            self.refresh_files()

    def add_device(self, device):
        for row in range(self.devices.count()):
            item = self.devices.item(row)
            if item.data(Qt.ItemDataRole.UserRole)["fingerprint"] == device["fingerprint"]:
                break
        else:
            item = QListWidgetItem()
            self.devices.addItem(item)
        model = device.get("deviceModel") or device.get("deviceType") or ""
        item.setText(device["alias"] + "\n" + "  ·  ".join(part for part in (model, device["ip"]) if part))
        item.setIcon(icon("phone", "accent_text"))
        item.setData(Qt.ItemDataRole.UserRole, device)
        if self.devices.currentRow() < 0:
            self.devices.setCurrentRow(0)
        self.empty_hint.hide()
        self.update_buttons()

    def search(self):
        link = self.main.phone_link
        if not link:
            return
        self.empty_hint.setText(tr("Looking for phones… Open LocalSend on the phone."))
        self.empty_hint.setVisible(self.devices.count() == 0)
        link.announce()
        self.main.background(link.scan_network, lambda ok, _: self.search_finished())

    def search_finished(self):
        if self.devices.count() == 0:
            self.empty_hint.setText(tr("No phone found.\n1. Is the phone on the same Wi-Fi?\n"
                                       "2. Open the LocalSend app on the phone (free, Play Store / App Store).\n"
                                       "3. Or simply scan the QR code on the right."))
            self.empty_hint.show()

    def update_buttons(self):
        self.send_button.setEnabled(bool(self.files) and self.devices.currentItem() is not None
                                    and not self.sending)
        if MAC:
            self.airdrop_button.setEnabled(bool(self.files))
        self.search_button.setEnabled(not self.sending)

    def send(self):
        item = self.devices.currentItem()
        if not item or not self.files or self.sending:
            return
        device = item.data(Qt.ItemDataRole.UserRole)
        link = self.main.phone_link
        self.sending, self.cancel_send = True, False
        self.bar.setValue(0)
        self.bar.show()
        self.send_status.setText(tr("Waiting for {phone} to accept… Tap Accept on the phone.",
                                    phone=device["alias"]))
        self.update_buttons()
        bridge, files = self.main.phone_bridge, list(self.files)

        def work():
            try:
                link.send(device, files, lambda value, step: bridge.send_progress.emit(value, step),
                          lambda: self.cancel_send)
                bridge.send_done.emit("")
            except PhoneError as exc:
                bridge.send_done.emit(str(exc))
            except Exception as exc:
                bridge.send_done.emit(f"error: {exc}")

        self.target_name = device["alias"]
        threading.Thread(target=work, daemon=True).start()

    def progress(self, value, step):
        if step == "send":
            self.bar.setValue(value)
            self.send_status.setText(tr("Sending to {phone}… {value}%", phone=self.target_name, value=value))

    def finished_sending(self, problem):
        self.sending = False
        self.bar.hide()
        messages = {
            "declined": tr("{phone} declined the files.", phone=self.target_name),
            "busy": tr("{phone} is busy with another transfer. Try again in a moment.", phone=self.target_name),
            "pin": tr("{phone} asks for a PIN. Turn off the PIN in LocalSend settings on the phone.",
                      phone=self.target_name),
            "unreachable": tr("Could not reach {phone}. Is LocalSend open and on the same Wi-Fi?",
                              phone=self.target_name) + (f"\n({self.main.phone_link.last_error})"
                                                         if self.main.phone_link.last_error else ""),
            "cancelled": tr("Sending cancelled."),
        }
        if not problem:
            self.send_status.setText(tr("✓ Sent {count} file(s) to {phone}.", count=len(self.files),
                                        phone=self.target_name))
            self.main.set_status(tr("✓ Sent {count} file(s) to {phone}.", count=len(self.files),
                                      phone=self.target_name), "ok")
        else:
            self.send_status.setText("⚠ " + messages.get(problem, tr("Sending failed. {error}", error=problem)))
        self.update_buttons()

    def closeEvent(self, event):
        self.cancel_send = True
        super().closeEvent(event)


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
        self.network_caps = {}
        self.allowed_sources = None
        self.update_info = None
        self.text_dialog = None
        self.icon_widgets = []
        self.phone_link = None
        self.phone_devices = {}
        self.phone_dialog = None
        self.phone_until = 0.0
        self.phone_bridge = PhoneBridge(self)
        self.phone_bridge.device.connect(self.phone_device_found)
        self.phone_bridge.asked.connect(self.phone_ask)
        self.phone_bridge.received.connect(self.phone_received)
        self.phone_bridge.send_progress.connect(lambda value, step: self.phone_dialog and
                                                self.phone_dialog.progress(value, step))
        self.phone_bridge.send_done.connect(lambda problem: self.phone_dialog and
                                            self.phone_dialog.finished_sending(problem))
        self.build_settings_dialog()
        self.build_ui()
        clean_old_previews()

        self.led_timer = QTimer(self)
        self.led_timer.setInterval(1000)
        self.led_timer.timeout.connect(self.update_led)
        self.led_timer.start()
        self.phone_timer = QTimer(self)
        self.phone_timer.setInterval(1000)
        self.phone_timer.timeout.connect(self.phone_tick)
        if self.settings.value("phone_always", False, type=bool):
            QTimer.singleShot(1500, lambda: self.start_phone(always=True))

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
        documents = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DocumentsLocation)
        default = Path(documents or Path.home() / "Documents") / "What the Scan"
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
        self.phone_button = self.tool_button("phone", tr("Phone"),
                                             tr("Send to your phone or receive photos from it, on the same Wi-Fi "
                                                "(LocalSend app or QR code)"), self.open_phone)
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
        for button in (self.preview, self.phone_button, self.text_button, self.open_last_button, self.open_folder, self.cancel):
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
        self.nav.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.nav.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
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
                series = normalize(" ".join(brand.split()[1:]))
                plain = normalize(model)
                keys = [series + plain] if plain.isdigit() else [plain]
                for key in (*keys, *MODEL_ALIASES.get(model, ())):
                    self.catalog_keys.append((self.model.count() - 1, normalize(brand.split()[0]), key))
        self.catalog_keys.sort(key=lambda item: -len(item[2]))
        support = QPushButton(tr("Driver setup"))
        self.iconize(support, "save")
        support.clicked.connect(self.open_model_support)
        form.addRow(tr("Model"), self.row(self.model, support))
        form = self.section(box, tr("Network"))
        self.network = QComboBox()
        self.network.setPlaceholderText(tr("No network reply yet"))
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
            item = QListWidgetItem(f"{lang_name(code)}  ({tess})")
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

        # 4 · Phone
        nav_item("phone", tr("Phone"))
        page, box = self.settings_page(tr("Phone"), tr(
            "Send scans to your phone and receive photos from it, on the same Wi-Fi."))
        form = self.section(box, tr("Receiving from the phone"))
        self.phone_always = self.check(form, "Keep receiving on while the app is open", "phone_always",
                                       False)
        self.phone_always.toggled.connect(self.phone_always_changed)
        note = QLabel(tr("When this is off, receiving opens for {minutes} minutes each time you press Phone.",
                         minutes=PHONE_OPEN_MINUTES))
        note.setObjectName("hint")
        note.setWordWrap(True)
        form.addRow("", note)
        self.phone_photos = self.choice(form, "Phone photos", [
            ("Just save them in the scans folder", "save"),
            ("Make a PDF, like a scan (OCR, Word)", "scan"),
        ], "phone_photos")
        self.phone_photos.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.phone_photos.setMinimumContentsLength(24)
        self.phone_name = QLineEdit(self.settings.value("phone_name", "") or self.phone_alias())
        self.phone_name.textChanged.connect(self.phone_name_changed)
        form.addRow(tr("Name on the phone"), self.phone_name)
        form = self.section(box, tr("How it works"))
        steps = QLabel(tr("1. Phone and computer on the same Wi-Fi.\n"
                          "2. Install the free LocalSend app on the phone, or simply scan the QR code.\n"
                          "3. Press Phone, next to Preview, choose the phone and Send.\n"
                          "4. To send from the phone: in LocalSend choose “{name}”, or use the QR page.",
                          name=self.phone_name.text()))
        steps.setWordWrap(True)
        form.addRow("", steps)
        get_app = QPushButton(tr("LocalSend for the phone"))
        self.iconize(get_app, "phone")
        get_app.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(LOCALSEND_URL)))
        form.addRow("", self.left(get_app))
        box.addStretch()

        # 5 · General
        nav_item("gear", tr("General"))
        page, box = self.settings_page(tr("General"), tr("Language, appearance and updates."))
        form = self.section(box, tr("Appearance"))
        self.language = self.choice(form, "Language", [
            ("Auto · system language", "auto"), *((name, code) for code, name in UI_LANGUAGES),
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
        system = LANG_NAMES.get(system_language()) or LANG_NAMES.get(
            {"zh": "zh-CN"}.get(system_language(), ""))
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
        QMessageBox.information(self, tr("Quick guide"), GUIDES.get(UI_LANG, GUIDES["en"]))

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
                value = tr(str(value))
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
        if FROZEN and MAC:
            subprocess.Popen(["/usr/bin/open", "-n", str(app_path())])
            self.close()
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
        if self.scanning() and self.job and self.job.get("phone"):
            return "idle", tr("Idle · making a PDF from phone photos"), ""
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
        self.apply_sources()
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
        if brand == "Brother":
            QGuiApplication.clipboard().setText(model)
            self.set_status(tr("Brother's download page is opening. The model {model} is copied: paste it in the "
                               "search box (Ctrl+V). Most Brother models also scan with no driver over the network.",
                               model=model), "info")
        QDesktopServices.openUrl(QUrl(self.support_url(brand, model)))

    @staticmethod
    def support_url(brand, model):
        if brand == "Epson":
            return "https://download-center.epson.com/softwares/?" + urllib.parse.urlencode(
                {"device_id": f"{model} Series"})
        if brand == "Canon":
            return "https://www.canon-europe.com/search/?" + urllib.parse.urlencode({"q": model})
        if brand == "Brother":
            return "https://support.brother.com/g/b/productsearch.aspx?c=gr&lang=el&content=dl" \
                if UI_LANG == "el" else "https://support.brother.com/g/b/productsearch.aspx?c=us&lang=en&content=dl"
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
            urls = (package["url"], *package.get("mirrors", ()))
            for number, url in enumerate(urls):
                try:
                    install_vendor(url, package["signer"], package.get("flags", []),
                                   lambda message: events.put(message), label,
                                   filename=package.get("filename") if number == 0 else None)
                    break
                except (OSError, ValueError, urllib.error.URLError):
                    if number == len(urls) - 1:
                        raise
                    events.put(tr("Trying Epson's other download server…"))
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
        self.network_status.setText(tr("Searching the local network for scanners (Epson, Canon, HP, AirPrint)…"))

        def done(ok, devices):
            self.find_network.setEnabled(True)
            if not ok:
                self.network_status.setText(tr("Network discovery failed. {error}", error=devices))
                return
            preferred = self.settings.value("network_mac", "")
            preferred_ip = self.settings.value("network_ip", "")
            self.network.blockSignals(True)
            self.network.clear()
            selection = -1
            for index, (ip, mac, reachable, brand, name) in enumerate(devices):
                label = f"{name}  ·  {ip}" if name else f"{brand}  ·  {ip}"
                self.network.addItem(label + (f"  ·  {mac}" if mac else ""), (ip, mac, reachable, brand, name))
                if (mac and mac == preferred) or (selection < 0 and ip == preferred_ip):
                    selection = index
            self.network.setCurrentIndex(0 if len(devices) == 1 else selection)
            self.network.blockSignals(False)
            QTimer.singleShot(0, self.offer_missing_driver)
            if self.network.currentIndex() >= 0:
                self.remember_network()
            else:
                self.escl_ip = None
                self.network_status.setText(tr("Select your scanner's network address.") if devices else
                                            tr("No scanner replied on this local network."))
            self.update_connection()
            self.update_controls()

        self.background(discover_network, done)

    def remember_network(self):
        device = self.network.currentData()
        if not device:
            self.escl_ip = None
            return
        ip, mac, reachable, brand, name = device
        if mac:
            self.settings.setValue("network_mac", mac)
        self.settings.setValue("network_ip", ip)
        self.escl_ip = ip
        if ip not in self.network_caps:
            self.network_caps[ip] = None
            self.background(lambda: escl_capabilities(ip), lambda ok, caps: self.caps_ready(ip, caps if ok else None))
        if brand == "Canon":
            state = tr("answered as a Canon scanner ✓")
        elif brand != "Epson":
            state = tr("answered as a network (eSCL) scanner ✓")
        else:
            state = tr("responds on the scanner port ✓") if reachable else tr("did not respond on the scanner port")
        self.network_status.setText(tr("{brand} {ip} {state}. Scanning uses the driver chosen above.",
                                       brand=brand, ip=ip, state=state))
        self.update_connection()
        self.update_controls()

    def caps_ready(self, ip, caps):
        self.network_caps[ip] = caps
        self.apply_sources()

    def scanner_sources(self):
        """The paper sources the selected scanner has (set of glass/feeder/duplex), or None if unknown."""
        device = self.device.currentData()
        network = self.network.currentData()
        if device and network:
            caps = self.network_caps.get(network[0])
            name = normalize(device[0])
            same = device[1] == "escl" or normalize(network[3]) in name or (
                network[4] and normalize(network[4])[:12] in name)
            if caps and same:
                return set(caps)
        entry = self.model.currentData()
        if device and entry:
            known = MODEL_SOURCES.get(f"{entry[0]} {entry[1]}")
            if known:
                return set(known)
        return None

    def apply_sources(self):
        """Grey out paper sources the scanner doesn't have; move off an unavailable choice."""
        allowed = self.scanner_sources()
        self.allowed_sources = allowed
        model = self.source.model()
        for row in range(self.source.count()):
            value = self.source.itemData(row)
            item = model.item(row)
            if item is not None:
                item.setEnabled(value == "auto" or allowed is None or value in allowed)
        if allowed is not None and self.source.currentData() not in allowed | {"auto"}:
            self.source.setCurrentIndex(max(0, self.source.findData("auto")))
        if allowed:
            names = {"glass": tr("Flatbed"), "feeder": tr("Feeder"), "duplex": tr("Feeder · 2 sides")}
            self.source.setToolTip(tr("This scanner has: {sources}",
                                      sources=", ".join(names[k] for k in ("glass", "feeder", "duplex") if k in allowed)))
        else:
            self.source.setToolTip("")
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
        has_glass = self.allowed_sources is None or "glass" in self.allowed_sources
        self.preview.setEnabled(ready and has_glass and self.source.currentData() in ("glass", "auto"))
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
        if (self.settings.value("auto_update", True, type=bool) and not os.environ.get(RESTART_ENV)
                and not SMOKE_FILE):
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
        QTimer.singleShot(0, self.offer_missing_driver)

    @staticmethod
    def epson_utility():
        """Epson Scan 2 Utility on Windows: its Start-menu shortcut, else the program folder."""
        roots = [Path(os.environ.get(name, "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
                 for name in ("ProgramData", "APPDATA") if os.environ.get(name)]
        for root in roots:
            for link in sorted(root.glob("EPSON*/**/Epson Scan 2 Utility*.lnk")):
                return link
        for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")):
            folder = Path(base or "") / "epson" / "Epson Scan 2"
            if base and folder.is_dir():
                for exe in sorted(folder.rglob("*.exe")):
                    if "utility" in exe.name.lower() and "maint" not in exe.name.lower():
                        return exe
        return None

    def guide_epson_network(self):
        """After a fresh Epson driver install, Epson Scan 2 does not know the scanner's network address
        yet. The app knows it: copy it and walk the user through the 4 clicks in Epson's own utility."""
        if getattr(self, "epson_guide_open", False):
            return
        network = self.network.currentData()
        ip = network[0] if network else ""
        if ip:
            QGuiApplication.clipboard().setText(ip)
        utility = self.epson_utility()
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Information)
        box.setWindowTitle(tr("Connect Epson Scan 2 to the scanner"))
        box.setText(tr("Epson Scan 2 does not know your scanner's network address yet. "
                       "This happens after the driver is (re)installed. One time only:"))
        box.setInformativeText(tr(
            "1. Click “Open Epson Scan 2 Utility” below.\n"
            "2. At the top, in “Scanner”, choose “Settings”.\n"
            "3. Click “Add”, choose “Enter address”, press Ctrl+V (the address {ip} is already copied) "
            "and click OK.\n"
            "4. Click OK, close the utility and press Scan again.", ip=ip or "?"))
        open_button = box.addButton(tr("Open Epson Scan 2 Utility"), QMessageBox.ButtonRole.AcceptRole) \
            if utility else None
        box.addButton(tr("Close"), QMessageBox.ButtonRole.RejectRole)
        self.epson_guide_open = True
        box.exec()
        self.epson_guide_open = False
        if open_button is not None and box.clickedButton() is open_button:
            try:
                os.startfile(str(utility))  # noqa: the .lnk or .exe opens like a double-click
            except OSError as exc:
                self.set_status(tr("Could not open Epson Scan 2 Utility. {error}", error=exc), "error")

    def missing_driver(self):
        """A scanner answers on the network, but no driver sees it: which official driver is missing?"""
        windir = Path(os.environ.get("WINDIR", r"C:\Windows"))
        for index in range(self.network.count()):
            ip, _mac, _reachable, brand, name = self.network.itemData(index)
            text = normalize(f"{brand} {name}").replace("pixma", "")
            for model, package in DRIVER_PACKAGES.items():
                keys = (normalize(model).replace("pixma", ""), *MODEL_ALIASES.get(model, ()))
                if not any(key in text for key in keys):
                    continue
                check = package.get("check")
                if check and windir.joinpath(*check).is_file():
                    continue  # installed: the problem is elsewhere (power, Wi-Fi)
                label = name if normalize(brand) in normalize(name) else f"{brand} {name}".strip()
                return package, ("Canon" if "canon" in text or "ts3" in text else "Epson"), model, label, ip
        return None

    def offer_missing_driver(self):
        """Driver removed or never installed: offer the official one in a single click (Windows)."""
        if (not WINDOWS or self.device.count() or not self.searched_once or self.discoveries
                or getattr(self, "driver_offered", False) or getattr(self, "model_install_running", False)):
            return
        found = self.missing_driver()
        if not found:
            return
        package, brand, model, name, ip = found
        self.driver_offered = True
        self.set_status(tr("{name} answers on the network ({ip}), but its scanner driver is not installed.",
                           name=name, ip=ip), "error")
        answer = QMessageBox.question(self, tr("Scanner driver missing"), tr(
            "{name} was found on the network ({ip}), but its scanner driver is not installed, "
            "so the app cannot scan with it.\n\n"
            "Install the official {label} now? It is downloaded and installed automatically "
            "(a few minutes; Windows may ask for permission).", name=name, ip=ip, label=package["label"]))
        if answer == QMessageBox.StandardButton.Yes:
            self.install_driver(package, brand, model)

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
        allowed = self.allowed_sources
        if source == "auto" and allowed and "feeder" not in allowed:
            source = "glass"  # no document feeder: go straight to the flatbed
        elif source == "auto" and allowed == {"feeder"}:
            source = "feeder"
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
                QTimer.singleShot(0, self.guide_epson_network)
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
        if job.get("phone"):
            for photo in job["phone"]:
                if photo not in outputs:
                    Path(photo).unlink(missing_ok=True)
            self.set_status(tr("✓ Made {file} from {count} phone photo(s)", file=outputs[0].name,
                               count=len(job["phone"])), "ok")
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
        default_target = self.auto_translate.currentData() or ("zh-CN" if UI_LANG == "zh" else UI_LANG)
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

    # ---------- phone (LocalSend + QR page) ----------
    @staticmethod
    def phone_alias():
        return f"What the Scan · {socket.gethostname().split('.')[0]}"

    def phone_name_changed(self, text):
        self.settings.setValue("phone_name", text.strip())
        if self.phone_link:
            self.phone_link.alias = text.strip() or self.phone_alias()

    def start_phone(self, always=False):
        """Start receiving: always (Settings) or for a few minutes after pressing Phone."""
        if WINDOWS and not self.settings.value("phone_firewall_ok", False, type=bool):
            self.open_windows_firewall()
        if self.phone_link is None:
            self.phone_link = PhoneLink(self.phone_name.text().strip() or self.phone_alias(),
                                        QT_CACHE.parent, self.phone_bridge)
        self.phone_link.save_folder = self.output_folder()
        if not self.phone_link.start():
            self.set_status(tr("The phone connection could not start. Another program may be using the network "
                               "ports {ports}.", ports=f"{LOCALSEND_PORT}, {PHONE_WEB_PORT}"), "error")
            return False
        if not always:
            self.phone_until = max(self.phone_until, time.monotonic() + PHONE_OPEN_MINUTES * 60)
        self.phone_timer.start()
        return True

    def open_windows_firewall(self):
        """Phones must reach this PC: allow the phone ports from the local network only, once.
        Also removes "block" rules Windows made for this program if its question was ever dismissed."""
        name = "What the Scan (phone)"
        try:
            exists = run_hidden(["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"],
                                capture_output=True, timeout=15).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return
        if exists:
            self.settings.setValue("phone_firewall_ok", True)
            return
        answer = QMessageBox.question(self, tr("Phone"), tr(
            "So that your phone can send to this computer, Windows Firewall must let it in.\n\n"
            "Allow it now? Windows asks for permission once (only phones on your own network, "
            "only the ports of {app}).", app=APP_NAME))
        if answer != QMessageBox.StandardButton.Yes:
            return
        program = sys.executable
        commands = [
            f'netsh advfirewall firewall delete rule name=all dir=in program="{program}"',
            f'netsh advfirewall firewall add rule name="{name}" dir=in action=allow protocol=TCP '
            f'localport={LOCALSEND_PORT}-{PHONE_WEB_PORT + 10} remoteip=localsubnet profile=any',
            f'netsh advfirewall firewall add rule name="{name}" dir=in action=allow protocol=UDP '
            f'localport={LOCALSEND_PORT} remoteip=localsubnet profile=any',
        ]
        script = " & ".join(commands)
        env = dict(os.environ, WTS_FIREWALL=script)
        env.pop("PSModulePath", None)
        self.set_status(tr("Waiting for Windows permission (firewall)…"), "busy")
        QApplication.processEvents()
        try:
            run_hidden(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                        "$p=Start-Process -FilePath cmd.exe -ArgumentList ('/c ' + $env:WTS_FIREWALL) "
                        "-Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode"],
                       env=env, capture_output=True, timeout=120)
            ok = run_hidden(["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"],
                            capture_output=True, timeout=15).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            ok = False
        self.settings.setValue("phone_firewall_ok", ok)
        self.set_status(tr("✓ Windows Firewall lets your phone in now.") if ok else
                        tr("Windows Firewall was not changed, so the phone may not be able to send to this computer."),
                        "ok" if ok else "error")

    def phone_always_changed(self, on):
        if on:
            self.start_phone(always=True)
        else:
            self.phone_until = time.monotonic() + PHONE_OPEN_MINUTES * 60 if self.phone_link else 0

    def phone_tick(self):
        if not self.phone_link or not self.phone_link.running:
            self.phone_timer.stop()
            return
        always = self.phone_always.isChecked()
        left = int(self.phone_until - time.monotonic())
        if not always and left <= 0:
            if self.phone_dialog and self.phone_dialog.isVisible() or self.phone_link.session:
                self.phone_until = time.monotonic() + 60
                left = 60
            else:
                self.phone_link.stop()
                self.phone_timer.stop()
                if self.phone_dialog:
                    self.phone_dialog.receive_label.setText(tr("Receiving is off. Press Phone to open it again."))
                return
        if self.phone_dialog:
            name = self.phone_link.alias
            if always:
                text = tr("Receiving is on: the phone can send files to “{name}”.", name=name)
            else:
                text = tr("Receiving is on for {time}: the phone can send files to “{name}”.",
                          time=f"{left // 60}:{left % 60:02d}", name=name)
            self.phone_dialog.receive_label.setText(text)

    def open_phone(self):
        if not self.start_phone():
            return
        if self.phone_dialog is None:
            self.phone_dialog = PhoneDialog(self)
        files = [path for path in self.last_outputs if path.exists()]
        self.phone_tick()
        self.phone_dialog.present(files)

    def phone_device_found(self, device):
        self.phone_devices[device["fingerprint"]] = device
        if self.phone_dialog and self.phone_dialog.isVisible():
            self.phone_dialog.add_device(device)

    def phone_ask(self, request):
        files = request["files"]
        names = "\n".join(f"• {name}  ({readable_size(size)})" for name, size in files[:8])
        if len(files) > 8:
            names += "\n" + tr("… and {count} more", count=len(files) - 8)
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle(tr("Files from a phone"))
        box.setText(tr("“{sender}” wants to send {count} file(s):", sender=request["sender"], count=len(files)))
        box.setInformativeText(names + "\n\n" + tr("They will be saved in {folder}.",
                                                     folder=self.output_folder()))
        accept = box.addButton(tr("Accept"), QMessageBox.ButtonRole.AcceptRole)
        box.addButton(tr("Decline"), QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(accept)
        QTimer.singleShot(PHONE_ASK_SECONDS * 1000, box.reject)
        self.showNormal()
        self.raise_()
        self.activateWindow()
        QApplication.alert(self)
        if self.phone_link:
            self.phone_link.save_folder = self.output_folder()
        box.exec()
        request["ok"] = box.clickedButton() is accept
        request["event"].set()
        if request["ok"]:
            self.set_status(tr("Receiving files from {sender}…", sender=request["sender"]), "busy")

    def phone_received(self, paths, sender):
        paths = [Path(path) for path in paths if Path(path).exists()]
        if not paths:
            return
        self.last_outputs = paths
        self.last_text = ""
        photos = [path for path in paths if path.suffix.lower() in PHONE_IMAGES]
        self.set_status(tr("✓ Received {count} file(s) from {sender} in {folder}", count=len(paths),
                           sender=sender, folder=paths[0].parent.name), "ok")
        self.update_controls()
        if photos and self.phone_photos.currentData() == "scan":
            if self.busy():
                self.set_status(f"{self.status_text()}\n" + tr(
                    "The photos were saved as they are, because a scan is running."), "ok")
            else:
                self.photos_to_pdf(photos)

    def photos_to_pdf(self, photos):
        """Phone photos → PDF through NAPS2 (same OCR / Word / JPG settings as a scan)."""
        folder = photos[0].parent
        base = folder / datetime.now().strftime("Phone-%Y%m%d-%H%M%S")
        doc = self.doc_format()
        ocr = self.ocr_languages() if self.ocr_on.isChecked() or doc else []
        self.job = {"kind": "both" if self.save_format() == "both" else "pdf", "base": base, "replace": False,
                    "auto": False, "source": "glass", "ocr": ocr, "doc": doc, "phone": photos}
        backend = get_backend()
        if not backend:
            self.job = None
            return

        def run():
            job = self.job
            if not job:
                return
            self.pending = folder / f".scan-{uuid4().hex}.pdf"
            args = ["-o", str(self.pending), "-i", ";".join(str(photo) for photo in photos), "-n", "0",
                    "--noprofile"]
            args += ["--ocrlang", "+".join(job["ocr"])] if job["ocr"] else ["--disableocr"]
            self.job_device = None
            self.cancelled = False
            message = tr("Making a PDF from {count} phone photo(s)…", count=len(photos))
            if job["ocr"]:
                message += tr(" Recognising text (OCR)…")
            self.set_status(message, "busy")
            self.process.start(backend[0], backend[1:] + args)
            self.update_controls()
            self.update_led()

        self.ensure_ocr(ocr, run)

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
        if self.phone_link:
            self.phone_link.stop()
        if self.phone_dialog:
            self.phone_dialog.close()
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
    if SMOKE_FILE:
        started = time.monotonic()

        def smoke_done():
            if (window.discoveries or not window.searched_once) and time.monotonic() - started < 40:
                QTimer.singleShot(500, smoke_done)
                return
            if MAC:
                try:
                    probe = Path(tempfile.gettempdir()) / "whatthescan-airdrop.txt"
                    probe.write_text("AirDrop check")
                    smoke(f"AirDrop: {'available' if airdrop([probe], check_only=True) else 'not available'}")
                except Exception as exc:
                    smoke(f"ERROR AirDrop check: {exc}")
            smoke(f"OK window started · {window.device.count()} scanner(s) · status: {window.status_text()}")
            app.exit(0)

        default_hook = sys.excepthook
        sys.excepthook = lambda kind, value, tb: (smoke(f"ERROR {kind.__name__}: {value}"),
                                                  default_hook(kind, value, tb))
        QTimer.singleShot(1500, smoke_done)
    sys.exit(app.exec())

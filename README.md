<p align="center"><img src="assets/WhatTheScan-logo.png" alt="What the Scan?!" width="520"></p>

<p align="center"><b>Scanner busy? Now you know who.</b><br>
Scan to PDF, JPG, Word or OpenDocument from Epson, Canon &amp; HP scanners, with OCR, translation
and a status light that shows when someone else on the network is using the scanner.</p>

<p align="center">
<img src="assets/screenshots/main-en-dark.png" width="48%">
<img src="assets/screenshots/main-gr-light.png" width="48%">
</p>

## Features

- **One-click scanning.** It finds every scanner on every driver (TWAIN, WIA, eSCL, SANE, Apple) at the same time and connects automatically.
- **Output formats:**
  - PDF, JPG or PDF + JPG
  - an optional editable document: Word (.docx) or OpenDocument (.odt)
- **Status light:**
  - 🟢 ready
  - 🟡 idle
  - 🔴 in use: by you, by another PC on the network running the app, or by the scanner itself (eSCL status)
  - Anyone who tries to scan while the light is red gets a clear "please wait" message and a beep when the scanner is free.
- **OCR (searchable PDFs).**
  - Languages are chosen automatically (English + Greek + your system language), or you pick them by hand.
  - Languages download automatically the first time they are used.
- **Translation** of the recognised text with Google Translate (free), MyMemory (free) or your own LibreTranslate server, either automatically after every scan or from the Text window.
- **Paper source "Auto":** uses the document feeder when it has paper, otherwise the flatbed glass.
- **Send to your phone** on the same Wi-Fi: phones with the free LocalSend app, a QR code page for any phone, and AirDrop on a Mac. Photos from the phone can be saved or turned into a PDF like a scan.
- **11 languages:** English, Ελληνικά, Français, Deutsch, Italiano, Español, Română, Čeština, Русский, 日本語, 中文 (简体). **Auto / Light / Dark** theme.
- **Drivers:**
  - Epson L14150 and Canon PIXMA TS3150: one-click driver install, with the publisher signature checked. See [Epson Scan 2 driver](#epson-scan-2-driver-epson-l14150-and-other-epson-scanners).
  - Other Epson, Canon and HP models (2024–2026): the Driver setup button opens the right driver page.
  - **Brother** all-in-ones and ADS scanners from 2024 (MFC-L2820DW, DCP-L3560CDW, MFC-J4355DW, MFC-J6960DW, ADS-1800W…): they scan over the network with no driver (AirPrint / eSCL), or with Brother's driver package; Driver setup opens Brother's download page with the model copied.
- **Over-the-air updates** from this repository's GitHub releases (SHA-256 checked).

## Supported scanner models

What the Scan works with **any scanner that NAPS2 can reach** (TWAIN, WIA, eSCL / AirPrint, SANE, Apple ICA). The models below are known to the app: it recognises them, picks the right driver page and, where marked, installs the driver in one click.

Η εφαρμογή δουλεύει με **κάθε σαρωτή που βλέπει το NAPS2**. Τα παρακάτω μοντέλα τα αναγνωρίζει η εφαρμογή, ανοίγει τη σωστή σελίδα driver και, όπου σημειώνεται, εγκαθιστά τον driver με ένα κλικ.

### Epson

Driver: Epson Scan 2 (TWAIN / WIA). **L14150: one-click driver install.** See [Epson Scan 2 driver](#epson-scan-2-driver-epson-l14150-and-other-epson-scanners).

| Series | Year | Models |
|---|---|---|
| DS / ES / RR | 2024 | DS-800WN, DS-900WN |
| DS / ES / RR | 2025 | DS-1730, DS-1760WN, DS-530 II TAA, DS-730N TAA, DS-870 TAA |
| DS / ES / RR | 2026 | DS-530X, DS-785W, ES-550W, ES-590W, RR-620W |
| EcoTank / L series | earlier | L14150 |

### Canon

Driver: Canon MP Drivers / IJ Scan Utility, or driverless over the network (eSCL). **PIXMA TS3150 (TS3100 series): one-click driver install.**

| Series | Year | Models |
|---|---|---|
| PIXMA | earlier | PIXMA TS3150 |
| PIXMA | 2025 | TS4140i, TS4150i, TS4320, TS6520, TS6540i, TS6550i, TS7550i, TR7120 |
| MAXIFY | 2025 | GX5150, GX6150, GX7150, GX5170, GX6170, GX7170 |
| imageCLASS | 2025 | MF460 II |
| imageFORMULA | 2025 | DR-C340, DR-C350 |
| imageFORMULA | 2026 | R40II |

### HP

Driverless over the network (AirPrint / eSCL), or the HP Smart / HP Scan driver.

| Series | Year | Models |
|---|---|---|
| Smart Tank | — | 520, 525, 580, 585, 720, 750, 790, 5101, 5105, 5106, 6001, 6005, 6006, 7001, 7005, 7006, 7301, 7305, 7306, 7602, 7605 |
| ScanJet Pro | — | 2000 s2, 2600 f1, 3000 s4, 3600 f1, N4000 snw1, N4600 fnw1 |
| ScanJet Enterprise Flow | — | 5000 s5, 7000 s3, N6600 fnw1, N7000 snw1, 9000 s1, N9120 fn2 |

### Brother

Driverless over the network (AirPrint / eSCL), or Brother's Full Driver & Software Package (TWAIN / WIA, brscan on Linux).

| Series | Year | Models |
|---|---|---|
| MFC / DCP / HL laser | 2024 | MFC-L2800DW, MFC-L2820DW, MFC-L2880DW, MFC-L2900DW, MFC-L2920DW, MFC-L2960DW, MFC-L2980DW, DCP-L2640DW, HL-L2480DW, DCP-L5510DW, MFC-L5710DN, MFC-L5710DW, MFC-L5915DW, MFC-L6710DW, MFC-L6910DN |
| MFC / DCP colour laser | 2024 | DCP-L3520CDW, DCP-L3560CDW, MFC-L3755CDW, MFC-L3760CDW, MFC-L8390CDW |
| MFC / DCP inkjet & laser | 2025 | MFC-J4355DW, MFC-J4555DW, MFC-J6760DW, MFC-J6960DW, MFC-L8730CDW, MFC-L8930CDW, MFC-EX575, DCP-J1260W |
| MFC A3 inkjet | 2026 | MFC-J3660DW, MFC-J3960DW, MFC-J6560DW, MFC-J6975DW |
| ADS document scanners | — | ADS-1300, ADS-1800W |

**Other brands** (Kyocera, Ricoh, Xerox, Samsung, Lexmark and others): any network scanner that supports eSCL / AirPrint is found and used automatically, with the status light and paper sources it reports.

## Install

Download from the [latest release](https://github.com/nikkpap/What_the_Scan-/releases/latest):

| System | File | How |
|---|---|---|
| Windows 10/11 (64-bit) | `WhatTheScan-windows-x64.exe` | Double-click it. If SmartScreen appears: *More info › Run anyway*. |
| Linux (x64) | `WhatTheScan-linux-x64` | `chmod +x WhatTheScan-linux-x64`, then open it. |
| macOS Apple Silicon / Intel | `WhatTheScan-macos-arm64.zip` / `WhatTheScan-macos-x64.zip` | Unzip it and drag *What the Scan* to Applications. First start: *System Settings › Privacy & Security › Open Anyway*. |
| Any OS with Python 3 | `WhatTheScan.pyw` | Double-click it. It installs PyQt6, PyMuPDF and python-docx itself. |

The first start installs the [NAPS2](https://www.naps2.com) scanning engine automatically, if it is
missing. Install your scanner's own driver if it needs one (Settings › Scanner › Driver setup).

### Offline installation

Download **`WhatTheScan-offline.zip`** from the same release and put it in the same folder as the
app. On first start the app installs everything from it, with no internet:

- NAPS2
- the Python packages
- 64-bit Python (Windows)
- the Epson L14150 and Canon TS3150 drivers
- OCR for 18 languages

Every file is still checked the same way as a download. Without the zip the app downloads what it
needs. Βάλε το zip δίπλα στην εφαρμογή και όλα εγκαθίστανται χωρίς internet.

## Εγκατάσταση (Ελληνικά)

- **Windows:** κατέβασε το `WhatTheScan-windows-x64.exe` από το [τελευταίο release](https://github.com/nikkpap/What_the_Scan-/releases/latest) και άνοιξέ το.
- **Linux:** κατέβασε το `WhatTheScan-linux-x64`, δώσε `chmod +x` και άνοιξέ το.
- **Mac ή οτιδήποτε με Python 3:** κατέβασε το `WhatTheScan.pyw` και άνοιξέ το.

Την πρώτη φορά εγκαθιστά μόνο του ό,τι χρειάζεται. Πάτα **Σάρωση** και τα αρχεία αποθηκεύονται στα
*Έγγραφα › What the Scan*. Όλες οι ρυθμίσεις είναι αυτόματες από προεπιλογή και αλλάζουν από τις **Ρυθμίσεις**.

## Epson Scan 2 driver (Epson L14150 and other Epson scanners)

**English**

Windows needs Epson's own driver, **Epson Scan 2**, to scan from an Epson printer/scanner.

1. **Install the driver.** Open What the Scan. If the scanner answers on the network but the driver is
   missing, the app asks *"Scanner driver missing — install now?"*. Click **Yes**. The app downloads the official
   driver from Epson (European server, Latin America as a fallback), checks Epson's digital signature and starts
   the installer. Click **Next / Install** in Epson's windows if they appear.
   You can also start it any time from **Settings › Scanner › Driver setup**.
2. **Tell Epson Scan 2 where the scanner is (one time per PC).** After a new or repeated driver install, Epson Scan 2
   does not know the scanner's network address. When you press **Scan**, What the Scan shows the steps and has
   already copied the address for you:
   1. Click **Open Epson Scan 2 Utility**.
   2. At the top, in **Scanner**, choose **Settings**.
   3. Click **Add**, choose **Enter address**, press **Ctrl+V** and click **OK**.
   4. Click **OK**, close the utility and press **Scan** again.
3. **Still not scanning?**
   - The scanner must be on and on the same Wi-Fi/network as the PC (the address is in **Settings › Scanner › Network**).
   - Give the printer a fixed address in your router, so it does not change after a restart.
   - In Epson Scan 2 Utility, use **Other › Reset** and repeat step 2.
   - Uninstalling the driver also removes step 2: do it again after reinstalling.

Download page: [Epson Download Center · L14150](https://download-center.epson.com/softwares/?device_id=L14150%20Series)
(*Scanner Driver and Epson Scan 2 Utility*).

**Ελληνικά**

Τα Windows χρειάζονται τον driver της Epson, το **Epson Scan 2**, για να σαρώνουν από εκτυπωτή/σαρωτή Epson.

1. **Εγκατάσταση driver.** Άνοιξε το What the Scan. Αν ο σαρωτής απαντά στο δίκτυο αλλά λείπει ο driver, η εφαρμογή
   ρωτά *«Λείπει ο driver του σαρωτή — εγκατάσταση τώρα;»*. Πάτα **Ναι**. Κατεβαίνει ο επίσημος driver της Epson
   (ευρωπαϊκός server, εφεδρικός ο server Λατινικής Αμερικής), ελέγχεται η ψηφιακή υπογραφή της Epson και ξεκινά η
   εγκατάσταση. Πάτα **Next / Install** στα παράθυρα της Epson αν εμφανιστούν.
   Το ίδιο γίνεται κι από **Ρυθμίσεις › Σαρωτής › Εγκατάσταση driver**.
2. **Πες στο Epson Scan 2 πού είναι ο σαρωτής (μία φορά σε κάθε PC).** Μετά από νέα εγκατάσταση ή επανεγκατάσταση
   του driver, το Epson Scan 2 δεν ξέρει τη διεύθυνση του σαρωτή. Όταν πατήσεις **Σάρωση**, το What the Scan σού
   δείχνει τα βήματα και έχει ήδη αντιγράψει τη διεύθυνση:
   1. Πάτα **Άνοιγμα Epson Scan 2 Utility**.
   2. Πάνω, στο **Scanner** (Σαρωτής), διάλεξε **Settings** (Ρυθμίσεις).
   3. Πάτα **Add** (Προσθήκη), διάλεξε **Enter address** (Εισαγωγή διεύθυνσης), πάτα **Ctrl+V** και **OK**.
   4. Πάτα **OK**, κλείσε το utility και ξαναπάτα **Σάρωση**.
3. **Ακόμα δεν σαρώνει;**
   - Ο σαρωτής πρέπει να είναι αναμμένος και στο ίδιο Wi-Fi/δίκτυο με το PC (η διεύθυνση φαίνεται στις
     **Ρυθμίσεις › Σαρωτής › Δίκτυο**).
   - Δώσε στον εκτυπωτή σταθερή διεύθυνση από το router, για να μην αλλάζει μετά από επανεκκίνηση.
   - Στο Epson Scan 2 Utility πάτα **Other › Reset** (Άλλο › Επαναφορά) και κάνε ξανά το βήμα 2.
   - Αν απεγκαταστήσεις τον driver, χάνεται και το βήμα 2: κάν' το ξανά μετά την εγκατάσταση.

## Publishing an update

1. Raise `VERSION` in `WhatTheScan.pyw` (for example to `1.0.2`) and update `RELEASE_NOTES.md`.
2. Commit and push to `main`.
3. If release `v1.0.2` doesn't exist yet, GitHub Actions builds the Windows .exe and the Linux
   binary and publishes the release (it creates the tag itself), with all files and their
   `.sha256` checksums.

Every copy (.exe, Linux binary or .pyw) finds its own file in the release and offers the update
from **Help › Check for updates**. It can also check by itself on startup.

## Signing the Windows .exe

GitHub signs the .exe automatically when the repository has your code-signing certificate:

1. Export your certificate as a **.pfx** with a password (for example from CertifiCat).
2. Turn it into text. In PowerShell, in the folder with the file:
   `[Convert]::ToBase64String([IO.File]::ReadAllBytes("$PWD\cert.pfx")) | Set-Clipboard`
3. On GitHub: **Settings › Secrets and variables › Actions › New repository secret**:
   - `WINDOWS_CERT_PFX`: paste the text
   - `WINDOWS_CERT_PASSWORD`: the .pfx password
4. **Actions › Build and release › Run workflow** rebuilds the current release, now signed.
   Every later release is signed automatically.

A self-signed certificate shows your name as the publisher only on PCs that trust it (install its
.cer in *Trusted Root Certification Authorities* and *Trusted Publishers*). To remove the
SmartScreen warning on every PC you need a certificate from a public certificate authority.

## Signing and notarizing the Mac app (optional)

With an Apple Developer Program membership, add these repository secrets and every release is
signed with your Developer ID and notarized, so macOS opens the app with no warning:

- `MACOS_CERT_P12`: your *Developer ID Application* certificate (.p12) as base64 (`base64 -i cert.p12 | pbcopy`)
- `MACOS_CERT_PASSWORD`: the .p12 password
- `APPLE_ID`: your Apple ID e-mail
- `APPLE_TEAM_ID`: your Team ID
- `APPLE_APP_PASSWORD`: an app-specific password from appleid.apple.com

Without them the Mac app is ad-hoc signed and users confirm it once in
*System Settings › Privacy & Security*.

## Credits

Made by **Nikolaos K. Paridis** ([nikkpap](https://github.com/nikkpap)), ALU DEV TEAM.

Built with NAPS2 (GPL) and Tesseract OCR, PyMuPDF, python-docx and PyQt6.

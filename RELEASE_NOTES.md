## What the Scan?! v1.0.2

**New: offline installation**
- **`WhatTheScan-offline.zip`:** download it from this release and put it next to the app (the .exe, the Linux binary or the .pyw). The app then installs everything from it, with no internet:
  - the NAPS2 scanning engine (Windows, macOS, Linux)
  - PyQt6, PyMuPDF and python-docx for Python 3.10–3.14 (Windows, macOS, Linux)
  - 64-bit Python for Windows
  - the Epson L14150 and Canon TS3150 drivers
  - OCR for 18 languages
- **Same checks:** every file goes through the same signature or checksum check as a download.
- **Without the zip:** the app downloads what it needs, as before.

**Improvements**
- Smaller installation: PyMuPDF stays on the 1.x series, which doesn't need the heavy AI layout extras.

**Downloads**
- **Windows:** `WhatTheScan-windows-x64.exe` (signed)
- **Linux:** `WhatTheScan-linux-x64`. Run `chmod +x`, then open it.
- **macOS / any OS with Python 3:** `WhatTheScan.pyw`
- **Offline package for all OS:** `WhatTheScan-offline.zip`

**Ελληνικά**
- **Νέο:** το `WhatTheScan-offline.zip`. Βάλ' το δίπλα στην εφαρμογή και όλα εγκαθίστανται χωρίς internet.
- **Χωρίς το zip:** η εφαρμογή κατεβάζει ό,τι χρειάζεται, όπως πάντα.

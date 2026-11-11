## What the Scan?! v1.0.7

**Linux: works on a fresh installation**
- **pip:** Debian and Ubuntu often ship Python without pip, which used to stop setup. The app now installs pip by itself (apt or dnf, asking for the administrator password).
- **Window libraries:** the app installs every system library the window needs (glib, EGL, X11/xcb…). If one package name doesn't exist on your distribution, it installs the rest one by one.
- **Setup progress:** without tkinter, the app shows the system's own progress window (zenity) instead of working silently.
- **Tested on fresh systems:** every release is now started on fresh Debian 12, Ubuntu 24.04 and Fedora 41 systems with only Python installed. The app has to set everything up by itself (pip, PyQt6, libraries, NAPS2), or the release is not published.
- **Updates:** the Linux binary's self-update was tested from v1.0.5 to v1.0.6. It downloads, checks the checksum, replaces itself and starts.

**Ελληνικά**
- **Linux:** η εφαρμογή εγκαθιστά πλέον μόνη της το pip και τις βιβλιοθήκες γραφικών σε «γυμνό» Linux.
- **Πρόοδος:** αν λείπει το tkinter, δείχνει την πρόοδο της εγκατάστασης σε παράθυρο του συστήματος.
- **Έλεγχος:** κάθε έκδοση δοκιμάζεται σε φρέσκα Debian 12, Ubuntu 24.04 και Fedora 41 πριν δημοσιευτεί.

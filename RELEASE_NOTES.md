## What the Scan?! v1.0.6

**Fix: updates and downloads on Mac**
- **The problem:** Python from python.org on macOS comes without security certificates, so every HTTPS connection failed (`CERTIFICATE_VERIFY_FAILED`). That broke update checks, the NAPS2 download and translation. The same could happen in the .app.
- **The fix:** the app now always uses certifi's certificate list as well as the system's. It installs certifi by itself, and in the meantime uses the copy built into pip. certifi is also included in the .app, .exe and Linux builds.
- **Clear messages instead of a cryptic error:**
  - when macOS runs the app from a temporary read-only copy (opened straight from Downloads). Drag it to Applications first.
  - when the app's folder can't be written to.

**Διόρθωση: ενημερώσεις και λήψεις στον Mac**
- **Το πρόβλημα:** η Python από το python.org στον Mac δεν έχει πιστοποιητικά ασφαλείας, οπότε οι ενημερώσεις, οι λήψεις και η μετάφραση αποτύγχαναν.
- **Η διόρθωση:** η εφαρμογή χρησιμοποιεί πλέον τα δικά της πιστοποιητικά (certifi) και τα εγκαθιστά μόνη της.
- **Αν τρέχεις το .app κατευθείαν από τις Λήψεις:** η εφαρμογή σού ζητά να το σύρεις πρώτα στις Εφαρμογές.

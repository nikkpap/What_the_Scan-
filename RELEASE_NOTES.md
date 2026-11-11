## What the Scan?! v1.0.5

**Fix:** on a PC without NAPS2, v1.0.4 stopped at setup with "name 'app_path' is not defined". Fixed. Every release is now checked on GitHub with a real first start before it is published.

**Διόρθωση:** σε PC χωρίς NAPS2 η v1.0.4 σταματούσε στην εγκατάσταση με το μήνυμα «name 'app_path' is not defined». Διορθώθηκε, και κάθε έκδοση ελέγχεται πλέον στο GitHub με πραγματική πρώτη εκκίνηση πριν δημοσιευτεί.

### From v1.0.4

**New: HP Smart Tank support, including the Smart Tank 750**
- **Model list:** the 21 HP Smart Tank all-in-ones (520 to 7605), so the right model is picked automatically.
- **Network search:** "Find on network" now also finds HP printers and every other AirPrint / eSCL scanner (Brother, Kyocera, Ricoh…), using mDNS. Epson and Canon devices are found as before.
- **Paper sources:** the app asks a network scanner which paper sources it has (flatbed, feeder, feeder both sides) and greys out the rest. For example, the Smart Tank 750 has a feeder but cannot scan both sides.
- **Without a network connection:** for known models (Smart Tank 750, 7001/7005, Canon TS3150) the app uses a built-in list.
- **"Auto" paper source:** goes straight to the flatbed on scanners without a feeder, which is faster.

**Ελληνικά**
- **Νέο:** υποστήριξη για HP Smart Tank, μαζί με το 750.
- **Εύρεση στο δίκτυο:** βρίσκει και εκτυπωτές HP, και κάθε σαρωτή AirPrint.
- **Πηγές χαρτιού:** όσες δεν έχει ο σαρωτής, π.χ. η διπλή όψη στο 750, εμφανίζονται γκρι.

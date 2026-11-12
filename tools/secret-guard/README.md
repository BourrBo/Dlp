# Enterprise Secret Guard - Combined Milestones 2 and 3

Standalone scanner that finds secrets **and** Indian customer identifiers in
spreadsheets, CSV/TSV, source code, logs, text files and data exports, using
checksums, structural rules, context scoring and exclusions to keep false
positives low. It combines the Milestone 2 credential signatures and entropy
checks with the Milestone 3 India identifier detectors. It remains a standalone
CLI and is not connected to the DLP API. No third-party dependencies (Python
3.9+).

Secret reports expose a SHA-256 fingerprint rather than any part of the matched
credential. Indian identifier detectors use type-specific masking.

## Run it (VS Code or any terminal)

```bash
python -m unittest discover -s tests -t .      # 115 tests
python scripts/demo.py                         # 10-record synthetic customer sheet
python scripts/evaluate.py                     # precision/recall on the smoke corpus
python -m secretguard scan data/               # full redacted report
python -m secretguard scan data/ --format sarif -o report.sarif
python -m secretguard rules                    # list detectors
```

In VS Code: open the folder, then use **Run and Debug** (launch configs for the
demo, evaluation, scan and tests are included) or the Testing panel.

CLI options: `--format text|json|sarif`, `--output FILE`, `--min-confidence 0.30`,
`--fail-on low|medium|high|critical` (exit code 1 for CI gating),
`--no-secrets`, `--no-india`. Exit codes: 0 clean, 1 findings at/above
threshold, 2 error.

## Architecture

```
Scanner (files, CSV/TSV/XLSX/text, overlap resolution, reporting)
   |
   +-- detectors/secrets.py          M2 credential signatures, JWT role and entropy rules
   +-- detectors/india/
         aadhaar.py  pan.py  gstin.py  ifsc.py
         bank_account.py  upi.py  mobile.py
         verhoeff.py  common.py (context, exclusions, masking)
   |
Finding: rule - severity - confidence - file - line - column - field - redacted evidence
```

## Validation and context rules

| Identifier | Validation | Context handling |
|---|---|---|
| Aadhaar | 12 digits, first digit 2-9, Verhoeff checksum, rejects all-same, repeating-block and 6+ digit runs | `Aadhaar`/`UIDAI` = 0.95, bare `UID` = 0.75, unlabeled = 0.45 (0.60 if 4-4-4 grouped) |
| PAN | `AAAPL1234C`, 4th char in `A B C F G H J K L P T` | `PAN`/tax-ID label = 0.95; unlabeled uppercase = 0.55; lowercase needs a label |
| GSTIN | state code (01-38, 97, 99), embedded PAN structure, entity char, `Z`, mod-36 checksum | label = 0.98; unlabeled valid = 0.85 |
| IFSC | 4 letters + `0` + 6 alphanumerics | label = 0.95; unlabeled known bank code = 0.60; unlabeled unknown bank code = 0.25 (suppressed) |
| Bank account | 9-18 digits, >=4 distinct digits, no repeats or long runs | **Mandatory** account label (`A/C No`, `Account Number`, `bank_account`...) = 0.85; never flagged on digits alone |
| UPI | `name@handle`, handle in PSP allowlist (extendable) | label = 0.95; unlabeled = 0.70; `person@gmail.com` and `x@ybl.com` are never UPI |
| Indian mobile | 10 digits starting 6-9, optional `+91`/`0091`/`0` | phone label = 0.90-0.95; unlabeled = 0.40 (0.65 with `+91`) |

Safeguards applied across detectors:

- **The nearest label wins.** `pan=... aadhaar=...` does not let one label leak onto the other value.
- **Timestamp exclusions.** Compact dates (`YYYYMMDDHHMM`), Unix epochs, and values preceded by words like `timestamp`, `created_at`, `date` are dropped. The demo's C009 is a timestamp that *passes* the Aadhaar checksum and is still ignored.
- **Reference-style context.** `order_id`, `invoice`, `txn`, `reference_no`... suppress unlabeled matches. C010 is a checksum-valid 12-digit reference that is ignored.
- **Overlap resolution.** If two detectors claim the same span, the higher-confidence interpretation wins (a labeled bank account beats an unlabeled Aadhaar reading).
- **No raw values in output.** Findings carry only redacted evidence (`XXXX XXXX 1234`, `AB*******F`, `ra****@oksbi`); tests assert that no text/JSON/SARIF report contains a raw value.

Severity = detector base severity (Aadhaar CRITICAL; PAN, bank account HIGH; UPI, mobile MEDIUM;
GSTIN, IFSC LOW because they are largely public business/branch identifiers), lowered one
level below confidence 0.60 and two levels below 0.40.

## Supported inputs

Text-like files of any extension (logs, source, JSON, Markdown...), `.csv`/`.tsv`
(first row used as header context), and `.xlsx`/`.xlsm` (stdlib parser; header row gives
column context). Binary files, symlinks and files over 25 MB are skipped and listed.
Not yet supported: `.docx`, `.pdf`, `.xls`, UTF-16 text, archives.

## Extending

```python
from secretguard.detectors.base import Detector
from secretguard.models import Hit

class MyEngine(Detector):
    rule_id, category = "secret.m2", "secret"
    def detect(self, text, hint=""): ...   # return [Hit(...)]
    def redact(self, value): ...

from secretguard.scanner import Scanner
Scanner([MyEngine(), *all_india_detectors()]).scan_path("data/")
```

Add UPI handles or IFSC bank codes with `UpiDetector(extra_handles={...})` and
`IfscDetector(extra_bank_codes={...})`.

## Evaluation: read this before quoting numbers

`scripts/evaluate.py` scores the 10-record synthetic sheet: 7 TP, 0 FP, 0 FN, 3 TN
(precision 1.000, recall 1.000). That is a **hand-curated smoke test**, written by the same
people who wrote the rules, and says nothing about production accuracy. Before claiming
enterprise accuracy, evaluate on a larger, independently labeled holdout corpus drawn from
real data shapes (with proper data-handling approvals), and track per-identifier precision
and recall.

Known limitations: unlabeled values rely on checksums/structure alone (Aadhaar's checksum
passes ~1 in 10 random 12-digit numbers); identifiers split across cells/lines or
obfuscated/encoded are not detected; the UPI handle and IFSC bank-code lists are
non-exhaustive; label vocabulary is English/transliterated only.

## Data handling

All demo data is fabricated. Numeric values are random but structurally valid, so they
may coincidentally resemble real identifiers; do not replace them with real data.
This tool is a detection aid, not a compliance certification.

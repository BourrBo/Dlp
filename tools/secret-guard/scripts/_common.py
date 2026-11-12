import csv
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# The engine lives in the backend package: <repo>/dlp-backend/secretguard
BACKEND = os.path.abspath(os.path.join(ROOT, "..", "..", "dlp-backend"))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from secretguard.detectors import default_detectors  # noqa: E402
from secretguard.scanner import Scanner  # noqa: E402

DATA = os.path.join(ROOT, "data")
CSV_PATH = os.path.join(DATA, "synthetic_customers.csv")
LABELS_PATH = os.path.join(DATA, "synthetic_customers_labels.csv")


def load_customers():
    with open(CSV_PATH, newline="") as fh:
        return [r["customer_id"] for r in csv.DictReader(fh)]


def load_expected():
    with open(LABELS_PATH, newline="") as fh:
        return {r["customer_id"]: r["expected_rule"] for r in csv.DictReader(fh)}


def findings_by_customer():
    """Map customer_id -> set of rule_ids. Row i sits on physical line i+1."""
    ids = load_customers()
    findings = Scanner(default_detectors()).scan_file(CSV_PATH)
    out = {cid: set() for cid in ids}
    for f in findings:
        out[ids[f.line - 2]].add(f.rule_id)
    return out


def evaluate():
    expected, got = load_expected(), findings_by_customer()
    tp = fp = fn = tn = 0
    rows = []
    for cid in load_customers():
        exp, found = expected[cid], got[cid]
        if exp:
            hit = exp in found
            tp += hit
            fn += (not hit)
            fp += len(found - {exp}) > 0
            status = "TP" if hit and not (found - {exp}) else ("FN" if not hit else "TP+FP")
        else:
            fp += len(found) > 0
            tn += (not found)
            status = "TN" if not found else "FP"
        rows.append((cid, exp or "(none)", ", ".join(sorted(found)) or "(none)", status))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return rows, dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=precision, recall=recall)

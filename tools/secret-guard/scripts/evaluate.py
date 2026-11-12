"""Precision/recall on the tiny synthetic smoke corpus.

IMPORTANT: this is a hand-curated smoke test, NOT a production accuracy
measurement. Publish accuracy claims only after evaluating on a larger,
independently labeled holdout corpus.
"""
import json
import sys

from _common import evaluate

rows, m = evaluate()
if "--json" in sys.argv:
    print(json.dumps(m, indent=2))
else:
    print("True positives : %d\nFalse positives: %d\nFalse negatives: %d\nTrue negatives : %d"
          % (m["tp"], m["fp"], m["fn"], m["tn"]))
    print("Precision      : %.3f\nRecall         : %.3f" % (m["precision"], m["recall"]))
    print("\nCAVEAT: tiny synthetic smoke corpus - not a production accuracy measurement.")
sys.exit(0 if m["fp"] == 0 and m["fn"] == 0 else 1)

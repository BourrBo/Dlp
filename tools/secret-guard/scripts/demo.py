"""Run the scanner over the synthetic customer sheet and print a per-record table."""
from _common import evaluate, load_expected

NAMES = {"": "Skipped (correctly ignored)"}
rows, _ = evaluate()
print("Synthetic customer-sheet demonstration (10 fabricated records)\n")
print("%-6s %-20s %-20s %s" % ("ID", "Expected", "Detected", "Result"))
print("-" * 62)
for cid, exp, got, status in rows:
    print("%-6s %-20s %-20s %s" % (cid, exp, got, status))
print("\nSee `python -m secretguard scan data/` for the full redacted report.")

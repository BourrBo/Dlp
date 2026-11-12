import os
import sys
import unittest

TOOLS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools", "secret-guard"))
sys.path.insert(0, os.path.join(TOOLS, "scripts"))
from _common import evaluate, findings_by_customer, load_expected  # noqa: E402

from tests.secretguard_engine.helpers import scan  # noqa: E402


class SyntheticSheetTests(unittest.TestCase):
    def setUp(self):
        self.got = findings_by_customer()
        self.expected = load_expected()

    def test_each_positive_record_detected_as_expected_family(self):
        for cid in ["C001", "C002", "C003", "C004", "C005", "C006", "C007"]:
            self.assertEqual(self.got[cid], {self.expected[cid]}, cid)

    def test_ordinary_email_skipped(self):
        self.assertEqual(self.got["C008"], set())

    def test_checksum_valid_timestamp_skipped(self):
        self.assertEqual(self.got["C009"], set())

    def test_checksum_valid_reference_skipped(self):
        self.assertEqual(self.got["C010"], set())

    def test_hard_negatives_would_pass_checksum_without_context(self):
        # prove the exclusions matter: these values pass the Verhoeff checksum
        import csv
        with open(os.path.join(TOOLS, "data", "synthetic_customers.csv")) as fh:
            rows = {r["customer_id"]: r for r in csv.DictReader(fh)}
        for cid, col in (("C009", "last_login_ts"), ("C010", "reference_no")):
            from secretguard.detectors.india import verhoeff
            self.assertTrue(verhoeff.is_valid(rows[cid][col]), cid)

    def test_metrics_on_smoke_corpus(self):
        _, m = evaluate()
        self.assertEqual((m["tp"], m["fp"], m["fn"], m["tn"]), (7, 0, 0, 3))
        self.assertEqual((m["precision"], m["recall"]), (1.0, 1.0))


if __name__ == "__main__":
    unittest.main()

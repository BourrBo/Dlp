import unittest

from tests.secretguard_engine.helpers import AADHAAR_BODIES, invalid_checksum, make_aadhaar, rules, scan


class AadhaarTests(unittest.TestCase):
    def test_labeled_valid_high_confidence(self):
        f = scan("Aadhaar: %s" % make_aadhaar())
        self.assertEqual([x.rule_id for x in f], ["india.aadhaar"])
        self.assertGreaterEqual(f[0].confidence, 0.9)

    def test_multiple_valid_values(self):
        for body in AADHAAR_BODIES:
            self.assertIn("india.aadhaar", rules("aadhaar no %s" % make_aadhaar(body)))

    def test_grouped_formats(self):
        a = make_aadhaar()
        for text in ("Aadhaar %s %s %s" % (a[:4], a[4:8], a[8:]),
                     "Aadhaar %s-%s-%s" % (a[:4], a[4:8], a[8:])):
            self.assertIn("india.aadhaar", rules(text))

    def test_invalid_checksum_rejected_even_when_labeled(self):
        self.assertEqual(rules("Aadhaar: %s" % invalid_checksum(make_aadhaar())), [])

    def test_first_digit_zero_or_one_rejected(self):
        for lead in "01":
            self.assertEqual(rules("Aadhaar: %s" % make_aadhaar(lead + "7291836502")), [])

    def test_all_same_digits_rejected(self):
        self.assertEqual(rules("Aadhaar: 222222222222"), [])

    def test_sequential_digits_rejected(self):
        self.assertEqual(rules("Aadhaar: 234567890123"), [])

    def test_repeating_block_rejected(self):
        self.assertEqual(rules("Aadhaar: 472947294729"), [])

    def test_unlabeled_ungrouped_lower_confidence(self):
        f = scan("value %s end" % make_aadhaar())
        self.assertEqual(len(f), 1)
        self.assertLess(f[0].confidence, 0.6)

    def test_unlabeled_grouped_beats_ungrouped(self):
        a = make_aadhaar()
        grouped = scan("v %s %s %s" % (a[:4], a[4:8], a[8:]))[0].confidence
        plain = scan("v %s" % a)[0].confidence
        self.assertGreater(grouped, plain)

    def test_uid_weak_label_between_unlabeled_and_strong(self):
        a = make_aadhaar()
        weak = scan("uid=%s" % a)[0].confidence
        self.assertGreater(weak, scan("v %s" % a)[0].confidence)
        self.assertLess(weak, scan("aadhaar=%s" % a)[0].confidence)

    def test_compact_timestamp_excluded_without_label(self):
        # 202406010003 passes the Verhoeff checksum but is a YYYYMMDDHHMM date
        self.assertEqual(rules("run id 202406010003 done"), [])

    def test_datetime_context_excluded(self):
        self.assertEqual(rules("created_at: %s" % make_aadhaar()), [])

    def test_reference_context_suppresses_unlabeled(self):
        self.assertEqual(rules("order_id=%s" % make_aadhaar()), [])

    def test_longer_digit_runs_not_matched(self):
        self.assertEqual(rules("Aadhaar: %s9" % make_aadhaar()), [])
        self.assertEqual(rules("Aadhaar: 9%s" % make_aadhaar()), [])

    def test_redaction_keeps_last_four_only(self):
        a = make_aadhaar()
        f = scan("Aadhaar: %s" % a)[0]
        self.assertEqual(f.evidence, "XXXX XXXX " + a[-4:])
        self.assertNotIn(a[:8], f.evidence)

    def test_label_does_not_leak_onto_other_identifier(self):
        a = make_aadhaar()
        # nearest label before the number is "mobile", not Aadhaar -> unlabeled score
        f = [x for x in scan("Aadhaar ref, mobile: %s" % a) if x.rule_id == "india.aadhaar"]
        self.assertTrue(all(x.confidence < 0.9 for x in f))


if __name__ == "__main__":
    unittest.main()

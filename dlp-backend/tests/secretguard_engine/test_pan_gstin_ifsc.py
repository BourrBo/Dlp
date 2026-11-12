import unittest

from tests.secretguard_engine.helpers import make_gstin, rules, scan
from secretguard.detectors.india import gstin as gstin_mod


class PanTests(unittest.TestCase):
    def test_labeled_valid(self):
        f = scan("PAN: ABCPK1234F")
        self.assertEqual([x.rule_id for x in f], ["india.pan"])
        self.assertGreaterEqual(f[0].confidence, 0.9)

    def test_all_valid_categories_detected(self):
        for cat in "ABCFGHJKLPT":
            self.assertIn("india.pan", rules("PAN: ABC%sK1234F" % cat))

    def test_invalid_category_rejected(self):
        for cat in "DEIMNOQRSUVWXYZ":
            self.assertNotIn("india.pan", rules("PAN: ABC%sK1234F" % cat))

    def test_wrong_structure_rejected(self):
        for bad in ("ABCPK12345", "ABCPK123F", "1BCPK1234F", "ABCPKA234F"):
            self.assertNotIn("india.pan", rules("PAN: " + bad))

    def test_unlabeled_lower_confidence(self):
        f = scan("code ABCPK1234F end")
        self.assertEqual(len(f), 1)
        self.assertLess(f[0].confidence, 0.7)

    def test_lowercase_needs_label(self):
        self.assertEqual(rules("code abcpk1234f end"), [])
        self.assertIn("india.pan", rules("PAN: abcpk1234f"))

    def test_pan_inside_gstin_not_double_reported(self):
        self.assertEqual(rules("GSTIN: " + make_gstin()), ["india.gstin"])

    def test_redaction(self):
        self.assertEqual(scan("PAN: ABCPK1234F")[0].evidence, "ABXXXXXXXF")


class GstinTests(unittest.TestCase):
    PUBLIC_SAMPLES = ["27AAPFU0939F1ZV", "07AAGFF2194N1Z1", "24AAACC1206D1ZM"]

    def test_publicly_cited_samples_validate(self):
        for g in self.PUBLIC_SAMPLES:
            self.assertTrue(gstin_mod.is_valid(g), g)

    def test_generated_valid_detected(self):
        self.assertEqual(rules("GSTIN: " + make_gstin()), ["india.gstin"])

    def test_unlabeled_valid_still_detected_with_lower_confidence(self):
        f = scan("x " + make_gstin() + " y")
        self.assertEqual(len(f), 1)
        self.assertLess(f[0].confidence, scan("GSTIN: " + make_gstin())[0].confidence)

    def test_bad_checksum_rejected(self):
        g = make_gstin()
        bad = g[:-1] + ("A" if g[-1] != "A" else "B")
        self.assertEqual(rules("GSTIN: " + bad), [])

    def test_invalid_state_code_rejected(self):
        for state in ("00", "39", "50"):
            self.assertEqual(rules("GSTIN: " + make_gstin(state=state)), [])

    def test_14th_char_must_be_z(self):
        g = make_gstin()
        self.assertEqual(rules("GSTIN: " + g[:13] + "Y" + g[14]), [])

    def test_embedded_pan_category_enforced(self):
        self.assertEqual(rules("GSTIN: " + make_gstin(pan="ABCDK1234F")), [])

    def test_redaction(self):
        g = make_gstin()
        e = scan("GSTIN: " + g)[0].evidence
        self.assertEqual((e[:2], e[-3:]), (g[:2], g[-3:]))
        self.assertNotIn(g[2:12], e)


class IfscTests(unittest.TestCase):
    def test_labeled(self):
        f = scan("IFSC: HDFC0001234")
        self.assertEqual([x.rule_id for x in f], ["india.ifsc"])
        self.assertGreaterEqual(f[0].confidence, 0.9)

    def test_unlabeled_known_bank_reported_medium_confidence(self):
        f = scan("route HDFC0001234 now")
        self.assertEqual(len(f), 1)
        self.assertLess(f[0].confidence, 0.9)

    def test_unlabeled_unknown_bank_suppressed(self):
        self.assertEqual(rules("code ABCD0123456 here"), [])

    def test_labeled_unknown_bank_reported(self):
        self.assertIn("india.ifsc", rules("IFSC code: ABCD0123456"))

    def test_fifth_char_must_be_zero(self):
        self.assertEqual(rules("IFSC: HDFC1001234"), [])

    def test_wrong_length_rejected(self):
        self.assertEqual(rules("IFSC: HDFC000123"), [])
        self.assertEqual(rules("IFSC: HDFC00012345"), [])

    def test_redaction_keeps_bank_prefix(self):
        self.assertEqual(scan("IFSC: HDFC0001234")[0].evidence, "HDFC0XXXXXX")


if __name__ == "__main__":
    unittest.main()

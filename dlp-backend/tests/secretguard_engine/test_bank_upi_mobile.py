import unittest

from tests.secretguard_engine.helpers import make_aadhaar, rules, scan


class BankAccountTests(unittest.TestCase):
    def test_never_flagged_on_digits_alone(self):
        for n in ("853645568151", "9876543210123", "123450067", "123456789012345678"):
            self.assertEqual(rules("value %s" % n), [], n)

    def test_flagged_with_account_label(self):
        f = scan("Bank account no: 853645568151")
        self.assertEqual([x.rule_id for x in f], ["india.bank_account"])

    def test_label_variants(self):
        for label in ("A/C No", "acct number", "Account Number", "bank_account", "ac no"):
            self.assertIn("india.bank_account", rules("%s: 853645568151" % label), label)

    def test_length_bounds(self):
        self.assertEqual(rules("account no: 85364556"), [])             # 8 digits
        self.assertEqual(rules("account no: 8536455681511294767"), [])  # 19 digits
        self.assertIn("india.bank_account", rules("account no: 853645568"))        # 9
        self.assertIn("india.bank_account", rules("account no: 853645568151129476"))  # 18

    def test_diversity_rejections(self):
        for n in ("111111111111", "123456789012", "909090909090", "000000000000", "112211221122"):
            self.assertEqual(rules("account no: %s" % n), [], n)

    def test_datetime_context_excluded(self):
        self.assertEqual(rules("account no, timestamp: 853645568151"), [])

    def test_label_must_be_nearest(self):
        self.assertNotIn("india.bank_account", rules("account no. n/a, mobile: 853645568151"))

    def test_beats_unlabeled_aadhaar_interpretation(self):
        self.assertEqual(rules("bank account no: %s" % make_aadhaar()), ["india.bank_account"])

    def test_redaction_last_four(self):
        self.assertEqual(scan("account no: 853645568151")[0].evidence, "XXXXXXXX8151")


class UpiTests(unittest.TestCase):
    def test_plain_gmail_is_not_upi(self):
        self.assertEqual(rules("person@gmail.com"), [])
        self.assertEqual(rules("UPI id: person@gmail.com"), [])

    def test_common_email_domains_not_upi(self):
        for e in ("a.b@yahoo.com", "x@outlook.com", "user@company.co.in", "u@sbi.co.in", "u@ybl.com"):
            self.assertEqual(rules(e), [], e)

    def test_allowlisted_handles(self):
        for h in ("okhdfcbank", "oksbi", "ybl", "paytm", "okaxis", "ibl", "upi"):
            self.assertIn("india.upi", rules("pay synthetic.user@%s now" % h), h)

    def test_labeled_scores_higher(self):
        a = scan("send to ravi.kumar@oksbi")[0].confidence
        b = scan("UPI ID: ravi.kumar@oksbi")[0].confidence
        self.assertGreater(b, a)

    def test_unknown_handle_rejected(self):
        self.assertEqual(rules("UPI: ravi.kumar@notabank"), [])

    def test_handle_case_insensitive(self):
        self.assertIn("india.upi", rules("UPI: ravi.kumar@OKSBI"))

    def test_mobile_as_local_part(self):
        self.assertEqual(rules("pay 8472940557@ybl"), ["india.upi"])

    def test_trailing_sentence_period_ok(self):
        self.assertIn("india.upi", rules("Send to ravi.kumar@oksbi."))

    def test_redaction(self):
        self.assertEqual(scan("UPI: ravi.kumar@oksbi")[0].evidence, "ra****@oksbi")


class MobileTests(unittest.TestCase):
    def test_labeled_high_confidence(self):
        f = scan("Mobile: 8472940557")
        self.assertEqual([x.rule_id for x in f], ["india.mobile"])
        self.assertGreaterEqual(f[0].confidence, 0.9)

    def test_unlabeled_lower_confidence(self):
        f = scan("call 8472940557 now")
        self.assertEqual(len(f), 1)
        self.assertLess(f[0].confidence, 0.5)

    def test_country_code_boosts_unlabeled(self):
        self.assertGreater(scan("x +91 8472940557")[0].confidence, scan("x 8472940557")[0].confidence)

    def test_prefix_and_grouping_variants(self):
        for v in ("+91 84729 40557", "+91-8472940557", "0091 8472940557", "08472940557", "84729-40557"):
            self.assertIn("india.mobile", rules("Phone: " + v), v)

    def test_solid_91_prefix_requires_label(self):
        self.assertIn("india.mobile", rules("Phone: 918472940557"))
        self.assertEqual(rules("value 918472940557"), [])

    def test_must_start_with_6_to_9(self):
        for lead in "012345":
            self.assertEqual(rules("Mobile: %s472940557" % lead), [])

    def test_epoch_timestamps_excluded(self):
        self.assertEqual(rules("ts 1717243200 and 1717243200000"), [])

    def test_datetime_context_excluded(self):
        self.assertEqual(rules("timestamp: 8472940557"), [])

    def test_reference_context_suppressed(self):
        self.assertEqual(rules("order_id=8472940557"), [])

    def test_degenerate_numbers_rejected(self):
        for n in ("9999999999", "9898989898"):
            self.assertEqual(rules("Mobile: " + n), [], n)

    def test_sequential_unlabeled_rejected_labeled_downgraded(self):
        self.assertEqual(rules("value 9876543210"), [])
        f = scan("Mobile: 9876543210")
        self.assertEqual(len(f), 1)
        self.assertLess(f[0].confidence, 0.8)

    def test_embedded_in_longer_number_not_matched(self):
        self.assertEqual(rules("Mobile: 84729405571"), [])
        self.assertEqual(rules("Mobile: 584729405571 "), [])

    def test_decimal_not_matched(self):
        self.assertEqual(rules("Mobile: 8472940557.25"), [])

    def test_redaction(self):
        self.assertEqual(scan("Mobile: 8472940557")[0].evidence, "XXXXXX0557")
        self.assertEqual(scan("Mobile: +91 8472940557")[0].evidence, "+91 XXXXXX0557")


if __name__ == "__main__":
    unittest.main()

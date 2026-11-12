import unittest

from tests.secretguard_engine.helpers import make_aadhaar
from secretguard.detectors.india import verhoeff


class VerhoeffTests(unittest.TestCase):
    def test_published_vector_valid(self):
        self.assertTrue(verhoeff.is_valid("2363"))   # 236 -> check digit 3

    def test_published_vector_invalid(self):
        self.assertFalse(verhoeff.is_valid("2364"))

    def test_generator_round_trip(self):
        for body in ("123456", "987654321", "47291836502"):
            self.assertTrue(verhoeff.is_valid(body + verhoeff.generate_check_digit(body)))

    def test_detects_every_single_digit_error(self):
        good = make_aadhaar()
        for i in range(len(good)):
            for d in "0123456789":
                if d != good[i]:
                    self.assertFalse(verhoeff.is_valid(good[:i] + d + good[i + 1:]))

    def test_detects_adjacent_transpositions(self):
        good = make_aadhaar()
        for i in range(len(good) - 1):
            if good[i] != good[i + 1]:
                swapped = good[:i] + good[i + 1] + good[i] + good[i + 2:]
                self.assertFalse(verhoeff.is_valid(swapped))

    def test_rejects_non_digits_and_empty(self):
        self.assertFalse(verhoeff.is_valid(""))
        self.assertFalse(verhoeff.is_valid("23a3"))


if __name__ == "__main__":
    unittest.main()

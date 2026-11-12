import unittest

from app.models.finding import DataType
from app.services.person_b import detection_service, secretguard_service
from secretguard.detectors.india.verhoeff import generate_check_digit


def _aadhaar() -> str:
    base = "23456789012"
    return base + str(generate_check_digit(base))


class SecretGuardIntegrationTests(unittest.TestCase):
    def test_cloud_key_detected_and_redacted(self):
        findings = secretguard_service.detect("key=AKIAIOSFODNN7EXAMPLE")
        self.assertTrue(any(f.data_type is DataType.API_KEY for f in findings))
        self.assertFalse(any("AKIAIOSFODNN7EXAMPLE" in (f.matched_snippet or "") for f in findings))

    def test_indian_identifiers_flow_through_detection_service(self):
        text = f"Customer PAN: ABCPE1234F\nAadhaar: {_aadhaar()}"
        findings = detection_service.detect(text)
        types = {f.data_type for f in findings}
        self.assertIn(DataType.NATIONAL_ID, types)

    def test_clean_text_has_no_secretguard_findings(self):
        self.assertEqual(secretguard_service.detect("hello world"), [])


if __name__ == "__main__":
    unittest.main()

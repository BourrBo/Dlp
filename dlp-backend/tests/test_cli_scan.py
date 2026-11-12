import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.cli_scan import _finding_result, make_sarif, scan_paths
from app.models.finding import DataType, Finding
from app.extractors.models import ExtractedChunk, ExtractionResult


class CliScanTests(unittest.TestCase):
    def test_sarif_uses_line_column_and_never_includes_match(self):
        finding = Finding(
            data_type=DataType.API_KEY,
            confidence=0.9,
            matched_snippet="sk************xy",
            start=4,
            end=20,
        )
        result = _finding_result(Path("example.py"), finding, "top\nsk_live_secret_value\n", {"line_start": 7})
        physical = result["locations"][0]["physicalLocation"]
        self.assertEqual(physical["region"], {"startLine": 8, "startColumn": 1, "endLine": 8, "endColumn": 17})
        self.assertNotIn("sk", str(make_sarif([result])))
        self.assertEqual(make_sarif([result])["version"], "2.1.0")

    def test_scan_only_uses_offline_detector_and_deduplicates_overlapping_chunks(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd() / ".test-tmp") as tmp:
            target = Path(tmp) / "sample.txt"
            target.write_text("synthetic", encoding="utf-8")
            extracted = ExtractionResult(path=str(target), chunks=[
                ExtractedChunk("synthetic", {"path": str(target), "line_start": 1, "char_start": 0}),
            ])
            finding = Finding(data_type=DataType.EMAIL_PII, confidence=0.6,
                              matched_snippet="a************m", start=0, end=16)
            with patch("app.cli_scan.extract_bytes_with_timeout", return_value=extracted), \
                 patch("app.cli_scan.detect", return_value=[finding]) as detector:
                results, skipped, truncated = scan_paths([Path(tmp)])
            detector.assert_called_once_with("synthetic")
            self.assertEqual(len(results), 1)
            self.assertEqual(skipped, [])
            self.assertFalse(truncated)


if __name__ == "__main__":
    unittest.main()

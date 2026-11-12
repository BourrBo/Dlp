from pathlib import Path
from unittest import TestCase

from scripts.check_extractor_boundaries import check_boundaries


class ExtractorBoundaryTests(TestCase):
    def test_extractors_do_not_import_database_or_network_layers(self):
        root = Path(__file__).resolve().parents[1] / "app" / "extractors"
        self.assertEqual(check_boundaries(root), [])

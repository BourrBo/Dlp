import contextlib
import io
import json
import os
import tempfile
import unittest
import zipfile

from tests.secretguard_engine.helpers import make_aadhaar, make_gstin, scan, scanner
from secretguard import cli
from secretguard.reporting import render_json, render_sarif, render_text
from secretguard.scanner import ScanConfig, Scanner
from secretguard.detectors import default_detectors


def _xlsx(path, rows):
    """Minimal xlsx writer (shared strings for text, raw numbers otherwise)."""
    strings, sheet_rows = [], []
    for r, row in enumerate(rows, 1):
        cells = []
        for c, val in enumerate(row):
            ref = "%s%d" % ("ABCDEFGH"[c], r)
            if isinstance(val, int):
                cells.append('<c r="%s"><v>%d</v></c>' % (ref, val))
            else:
                strings.append(val)
                cells.append('<c r="%s" t="s"><v>%d</v></c>' % (ref, len(strings) - 1))
        sheet_rows.append('<row r="%d">%s</row>' % (r, "".join(cells)))
    ns = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("xl/sharedStrings.xml", '<sst %s>%s</sst>' % (
            ns, "".join("<si><t>%s</t></si>" % s for s in strings)))
        z.writestr("xl/worksheets/sheet1.xml", '<worksheet %s><sheetData>%s</sheetData></worksheet>' % (
            ns, "".join(sheet_rows)))


class FormatTests(unittest.TestCase):
    def test_csv_header_supplies_context(self):
        a = make_aadhaar()
        f = scan("customer,aadhaar_no\nC1,%s\n" % a, kind="csv")
        self.assertEqual([(x.rule_id, x.line, x.field_name) for x in f], [("india.aadhaar", 2, "aadhaar_no")])

    def test_csv_reference_column_not_flagged(self):
        self.assertEqual(scan("customer,reference_no\nC1,%s\n" % make_aadhaar(), kind="csv"), [])

    def test_csv_unrelated_column_lower_confidence(self):
        f = scan("customer,notes\nC1,%s\n" % make_aadhaar(), kind="csv")
        self.assertTrue(all(x.confidence < 0.6 for x in f))

    def test_tsv(self):
        f = scan("id\tpan\nC1\tABCPK1234F\n", kind="tsv")
        self.assertEqual([x.rule_id for x in f], ["india.pan"])

    def test_csv_quoted_cells_and_commas(self):
        f = scan('id,notes,mobile\nC1,"hello, world",8472940557\n', kind="csv")
        self.assertEqual([x.rule_id for x in f], ["india.mobile"])

    def test_log_line(self):
        line = "2026-03-01 10:15:02,114 INFO [kyc] verified aadhaar=%s pan=ABCPK1234F" % make_aadhaar()
        self.assertEqual(sorted(x.rule_id for x in scan(line)), ["india.aadhaar", "india.pan"])

    def test_log_timestamp_fields_not_flagged(self):
        self.assertEqual(scan("2026-03-01 10:15:05,000 INFO timestamp=202406010003 depth=14"), [])

    def test_source_code_and_json(self):
        f = scan('{"gstin": "%s", "upi_vpa": "shop@ybl"}' % make_gstin())
        self.assertEqual(sorted(x.rule_id for x in f), ["india.gstin", "india.upi"])

    def test_adjacent_labeled_fields_do_not_cross_contaminate(self):
        text = "pan=ABCPK1234F aadhaar=%s mobile=8472940557" % make_aadhaar()
        self.assertEqual(sorted(x.rule_id for x in scan(text)),
                         ["india.aadhaar", "india.mobile", "india.pan"])
        self.assertTrue(all(x.confidence >= 0.9 for x in scan(text)))

    def test_line_and_column_reported(self):
        f = scan("first line\nsecond PAN: ABCPK1234F\n")
        self.assertEqual((f[0].line, f[0].column), (2, 13))

    def test_xlsx_with_header_context(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "book.xlsx")
            _xlsx(p, [["customer", "aadhaar_no", "reference_no"],
                      ["C1", make_aadhaar(), make_aadhaar("58204691372")],
                      ["C2", "x", 8472940557]])
            f = Scanner(default_detectors()).scan_file(p)
            self.assertEqual([(x.rule_id, x.line, x.field_name) for x in f],
                             [("india.aadhaar", 2, "sheet1!aadhaar_no")])

    def test_corrupt_xlsx_is_skipped_not_crashed(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.xlsx")
            with open(p, "wb") as fh:
                fh.write(b"not a zip")
            r = Scanner(default_detectors()).scan_path(d)
            self.assertEqual(r.files_scanned, 0)
            self.assertEqual(len(r.skipped), 1)


class EngineTests(unittest.TestCase):
    def test_overlap_resolution_keeps_single_best_interpretation(self):
        f = scan("mobile banking account no: %s" % make_aadhaar())
        self.assertEqual(len(f), 1)

    def test_min_confidence_filter(self):
        text = "call 8472940557"
        self.assertEqual(len(Scanner(default_detectors(), ScanConfig(min_confidence=0.3)).scan_text(text)), 1)
        self.assertEqual(len(Scanner(default_detectors(), ScanConfig(min_confidence=0.6)).scan_text(text)), 0)

    def test_disable_india_detectors(self):
        self.assertEqual(scan("Aadhaar: %s" % make_aadhaar(), include_india=False), [])

    def test_secret_detector_flags_known_formats(self):
        ids = [x.rule_id for x in scan('key = "AKIAIOSFODNN7EXAMPLE"')]
        self.assertIn("secret.aws_access_key", ids)

    def test_secret_detector_ignores_placeholders(self):
        self.assertEqual(scan('password = "changeme-changeme-123"'), [])

    def test_directory_walk_skips_binary_and_excluded_dirs(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "node_modules"))
            os.makedirs(os.path.join(d, "src"))
            for rel, data in (("node_modules/x.txt", b"PAN: ABCPK1234F"),
                              ("src/a.txt", b"PAN: ABCPK1234F"),
                              ("src/blob.dat", b"\x00\x01PAN: ABCPK1234F")):
                with open(os.path.join(d, rel), "wb") as fh:
                    fh.write(data)
            r = Scanner(default_detectors()).scan_path(d)
            self.assertEqual([os.path.basename(f.file) for f in r.findings], ["a.txt"])
            self.assertEqual(len(r.skipped), 1)

    def test_oversized_file_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "big.txt")
            with open(p, "w") as fh:
                fh.write("PAN: ABCPK1234F\n" * 10)
            r = Scanner(default_detectors(), ScanConfig(max_file_bytes=10)).scan_path(d)
            self.assertEqual((r.files_scanned, len(r.skipped)), (0, 1))


class NoLeakageTests(unittest.TestCase):
    """Raw identifier values must never appear in any report format."""

    def setUp(self):
        self.aadhaar, self.gstin = make_aadhaar(), make_gstin()
        self.raw = [self.aadhaar, self.gstin, "ABCPK1234F", "853645568151",
                    "8472940557", "ravi.kumar@oksbi", "q8Zr2LkP9xWm4TvB7nYc1HdS5gJf3QaE"]
        text = ("aadhaar=%s gstin=%s pan=ABCPK1234F account no: 853645568151 "
                "mobile=8472940557 upi=ravi.kumar@oksbi "
                'api_key="q8Zr2LkP9xWm4TvB7nYc1HdS5gJf3QaE"\n') % (self.aadhaar, self.gstin)
        self.dir = tempfile.TemporaryDirectory()
        with open(os.path.join(self.dir.name, "x.log"), "w") as fh:
            fh.write(text)
        self.result = scanner().scan_path(self.dir.name)

    def tearDown(self):
        self.dir.cleanup()

    def test_all_identifier_families_found(self):
        self.assertGreaterEqual(len({f.rule_id for f in self.result.findings}), 7)

    def test_text_json_sarif_contain_no_raw_values(self):
        for render in (render_text, render_json, render_sarif):
            out = render(self.result)
            for value in self.raw:
                self.assertNotIn(value, out)
                # nor the 8-digit prefix of the numeric ones
            self.assertNotIn(self.aadhaar[:8], out)

    def test_finding_objects_hold_no_raw_value(self):
        for f in self.result.findings:
            blob = repr(f) + json.dumps(f.to_dict())
            for value in self.raw:
                self.assertNotIn(value, blob)

    def test_sarif_is_valid_json_with_locations(self):
        sarif = json.loads(render_sarif(self.result))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertTrue(all("locations" in r for r in sarif["runs"][0]["results"]))


class CliTests(unittest.TestCase):
    def _run(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(argv)
        return code, buf.getvalue()

    def test_exit_code_reflects_fail_on_threshold(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.txt")
            with open(p, "w") as fh:
                fh.write("Aadhaar: %s\n" % make_aadhaar())
            self.assertEqual(self._run(["scan", p])[0], 1)
            self.assertEqual(self._run(["scan", p, "--fail-on", "critical"])[0], 1)
            self.assertEqual(self._run(["scan", p, "--no-india"])[0], 0)

    def test_clean_file_exits_zero(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.txt")
            with open(p, "w") as fh:
                fh.write("nothing to see here\n")
            self.assertEqual(self._run(["scan", p])[0], 0)

    def test_missing_path_exits_two(self):
        self.assertEqual(self._run(["scan", "/definitely/not/here"])[0], 2)

    def test_json_output_parses(self):
        code, out = self._run(["scan", os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools", "secret-guard", "data"), "--format", "json"])
        self.assertEqual(json.loads(out)["tool"], "enterprise-secret-guard")

    def test_rules_listing(self):
        code, out = self._run(["rules"])
        self.assertEqual(code, 0)
        self.assertIn("india.aadhaar", out)


if __name__ == "__main__":
    unittest.main()

from io import BytesIO
import gzip
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest
from unittest import TestCase
from unittest.mock import patch
from uuid import UUID
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile, ZipInfo
import tarfile

from docx import Document
from openpyxl import Workbook
from PIL import Image, ImageDraw, ImageFont
from pypdf import PdfWriter
from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject, NumberObject
from pptx import Presentation

from app.extractors.docx_file import extract_docx
from app.extractors.pdf_file import extract_pdf
from app.extractors.pdf_file import OcrUnavailable
from app.extractors.pptx_file import extract_pptx
from app.extractors.registry import extract_bytes, extract_file
from app.extractors.runner import extract_bytes_with_timeout
from app.extractors.xlsx_file import extract_xlsx
from app.extractors.models import ExtractedChunk, ExtractionResult
try:
    from starlette.datastructures import UploadFile as StarletteUploadFile
    from app.models.finding import Decision, ScanResult
    from app.routers.scans import scan_upload
except ModuleNotFoundError as exc:
    if exc.name not in {"fastapi", "starlette", "httpx"}:
        raise
    StarletteUploadFile = Decision = ScanResult = scan_upload = None


def _pdf_with_text(text: str) -> bytes:
    writer = PdfWriter()
    page = writer.add_blank_page(width=612, height=792)
    resources = page[NameObject("/Resources")].get_object()
    font = DictionaryObject()
    font[NameObject("/F1")] = writer._add_object(
        DictionaryObject(
            {
                NameObject("/Type"): NameObject("/Font"),
                NameObject("/Subtype"): NameObject("/Type1"),
                NameObject("/BaseFont"): NameObject("/Helvetica"),
            }
        )
    )
    resources[NameObject("/Font")] = font
    stream = DecodedStreamObject()
    safe_text = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream.set_data(f"BT /F1 12 Tf 72 720 Td ({safe_text}) Tj ET".encode("ascii"))
    page[NameObject("/Contents")] = writer._add_object(stream)
    output = BytesIO()
    writer.write(output)
    return output.getvalue()


def _docx_bytes() -> bytes:
    document = Document()
    document.add_paragraph("Sensitive value: person@example.com")
    table = document.add_table(rows=1, cols=2)
    table.cell(0, 0).text = "Account"
    table.cell(0, 1).text = "4111 1111 1111 1111"
    document.sections[0].header.paragraphs[0].text = "Internal header"
    output = BytesIO()
    document.save(output)
    packaged = BytesIO()
    with ZipFile(BytesIO(output.getvalue())) as source, ZipFile(packaged, "w") as target:
        for entry in source.infolist():
            target.writestr(entry, source.read(entry.filename))
        target.writestr(
            "word/comments.xml",
            b'<w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            b'<w:comment w:id="7"><w:p><w:r><w:t>Review comment</w:t></w:r></w:p></w:comment>'
            b'</w:comments>',
        )
    return packaged.getvalue()


def _xlsx_bytes() -> bytes:
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Customers"
    sheet.append(["Name", "Email"])
    sheet.append(["Ada", "ada@example.com"])
    output = BytesIO()
    workbook.save(output)
    return output.getvalue()


def _pptx_bytes() -> bytes:
    presentation = Presentation()
    slide = presentation.slides.add_slide(presentation.slide_layouts[1])
    slide.shapes.title.text = "Customer data"
    slide.placeholders[1].text = "ada@example.com"
    slide.notes_slide.notes_text_frame.text = "Internal speaker note"
    output = BytesIO()
    presentation.save(output)
    return output.getvalue()


def _image_only_pdf_bytes() -> bytes:
    image = Image.new("RGB", (1200, 360), "white")
    ImageDraw.Draw(image).text(
        (45, 90),
        "person@example.com",
        font=ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 72),
        fill="black",
    )
    xobject = DecodedStreamObject()
    xobject.set_data(image.tobytes())
    xobject.update(
        {
            NameObject("/Type"): NameObject("/XObject"),
            NameObject("/Subtype"): NameObject("/Image"),
            NameObject("/Width"): NumberObject(1200),
            NameObject("/Height"): NumberObject(360),
            NameObject("/ColorSpace"): NameObject("/DeviceRGB"),
            NameObject("/BitsPerComponent"): NumberObject(8),
        }
    )
    writer = PdfWriter()
    page = writer.add_blank_page(width=600, height=180)
    page[NameObject("/Resources")] = DictionaryObject(
        {NameObject("/XObject"): DictionaryObject({NameObject("/Im0"): writer._add_object(xobject)})}
    )
    content = DecodedStreamObject()
    content.set_data(b"q 600 0 0 180 0 0 cm /Im0 Do Q")
    page[NameObject("/Contents")] = writer._add_object(content)
    output = BytesIO()
    writer.write(output)
    return output.getvalue()


class ExtractorTests(TestCase):
    def test_zip_archive_scans_text_and_preserves_nested_path(self):
        output = BytesIO()
        with ZipFile(output, "w", ZIP_STORED) as archive:
            archive.writestr("reports/customer.txt", "contact person@example.com")
        result = extract_bytes(output.getvalue(), display_path="bundle.zip")
        self.assertIsNone(result.skipped_reason)
        self.assertEqual(result.chunks[0].location["archive_member"], "bundle.zip/reports/customer.txt")
        self.assertIn("person@example.com", result.chunks[0].text)

    def test_nested_zip_archive_scans_members_recursively(self):
        inner = BytesIO()
        with ZipFile(inner, "w", ZIP_STORED) as archive:
            archive.writestr("account.txt", "person@example.com")
        outer = BytesIO()
        with ZipFile(outer, "w", ZIP_STORED) as archive:
            archive.writestr("nested.zip", inner.getvalue())
        result = extract_bytes(outer.getvalue(), display_path="outer.zip")
        self.assertIsNone(result.skipped_reason)
        self.assertEqual(result.chunks[0].location["archive_member"], "outer.zip/nested.zip/account.txt")

    def test_zip_archive_rejects_traversal_and_does_not_return_partial_chunks(self):
        output = BytesIO()
        with ZipFile(output, "w", ZIP_STORED) as archive:
            archive.writestr("safe.txt", "safe content")
            archive.writestr("../outside.txt", "person@example.com")
        result = extract_bytes(output.getvalue(), display_path="unsafe.zip")
        self.assertIn("traversal", result.skipped_reason or "")
        self.assertFalse(result.chunks)

    def test_zip_archive_rejects_case_colliding_names(self):
        output = BytesIO()
        with ZipFile(output, "w", ZIP_STORED) as archive:
            archive.writestr("Docs/Readme.txt", "safe content")
            archive.writestr("docs/README.TXT", "person@example.com")
        result = extract_bytes(output.getvalue(), display_path="case-collision.zip")
        self.assertIn("case-colliding", result.skipped_reason or "")
        self.assertFalse(result.chunks)

    def test_zip_archive_rejects_symlink_members(self):
        output = BytesIO()
        link = ZipInfo("link.txt")
        link.create_system = 3
        link.external_attr = (0o120777 << 16)
        with ZipFile(output, "w") as archive:
            archive.writestr(link, "target.txt")
        result = extract_bytes(output.getvalue(), display_path="link.zip")
        self.assertIn("symbolic link", result.skipped_reason or "")

    def test_zip_archive_rejects_excessive_expansion_ratio(self):
        output = BytesIO()
        with ZipFile(output, "w", ZIP_DEFLATED) as archive:
            archive.writestr("large.txt", "A" * 100_000)
        result = extract_bytes(output.getvalue(), display_path="bomb.zip")
        self.assertIn("100:1", result.skipped_reason or "")

    def test_tar_archive_scans_text_and_rejects_links(self):
        output = BytesIO()
        payload = b"person@example.com"
        with tarfile.open(fileobj=output, mode="w:") as archive:
            info = tarfile.TarInfo("customers.txt")
            info.size = len(payload)
            archive.addfile(info, BytesIO(payload))
        result = extract_bytes(output.getvalue(), display_path="bundle.tar")
        self.assertIsNone(result.skipped_reason)
        self.assertEqual(result.chunks[0].location["archive_member"], "bundle.tar/customers.txt")

        linked = BytesIO()
        with tarfile.open(fileobj=linked, mode="w:") as archive:
            info = tarfile.TarInfo("linked.txt")
            info.type = tarfile.SYMTYPE
            info.linkname = "target.txt"
            archive.addfile(info)
        rejected = extract_bytes(linked.getvalue(), display_path="links.tar")
        self.assertIn("link or special file", rejected.skipped_reason or "")

    def test_tar_archive_rejects_traversal(self):
        output = BytesIO()
        with tarfile.open(fileobj=output, mode="w:") as archive:
            info = tarfile.TarInfo("../outside.txt")
            payload = b"person@example.com"
            info.size = len(payload)
            archive.addfile(info, BytesIO(payload))
        result = extract_bytes(output.getvalue(), display_path="traversal.tar")
        self.assertIn("traversal", result.skipped_reason or "")
        self.assertFalse(result.chunks)

    def test_gzip_archive_rejects_excessive_expansion_ratio(self):
        result = extract_bytes(gzip.compress(b"A" * 300_000), display_path="large.txt.gz")
        self.assertIn("100:1", result.skipped_reason or "")

    def test_gzip_scans_decompressed_file_with_original_member_location(self):
        compressed = gzip.compress(b"person@example.com")
        result = extract_bytes(compressed, display_path="customer.txt.gz")
        self.assertIsNone(result.skipped_reason)
        self.assertEqual(result.chunks[0].location["archive_member"], "customer.txt")

    def test_pdf_extracts_page_location(self):
        result = extract_pdf(_pdf_with_text("person@example.com"), path="sample.pdf")
        self.assertIsNone(result.skipped_reason)
        self.assertTrue(result.chunks)
        self.assertEqual(result.chunks[0].location["page"], 1)
        self.assertIn("person@example.com", result.chunks[0].text)

    def test_ocr_preprocesses_page_and_uses_installed_english_and_hindi(self):
        from app.extractors.pdf_file import _ocr_page

        class RenderedPage:
            def get_size(self):
                return 200, 100

            def render(self, *, scale):
                self.scale = scale
                return self

            def to_pil(self):
                return Image.new("RGB", (200, 100), (120, 120, 120))

        with (
            patch("app.extractors.pdf_file.pytesseract.get_languages", return_value=["eng", "hin", "osd"]),
            patch("app.extractors.pdf_file.pytesseract.image_to_string", return_value="recognized") as ocr,
        ):
            recognized = _ocr_page(RenderedPage())
        self.assertEqual(recognized, "recognized")
        self.assertEqual(ocr.call_args.kwargs["lang"], "eng+hin")
        self.assertEqual(ocr.call_args.kwargs["timeout"], 15)
        self.assertEqual(ocr.call_args.args[0].mode, "L")

    def test_ocr_reports_when_no_supported_language_data_is_installed(self):
        from app.extractors.pdf_file import _available_ocr_languages

        with patch("app.extractors.pdf_file.pytesseract.get_languages", return_value=["osd"]):
            with self.assertRaisesRegex(OcrUnavailable, "English or Hindi"):
                _available_ocr_languages()

    def test_image_only_pdf_is_reported_as_needing_ocr(self):
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        output = BytesIO()
        writer.write(output)
        with patch("app.extractors.pdf_file._ocr_page", side_effect=OcrUnavailable("Tesseract OCR is not installed")):
            result = extract_pdf(output.getvalue(), path="scan.pdf")
        self.assertIn("requiring OCR", result.skipped_reason or "")

    def test_image_only_pdf_page_is_ocr_scanned_and_located(self):
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        output = BytesIO()
        writer.write(output)
        with patch("app.extractors.pdf_file._ocr_page", return_value="private@example.com"):
            result = extract_pdf(output.getvalue(), path="scan.pdf")
        self.assertIsNone(result.skipped_reason)
        self.assertEqual(result.chunks[0].location["page"], 1)
        self.assertTrue(result.chunks[0].location["ocr"])
        self.assertIn("private@example.com", result.chunks[0].text)

    @unittest.skipUnless(shutil.which("tesseract"), "Tesseract is installed in the Docker image")
    def test_real_tesseract_recognizes_image_only_pdf_text(self):
        result = extract_pdf(_image_only_pdf_bytes(), path="ocr-fixture.pdf")
        self.assertIsNone(result.skipped_reason)
        self.assertTrue(any("person@example.com" in chunk.text.lower() for chunk in result.chunks))

    def test_pdf_with_unscanned_page_does_not_return_partial_clean_result(self):
        writer = PdfWriter()
        page = writer.add_blank_page(width=612, height=792)
        resources = page[NameObject("/Resources")].get_object()
        font = DictionaryObject()
        font[NameObject("/F1")] = writer._add_object(
            DictionaryObject({NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"), NameObject("/BaseFont"): NameObject("/Helvetica")})
        )
        resources[NameObject("/Font")] = font
        stream = DecodedStreamObject()
        stream.set_data(b"BT /F1 12 Tf 72 720 Td (safe text) Tj ET")
        page[NameObject("/Contents")] = writer._add_object(stream)
        writer.add_blank_page(width=612, height=792)
        output = BytesIO()
        writer.write(output)
        with patch("app.extractors.pdf_file._ocr_page", side_effect=OcrUnavailable("Tesseract OCR is not installed")):
            result = extract_pdf(output.getvalue(), path="partial.pdf")
        self.assertFalse(result.chunks)
        self.assertIn("requiring OCR", result.skipped_reason or "")

    def test_xlsx_extracts_cell_text_with_locations(self):
        result = extract_xlsx(_xlsx_bytes(), path="customers.xlsx")
        self.assertIsNone(result.skipped_reason)
        self.assertTrue(any(chunk.location.get("sheet") == "Customers" and chunk.location.get("row") == 2 for chunk in result.chunks))
        self.assertTrue(any("B2=ada@example.com" in chunk.text for chunk in result.chunks))

    def test_pptx_extracts_slide_text_and_speaker_notes(self):
        result = extract_pptx(_pptx_bytes(), path="presentation.pptx")
        self.assertIsNone(result.skipped_reason)
        text = "\n".join(chunk.text for chunk in result.chunks)
        self.assertIn("ada@example.com", text)
        self.assertIn("Internal speaker note", text)
        self.assertTrue(any(chunk.location.get("content") == "notes" and chunk.location.get("slide") == 1 for chunk in result.chunks))

    def test_registry_supports_xlsx_and_pptx(self):
        for name, data in (("customers.xlsx", _xlsx_bytes()), ("presentation.pptx", _pptx_bytes())):
            with self.subTest(name=name):
                result = extract_bytes(data, display_path=name)
                self.assertIsNone(result.skipped_reason)
                self.assertTrue(result.chunks)

    def test_encrypted_pdf_is_skipped(self):
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        writer.encrypt("secret")
        output = BytesIO()
        writer.write(output)
        result = extract_pdf(output.getvalue(), path="locked.pdf")
        self.assertIn("Password-protected", result.skipped_reason or "")

    def test_docx_extracts_paragraph_table_and_header_locations(self):
        result = extract_docx(_docx_bytes(), path="sample.docx")
        self.assertIsNone(result.skipped_reason)
        locations = [chunk.location for chunk in result.chunks]
        self.assertTrue(any("paragraph" in location for location in locations))
        self.assertTrue(any("table" in location for location in locations))
        self.assertTrue(any("header" in key for location in locations for key in location))
        self.assertTrue(any(location.get("comment_id") == "7" for location in locations))
        text = "\n".join(chunk.text for chunk in result.chunks)
        self.assertIn("person@example.com", text)
        self.assertIn("4111 1111 1111 1111", text)
        self.assertIn("Internal header", text)
        self.assertEqual(text.count("Internal header"), 1)

    def test_binary_file_named_txt_is_skipped(self):
        result = extract_bytes(b"\x00\x01\x02\xff", display_path="not-really-text.txt")
        self.assertIn("binary", result.skipped_reason or "")

    def test_unsupported_file_has_a_skip_reason(self):
        result = extract_bytes(b"data", display_path="archive.7z")
        self.assertIn("Unsupported file type", result.skipped_reason or "")

    def test_original_supported_formats_return_locations(self):
        samples = (
            ("notes.txt", b"first line\nsecond line", "line_start"),
            ("users.csv", b"name,email\nAda,ada@example.com\n", "row"),
            ("record.json", b'{"user":{"email":"ada@example.com"}}', "json_path"),
            ("record.xml", b'<user email="ada@example.com">Ada</user>', "xml_path"),
        )
        for filename, content, location_key in samples:
            with self.subTest(filename=filename):
                result = extract_bytes(content, display_path=filename)
                self.assertIsNone(result.skipped_reason)
                self.assertTrue(result.chunks)
                self.assertIn(location_key, result.chunks[0].location)

    def test_xml_dtd_is_skipped(self):
        result = extract_bytes(
            b'<!DOCTYPE user [<!ENTITY x "secret">]><user>&x;</user>',
            display_path="unsafe.xml",
        )
        self.assertIn("DTD", result.skipped_reason or "")

    def test_corrupt_docx_is_skipped_without_raising(self):
        result = extract_docx(b"not a zip", path="corrupt.docx")
        self.assertIn("not a valid DOCX", result.skipped_reason or "")

    def test_docx_expansion_ratio_is_bounded(self):
        output = BytesIO()
        with ZipFile(output, "w", ZIP_DEFLATED) as package:
            package.writestr("word/document.xml", b"A" * 100_000)
        result = extract_docx(output.getvalue(), path="bomb.docx")
        self.assertIn("100:1", result.skipped_reason or "")

    def test_extract_file_rejects_oversized_input_before_reading_all(self):
        writable_tmp = Path(__file__).resolve().parents[1] / ".test-tmp"
        writable_tmp.mkdir(exist_ok=True)
        with TemporaryDirectory(dir=writable_tmp) as temporary:
            path = Path(temporary) / "oversized.txt"
            with path.open("wb") as output:
                output.truncate(100 * 1024 * 1024)
            result = extract_file(path)
        self.assertIn("25 MB limit", result.skipped_reason or "")

    def test_exact_25_mib_file_is_accepted(self):
        result = extract_bytes(b"x" * (25 * 1024 * 1024), display_path="maximum.txt")
        self.assertIsNone(result.skipped_reason)
        self.assertTrue(result.chunks)

    def test_timeout_runner_returns_extracted_text(self):
        result = extract_bytes_with_timeout(b"safe sample", display_path="sample.txt")
        self.assertIsNone(result.skipped_reason)
        self.assertIn("safe sample", result.chunks[0].text)

    @unittest.skipIf(scan_upload is None, "install backend requirements to test the upload API")
    def test_upload_endpoint_returns_scan_results_with_locations(self):
        from app.auth import AuthenticatedPrincipal

        synthetic_scan = ScanResult(findings=[], decision=Decision.ALLOW, reason="test")
        extracted = ExtractionResult(
            path="sample.txt",
            chunks=[ExtractedChunk(text="safe sample", location={"path": "sample.txt", "line_start": 1, "line_end": 1})],
        )
        upload = StarletteUploadFile(file=BytesIO(b"safe sample"), filename="sample.txt")
        with (
            patch("app.routers.scans.extract_bytes_with_timeout", return_value=extracted),
            patch("app.routers.scans.scan_for_verified_user", return_value=synthetic_scan),
            patch("app.routers.scans.resolve_org", side_effect=lambda principal, org_id: org_id or principal.org_id),
        ):
            response = scan_upload(
                principal=AuthenticatedPrincipal(
                    user_id=UUID("00000000-0000-0000-0000-000000000002"),
                    org_id=UUID("00000000-0000-0000-0000-000000000001"),
                    access_token="verified-token",
                ),
                file=upload,
                org_id=UUID("00000000-0000-0000-0000-000000000001"),
                destination="internal.example",
            )
        body = response.model_dump(mode="json")["files"][0]
        self.assertEqual(body["filename"], "sample.txt")
        self.assertEqual(body["chunks"][0]["location"]["path"], "sample.txt")

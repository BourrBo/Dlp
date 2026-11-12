# Ingestion and extraction

The extraction layer lives in `app/extractors/`. It has no Supabase, HTTP, or
detector imports, so the same code can later serve upload, archive, repository,
and CLI scanning paths.

## Supported formats today

| Format | Content extraction | Location metadata |
| --- | --- | --- |
| Text and source files (`.txt`, `.md`, `.log`, `.py`, `.js`, `.ts`, `.sql`, etc.) | UTF-8, BOM-marked UTF-16/32, with Windows-1252 fallback | Path, chunk index, character offsets, line range |
| CSV | Rows serialized with their column names | Path, logical row number |
| JSON | Scalar leaf values serialized with their JSON path | Path, JSON path |
| XML | Element text and attribute values | Path, XML element/attribute path |
| PDF | Selectable page text | Path, one-based page number |
| DOCX | Paragraphs, tables, section headers and comments | Path, paragraph/table row/header/comment id |
| XLSX | Cell values streamed in read-only mode | Path, worksheet, row, cell coordinate |
| PPTX | Slide text, grouped shapes, tables and speaker notes | Path, one-based slide and content kind |
| ZIP/TAR/GZ | Supported members extracted recursively in memory | Archive member path plus nested extractor locations |

Text is chunked at up to 50,000 characters with 1,000 characters of overlap.
That overlap helps detectors recognize values at chunk boundaries; consumers
should deduplicate overlapping matches before displaying findings.

## Limits and skip behavior

- Maximum input size is 25 MiB per file. The read is capped as well as checking
  the file's reported size, to avoid reading an unexpectedly growing file.
- PDF extraction is capped at 500 pages and 5 MiB of extracted text. Pages
  without selectable text are rendered and OCR-scanned with Tesseract (at most
  50 OCR pages and 20 megapixels per rendered page). Rendered pages are
  converted to grayscale and autocontrasted; the Docker image installs English
  and Hindi Tesseract data, and the extractor uses whichever of those languages
  are installed. If OCR is unavailable, exceeds a limit, or fails, the
  whole PDF is skipped instead of returning a partial clean result.
- DOCX is preflighted as a ZIP package before parsing: at most 1,000 parts,
  200 MiB expanded size and 100:1 compression ratio. Encrypted packages are
  skipped. Extracted text is capped at 5 MiB.
- XLSX and PPTX use the same OOXML ZIP preflight as DOCX. XLSX uses openpyxl's
  read-only mode and caps work at 250 worksheets, 250,000 cells, and 5 MiB of
  extracted text. Spreadsheet formulas are read as cached values; formulas
  without a cached value are not evaluated. PPTX caps at 500 slides, 100,000
  top-level shapes, and 5 MiB of text.
- ZIP/TAR/GZ extraction never writes archive members to disk. Absolute paths,
  drive-qualified paths, `..` traversal, symbolic/hard links, special files,
  duplicate and case-colliding paths, encrypted ZIP entries, excessive expansion, too many files,
  and nesting beyond three levels reject the whole archive. The upload file
  cap remains 25 MiB; archive members are limited to 25 MiB each and 200 MiB
  total expanded content. A member the scanner cannot parse also rejects the
  archive so a partial scan is not presented as clean.
- `POST /scans` is the synchronous compatibility endpoint. `POST /scan-jobs`
  accepts the same multipart fields and returns a job id; poll
  `GET /scan-jobs/{id}` for progress/results, list the user's recent jobs with
  `GET /scan-jobs`, and cancel with `DELETE /scan-jobs/{id}`. Job metadata and
  masked results use a SQLite database in a persistent Docker volume. Queued
  upload bytes are authenticated-encrypted with a purpose-derived key from the
  backend's service-only Supabase key, and erased on completion, failure,
  cancellation, or interruption. Queued work remains queued through a restart;
  any running job becomes `interrupted`, keeps its partial results/progress,
  and requires a fresh upload to scan again. Stable event ids prevent duplicate
  events while a job is running.
  The authenticated file-scan UI accepts up to 20 files per selection or drop,
  checks the 25 MiB per-file bound before upload, and queues each file as its
  own durable job. Uploads are sent sequentially with a per-file status; the
  backend endpoint remains a one-file-per-job contract.
  Parsing runs in a subprocess terminated after 30 seconds. The API verifies the
  Supabase bearer token, resolves the authenticated user's organization
  membership, and derives ownership from that verified principal. The extension
  currently uses a managed API-key contract, so its API-key-to-principal
  adapter remains pending before extension scans can use these routes.
- Binary-looking content, unsupported extensions, invalid structured data, and
  empty text return an `ExtractionResult` with a human-readable
  `skipped_reason`; they do not raise into the scan caller.
- XML containing a DTD or entity declaration is skipped.
- Archive limits are defined centrally for the later ZIP implementation:
  depth 3, 1,000 files, 200 MiB uncompressed, 100:1 compression ratio.
- GitHub/repository scans and later endpoint/agent features remain future P3
  milestones. The SQLite job store is for a single Docker host; horizontal
  worker fleets require the shared durable queue/storage handoff in the
  enterprise architecture.

Run the sandbox inspector from `dlp-backend/` to review chunks and locations:

```sh
python scripts/inspect_extractors.py path/to/sample.txt path/to/samples/
```

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

Text is chunked at up to 50,000 characters with 1,000 characters of overlap.
That overlap helps detectors recognize values at chunk boundaries; consumers
should deduplicate overlapping matches before displaying findings.

## Limits and skip behavior

- Maximum input size is 25 MiB per file. The read is capped as well as checking
  the file's reported size, to avoid reading an unexpectedly growing file.
- Binary-looking content, unsupported extensions, invalid structured data, and
  empty text return an `ExtractionResult` with a human-readable
  `skipped_reason`; they do not raise into the scan caller.
- XML containing a DTD or entity declaration is skipped.
- Archive limits are defined centrally for the later ZIP implementation:
  depth 3, 1,000 files, 200 MiB uncompressed, 100:1 compression ratio.
- Office/PDF extraction, ZIP traversal checks, per-file process timeouts, and
  async scan jobs are not implemented yet.

Run the sandbox inspector from `dlp-backend/` to review chunks and locations:

```sh
python scripts/inspect_extractors.py path/to/sample.txt path/to/samples/
```

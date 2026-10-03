"""
Person B — Detection Engine & Extension. Everything in this package is
owned and editable by Person B without touching anyone else's code.

Only two integration points exist outside this package, both single-line
and documented where they occur:
  1. app/routers/detect.py imports `detect` from here instead of the old
     app.services.detection_service (one import line + one call site).
  2. main.py registers app/routers/classifications.py (one line), which
     itself only imports from this package.

Everything else — the pipeline logic, NER, EDM, fingerprinting, the
per-org rule cache, redaction — lives inside person_b/ and can be changed
freely without risking Person A's policy engine or Person C's channels.
"""

from app.services.person_b.detection_service import detect

__all__ = ["detect"]

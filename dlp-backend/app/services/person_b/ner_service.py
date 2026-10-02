"""
NER-based unstructured PII detection — Presidio/spaCy wrapper.

Stage 2 of the detection pipeline. Regex (Stage 1) only catches structured
patterns (card numbers, keys); this catches context-dependent PII that has
no fixed shape — person names, physical addresses, phone numbers.

Presidio + spaCy are heavyweight (model load takes ~1-2s, done once and
cached) and optional at install time: if they aren't installed, this module
degrades to a no-op with a one-time warning instead of crashing the
backend, so regex + EDM + fingerprint detection keep working standalone.

Install:
    pip install presidio-analyzer spacy
    python -m spacy download en_core_web_sm
"""

import logging
from functools import lru_cache

from app.models.finding import DataType, Finding
from app.services.person_b.text_utils import redact

logger = logging.getLogger(__name__)

# Presidio's built-in entity names -> our DataType enum. Anything not listed
# here still comes through as DataType.CUSTOM with the raw entity type kept
# in `label`, so new entity types show up rather than getting silently
# dropped.
_ENTITY_MAP = {
    "PERSON": DataType.PERSON_NAME,
    "LOCATION": DataType.ADDRESS,
    "PHONE_NUMBER": DataType.PHONE_NUMBER,
    "US_SSN": DataType.NATIONAL_ID,
    "US_DRIVER_LICENSE": DataType.NATIONAL_ID,
    "CREDIT_CARD": DataType.CREDIT_CARD,
    "EMAIL_ADDRESS": DataType.EMAIL_PII,
}

_MIN_CONFIDENCE = 0.5


@lru_cache
def _get_analyzer():
    """Built once per process. Returns None (not raises) if unavailable."""
    try:
        from presidio_analyzer import AnalyzerEngine
    except ImportError:
        logger.warning(
            "presidio-analyzer / spacy not installed — NER detection disabled. "
            "Install with: pip install presidio-analyzer spacy && "
            "python -m spacy download en_core_web_sm"
        )
        return None

    try:
        # Explicitly use the small English model documented by this project.
        # Presidio's default NLP configuration may expect a larger model that
        # is not installed by `python -m spacy download en_core_web_sm`.
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        configuration = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
        provider = NlpEngineProvider(nlp_configuration=configuration)
        nlp_engine = provider.create_engine()
        return AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
    except Exception as exc:  # e.g. spaCy model not downloaded or incompatible
        logger.warning("Presidio AnalyzerEngine failed to initialize: %s", exc)
        return None


def detect(content: str) -> list[Finding]:
    analyzer = _get_analyzer()
    if analyzer is None:
        return []

    try:
        results = analyzer.analyze(text=content, language="en")
    except Exception as exc:
        logger.warning("Presidio analysis failed; continuing without NER: %s", exc)
        return []
    findings: list[Finding] = []
    for r in results:
        if r.score < _MIN_CONFIDENCE:
            continue
        data_type = _ENTITY_MAP.get(r.entity_type, DataType.CUSTOM)
        snippet = content[r.start : r.end]
        findings.append(
            Finding(
                data_type=data_type,
                confidence=round(r.score, 2),
                matched_snippet=redact(snippet),
                label=r.entity_type,
            )
        )
    return findings

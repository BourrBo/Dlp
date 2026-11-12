import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # dlp-backend
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from secretguard.detectors import default_detectors  # noqa: E402
from secretguard.detectors.india import gstin as gstin_mod  # noqa: E402
from secretguard.detectors.india import verhoeff  # noqa: E402
from secretguard.scanner import Scanner  # noqa: E402

AADHAAR_BODIES = ["47291836502", "93817264053", "58204691372"]


def make_aadhaar(body="47291836502"):
    return body + verhoeff.generate_check_digit(body)


def make_gstin(state="27", pan="ABCPK1234F", entity="1"):
    first14 = state + pan + entity + "Z"
    return first14 + gstin_mod.check_char(first14)


def invalid_checksum(digits):
    last = (int(digits[-1]) + 1) % 10
    return digits[:-1] + str(last)


def scanner(**kw):
    return Scanner(default_detectors(**kw))


def scan(text, kind="text", **kw):
    return scanner(**kw).scan_text(text, "<t>", kind)


def rules(text, kind="text"):
    return [f.rule_id for f in scan(text, kind)]

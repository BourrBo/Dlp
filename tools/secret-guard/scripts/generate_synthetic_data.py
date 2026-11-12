"""Generate the synthetic demo corpus (deterministic).

All values are fabricated. Numeric identifiers are random but structurally
valid (e.g. Aadhaar values carry a correct Verhoeff check digit), so they may
coincidentally resemble real identifiers. Never replace them with real data.
"""
import csv
import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from secretguard.detectors.india import gstin as gst  # noqa: E402
from secretguard.detectors.india import verhoeff  # noqa: E402
from secretguard.detectors.india.common import (all_same, is_repeating_block,  # noqa: E402
                                                longest_run, looks_like_timestamp)

rng = random.Random(2026)
LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def aadhaar() -> str:
    while True:
        body = str(rng.randint(2, 9)) + "".join(str(rng.randint(0, 9)) for _ in range(10))
        d = body + verhoeff.generate_check_digit(body)
        if not (all_same(d) or is_repeating_block(d) or longest_run(d) >= 6 or looks_like_timestamp(d)):
            return d


def pan() -> str:
    return "".join(rng.choice(LETTERS) for _ in range(3)) + "P" + rng.choice(LETTERS) + \
        "%04d" % rng.randint(1000, 9999) + rng.choice(LETTERS)


def gstin() -> str:
    first14 = rng.choice(["27", "29", "07", "33", "24"]) + pan()[:3] + "C" + rng.choice(LETTERS) + \
        "%04d" % rng.randint(1000, 9999) + rng.choice(LETTERS) + "1Z"
    return first14 + gst.check_char(first14)


def bank() -> str:
    while True:
        d = str(rng.randint(1, 9)) + "".join(str(rng.randint(0, 9)) for _ in range(11))
        if len(set(d)) >= 6 and longest_run(d) < 5:
            return d


def mobile() -> str:
    while True:
        d = str(rng.randint(6, 9)) + "".join(str(rng.randint(0, 9)) for _ in range(9))
        if len(set(d)) >= 6 and longest_run(d) < 5:
            return d


def checksum_valid_timestamp() -> str:
    """A compact datetime (YYYYMMDDHHMM) that WOULD pass the Aadhaar checksum."""
    for day in range(1, 29):
        for hh in range(24):
            for mm in range(60):
                d = "202406%02d%02d%02d" % (day, hh, mm)
                if verhoeff.is_valid(d):
                    return d
    raise RuntimeError("none found")


def checksum_valid_reference() -> str:
    """A 12-digit order reference that WOULD pass the Aadhaar checksum."""
    while True:
        body = str(rng.randint(2, 9)) + "".join(str(rng.randint(0, 9)) for _ in range(10))
        d = body + verhoeff.generate_check_digit(body)
        if len(set(d)) >= 6 and longest_run(d) < 4 and not looks_like_timestamp(d):
            return d


COLUMNS = ["customer_id", "customer_name", "aadhaar_no", "pan", "gstin", "ifsc",
           "bank_account_no", "upi_id", "mobile", "email", "last_login_ts", "reference_no"]
ROWS = [
    ("C001", "Synthetic Customer 01", {"aadhaar_no": aadhaar()}, "aadhaar"),
    ("C002", "Synthetic Customer 02", {"pan": pan()}, "pan"),
    ("C003", "Synthetic Customer 03", {"gstin": gstin()}, "gstin"),
    ("C004", "Synthetic Customer 04", {"ifsc": "HDFC0%06d" % rng.randint(100, 999999)}, "ifsc"),
    ("C005", "Synthetic Customer 05", {"bank_account_no": bank()}, "bank_account"),
    ("C006", "Synthetic Customer 06", {"upi_id": "synthetic.user06@okhdfcbank"}, "upi"),
    ("C007", "Synthetic Customer 07", {"mobile": "+91 " + mobile()}, "mobile"),
    ("C008", "Synthetic Customer 08", {"email": "person@gmail.com"}, ""),
    ("C009", "Synthetic Customer 09", {"last_login_ts": checksum_valid_timestamp()}, ""),
    ("C010", "Synthetic Customer 10", {"reference_no": checksum_valid_reference()}, ""),
]

with open(os.path.join(ROOT, "data", "synthetic_customers.csv"), "w", newline="") as fh:
    w = csv.writer(fh, lineterminator="\n")
    w.writerow(COLUMNS)
    for cid, name, vals, _ in ROWS:
        w.writerow([cid, name] + [vals.get(c, "") for c in COLUMNS[2:]])

with open(os.path.join(ROOT, "data", "synthetic_customers_labels.csv"), "w", newline="") as fh:
    w = csv.writer(fh, lineterminator="\n")
    w.writerow(["customer_id", "expected_rule"])
    for cid, _, _, rule in ROWS:
        w.writerow([cid, ("india." + rule) if rule else ""])

A, P, G, B, M = aadhaar(), pan(), gstin(), bank(), mobile()
with open(os.path.join(ROOT, "data", "sample_app.log"), "w") as fh:
    fh.write(
        "2026-03-01 10:15:02,114 INFO  [kyc] customer verified aadhaar=%s pan=%s\n"
        "2026-03-01 10:15:03,201 DEBUG [payments] payout to vpa=synthetic.user@okhdfcbank status=OK\n"
        "2026-03-01 10:15:03,950 INFO  [payments] settlement account no: %s ifsc: ICIC0001234\n"
        "2026-03-01 10:15:04,555 INFO  [auth] user person@gmail.com logged in\n"
        "2026-03-01 10:15:05,000 INFO  [metrics] timestamp=%s queue_depth=14\n"
        "2026-03-01 10:15:06,321 WARN  [sms] retry sending to mobile=+91 %s\n"
        "2026-03-01 10:15:07,008 INFO  [billing] order_id=%s processed\n"
        % (A, P, B, checksum_valid_timestamp(), M, checksum_valid_reference())
    )

with open(os.path.join(ROOT, "data", "sample_service.py"), "w") as fh:
    fh.write(
        '"""Synthetic service config used by the scanner demo. Not real data."""\n'
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # AWS documentation example key\n'
        'SERVICE_API_KEY = "%s"\n'
        'MERCHANT = {\n'
        '    "gstin": "%s",\n'
        '    "settlement_bank_account": "%s",\n'
        '    "upi_vpa": "merchant.demo@ybl",\n'
        '}\n'
        'REQUEST_TIMEOUT_SECONDS = 30\n'
        % ("q8Zr2LkP9xWm4TvB7nYc1HdS5gJf3QaE", gstin(), bank())
    )
print("synthetic data written")

from conftest import make_aadhaar, make_aws_key, make_card, make_github_token
from dlp_cli.detectors import detect_line, luhn_ok, mask, verhoeff_ok


def ids(line):
    return [m.rule.id for m in detect_line(line)]


def test_card_with_valid_luhn_is_found_with_exact_columns():
    line = f'card = "{make_card()}"'
    [m] = detect_line(line)
    assert m.rule.id == "DLP009" and line[m.start:m.end] == make_card()


def test_card_with_separators_found():
    assert ids("pay 4111-1111-1111-1111 now") == ["DLP009"]
    assert ids("pay 4111 1111 1111 1111 now") == ["DLP009"]


def test_bad_luhn_and_timestamp_are_not_cards():
    assert ids("id 4111111111111112") == []
    assert ids("ts 1696000000000") == []
    assert ids("order 1234567890123456") == []


def test_card_is_not_also_reported_as_aadhaar():
    assert ids(f"x {make_card()} y") == ["DLP009"]


def test_aadhaar_needs_verhoeff():
    good = make_aadhaar("23456789012")
    assert verhoeff_ok(good) and ids(f"aadhaar {good}") == ["DLP010"]
    spaced = f"{good[:4]} {good[4:8]} {good[8:]}"
    assert ids(spaced) == ["DLP010"]
    bad = good[:-1] + str((int(good[-1]) + 1) % 10)
    assert ids(f"aadhaar {bad}") == []
    assert ids("012345678901") == []  # cannot start with 0 or 1


def test_pan_and_email():
    assert ids("PAN ABCPE1234F") == ["DLP011"]
    assert ids("mail a.b@example.test") == ["DLP012"]


def test_secrets():
    assert ids(make_aws_key()) == ["DLP002"]
    assert ids(f"token={make_github_token()}") == ["DLP004"]
    assert ids("-----BEGIN RSA PRIVATE KEY-----") == ["DLP001"]
    assert ids("-----BEGIN OPENSSH PRIVATE KEY-----") == ["DLP001"]
    assert ids('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"') == ["DLP003"]
    assert ids("AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q") == ["DLP006"]
    assert ids("xoxb-1234567890-abcdefghij") == ["DLP005"]


def test_hardcoded_secret_needs_entropy_and_not_placeholder():
    assert ids('password = "Zx9!qL2#vB7mKp4w"') == ["DLP008"]
    assert ids('password = "changeme123"') == []
    assert ids('password = "your_password_here"') == []
    assert ids('password = "aaaaaaaaaaaa"') == []
    assert ids("password = os.environ['PW']") == []


def test_prefixed_api_key():
    assert ids("sk_live_" + "Q7wE3rT9yU1iO5pA") == ["DLP007"]
    assert ids("sk_live_aaaaaaaaaaaaaaaa") == []


def test_mask_never_returns_raw_and_hides_short_values():
    assert mask("abcd") == "****"
    masked = mask(make_card())
    assert make_card() not in masked and masked.startswith("41") and masked.endswith("11")


def test_luhn_helper():
    assert luhn_ok(make_card()) and not luhn_ok("4111111111111112")


def test_long_minified_line_is_still_scanned_in_windows():
    from dlp_cli.config import Config
    from dlp_cli.scanner import Scanner
    from pathlib import Path

    scanner = Scanner(Config(), Path("."))
    line = ("a" * 10_000) + " " + make_aws_key() + " " + ("b" * 10_000)
    scanner.scan_text_line("x.js", 1, line)
    [f] = scanner.report.findings
    assert f.column == 10_002

from app.analyzers.sender_auth import DMARC_FAIL, UNVERIFIED, SenderAuthenticationAnalyzer
from tests.helpers import email_with_headers

FROM_PAYPAL = "From: PayPal <service@paypal.com>"


def gmail_stamp(results: str) -> str:
    return f"Authentication-Results: mx.google.com; {results}"


def finding_ids(*header_lines: str) -> list[str]:
    detections = SenderAuthenticationAnalyzer().analyze(email_with_headers(*header_lines))
    return [detection.finding_id for detection in detections]


def test_all_checks_passing_is_clean() -> None:
    stamp = gmail_stamp("dkim=pass header.i=@paypal.com; spf=pass smtp.mailfrom=paypal.com; dmarc=pass header.from=paypal.com")

    assert finding_ids(stamp, FROM_PAYPAL) == []


def test_dmarc_failure_is_reported() -> None:
    stamp = gmail_stamp("dkim=pass header.i=@evil.com; spf=pass smtp.mailfrom=evil.com; dmarc=fail (p=REJECT) header.from=paypal.com")

    assert finding_ids(stamp, FROM_PAYPAL) == [DMARC_FAIL]


def test_neither_spf_nor_dkim_passing_is_unverified() -> None:
    stamp = gmail_stamp("dkim=none; spf=softfail (google.com: domain of x does not designate 1.2.3.4) smtp.mailfrom=x.com")

    assert finding_ids(stamp, FROM_PAYPAL) == [UNVERIFIED]


def test_only_strongest_outcome_is_reported() -> None:
    stamp = gmail_stamp("dkim=fail; spf=fail; dmarc=fail header.from=paypal.com")

    assert finding_ids(stamp, FROM_PAYPAL) == [DMARC_FAIL]


def test_one_passing_dkim_signature_is_enough() -> None:
    stamp = gmail_stamp("dkim=fail header.i=@list.org; dkim=pass header.i=@paypal.com; spf=fail; dmarc=pass")

    assert finding_ids(stamp, FROM_PAYPAL) == []


def test_forged_pass_below_gmail_stamp_is_ignored() -> None:
    real = gmail_stamp("dkim=none; spf=fail; dmarc=fail header.from=paypal.com")
    forged = gmail_stamp("dkim=pass; spf=pass; dmarc=pass")

    assert finding_ids(real, forged, FROM_PAYPAL) == [DMARC_FAIL]


def test_stamp_not_written_by_gmail_is_ignored() -> None:
    forged = "Authentication-Results: attacker.example; dmarc=fail"

    assert finding_ids(forged, FROM_PAYPAL) == []


def test_missing_stamp_gives_no_verdict() -> None:
    assert finding_ids(FROM_PAYPAL) == []

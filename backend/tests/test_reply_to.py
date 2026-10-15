import pytest

from app.analyzers.reply_to import REPLY_TO_MISMATCH, ReplyToMismatchAnalyzer
from tests.helpers import email_with_headers


def finding_ids(*header_lines: str) -> list[str]:
    detections = ReplyToMismatchAnalyzer().analyze(email_with_headers(*header_lines))
    return [detection.finding_id for detection in detections]


@pytest.mark.parametrize(
    "reply_to",
    [
        "Reply-To: ceo.company@gmail.com",
        "Reply-To: billing@company.com, ceo.company@gmail.com",
    ],
    ids=["different-domain", "one-of-several-differs"],
)
def test_reply_to_another_organization_is_flagged(reply_to: str) -> None:
    assert finding_ids("From: CEO <ceo@company.com>", reply_to) == [REPLY_TO_MISMATCH]


@pytest.mark.parametrize(
    "reply_to",
    [
        "Reply-To: support@company.com",
        "Reply-To: support@help.company.com",
        "Reply-To: Support@COMPANY.com",
    ],
    ids=["same-domain", "subdomain", "different-case"],
)
def test_reply_to_same_organization_is_clean(reply_to: str) -> None:
    assert finding_ids("From: news@company.com", reply_to) == []


def test_no_reply_to_is_clean() -> None:
    assert finding_ids("From: news@company.com") == []

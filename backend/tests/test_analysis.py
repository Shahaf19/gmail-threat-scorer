import logging

import pytest

from app.analysis import RuleBasedAnalysisService
from app.analyzers.base import Detection
from app.parsed_email import ParsedEmail
from app.schemas import MAX_SCORE, AnalyzeRequest, AnalyzeResponse, Verdict
from app.scoring import MALICIOUS_FROM, SUSPICIOUS_FROM, verdict_for

POINTS = {
    "known_malware_hash": 100,
    "spf_fail": 40,
    "lookalike_domain": 35,
    "urgent_language": 10,
}
EMAIL_CONTENT_IN_ERROR = "secret-from-the-email"


class FixedAnalyzer:
    def __init__(self, *finding_ids: str, name: str = "Fixed check") -> None:
        self.name = name
        self._finding_ids = finding_ids

    def analyze(self, email: ParsedEmail) -> list[Detection]:
        return [Detection(finding_id=id_, title=id_, detail="") for id_ in self._finding_ids]


class CrashingAnalyzer:
    name = "Crashing check"

    def analyze(self, email: ParsedEmail) -> list[Detection]:
        raise ValueError(EMAIL_CONTENT_IN_ERROR)


def analyze_with(*analyzers: object) -> AnalyzeResponse:
    email = AnalyzeRequest(
        headers="From: a@example.com",
        subject="",
        body_text="",
        body_html="",
        truncated=False,
        attachments=[],
    )
    return RuleBasedAnalysisService(analyzers, POINTS).analyze(email)


def test_no_findings_means_safe_with_zero_score() -> None:
    result = analyze_with(FixedAnalyzer())

    assert (result.score, result.verdict, result.findings) == (0, Verdict.SAFE, [])


def test_points_add_up_and_findings_rank_highest_first() -> None:
    result = analyze_with(FixedAnalyzer("urgent_language", "spf_fail"), FixedAnalyzer("lookalike_domain"))

    assert result.score == 85
    assert [finding.id for finding in result.findings] == ["spf_fail", "lookalike_domain", "urgent_language"]
    assert result.verdict is Verdict.MALICIOUS


def test_score_is_capped_at_maximum() -> None:
    result = analyze_with(FixedAnalyzer("known_malware_hash", "spf_fail"))

    assert result.score == MAX_SCORE


def test_same_finding_counts_once() -> None:
    result = analyze_with(FixedAnalyzer("spf_fail"), FixedAnalyzer("spf_fail"))

    assert result.score == POINTS["spf_fail"]
    assert len(result.findings) == 1


def test_crashing_analyzer_is_skipped_and_reported() -> None:
    result = analyze_with(CrashingAnalyzer(), FixedAnalyzer("spf_fail"))

    assert result.skipped_checks == [CrashingAnalyzer.name]
    assert result.score == POINTS["spf_fail"]


def test_crash_log_does_not_contain_email_content(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        analyze_with(CrashingAnalyzer())

    assert CrashingAnalyzer.name in caplog.text
    assert EMAIL_CONTENT_IN_ERROR not in caplog.text


def test_unknown_finding_id_counts_as_analyzer_failure() -> None:
    result = analyze_with(FixedAnalyzer("not_in_policy", name="Buggy check"))

    assert result.skipped_checks == ["Buggy check"]
    assert result.findings == []


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, Verdict.SAFE),
        (SUSPICIOUS_FROM - 1, Verdict.SAFE),
        (SUSPICIOUS_FROM, Verdict.SUSPICIOUS),
        (MALICIOUS_FROM - 1, Verdict.SUSPICIOUS),
        (MALICIOUS_FROM, Verdict.MALICIOUS),
        (MAX_SCORE, Verdict.MALICIOUS),
    ],
)
def test_verdict_thresholds(score: int, expected: Verdict) -> None:
    assert verdict_for(score) is expected

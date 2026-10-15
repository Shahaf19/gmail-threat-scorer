"""Runs every analyzer, scores what they found, and turns the score into a verdict."""

import logging
from collections.abc import Mapping, Sequence
from typing import Protocol

from app.analyzers.base import Analyzer, Detection
from app.parsed_email import ParsedEmail, parse_email
from app.schemas import AnalyzeRequest, AnalyzeResponse, Finding
from app.scoring import total_score, verdict_for

logger = logging.getLogger(__name__)

# Finding text can quote attacker-controlled values (e.g. a 100,000-character domain); capping it keeps
# the add-on card displayable, so an oversized value can't turn a verdict into "couldn't analyze".
MAX_FINDING_TEXT_CHARS = 300
ELLIPSIS = "..."


def _shorten(text: str) -> str:
    if len(text) <= MAX_FINDING_TEXT_CHARS:
        return text
    return text[: MAX_FINDING_TEXT_CHARS - len(ELLIPSIS)] + ELLIPSIS


class AnalysisService(Protocol):
    def analyze(self, email: AnalyzeRequest) -> AnalyzeResponse: ...


class RuleBasedAnalysisService:
    def __init__(self, analyzers: Sequence[Analyzer], finding_points: Mapping[str, int]) -> None:
        self._analyzers = analyzers
        self._finding_points = finding_points

    def analyze(self, email: AnalyzeRequest) -> AnalyzeResponse:
        findings, skipped_checks = self._run_analyzers(parse_email(email))
        ranked = sorted(findings, key=lambda finding: finding.points, reverse=True)
        score = total_score(finding.points for finding in ranked)
        return AnalyzeResponse(
            score=score,
            verdict=verdict_for(score),
            findings=ranked,
            skipped_checks=skipped_checks,
        )

    def _run_analyzers(self, email: ParsedEmail) -> tuple[list[Finding], list[str]]:
        findings_by_id: dict[str, Finding] = {}
        skipped_checks: list[str] = []
        for analyzer in self._analyzers:
            try:
                # Scoring inside the try makes an unknown finding id count as that analyzer failing.
                findings = [self._to_finding(detection) for detection in analyzer.analyze(email)]
            except Exception as error:
                # One failing check must not silence the others. Only the error type is logged:
                # error messages can quote email content.
                logger.warning("Analyzer %r failed: %s", analyzer.name, type(error).__name__)
                skipped_checks.append(analyzer.name)
                continue
            for finding in findings:
                # Each kind of finding counts once, so repeated weak signals can't pile up.
                findings_by_id.setdefault(finding.id, finding)
        return list(findings_by_id.values()), skipped_checks

    def _to_finding(self, detection: Detection) -> Finding:
        return Finding(
            id=detection.finding_id,
            title=_shorten(detection.title),
            detail=_shorten(detection.detail),
            points=self._finding_points[detection.finding_id],
        )

"""Boundary between the HTTP layer and the analysis pipeline."""

from typing import Protocol

from app.schemas import MIN_SCORE, AnalyzeRequest, AnalyzeResponse, Verdict


class AnalysisService(Protocol):
    def analyze(self, email: AnalyzeRequest) -> AnalyzeResponse: ...


class StubAnalysisService:
    """Fixed result so the add-on can be wired end to end before the scoring engine exists."""

    def analyze(self, email: AnalyzeRequest) -> AnalyzeResponse:
        return AnalyzeResponse(score=MIN_SCORE, verdict=Verdict.SAFE, findings=[])

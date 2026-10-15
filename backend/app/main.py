"""HTTP entry point: routes, input guards and dependency wiring."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app import limits
from app.analysis import AnalysisService, RuleBasedAnalysisService
from app.analyzer_registry import build_analyzers
from app.body_size_limit import BodySizeLimitMiddleware
from app.feedback import record_feedback
from app.schemas import AnalyzeRequest, AnalyzeResponse, FeedbackRequest
from app.scoring import COMBINATIONS, FINDING_POINTS

INVALID_REQUEST_DETAIL = "Invalid request"

# Without this, Python drops INFO messages and the feedback line would never reach Cloud Run's log.
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

_analysis_service = RuleBasedAnalysisService(build_analyzers(), FINDING_POINTS, COMBINATIONS)

router = APIRouter()


def get_analysis_service() -> AnalysisService:
    return _analysis_service


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze(
    email: AnalyzeRequest,
    service: Annotated[AnalysisService, Depends(get_analysis_service)],
) -> AnalyzeResponse:
    return service.analyze(email)


@router.post("/feedback")
def feedback(rating: FeedbackRequest) -> dict[str, str]:
    record_feedback(rating)
    return {"status": "recorded"}


async def _reject_invalid_request(_: Request, __: RequestValidationError) -> JSONResponse:
    # FastAPI's default handler echoes the offending input back. Here that input is email
    # content, so echoing it would reflect attacker-controlled data (up to megabytes) to callers.
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": INVALID_REQUEST_DETAIL},
    )


def create_app() -> FastAPI:
    # Interactive docs are off: a public endpoint has no reason to advertise its own schema.
    app = FastAPI(title="Gmail Threat Scorer", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=limits.MAX_REQUEST_BYTES)
    app.add_exception_handler(RequestValidationError, _reject_invalid_request)
    app.include_router(router)
    return app


app = create_app()

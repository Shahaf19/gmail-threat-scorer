"""HTTP entry point: routes, input guards and dependency wiring."""

from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app import limits
from app.analysis import AnalysisService, RuleBasedAnalysisService
from app.analyzers.base import Analyzer
from app.analyzers.language import SensitiveInfoRequestAnalyzer, UrgentLanguageAnalyzer
from app.analyzers.links import LinkAnalyzer
from app.analyzers.lookalike_domain import LookalikeDomainAnalyzer
from app.analyzers.reply_to import ReplyToMismatchAnalyzer
from app.analyzers.sender_auth import SenderAuthenticationAnalyzer
from app.body_size_limit import BodySizeLimitMiddleware
from app.data.brands import BRANDS
from app.data.top_sites import load_top_sites
from app.schemas import AnalyzeRequest, AnalyzeResponse
from app.scoring import FINDING_POINTS

INVALID_REQUEST_DETAIL = "Invalid request"

ANALYZERS: list[Analyzer] = [
    SenderAuthenticationAnalyzer(),
    ReplyToMismatchAnalyzer(),
    LookalikeDomainAnalyzer(load_top_sites(), BRANDS),
    LinkAnalyzer(),
    UrgentLanguageAnalyzer(),
    SensitiveInfoRequestAnalyzer(),
]

_analysis_service = RuleBasedAnalysisService(ANALYZERS, FINDING_POINTS)

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

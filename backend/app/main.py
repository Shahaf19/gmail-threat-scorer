"""HTTP entry point: routes, input guards and dependency wiring."""

from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app import limits
from app.analysis import AnalysisService, StubAnalysisService
from app.body_size_limit import BodySizeLimitMiddleware
from app.schemas import AnalyzeRequest, AnalyzeResponse

INVALID_REQUEST_DETAIL = "Invalid request"

router = APIRouter()


def get_analysis_service() -> AnalysisService:
    return StubAnalysisService()


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

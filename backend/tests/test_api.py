from collections.abc import Callable, Iterator

import pytest
from fastapi.testclient import TestClient

from app import limits
from app.main import create_app, get_analysis_service
from app.schemas import AnalyzeRequest, AnalyzeResponse, Finding, Verdict

STREAM_CHUNK_BYTES = 64 * 1024
ECHO_SENTINEL = "SENTINEL-must-not-be-echoed"


def valid_request() -> dict:
    return {
        "headers": "From: Alice <alice@example.com>\r\nSubject: Hi\r\n",
        "subject": "Hi",
        "body_text": "Hello",
        "body_html": "<p>Hello</p>",
        "truncated": False,
        "attachments": [
            {
                "filename": "report.pdf",
                "mime_type": "application/pdf",
                "size_bytes": 1024,
                "sha256": "a" * 64,
            }
        ],
    }


def with_fields(**changes: object) -> dict:
    return {**valid_request(), **changes}


def without_field(name: str) -> dict:
    request = valid_request()
    del request[name]
    return request


def with_attachment_fields(**changes: object) -> dict:
    request = valid_request()
    request["attachments"][0].update(changes)
    return request


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


def test_health_reports_ok(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_valid_request_returns_a_verdict(client: TestClient) -> None:
    response = client.post("/analyze", json=valid_request())

    assert response.status_code == 200
    AnalyzeResponse.model_validate(response.json())


def test_route_returns_the_injected_service_result() -> None:
    expected = AnalyzeResponse(
        score=90,
        verdict=Verdict.MALICIOUS,
        findings=[Finding(id="test", title="Test", detail="Injected", points=90)],
        skipped_checks=[],
    )

    class FixedService:
        def analyze(self, email: AnalyzeRequest) -> AnalyzeResponse:
            return expected

    app = create_app()
    app.dependency_overrides[get_analysis_service] = FixedService
    response = TestClient(app).post("/analyze", json=valid_request())

    assert response.json() == expected.model_dump(mode="json")


@pytest.mark.parametrize(
    "build_request",
    [
        pytest.param(lambda: with_fields(is_admin=True), id="unknown-field"),
        pytest.param(lambda: without_field("headers"), id="missing-field"),
        pytest.param(lambda: with_fields(headers=""), id="empty-headers"),
        pytest.param(lambda: with_fields(truncated="false"), id="string-instead-of-bool"),
        pytest.param(lambda: with_attachment_fields(size_bytes="1024"), id="string-instead-of-int"),
        pytest.param(lambda: with_attachment_fields(size_bytes=-1), id="negative-size"),
        pytest.param(lambda: with_attachment_fields(sha256="not-a-hash"), id="malformed-hash"),
        pytest.param(lambda: with_attachment_fields(sha256="A" * 64), id="uppercase-hash"),
        pytest.param(
            lambda: with_fields(body_text="x" * (limits.MAX_BODY_CHARS + 1)),
            id="body-over-cap",
        ),
        pytest.param(
            lambda: with_fields(subject="x" * (limits.MAX_SUBJECT_CHARS + 1)),
            id="subject-over-cap",
        ),
        pytest.param(
            lambda: with_fields(attachments=valid_request()["attachments"] * (limits.MAX_ATTACHMENTS + 1)),
            id="too-many-attachments",
        ),
    ],
)
def test_invalid_request_is_rejected(client: TestClient, build_request: Callable[[], dict]) -> None:
    response = client.post("/analyze", json=build_request())

    assert response.status_code == 422


def test_malformed_json_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/analyze", content=b"{not json", headers={"content-type": "application/json"}
    )

    assert response.status_code == 422


def test_rejection_does_not_echo_input(client: TestClient) -> None:
    response = client.post("/analyze", json=with_fields(body_text=ECHO_SENTINEL, is_admin=True))

    assert response.status_code == 422
    assert ECHO_SENTINEL not in response.text


def test_body_declared_over_limit_is_rejected(client: TestClient) -> None:
    oversized = b"x" * (limits.MAX_REQUEST_BYTES + 1)

    response = client.post(
        "/analyze", content=oversized, headers={"content-type": "application/json"}
    )

    assert response.status_code == 413


def test_streamed_body_over_limit_is_rejected(client: TestClient) -> None:
    def chunks() -> Iterator[bytes]:
        sent = 0
        while sent <= limits.MAX_REQUEST_BYTES:
            yield b"x" * STREAM_CHUNK_BYTES
            sent += STREAM_CHUNK_BYTES

    response = client.post(
        "/analyze", content=chunks(), headers={"content-type": "application/json"}
    )

    assert "content-length" not in response.request.headers
    assert response.status_code == 413


def test_feedback_is_accepted_and_malformed_feedback_is_not(client: TestClient) -> None:
    good = {"verdict": "safe", "score": 5, "finding_ids": ["tracking_pixel"], "rating": "wrong"}

    assert client.post("/feedback", json=good).json() == {"status": "recorded"}
    assert client.post("/feedback", json={**good, "finding_ids": ["bad\nline"]}).status_code == 422
    assert client.post("/feedback", json={**good, "rating": "maybe"}).status_code == 422


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_api_schema_is_not_published(client: TestClient, path: str) -> None:
    assert client.get(path).status_code == 404

"""Rejects oversized request bodies before they are buffered in memory.

Schema length checks only run after the whole body has been read and parsed, so on their
own they cannot stop a huge upload from exhausting the server's memory.
"""

from fastapi import HTTPException, status
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

TOO_LARGE_DETAIL = "Request body too large"


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self._app = app
        self._max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        if self._declared_length(scope) > self._max_bytes:
            await _too_large_response()(scope, receive, send)
            return
        await self._app(scope, self._limited(receive), send)

    @staticmethod
    def _declared_length(scope: Scope) -> int:
        for name, value in scope["headers"]:
            if name == b"content-length" and value.isdigit():
                return int(value)
        return 0

    def _limited(self, receive: Receive) -> Receive:
        # A chunked upload declares no length, so the bytes are also counted as they arrive.
        received_bytes = 0

        async def receive_within_limit() -> Message:
            nonlocal received_bytes
            message = await receive()
            received_bytes += len(message.get("body", b""))
            if received_bytes > self._max_bytes:
                raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, TOO_LARGE_DETAIL)
            return message

        return receive_within_limit


def _too_large_response() -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
        content={"detail": TOO_LARGE_DETAIL},
    )

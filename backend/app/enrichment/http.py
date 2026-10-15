"""The one way this backend calls outside services.

Everything that comes back is untrusted: it is bounded in time and size, redirects are never followed
(a redirect could send our request, and any key in it, to an address the service didn't choose),
and the body is only ever parsed as JSON data.
"""

import json
from collections.abc import Mapping

import requests

REQUEST_TIMEOUT_SECONDS = 3
MAX_RESPONSE_BYTES = 512 * 1024
HTTP_OK = 200


class ExternalServiceError(Exception):
    """An outside service failed or answered with something unusable.

    The message never contains the request URL or headers, which may hold a secret key.
    """

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def fetch_json(
    method: str, url: str, *, headers: Mapping[str, str] | None = None, data: Mapping[str, str] | None = None
) -> object:
    try:
        with requests.request(
            method, url, headers=headers, data=data, timeout=REQUEST_TIMEOUT_SECONDS, allow_redirects=False, stream=True
        ) as response:
            if response.status_code != HTTP_OK:
                raise ExternalServiceError(f"HTTP {response.status_code}", response.status_code)
            body = response.raw.read(MAX_RESPONSE_BYTES + 1, decode_content=True)
    except requests.RequestException as error:
        raise ExternalServiceError(type(error).__name__) from error
    if len(body) > MAX_RESPONSE_BYTES:
        raise ExternalServiceError("response too large")
    try:
        return json.loads(body)
    except ValueError as error:
        raise ExternalServiceError("response is not JSON") from error

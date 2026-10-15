"""abuse.ch lookups: MalwareBazaar for file hashes, URLhaus for hosts that serve malware.

Needs a free abuse.ch Auth-Key. The key goes in a request header, never in a URL or a log line.
"""

from collections.abc import Callable

from app.enrichment.http import ExternalServiceError, fetch_json

MALWARE_BAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
URLHAUS_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"
MAX_HOST_CHARS = 253

STATUS_OK = "ok"
HASH_NOT_FOUND = "hash_not_found"
HOST_NO_RESULTS = "no_results"
HOST_INVALID = "invalid_host"
URL_ONLINE = "online"


class AbuseChClient:
    def __init__(self, auth_key: str, fetch: Callable[..., object] = fetch_json) -> None:
        self._headers = {"Auth-Key": auth_key}
        self._fetch = fetch

    def is_known_malware(self, sha256: str) -> bool:
        answer = self._fetch("POST", MALWARE_BAZAAR_URL, headers=self._headers, data={"query": "get_info", "hash": sha256})
        status = _status(answer)
        if status == STATUS_OK:
            return True
        if status == HASH_NOT_FOUND:
            return False
        # Any other answer is a surprise (or our own bug): report "couldn't check", never "clean".
        raise ExternalServiceError(f"unexpected status {status!r}")

    def serves_live_malware(self, host: str) -> bool:
        answer = self._fetch("POST", URLHAUS_HOST_URL, headers=self._headers, data={"host": host[:MAX_HOST_CHARS]})
        status = _status(answer)
        if status in (HOST_NO_RESULTS, HOST_INVALID):
            return False
        if status != STATUS_OK:
            raise ExternalServiceError(f"unexpected status {status!r}")
        urls = answer.get("urls") if isinstance(answer, dict) else None
        return isinstance(urls, list) and any(isinstance(url, dict) and url.get("url_status") == URL_ONLINE for url in urls)


def _status(answer: object) -> object:
    if not isinstance(answer, dict):
        raise ExternalServiceError("unexpected answer format")
    # The URLhaus documentation's own example spells the key "query_staus".
    return answer.get("query_status", answer.get("query_staus"))

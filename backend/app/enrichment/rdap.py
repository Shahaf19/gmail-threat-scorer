"""Looks up when a domain was registered, using RDAP (the standard, machine-readable "whois").

Only the registry servers listed in IANA's official bootstrap file are ever contacted.
"""

import re
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from datetime import datetime, timezone

from app.domains import to_ascii
from app.enrichment.http import ExternalServiceError, fetch_json

IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
HTTPS_PREFIX = "https://"
NOT_FOUND = 404
DAY_SECONDS = 24 * 60 * 60
MAX_CACHED_DOMAINS = 1_000
RDAP_ACCEPT = {"Accept": "application/rdap+json"}
# Only plain ASCII hostnames reach a registry's URL: anything else could change the request's path or query.
_SAFE_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")

Fetch = Callable[..., object]


class RdapClient:
    def __init__(self, fetch: Fetch = fetch_json, clock: Callable[[], float] = time.time) -> None:
        self._fetch = fetch
        self._clock = clock
        self._lock = threading.Lock()
        self._servers: dict[str, str] = {}
        self._servers_loaded_at: float | None = None
        self._dates: OrderedDict[str, datetime | None] = OrderedDict()

    def registration_date(self, domain: str) -> datetime | None:
        """None when the registry doesn't say (unsupported ending, unknown domain). Raises ExternalServiceError on failure."""
        ascii_domain = to_ascii(domain.lower())
        if not _SAFE_DOMAIN.match(ascii_domain):
            return None
        with self._lock:
            if ascii_domain in self._dates:
                return self._dates[ascii_domain]
        date = self._look_up(ascii_domain)
        with self._lock:
            self._dates[ascii_domain] = date
            if len(self._dates) > MAX_CACHED_DOMAINS:
                self._dates.popitem(last=False)
        return date

    def _look_up(self, domain: str) -> datetime | None:
        server = self._server_for(domain.rsplit(".", 1)[-1])
        if server is None:
            return None
        try:
            answer = self._fetch("GET", f"{server}domain/{domain}", headers=RDAP_ACCEPT)
        except ExternalServiceError as error:
            if error.status_code == NOT_FOUND:
                return None
            raise
        return _registration_event(answer)

    def _server_for(self, ending: str) -> str | None:
        with self._lock:
            expired = self._servers_loaded_at is None or self._clock() - self._servers_loaded_at > DAY_SECONDS
        if expired:
            servers = _parse_bootstrap(self._fetch("GET", IANA_BOOTSTRAP_URL))
            with self._lock:
                self._servers, self._servers_loaded_at = servers, self._clock()
        with self._lock:
            return self._servers.get(ending)


def _parse_bootstrap(document: object) -> dict[str, str]:
    servers: dict[str, str] = {}
    services = document.get("services") if isinstance(document, dict) else None
    if not isinstance(services, list):
        raise ExternalServiceError("unexpected bootstrap format")
    for service in services:
        if not (isinstance(service, list) and len(service) == 2):
            continue
        endings, urls = service
        https_url = next((url for url in urls if isinstance(url, str) and url.startswith(HTTPS_PREFIX)), None)
        if https_url:
            base = https_url if https_url.endswith("/") else https_url + "/"
            servers.update({ending: base for ending in endings if isinstance(ending, str)})
    return servers


def _registration_event(answer: object) -> datetime | None:
    events = answer.get("events") if isinstance(answer, dict) else None
    if not isinstance(events, list):
        return None
    for event in events:
        if isinstance(event, dict) and event.get("eventAction") == "registration":
            return _parse_date(event.get("eventDate"))
    return None


def _parse_date(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

from datetime import datetime, timezone

import pytest

from app.enrichment.abusech import AbuseChClient
from app.enrichment.http import ExternalServiceError
from app.enrichment.rdap import IANA_BOOTSTRAP_URL, RdapClient

BOOTSTRAP = {"services": [[["com"], ["https://rdap.example-registry.test/com/v1/"]]]}


def rdap_with(answer: object, calls: list[str]) -> RdapClient:
    def fetch(method: str, url: str, **_: object) -> object:
        calls.append(url)
        return BOOTSTRAP if url == IANA_BOOTSTRAP_URL else answer

    return RdapClient(fetch=fetch)


def test_registration_date_is_read_from_the_registry_answer() -> None:
    calls: list[str] = []
    answer = {"events": [{"eventAction": "registration", "eventDate": "2026-10-01T10:00:00Z"}]}

    date = rdap_with(answer, calls).registration_date("paypal-security.com")

    assert date == datetime(2026, 10, 1, 10, tzinfo=timezone.utc)
    assert calls[-1] == "https://rdap.example-registry.test/com/v1/domain/paypal-security.com"


def test_unsupported_ending_and_unsafe_names_never_reach_the_network() -> None:
    calls: list[str] = []
    client = rdap_with({}, calls)

    assert client.registration_date("example.co.il") is None
    assert client.registration_date("evil.com/../../x?y=1") is None
    assert calls == [IANA_BOOTSTRAP_URL]


def test_unexpected_malware_bazaar_answer_is_an_error_not_a_clean_result() -> None:
    def fetch(*_: object, **__: object) -> object:
        return {"query_status": "something_new"}

    with pytest.raises(ExternalServiceError):
        AbuseChClient("key", fetch=fetch).is_known_malware("a" * 64)


def test_abuse_ch_answers_are_interpreted() -> None:
    def fetch(method: str, url: str, **_: object) -> object:
        if "mb-api" in url:
            return {"query_status": "hash_not_found"}
        return {"query_status": "ok", "urls": [{"url_status": "offline"}, {"url_status": "online"}]}

    client = AbuseChClient("key", fetch=fetch)

    assert client.is_known_malware("a" * 64) is False
    assert client.serves_live_malware("bad.example") is True

"""Checks attachment fingerprints and link hosts against abuse.ch's lists of known malware.

Only SHA-256 hashes and host names leave this server, never file contents or message text.
"""

from app.analyzers.base import Detection
from app.domains import has_public_suffix, split_domain
from app.enrichment.abusech import AbuseChClient
from app.enrichment.http import ExternalServiceError
from app.enrichment.parallel import run_parallel
from app.parsed_email import ParsedEmail
from app.urls import parse_url

KNOWN_MALWARE_HASH = "known_malware_hash"
KNOWN_MALICIOUS_HOST = "known_malicious_host"

MAX_HASH_LOOKUPS = 5
MAX_HOST_LOOKUPS = 5
HASH = "hash"
HOST = "host"


class KnownBadAnalyzer:
    name = "Known threats check"

    def __init__(self, client: AbuseChClient, known_domains: frozenset[str]) -> None:
        self._client = client
        self._known_domains = known_domains

    def analyze(self, email: ParsedEmail) -> list[Detection]:
        queries = [(HASH, sha) for sha in _hashes(email)] + [(HOST, host) for host in self._hosts(email)]
        outcomes = run_parallel(self._ask, queries)
        if queries and all(isinstance(outcome, Exception) for outcome in outcomes.values()):
            raise ExternalServiceError("no known-threat lookup succeeded")
        found = {}
        for (kind, _), outcome in outcomes.items():
            if outcome is True:
                detection = _hash_detection() if kind == HASH else _host_detection()
                found.setdefault(detection.finding_id, detection)
        return list(found.values())

    def _ask(self, query: tuple[str, str]) -> bool:
        kind, value = query
        return self._client.is_known_malware(value) if kind == HASH else self._client.serves_live_malware(value)

    def _hosts(self, email: ParsedEmail) -> list[str]:
        hosts = []
        for link in email.links:
            url = parse_url(link.href)
            if not (url and url.host):
                continue
            # Big platforms (github.com, ...) host some malware too; listing the whole site would condemn every link to it.
            if url.is_numeric_address or (
                has_public_suffix(url.host) and split_domain(url.host).registrable not in self._known_domains
            ):
                hosts.append(url.host)
        return list(dict.fromkeys(hosts))[:MAX_HOST_LOOKUPS]


def _hashes(email: ParsedEmail) -> list[str]:
    return list(dict.fromkeys(attachment.sha256 for attachment in email.request.attachments))[:MAX_HASH_LOOKUPS]


def _hash_detection() -> Detection:
    return Detection(
        KNOWN_MALWARE_HASH,
        "Attachment is known malware",
        "An attachment's fingerprint matches a file reported as malware to MalwareBazaar.",
    )


def _host_detection() -> Detection:
    return Detection(
        KNOWN_MALICIOUS_HOST,
        "Link to a site serving malware",
        "A link goes to a website that URLhaus currently lists as distributing malware.",
    )

"""Scoring policy: how much each finding matters, and where the verdict lines fall.

All judgment lives in this one table so it can be reviewed and tuned in one place;
analyzers only report facts. A future learned model would replace exactly this table.
"""

from collections.abc import Iterable, Mapping

from app.analyzers import language, links, lookalike_domain, reply_to, sender_auth
from app.schemas import MAX_SCORE, MIN_SCORE, Verdict

SUSPICIOUS_FROM = 30
MALICIOUS_FROM = 70

# Finding id -> points. Entries are added together with the analyzers that emit them.
FINDING_POINTS: Mapping[str, int] = {
    sender_auth.DMARC_FAIL: 45,
    sender_auth.UNVERIFIED: 25,
    reply_to.REPLY_TO_MISMATCH: 20,
    lookalike_domain.LOOKALIKE_DOMAIN: 50,
    lookalike_domain.BRAND_IN_SUBDOMAIN: 35,
    lookalike_domain.BRAND_WITH_EXTRA_WORDS: 25,
    links.LINK_TEXT_MISMATCH: 35,
    links.LINK_USERINFO: 40,
    links.LINK_RAW_IP: 30,
    links.LINK_DANGEROUS_SCHEME: 40,
    language.URGENT_LANGUAGE: 10,
    language.SENSITIVE_INFO_REQUEST: 30,
}


def total_score(points: Iterable[int]) -> int:
    return max(MIN_SCORE, min(MAX_SCORE, sum(points)))


def verdict_for(score: int) -> Verdict:
    if score >= MALICIOUS_FROM:
        return Verdict.MALICIOUS
    if score >= SUSPICIOUS_FROM:
        return Verdict.SUSPICIOUS
    return Verdict.SAFE

"""Scoring policy: how much each finding matters, and where the verdict lines fall.

All judgment lives in this one table so it can be reviewed and tuned in one place;
analyzers only report facts. A future learned model would replace exactly this table.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from app.analyzers import (
    attachments,
    baseline,
    display_name,
    domain_age,
    known_bad,
    language,
    links,
    lookalike_domain,
    message_structure,
    reply_to,
    sender_auth,
)
from app.analyzers.base import Detection
from app.schemas import MAX_SCORE, MIN_SCORE, Verdict

SUSPICIOUS_FROM = 30
MALICIOUS_FROM = 70

CREDENTIAL_HARVEST = "credential_harvest_pattern"


@dataclass(frozen=True)
class Combination:
    """A pattern worse than the sum of its parts.

    Adding points under-rates signals that are ambiguous alone and damning together, so a combination adds
    its own finding when every `requires` finding and at least one `any_of` finding are present.
    """

    detection: Detection
    requires: frozenset[str]
    any_of: frozenset[str]


COMBINATIONS: tuple[Combination, ...] = (
    Combination(
        detection=Detection(
            CREDENTIAL_HARVEST,
            "Asks for secrets behind a disguise",
            "The email asks for private information while hiding where its links lead or who really sent it. "
            "Together, that is the classic phishing pattern.",
        ),
        requires=frozenset({language.SENSITIVE_INFO_REQUEST}),
        any_of=frozenset({
            links.LINK_TEXT_MISMATCH,
            links.LINK_USERINFO,
            links.LINK_RAW_IP,
            lookalike_domain.LOOKALIKE_DOMAIN,
            lookalike_domain.BRAND_IN_SUBDOMAIN,
            lookalike_domain.BRAND_WITH_EXTRA_WORDS,
            display_name.DISPLAY_NAME_BRAND_SPOOF,
            domain_age.DOMAIN_NEWLY_REGISTERED,
            reply_to.REPLY_TO_MISMATCH,
            baseline.KNOWN_NAME_NEW_DOMAIN,
            sender_auth.DMARC_FAIL,
            message_structure.EMAIL_FORM,
        }),
    ),
)

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
    attachments.ATTACHMENT_EXECUTABLE: 50,
    attachments.ATTACHMENT_REVERSED_NAME: 50,
    attachments.ATTACHMENT_DISGUISED_PROGRAM: 45,
    attachments.ATTACHMENT_DOUBLE_EXTENSION: 40,
    attachments.ATTACHMENT_MACRO: 25,
    attachments.ATTACHMENT_WEB_PAGE: 25,
    attachments.ATTACHMENT_ARCHIVE: 10,
    message_structure.EMAIL_FORM: 25,
    message_structure.HIDDEN_TEXT: 10,
    message_structure.IMAGE_ONLY_EMAIL: 10,
    message_structure.TRACKING_PIXEL: 5,
    message_structure.TRUNCATED_EMAIL: 5,
    baseline.KNOWN_NAME_NEW_DOMAIN: 35,
    baseline.FIRST_TIME_SENDER: 10,
    domain_age.DOMAIN_NEWLY_REGISTERED: 35,
    domain_age.DOMAIN_RECENTLY_REGISTERED: 15,
    known_bad.KNOWN_MALWARE_HASH: 100,
    known_bad.KNOWN_MALICIOUS_HOST: 60,
    display_name.DISPLAY_NAME_BRAND_SPOOF: 30,
    CREDENTIAL_HARVEST: 30,
}


def total_score(points: Iterable[int]) -> int:
    return max(MIN_SCORE, min(MAX_SCORE, sum(points)))


def verdict_for(score: int) -> Verdict:
    if score >= MALICIOUS_FROM:
        return Verdict.MALICIOUS
    if score >= SUSPICIOUS_FROM:
        return Verdict.SUSPICIOUS
    return Verdict.SAFE

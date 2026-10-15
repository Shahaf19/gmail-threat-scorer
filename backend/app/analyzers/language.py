"""Spots pressure tactics and requests for secrets in the subject and body."""

import re
import unicodedata

from app.analyzers.base import Detection
from app.confusables import skeleton
from app.data.phrases import NEGATIONS, REQUEST_VERBS, SECRET_KINDS, URGENCY_PHRASES, SecretKind
from app.parsed_email import ParsedEmail

URGENT_LANGUAGE = "urgent_language"
SENSITIVE_INFO_REQUEST = "sensitive_info_request"

# One urgent phrase is common in ordinary marketing mail; several together are a pressure campaign.
MIN_URGENCY_MATCHES = 2
MAX_CHARS_BETWEEN_VERB_AND_SECRET = 40  # within one sentence
NEGATION_LOOKBEHIND_CHARS = 30

_WHITESPACE = re.compile(r"\s+")


def normalize(text: str) -> str:
    """Lowercase, drop invisible characters and flatten look-alike letters, so obfuscation doesn't hide a phrase."""
    visible = "".join(char for char in text if unicodedata.category(char) != "Cf")  # zero-width and similar
    return skeleton(_WHITESPACE.sub(" ", visible))


def message_text(email: ParsedEmail) -> str:
    return normalize(f"{email.request.subject}\n{email.text}")


class UrgentLanguageAnalyzer:
    name = "Urgent language check"

    def __init__(self) -> None:
        self._phrases = [(phrase, normalize(phrase)) for phrase in URGENCY_PHRASES]

    def analyze(self, email: ParsedEmail) -> list[Detection]:
        text = message_text(email)
        matched = [(phrase, key) for phrase, key in self._phrases if key in text]
        # "urgent" inside "urgent action" is one signal, not two.
        distinct = [phrase for phrase, key in matched if not any(key != other and key in other for _, other in matched)]
        if len(distinct) < MIN_URGENCY_MATCHES:
            return []
        return [
            Detection(
                URGENT_LANGUAGE,
                "Pressure to act fast",
                f'Phrases like "{distinct[0]}" and "{distinct[1]}" try to rush you into acting without thinking.',
            )
        ]


class SensitiveInfoRequestAnalyzer:
    name = "Information request check"

    def __init__(self) -> None:
        verbs = _alternatives(REQUEST_VERBS)
        self._negation = re.compile(rf"\b(?:{_alternatives(NEGATIONS)})\b")
        self._patterns = [
            (kind, re.compile(rf"\b(?:{verbs})\b[^.!?\n]{{0,{MAX_CHARS_BETWEEN_VERB_AND_SECRET}}}?\b(?:{_alternatives(kind.objects)})\b"))
            for kind in SECRET_KINDS
        ]

    def analyze(self, email: ParsedEmail) -> list[Detection]:
        text = message_text(email)
        kind = self._first_request(text)
        if kind is None:
            return []
        return [
            Detection(
                SENSITIVE_INFO_REQUEST,
                "Asks for private information",
                f"The email asks you to send or enter {kind.label}. Legitimate companies don't ask for this by email.",
            )
        ]

    def _first_request(self, text: str) -> SecretKind | None:
        for kind, pattern in self._patterns:
            for match in pattern.finditer(text):
                if not self._is_warning(text, match.start()):
                    return kind
        return None

    def _is_warning(self, text: str, request_start: int) -> bool:
        # "Never share your password" is advice, not a request.
        before = text[max(0, request_start - NEGATION_LOOKBEHIND_CHARS):request_start]
        return self._negation.search(before) is not None


def _alternatives(words: tuple[str, ...]) -> str:
    return "|".join(re.escape(normalize(word)) for word in words)

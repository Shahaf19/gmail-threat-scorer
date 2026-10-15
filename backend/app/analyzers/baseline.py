"""Judges the sender against what is normal for this user: the add-on supplies the history as facts."""

from app.analyzers.base import Detection
from app.parsed_email import ParsedEmail

FIRST_TIME_SENDER = "first_time_sender"
KNOWN_NAME_NEW_DOMAIN = "known_name_new_domain"

# With an empty history everyone looks new, so "first time" only counts once the add-on has seen
# enough senders for that to mean something.
MIN_BASELINE_SENDERS = 20


class BaselineDeviationAnalyzer:
    name = "Sender history check"

    def analyze(self, email: ParsedEmail) -> list[Detection]:
        history = email.request.sender_history
        if history is None:
            return []
        found = []
        if history.name_seen_with_other_domain:
            found.append(
                Detection(
                    KNOWN_NAME_NEW_DOMAIN,
                    "Familiar name from a new address",
                    "This sender's name has written to you before, but from a different domain. "
                    "Impersonating a known contact this way is a common trick.",
                )
            )
        if not history.address_seen_before and history.known_sender_count >= MIN_BASELINE_SENDERS:
            found.append(
                Detection(FIRST_TIME_SENDER, "First time you hear from this sender",
                          "You haven't received mail from this address before.")
            )
        return found

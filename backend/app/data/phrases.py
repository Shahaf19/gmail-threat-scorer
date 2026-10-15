"""Wording that pressures people or asks for secrets. Plain English phrases; matching ignores case and obfuscation."""

from dataclasses import dataclass

# Pressure to act before thinking. Marketing mail uses some of these too, so one match proves nothing.
URGENCY_PHRASES: tuple[str, ...] = (
    "urgent",
    "act now",
    "act immediately",
    "immediate action",
    "respond immediately",
    "right away",
    "as soon as possible",
    "within 24 hours",
    "within 48 hours",
    "expires today",
    "final notice",
    "final warning",
    "last warning",
    "last chance",
    "limited time",
    "your account will be suspended",
    "your account will be closed",
    "your account will be locked",
    "your account has been suspended",
    "your account has been locked",
    "avoid suspension",
    "avoid penalties",
    "legal action",
    "failure to comply",
    "failure to respond",
    "unusual activity",
    "suspicious activity",
    "unauthorized access",
    "verify your account",
    "confirm your identity",
)

# Words that make a sentence a request ("send", "enter", ...).
REQUEST_VERBS: tuple[str, ...] = (
    "send", "reply with", "provide", "enter", "re-enter", "confirm", "verify", "update",
    "share", "submit", "give", "type", "disclose", "tell us", "buy", "purchase",
)

# Warnings that turn a request into its opposite: "never share your password".
NEGATIONS: tuple[str, ...] = (
    "not", "never", "don't", "dont", "won't", "cannot", "can't", "no one", "nobody", "without",
)


@dataclass(frozen=True)
class SecretKind:
    label: str  # shown to the user, e.g. "a password or login code"
    objects: tuple[str, ...]


SECRET_KINDS: tuple[SecretKind, ...] = (
    SecretKind(
        "a password or login code",
        ("password", "passcode", "pin", "login details", "login credentials", "security code",
         "verification code", "one-time code", "one time code", "otp", "authentication code"),
    ),
    SecretKind(
        "card or bank details",
        ("credit card", "debit card", "card number", "card details", "cvv", "cvc", "expiry date",
         "bank account", "account number", "routing number", "iban", "sort code", "bank details",
         "banking details", "payment details", "billing information"),
    ),
    SecretKind(
        "identity details such as an ID or social security number",
        ("social security", "ssn", "passport", "driver's license", "drivers license", "national id",
         "id number", "date of birth", "tax id"),
    ),
    SecretKind("a crypto recovery phrase", ("seed phrase", "recovery phrase", "private key")),
    SecretKind("gift cards", ("gift card", "gift cards")),
)

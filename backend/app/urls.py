"""Reads where a link goes the way a browser would, without ever requesting it."""

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

HTTP_SCHEMES = frozenset({"http", "https"})

# Browsers delete tabs and newlines anywhere in a URL and trim control characters and spaces from
# both ends, so "java<TAB>script:..." still runs as javascript. We must see what the browser sees.
_DELETED_BY_BROWSERS = re.compile(r"[\t\r\n]")
_TRIMMED_BY_BROWSERS = "".join(chr(code) for code in range(0x21))
# Dotted numbers or hex, as a browser also accepts them in place of an IP address (3232235777, 0xC0A80001).
_NUMERIC_HOST = re.compile(r"(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}")


@dataclass(frozen=True)
class ParsedUrl:
    scheme: str
    host: str | None
    has_userinfo: bool  # the "name@" part, as in https://paypal.com@evil.ru/

    @property
    def is_numeric_address(self) -> bool:
        if not self.host:
            return False
        try:
            ipaddress.ip_address(self.host)
            return True
        except ValueError:
            return _NUMERIC_HOST.fullmatch(self.host) is not None


def parse_url(href: str) -> ParsedUrl | None:
    cleaned = _DELETED_BY_BROWSERS.sub("", href).strip(_TRIMMED_BY_BROWSERS)
    if cleaned.lower().startswith(("http:", "https:")):
        # Browsers read "\" as "/" in web addresses; Python does not. Without this, a
        # parser-vs-browser mismatch lets https://evil.ru\@paypal.com/ hide its real host.
        cleaned = cleaned.replace("\\", "/")
    try:
        parts = urlsplit(cleaned)
    except ValueError:
        return None
    host = (parts.hostname or "").rstrip(".")
    return ParsedUrl(scheme=parts.scheme.lower(), host=host or None, has_userinfo="@" in parts.netloc)

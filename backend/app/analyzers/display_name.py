"""Flags a sender whose display name claims a brand its address doesn't belong to: "PayPal Security" <x@gmail.com>.

Many mail apps show only the name, so the name is what the reader trusts.
"""

from collections.abc import Sequence

from app.analyzers.base import Detection
from app.brand_mentions import mentions
from app.data.brands import Brand
from app.domains import split_domain
from app.parsed_email import ParsedEmail

DISPLAY_NAME_BRAND_SPOOF = "display_name_brand_spoof"

MAX_SHOWN_NAME_CHARS = 60


class DisplayNameAnalyzer:
    name = "Sender name check"

    def __init__(self, brands: Sequence[Brand]) -> None:
        self._brands = [brand for brand in brands if not brand.is_common_name]

    def analyze(self, email: ParsedEmail) -> list[Detection]:
        header = email.headers.get("From")
        if header is None or not header.addresses or not header.addresses[0].domain:
            return []
        sender = header.addresses[0]
        registrable = split_domain(sender.domain).registrable
        brand = next(
            (brand for brand in self._brands if registrable not in brand.domains and mentions(brand, sender.display_name)),
            None,
        )
        if brand is None:
            return []
        return [
            Detection(
                DISPLAY_NAME_BRAND_SPOOF,
                f"Sender name claims to be {brand.name}",
                f'The sender calls itself "{sender.display_name[:MAX_SHOWN_NAME_CHARS]}" but writes from '
                f"{registrable}, which is not a {brand.name} domain.",
            )
        ]

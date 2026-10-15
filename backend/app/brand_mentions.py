"""Does a piece of text name a brand? Shared by the domain checks and the display-name check."""

import re

from app.confusables import skeleton
from app.data.brands import Brand
from app.domains import to_unicode

# Brand names shorter than this ("ups", "chase", "zoom") only match as a whole word.
MIN_SUBSTRING_BRAND_LENGTH = 6
_WORD_SEPARATORS = re.compile(r"[\s.\-_]+")


def token_skeletons(brand: Brand) -> set[str]:
    return {skeleton(token) for token in brand.tokens}


def mentions(brand: Brand, text: str) -> bool:
    """True when text names the brand, even through look-alike letters ("PаyPal" with a Cyrillic "а")."""
    words = [skeleton(word) for word in _WORD_SEPARATORS.split(to_unicode(text)) if word]
    for token in token_skeletons(brand):
        for word in words:
            if word == token or (len(token) >= MIN_SUBSTRING_BRAND_LENGTH and token in word):
                return True
    return False

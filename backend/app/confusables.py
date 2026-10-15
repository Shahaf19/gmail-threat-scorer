"""Reduces a name to a "skeleton" so look-alike spellings of the same word compare equal."""

import unicodedata

# Characters that render like another letter (Cyrillic/Greek lookalikes, digits used as letters),
# plus "i" -> "l" because the two are easily confused in many fonts. Applied to both sides of every
# comparison, so the mapping only has to be consistent, not linguistically correct.
_LOOK_ALIKES = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
        "у": "y", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h",
        "ӏ": "l",
        "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "ι": "i",
        "κ": "k",
        "0": "o", "1": "l", "3": "e", "5": "s",
        "i": "l",
    }
)
# Two letters that read as one: "rn" looks like "m", "vv" like "w".
_PAIRS = (("rn", "m"), ("vv", "w"))


def skeleton(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text.lower())
    without_accents = "".join(char for char in decomposed if not unicodedata.combining(char))
    result = without_accents.translate(_LOOK_ALIKES)
    for pair, single in _PAIRS:
        result = result.replace(pair, single)
    return result


def is_one_edit_away(first: str, second: str) -> bool:
    """True when the texts differ by exactly one insertion, deletion, substitution or adjacent swap."""
    if first == second or abs(len(first) - len(second)) > 1:
        return False
    shared = 0
    while shared < min(len(first), len(second)) and first[shared] == second[shared]:
        shared += 1
    rest_first, rest_second = first[shared:], second[shared:]
    if len(first) == len(second):
        is_substitution = rest_first[1:] == rest_second[1:]
        is_swap = rest_first[:2] == rest_second[:2][::-1] and rest_first[2:] == rest_second[2:]
        return is_substitution or is_swap
    shorter, longer = sorted((rest_first, rest_second), key=len)
    return shorter == longer[1:]

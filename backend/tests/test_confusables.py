import pytest

from app.confusables import is_one_edit_away, skeleton


@pytest.mark.parametrize(
    ("look_alike", "original"),
    [
        ("paypa1", "paypal"),
        ("g00gle", "google"),
        ("rnicrosoft", "microsoft"),
        ("vvalmart", "walmart"),
        ("рaypal", "paypal"),
        ("paypaál", "paypaal"),
        ("PAYPAL", "paypal"),
    ],
)
def test_look_alikes_share_a_skeleton(look_alike: str, original: str) -> None:
    assert skeleton(look_alike) == skeleton(original)


def test_different_words_keep_different_skeletons() -> None:
    assert skeleton("paypal") != skeleton("google")


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("paypal", "paypall"),
        ("paypal", "paypl"),
        ("paypal", "paypaa"),
        ("paypal", "paypla"),
        ("a", "ab"),
    ],
    ids=["insertion", "deletion", "substitution", "adjacent-swap", "one-letter-insertion"],
)
def test_single_edits_are_detected(first: str, second: str) -> None:
    assert is_one_edit_away(first, second)
    assert is_one_edit_away(second, first)


@pytest.mark.parametrize(
    ("first", "second"),
    [("paypal", "paypal"), ("paypal", "payyyl"), ("paypal", "pay"), ("paypal", "google"), ("abcd", "badc")],
    ids=["identical", "two-substitutions", "two-deletions", "unrelated", "two-swaps"],
)
def test_other_differences_are_not_one_edit(first: str, second: str) -> None:
    assert not is_one_edit_away(first, second)

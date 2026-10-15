from app.analyzers.language import (
    SENSITIVE_INFO_REQUEST,
    URGENT_LANGUAGE,
    SensitiveInfoRequestAnalyzer,
    UrgentLanguageAnalyzer,
)
from tests.helpers import email_with


def urgent(body: str) -> list[str]:
    return [d.finding_id for d in UrgentLanguageAnalyzer().analyze(email_with(body_text=body))]


def secrets(body: str) -> list[str]:
    return [d.finding_id for d in SensitiveInfoRequestAnalyzer().analyze(email_with(body_text=body))]


def test_one_urgent_phrase_is_not_enough_but_two_are() -> None:
    assert urgent("Last chance to save 20% on shoes!") == []
    assert urgent("FINAL NOTICE: act now or your account will be suspended.") == [URGENT_LANGUAGE]


def test_hidden_characters_and_look_alike_letters_do_not_hide_phrases() -> None:
    assert urgent("Fin​al notіce. Act n0w!") == [URGENT_LANGUAGE]


def test_request_for_a_secret_is_flagged_but_a_warning_is_not() -> None:
    assert secrets("Please reply with your password and card number.") == [SENSITIVE_INFO_REQUEST]
    assert secrets("We will never ask you to share your password.") == []

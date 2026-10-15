from app.analyzers.baseline import (
    FIRST_TIME_SENDER,
    KNOWN_NAME_NEW_DOMAIN,
    MIN_BASELINE_SENDERS,
    BaselineDeviationAnalyzer,
)
from app.analyzers.message_structure import (
    EMAIL_FORM,
    HIDDEN_TEXT,
    IMAGE_ONLY_EMAIL,
    MIN_HIDDEN_CHARS,
    TRACKING_PIXEL,
    TRUNCATED_EMAIL,
    MessageStructureAnalyzer,
)
from app.schemas import SenderHistory
from tests.helpers import email_with


def structure_ids(**email_arguments) -> set[str]:
    return {d.finding_id for d in MessageStructureAnalyzer().analyze(email_with(**email_arguments))}


def test_pixel_hidden_text_and_form_are_found_in_html() -> None:
    hidden = "x" * MIN_HIDDEN_CHARS
    html = (
        f'<p>Hello, please read this message carefully today.</p><img src="https://t.example/p.gif" width="1" height="1">'
        f'<div style="display:none">{hidden}</div><form><input type="password"></form>'
    )

    assert structure_ids(body_html=html) == {TRACKING_PIXEL, HIDDEN_TEXT, EMAIL_FORM}


def test_image_only_and_truncated_email_are_flagged() -> None:
    assert structure_ids(body_html='<a href="https://x.com"><img src="https://x.com/a.png"></a>', truncated=True) == {
        IMAGE_ONLY_EMAIL,
        TRUNCATED_EMAIL,
    }


def test_ordinary_text_email_is_clean() -> None:
    assert structure_ids(body_text="A normal email with enough words in it to read.") == set()


def test_known_name_from_new_domain_and_first_time_sender() -> None:
    history = SenderHistory(
        known_sender_count=MIN_BASELINE_SENDERS, address_seen_before=False, name_seen_with_other_domain=True
    )

    found = {d.finding_id for d in BaselineDeviationAnalyzer().analyze(email_with(sender_history=history))}

    assert found == {KNOWN_NAME_NEW_DOMAIN, FIRST_TIME_SENDER}


def test_first_time_sender_is_ignored_while_the_history_is_still_empty() -> None:
    history = SenderHistory(known_sender_count=3, address_seen_before=False, name_seen_with_other_domain=False)

    assert BaselineDeviationAnalyzer().analyze(email_with(sender_history=history)) == []

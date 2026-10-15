from app.analyzers.display_name import DISPLAY_NAME_BRAND_SPOOF, DisplayNameAnalyzer
from app.data.brands import BRANDS
from tests.helpers import email_with


def ids_for(from_header: str) -> list[str]:
    return [d.finding_id for d in DisplayNameAnalyzer(BRANDS).analyze(email_with(from_header))]


def test_brand_name_on_someone_elses_address_is_flagged() -> None:
    assert ids_for("From: PayPal Security <alerts.team@gmail.com>") == [DISPLAY_NAME_BRAND_SPOOF]
    assert ids_for("From: PаyPal <x@gmail.com>") == [DISPLAY_NAME_BRAND_SPOOF]  # Cyrillic "а"


def test_real_brand_senders_and_people_named_like_brands_are_clean() -> None:
    assert ids_for("From: PayPal <service@mail.paypal.com>") == []
    assert ids_for("From: Chase Smith <chase.smith@gmail.com>") == []
    assert ids_for("From: Dana Levi <dana@gmail.com>") == []

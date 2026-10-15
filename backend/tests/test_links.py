from app.analyzers.links import (
    LINK_DANGEROUS_SCHEME,
    LINK_RAW_IP,
    LINK_TEXT_MISMATCH,
    LINK_USERINFO,
    LinkAnalyzer,
)
from app.data.brands import Brand
from tests.helpers import email_with


GOOGLE = Brand("Google", ("google",), frozenset({"google.com", "c.gle"}))


def ids_for(body_html: str, sender: str = "From: x@example.org") -> list[str]:
    return [d.finding_id for d in LinkAnalyzer((GOOGLE,)).analyze(email_with(sender, body_html=body_html))]


def test_link_into_the_senders_own_organization_is_not_a_mismatch() -> None:
    html = '<a href="https://c.gle/abc">abuse.ch</a>'

    assert ids_for(html, "From: Google <noreply@accounts.google.com>") == []
    assert ids_for(html, "From: Evil <a@evil.ru>") == [LINK_TEXT_MISMATCH]


def test_text_that_names_another_site_is_flagged() -> None:
    assert ids_for('<a href="https://evil.ru/x">https://paypal.com/login</a>') == [LINK_TEXT_MISMATCH]


def test_honest_links_and_plain_labels_are_clean() -> None:
    html = '<a href="https://www.paypal.com/x">paypal.com</a><a href="https://evil.ru">Click here</a><a href="https://x.ru">invoice.pdf</a>'

    assert ids_for(html) == []


def test_deceptive_url_forms_are_flagged() -> None:
    html = '<a href="https://paypal.com@evil.ru/">a</a><a href="http://185.12.4.9/">b</a><a href="javascript:alert(1)">c</a>'

    assert set(ids_for(html)) == {LINK_USERINFO, LINK_RAW_IP, LINK_DANGEROUS_SCHEME}

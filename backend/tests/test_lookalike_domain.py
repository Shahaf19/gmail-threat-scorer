import pytest

from app.analyzers.lookalike_domain import (
    BRAND_IN_SUBDOMAIN,
    BRAND_WITH_EXTRA_WORDS,
    LOOKALIKE_DOMAIN,
    MAX_HEADER_DOMAINS,
    MAX_TARGET_SITES,
    LookalikeDomainAnalyzer,
)
from app.data.brands import BRANDS, Brand
from app.data.top_sites import load_top_sites
from tests.helpers import email_with_headers

TOP_SITES = ["paypal.com", "google.com", "microsoft.com", "amazon.com", "bbc.co.uk"]
TEST_BRANDS = (
    Brand("PayPal", ("paypal",), frozenset({"paypal.com"})),
    Brand("Microsoft", ("microsoft",), frozenset({"microsoft.com"})),
    Brand("Chase", ("chase",), frozenset({"chase.com"})),
)
CYRILLIC_PAYPAL = "раypal.com"  # first two letters are Cyrillic "r" and "a" lookalikes


def finding_ids(domain: str, *, reply_to: str | None = None) -> list[str]:
    headers = [f"From: Someone <person@{domain}>"]
    if reply_to:
        headers.append(f"Reply-To: {reply_to}")
    analyzer = LookalikeDomainAnalyzer(TOP_SITES, TEST_BRANDS)
    return [detection.finding_id for detection in analyzer.analyze(email_with_headers(*headers))]


@pytest.mark.parametrize(
    "domain",
    [
        "paypa1.com",
        "paypall.com",
        "paypla.com",
        "paypl.com",
        "g00gle.com",
        "rnicrosoft.com",
        "paypál.com",
        CYRILLIC_PAYPAL,
        CYRILLIC_PAYPAL.encode("idna").decode("ascii"),
    ],
    ids=[
        "digit-for-l", "doubled-letter", "swapped-letters", "dropped-letter", "zeros-for-os",
        "rn-for-m", "accented-letter", "cyrillic-letters", "punycode-form",
    ],
)
def test_imitation_of_a_known_domain_is_flagged(domain: str) -> None:
    assert LOOKALIKE_DOMAIN in finding_ids(domain)


@pytest.mark.parametrize(
    "domain",
    ["paypal.com", "mail.paypal.com", "google.com", "bbc.co.uk", "news.bbc.co.uk", "example.org", "acme-corp.com", "sleepyhollow.org"],
)
def test_legitimate_and_unrelated_domains_are_clean(domain: str) -> None:
    assert finding_ids(domain) == []


def test_short_names_are_not_compared() -> None:
    assert finding_ids("pay.com") == []


def test_same_name_on_another_tld_is_left_alone() -> None:
    assert finding_ids("paypal.xyz") == []


@pytest.mark.parametrize(
    "domain",
    ["paypal.com.secure-login.ru", "paypal.weebly.com", "login.paypa1.secure-login.ru", "microsoft.verify.example.org"],
)
def test_brand_in_front_of_someone_elses_domain_is_flagged(domain: str) -> None:
    assert BRAND_IN_SUBDOMAIN in finding_ids(domain)


def test_brand_owned_subdomains_are_not_flagged() -> None:
    assert finding_ids("login.paypal.com") == []


@pytest.mark.parametrize(
    "domain",
    ["paypal-security.com", "securepaypal.com", "microsoftonline-login.net", "chase-alert.com"],
)
def test_brand_with_extra_words_is_flagged(domain: str) -> None:
    assert BRAND_WITH_EXTRA_WORDS in finding_ids(domain)


def test_short_brand_name_only_matches_as_a_whole_word() -> None:
    assert finding_ids("purchase-orders.com") == []


def test_reply_to_domain_is_checked_too() -> None:
    assert LOOKALIKE_DOMAIN in finding_ids("example.org", reply_to="help@paypa1.com")


def test_each_finding_is_reported_once() -> None:
    result = finding_ids("paypa1.com", reply_to="x@paypall.com")

    assert result.count(LOOKALIKE_DOMAIN) == 1


def test_a_header_stuffed_with_addresses_is_bounded() -> None:
    stuffed = ", ".join(f"a@spam{number}.example.org" for number in range(MAX_HEADER_DOMAINS * 50))

    assert finding_ids("example.org", reply_to=stuffed) == []


def test_overlong_label_is_ignored() -> None:
    assert finding_ids("a" * 500 + ".com") == []


def test_only_the_best_known_sites_are_imitation_targets() -> None:
    top_sites = [f"filler{number}.com" for number in range(MAX_TARGET_SITES)] + ["obscurename.com"]
    analyzer = LookalikeDomainAnalyzer(top_sites, ())

    def flagged(domain: str) -> bool:
        email = email_with_headers(f"From: x <a@{domain}>")
        return LOOKALIKE_DOMAIN in [d.finding_id for d in analyzer.analyze(email)]

    assert not flagged("obscurename.com")  # itself a known site: exempt
    assert not flagged("obscurenam.com")  # one letter off, but not a target
    assert flagged("fil1er0.com")  # a visual swap of a real target is still caught


class TestWithRealData:
    analyzer = LookalikeDomainAnalyzer(load_top_sites(), BRANDS)

    def ids(self, domain: str) -> list[str]:
        email = email_with_headers(f"From: Someone <person@{domain}>")
        return [detection.finding_id for detection in self.analyzer.analyze(email)]

    @pytest.mark.parametrize("domain", ["paypa1.com", "arnazon.com", "rnicrosoft.com", "faceboook.com", "netfliix.com"])
    def test_known_lookalikes_are_flagged(self, domain: str) -> None:
        assert LOOKALIKE_DOMAIN in self.ids(domain)

    @pytest.mark.parametrize("domain", ["github.com", "gmail.com", "outlook.com", "amazon.co.uk", "mail.google.com", "bbc.co.uk"])
    def test_real_sites_are_clean(self, domain: str) -> None:
        assert self.ids(domain) == []

    def test_top_site_list_is_loaded(self) -> None:
        assert len(load_top_sites()) > 9000

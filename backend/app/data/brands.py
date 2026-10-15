"""Frequently impersonated brands: the names attackers embed in domains, and the domains each brand owns.

Short or common-word names (ups, chase, zoom) only ever match as a whole hyphen/dot-separated
word, so "purchase-orders.com" is not mistaken for Chase.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Brand:
    name: str
    tokens: tuple[str, ...]
    domains: frozenset[str]
    # Also a common person's name ("Chase Smith"), so a display name alone proves nothing.
    is_common_name: bool = False


def _brand(name: str, tokens: tuple[str, ...], *domains: str, is_common_name: bool = False) -> Brand:
    return Brand(name=name, tokens=tokens, domains=frozenset(domains), is_common_name=is_common_name)


BRANDS: tuple[Brand, ...] = (
    _brand("PayPal", ("paypal",), "paypal.com", "paypal.me"),
    _brand(
        "Microsoft",
        ("microsoft", "office365", "outlook", "onedrive", "sharepoint"),
        "microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com",
        "office365.com", "sharepoint.com", "onmicrosoft.com", "onedrive.com", "microsoft365.com",
        "hotmail.com",
    ),
    _brand(
        "Google",
        ("google", "gmail"),
        "google.com", "gmail.com", "googlemail.com", "youtube.com", "googleusercontent.com", "gstatic.com",
        "c.gle", "g.co", "goo.gl",
    ),
    _brand("Apple", ("apple", "icloud", "itunes"), "apple.com", "icloud.com", "me.com", "itunes.com"),
    _brand(
        "Amazon",
        ("amazon",),
        "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.es", "amazon.ca",
        "amazon.co.jp", "amazon.in", "amazonaws.com",
    ),
    _brand("Netflix", ("netflix",), "netflix.com"),
    _brand(
        "Meta",
        ("facebook", "instagram", "whatsapp"),
        "facebook.com", "fb.com", "facebookmail.com", "instagram.com", "whatsapp.com", "meta.com",
    ),
    _brand("LinkedIn", ("linkedin",), "linkedin.com"),
    _brand("X (Twitter)", ("twitter",), "twitter.com", "x.com"),
    _brand("Dropbox", ("dropbox",), "dropbox.com", "dropboxmail.com"),
    _brand("DocuSign", ("docusign",), "docusign.com", "docusign.net"),
    _brand("Adobe", ("adobe",), "adobe.com"),
    _brand("DHL", ("dhl",), "dhl.com", "dhl.de"),
    _brand("FedEx", ("fedex",), "fedex.com"),
    _brand("UPS", ("ups",), "ups.com"),
    _brand("USPS", ("usps",), "usps.com"),
    _brand("Wells Fargo", ("wellsfargo",), "wellsfargo.com"),
    _brand("Chase", ("chase",), "chase.com", "jpmorganchase.com", is_common_name=True),
    _brand("Bank of America", ("bankofamerica",), "bankofamerica.com", "bofa.com"),
    _brand("Citi", ("citibank",), "citi.com", "citibank.com"),
    _brand("American Express", ("americanexpress", "amex"), "americanexpress.com", "aexp.com"),
    _brand("Mastercard", ("mastercard",), "mastercard.com"),
    _brand("Coinbase", ("coinbase",), "coinbase.com"),
    _brand("Binance", ("binance",), "binance.com"),
    _brand("eBay", ("ebay",), "ebay.com", "ebay.co.uk", "ebay.de"),
    _brand("Walmart", ("walmart",), "walmart.com"),
    _brand("Spotify", ("spotify",), "spotify.com"),
    _brand("Steam", ("steampowered", "steamcommunity"), "steampowered.com", "steamcommunity.com"),
    _brand("GitHub", ("github",), "github.com"),
    _brand("Zoom", ("zoom",), "zoom.us", "zoom.com"),
    _brand("Slack", ("slack",), "slack.com"),
    _brand("Yahoo", ("yahoo",), "yahoo.com"),
    _brand("Booking.com", ("booking",), "booking.com"),
    _brand("Airbnb", ("airbnb",), "airbnb.com"),
    _brand("AliExpress", ("aliexpress",), "aliexpress.com"),
    _brand("IRS", ("irs",), "irs.gov"),
    _brand("Intuit", ("intuit", "quickbooks"), "intuit.com", "quickbooks.com"),
    _brand("WeTransfer", ("wetransfer",), "wetransfer.com"),
    _brand("Revolut", ("revolut",), "revolut.com"),
    _brand("Norton", ("norton",), "norton.com", is_common_name=True),
)

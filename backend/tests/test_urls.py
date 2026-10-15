from app.urls import parse_url


def test_userinfo_trick_reveals_the_real_host() -> None:
    parsed = parse_url("https://paypal.com@evil.ru/login")

    assert (parsed.host, parsed.has_userinfo) == ("evil.ru", True)


def test_backslash_is_read_like_a_browser_does() -> None:
    assert parse_url("https://evil.ru\\@paypal.com/").host == "evil.ru"


def test_scheme_is_seen_as_the_browser_sees_it() -> None:
    assert parse_url("  java\tscript:alert(1)").scheme == "javascript"


def test_numeric_hosts_are_recognized() -> None:
    assert parse_url("http://3232235777/x").is_numeric_address
    assert not parse_url("http://paypal.com/x").is_numeric_address

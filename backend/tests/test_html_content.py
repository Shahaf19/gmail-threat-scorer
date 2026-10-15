from app.html_content import Link, read_content


def test_anchor_gives_destination_and_visible_text() -> None:
    html = '<p>Hi</p><a href="https://evil.ru/login">https://paypal.com/login</a>'

    assert read_content("", html).links == (Link("https://evil.ru/login", "https://paypal.com/login"),)


def test_script_text_is_not_visible_and_plain_urls_are_found() -> None:
    content = read_content("See https://example.com/a, ok.", "<script>alert(1)</script>")

    assert content.links == (Link("https://example.com/a", ""),)


def test_comments_are_read_like_a_browser_does() -> None:
    html = '<!--> <a href="https://after-empty-comment.com">x</a> <!-- hidden <a href="https://in-comment.com">y</a>'

    assert [link.href for link in read_content("", html).links] == ["https://after-empty-comment.com"]


def test_a_link_hidden_behind_many_others_or_a_long_prefix_is_still_seen() -> None:
    padding = "".join(f'<a href="https://site{n}.com">x</a>' for n in range(500))
    long_prefix = "https://" + "a" * 5_000 + "@evil.example/"
    links = read_content("", padding + f'<a href="{long_prefix}">paypal.com</a>').links

    assert links[-1].href == long_prefix

from app.html_content import MAX_LINKS, Link, read_content


def test_anchor_gives_destination_and_visible_text() -> None:
    html = '<p>Hi</p><a href="https://evil.ru/login">https://paypal.com/login</a>'

    assert read_content("", html).links == (Link("https://evil.ru/login", "https://paypal.com/login"),)


def test_script_text_is_not_visible_and_plain_urls_are_found() -> None:
    content = read_content("See https://example.com/a, ok.", "<script>alert(1)</script>")

    assert content.links == (Link("https://example.com/a", ""),)


def test_comments_are_read_like_a_browser_does() -> None:
    html = '<!--> <a href="https://after-empty-comment.com">x</a> <!-- hidden <a href="https://in-comment.com">y</a>'

    assert [link.href for link in read_content("", html).links] == ["https://after-empty-comment.com"]


def test_number_of_links_is_capped() -> None:
    html = "".join(f'<a href="https://site{n}.com">x</a>' for n in range(MAX_LINKS * 2))

    assert len(read_content("", html).links) == MAX_LINKS

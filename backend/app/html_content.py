"""Reads links, visible text and structure out of untrusted message bodies.

Nothing found here is ever fetched, rendered or run: links stay plain text for the analyzers.
Only inline styles are understood; styles from <style> blocks are not resolved.
"""

import re
from dataclasses import dataclass, replace
from html.parser import HTMLParser

# Links are never capped or cut: an attacker could put the real link after the cap, or hide the real host
# after a long "user@" prefix. The body itself is capped (200,000 characters), which bounds the work.
MAX_TRACKING_PIXEL_SIZE = 2  # an image this small (in pixels, both ways) is not for reading
# Browsers don't show these, so text inside them must not count as something the user reads.
_NON_TEXT_TAGS = frozenset({"script", "style"})
# Tags that never have a closing tag, so they can't open a hidden region.
_VOID_TAGS = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"})
# font-size:0 is deliberately absent: templates set it on layout cells to collapse whitespace, and the
# text inside declares its own size, so counting it as hidden flags ordinary newsletters.
_INVISIBLE_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0\s*(?:;|$)", re.IGNORECASE)
_LEADING_NUMBER = re.compile(r"^\s*(\d+)")
_PLAIN_URL = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
_COMMENT_OPEN = "<!--"
# (closing marker, where to start looking after the opener)
_COMMENT_CLOSERS = (("-->", 2), ("--!>", 4))
_TRAILING_PUNCTUATION = ".,;:!?"
_WHITESPACE = re.compile(r"\s+")


@dataclass(frozen=True)
class Link:
    href: str  # where the link goes
    text: str  # what the reader sees ("" for a bare URL in plain text)


@dataclass(frozen=True)
class MessageContent:
    text: str
    links: tuple[Link, ...]
    visible_chars: int = 0  # text the reader can see (hidden elements excluded)
    hidden_chars: int = 0  # text inside elements styled invisible
    image_count: int = 0
    tracking_pixel_count: int = 0
    has_form: bool = False  # a <form>, or a password field


def read_content(body_text: str, body_html: str) -> MessageContent:
    html = _read_html(body_html)
    plain_links = [Link(url.rstrip(_TRAILING_PUNCTUATION), "") for url in _PLAIN_URL.findall(body_text)]
    unique_links = dict.fromkeys([*html.links, *plain_links])
    return replace(
        html,
        text=body_text or html.text,
        links=tuple(unique_links),
        visible_chars=word_chars(body_text) or html.visible_chars,
    )


def word_chars(text: str) -> int:
    """Letters and digits only: newsletters pad hidden preview text with invisible and joiner characters."""
    return sum(1 for char in text if char.isalnum())


class _HtmlReader(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self.text_parts: list[str] = []
        self.visible_chars = 0
        self.hidden_chars = 0
        self.image_count = 0
        self.tracking_pixel_count = 0
        self.has_form = False
        self._href: str | None = None
        self._anchor_text: list[str] = []
        self._non_text_depth = 0
        self._invisible_tag: str | None = None  # the element whose style hides everything inside it
        self._invisible_nesting = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # Browsers use the first of two identical attributes.
        values = {}
        for name, value in attrs:
            values.setdefault(name, value or "")
        if tag in _NON_TEXT_TAGS:
            self._non_text_depth += 1
        elif tag == "a":
            self.finish_anchor()
            self._href = values.get("href")
        elif tag == "img":
            self.image_count += 1
            self.tracking_pixel_count += _is_tracking_pixel(values)
        elif tag == "form" or (tag == "input" and values.get("type", "").strip().lower() == "password"):
            self.has_form = True
        self._track_invisible(tag, values)

    def handle_endtag(self, tag: str) -> None:
        if tag in _NON_TEXT_TAGS:
            self._non_text_depth = max(0, self._non_text_depth - 1)
        elif tag == "a":
            self.finish_anchor()
        if tag == self._invisible_tag:
            self._invisible_nesting -= 1
            if self._invisible_nesting == 0:
                self._invisible_tag = None

    def handle_data(self, data: str) -> None:
        if self._non_text_depth:
            return
        self.text_parts.append(data)
        if self._invisible_tag:
            self.hidden_chars += word_chars(data)
        else:
            self.visible_chars += word_chars(data)
        if self._href is not None:
            self._anchor_text.append(data)

    def finish_anchor(self) -> None:
        if self._href and self._href.strip():
            text = _collapse_whitespace("".join(self._anchor_text))
            self.links.append(Link(self._href.strip(), text))
        self._href = None
        self._anchor_text = []

    def _track_invisible(self, tag: str, values: dict[str, str]) -> None:
        if tag in _VOID_TAGS:
            return
        if self._invisible_tag:
            if tag == self._invisible_tag:
                self._invisible_nesting += 1
        elif _INVISIBLE_STYLE.search(values.get("style", "")):
            self._invisible_tag = tag
            self._invisible_nesting = 1


def _is_tracking_pixel(values: dict[str, str]) -> bool:
    width, height = _size(values, "width"), _size(values, "height")
    return width is not None and height is not None and max(width, height) <= MAX_TRACKING_PIXEL_SIZE


def _size(values: dict[str, str], dimension: str) -> int | None:
    for source in (values.get(dimension, ""), _style_value(values.get("style", ""), dimension)):
        match = _LEADING_NUMBER.match(source)
        if match:
            return int(match.group(1))
    return None


def _style_value(style: str, property_name: str) -> str:
    match = re.search(rf"(?:^|;)\s*{property_name}\s*:\s*([^;]*)", style, re.IGNORECASE)
    return match.group(1) if match else ""


def _remove_comments(html: str) -> str:
    """Cuts out comments the way a browser reads them, in one linear pass.

    Python's parser rescans to the end of the text for every unclosed "<!--" (about 25 s on a
    200,000-character body), and it disagrees with browsers on forms like "<!-->", which would let a
    link after one stay invisible to us while the reader can click it. A browser treats everything after
    an unclosed comment as part of it, so dropping that remainder loses nothing the reader sees.
    """
    kept: list[str] = []
    position = 0
    while (start := html.find(_COMMENT_OPEN, position)) != -1:
        kept.append(html[position:start])
        end = _comment_end(html, start)
        if end is None:
            return "".join(kept)
        position = end
    kept.append(html[position:])
    return "".join(kept)


def _comment_end(html: str, start: int) -> int | None:
    """Index just after the comment's closing marker, or None if it never closes."""
    ends = []
    for closer, search_offset in _COMMENT_CLOSERS:
        index = html.find(closer, start + search_offset)
        if index != -1:
            ends.append(index + len(closer))
    return min(ends) if ends else None


def _read_html(html: str) -> MessageContent:
    reader = _HtmlReader()
    try:
        reader.feed(_remove_comments(html))
        reader.close()
    except Exception:  # best effort: whatever was read before a parser error still counts
        pass
    reader.finish_anchor()
    return MessageContent(
        text=_collapse_whitespace(" ".join(reader.text_parts)),
        links=tuple(reader.links),
        visible_chars=reader.visible_chars,
        hidden_chars=reader.hidden_chars,
        image_count=reader.image_count,
        tracking_pixel_count=reader.tracking_pixel_count,
        has_form=reader.has_form,
    )


def _collapse_whitespace(text: str) -> str:
    return _WHITESPACE.sub(" ", text).strip()

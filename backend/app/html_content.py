"""Reads links and visible text out of untrusted message bodies.

Nothing found here is ever fetched, rendered or run: links stay plain text for the analyzers.
"""

import re
from dataclasses import dataclass
from html.parser import HTMLParser

MAX_LINKS = 200
MAX_HREF_CHARS = 2_048  # the host sits at the front, so cutting a longer URL never hides it
MAX_LINK_TEXT_CHARS = 500
# Browsers don't show these, so text inside them must not count as something the user reads.
_HIDDEN_CONTENT_TAGS = frozenset({"script", "style"})
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


def read_content(body_text: str, body_html: str) -> MessageContent:
    html = _read_html(body_html)
    plain_links = [Link(url.rstrip(_TRAILING_PUNCTUATION), "") for url in _PLAIN_URL.findall(body_text)]
    unique_links = dict.fromkeys([*html.links, *plain_links])
    return MessageContent(text=body_text or html.text, links=tuple(unique_links)[:MAX_LINKS])


class _HtmlReader(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self.text_parts: list[str] = []
        self._href: str | None = None
        self._anchor_text: list[str] = []
        self._hidden_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _HIDDEN_CONTENT_TAGS:
            self._hidden_depth += 1
        elif tag == "a":
            self.finish_anchor()
            # Browsers use the first of two identical attributes.
            self._href = next((value for name, value in attrs if name == "href"), None)

    def handle_endtag(self, tag: str) -> None:
        if tag in _HIDDEN_CONTENT_TAGS:
            self._hidden_depth = max(0, self._hidden_depth - 1)
        elif tag == "a":
            self.finish_anchor()

    def handle_data(self, data: str) -> None:
        if self._hidden_depth:
            return
        self.text_parts.append(data)
        if self._href is not None:
            self._anchor_text.append(data)

    def finish_anchor(self) -> None:
        if self._href and self._href.strip():
            text = _collapse_whitespace("".join(self._anchor_text))[:MAX_LINK_TEXT_CHARS]
            self.links.append(Link(self._href.strip()[:MAX_HREF_CHARS], text))
        self._href = None
        self._anchor_text = []


@dataclass(frozen=True)
class _HtmlContent:
    text: str
    links: tuple[Link, ...]


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


def _read_html(html: str) -> _HtmlContent:
    reader = _HtmlReader()
    try:
        reader.feed(_remove_comments(html))
        reader.close()
    except Exception:  # best effort: whatever was read before a parser error still counts
        pass
    reader.finish_anchor()
    return _HtmlContent(text=_collapse_whitespace(" ".join(reader.text_parts)), links=tuple(reader.links))


def _collapse_whitespace(text: str) -> str:
    return _WHITESPACE.sub(" ", text).strip()

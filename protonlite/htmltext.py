"""Turn an HTML mail body into something worth putting in front of a reader.

Most mail is HTML, and handing 20 KB of table markup to a language model is
both useless and expensive. This is a deliberately small converter built on the
standard library: no extra dependency earns its place for this.
"""

from __future__ import annotations

import re
from html import escape, unescape
from html.parser import HTMLParser

#: Tags whose *contents* are not text. Only elements that really do close:
#: counting a void tag like ``<meta>`` here would open a skip that never ends
#: and swallow the whole document.
_SKIP = {"script", "style", "title"}

#: Tags that end the current line.
_BREAK_AFTER = {
    "p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6",
    "table", "ul", "ol", "blockquote", "section", "header", "footer", "article",
}


class _Extractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skipping = 0

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag in _SKIP:
            self._skipping += 1
        elif tag == "br":
            self.parts.append("\n")
        elif tag == "li":
            self.parts.append("\n- ")

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP:
            self._skipping = max(0, self._skipping - 1)
        elif tag in _BREAK_AFTER:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skipping and data.strip():
            self.parts.append(re.sub(r"[ \t\r\f\v]+", " ", data))


def to_text(html: str) -> str:
    """Flatten HTML to plain text, keeping paragraph breaks and list items."""
    parser = _Extractor()
    try:
        parser.feed(html)
        parser.close()
        text = collapse("".join(parser.parts))
    except Exception:
        text = ""

    if text:
        return text
    # Nothing came out, which for a body that clearly had words in it means the
    # markup defeated the parser. Strip tags and keep whatever is left rather
    # than handing back an empty message.
    return collapse(unescape(re.sub(r"<[^>]+>", " ", html)))


def collapse(text: str) -> str:
    """Trim each line and leave at most one blank line between blocks."""
    lines = [line.strip() for line in text.splitlines()]
    out: list[str] = []
    for line in lines:
        if line or (out and out[-1]):
            out.append(line)
    return "\n".join(out).strip()


def plaintext_to_html(text: str) -> str:
    """Wrap plain text in minimal, safe HTML so it reads like a normal mail.

    This is the default send path: the caller passes ordinary text, and the
    recipient should see a normal-looking message rather than raw text. HTML
    collapses whitespace, so I escape the text and keep its line breaks -- a
    blank line starts a new paragraph, a single newline becomes a <br>.
    """
    escaped = escape(text or "", quote=False)
    blocks = [
        "<p>" + block.replace("\n", "<br>\n") + "</p>"
        for block in escaped.split("\n\n")
        if block.strip()
    ]
    return "\n".join(blocks) or "<p></p>"


def render_body(body: str, fmt: str = "auto") -> tuple[str, str]:
    """Resolve a send ``format`` to a ``(body, mime_type)`` pair.

    ``auto`` (the default) renders plain text to HTML so the mail looks normal;
    ``html`` sends a body that is already HTML unchanged; ``text`` sends plain
    text. Anything else is a programming error, since the callers restrict it.
    """
    fmt = (fmt or "auto").lower()
    if fmt == "text":
        return body, "text/plain"
    if fmt == "html":
        return body, "text/html"
    if fmt == "auto":
        return plaintext_to_html(body), "text/html"
    raise ValueError(f"unknown body format {fmt!r}")


def looks_like_html(body: str, mime_type: str = "") -> bool:
    if "html" in mime_type.lower():
        return True
    head = body.lstrip()[:200].lower()
    return head.startswith(("<!doctype html", "<html")) or "<body" in head

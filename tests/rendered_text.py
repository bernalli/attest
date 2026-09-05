"""Visible prose with inline text preserved and block boundaries retained."""

from html.parser import HTMLParser

_INLINE = frozenset(
    "a abbr b bdi bdo cite code data del dfn em i ins kbd mark q rp rt ruby s "
    "samp small span strong sub sup time u var wbr tt bcp14 xref".split()
)
_HIDDEN = frozenset({"script", "style", "template"})


class _Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _HIDDEN:
            self.hidden += 1
        if not self.hidden and tag not in _INLINE:
            self.parts.append(" " if tag == "br" else " <> ")

    def handle_endtag(self, tag: str) -> None:
        if tag in _HIDDEN:
            self.hidden = max(0, self.hidden - 1)
        if not self.hidden and tag not in _INLINE:
            self.parts.append(" " if tag == "br" else " <> ")

    def handle_data(self, data: str) -> None:
        if not self.hidden:
            self.parts.append(data)


def visible_text(markup: str) -> str:
    parser = _Text()
    parser.feed(markup)
    parser.close()
    return " ".join("".join(parser.parts).split())

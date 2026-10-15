"""Rendering untrusted text safely in Markdown and on a terminal (PROJECT_SPEC.md 12.3, 11.3).

- **Control characters** (C0, DEL, C1) and Unicode bidirectional or invisible formatting
  characters are replaced by a visible `\\u{XXXX}` notation, so nothing reaches a terminal as
  an escape sequence and nothing reorders displayed text.
- **Markdown:** `&`, `<` and `>` become HTML entities and every other character with Markdown
  meaning is backslash-escaped, so no link, image (remote or local), HTML tag, heading, table
  cell or emphasis can be injected, even in a renderer that ignores backslash escapes for HTML.
  Newlines become spaces: one value is always one line.
- **Size:** every value is truncated to a bound with a visible marker.

- **Fixed wording** (`prose`): PatchProof's own constant sentences and labels are emitted
  literally, so a report reads naturally, but only after a check that they contain nothing that
  can form Markdown or HTML structure. Values never take this path.

These functions escape; they do not decide what may be shown. Reports pass only allowlisted
fields (`workflow.reports`), and redaction of known secret shapes is defence in depth on top.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Final

DEFAULT_LIMIT: Final = 300
TRUNCATED: Final = " …[truncated]"
_MARKDOWN_SPECIAL: Final = frozenset("\\`*_{}[]()#+-.!|~=\"':;$%^@/")
_ENTITIES: Final = {"&": "&amp;", "<": "&lt;", ">": "&gt;"}
# Bidirectional overrides/isolates and zero-width or invisible format characters.
_INVISIBLE: Final = frozenset(
    [0x061C, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2028, 0x2029, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
     0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x2066, 0x2067, 0x2068, 0x2069, 0xFEFF])
# Known secret shapes (synthetic fixture tokens and protected markers, bearer credentials).
# Reports never select fields that carry them; this catches a mistake, it is not the control.
SECRET_PATTERNS: Final = (
    re.compile(r"pt-synthetic-[a-z]{1,16}-[0-9a-f]{12}"),
    re.compile(r"PT-PROTECTED-[A-Z]{1,16}-[0-9a-f]{12}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}"),
)
REDACTED: Final = "[redacted]"


def _unsafe(ch: str) -> bool:
    cp = ord(ch)
    return cp < 0x20 or 0x7F <= cp <= 0x9F or cp in _INVISIBLE or unicodedata.category(ch) in ("Cs", "Co", "Cn")


def plain(value: object, limit: int = DEFAULT_LIMIT) -> str:
    """One terminal-safe line: visible escapes for unsafe characters, secrets redacted, bounded."""
    text = str(value)
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(REDACTED, text)
    out: list[str] = []
    for ch in text:
        if ch in "\n\r\t":
            out.append(" ")
        elif _unsafe(ch):
            out.append(f"\\u{{{ord(ch):04X}}}")
        else:
            out.append(ch)
    rendered = "".join(out)
    if len(rendered) > limit:
        rendered = rendered[:limit] + TRUNCATED
    return rendered


def md(value: object, limit: int = DEFAULT_LIMIT) -> str:
    """`plain`, then HTML-significant characters as entities and Markdown-significant ones backslash-escaped.

    A leading space becomes an entity, so a value placed at the start of a line or list item can
    never indent it into a code block."""
    text = "".join(_ENTITIES[ch] if ch in _ENTITIES else "\\" + ch if ch in _MARKDOWN_SPECIAL else ch
                   for ch in plain(value, limit))
    return "&#32;" + text[1:] if text.startswith(" ") else text


class UnsafeProse(ValueError):
    """Fixed report wording contains a character that could form Markdown or HTML structure."""


# Fixed wording may not contain anything that forms Markdown or HTML structure inline: no link,
# image, autolink, HTML, entity, code span, emphasis, strikethrough, table cell or escape.
_PROSE_FORBIDDEN: Final = re.compile(r"[\\`*{}\[\]<>#|~&]|://|www\.")
# An underscore is inert only between two letters or digits (CommonMark intraword rule).
_LOOSE_UNDERSCORE: Final = re.compile(r"(?<![A-Za-z0-9])_|_(?![A-Za-z0-9])")
# A line may not begin a block: a list item, heading, quote, thematic break or setext underline.
_BLOCK_START: Final = re.compile(r"[-+=>]|\d+[.)]|\s")


def prose(text: str) -> str:
    """PatchProof's own fixed wording, emitted literally (no escaping) after proving it is inert.

    Only report-authored constants pass through here; values from evidence, records or the
    target always go through `md` or `code`. Wording that could form structure is refused, never
    escaped: the remedy is to rewrite the constant (a programming error, caught by the tests).
    """
    if (not text or any(_unsafe(ch) or ch in "\n\r\t" for ch in text) or _PROSE_FORBIDDEN.search(text)
            or _LOOSE_UNDERSCORE.search(text) or _BLOCK_START.match(text)):
        raise UnsafeProse(f"fixed report wording is not inert Markdown: {plain(text, 120)!r}")
    return text


def contains_secret(text: str) -> bool:
    return any(p.search(text) for p in SECRET_PATTERNS)


_CODE_SAFE: Final = re.compile(r"[A-Za-z0-9:._/@+=-]{1,200}")


def code(value: object) -> str:
    """An identifier or hash as a Markdown code span when it is plainly safe, else escaped text."""
    text = str(value)
    if _CODE_SAFE.fullmatch(text) and not contains_secret(text):
        return f"`{text}`"
    return md(text)

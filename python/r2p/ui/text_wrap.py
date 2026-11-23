"""Word wrap for UI text lines using a font size callback."""

from __future__ import annotations

from typing import Callable


def wrap_text(
    text: str,
    max_width: int,
    measure: Callable[[str], int],
) -> list[str]:
    """
    Word-wrap text to max_width pixels.
    measure(s) returns pixel width of string s (e.g. font.size(s)[0]).
    Long words without spaces are hard-split by character.
    """
    if max_width <= 0:
        return [text] if text else [""]
    if text == "":
        return [""]

    lines: list[str] = []
    cur = ""

    def hard_append(token: str) -> None:
        nonlocal cur
        for ch in token:
            if measure(cur + ch) <= max_width:
                cur += ch
            else:
                if cur:
                    lines.append(cur)
                cur = ch

    def place_word(word: str) -> None:
        nonlocal cur
        if not word:
            return
        if cur == "":
            if measure(word) <= max_width:
                cur = word
            else:
                hard_append(word)
            return
        trial = cur + " " + word
        if measure(trial) <= max_width:
            cur = trial
            return
        lines.append(cur)
        cur = ""
        if measure(word) <= max_width:
            cur = word
        else:
            hard_append(word)

    # split keeps empty strings for consecutive / leading / trailing spaces
    parts = text.split(" ")
    for i, word in enumerate(parts):
        if word == "":
            # Space token (leading, trailing, or doubled).
            if cur == "":
                if not lines and measure(" ") <= max_width:
                    cur = " "
            elif measure(cur + " ") <= max_width:
                cur += " "
            else:
                lines.append(cur)
                cur = ""
            continue
        place_word(word)

    if cur or not lines:
        lines.append(cur)
    return lines

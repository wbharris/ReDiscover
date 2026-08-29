"""Person recon: operator search URLs, optional browser open."""

from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import quote, quote_plus

from rediscover.models import Engagement, SearchLink, ToolRun
from rediscover.tools import planned, spawn, which

NAME_RE = re.compile(r"^[A-Za-z][A-Za-z'.-]{0,39}$")

Runner = Callable[[str, list[str]], ToolRun]


def validate_name(value: str, label: str) -> str:
    text = (value or "").strip()
    if not NAME_RE.fullmatch(text):
        raise ValueError(
            f"not a {label}: {value!r} (letters, hyphen, apostrophe, period; max 40)"
        )
    return text


def person_links(first: str, last: str) -> list[SearchLink]:
    dash = quote(f"{first}-{last}")
    plus = quote_plus(f"{first} {last}")
    space = quote(f"{first} {last}")
    return [
        SearchLink("DuckDuckGo", f"https://duckduckgo.com/?q={space}"),
        SearchLink("Google", f"https://www.google.com/search?q={space}"),
        SearchLink("LinkedIn", f"https://www.linkedin.com/search/results/people/?keywords={space}"),
        SearchLink("GitHub", f"https://github.com/search?q={space}&type=users"),
        SearchLink("Wikipedia", f"https://en.wikipedia.org/wiki/Special:Search?search={space}"),
        SearchLink("YouTube", f"https://www.youtube.com/results?search_query={plus}"),
        SearchLink("Facebook public", f"https://www.facebook.com/public/{dash}"),
        SearchLink("Whitepages", f"https://www.whitepages.com/name/{dash}/"),
        SearchLink("411", f"https://www.411.com/name/{dash}/"),
        SearchLink("Spokeo", f"https://www.spokeo.com/{dash}"),
        SearchLink("TruePeopleSearch", f"https://www.truepeoplesearch.com/results?name={space}"),
        SearchLink("Radaris", f"https://radaris.com/p/{quote(first)}/{quote(last)}-US/"),
        SearchLink("FamilyTreeNow", f"https://www.familytreenow.com/search/genealogy/results?first={quote(first)}&last={quote(last)}"),
    ]


def plan_person() -> list[ToolRun]:
    browser = "firefox" if which("firefox") else "xdg-open"
    return [planned("open-search", [browser, "<search-url>"])]


def open_person_links(
    links: list[SearchLink],
    runner: Runner | None = None,
) -> list[ToolRun]:
    browser = "firefox" if which("firefox") else "xdg-open"
    if which(browser) is None:
        return [
            ToolRun(
                name="open-search",
                status="skipped",
                command=[browser],
                reason="firefox/xdg-open not installed",
            )
        ]
    runs: list[ToolRun] = []
    for link in links:
        argv = [browser, link.url]
        if runner is not None:
            runs.append(runner(f"open:{link.title}", argv))
        else:
            result = spawn(f"open:{link.title}", argv)
            runs.append(result)
    return runs


def person_case(first: str, last: str) -> Engagement:
    first_n = validate_name(first, "first name")
    last_n = validate_name(last, "last name")
    return Engagement(
        kind="person",
        mode="person",
        person_first=first_n,
        person_last=last_n,
        links=person_links(first_n, last_n),
    )

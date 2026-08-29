from rediscover.cli import main
from rediscover.person import person_links, validate_name
from rediscover.pipeline import person
from rediscover.report import to_markdown


def test_validate_name_rejects_empty():
    try:
        validate_name("", "first name")
    except ValueError as exc:
        assert "not a first name" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_person_links_include_public_search():
    links = person_links("Jane", "Doe")
    titles = [link.title for link in links]
    urls = [link.url for link in links]
    assert "DuckDuckGo" in titles
    assert "LinkedIn" in titles
    assert "Whitepages" in titles
    assert any("Jane" in url and "Doe" in url for url in urls)


def test_person_case_markdown():
    engagement = person("Jane", "Doe")
    assert engagement.kind == "person"
    assert engagement.title == "Jane Doe"
    md = to_markdown(engagement)
    assert "Jane Doe" in md
    assert "DuckDuckGo" in md
    assert "not a confirmation of identity" in md.lower() or "not a confirmation" in md


def test_person_cli(capsys):
    assert main(["person", "Jane", "Doe"]) == 0
    out = capsys.readouterr().out
    assert "Jane Doe" in out
    assert "truepeoplesearch.com" in out


def test_person_cli_bad_name():
    assert main(["person", "Jane", "Doe;rm"]) == 2


def test_person_dry_run():
    engagement = person("Jane", "Doe", dry_run=True)
    assert engagement.mode == "dry-run"
    assert engagement.tools
    assert all(t.status in {"planned", "skipped"} for t in engagement.tools)

import json

from dns_monitor.analyzer import Analyzer
from dns_monitor.config import OutputConfig
from dns_monitor.reporting import (
    render_console,
    render_html,
    render_json,
    render_markdown,
    write_reports,
)


def _analyzer(make_query) -> Analyzer:
    analyzer = Analyzer()
    analyzer.ingest_many(
        [
            make_query(domain="google.com", timestamp=1_700_000_000),
            make_query(domain="malware-c2.evil.xyz", timestamp=1_700_000_060),
        ]
    )
    return analyzer


def test_renderers_contain_expected_content(make_query):
    analyzer = _analyzer(make_query)
    assert "DNS TRAFFIC MONITOR" in render_console(analyzer)
    assert "google.com" in render_console(analyzer)
    assert "# DNS Monitor" in render_markdown(analyzer)
    assert "malware-c2.evil.xyz" in render_markdown(analyzer)
    assert json.loads(render_json(analyzer))["summary"]["total_queries"] == 2

    page = render_html(analyzer)
    assert page.startswith("<!doctype html>")
    assert "<svg" in page
    assert "Top queried domains" in page
    assert "malware-c2.evil.xyz" in page


def test_write_reports(tmp_path, make_query):
    analyzer = _analyzer(make_query)
    output = OutputConfig(
        json=str(tmp_path / "nested" / "report.json"),
        markdown=str(tmp_path / "nested" / "report.md"),
        html=str(tmp_path / "nested" / "report.html"),
    )
    paths = write_reports(analyzer, output)
    assert len(paths) == 3
    assert all(path.exists() for path in paths)

import json

from dns_monitor.cli import main


def test_rules_command(capsys):
    assert main(["rules"]) == 0
    output = capsys.readouterr().out
    assert "rate_limit" in output
    assert "nxdomain_burst" in output


def test_no_command_prints_help(capsys):
    assert main([]) == 0
    assert "usage: dns-monitor" in capsys.readouterr().out


def test_simulate_command_writes_reports(tmp_path, capsys):
    report = tmp_path / "report.json"
    events = tmp_path / "events.jsonl"
    database = tmp_path / "dns.db"
    assert (
        main(
            [
                "run",
                "--simulate",
                "120",
                "--seed",
                "3",
                "--json",
                str(report),
                "--jsonl",
                str(events),
                "--sqlite",
                str(database),
                "--quiet",
                "--no-console-report",
            ]
        )
        == 0
    )
    capture = capsys.readouterr()
    assert "wrote" in capture.out
    payload = json.loads(report.read_text())
    assert payload["summary"]["total_queries"] == 120
    event_lines = [json.loads(line) for line in events.read_text().splitlines()]
    assert sum(item["kind"] == "query" for item in event_lines) == 120
    assert any(item["kind"] == "alert" for item in event_lines)
    assert database.exists()


def test_report_command_reads_sqlite(tmp_path, capsys):
    database = tmp_path / "dns.db"
    assert (
        main(
            [
                "run",
                "--simulate",
                "40",
                "--sqlite",
                str(database),
                "--quiet",
                "--no-console-report",
            ]
        )
        == 0
    )
    capsys.readouterr()
    html = tmp_path / "from-db.html"
    assert main(["report", str(database), "--html", str(html), "--no-console-report"]) == 0
    assert html.read_text().startswith("<!doctype html>")

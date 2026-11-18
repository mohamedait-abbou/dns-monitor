"""Command-line interface for DNS Monitor."""

from __future__ import annotations

import argparse
import sys
from typing import Any

from . import __version__
from .alerts import AlertDispatcher, AlertLog
from .analyzer import Analyzer
from .capture import capture_live, capture_pcap, run_simulation
from .config import Config
from .models import RULES
from .reporting import render_console, write_reports
from .storage import CSVSink, JSONLSink, MultiSink, SQLiteSink, load_sqlite

EPILOG = """examples:
  dns-monitor run --simulate 500 --html report.html
  dns-monitor run -i eth0 --sqlite out/dns.db --webhook-url https://example.com/hook
  dns-monitor analyze capture.pcap --markdown report.md
  dns-monitor report out/dns.db --html report.html

Need root privileges for live capture; simulation and pcap analysis do not.
"""


def add_output_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("output")
    group.add_argument("--jsonl", metavar="PATH", help="write all events as JSON Lines")
    group.add_argument("--json", metavar="PATH", help="render the summary report as JSON")
    group.add_argument("--sqlite", metavar="PATH", help="write events into a SQLite database")
    group.add_argument("--csv", metavar="PATH", help="write queries into a CSV file")
    group.add_argument("--html", metavar="PATH", help="render a self-contained HTML dashboard")
    group.add_argument("--markdown", metavar="PATH", help="render a Markdown report")
    group.add_argument("--log-file", metavar="PATH", help="append human-readable alert log")
    group.add_argument("-q", "--quiet", action="store_true", help="suppress console alerts")
    group.add_argument("--no-console-report", action="store_true", help="skip the text summary")


def add_detector_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("detection")
    group.add_argument("--rate-threshold", type=int, metavar="N", help="queries per window per IP")
    group.add_argument("--rate-window", type=float, metavar="SEC", help="rate-limit window seconds")
    group.add_argument("--entropy-threshold", type=float, metavar="F", help="DGA entropy threshold")
    group.add_argument("--nxdomain-threshold", type=int, metavar="N", help="NXDOMAIN burst limit")
    group.add_argument("--webhook-url", metavar="URL", help="POST alerts to this URL")
    group.add_argument(
        "--webhook-format", choices=["generic", "slack"], help="webhook payload format"
    )
    group.add_argument(
        "--min-severity",
        choices=["info", "low", "medium", "high", "critical"],
        help="minimum severity to dispatch",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dns-monitor",
        description="Real-time DNS traffic analysis and threat detection.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    run = subparsers.add_parser("run", help="capture live traffic or run a simulation")
    run.add_argument("-c", "--config", metavar="PATH", help="YAML/JSON configuration file")
    run.add_argument("-i", "--interface", metavar="IFACE", help="capture interface (default: auto)")
    run.add_argument("--bpf", metavar="FILTER", help="override the BPF capture filter")
    run.add_argument("--duration", type=float, metavar="SEC", help="stop after N seconds")
    run.add_argument("--simulate", type=int, metavar="N", help="generate N synthetic DNS queries")
    run.add_argument("--seed", type=int, default=7, help="simulation RNG seed (default: 7)")
    add_detector_args(run)
    add_output_args(run)

    analyze = subparsers.add_parser("analyze", help="analyse a pcap/pcapng file")
    analyze.add_argument("pcap", help="path to a pcap/pcapng capture")
    analyze.add_argument("-c", "--config", metavar="PATH", help="YAML/JSON configuration file")
    analyze.add_argument("--bpf", metavar="FILTER", help="BPF filter applied to the capture")
    add_detector_args(analyze)
    add_output_args(analyze)

    report = subparsers.add_parser("report", help="re-render reports from a SQLite database")
    report.add_argument("database", help="SQLite database created by --sqlite")
    report.add_argument("-c", "--config", metavar="PATH", help="YAML/JSON configuration file")
    add_output_args(report)

    subparsers.add_parser("rules", help="list all detection rules")
    return parser


def _apply_cli_overrides(config: Config, args: argparse.Namespace) -> None:
    """Only override values explicitly supplied on the command line."""
    values: dict[str, Any] = vars(args)
    capture_map = {"interface": "interface", "bpf": "bpf_filter", "duration": "duration"}
    for arg_name, field_name in capture_map.items():
        if values.get(arg_name) is not None:
            setattr(config.capture, field_name, values[arg_name])

    detector_map = {
        "rate_threshold": "rate_threshold",
        "rate_window": "rate_window",
        "entropy_threshold": "entropy_threshold",
        "nxdomain_threshold": "nxdomain_threshold",
    }
    for arg_name, field_name in detector_map.items():
        if values.get(arg_name) is not None:
            setattr(config.detectors, field_name, values[arg_name])

    output_map = {
        "jsonl": "jsonl",
        "json": "json",
        "sqlite": "sqlite",
        "csv": "csv",
        "html": "html",
        "markdown": "markdown",
        "log_file": "log_file",
        "quiet": "quiet",
    }
    for arg_name, field_name in output_map.items():
        if values.get(arg_name) is not None:
            setattr(config.output, field_name, values[arg_name])

    alerting_map = {
        "webhook_url": "webhook_url",
        "webhook_format": "webhook_format",
        "min_severity": "min_severity",
    }
    for arg_name, field_name in alerting_map.items():
        if values.get(arg_name) is not None:
            setattr(config.alerting, field_name, values[arg_name])


def _build_sinks(config: Config) -> MultiSink:
    sinks = MultiSink()
    if config.output.jsonl:
        sinks.add(JSONLSink(config.output.jsonl))
    if config.output.csv:
        sinks.add(CSVSink(config.output.csv))
    if config.output.sqlite:
        sinks.add(SQLiteSink(config.output.sqlite))
    return sinks


def _run(args: argparse.Namespace) -> int:
    config = Config.load(getattr(args, "config", None))
    _apply_cli_overrides(config, args)
    config.prepare_paths()

    if args.command == "analyze":
        config.capture.pcap = args.pcap

    analyzer = Analyzer(config)
    sinks = _build_sinks(config)
    dispatcher = AlertDispatcher(config.alerting, quiet=config.output.quiet)
    alert_log = AlertLog(config.output.log_file) if config.output.log_file else None

    def on_query(query) -> None:
        alerts = analyzer.ingest(query)
        sinks.write_query(query)
        for alert in alerts:
            sinks.write_alert(alert)
            dispatcher.emit(alert)
            if alert_log:
                alert_log.write(alert)

    try:
        if args.command == "run" and getattr(args, "simulate", None):
            run_simulation(args.simulate, args.seed, on_query)
        elif args.command == "run":
            try:
                capture_live(config.capture, on_query)
            except PermissionError:
                print(
                    "error: live capture needs elevated privileges. "
                    "Use sudo, or try --simulate / analyze <file.pcap>.",
                    file=sys.stderr,
                )
                return 1
        elif args.command == "analyze":
            capture_pcap(config.capture.pcap, on_query, config.capture.bpf_filter)
        elif args.command == "report":
            queries, alerts = load_sqlite(args.database)
            analyzer.import_events(queries, alerts)
    finally:
        sinks.close()
        if alert_log:
            alert_log.close()

    if not getattr(args, "no_console_report", False):
        print(render_console(analyzer))
    written = write_reports(analyzer, config.output)
    for path in written:
        print(f"[+] wrote {path}")
    if dispatcher.webhook_errors:
        print(f"[!] {dispatcher.webhook_errors} webhook delivery error(s)", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    if args.command == "rules":
        print(f"{'RULE':<22} DESCRIPTION")
        print("-" * 78)
        for name, description in RULES.items():
            print(f"{name:<22} {description}")
        return 0
    try:
        return _run(args)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[!] interrupted — writing partial report", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

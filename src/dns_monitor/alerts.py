"""Console, file and webhook alert delivery."""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

from .config import AlertingConfig
from .models import Alert
from .utils import ensure_parent, severity_rank

_SEVERITY_ICONS = {
    "critical": "💀",
    "high": "🚨",
    "medium": "⚠️",
    "low": "ℹ️",
    "info": "•",
}


class AlertDispatcher:
    """Fan alerts out to the terminal, a log file and an optional webhook."""

    def __init__(self, config: AlertingConfig | None = None, quiet: bool = False) -> None:
        self.config = config or AlertingConfig()
        self.quiet = quiet
        self.delivered = 0
        self.webhook_errors = 0
        self._min_rank = severity_rank(self.config.min_severity)

    def emit(self, alert: Alert) -> None:
        if severity_rank(alert.severity) < self._min_rank:
            return
        self.delivered += 1
        if not self.quiet:
            icon = _SEVERITY_ICONS.get(alert.severity.lower(), "•")
            print(
                f"{icon} [{alert.severity.upper()}] {alert.rule}: "
                f"{alert.domain} ← {alert.source_ip} — {alert.message}",
                file=sys.stderr,
                flush=True,
            )
        if self.config.webhook_url:
            self._post_webhook(alert)

    def emit_many(self, alerts: list[Alert]) -> None:
        for alert in alerts:
            self.emit(alert)

    def _post_webhook(self, alert: Alert) -> None:
        if self.config.webhook_format.lower() == "slack":
            payload = {
                "text": (
                    f":rotating_light: *DNS Monitor {alert.severity.upper()}* — "
                    f"`{alert.rule}` detected `{alert.domain}` from `{alert.source_ip}`. "
                    f"{alert.message}"
                )
            }
        else:
            payload = alert.to_dict()
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.config.webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.webhook_timeout) as response:
                response.read(128)
        except Exception:  # pragma: no cover - network dependent
            self.webhook_errors += 1


class AlertLog:
    """Simple human-readable alert log file."""

    def __init__(self, path: str | Path) -> None:
        self.path = ensure_parent(path)
        self.file = self.path.open("a", encoding="utf-8")

    def write(self, alert: Alert) -> None:
        import datetime

        stamp = datetime.datetime.fromtimestamp(alert.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        self.file.write(
            f"[{stamp}] [{alert.severity.upper()}] {alert.rule} "
            f"{alert.source_ip} -> {alert.domain}: {alert.message}\n"
        )
        self.file.flush()

    def close(self) -> None:
        self.file.close()

#!/usr/bin/env python3
"""Regenerate the documentation images committed under docs/images/.

Requirements: Pillow, matplotlib and Graphviz ``dot`` (only for the diagram).
Usage: python tools/generate_assets.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGES = ROOT / "docs" / "images"
IMAGES.mkdir(parents=True, exist_ok=True)

BG = "#070c17"
PANEL = "#0f172a"
CYAN = "#22d3ee"
RED = "#f43f5e"
TEXT = "#e2e8f0"
MUTED = "#94a3b8"


def font_path() -> str:
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationMono-Regular.ttf",
    ]
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate
    return "DejaVuSansMono"


def make_logo() -> Path:
    """Draw a shield + magnifier + network-nodes app icon."""
    from PIL import Image, ImageDraw

    scale = 2
    size = 256 * scale
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    def box(coords):
        return tuple(int(value * scale) for value in coords)

    # Rounded dark tile with a subtle cyan top-left glow.
    draw.rounded_rectangle(box((8, 8, 248, 248)), radius=44 * scale, fill="#0b1220")
    draw.rounded_rectangle(
        box((12, 12, 244, 244)), radius=40 * scale, outline="#164e63", width=2 * scale
    )

    # Shield silhouette.
    shield = [
        (128, 34), (190, 58), (186, 128), (170, 177), (128, 214),
        (86, 177), (70, 128), (66, 58),
    ]
    draw.polygon([(int(x * scale), int(y * scale)) for x, y in shield], fill="#0e2a3a")
    draw.line([(int(x * scale), int(y * scale)) for x, y in shield + [shield[0]]],
              fill=CYAN, width=6 * scale, joint="curve")

    # Network nodes inside the shield.
    nodes = [(104, 92), (150, 80), (128, 132), (100, 166), (158, 158)]
    for a, b in [(0, 2), (1, 2), (2, 3), (2, 4), (3, 4)]:
        draw.line([box(nodes[a]), box(nodes[b])], fill="#38bdf8", width=3 * scale)
    for x, y in nodes:
        r = 7 * scale
        draw.ellipse((x * scale - r, y * scale - r, x * scale + r, y * scale + r),
                     fill="#a5f3fc", outline="#0b1220", width=2 * scale)

    # Magnifying glass over the lower-right quadrant.
    cx, cy, radius = 164, 160, 36
    draw.ellipse(box((cx - radius, cy - radius, cx + radius, cy + radius)),
                 outline="#67e8f9", width=8 * scale)
    draw.line([box((188, 184)), box((215, 211))], fill="#67e8f9", width=11 * scale)

    # Alert spark.
    draw.ellipse(box((46, 42, 70, 66)), fill=RED)
    draw.line([box((58, 47)), box((58, 56))], fill="#fff1f2", width=3 * scale)
    draw.ellipse(box((56, 59, 60, 63)), fill="#fff1f2")

    output = IMAGES / "logo.png"
    image.resize((256, 256), Image.Resampling.LANCZOS).save(output)
    return output


def _captured_demo() -> dict:
    """Run the CLI with a fixed seed and return its JSON report."""
    with tempfile.TemporaryDirectory() as tmp:
        report_path = Path(tmp) / "report.json"
        env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONDONTWRITEBYTECODE="1")
        subprocess.run(
            [sys.executable, "-m", "dns_monitor", "run", "--simulate", "600", "--seed", "7",
             "--json", str(report_path), "--quiet", "--no-console-report"],
            cwd=ROOT, env=env, check=True, capture_output=True, text=True,
        )
        return json.loads(report_path.read_text())


def make_terminal() -> Path:
    """Render a real CLI session into a png that looks like a terminal window."""
    from PIL import Image, ImageDraw, ImageFont

    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run(
        [sys.executable, "-m", "dns_monitor", "run", "--simulate", "120", "--seed", "7"],
        cwd=ROOT, env=env, capture_output=True, text=True, check=True,
    )
    alert_lines = [line for line in result.stderr.splitlines() if line.strip()][:4]
    report_lines = result.stdout.splitlines()
    lines = ["$ dns-monitor run --simulate 120 --seed 7", ""] + alert_lines + [""] + report_lines[:26]

    line_height = 25
    width, height = 1180, 110 + line_height * len(lines)
    image = Image.new("RGB", (width, height), "#0b1120")
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((6, 6, width - 7, height - 7), radius=14, fill="#0b1120",
                           outline="#1e293b", width=2)
    draw.rectangle((7, 7, width - 8, 48), fill="#111c33")
    for index, color in enumerate(["#fb7185", "#fbbf24", "#34d399"]):
        x = 28 + index * 24
        draw.ellipse((x, 20, x + 12, 32), fill=color)
    draw.text((width // 2 - 105, 18), "dns-monitor — bash", font=ImageFont.truetype(font_path(), 15),
              fill=MUTED)

    mono = ImageFont.truetype(font_path(), 16)
    mono_bold = ImageFont.truetype(font_path(), 16)
    for index, line in enumerate(lines):
        color = TEXT
        if line.startswith("[!]"):
            color = RED
        elif line.startswith("[+]"):
            color = "#34d399"
        elif line.startswith("$"):
            color = CYAN
        elif "DNS TRAFFIC MONITOR" in line or line.strip().startswith(("TOP", "DETECTION", "RECENT")):
            color = "#67e8f9"
        draw.text((26, 62 + index * line_height), line[:118], font=mono_bold if index == 0 else mono,
                  fill=color)

    output = IMAGES / "terminal.png"
    image.save(output)
    return output


def make_dashboard(data: dict) -> Path:
    """Render a publication-quality PNG of the report statistics with matplotlib."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyBboxPatch
    from PIL import Image

    plt.rcParams.update({
        "font.family": "DejaVu Sans",
        "text.color": TEXT,
        "axes.labelcolor": MUTED,
        "xtick.color": MUTED,
        "ytick.color": MUTED,
    })
    fig = plt.figure(figsize=(15, 10.8), facecolor=BG)
    summary = data["summary"]

    logo_ax = fig.add_axes([0.915, 0.915, 0.06, 0.06])
    logo_ax.imshow(Image.open(IMAGES / "logo.png"))
    logo_ax.axis("off")
    fig.text(0.04, 0.948, "DNS Monitor — Analysis Report", fontsize=25, weight="bold", color=TEXT)
    fig.text(0.04, 0.915, f"Generated {data['generated_at']}  ·  {summary['queries_per_second']} queries/sec average",
             fontsize=11, color=MUTED)

    cards = [
        ("QUERIES", f"{summary['total_queries']:,}"),
        ("UNIQUE DOMAINS", f"{summary['unique_domains']:,}"),
        ("SOURCE IPS", f"{summary['unique_source_ips']:,}"),
        ("ALERTS", f"{summary['total_alerts']:,}"),
        ("QUERIES / SEC", f"{summary['queries_per_second']:,}"),
    ]
    for index, (label, value) in enumerate(cards):
        ax = fig.add_axes([0.04 + index * 0.186, 0.815, 0.172, 0.073])
        ax.add_patch(FancyBboxPatch((0, 0), 1, 1, boxstyle="round,pad=0.02,rounding_size=0.08",
                                    transform=ax.transAxes, facecolor=PANEL,
                                    edgecolor="#1e293b", lw=1))
        ax.text(0.07, 0.68, label, transform=ax.transAxes, fontsize=9, color=MUTED,
                weight="bold")
        ax.text(0.07, 0.24, value, transform=ax.transAxes, fontsize=22, color=TEXT,
                weight="bold")
        ax.set_axis_off()

    timeline = data["timeline"]
    ax_time = fig.add_axes([0.05, 0.50, 0.57, 0.26], facecolor=PANEL)
    xs = list(range(len(timeline)))
    values = [point["queries"] for point in timeline]
    labels = [point["label"] for point in timeline]
    ax_time.fill_between(xs, values, color=CYAN, alpha=0.18)
    ax_time.plot(xs, values, color=CYAN, lw=2.4)
    alerts_series = [point["alerts"] for point in timeline]
    ax_time.plot(xs, alerts_series, color=RED, lw=1.8, ls="--", label="alerts")
    ax_time.set_title("Query volume & alerts", fontsize=12, loc="left", pad=10, color=TEXT)
    step = max(1, len(labels) // 6)
    ax_time.set_xticks(xs[::step], [labels[i] for i in xs[::step]])
    ax_time.grid(axis="y", color="#1e293b", lw=0.8)
    ax_time.set_axisbelow(True)
    for spine in ax_time.spines.values():
        spine.set_visible(False)

    ax_rules = fig.add_axes([0.66, 0.50, 0.29, 0.26], facecolor=PANEL)
    rules = list(reversed(data["alerts_by_rule"][:7]))
    ax_rules.barh([item["rule"] for item in rules], [item["count"] for item in rules],
                  color="#fb7185", height=0.62)
    ax_rules.set_title("Rule triggers", fontsize=12, loc="left", pad=10, color=TEXT)
    ax_rules.tick_params(labelsize=9)
    for spine in ax_rules.spines.values():
        spine.set_visible(False)
    ax_rules.grid(axis="x", color="#1e293b", lw=0.8)
    ax_rules.set_axisbelow(True)

    ax_domains = fig.add_axes([0.05, 0.24, 0.57, 0.19], facecolor=PANEL)
    domains = list(reversed(data["top_domains"][:8]))
    ax_domains.barh([item["domain"][:36] for item in domains], [item["count"] for item in domains],
                    color=CYAN, height=0.6)
    ax_domains.set_title("Top queried domains", fontsize=12, loc="left", pad=8, color=TEXT)
    ax_domains.tick_params(labelsize=9)
    for spine in ax_domains.spines.values():
        spine.set_visible(False)
    ax_domains.grid(axis="x", color="#1e293b", lw=0.8)
    ax_domains.set_axisbelow(True)

    ax_ips = fig.add_axes([0.66, 0.24, 0.29, 0.19], facecolor=PANEL)
    ips = list(reversed(data["top_ips"][:6]))
    ax_ips.barh([item["ip"] for item in ips], [item["queries"] for item in ips],
                color="#38bdf8", height=0.6)
    ax_ips.set_title("Top source IPs", fontsize=12, loc="left", pad=8, color=TEXT)
    ax_ips.tick_params(labelsize=9)
    for spine in ax_ips.spines.values():
        spine.set_visible(False)
    ax_ips.grid(axis="x", color="#1e293b", lw=0.8)
    ax_ips.set_axisbelow(True)

    ax_alerts = fig.add_axes([0.05, 0.035, 0.90, 0.155], facecolor=PANEL)
    ax_alerts.axis("off")
    ax_alerts.set_title("Recent detections", fontsize=12, loc="left", pad=8, color=TEXT)
    ax_alerts.text(0.01, 0.79, "SEVERITY", transform=ax_alerts.transAxes, fontsize=8, color=MUTED, weight="bold")
    ax_alerts.text(0.13, 0.79, "RULE", transform=ax_alerts.transAxes, fontsize=8, color=MUTED, weight="bold")
    ax_alerts.text(0.37, 0.79, "DOMAIN", transform=ax_alerts.transAxes, fontsize=8, color=MUTED, weight="bold")
    ax_alerts.text(0.74, 0.79, "DETAIL", transform=ax_alerts.transAxes, fontsize=8, color=MUTED, weight="bold")
    for index, alert in enumerate(data["alerts"][:4]):
        y = 0.60 - index * 0.19
        severity_color = {"critical": RED, "high": RED, "medium": "#fbbf24", "low": CYAN}.get(
            alert["severity"], MUTED
        )
        ax_alerts.plot([0.01, 0.98], [y - 0.07, y - 0.07], color="#1e293b", lw=0.8,
                       transform=ax_alerts.transAxes)
        ax_alerts.text(0.01, y, alert["severity"].upper(), transform=ax_alerts.transAxes,
                       fontsize=9, color=severity_color, weight="bold")
        ax_alerts.text(0.13, y, alert["rule"], transform=ax_alerts.transAxes,
                       fontsize=9, color="#a5f3fc", family="DejaVu Sans Mono")
        ax_alerts.text(0.37, y, alert["domain"][:34], transform=ax_alerts.transAxes,
                       fontsize=9, color=TEXT, family="DejaVu Sans Mono")
        ax_alerts.text(0.74, y, alert["message"][:44], transform=ax_alerts.transAxes,
                       fontsize=8.5, color=MUTED)
    fig.text(0.5, 0.008, "github.com/mohamedait-abbou/dns-monitor  ·  open-source DNS traffic analysis",
             ha="center", fontsize=9, color="#475569")

    output = IMAGES / "dashboard.png"
    fig.savefig(output, dpi=150, facecolor=BG)
    plt.close(fig)
    return output


def make_architecture() -> Path | None:
    dot_file = ROOT / "docs" / "diagrams" / "architecture.dot"
    output = IMAGES / "architecture.png"
    try:
        subprocess.run(["dot", "-Tpng", str(dot_file), "-o", str(output)], check=True,
                       capture_output=True, text=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        print(f"warning: Graphviz unavailable, skipping diagram: {exc}", file=sys.stderr)
        return None
    return output


def main() -> None:
    logo = make_logo()
    data = _captured_demo()
    (IMAGES / "demo-report.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    created = [logo, make_terminal(), make_dashboard(data)]
    diagram = make_architecture()
    if diagram:
        created.append(diagram)
    for path in created:
        print(f"created {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()

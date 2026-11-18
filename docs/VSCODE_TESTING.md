# Testing DNS Monitor in VSCode

This guide gets you from an opened folder to running tests and a generated dashboard.

## 1. Open and install extensions

1. Open VSCode.
2. `File → Open Folder...` → select the `dns-monitor` folder.
3. VSCode will recommend the Python, Pylance, Debugpy and Ruff extensions. Install them.
   If it does not ask, press `Ctrl + Shift + X`, search for `ms-python.python` and install it.

## 2. Create the virtual environment

Open the integrated terminal with **Ctrl + `**. Make sure you are in the project root — the folder containing `pyproject.toml`.

### Windows PowerShell

```powershell
python --version
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
pip install -e .
```

If `python` is not found, try `py -3.12` everywhere instead:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
py -3.12 -m pip install -r requirements-dev.txt
py -3.12 -m pip install -e .
```

### macOS / Linux / WSL

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
pip install -e .
```

## 3. Select the interpreter

Press `Ctrl + Shift + P`, then choose:

```text
Python: Select Interpreter
```

Pick `.venv`:

- Windows → `.venv\Scripts\python.exe`
- macOS/Linux → `.venv/bin/python`

The repository already contains `.vscode/settings.json`, so pytest discovery is enabled automatically.

## 4. Run the tests

### From the terminal

```bash
python -m pytest -q
```

Expected:

```text
30 passed
```

With coverage:

```bash
python -m pytest --cov=dns_monitor --cov-report=term-missing
```

Lint:

```bash
python -m ruff check src tests
```

Build:

```bash
python -m build
```

### From the VSCode UI

Click the **beaker** icon in the left activity bar, then click **Run All Tests**. You should see 30 tests pass under `tests/`.

### With the debugger

Press `F5` and choose **Pytest: all tests**. This uses `.vscode/launch.json` and sets `PYTHONPATH=src`.

## 5. Generate the demo dashboard

From the VSCode terminal:

```bash
python -m dns_monitor run --simulate 600 --seed 7 --json out/report.json --html out/report.html --markdown out/report.md --sqlite out/dns.db --jsonl out/events.jsonl --quiet --no-console-report
```

Then check the numbers:

```bash
python -c "import json; d=json.load(open('out/report.json')); print(d['summary']); print(d['alerts_by_rule'])"
```

You should see `total_queries: 600`, `total_alerts > 0`, and all eight detection rules.

Open `out/report.html` in a browser to see the dashboard. You can also press `F5` and choose **DNS Monitor: simulate 600** to debug the whole pipeline.

## 6. Test PCAP analysis

```bash
python examples/generate_pcap.py --output out/sample.pcap --count 250 --seed 5
python -m dns_monitor analyze out/sample.pcap --json out/pcap-report.json --html out/pcap-report.html
```

Expected: 250 queries, alerts from all 8 rules.

## 7. Test report re-rendering

```bash
python -m dns_monitor report out/dns.db --html out/from-db.html --markdown out/from-db.md
```

## 8. Makefile shortcuts

On Linux/macOS/WSL/Git Bash:

```bash
make test
make lint
make demo
make build
```

In normal Windows PowerShell, use the direct Python commands above instead of `make`.

## 9. Troubleshooting

| Problem | Fix |
| --- | --- |
| `python not found` | Install Python 3.10+ and reopen VSCode; on Windows use `py -3.12`. |
| Activation policy error | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |
| `No module named dns_monitor` | Activate `.venv` and run `pip install -e .` |
| `Scapy is required for packet capture` | `pip install -r requirements.txt` |
| Tests not visible in the beaker panel | `Ctrl + Shift + P → Python: Configure Tests → pytest → tests` |
| Live capture permission denied | Expected — use `--simulate` or `analyze` first. Live capture needs admin/root. |

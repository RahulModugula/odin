"""CLI machine-output contract: --json / --sarif stdout must be *only* the payload.

Regression guard for the launch-critical `uvx odin-review review … --json | jq`
and SARIF-upload paths. The human-readable header, per-file prints, and summary
must never leak onto stdout in machine mode, and diagnostics must go to stderr.
"""

from __future__ import annotations

import json
import sys

from app.cli import review

_BAD = 'import os\n\n\ndef ping(host):\n    os.system(f"ping {host}")\n'
_CLEAN = "def add(a: int, b: int) -> int:\n    return a + b\n"


def _run(capsys, monkeypatch, args: list[str]) -> tuple[int, str, str]:
    monkeypatch.setattr(sys, "argv", ["odin-review", *args])
    code = 0
    try:
        review.main()
    except SystemExit as exc:  # argparse / fail-on / quality gate
        code = int(exc.code or 0)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_json_stdout_is_pure_array(tmp_path, capsys, monkeypatch):
    f = tmp_path / "bad.py"
    f.write_text(_BAD)
    _, out, _ = _run(capsys, monkeypatch, ["review", str(f), "--rules-only", "--json"])
    data = json.loads(out)  # would raise if the header leaked onto stdout
    assert isinstance(data, list)
    assert len(data) >= 1


def test_json_clean_file_is_empty_array(tmp_path, capsys, monkeypatch):
    f = tmp_path / "clean.py"
    f.write_text(_CLEAN)
    _, out, _ = _run(capsys, monkeypatch, ["review", str(f), "--rules-only", "--json"])
    assert json.loads(out) == []


def test_sarif_stdout_is_valid_sarif(tmp_path, capsys, monkeypatch):
    f = tmp_path / "bad.py"
    f.write_text(_BAD)
    _, out, _ = _run(capsys, monkeypatch, ["review", str(f), "--rules-only", "--sarif"])
    doc = json.loads(out)
    assert doc["runs"][0]["results"]


def test_json_fail_on_exits_1_with_pure_stdout(tmp_path, capsys, monkeypatch):
    f = tmp_path / "bad.py"
    f.write_text(_BAD)
    code, out, err = _run(
        capsys, monkeypatch, ["review", str(f), "--rules-only", "--json", "--fail-on", "high"]
    )
    assert code == 1
    assert isinstance(json.loads(out), list)  # stdout stays pure JSON
    assert "blocking" in err  # diagnostic routed to stderr

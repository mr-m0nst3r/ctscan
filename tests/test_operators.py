from ctscan.ct.log_list import (
    operator_contact_map,
    parse_operators_from_json,
)
from typer.testing import CliRunner

from ctscan.cli import app

runner = CliRunner()


def test_parse_operators_from_json():
    data = {
        "operators": [
            {"name": "Google", "email": ["google-ct-logs@googlegroups.com"]},
            {"name": "Legacy", "email": "single@example.com"},
            {"name": "NoEmail"},
        ]
    }
    ops = parse_operators_from_json(data)
    assert len(ops) == 3
    assert ops[0].contact == "google-ct-logs@googlegroups.com"
    assert ops[1].emails == ["single@example.com"]
    assert ops[2].contact == "—"

    cmap = operator_contact_map(ops)
    assert cmap["Google"] == "google-ct-logs@googlegroups.com"


def test_operators_command(monkeypatch):
    from ctscan.models import CtOperatorInfo

    def fake_ops(force_refresh=False, **kwargs):
        return [
            CtOperatorInfo(name="Google", emails=["a@google.com"]),
            CtOperatorInfo(name="Cloudflare", emails=["b@cf.com"]),
        ], "disk_cache"

    def fake_logs(force_refresh=False, **kwargs):
        from ctscan.models import CtLogInfo

        return [
            CtLogInfo(
                description="G1",
                url="https://g/",
                year="2026",
                start="2026-01-01",
                end="2027-01-01",
                state="usable",
                operator="Google",
            ),
            CtLogInfo(
                description="C1",
                url="https://c/",
                year="2026",
                start="2026-01-01",
                end="2027-01-01",
                state="usable",
                operator="Cloudflare",
            ),
        ], "disk_cache"

    monkeypatch.setattr("ctscan.cli.fetch_ct_operators", fake_ops)
    monkeypatch.setattr("ctscan.cli.fetch_ct_logs", fake_logs)

    result = runner.invoke(app, ["operators"])
    assert result.exit_code == 0
    assert "a@google.com" in result.stdout
    assert "b@cf.com" in result.stdout

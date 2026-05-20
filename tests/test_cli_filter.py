from typer.testing import CliRunner

from ctscan.cli import app

runner = CliRunner()


def test_scan_rejects_query_and_filter_together():
    result = runner.invoke(
        app,
        [
            "scan",
            "--log-uri",
            "https://ct.googleapis.com/logs/us1/argon2026h1/",
            "--query",
            "issuer_org = 'X'",
            "--filter",
            "issuer_org == 'X'",
            "--target",
            "1",
        ],
    )
    assert result.exit_code != 0
    assert "Cannot use both" in result.stdout

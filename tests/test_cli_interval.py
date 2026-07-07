from typer.testing import CliRunner

from ctscan.cli import app

runner = CliRunner()


def test_scan_rejects_log_uri_and_interval():
    result = runner.invoke(
        app,
        [
            "scan",
            "--log-uri",
            "https://ct.googleapis.com/logs/us1/argon2026h1/",
            "--from",
            "2026-01-01",
            "--target",
            "1",
        ],
    )
    assert result.exit_code != 0
    assert "not both" in result.stdout


def test_scan_requires_log_source():
    result = runner.invoke(app, ["scan", "--target", "1"])
    assert result.exit_code != 0
    assert "Specify" in result.stdout

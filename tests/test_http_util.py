from unittest.mock import patch

from ctscan.ct.http_util import build_http_client


def test_build_http_client_defaults_trust_env_false(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
    with patch("ctscan.ct.http_util.httpx.Client") as mock_client:
        build_http_client()
        assert mock_client.call_args.kwargs["trust_env"] is False
        assert "proxy" not in mock_client.call_args.kwargs

from ctscan.ct.log_list import _builtin_fallback_logs, fetch_ct_logs


def test_builtin_fallback_non_empty():
    logs = _builtin_fallback_logs()
    assert len(logs) >= 5
    assert all(log.url.startswith("https://") for log in logs)


def test_fetch_returns_builtin_when_remote_unavailable(monkeypatch):
    def boom():
        raise ConnectionError("simulated")

    monkeypatch.setattr("ctscan.ct.log_list._fetch_remote_log_list", boom)
    monkeypatch.setattr("ctscan.ct.log_list._load_disk_cache", lambda: None)

    logs, source = fetch_ct_logs(force_refresh=True)
    assert source == "builtin"
    assert len(logs) > 0

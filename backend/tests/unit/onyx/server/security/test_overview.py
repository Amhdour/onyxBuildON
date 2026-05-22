from types import SimpleNamespace

from onyx.server.security import overview


class _Persistence:
    def list_policy_decisions(self, *_args, **_kwargs):
        return []

    def list_retrieval_events(self, *_args, **_kwargs):
        return []

    def list_mcp_events(self, *_args, **_kwargs):
        return []


class _FindingService:
    def list_findings(self, *_args, **_kwargs):
        return [SimpleNamespace(status="open", severity="high")]


def _run_overview(monkeypatch, enabled: bool, configured_mode: str) -> dict[str, object]:
    monkeypatch.setattr(overview, "SECURITY_LAYER_ENABLED", enabled)
    monkeypatch.setattr(overview, "get_security_layer_mode", lambda: configured_mode)
    monkeypatch.setattr(overview, "get_current_tenant_id", lambda: "tenant")
    monkeypatch.setattr(overview, "SecurityPersistenceService", _Persistence)
    monkeypatch.setattr(overview, "FindingService", _FindingService)

    return overview.get_security_overview(_=None)


def test_overview_policy_mode_enabled_observe(monkeypatch) -> None:
    payload = _run_overview(monkeypatch, enabled=True, configured_mode="observe")

    assert payload["security_layer_enabled"] is True
    assert payload["configured_policy_mode"] == "observe"
    assert payload["effective_policy_mode"] == "observe"
    assert payload["policy_mode"] == "observe"


def test_overview_policy_mode_enabled_enforce(monkeypatch) -> None:
    payload = _run_overview(monkeypatch, enabled=True, configured_mode="enforce")

    assert payload["security_layer_enabled"] is True
    assert payload["configured_policy_mode"] == "enforce"
    assert payload["effective_policy_mode"] == "enforce"
    assert payload["policy_mode"] == "enforce"


def test_overview_policy_mode_disabled_enforce(monkeypatch) -> None:
    payload = _run_overview(monkeypatch, enabled=False, configured_mode="enforce")

    assert payload["security_layer_enabled"] is False
    assert payload["configured_policy_mode"] == "enforce"
    assert payload["effective_policy_mode"] == "disabled"
    assert payload["policy_mode"] == "disabled"

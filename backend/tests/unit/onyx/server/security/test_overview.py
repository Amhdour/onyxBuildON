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


def test_overview_policy_mode_respects_configured_mode(monkeypatch) -> None:
    monkeypatch.setattr(overview, "SECURITY_LAYER_ENABLED", True)
    monkeypatch.setattr(overview, "get_security_layer_mode", lambda: "observe")
    monkeypatch.setattr(overview, "get_current_tenant_id", lambda: "tenant")
    monkeypatch.setattr(overview, "SecurityPersistenceService", _Persistence)
    monkeypatch.setattr(overview, "FindingService", _FindingService)

    payload = overview.get_security_overview(_=None)

    assert payload["policy_mode"] == "observe"

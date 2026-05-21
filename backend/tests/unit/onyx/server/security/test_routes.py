from onyx.server.security import router


def test_security_routes_registered() -> None:
    paths = {route.path for route in router.routes}
    assert "/admin/security/overview" in paths
    assert "/admin/security/findings" in paths
    assert "/admin/security/audit" in paths
    assert "/admin/security/tools/decisions" in paths
    assert "/admin/security/retrieval/events" in paths
    assert "/admin/security/mcp/events" in paths
    assert "/admin/security/sandbox/gates" in paths
    assert "/admin/security/artifacts/scans" in paths
    assert "/admin/security/launch-gates" in paths
    assert "/admin/security/launch-gates/run" in paths
    assert "/admin/security/reports" in paths

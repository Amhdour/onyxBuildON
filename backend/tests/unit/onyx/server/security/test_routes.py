from onyx.server.security import router


def test_security_routes_registered() -> None:
    paths = {route.path for route in router.routes}
    assert "/security/overview" in paths
    assert "/security/findings" in paths
    assert "/security/audit" in paths
    assert "/security/tools/decisions" in paths
    assert "/security/retrieval/events" in paths
    assert "/security/mcp/events" in paths
    assert "/security/sandbox/gates" in paths
    assert "/security/artifacts/scans" in paths
    assert "/security/launch-gates" in paths
    assert "/security/launch-gates/run" in paths
    assert "/security/reports" in paths

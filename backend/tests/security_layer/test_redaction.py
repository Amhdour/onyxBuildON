from onyx.security_layer.redaction import redact_security_payload


def test_redacts_nested_payload_and_strings() -> None:
    payload = {
        "api_key": "sk-test-123456789",
        "headers": {"Authorization": "Bearer abc.def.ghi"},
        "nested": [{"password": "p@ss"}, "token=abc", {"jwt": "eyJabc.def.ghi"}],
        "aws": "AKIAABCDEFGHIJKLMNOP",
        "pem": "-----BEGIN PRIVATE KEY-----\\na\\n-----END PRIVATE KEY-----",
        "demo": "demo_secret",
    }
    out = redact_security_payload(payload)
    assert out["api_key"] == "[REDACTED]"
    assert out["headers"]["Authorization"] == "[REDACTED]"
    assert out["nested"][0]["password"] == "[REDACTED]"
    assert "[REDACTED]" in out["nested"][1]
    assert out["nested"][2]["jwt"] == "[REDACTED]"
    assert out["aws"] == "[REDACTED]"
    assert out["pem"] == "[REDACTED]"
    assert out["demo"] == "[REDACTED]"

from onyx.security_layer.redaction import redact_security_payload


def test_redacts_nested_payload_and_strings() -> None:
    payload = {
        "api_key": "sk-test-123456789",
        "headers": {"Authorization": "Bearer abc.def.ghi"},
        "nested": [{"password": "p@ss"}, "token=abc"],
    }
    out = redact_security_payload(payload)
    assert out["api_key"] == "[REDACTED]"
    assert out["headers"]["Authorization"] == "[REDACTED]"
    assert out["nested"][0]["password"] == "[REDACTED]"
    assert "[REDACTED]" in out["nested"][1]

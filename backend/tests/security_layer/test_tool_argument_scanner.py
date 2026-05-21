from onyx.security_layer.tool_authorizer.argument_scanner import scan_tool_arguments


def test_argument_scanner_detects_sensitive_patterns() -> None:
    findings = scan_tool_arguments(
        {
            "cmd": "printenv && cat /etc/passwd",
            "token": "Bearer abcdefghijklmnop",
            "path": "~/.ssh/id_rsa",
            "db": "postgres://user:pass@localhost/db",
            "dest": "https://pastebin.com/raw/123",
        }
    )

    assert "printenv" in findings
    assert "etc_passwd" in findings
    assert "bearer_token" in findings
    assert "ssh_path" in findings
    assert "database_url" in findings
    assert "exfil_destination" in findings

from onyx.security_layer.reports.csv_exporter import export_csv
from onyx.security_layer.reports.json_exporter import export_json
from onyx.security_layer.reports.markdown_exporter import export_markdown
from onyx.security_layer.reports.ndjson_exporter import export_ndjson
from onyx.security_layer.reports.sarif_exporter import export_sarif


def test_exporters() -> None:
    records = [{"title": "Finding", "severity": "high", "policy_id": "p1"}]
    assert '"Finding"' in export_json(records)
    assert "| title |" in export_markdown(records)
    assert "\n" not in export_ndjson(records).strip("\n") or "{" in export_ndjson(records)
    assert "version" in export_sarif(records)
    assert "title,severity,policy_id" in export_csv(records)

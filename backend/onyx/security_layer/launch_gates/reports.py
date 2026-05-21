from __future__ import annotations

import json
from pathlib import Path

from onyx.security_layer.launch_gates.engine import LaunchGateResult
from onyx.security_layer.reports.csv_exporter import export_csv
from onyx.security_layer.reports.json_exporter import export_json
from onyx.security_layer.reports.markdown_exporter import export_markdown
from onyx.security_layer.reports.ndjson_exporter import export_ndjson
from onyx.security_layer.reports.sarif_exporter import export_sarif


def _summary_payload(result: LaunchGateResult) -> dict[str, object]:
    checks = result.scorecard.checks
    return {
        "summary": {
            "total_gates": len(checks),
            "pass_count": sum(1 for c in checks if c.status.value == "pass"),
            "fail_count": sum(1 for c in checks if c.status.value == "fail"),
            "warning_count": sum(1 for c in checks if c.status.value == "warning"),
        },
        "overall_status": result.scorecard.overall_status.value,
        "passed_gates": result.scorecard.passed_gates,
        "failed_gates": result.scorecard.failed_gates,
        "warnings": result.scorecard.warnings,
        "blocking_failures": result.blocking_failures,
        "findings": result.findings,
        "audit_evidence_sample": result.evidence.audit_evidence_sample,
        "policy_decisions": result.evidence.policy_decisions,
        "recommended_fixes": [f.get("recommended_fix", "") for f in result.findings],
    }


def generate_launch_gate_reports(result: LaunchGateResult, output_dir: Path | str = "security_reports") -> dict[str, Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    payload = _summary_payload(result)

    json_path = out / "launch_gate_report.json"
    json_path.write_text(json.dumps(payload, indent=2, default=str))

    md_records = [
        {"gate": c.gate, "status": c.status.value, "message": c.message, "blocking": c.is_blocking}
        for c in result.scorecard.checks
    ]
    md_content = "# Launch Gate Report\n\n"
    md_content += f"Overall status: **{result.scorecard.overall_status.value}**\n\n"
    md_content += export_markdown(md_records)
    md_path = out / "launch_gate_report.md"
    md_path.write_text(md_content)

    sarif_path = out / "security_findings.sarif"
    sarif_path.write_text(export_sarif(result.findings))

    ndjson_path = out / "audit_sample.ndjson"
    ndjson_path.write_text(export_ndjson(result.evidence.audit_evidence_sample))

    csv_path = out / "policy_decisions.csv"
    csv_path.write_text(export_csv(result.evidence.policy_decisions))

    return {
        "launch_gate_report.json": json_path,
        "launch_gate_report.md": md_path,
        "security_findings.sarif": sarif_path,
        "audit_sample.ndjson": ndjson_path,
        "policy_decisions.csv": csv_path,
    }

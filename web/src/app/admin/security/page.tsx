"use client";

import { Text } from "@opal/components";
import { ContentAction } from "@opal/layouts";
import SvgShield from "@/icons/shield";
import useSWR from "swr";

const fetcher = (url: string) => fetch(url).then((res) => res.json());
const ENDPOINTS = {
  overview: "/api/admin/security/overview",
  decisions: "/api/admin/security/tools/decisions",
  findings: "/api/admin/security/findings",
  approvals: "/api/admin/security/approvals",
  retrieval: "/api/admin/security/retrieval/events",
  mcp: "/api/admin/security/mcp/events",
};

export default function SecurityAdminPage() {
  const { data, isLoading, error } = useSWR(Object.values(ENDPOINTS), async (urls: string[]) => Promise.all(urls.map((url) => fetcher(url))));
  const [overview, decisions, findings, approvals, retrieval, mcp] = data || [];

  return <div className="p-6 space-y-4">
    <ContentAction sizePreset="main-ui" variant="section" icon={SvgShield} title="Agent Runtime Security Operations" description="Enforcement and audit telemetry" />
    {isLoading && <Text font="main-ui-body" color="text-03">Loading...</Text>}
    {error && <Text font="main-ui-body" color="text-03">Failed to load.</Text>}

    <div className="grid grid-cols-2 gap-3">
      {Object.entries(overview || {}).map(([k, v]) => <div key={k} className="border border-border-02 rounded-md p-3"><Text font="secondary-action" color="text-03">{k}</Text><Text font="heading-h3" color="text-01">{String(v)}</Text></div>)}
    </div>

    <Section title="Recent Denials" rows={(decisions || []).filter((d: any) => d.decision === "deny")} cols={["created_at", "decision", "reason", "actor_user_id", "tenant_id", "correlation_id"]} />
    <Section title="Findings" rows={findings || []} cols={["created_at", "severity", "title", "status", "actor_user_id", "tenant_id", "correlation_id"]} />
    <Section title="Pending Approvals" rows={(approvals || []).filter((a: any) => a.status === "pending")} cols={["created_at", "status", "action", "tool_name", "requested_by_user_id", "tenant_id", "expires_at"]} />
    <Section title="Audit Timeline" rows={[...(retrieval || []), ...(mcp || [])].slice(0, 50)} cols={["created_at", "decision", "action", "reason", "actor_user_id", "tenant_id", "correlation_id"]} />
    <details className="border border-border-02 rounded-md p-3"><summary><Text font="main-ui-action" color="text-02">Raw JSON (expand)</Text></summary><pre className="bg-background-neutral-02 p-2 rounded-md overflow-x-auto text-xs">{JSON.stringify({ overview, decisions, findings, approvals, retrieval, mcp }, null, 2)}</pre></details>
  </div>;
}

interface SectionProps { title: string; rows: any[]; cols: string[] }
function Section({ title, rows, cols }: SectionProps) {
  return <div className="border border-border-02 rounded-md p-3 space-y-2">
    <Text font="main-ui-action" color="text-02">{title}</Text>
    <div className="overflow-x-auto"><table className="w-full text-xs"><thead><tr>{cols.map((c) => <th key={c} className="text-left p-1">{c}</th>)}</tr></thead><tbody>{rows.slice(0, 20).map((row, i) => <tr key={i}>{cols.map((c) => <td key={c} className="p-1 border-t border-border-01">{String(row?.[c] ?? "")}</td>)}</tr>)}</tbody></table></div>
  </div>;
}

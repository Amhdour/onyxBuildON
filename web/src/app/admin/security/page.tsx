"use client";

import { Text } from "@opal/components";
import { ContentAction } from "@opal/layouts";
import useSWR from "swr";
import { useMemo, useState } from "react";

const fetcher = (url: string) => fetch(url).then((res) => res.json());
const ENDPOINTS = { overview: "/api/admin/security/overview", decisions: "/api/admin/security/tools/decisions", findings: "/api/admin/security/findings", approvals: "/api/admin/security/approvals", retrieval: "/api/admin/security/retrieval/events", mcp: "/api/admin/security/mcp/events" };

export default function SecurityAdminPage() {
  const { data, isLoading, error, mutate } = useSWR(Object.values(ENDPOINTS), async (urls: string[]) => Promise.all(urls.map((url) => fetcher(url))));
  const [overview, decisions, findings, approvals, retrieval, mcp] = data || [];
  const [filters, setFilters] = useState({ correlation: "", tenant: "", user: "", severity: "", decision: "" });
  const timelineRows = useMemo(() => ([...(retrieval || []), ...(mcp || []), ...(decisions || [])].filter((r: any) =>
    (!filters.correlation || String(r.correlation_id || "").includes(filters.correlation)) &&
    (!filters.tenant || String(r.tenant_id || "").includes(filters.tenant)) &&
    (!filters.user || String(r.actor_user_id || r.user_id || "").includes(filters.user)) &&
    (!filters.severity || String(r.severity || "").toLowerCase() === filters.severity.toLowerCase()) &&
    (!filters.decision || String(r.decision || "").toLowerCase() === filters.decision.toLowerCase())
  )), [retrieval, mcp, decisions, filters]);

  async function setApproval(id: string, status: "approve" | "deny") {
    await fetch(`/api/admin/security/approvals/${id}/${status}`, { method: "POST" });
    mutate();
  }

  return <div className="p-6 space-y-4">
    <ContentAction sizePreset="main-ui" variant="section" title="Agent Runtime Security Operations" description="Enforcement and audit telemetry" />
    {isLoading && <Text font="main-ui-body" color="text-03">Loading...</Text>}
    {error && <Text font="main-ui-body" color="text-03">Failed to load.</Text>}

    <div className="grid grid-cols-5 gap-2">
      <input className="border border-border-02 p-2 rounded-md" placeholder="correlation_id" onChange={(e) => setFilters({ ...filters, correlation: e.target.value })} />
      <input className="border border-border-02 p-2 rounded-md" placeholder="tenant_id" onChange={(e) => setFilters({ ...filters, tenant: e.target.value })} />
      <input className="border border-border-02 p-2 rounded-md" placeholder="user_id" onChange={(e) => setFilters({ ...filters, user: e.target.value })} />
      <input className="border border-border-02 p-2 rounded-md" placeholder="severity" onChange={(e) => setFilters({ ...filters, severity: e.target.value })} />
      <input className="border border-border-02 p-2 rounded-md" placeholder="decision" onChange={(e) => setFilters({ ...filters, decision: e.target.value })} />
    </div>

    <Section title="Pending Approvals" rows={(approvals || []).filter((a: any) => a.status === "pending")} cols={["created_at", "status", "action", "tool_name", "requested_by_user_id", "tenant_id", "expires_at"]}
      rowActions={(row: any) => <div className="flex gap-2"><button className="border border-border-02 rounded-md p-1" onClick={() => setApproval(row.id, "approve")}>Approve</button><button className="border border-border-02 rounded-md p-1" onClick={() => setApproval(row.id, "deny")}>Deny</button></div>} />

    <Section title="Correlation Timeline" rows={timelineRows.slice(0, 100)} cols={["created_at", "decision", "action", "reason", "actor_user_id", "tenant_id", "correlation_id"]} />
    <Section title="Findings" rows={findings || []} cols={["created_at", "severity", "title", "status", "actor_user_id", "tenant_id", "correlation_id"]} />
    <details className="border border-border-02 rounded-md p-3"><summary><Text font="main-ui-action" color="text-02">Raw JSON (expand)</Text></summary><pre className="bg-background-neutral-02 p-2 rounded-md overflow-x-auto text-xs">{JSON.stringify({ overview, decisions, findings, approvals, retrieval, mcp }, null, 2)}</pre></details>
  </div>;
}

interface SectionProps { title: string; rows: any[]; cols: string[]; rowActions?: (row: any) => JSX.Element }
function Section({ title, rows, cols, rowActions }: SectionProps) {
  return <div className="border border-border-02 rounded-md p-3 space-y-2">
    <Text font="main-ui-action" color="text-02">{title}</Text>
    <div className="overflow-x-auto"><table className="w-full text-xs"><thead><tr>{cols.map((c) => <th key={c} className="text-left p-1">{c}</th>)}{rowActions && <th className="text-left p-1">actions</th>}</tr></thead><tbody>{rows.slice(0, 20).map((row, i) => <tr key={i}>{cols.map((c) => <td key={c} className="p-1 border-t border-border-01"><details><summary>{String(row?.[c] ?? "")}</summary><pre>{JSON.stringify(row?.[c], null, 2)}</pre></details></td>)}{rowActions && <td className="p-1 border-t border-border-01">{rowActions(row)}</td>}</tr>)}</tbody></table></div>
  </div>;
}

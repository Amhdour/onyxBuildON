"use client";

import { Text } from "@opal/components";
import { ContentAction } from "@opal/layouts";
import SvgShield from "@/icons/shield";
import useSWR from "swr";

const fetcher = (url: string) => fetch(url).then((res) => res.json());

interface TabConfig {
  key: string;
  label: string;
  endpoint: string;
}

const TABS: TabConfig[] = [
  { key: "overview", label: "Overview", endpoint: "/api/admin/security/overview" },
  { key: "tools", label: "Tool Decisions", endpoint: "/api/admin/security/tools/decisions" },
  { key: "retrieval", label: "Retrieval", endpoint: "/api/admin/security/retrieval/events" },
  { key: "mcp", label: "MCP", endpoint: "/api/admin/security/mcp/events" },
  { key: "artifacts", label: "Artifacts", endpoint: "/api/admin/security/artifacts/scans" },
  { key: "findings", label: "Findings", endpoint: "/api/admin/security/findings" },
  { key: "launch", label: "Launch Gates", endpoint: "/api/admin/security/launch-gates" },
  { key: "sandbox", label: "Sandbox", endpoint: "/api/admin/security/sandbox/gates" },
  { key: "approvals", label: "Approvals", endpoint: "/api/admin/security/approvals" },
  { key: "reports", label: "Reports", endpoint: "/api/admin/security/reports" },
];

export default function SecurityAdminPage() {
  const { data: sections, isLoading, error } = useSWR(
    TABS.map((tab) => tab.endpoint),
    async (urls: string[]) => Promise.all(urls.map((url) => fetcher(url)))
  );

  return (
    <div className="p-6 space-y-4">
      <ContentAction
        sizePreset="main-ui"
        variant="section"
        icon={SvgShield}
        title="Agent Runtime Security Operations"
        description="DB-backed audit, policy decisions, retrieval/MCP/artifact/sandbox telemetry, and approvals"
      />
      {isLoading && <Text font="main-ui-body" color="text-03">Loading security operations data...</Text>}
      {error && <Text font="main-ui-body" color="text-03">Failed to load security operations data.</Text>}
      {sections && TABS.map((tab, index) => (
        <div key={tab.key} className="border border-border-02 rounded-md p-3 space-y-2">
          <Text font="main-ui-action" color="text-02">{tab.label}</Text>
          <pre className="bg-background-neutral-02 p-2 rounded-md overflow-x-auto text-xs">
            {JSON.stringify(sections[index], null, 2)}
          </pre>
        </div>
      ))}
    </div>
  );
}

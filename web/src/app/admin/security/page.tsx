"use client";

import { Text } from "@opal/components";
import { ContentAction } from "@opal/layouts";
import SvgShield from "@/icons/shield";
import useSWR from "swr";

interface SecurityDashboardResponse {
  enabled_by_default: boolean;
  default_mode: string;
  controls: string[];
}

const fetcher = (url: string) => fetch(url).then((res) => res.json());

export default function SecurityAdminPage() {
  const { data, isLoading } = useSWR<SecurityDashboardResponse>(
    "/api/admin/security-layer/dashboard",
    fetcher
  );

  return (
    <div className="p-6">
      <ContentAction
        sizePreset="main-ui"
        variant="section"
        icon={SvgShield}
        title="Agent Runtime Security Layer"
        description="Internal MVP controls for runtime policy enforcement"
      />
      {isLoading && <Text font="main-ui-body" color="text-03">Loading security controls...</Text>}
      {data && (
        <div className="pt-4 space-y-2">
          <Text font="main-ui-action" color="text-02">
            Default Mode: {data.default_mode}
          </Text>
          <Text font="main-ui-body" color="text-03">
            Enabled by default: {data.enabled_by_default ? "yes" : "no"}
          </Text>
          {data.controls.map((control) => (
            <Text key={control} font="main-ui-body" color="text-03" as="p">
              • {control}
            </Text>
          ))}
        </div>
      )}
    </div>
  );
}

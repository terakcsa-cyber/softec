"use client";

import { Suspense } from "react";
import { useParams } from "next/navigation";
import { RequireAuth } from "@/components/auth/require-auth";
import { VcShell } from "@/components/vulncontrol/shell";
import { VcProvider } from "@/components/vulncontrol/vc-context";
import { VulnerabilityPage } from "@/components/vulncontrol/vulnerability-page";

export default function VulnerabilityRoute() {
  const params = useParams<{ cveId: string }>();
  return (
    <RequireAuth>
      <main className="h-dvh overflow-hidden">
        <VcProvider initialPage="vulns">
          <VcShell>
            <Suspense fallback={<p className="text-[12px] text-[var(--vc-muted)]">Загрузка карточки…</p>}>
              <VulnerabilityPage cveId={params.cveId} />
            </Suspense>
          </VcShell>
        </VcProvider>
      </main>
    </RequireAuth>
  );
}

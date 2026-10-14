import { RequireAuth } from "@/components/auth/require-auth";
import { VulnControlRoot } from "@/components/vulncontrol/vulncontrol-root";

export default function VulnerabilitiesPage() {
  return (
    <RequireAuth>
      <main className="h-dvh overflow-hidden">
        <VulnControlRoot initialPage="vulns" />
      </main>
    </RequireAuth>
  );
}

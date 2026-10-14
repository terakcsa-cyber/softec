import { RequireAuth } from "../components/auth/require-auth";
import { VulnControlRoot } from "../components/vulncontrol/vulncontrol-root";
import { VocTriageProvider } from "@/lib/voc-triage-context";

export default function Page() {
  return (
    <RequireAuth>
      <VocTriageProvider>
        <main className="h-dvh overflow-hidden">
          <VulnControlRoot />
        </main>
      </VocTriageProvider>
    </RequireAuth>
  );
}


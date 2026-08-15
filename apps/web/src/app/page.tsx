import { RequireAuth } from "../components/auth/require-auth";
import { Dashboard } from "../components/dashboard/dashboard";
import { VocTriageProvider } from "@/lib/voc-triage-context";

export default function Page() {
  return (
    <RequireAuth>
      <VocTriageProvider>
        <main className="h-dvh overflow-hidden px-6 py-6">
          <Dashboard />
        </main>
      </VocTriageProvider>
    </RequireAuth>
  );
}


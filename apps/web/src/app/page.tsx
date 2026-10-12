import { RequireAuth } from "../components/auth/require-auth";
import { Dashboard } from "../components/dashboard/dashboard";
import { VocTriageProvider } from "@/lib/voc-triage-context";

export default function Page() {
  return (
    <RequireAuth>
      <VocTriageProvider>
        <main className="h-dvh overflow-hidden px-3 py-3 sm:px-4 sm:py-4">
          <Dashboard />
        </main>
      </VocTriageProvider>
    </RequireAuth>
  );
}


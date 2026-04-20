import { RequireAuth } from "../components/auth/require-auth";
import { Dashboard } from "../components/dashboard/dashboard";

export default function Page() {
  return (
    <RequireAuth>
      <main className="min-h-screen px-6 py-8">
        <Dashboard />
      </main>
    </RequireAuth>
  );
}


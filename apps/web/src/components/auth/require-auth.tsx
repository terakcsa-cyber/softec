"use client";

import { useAuth } from "@/contexts/auth-context";
import { usePathname, useRouter } from "next/navigation";
import { useEffect } from "react";

export function RequireAuth({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (!loading && !user) router.replace("/login");
    if (!loading && user?.mustChangePassword && pathname !== "/change-password") {
      router.replace("/change-password");
    }
  }, [loading, pathname, user, router]);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-bg text-sm text-muted">
        Загрузка сессии…
      </div>
    );
  }
  if (!user) return null;
  if (user.mustChangePassword && pathname !== "/change-password") return null;
  return <>{children}</>;
}

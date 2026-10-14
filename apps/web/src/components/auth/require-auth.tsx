"use client";

import { AuthLoading } from "@/components/auth/auth-shell";
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

  if (loading) return <AuthLoading message="Загрузка сессии…" />;
  if (!user) return <AuthLoading message="Переход ко входу…" />;
  if (user.mustChangePassword && pathname !== "/change-password") {
    return <AuthLoading message="Нужна смена пароля…" />;
  }
  return <>{children}</>;
}

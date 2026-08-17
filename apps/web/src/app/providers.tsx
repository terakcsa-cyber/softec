"use client";

import { AuthProvider } from "@/contexts/auth-context";
import { ThemeProvider } from "@/contexts/theme-context";
import { LiveFeedNotifier } from "@/components/notifications/live-feed-notifier";
import { QueryClient, QueryClientProvider, keepPreviousData } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { restorePersistedQueries, subscribeQueryPersist } from "@/lib/query-persist";
import { DataRevisionSync } from "@/lib/data-revision";

export function Providers({ children }: { children: React.ReactNode }) {
  const [client] = useState(() => {
    const qc = new QueryClient({
      defaultOptions: {
        queries: {
          refetchOnWindowFocus: false,
          retry: 1,
          gcTime: 30 * 60_000,
          placeholderData: keepPreviousData
        }
      }
    });
    restorePersistedQueries(qc);
    return qc;
  });

  useEffect(() => subscribeQueryPersist(client), [client]);

  return (
    <QueryClientProvider client={client}>
      <ThemeProvider>
        <AuthProvider>
          {children}
          <DataRevisionSync />
          <LiveFeedNotifier />
        </AuthProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}


"use client";

import { AnalyticsView } from "./analytics-view";
import { BduView } from "./bdu-view";
import { DashboardView } from "./dashboard-view";
import { useVc } from "./vc-context";
import { PatchesView } from "./patches-view";
import { ProductsView } from "./products-view";
import { VulnsView } from "./vulns-view";
import { IntegrationsView } from "./integrations-view";
import { ReportsView } from "./reports-view";
import { SettingsView } from "./settings-view";
import { TasksView } from "./tasks-view";

export function VcPageBody() {
  const { page } = useVc();
  if (page === "dashboard") return <DashboardView />;
  if (page === "vulns") return <VulnsView />;
  if (page === "bdu") return <BduView />;
  if (page === "products") return <ProductsView />;
  if (page === "tasks") return <TasksView />;
  if (page === "patches") return <PatchesView />;
  if (page === "analytics") return <AnalyticsView />;
  if (page === "reports") return <ReportsView />;
  if (page === "integrations") return <IntegrationsView />;
  return <SettingsView />;
}

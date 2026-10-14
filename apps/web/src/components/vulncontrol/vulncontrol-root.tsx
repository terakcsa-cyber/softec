"use client";

import { VcPageBody } from "./pages";
import { VcShell } from "./shell";
import { VcProvider, type VcPage } from "./vc-context";

export function VulnControlRoot({ initialPage }: { initialPage?: VcPage }) {
  return (
    <VcProvider initialPage={initialPage}>
      <VcShell>
        <VcPageBody />
      </VcShell>
    </VcProvider>
  );
}

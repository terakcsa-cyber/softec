"use client";

import { ProcessedCheckpoint, processedCardClass } from "./processed-checkpoint";
import { useVocTriage } from "@/lib/voc-triage-context";

export { processedCardClass };

export function VocTriageCheckpoint({
  refKey,
  title,
  compact = false,
  className
}: {
  refKey: string;
  title?: string;
  compact?: boolean;
  className?: string;
}) {
  const { isDone, toggleDone } = useVocTriage();
  const done = isDone(refKey);
  return (
    <ProcessedCheckpoint
      processed={done}
      onToggle={() => toggleDone(refKey, { title })}
      compact={compact}
      className={className}
    />
  );
}

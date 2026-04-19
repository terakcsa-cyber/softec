export type RiskScoreFactors = {
  cvss?: number;
  epss?: number;
  exploitKnown?: boolean;
  mentions?: number;
  freshnessDays?: number;
};

const clamp = (n: number, min: number, max: number) => Math.max(min, Math.min(max, n));

/**
 * v1: rule-based scoring that can later be replaced by ML.
 * Output is 0..100 and is explainable via returned factors.
 */
export function computeUnifiedRiskScoreV1(input: {
  cvss?: number;
  epss?: number;
  exploitKnown?: boolean;
  mentions?: number;
  publishedAt?: Date;
  now?: Date;
}): { score: number; factors: RiskScoreFactors; modelVersion: string } {
  const now = input.now ?? new Date();
  const freshnessDays =
    input.publishedAt != null ? Math.max(0, (now.getTime() - input.publishedAt.getTime()) / 86_400_000) : undefined;

  const cvss = input.cvss;
  const epss = input.epss;
  const exploitKnown = input.exploitKnown ?? false;
  const mentions = input.mentions ?? 0;

  // Normalize to 0..1
  const cvssN = cvss == null ? 0.35 : clamp(cvss / 10, 0, 1);
  const epssN = epss == null ? 0.15 : clamp(epss, 0, 1);
  const exploitN = exploitKnown ? 1 : 0;
  const mentionsN = clamp(Math.log10(mentions + 1) / 4, 0, 1); // 10k+ mentions saturates

  // Freshness: newer -> higher weight; half-life style curve
  const freshnessN =
    freshnessDays == null ? 0.2 : clamp(Math.exp(-freshnessDays / 180), 0, 1); // ~6 month decay

  // Weighted sum -> 0..1
  const combined =
    0.45 * cvssN +
    0.25 * epssN +
    0.15 * exploitN +
    0.08 * freshnessN +
    0.07 * mentionsN;

  // Non-linear boost for exploit-known + high CVSS
  const boost = exploitKnown && cvss != null && cvss >= 9 ? 0.08 : 0;
  const score = Math.round(clamp((combined + boost) * 100, 0, 100));

  return {
    score,
    modelVersion: "rule_v1",
    factors: {
      cvss,
      epss,
      exploitKnown,
      mentions,
      freshnessDays: freshnessDays == null ? undefined : Math.round(freshnessDays)
    }
  };
}


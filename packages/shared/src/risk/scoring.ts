export type RiskScoreFactors = {
  cvss?: number;
  epss?: number;
  exploitKnown?: boolean;
  vckevOnly?: boolean;
  vulncheckKev?: boolean;
  epssSpike?: boolean;
  hasPoc?: boolean;
  hasPublicExploit?: boolean;
  mentions?: number;
  tgMentions24h?: number;
  freshnessDays?: number;
};

const clamp = (n: number, min: number, max: number) => Math.max(min, Math.min(max, n));

function exploitExposureN(input: {
  exploitKnown?: boolean;
  vckevOnly?: boolean;
  vulncheckKev?: boolean;
  hasPublicExploit?: boolean;
  hasPoc?: boolean;
}): number {
  if (input.exploitKnown) return 1;
  if (input.vckevOnly) return 0.92;
  if (input.hasPublicExploit) return 0.88;
  if (input.vulncheckKev) return 0.8;
  if (input.hasPoc) return 0.55;
  return 0;
}

/**
 * v1: rule-based scoring (legacy; CISA KEV only for exploit signal).
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

/**
 * v2: exploit intel aware (VulnCheck KEV, EPSS spike, PoC, TG mentions).
 */
export function computeUnifiedRiskScoreV2(input: {
  cvss?: number;
  epss?: number;
  exploitKnown?: boolean;
  vckevOnly?: boolean;
  vulncheckKev?: boolean;
  epssSpike?: boolean;
  hasPoc?: boolean;
  hasPublicExploit?: boolean;
  mentions?: number;
  tgMentions24h?: number;
  publishedAt?: Date;
  now?: Date;
}): { score: number; factors: RiskScoreFactors; modelVersion: string } {
  const now = input.now ?? new Date();
  const freshnessDays =
    input.publishedAt != null ? Math.max(0, (now.getTime() - input.publishedAt.getTime()) / 86_400_000) : undefined;

  const cvss = input.cvss;
  const epss = input.epss;
  const exploitKnown = input.exploitKnown ?? false;
  const vckevOnly = input.vckevOnly ?? false;
  const vulncheckKev = input.vulncheckKev ?? false;
  const epssSpike = input.epssSpike ?? false;
  const hasPoc = input.hasPoc ?? false;
  const hasPublicExploit = input.hasPublicExploit ?? false;
  const mentions = (input.mentions ?? 0) + (input.tgMentions24h ?? 0);

  const cvssN = cvss == null ? 0.35 : clamp(cvss / 10, 0, 1);
  const epssN = epss == null ? 0.15 : clamp(epss, 0, 1);
  const exploitN = exploitExposureN({ exploitKnown, vckevOnly, vulncheckKev, hasPublicExploit, hasPoc });
  const spikeN = epssSpike ? 1 : 0;
  const mentionsN = clamp(Math.log10(mentions + 1) / 4, 0, 1);
  const freshnessN =
    freshnessDays == null ? 0.2 : clamp(Math.exp(-freshnessDays / 180), 0, 1);

  const combined =
    0.36 * cvssN +
    0.22 * epssN +
    0.18 * exploitN +
    0.06 * spikeN +
    0.08 * freshnessN +
    0.1 * mentionsN;

  const boost =
    (exploitKnown || vckevOnly) && cvss != null && cvss >= 9
      ? 0.08
      : epssSpike && exploitN >= 0.55
        ? 0.05
        : 0;
  const score = Math.round(clamp((combined + boost) * 100, 0, 100));

  return {
    score,
    modelVersion: "rule_v2",
    factors: {
      cvss,
      epss,
      exploitKnown,
      vckevOnly,
      vulncheckKev,
      epssSpike,
      hasPoc,
      hasPublicExploit,
      mentions,
      tgMentions24h: input.tgMentions24h,
      freshnessDays: freshnessDays == null ? undefined : Math.round(freshnessDays)
    }
  };
}

/** Default scorer for new runs. */
export const computeUnifiedRiskScore = computeUnifiedRiskScoreV2;

/**
 * KnowThankYew Structured Handoff Protocol Specification
 * Types, Constants & Schema Validator
 */

export type DestinationToolId =
  | 'bill-of-rights-bot'
  | 'lease-audit'
  | 'care-check'
  | 'warranty-watch'
  | 'paystub-check';

export type TrapCategory =
  | 'AUTO_RENEWAL'
  | 'ARBITRATION'
  | 'UNILATERAL_CHANGE'
  | 'SURVEILLANCE'
  | 'WARRANTY_DISCLAIMER';

export type Severity = 'CRITICAL' | 'WARNING' | 'INFO';

export interface DiscoveredLegalLink {
  url: string;
  title: string;
  category: 'TERMS' | 'PRIVACY' | 'BILLING' | 'ARBITRATION';
  source?: 'DOM_ANCHOR' | 'WELL_KNOWN';
}

export interface KtyHandoffFinding {
  ruleId: string;
  title: string;
  category: TrapCategory;
  severity: Severity;
  statuteCode: string;
  statuteTitle: string;
  matchedSnippet: string;
  explanation: string;
  recommendation: string;
}

export interface KtyHandoffPayload {
  version: '1.0';
  originApp: 'knowthankyew-extension';
  domain: string;
  scanTimestamp: string;
  riskScore: number;
  summary: {
    critical: number;
    warning: number;
    info: number;
  };
  findings: KtyHandoffFinding[];
  primaryLegalLink: DiscoveredLegalLink | null;
  targetTool: DestinationToolId;
}

export const KTY_HANDOFF_SESSION_KEY = 'kty_handoff';

const VALID_CATEGORIES = new Set<string>([
  'AUTO_RENEWAL',
  'ARBITRATION',
  'UNILATERAL_CHANGE',
  'SURVEILLANCE',
  'WARRANTY_DISCLAIMER',
]);

const VALID_SEVERITIES = new Set<string>(['CRITICAL', 'WARNING', 'INFO']);

const VALID_TOOLS = new Set<string>([
  'bill-of-rights-bot',
  'lease-audit',
  'care-check',
  'warranty-watch',
  'paystub-check',
]);

/**
 * Fail-closed runtime validator for incoming KtyHandoffPayload envelopes.
 */
export function validateHandoffPayload(payload: unknown): payload is KtyHandoffPayload {
  if (!payload || typeof payload !== 'object') return false;
  const p = payload as Record<string, any>;

  if (p.version !== '1.0') return false;
  if (p.originApp !== 'knowthankyew-extension') return false;
  if (typeof p.domain !== 'string' || p.domain.trim().length === 0) return false;
  if (typeof p.scanTimestamp !== 'string' || Number.isNaN(Date.parse(p.scanTimestamp))) return false;
  if (typeof p.riskScore !== 'number' || p.riskScore < 0 || p.riskScore > 100) return false;

  if (!p.summary || typeof p.summary !== 'object') return false;
  if (
    typeof p.summary.critical !== 'number' ||
    typeof p.summary.warning !== 'number' ||
    typeof p.summary.info !== 'number'
  ) {
    return false;
  }

  if (!Array.isArray(p.findings)) return false;
  for (const f of p.findings) {
    if (!f || typeof f !== 'object') return false;
    if (typeof f.ruleId !== 'string' || f.ruleId.trim().length === 0) return false;
    if (typeof f.title !== 'string' || f.title.trim().length === 0) return false;
    if (!VALID_CATEGORIES.has(f.category)) return false;
    if (!VALID_SEVERITIES.has(f.severity)) return false;
    if (typeof f.statuteCode !== 'string') return false;
    if (typeof f.statuteTitle !== 'string') return false;
    if (typeof f.matchedSnippet !== 'string') return false;
    if (typeof f.explanation !== 'string') return false;
    if (typeof f.recommendation !== 'string') return false;
  }

  if (typeof p.targetTool !== 'string' || !VALID_TOOLS.has(p.targetTool)) {
    return false;
  }

  if (p.primaryLegalLink !== null) {
    if (!p.primaryLegalLink || typeof p.primaryLegalLink !== 'object') return false;
    if (typeof p.primaryLegalLink.url !== 'string') return false;
    if (typeof p.primaryLegalLink.title !== 'string') return false;
  }

  return true;
}

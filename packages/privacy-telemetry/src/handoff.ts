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
export const KTY_HANDOFF_HASH_PARAM = 'kty_handoff';

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(encoded: string): Uint8Array | null {
  if (!encoded || !/^[A-Za-z0-9_-]+$/.test(encoded)) return null;
  const normalized = encoded.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (normalized.length % 4)) % 4;
  const padded = normalized + '='.repeat(padLen);
  try {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return null;
  }
}

/**
 * Encodes a validated KTY handoff payload into a URL-safe base64url token
 * for zero-egress URL fragment delivery (#kty_handoff=...).
 */
export function encodeHandoffFragmentValue(payload: KtyHandoffPayload): string | null {
  if (!validateHandoffPayload(payload)) return null;
  try {
    const json = JSON.stringify(payload);
    const bytes = new TextEncoder().encode(json);
    return toBase64Url(bytes);
  } catch {
    return null;
  }
}

/**
 * Decodes and validates a base64url-encoded KTY handoff fragment token.
 * Fails closed on malformed encoding, JSON syntax errors, or schema violations.
 */
export function decodeHandoffFragmentValue(encoded: string): KtyHandoffPayload | null {
  const bytes = fromBase64Url(encoded);
  if (!bytes) return null;
  try {
    const json = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const parsed = JSON.parse(json);
    return validateHandoffPayload(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * Extracts and validates a KTY handoff payload from a URL hash string (e.g. #kty_handoff=...).
 */
export function extractHandoffFromHash(
  hash: string,
  expectedTargetTool?: string
): { payload: KtyHandoffPayload | null; hasHandoffParam: boolean; remainingHash: string } {
  if (typeof hash !== 'string' || hash.length === 0) {
    return { payload: null, hasHandoffParam: false, remainingHash: '' };
  }
  const stripped = hash.startsWith('#') ? hash.slice(1) : hash;
  if (!stripped) {
    return { payload: null, hasHandoffParam: false, remainingHash: '' };
  }

  const parts = stripped.split('&').filter(Boolean);
  let rawToken: string | null = null;
  const keptParts: string[] = [];

  for (const part of parts) {
    const eqIdx = part.indexOf('=');
    const key = eqIdx === -1 ? part : part.slice(0, eqIdx);
    if (key === KTY_HANDOFF_HASH_PARAM) {
      if (rawToken === null && eqIdx !== -1) {
        rawToken = part.slice(eqIdx + 1);
      }
      continue;
    }
    keptParts.push(part);
  }

  if (!stripped.split('&').some((p) => p === KTY_HANDOFF_HASH_PARAM || p.startsWith(`${KTY_HANDOFF_HASH_PARAM}=`))) {
    return { payload: null, hasHandoffParam: false, remainingHash: hash };
  }

  const remainingHash = keptParts.length > 0 ? `#${keptParts.join('&')}` : '';
  if (!rawToken) {
    return { payload: null, hasHandoffParam: true, remainingHash };
  }

  const decoded = decodeHandoffFragmentValue(rawToken);
  if (!decoded) {
    return { payload: null, hasHandoffParam: true, remainingHash };
  }
  if (expectedTargetTool && decoded.targetTool !== expectedTargetTool) {
    return { payload: null, hasHandoffParam: true, remainingHash };
  }

  return { payload: decoded, hasHandoffParam: true, remainingHash };
}

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
    typeof p.summary.info !== 'number' ||
    !Number.isFinite(p.summary.critical) ||
    !Number.isFinite(p.summary.warning) ||
    !Number.isFinite(p.summary.info) ||
    !Number.isInteger(p.summary.critical) ||
    !Number.isInteger(p.summary.warning) ||
    !Number.isInteger(p.summary.info) ||
    p.summary.critical < 0 ||
    p.summary.warning < 0 ||
    p.summary.info < 0
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

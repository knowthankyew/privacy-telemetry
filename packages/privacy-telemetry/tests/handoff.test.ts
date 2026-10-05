import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  validateHandoffPayload,
  KTY_HANDOFF_SESSION_KEY,
  KtyHandoffPayload,
} from '../src/handoff.js';

describe('Handoff Schema Validation & Protocol Specification', () => {
  const sampleValidPayload: KtyHandoffPayload = {
    version: '1.0',
    originApp: 'knowthankyew-extension',
    domain: 'predatory-stream.com',
    scanTimestamp: '2026-10-04T12:00:00.000Z',
    riskScore: 70,
    summary: { critical: 2, warning: 0, info: 0 },
    findings: [
      {
        ruleId: 'AR-001',
        title: 'Negative Option Renewal',
        category: 'AUTO_RENEWAL',
        severity: 'CRITICAL',
        statuteCode: '16 CFR Part 425',
        statuteTitle: 'Click-to-Cancel',
        matchedSnippet: 'Renews every month until cancelled.',
        explanation: 'Subscription auto-renews monthly without affirmative disclosure.',
        recommendation: 'Request immediate cancellation confirmation.',
      },
    ],
    primaryLegalLink: {
      url: 'https://predatory-stream.com/terms',
      title: 'Terms of Use',
      category: 'TERMS',
      source: 'DOM_ANCHOR',
    },
    targetTool: 'bill-of-rights-bot',
  };

  it('validates a legitimate KTY handoff payload', () => {
    expect(validateHandoffPayload(sampleValidPayload)).toBe(true);
  });

  it('rejects null, non-objects, and invalid types', () => {
    expect(validateHandoffPayload(null)).toBe(false);
    expect(validateHandoffPayload(undefined)).toBe(false);
    expect(validateHandoffPayload('payload')).toBe(false);
    expect(validateHandoffPayload(123)).toBe(false);
  });

  it('rejects envelope with wrong version or originApp', () => {
    expect(validateHandoffPayload({ ...sampleValidPayload, version: '2.0' })).toBe(false);
    expect(validateHandoffPayload({ ...sampleValidPayload, originApp: 'malicious-bot' })).toBe(false);
  });

  it('rejects envelope with invalid domain, timestamp, or riskScore', () => {
    expect(validateHandoffPayload({ ...sampleValidPayload, domain: '' })).toBe(false);
    expect(validateHandoffPayload({ ...sampleValidPayload, scanTimestamp: 'invalid-date' })).toBe(false);
    expect(validateHandoffPayload({ ...sampleValidPayload, riskScore: -1 })).toBe(false);
    expect(validateHandoffPayload({ ...sampleValidPayload, riskScore: 101 })).toBe(false);
  });

  it('rejects unrecognized destination tools', () => {
    expect(validateHandoffPayload({ ...sampleValidPayload, targetTool: 'unknown-tool' as any })).toBe(false);
  });

  it('rejects invalid categories or severities in findings', () => {
    const invalidCategory = {
      ...sampleValidPayload,
      findings: [{ ...sampleValidPayload.findings[0], category: 'UNKNOWN_CATEGORY' as any }],
    };
    expect(validateHandoffPayload(invalidCategory)).toBe(false);

    const invalidSeverity = {
      ...sampleValidPayload,
      findings: [{ ...sampleValidPayload.findings[0], severity: 'FATAL' as any }],
    };
    expect(validateHandoffPayload(invalidSeverity)).toBe(false);
  });
});

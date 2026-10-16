import { describe, it, expect } from 'vitest';
import {
  auditZeroEgress,
  auditAllowlistParity,
  auditDynamicClaims,
  auditHandoffProtocol,
  auditVocabulary,
  auditCentralPackageManagement,
  auditPortfolioMasterBrief,
} from '../../../scripts/audit-claims.mjs';

describe('Privacy Telemetry Claims & Invariant Linter Suite', () => {
  it('enforces zero-egress air-gap and default memory_only invariants', () => {
    const errors: string[] = [];
    auditZeroEgress(errors);
    expect(errors).toEqual([]);
  });

  it('enforces telemetry allowlist integrity and redaction parity between TS and .NET', () => {
    const errors: string[] = [];
    auditAllowlistParity(errors);
    expect(errors).toEqual([]);
  });

  it('enforces single source of truth for honest dynamic privacy claims', () => {
    const errors: string[] = [];
    auditDynamicClaims(errors);
    expect(errors).toEqual([]);
  });

  it('enforces cross-engine structured handoff protocol tool and category coverage', () => {
    const errors: string[] = [];
    auditHandoffProtocol(errors);
    expect(errors).toEqual([]);
  });

  it('enforces vocabulary guardrails eliminating unprovable marketing claims', () => {
    const errors: string[] = [];
    auditVocabulary(errors);
    expect(errors).toEqual([]);
  });

  it('enforces Central Package Management (CPM) and fail-closed NuGet audit configuration', () => {
    const errors: string[] = [];
    auditCentralPackageManagement(errors);
    expect(errors).toEqual([]);
  });

  it('enforces Portfolio Master Brief test count parity', () => {
    const errors: string[] = [];
    const checked = auditPortfolioMasterBrief(errors, { requireBrief: false });
    expect(errors).toEqual([]);
    expect(checked).toBe(true);

    // Negative test: brief required but missing
    const missingErrors: string[] = [];
    const missingChecked = auditPortfolioMasterBrief(missingErrors, {
      requireBrief: true,
      overrideBriefPath: '/non-existent/path/BRIEF.md',
    });
    expect(missingChecked).toBe(false);
    expect(missingErrors.length).toBeGreaterThan(0);
    expect(missingErrors[0]).toContain('not found but required via --require-brief');
  });
});

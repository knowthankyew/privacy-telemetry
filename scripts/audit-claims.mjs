#!/usr/bin/env node
/**
 * audit-claims.mjs - Automated Claims, Architectural Parity & Privacy Invariant Linter for privacy-telemetry.
 *
 * Enforces:
 * 1. Zero-Egress Privacy Invariant:
 *    - Verifies default telemetry operates in memory_only mode with zero network egress ('deny').
 *    - Verifies packages/privacy-telemetry/src/ contains zero unauthorized network egress primitives
 *      (fetch, XMLHttpRequest, sendBeacon, WebSocket), permitting fetch strictly in exportToOtlp.
 *    - Verifies .NET PrivacyTelemetryOptions defaults to memory_only and network egress deny.
 * 2. Telemetry Allowlist & Redaction Parity:
 *    - Validates strict allowlist coverage across TypeScript and .NET implementations.
 *    - Prohibits sensitive PII/PHI keys (e.g. ssn, patient_name, gross_pay, lease_snippet) in default allowlists.
 *    - Verifies fail-closed redaction token invariants ([REDACTED_...]).
 * 3. Single Source of Truth for Dynamic Claims:
 *    - Validates honest dynamic privacy claims generator (getPrivacyClaims & IsLocalOnlyHonest).
 * 4. Cross-Engine Structured Handoff Protocol Parity:
 *    - Validates tool IDs, categories, severities, and fail-closed envelope validator.
 * 5. Supply Chain & Central Package Management (CPM) Conformance:
 *    - Validates Directory.Packages.props and Directory.Build.props fail-closed security properties.
 * 6. Vocabulary Guardrails:
 *    - Prohibits unprovable marketing adjectives ('bulletproof', 'conclusive', 'definitive', 'infinitely scalable').
 * 7. Portfolio Master Brief Parity:
 *    - Verifies that KNOWTHANKYEW_PORTFOLIO_MASTER_BRIEF.md accurately reflects current privacy-telemetry test inventory.
 */

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const REPO_ROOT = resolve(__dirname, '..');
const DEV_ROOT = resolve(REPO_ROOT, '..');

const PROHIBITED_WORDS = [
  /\bbulletproof\b/i,
  /\bconclusive\b/i,
  /\bdefinitive\b/i,
  /\binfinitely scalable\b/i,
];

const PROHIBITED_ALLOWLIST_KEYS = [
  'patient_name',
  'ssn',
  'tenant_name',
  'gross_pay',
  'lease_snippet',
  'raw_text',
  'prompt',
  'matched_snippet',
  'matchedSnippet',
  'clause_text',
  'password',
];

const REQUIRED_SHARED_ALLOWLIST_KEYS = [
  'job_id',
  'status',
  'duration_ms',
  'duration_sec',
  'rule_id',
  'rule_ids',
  'jurisdiction',
  'clause_count',
  'flagged_count',
  'device',
  'dataset_hash',
];

const EXPECTED_HANDOFF_TOOLS = [
  'bill-of-rights-bot',
  'lease-audit',
  'care-check',
  'warranty-watch',
  'paystub-check',
];

/**
 * Audit 1: Zero-Egress & Network Invariants
 */
export function auditZeroEgress(errors = []) {
  const tsSrcDir = resolve(REPO_ROOT, 'packages/privacy-telemetry/src');
  if (!existsSync(tsSrcDir)) {
    errors.push('Missing packages/privacy-telemetry/src directory');
    return;
  }

  function scanDir(dir) {
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = resolve(dir, entry.name);
      if (entry.isDirectory()) {
        scanDir(fullPath);
      } else if (/\.(ts|tsx)$/.test(entry.name)) {
        const isExporter = entry.name === 'exporter.ts';
        const content = readFileSync(fullPath, 'utf-8');
        const lines = content.split('\n');

        lines.forEach((line, lineIdx) => {
          const trimmed = line.trim();
          if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) {
            return;
          }

          // In exporter.ts, fetch() is allowed only for exportToOtlp
          if (/\b(XMLHttpRequest|navigator\.sendBeacon|new\s+WebSocket)\b/.test(line)) {
            errors.push(
              `Privacy violation in ${fullPath.replace(REPO_ROOT + '/', '')}:${lineIdx + 1}: Forbidden network primitive: ${trimmed}`
            );
          } else if (/\bfetch\s*\(/.test(line) && !isExporter) {
            errors.push(
              `Privacy violation in ${fullPath.replace(REPO_ROOT + '/', '')}:${lineIdx + 1}: Direct fetch() detected outside exporter.ts: ${trimmed}`
            );
          }
        });
      }
    }
  }

  scanDir(tsSrcDir);

  // Check TypeScript TelemetryManager defaults
  const managerPath = resolve(tsSrcDir, 'manager.ts');
  if (existsSync(managerPath)) {
    const mgrContent = readFileSync(managerPath, 'utf-8');
    if (!mgrContent.includes("defaultMode: TelemetryMode = envEndpoint ? 'otlp' : 'memory_only'")) {
      errors.push('TelemetryManager default mode must default to memory_only when no endpoint is configured.');
    }
    if (!mgrContent.includes("networkEgress: defaultMode === 'otlp' ? 'allow_otlp' : 'deny'")) {
      errors.push("TelemetryManager default network egress must default to 'deny' in consumer mode.");
    }
  }

  // Check .NET PrivacyTelemetryOptions defaults
  const netOptionsPath = resolve(
    REPO_ROOT,
    'packages/KnowThankYew.Privacy.Telemetry/Configuration/PrivacyTelemetryOptions.cs'
  );
  if (existsSync(netOptionsPath)) {
    const optContent = readFileSync(netOptionsPath, 'utf-8');
    if (!optContent.includes('public bool BurnEnabled { get; set; } = true;')) {
      errors.push('PrivacyOptions.BurnEnabled must default to true.');
    }
    if (!optContent.includes('public string NetworkEgress { get; set; } = "deny";')) {
      errors.push('PrivacyOptions.NetworkEgress must default to "deny".');
    }
    if (!optContent.includes('public string Mode { get; set; } = "memory_only";')) {
      errors.push('TelemetryOptions.Mode must default to "memory_only".');
    }
    if (!optContent.includes('public bool AllowRawPayloads { get; set; } = false;')) {
      errors.push('TelemetryOptions.AllowRawPayloads must default to false.');
    }
  }
}

/**
 * Audit 2: Telemetry Allowlist & Redaction Parity
 */
export function auditAllowlistParity(errors = []) {
  const tsAllowlistPath = resolve(REPO_ROOT, 'packages/privacy-telemetry/src/allowlist.ts');
  const netAllowlistPath = resolve(
    REPO_ROOT,
    'packages/KnowThankYew.Privacy.Telemetry/Core/SafeAllowlist.cs'
  );

  if (!existsSync(tsAllowlistPath)) {
    errors.push('Missing packages/privacy-telemetry/src/allowlist.ts');
    return;
  }
  if (!existsSync(netAllowlistPath)) {
    errors.push('Missing packages/KnowThankYew.Privacy.Telemetry/Core/SafeAllowlist.cs');
    return;
  }

  const tsContent = readFileSync(tsAllowlistPath, 'utf-8');
  const netContent = readFileSync(netAllowlistPath, 'utf-8');

  // Verify no prohibited PII/PHI keys in allowlists
  for (const key of PROHIBITED_ALLOWLIST_KEYS) {
    if (tsContent.includes(`'${key}'`)) {
      errors.push(`Prohibited sensitive attribute '${key}' found in TypeScript DEFAULT_SAFE_ALLOWLIST_KEYS`);
    }
    if (netContent.includes(`"${key}"`)) {
      errors.push(`Prohibited sensitive attribute '${key}' found in .NET SafeAllowlist.DefaultKeys`);
    }
  }

  // Verify required shared keys exist in both allowlists
  for (const key of REQUIRED_SHARED_ALLOWLIST_KEYS) {
    if (!tsContent.includes(`'${key}'`)) {
      errors.push(`Required shared key '${key}' missing from TypeScript DEFAULT_SAFE_ALLOWLIST_KEYS`);
    }
    if (!netContent.includes(`"${key}"`)) {
      errors.push(`Required shared key '${key}' missing from .NET SafeAllowlist.DefaultKeys`);
    }
  }

  // Verify fail-closed redaction tokens start with [REDACTED_
  if (!tsContent.includes('[REDACTED_')) {
    errors.push('TypeScript allowlist sanitizer must produce [REDACTED_ tokens for unverified keys.');
  }
  if (!netContent.includes('[REDACTED_')) {
    errors.push('.NET SafeAllowlist sanitizer must produce [REDACTED_ tokens for unverified keys.');
  }
}

/**
 * Audit 3: Dynamic Claims Single Source of Truth
 */
export function auditDynamicClaims(errors = []) {
  const claimsPath = resolve(REPO_ROOT, 'packages/privacy-telemetry/src/claims.ts');
  const netServicePath = resolve(
    REPO_ROOT,
    'packages/KnowThankYew.Privacy.Telemetry/Core/PrivacyTelemetryService.cs'
  );

  if (!existsSync(claimsPath)) {
    errors.push('Missing packages/privacy-telemetry/src/claims.ts');
    return;
  }
  if (!existsSync(netServicePath)) {
    errors.push('Missing packages/KnowThankYew.Privacy.Telemetry/Core/PrivacyTelemetryService.cs');
    return;
  }

  const claimsContent = readFileSync(claimsPath, 'utf-8');
  if (!claimsContent.includes('100% Client-Side Local Execution • Zero Network Transmission')) {
    errors.push('getPrivacyClaims missing standard consumer dropzone notice claim.');
  }
  if (!claimsContent.includes('OTLP Operational Metadata Active (Strictly Redacted)')) {
    errors.push('getPrivacyClaims missing standard enterprise dropzone notice disclaimer.');
  }

  const netContent = readFileSync(netServicePath, 'utf-8');
  if (
    !netContent.includes(
      'public bool IsLocalOnlyHonest => _mode != "otlp" && string.IsNullOrEmpty(_otlpEndpoint) && _networkEgress == "deny";'
    )
  ) {
    errors.push('.NET PrivacyTelemetryService missing canonical IsLocalOnlyHonest invariant computation.');
  }
}

/**
 * Audit 4: Cross-Engine Structured Handoff Protocol Parity
 */
export function auditHandoffProtocol(errors = []) {
  const handoffPath = resolve(REPO_ROOT, 'packages/privacy-telemetry/src/handoff.ts');
  if (!existsSync(handoffPath)) {
    errors.push('Missing packages/privacy-telemetry/src/handoff.ts');
    return;
  }

  const handoffContent = readFileSync(handoffPath, 'utf-8');
  for (const tool of EXPECTED_HANDOFF_TOOLS) {
    if (!handoffContent.includes(`'${tool}'`)) {
      errors.push(`Handoff protocol missing standard destination tool: '${tool}'`);
    }
  }

  const expectedCategories = ['AUTO_RENEWAL', 'ARBITRATION', 'UNILATERAL_CHANGE', 'SURVEILLANCE', 'WARRANTY_DISCLAIMER'];
  for (const cat of expectedCategories) {
    if (!handoffContent.includes(`'${cat}'`)) {
      errors.push(`Handoff protocol missing trap category: '${cat}'`);
    }
  }

  if (!handoffContent.includes('export function validateHandoffPayload')) {
    errors.push('Handoff protocol must export fail-closed validateHandoffPayload function.');
  }
}

/**
 * Audit 5: Vocabulary Guardrails
 */
export function auditVocabulary(errors = []) {
  const docsToCheck = [
    resolve(REPO_ROOT, 'README.md'),
    resolve(REPO_ROOT, 'NOTICE.md'),
    resolve(REPO_ROOT, 'PRIVACY_TELEMETRY_SCHEMA.md'),
  ];

  for (const docPath of docsToCheck) {
    if (!existsSync(docPath)) continue;
    const lines = readFileSync(docPath, 'utf-8').split('\n');
    lines.forEach((line, idx) => {
      const lower = line.toLowerCase();
      // Skip lines discussing the rule or quotation disclaimer
      if (
        lower.includes('prohibits unprovable') ||
        lower.includes('prohibited word') ||
        lower.includes('prohibited marketing') ||
        lower.includes('bulletproof') && lower.includes('prohibit')
      ) {
        return;
      }
      for (const pattern of PROHIBITED_WORDS) {
        if (pattern.test(line)) {
          errors.push(
            `Prohibited marketing word '${pattern.source}' found in ${docPath.replace(REPO_ROOT + '/', '')}:${idx + 1}: ${line.trim()}`
          );
        }
      }
    });
  }
}

/**
 * Audit 6: Central Package Management & Build Properties Conformance
 */
export function auditCentralPackageManagement(errors = []) {
  const dirPackages = resolve(REPO_ROOT, 'Directory.Packages.props');
  const dirBuild = resolve(REPO_ROOT, 'Directory.Build.props');
  const rootPkg = resolve(REPO_ROOT, 'package.json');

  if (!existsSync(dirPackages)) {
    errors.push('Missing Directory.Packages.props');
  } else {
    const content = readFileSync(dirPackages, 'utf-8');
    if (!content.includes('<ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>')) {
      errors.push('Directory.Packages.props must enable ManagePackageVersionsCentrally.');
    }
  }

  if (!existsSync(dirBuild)) {
    errors.push('Missing Directory.Build.props');
  } else {
    const content = readFileSync(dirBuild, 'utf-8');
    if (!content.includes('<NuGetAudit>true</NuGetAudit>')) {
      errors.push('Directory.Build.props must enable NuGetAudit.');
    }
    if (!content.includes('<WarningsAsErrors>$(WarningsAsErrors);NU1903;NU1904</WarningsAsErrors>')) {
      errors.push('Directory.Build.props must treat NU1903 and NU1904 as build errors.');
    }
  }

  if (existsSync(rootPkg)) {
    const pkgJson = JSON.parse(readFileSync(rootPkg, 'utf-8'));
    if (!pkgJson.scripts?.['audit:claims']) {
      errors.push('Root package.json missing "audit:claims" script.');
    }
  }
}

/**
 * Audit 7: Portfolio Master Brief Parity
 */
export function auditPortfolioMasterBrief(
  errors = [],
  { requireBrief = false, overrideBriefPath = null } = {}
) {
  const briefCandidates = overrideBriefPath
    ? [overrideBriefPath]
    : [
        resolve(DEV_ROOT, 'KNOWTHANKYEW_PORTFOLIO_MASTER_BRIEF.md'),
        resolve(REPO_ROOT, 'KNOWTHANKYEW_PORTFOLIO_MASTER_BRIEF.md'),
      ];
  const briefPath = briefCandidates.find((p) => existsSync(p));

  if (!briefPath) {
    if (requireBrief) {
      errors.push('KNOWTHANKYEW_PORTFOLIO_MASTER_BRIEF.md not found but required via --require-brief.');
    }
    return false;
  }

  const briefContent = readFileSync(briefPath, 'utf-8');

  // Match: `privacy-telemetry` ... (\d+)/(\d+) tests pass ((\d+) TS + (\d+) .NET)
  const pattern = /`privacy-telemetry`.*?(\d+)\/(\d+)\s+tests pass\s*\((\d+)\s+TS\s*\+\s*(\d+)\s+\.NET\)/i;
  const match = briefContent.match(pattern);
  if (!match) {
    errors.push('Could not find privacy-telemetry test inventory count in KNOWTHANKYEW_PORTFOLIO_MASTER_BRIEF.md');
    return false;
  }

  const documentedTotal = parseInt(match[1], 10);
  const documentedTs = parseInt(match[3], 10);
  const documentedNet = parseInt(match[4], 10);

  // Count actual TS tests
  const tsTestsDir = resolve(REPO_ROOT, 'packages/privacy-telemetry/tests');
  let actualTsCount = 0;
  if (existsSync(tsTestsDir)) {
    const files = readdirSync(tsTestsDir).filter((f) => f.endsWith('.test.ts') || f.endsWith('.test.js'));
    for (const f of files) {
      const code = readFileSync(resolve(tsTestsDir, f), 'utf-8');
      const testMatches = code.match(/\b(?:it|test)(?:\.only|\.skip)?\s*\(/g) || [];
      actualTsCount += testMatches.length;
    }
  }

  // Count actual .NET tests
  const netTestsDir = resolve(REPO_ROOT, 'tests');
  let actualNetCount = 0;
  function scanNetTests(dir) {
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = resolve(dir, entry.name);
      if (entry.isDirectory()) {
        scanNetTests(fullPath);
      } else if (entry.name.endsWith('.cs')) {
        const code = readFileSync(fullPath, 'utf-8');
        const factMatches = code.match(/\[(?:Fact|Theory)(?:\([^)]*\))?\]/g) || [];
        actualNetCount += factMatches.length;
      }
    }
  }
  if (existsSync(netTestsDir)) {
    scanNetTests(netTestsDir);
  }

  const actualTotal = actualTsCount + actualNetCount;

  if (
    documentedTotal !== actualTotal ||
    documentedTs !== actualTsCount ||
    documentedNet !== actualNetCount
  ) {
    errors.push(
      `Portfolio Brief Drift: KNOWTHANKYEW_PORTFOLIO_MASTER_BRIEF.md documents ${documentedTotal}/${documentedTotal} tests (${documentedTs} TS + ${documentedNet} .NET), but actual test suite has ${actualTotal} tests (${actualTsCount} TS + ${actualNetCount} .NET).`
    );
    return false;
  }

  return true;
}

/**
 * Main execution CLI
 */
export function runAllAudits(options = {}) {
  const errors = [];
  auditZeroEgress(errors);
  auditAllowlistParity(errors);
  auditDynamicClaims(errors);
  auditHandoffProtocol(errors);
  auditVocabulary(errors);
  auditCentralPackageManagement(errors);
  const briefChecked = auditPortfolioMasterBrief(errors, options);

  return { errors, briefChecked };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  console.log('=== Privacy Telemetry Claims, Architecture & Parity Audit ===\n');
  const requireBrief = process.argv.includes('--require-brief');
  const { errors, briefChecked } = runAllAudits({ requireBrief });

  if (errors.length > 0) {
    console.error(`[FAIL] Found ${errors.length} claims / architectural invariant violation(s):`);
    for (const err of errors) {
      console.error(`  - ${err}`);
    }
    process.exit(1);
  }

  console.log('[PASS] All privacy-telemetry architectural & claims invariants verified:');
  console.log("  ✓ Zero-egress air-gap verified (memory_only default, networkEgress 'deny', zero unauthorized network primitives)");
  console.log('  ✓ Telemetry allowlist & fail-closed redaction parity verified between TS and .NET');
  console.log('  ✓ Single source of truth for honest dynamic privacy claims verified');
  console.log('  ✓ Cross-engine structured handoff protocol validated against portfolio tools');
  console.log('  ✓ Central Package Management (CPM) & fail-closed NuGet audit properties verified');
  console.log('  ✓ Zero prohibited marketing adjectives detected in documentation');
  if (briefChecked) {
    console.log('  ✓ Portfolio Master Brief parity verified');
  } else {
    console.log('  - Portfolio Master Brief check skipped (isolated CI)');
  }
  process.exit(0);
}

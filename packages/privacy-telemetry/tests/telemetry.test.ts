import { describe, it, expect, beforeEach } from 'vitest';
import v8 from 'node:v8';
import vm from 'node:vm';
import {
  TelemetryManager,
  MemoryExporter,
  createAllowlistSanitizer,
  getPrivacyClaims,
  DEFAULT_SAFE_ALLOWLIST_KEYS,
  sha256Hex,
  exportToOtlp,
  scrubRecordEntries,
} from '../src/index.js';
import {
  REDACTED_NOT_ALLOWLISTED,
  REDACTED_SENSITIVE_VALUE,
  REDACTED_UNALLOWLISTED_KEY,
  containsSensitivePattern,
} from '../src/allowlist.js';
import { runCoreRealmScenario } from './realm-worker.js';

describe('@knowthankyew/privacy-telemetry Core Invariants', () => {
  let telemetry: TelemetryManager;

  beforeEach(() => {
    telemetry = new TelemetryManager(
      { mode: 'memory_only', otlpEndpoint: null },
      ['domain_custom_key', 'cpt_code', 'gross_pay', 'lemon_law_qualifying', 'clause_type'],
      { domain_custom_key: ['hmac:0123456789abcdef', 'custom_value'] }
    );
  });

  it('Invariant 1: Default mode is memory_only with zero network egress', () => {
    const config = telemetry.getConfig();
    expect(config.mode).toBe('memory_only');
    expect(config.networkEgress).toBe('deny');
    expect(config.otlpEndpoint).toBeNull();

    const report = telemetry.getPrivacyAuditReport();
    expect(report.isLocalOnlyHonest).toBe(true);
    expect(report.telemetryMode).toBe('memory_only');
    expect(report.networkEgress).toBe('deny');
  });

  it('Invariant 2: Strict allowlist redacts unknown attributes fail-closed', () => {
    const validCustomDigest = 'hmac:0123456789abcdef';
    const span = telemetry.startSpan('rules_evaluated', {
      rule_id: 'CA_CIV_1950_5',
      jurisdiction: 'CA',
      domain_custom_key: validCustomDigest,
      // Prohibited / PII keys:
      tenant_name: 'Jane Doe',
      ssn: '000-12-3456',
      lease_snippet: 'The tenant Jane Doe agrees to pay $3500 deposit...',
      raw_text: 'Secret medical or wage text',
    });
    span.end('OK');

    const spans = telemetry.getBufferedSpans();
    expect(spans.length).toBe(1);
    const attrs = spans[0].attributes;

    // Allowlisted keys pass through (opaque digest on custom key)
    expect(attrs.rule_id).toBe('CA_CIV_1950_5');
    expect(attrs.jurisdiction).toBe('CA');
    expect(attrs.domain_custom_key).toBe(validCustomDigest);

    // Cleartext value on a custom domain key is still redacted fail-closed when allowRawPayloads=false
    const cleartextSpan = telemetry.startSpan('rules_evaluated', {
      domain_custom_key: 'custom_value',
    });
    cleartextSpan.end('OK');
    expect(telemetry.getBufferedSpans()[1].attributes.domain_custom_key).toBe(
      REDACTED_SENSITIVE_VALUE
    );

    // Unknown or unverified keys MUST be redacted without retaining unregistered key text
    expect('tenant_name' in attrs).toBe(false);
    expect('ssn' in attrs).toBe(false);
    expect('lease_snippet' in attrs).toBe(false);
    expect('raw_text' in attrs).toBe(false);
    expect(attrs['[REDACTED_KEY]']).toBe('[REDACTED_BY_DEFAULT_ALLOWLIST]');
  });

  it('Invariant 3: Truncates oversized string values even on allowlisted keys', () => {
    const oversizedString = 'A'.repeat(300);
    const nonAsciiOversized = '🔒'.repeat(150);
    const span = telemetry.startSpan('parse_document', {
      rule_id: oversizedString,
      statute_code: nonAsciiOversized,
    });
    span.end('OK');

    const spans = telemetry.getBufferedSpans();
    expect(spans[0].attributes.rule_id).toBe('[TRUNCATED_HASH_4daeb9ac]');
    expect(spans[0].attributes.rule_id).not.toContain('AAAA');
    expect(spans[0].attributes.statute_code).toBe('[TRUNCATED_HASH_87287bd9]');
    expect(spans[0].attributes.statute_code).not.toContain('🔒');

    // Known-answer tests against NIST SHA-256 vectors
    expect(sha256Hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    const nist56Bytes = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq';
    expect(sha256Hex(nist56Bytes)).toBe(
      '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'
    );
  });

  it('Invariant 4: "Burn Local Data" purges buffer and enforces permanent realm-wide tombstone', async () => {
    await runCoreRealmScenario(`
      const { TelemetryManager, isHardBurned } = core;
      const isolated = new TelemetryManager({ mode: 'memory_only', burnEnabled: true });

      const span1 = isolated.startSpan('scan_started', { rule_id: 'AR-001' });
      span1.end('OK');
      const pendingSpan = isolated.startSpan('scan_started', { rule_id: 'CA_CIV_1950_5' });
      isolated.recordAuditEvent('document_ingested', 'Document uploaded');

      const retainedSpans = isolated.getBufferedSpans();
      const retainedAudit = isolated.getAuditLog();
      assert.equal(retainedSpans.length, 1);
      assert.equal(retainedAudit.length, 1);

      isolated.burn();

      assert.equal(isHardBurned(), true);
      assert.equal(retainedSpans.length, 0);
      assert.equal(retainedAudit.length, 1);
      assert.equal(isolated.getBufferedSpans().length, 0);
      assert.equal(isolated.getAuditLog().length, 0);
      assert.equal(isolated.getPrivacyAuditReport().activeSpanCount, 0);

      // Pre-burn pending span completion, reset/restart, new spans, and new managers all fail closed
      pendingSpan.end('OK');
      isolated.reset();
      isolated.restartSession();
      const span2 = isolated.startSpan('scan_completed', { rule_id: 'CA-SEC-DEP-CAP-01' });
      span2.end('OK');
      isolated.recordAuditEvent('document_ingested', 'Post-burn upload');
      assert.equal(isolated.getBufferedSpans().length, 0);
      assert.equal(isolated.getAuditLog().length, 0);

      const isolated2 = new TelemetryManager({ mode: 'memory_only', burnEnabled: true });
      isolated2.startSpan('scan_completed', { rule_id: 'AR-001' }).end('OK');
      isolated2.recordAuditEvent('document_ingested', 'Post-burn second manager');
      assert.equal(isolated2.getBufferedSpans().length, 0);
      assert.equal(isolated2.getAuditLog().length, 0);
    `);

    // Duplicate module copies in the same JS realm share one tombstone, manager wiper registry, and listener set.
    await runCoreRealmScenario(`
      const copyA = await loadCopy('copyA');
      const copyB = await loadCopy('copyB');

      const mgrA = new copyA.TelemetryManager({ mode: 'memory_only', burnEnabled: true });
      mgrA.startSpan('scan_started', { rule_id: 'AR-001' }).end('OK');
      mgrA.recordAuditEvent('document_ingested', 'Copy A doc');
      const retainedSpansA = mgrA.getBufferedSpans();
      const retainedAuditA = mgrA.getAuditLog();
      assert.equal(retainedSpansA.length, 1);
      assert.equal(retainedAuditA.length, 1);

      const mgrAPassive = new copyA.TelemetryManager({ mode: 'memory_only', burnEnabled: false });
      mgrAPassive.startSpan('rules_evaluated', { rule_id: 'AR-002' }).end('OK');
      mgrAPassive.recordAuditEvent('audit_performed', 'Passive copy A event');
      assert.equal(mgrAPassive.getBufferedSpans().length, 1);
      assert.equal(mgrAPassive.getAuditLog().length, 1);

      let copyANotified = 0;
      const unsub = copyA.onHardBurn(() => {
        copyANotified += 1;
      });

      const mgrB = new copyB.TelemetryManager({ mode: 'memory_only', burnEnabled: true });
      mgrB.burn();

      assert.equal(copyA.isHardBurned(), true);
      assert.equal(copyB.isHardBurned(), true);
      assert.equal(copyANotified, 1);
      assert.equal(mgrA.getBufferedSpans().length, 0);
      assert.equal(retainedSpansA.length, 0);
      assert.equal(mgrA.getAuditLog().length, 0);
      assert.equal(retainedAuditA.length, 1);
      assert.equal(mgrAPassive.getBufferedSpans().length, 0);
      assert.equal(mgrAPassive.getAuditLog().length, 0);

      // Tombstone stays latched even if caller tries to mutate the shared realm symbol state.
      const realmState = globalThis[Symbol.for('knowthankyew.privacyTelemetry.realmState.v1')];
      realmState.hardBurned = false;
      assert.equal(copyA.isHardBurned(), true);

      // Subsequent dynamic module evaluation in the same JS realm still observes the latched tombstone.
      const copyC = await loadCopy('copyC');
      assert.equal(copyC.isHardBurned(), true);
      const mgrC = new copyC.TelemetryManager({ mode: 'memory_only', burnEnabled: true });
      mgrC.startSpan('scan_completed', { rule_id: 'AR-001' }).end('OK');
      mgrC.recordAuditEvent('document_ingested', 'Copy C post-burn');
      assert.equal(mgrC.getBufferedSpans().length, 0);
      assert.equal(mgrC.getAuditLog().length, 0);
      unsub();
    `);
  });

  it('Invariant 5: Honest dynamic privacy claims prevent false claims in enterprise mode', () => {
    // Consumer mode
    const consumerClaims = telemetry.getPrivacyClaims({
      consumerFooterTitle: 'Custom Local Footer',
    });
    expect(consumerClaims.isLocalOnlyHonest).toBe(true);
    expect(consumerClaims.isEnterpriseBuild).toBe(false);
    expect(consumerClaims.badgeLabel).toContain('Zero Network');
    expect(consumerClaims.dropzoneNotice).toContain('100% Client-Side');
    expect(consumerClaims.footerTitle).toBe('Custom Local Footer');

    // Enterprise mode
    const enterpriseTelemetry = new TelemetryManager({
      mode: 'otlp',
      otlpEndpoint: 'https://collector.internal.org:4318/v1/traces',
      networkEgress: 'allow_otlp',
    });

    const enterpriseClaims = enterpriseTelemetry.getPrivacyClaims({
      enterpriseFooterTitle: 'Enterprise Footer',
    });
    expect(enterpriseClaims.isLocalOnlyHonest).toBe(false);
    expect(enterpriseClaims.isEnterpriseBuild).toBe(true);
    expect(enterpriseClaims.badgeLabel).toContain('OTLP Active');
    expect(enterpriseClaims.dropzoneNotice).not.toContain('Zero Network');
    expect(enterpriseClaims.dropzoneNotice).toContain('OTLP Operational Metadata Active');
    expect(enterpriseClaims.footerTitle).toBe('Enterprise Footer');
  });

  it('MemoryExporter respects circular buffer capacity', () => {
    const exporter = new MemoryExporter(3);
    for (let i = 0; i < 5; i++) {
      exporter.export({
        id: `s_${i}`,
        name: `span_${i}`,
        startTime: i,
        status: 'OK',
        attributes: {},
        events: [],
      });
    }

    expect(exporter.count()).toBe(3);
    const spans = exporter.getSpans();
    expect(spans[0].id).toBe('s_2');
    expect(spans[1].id).toBe('s_3');
    expect(spans[2].id).toBe('s_4');
  });

  it('Invariant 6: Rejects sensitive values and free-text smuggling on allowlisted keys', () => {
    const { sanitize } = createAllowlistSanitizer(['dataset_relative_path', 'adapter_path']);
    const cleaned = sanitize({
      rule_id: 'Short prose: tenant Alice Smith owes $1,500',
      status: 'line1\nline2',
      jurisdiction: 'District of Columbia',
      statute_code: 'jane.doe@example.com',
      error_code: '123-45-6789',
      device: '/Users/alice/private/model',
      adapter_path: '/Users/alice/adapters/m1',
      dataset_relative_path: 'folder/job-1.jsonl',
      base_model: 'HuggingFaceTB/SmolLM2-135M',
    });

    expect(cleaned.rule_id).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(cleaned.status).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(cleaned.jurisdiction).toBe('District of Columbia');
    expect(cleaned.statute_code).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(cleaned.error_code).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(cleaned.device).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(cleaned.adapter_path).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(cleaned.dataset_relative_path).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(cleaned.base_model).toBe('HuggingFaceTB/SmolLM2-135M');

    const validPaths = sanitize({
      adapter_path: 'hmac:0123456789abcdef',
      dataset_relative_path: 'job-1.jsonl',
    });
    expect(validPaths.adapter_path).toBe('hmac:0123456789abcdef');
    expect(validPaths.dataset_relative_path).toBe('job-1.jsonl');
  });

  it('Invariant 7: Direct exportToOtlp enforces allowlist and value hygiene before fetch', async () => {
    const capturedBodies: string[] = [];
    const origFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: unknown, init?: { body?: string }) => {
      if (init?.body) capturedBodies.push(init.body);
      return { ok: true } as Response;
    }) as typeof fetch;

    try {
      await exportToOtlp('http://localhost:4318/v1/traces', {
        id: 's-1',
        name: 'test.export',
        startTime: 1000,
        status: 'OK',
        attributes: {
          rule_id: 'tenant@example.com',
          raw_secret: 'Do not send this',
          'alice@example.com': 'also-do-not-send',
          jurisdiction: 'CA',
        },
        events: [],
      });

      expect(capturedBodies.length).toBe(1);
      const parsed = JSON.parse(capturedBodies[0]);
      const attrs = parsed.resourceSpans[0].scopeSpans[0].spans[0].attributes as Array<{
        key: string;
        value: { stringValue?: string };
      }>;
      const byKey = Object.fromEntries(attrs.map((a) => [a.key, a.value.stringValue]));
      expect(byKey.rule_id).toBe('[REDACTED_SENSITIVE_VALUE]');
      expect(byKey.raw_secret).toBeUndefined();
      expect(byKey['alice@example.com']).toBeUndefined();
      expect(byKey.jurisdiction).toBe('CA');
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it('Invariant 8: Enforces per-key schemas, HMAC-16 adapter paths, and rejects non-scalar or non-finite values', () => {
    const { sanitize } = createAllowlistSanitizer([
      'adapter_path',
      'dataset_relative_path',
      'report_path',
      'findings_count',
      'charity_eligible',
      'hospital_id',
      'agreement_title',
      'warranty_type',
      'product_type',
      'rule_ids',
    ]);

    const cleaned = sanitize({
      adapter_path: 'sha256:0123456789abcdef',
      dataset_relative_path: 'Alice.Smith.medical.pdf',
      report_path: 'run-12.log',
      duration_ms: Number.NaN,
      step: Number.POSITIVE_INFINITY,
      findings_count: '3',
      charity_eligible: 'true',
      loss: { leak: '123-45-6789' },
      device: [1, 2, 3],
      action: null,
      error_code: undefined,
      statute_code: 'Tenant Alice Smith owes $1500',
      warranty_type: 'Anything goes here',
      product_type: 'Alice Smith laptop order',
      agreement_title: 'Alice Smith Gym Contract',
      rule_ids: ['AR-001', 'Alice Smith prose'],
    });

    expect(cleaned.adapter_path).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(cleaned.dataset_relative_path).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(cleaned.report_path).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(cleaned.duration_ms).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(cleaned.step).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(cleaned.findings_count).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(cleaned.charity_eligible).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(cleaned.loss).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(cleaned.device).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(cleaned.action).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(cleaned.error_code).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(cleaned.statute_code).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(cleaned.warranty_type).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(cleaned.product_type).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(cleaned.agreement_title).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(cleaned.rule_ids).toBe('[REDACTED_SENSITIVE_VALUE]');

    const badDatasetExtensions = sanitize({
      dataset_relative_path: 'job-1.txt',
      dataset_extra_path: 'job.foo.jsonl',
    });
    expect(badDatasetExtensions.dataset_relative_path).toBe('[REDACTED_SENSITIVE_VALUE]');

    const valid = sanitize({
      adapter_path: 'hmac:0123456789abcdef',
      dataset_relative_path: 'job-999.jsonl',
      findings_count: 4,
      charity_eligible: true,
      hospital_id: 'cleveland-clinic-main',
      statute_code: '29 U.S.C. § 206',
      warranty_type: 'Disclaimed / As-Is',
      product_type: 'Electronics & Laptops',
      rule_ids: ['AR-001', 'CA-SEC-DEP-CAP-01'],
    });

    expect(valid.adapter_path).toBe('hmac:0123456789abcdef');
    expect(valid.dataset_relative_path).toBe('job-999.jsonl');
    expect(valid.findings_count).toBe(4);
    expect(valid.charity_eligible).toBe(true);
    expect(valid.hospital_id).toBe('cleveland-clinic-main');
    expect(valid.statute_code).toBe('29 U.S.C. § 206');
    expect(valid.warranty_type).toBe('Disclaimed / As-Is');
    expect(valid.product_type).toBe('Electronics & Laptops');
    expect(valid.rule_ids).toBe('AR-001,CA-SEC-DEP-CAP-01');
  });

  it('Invariant 9: Caps raw strings at 256 chars and detects multiple contiguous Luhn cards', () => {
    const { sanitize } = createAllowlistSanitizer();

    const rawSanitized = sanitize(
      {
        custom_note: 'A'.repeat(300),
        bad_object: { ssn: '123-45-6789' },
        nan_metric: Number.NaN,
        short_raw: 'dev debug note',
      },
      true
    );
    expect(typeof rawSanitized.custom_note).toBe('string');
    expect(String(rawSanitized.custom_note)).toMatch(/^\[TRUNCATED_HASH_[a-f0-9]{8}\]$/);
    expect(rawSanitized.bad_object).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(rawSanitized.nan_metric).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(rawSanitized.short_raw).toBe('dev debug note');

    // Direct detector assertions verify scanning continues past an invalid-Luhn candidate.
    expect(containsSensitivePattern('4111111111111112 4111111111111111')).toBe(true);
    expect(containsSensitivePattern('4111111111111112 4111111111111113')).toBe(false);
  });

  it('Invariant 10: Preserves long rule_ids CSV and digest markers across repeated sanitization and OTLP export', async () => {
    const longRuleIds = Array.from({ length: 5 }, (_, i) => `hmac:${String(i).repeat(59).slice(0, 59)}`);
    const expectedCsv = longRuleIds.join(',');
    const capturedBodies: string[] = [];
    let resolveFetch!: () => void;
    const fetchDispatched = new Promise<void>((resolve) => {
      resolveFetch = resolve;
    });
    const origFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: unknown, init?: { body?: string }) => {
      if (init?.body) capturedBodies.push(init.body);
      resolveFetch();
      return { ok: true } as Response;
    }) as typeof fetch;

    try {
      const otlpTelemetry = new TelemetryManager(
        {
          mode: 'otlp',
          otlpEndpoint: 'http://localhost:4318/v1/traces',
          serviceName: 'test-svc',
        },
        ['rule_ids']
      );

      const span = otlpTelemetry.startSpan('evaluate_lease_rules', {
        rule_ids: longRuleIds,
        status: 'Z'.repeat(300),
      });
      span.end('OK');

      let timeoutId: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([
          fetchDispatched,
          new Promise<never>((_, reject) => {
            timeoutId = setTimeout(
              () => reject(new Error('Timed out waiting for OTLP fetch dispatch')),
              2000
            );
          }),
        ]);
      } finally {
        if (timeoutId !== undefined) clearTimeout(timeoutId);
      }

      const buffered = otlpTelemetry.getBufferedSpans()[0];
      expect(buffered.attributes.rule_ids).toBe(expectedCsv);
      expect(String(buffered.attributes.status)).toMatch(/^\[TRUNCATED_HASH_[a-f0-9]{8}\]$/);

      expect(capturedBodies.length).toBe(1);
      const parsed = JSON.parse(capturedBodies[0]);
      const attrs = parsed.resourceSpans[0].scopeSpans[0].spans[0].attributes as Array<{
        key: string;
        value: { stringValue?: string };
      }>;
      const byKey = Object.fromEntries(attrs.map((a) => [a.key, a.value.stringValue]));
      expect(byKey.rule_ids).toBe(buffered.attributes.rule_ids);
      expect(byKey.status).toBe(buffered.attributes.status);
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it('Invariant 11: Redacts Mastercard 2-series Luhn cards, enforces strict statute citations, and prevents digest markers on path keys', () => {
    const { sanitize } = createAllowlistSanitizer(['rule_id', 'rule_ids', 'adapter_path', 'dataset_relative_path', 'report_path']);

    // Mastercard 2-series (2221-2720): Luhn-valid detected as PAN; invalid-Luhn or out-of-range IINs not flagged by PAN detector, and all raw numeric rule_ids are redacted.
    expect(containsSensitivePattern('2223000048400011')).toBe(true);
    expect(containsSensitivePattern('2223000048400012')).toBe(false);
    expect(containsSensitivePattern('2220000000000000')).toBe(false);
    expect(containsSensitivePattern('2721000000000004')).toBe(false);
    expect(sanitize({ rule_id: '2223000048400011' }).rule_id).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitize({ rule_ids: ['2223000048400011'] }).rule_ids).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitize({ rule_id: '2223000048400012' }).rule_id).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitize({ rule_id: '2220000000000000' }).rule_id).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitize({ rule_id: '2721000000000004' }).rule_id).toBe('[REDACTED_SENSITIVE_VALUE]');

    // Strict statute citations: arbitrary prose with "Code"/"§" or unapproved chapter tokens redacted; genuine citations preserved.
    expect(sanitize({ statute_code: 'Tenant Alice Smith 42 Code' }).statute_code).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitize({ statute_code: 'Cal. Alice Smith § 42' }).statute_code).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitize({ statute_code: '123 SMITH 456' }).statute_code).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(
      new TelemetryManager({ mode: 'memory_only', allowRawPayloads: true }).sanitizeAttributes({
        statute_code: '123 SMITH 456',
      }).statute_code
    ).toBe('123 SMITH 456');
    expect(sanitize({ statute_code: '29 U.S.C. § 206' }).statute_code).toBe('29 U.S.C. § 206');
    expect(sanitize({ statute_code: '16 CFR Part 425' }).statute_code).toBe('16 CFR Part 425');
    expect(sanitize({ statute_code: '815 ILCS 601' }).statute_code).toBe('815 ILCS 601');
    expect(sanitize({ statute_code: 'Mass. Gen. Laws ch. 149 § 150' }).statute_code).toBe('Mass. Gen. Laws ch. 149 § 150');
    expect(sanitize({ statute_code: 'UCC § 2-314' }).statute_code).toBe('UCC § 2-314');
    expect(sanitize({ statute_code: 'EU GDPR Art. 6' }).statute_code).toBe('EU GDPR Art. 6');
    expect(sanitize({ statute_code: 'UK Consumer Rights Act 2015, Part 1, Section 9' }).statute_code).toBe(
      'UK Consumer Rights Act 2015, Part 1, Section 9'
    );

    // Path schema keys run before digest fallback / marker preservation.
    const longPath = '/Users/alice/' + 'a'.repeat(300);
    expect(sanitize({ adapter_path: longPath }).adapter_path).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitize({ adapter_path: '[TRUNCATED_HASH_12345678]' }).adapter_path).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitize({ dataset_relative_path: longPath }).dataset_relative_path).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitize({ dataset_relative_path: '[TRUNCATED_HASH_12345678]' }).dataset_relative_path).toBe(
      '[REDACTED_SENSITIVE_VALUE]'
    );
    expect(sanitize({ report_path: longPath }).report_path).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitize({ report_path: '[TRUNCATED_HASH_12345678]' }).report_path).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitize({ report_path: 'run-12.log' }).report_path).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitize({ report_path: 'hmac:0123456789abcdef' }).report_path).toBe('hmac:0123456789abcdef');
  });

  it('Invariant 12a: Enforces closed-domain sets for jurisdiction, state, product_type, and product_category', () => {
    const { sanitize } = createAllowlistSanitizer(['state', 'product_type', 'product_category']);

    expect(sanitize({ jurisdiction: 'CA' }).jurisdiction).toBe('CA');
    expect(sanitize({ jurisdiction: 'District of Columbia' }).jurisdiction).toBe('District of Columbia');
    expect(sanitize({ jurisdiction: 'FTC' }).jurisdiction).toBe('FTC');
    expect(sanitize({ state: 'Ohio' }).state).toBe('Ohio');
    expect(sanitize({ product_type: 'Automotive / EV' }).product_type).toBe('Automotive / EV');
    expect(sanitize({ product_category: 'Tools & Equipment' }).product_category).toBe('Tools & Equipment');

    // Arbitrary single-token identifiers, tenant names, and PHI must be redacted fail-closed
    expect(sanitize({ jurisdiction: 'Acme-Property-Management' }).jurisdiction).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitize({ state: 'john_doe' }).state).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitize({ product_type: 'HIV-positive' }).product_type).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitize({ product_category: 'CustomSecretSKU' }).product_category).toBe('[REDACTED_SENSITIVE_VALUE]');
  });

  it('Invariant 12b: Detects brand-specific PAN lengths (13/15/16/19) while skipping negative controls', () => {
    expect(containsSensitivePattern('card=4000000000006')).toBe(true); // 13-digit Visa (Luhn valid)
    expect(containsSensitivePattern('amex=378282246310005')).toBe(true); // 15-digit Amex (Luhn valid)
    expect(containsSensitivePattern('disc16=6440000000000005')).toBe(true); // 16-digit Discover 644x (Luhn valid)
    expect(containsSensitivePattern('visa19=4000000000000000006')).toBe(true); // 19-digit Visa (Luhn valid)
    expect(containsSensitivePattern('disc19=6011000000000000001')).toBe(true); // 19-digit Discover (Luhn valid)

    // Negative controls: Luhn-valid unsupported 14/17-digit numbers, Luhn-valid non-IIN 9-prefix, and non-Luhn 19-digit
    expect(containsSensitivePattern('id=40000000000002')).toBe(false); // 14 digits (not Visa IIN length)
    expect(containsSensitivePattern('id=40000000000000006')).toBe(false); // 17 digits (invalid PAN length, Luhn valid)
    expect(containsSensitivePattern('id=9000000000000001')).toBe(false); // non-card IIN (Luhn valid)
    expect(containsSensitivePattern('id=4000000000000000001')).toBe(false); // 19-digit non-Luhn
  });

  it('Invariant 12c: Detects embedded SSNs and file:// local filesystem URIs without false positives on benign paths', () => {
    expect(containsSensitivePattern('customer_123-45-6789')).toBe(true);
    expect(containsSensitivePattern('file:///Users/alice/private/model')).toBe(true);
    expect(containsSensitivePattern('file://localhost/Users/alice/private/model')).toBe(true);
    expect(containsSensitivePattern('file:///C:/Users/alice/docs')).toBe(true);
    expect(containsSensitivePattern('path=/Users/alice/x')).toBe(true);

    // Negative controls
    expect(containsSensitivePattern('id_12-345-6789')).toBe(false);
    expect(containsSensitivePattern('order_1234-56-7890')).toBe(false);
    expect(containsSensitivePattern('org/users/profile')).toBe(false);
    expect(containsSensitivePattern('https://example.com/home/page')).toBe(false);
  });

  it('Invariant 12d: Enforces rule_ids item count (<=50) and aggregate length boundaries', () => {
    const { sanitize } = createAllowlistSanitizer(['rule_ids']);
    const validFifty = Array.from({ length: 50 }, (_, i) => `hmac:${(i + 1).toString(16).padStart(16, '0')}`);
    expect(sanitize({ rule_ids: validFifty }).rule_ids).toBe(validFifty.join(','));

    const fiftyOne = Array.from({ length: 51 }, (_, i) => `hmac:${(i + 1).toString(16).padStart(16, '0')}`);
    expect(sanitize({ rule_ids: fiftyOne }).rule_ids).toBe('[REDACTED_SENSITIVE_VALUE]');
    const fiftyOneShortCsv = String(sanitize({ rule_ids: Array(51).fill('AR-001').join(',') }).rule_ids);
    expect(fiftyOneShortCsv).not.toContain('AR-001');
    expect(fiftyOneShortCsv).toMatch(/^(?:\[REDACTED_SENSITIVE_VALUE\]|\[TRUNCATED_HASH_[a-f0-9]{8}\])$/);
    const fiftyOneCsvOut = String(sanitize({ rule_ids: fiftyOne.join(',') }).rule_ids);
    expect(fiftyOneCsvOut).not.toContain('hmac:');
    expect(fiftyOneCsvOut).toMatch(/^(?:\[REDACTED_SENSITIVE_VALUE\]|\[TRUNCATED_HASH_[a-f0-9]{8}\])$/);

    const oversizedCsv = Array.from({ length: 50 }, () => `sha256:${'a'.repeat(65)}`).join(',');
    expect(oversizedCsv.length).toBeGreaterThan(3600);
    const oversizedOut = String(sanitize({ rule_ids: oversizedCsv }).rule_ids);
    expect(oversizedOut).toMatch(/^(?:\[REDACTED_SENSITIVE_VALUE\]|\[TRUNCATED_HASH_[a-f0-9]{8}\])$/);
    expect(oversizedOut).not.toContain('sha256:');
  });

  it('enforces closed domains and strict token formats to block prose and number smuggling', () => {
    const { sanitize } = createAllowlistSanitizer([
      'status',
      'risk_level',
      'action',
      'device',
      'rule_id',
      'rule_ids',
      'job_id',
      'error_code',
      'app.version',
      'hospital_id',
      'cpt_code',
      'custom_field',
    ]);

    const smuggled = sanitize({
      status: 'Patient-has-HIV',
      risk_level: 'Patient-has-HIV',
      action: 'Patient-has-HIV',
      device: 'Patient-has-HIV',
      rule_id: 'Patient-has-HIV',
      rule_ids: 'AR-001,Patient-has-HIV',
      job_id: 'Patient-has-HIV',
      error_code: 'Patient-has-HIV',
      'app.version': 'Patient-has-HIV',
      hospital_id: 'Patient-has-HIV',
      cpt_code: '123456789',
      custom_field: 'Patient-has-HIV',
    });

    for (const [key, value] of Object.entries(smuggled)) {
      expect(value, `expected smuggling payload to be redacted for ${key}`).toBe('[REDACTED_SENSITIVE_VALUE]');
    }

    const numericSmuggled = sanitize({
      job_id: '123456789',
      cpt_code: '123456789',
      custom_field: '123456789',
    });
    expect(numericSmuggled.job_id).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(numericSmuggled.cpt_code).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(numericSmuggled.custom_field).toBe('[REDACTED_SENSITIVE_VALUE]');

    const valid = sanitize({
      status: 'Completed',
      risk_level: 'HIGH',
      action: 'scan_completed',
      device: 'CUDA:0',
      rule_id: 'CA_CIV_1950_5',
      rule_ids: ['AR-001', 'implied_warranty_disclaimer'],
      job_id: 'job-123',
      error_code: 'edge_inference_notice',
      'app.version': '2.1.0',
      hospital_id: 'cleveland-clinic-main',
      cpt_code: '99213',
      custom_field: 'hmac:0123456789abcdef',
    });

    expect(valid.status).toBe('Completed');
    expect(valid.risk_level).toBe('HIGH');
    expect(valid.action).toBe('scan_completed');
    expect(valid.device).toBe('CUDA:0');
    expect(valid.rule_id).toBe('CA_CIV_1950_5');
    expect(valid.rule_ids).toBe('AR-001,implied_warranty_disclaimer');
    expect(valid.job_id).toBe('job-123');
    expect(valid.error_code).toBe('edge_inference_notice');
    expect(valid['app.version']).toBe('2.1.0');
    expect(valid.hospital_id).toBe('cleveland-clinic-main');
    expect(valid.cpt_code).toBe('99213');
    expect(valid.custom_field).toBe('hmac:0123456789abcdef');
  });

  it('R8 Hardening: Redacts compact 9-digit SSNs, underscore-delimited PANs, unsafe dataset paths/statutes, and emits default service.name', async () => {
    const telemetry = new TelemetryManager(
      { mode: 'memory_only' },
      ['dataset_relative_path', 'custom_field']
    );

    const span = telemetry.startSpan('audit_performed', {
      rule_id: '123456789',
      rule_ids: ['AR-001', '123456789'],
      job_id: 'job_4111111111111111',
      custom_field: '123456789',
      dataset_relative_path: 'Jane_Doe_HIV_positive.jsonl',
      statute_code: 'Jane.Doe_HIV_positive',
      service: 'knowthankyew-app',
    });
    span.end('OK');

    const attrs = telemetry.getBufferedSpans()[0].attributes;
    expect(attrs.rule_id).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(attrs.rule_ids).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(attrs.job_id).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(attrs.custom_field).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(attrs.dataset_relative_path).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(attrs.statute_code).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(attrs.service).toBe('knowthankyew-app');

    // Valid bounded tokens still pass
    const validSpan = telemetry.startSpan('rules_evaluated', {
      dataset_relative_path: 'job-42.jsonl',
      statute_code: 'Cal. Civ. Code § 1950.5',
      rule_id: 'CA_CIV_1950_5',
    });
    validSpan.end('OK');
    const validAttrs = telemetry.getBufferedSpans()[1].attributes;
    expect(validAttrs.dataset_relative_path).toBe('job-42.jsonl');
    expect(validAttrs.statute_code).toBe('Cal. Civ. Code § 1950.5');
    expect(validAttrs.rule_id).toBe('CA_CIV_1950_5');

    // Verify federal statutes pass statute_code while compact 9-digit SSN on job_id is caught
    const multiWordStatutes = telemetry.startSpan('evaluate_charity_care', {
      statute_code: '42 U.S.C. § 1983',
      rule_id: 'FLSA_EXEMPT_541',
      job_id: '123456789',
    });
    multiWordStatutes.end('OK');
    const statueAttrs = telemetry.getBufferedSpans()[2].attributes;
    expect(statueAttrs.statute_code).toBe('42 U.S.C. § 1983');
    expect(statueAttrs.rule_id).toBe('FLSA_EXEMPT_541');
    expect(statueAttrs.job_id).toBe('[REDACTED_SENSITIVE_VALUE]');

    // Default serviceName ("knowthankyew-app") must export unredacted as resource service.name
    const capturedBodies: string[] = [];
    let resolveFetch!: () => void;
    const fetchDispatched = new Promise<void>((resolve) => {
      resolveFetch = resolve;
    });
    const origFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: unknown, init?: { body?: string }) => {
      if (init?.body) capturedBodies.push(init.body);
      resolveFetch();
      return { ok: true } as Response;
    }) as typeof fetch;

    try {
      const defaultOtlp = new TelemetryManager({
        mode: 'otlp',
        otlpEndpoint: 'http://localhost:4318/v1/traces',
      });
      const otlpSpan = defaultOtlp.startSpan('audit_performed', { action: 'scan' });
      otlpSpan.end('OK');

      let timeoutId: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([
          fetchDispatched,
          new Promise<never>((_, reject) => {
            timeoutId = setTimeout(
              () => reject(new Error('Timed out waiting for default OTLP export')),
              2000
            );
          }),
        ]);
      } finally {
        if (timeoutId !== undefined) clearTimeout(timeoutId);
      }

      expect(capturedBodies).toHaveLength(1);
      const parsed = JSON.parse(capturedBodies[0]);
      const svcAttr = parsed.resourceSpans[0].resource.attributes.find(
        (a: { key: string; value: { stringValue?: string } }) => a.key === 'service.name'
      );
      expect(svcAttr?.value?.stringValue).toBe('knowthankyew-app');
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it('rejects arbitrary non-hex strings for dataset_hash while accepting hex SHA-256 digests (CodeRabbit R9)', () => {
    const { sanitize } = createAllowlistSanitizer(['dataset_hash']);
    expect(sanitize({ dataset_hash: 'patient_HIV_positive' }).dataset_hash).toBe(
      '[REDACTED_SENSITIVE_VALUE]'
    );
    expect(sanitize({ dataset_hash: 'DeadBeefCafe' }).dataset_hash).toBe(
      '[REDACTED_SENSITIVE_VALUE]'
    );
    expect(sanitize({ dataset_hash: 'abc123def456' }).dataset_hash).toBe('abc123def456');

    const digest = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    expect(sanitize({ dataset_hash: digest }).dataset_hash).toBe(digest);
    expect(sanitize({ dataset_hash: `sha256:${digest}` }).dataset_hash).toBe(`sha256:${digest}`);
  });

  it('redacts file:/ single-slash local URIs, sanitizes OTLP span names, and preserves valid UUID/hex IDs with 9 digits (CodeRabbit R10)', async () => {
    const { sanitize } = createAllowlistSanitizer(['dataset_relative_path']);

    // 1. file:/ single-slash local URIs must be caught BEFORE base_model acceptance
    expect(sanitize({ base_model: 'file:/Users/JaneDoe/models/private-model' }).base_model).toBe(
      '[REDACTED_SENSITIVE_VALUE]'
    );
    expect(sanitize({ base_model: 'FILE:/home/alice/secret-lora' }).base_model).toBe(
      '[REDACTED_SENSITIVE_VALUE]'
    );

    // 2. Constrained UUIDs and hex dataset_hash containing 9 leading decimal digits stay intact,
    // while free-form job-* tokens containing SSNs remain redacted.
    const uuidNineDigits = '12345678-1234-4abc-8abc-123456789abc';
    const hexNineDigits = '123456789abcdef0123456789abcdef0';
    expect(sanitize({ job_id: uuidNineDigits }).job_id).toBe(uuidNineDigits);
    expect(sanitize({ dataset_hash: hexNineDigits }).dataset_hash).toBe(hexNineDigits);
    expect(
      sanitize({ dataset_relative_path: `${uuidNineDigits}.jsonl` }).dataset_relative_path
    ).toBe(`${uuidNineDigits}.jsonl`);
    expect(sanitize({ job_id: 'job-123-45-6789' }).job_id).toBe('[REDACTED_SENSITIVE_VALUE]');

    // 3. OTLP span names must be redacted when unsafe and preserved when allowRawPayloads=true
    const capturedBodies: string[] = [];
    let resolveDispatches!: () => void;
    const twoDispatchesDone = new Promise<void>((resolve) => {
      resolveDispatches = resolve;
    });
    const origFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: unknown, init?: { body?: string }) => {
      if (init?.body) {
        capturedBodies.push(init.body);
        if (capturedBodies.length >= 2) resolveDispatches();
      }
      return { ok: true } as Response;
    }) as typeof fetch;

    try {
      const otlp = new TelemetryManager({
        mode: 'otlp',
        otlpEndpoint: 'http://localhost:4318/v1/traces',
      });
      otlp.startSpan('Jane Doe 123-45-6789', { action: 'scan' }).end('OK');
      expect(otlp.getBufferedSpans()[0].name).toBe('[REDACTED_SPAN_NAME]');

      await exportToOtlp('http://localhost:4318/v1/traces', {
        id: 'span-direct',
        name: 'Patient jane@example.com 123-45-6789',
        startTime: 1000,
        endTime: 1005,
        durationMs: 5,
        status: 'OK',
        attributes: {},
        events: [],
      });

      await twoDispatchesDone;
      const parsedPayloads = capturedBodies.map((raw) => JSON.parse(raw));
      const expectedDirectSpanId = sha256Hex('kty:span:span-direct').slice(0, 16);
      const expectedDirectTraceId = sha256Hex('kty:trace:span-direct').slice(0, 32);
      const directParsed = parsedPayloads.find(
        (payload) => payload.resourceSpans[0].scopeSpans[0].spans[0].spanId === expectedDirectSpanId
      );
      expect(directParsed).toBeDefined();
      expect(directParsed.resourceSpans[0].scopeSpans[0].spans[0].traceId).toBe(expectedDirectTraceId);
      expect(directParsed.resourceSpans[0].scopeSpans[0].spans[0].name).toBe('[REDACTED_SPAN_NAME]');
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it('enforces closed registered event/span names and strict opaque job_id values', () => {
    const telemetry = new TelemetryManager({ mode: 'memory_only', burnEnabled: true });

    const blockedSpan = telemetry.startSpan('patient_jane_doe_hiv_positive', {
      job_id: 'job-tenant_Alice_Smith',
    });
    blockedSpan.end('OK', { status: 'OK' });

    const panLookalikeSpan = telemetry.startSpan('unknown.unregistered_event', {
      job_id: 'job_4111111111111111',
    });
    panLookalikeSpan.end('OK');

    const numericLeakSpan = telemetry.startSpan('analyze_paystub', {
      job_id: '123456789',
    });
    numericLeakSpan.end('OK');

    const validSpan = telemetry.startSpan('job.transition.training', {
      job_id: 'hmac:0123456789abcdef',
      service: 'ftaas-worker',
    });
    validSpan.end('OK');

    const shaSpan = telemetry.startSpan('extension.page_scan', {
      job_id: `sha256:${'a'.repeat(64)}`,
    });
    shaSpan.end('OK');

    const spans = telemetry.getBufferedSpans();
    expect(spans).toHaveLength(5);
    expect(spans[0].name).toBe('[REDACTED_SPAN_NAME]');
    expect(spans[0].attributes.job_id).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(spans[1].name).toBe('[REDACTED_SPAN_NAME]');
    expect(spans[1].attributes.job_id).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(spans[2].name).toBe('analyze_paystub');
    expect(spans[2].attributes.job_id).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(spans[3].name).toBe('job.transition.training');
    expect(spans[3].attributes.job_id).toBe('hmac:0123456789abcdef');
    expect(spans[4].name).toBe('extension.page_scan');
    expect(spans[4].attributes.job_id).toBe(`sha256:${'a'.repeat(64)}`);
  });

  it('re-sanitizes custom sanitizeAttributes output inside exportToOtlp when allowRawPayloads is false', async () => {
    const capturedBodies: string[] = [];
    const origFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: unknown, init?: { body?: string }) => {
      if (init?.body) capturedBodies.push(init.body);
      return { ok: true } as Response;
    }) as typeof fetch;

    try {
      await exportToOtlp(
        'http://localhost:4318/v1/traces',
        {
          id: 'span-custom-cb-1',
          name: 'analyze_paystub',
          startTime: 1000,
          endTime: 1010,
          durationMs: 10,
          status: 'OK',
          attributes: {},
          events: [],
        },
        'paystub-check',
        () => ({
          raw_leak: 'Alice Smith',
          job_id: 'alice@example.com',
          status: 'OK',
        }),
        false
      );

      await exportToOtlp(
        'http://localhost:4318/v1/traces',
        {
          id: 'span-custom-cb-2',
          name: 'analyze_paystub',
          startTime: 2000,
          endTime: 2010,
          durationMs: 10,
          status: 'OK',
          attributes: {},
          events: [],
        },
        'paystub-check',
        () => ({
          regular_hours: 40,
          raw_leak: 'should-redact',
        }),
        false,
        ['regular_hours']
      );

      expect(capturedBodies).toHaveLength(2);
      const firstAttrs = Object.fromEntries(
        JSON.parse(capturedBodies[0]).resourceSpans[0].scopeSpans[0].spans[0].attributes.map(
          (a: { key: string; value: Record<string, unknown> }) => [a.key, a.value]
        )
      );
      expect(firstAttrs.raw_leak).toBeUndefined();
      expect(firstAttrs.job_id).toEqual({ stringValue: '[REDACTED_SENSITIVE_VALUE]' });
      expect(firstAttrs.status).toEqual({ stringValue: 'OK' });

      const secondAttrs = Object.fromEntries(
        JSON.parse(capturedBodies[1]).resourceSpans[0].scopeSpans[0].spans[0].attributes.map(
          (a: { key: string; value: Record<string, unknown> }) => [a.key, a.value]
        )
      );
      expect(secondAttrs.regular_hours).toEqual({ intValue: 40 });
      expect(secondAttrs.raw_leak).toBeUndefined();
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it('Enforces closed rule_id/rule_ids and base_model catalogs with opaque hmac/sha256 digest support', () => {
    const { sanitize } = createAllowlistSanitizer(['rule_id', 'rule_ids', 'base_model']);

    // Unregistered lookalikes and arbitrary tenant/PHI strings must be redacted fail-closed
    expect(sanitize({ rule_id: 'PATIENT_HAS_HIV' }).rule_id).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitize({ rule_ids: ['AR-001', 'PATIENT_HAS_HIV'] }).rule_ids).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitize({ rule_ids: 'AR-001,PATIENT_HAS_HIV' }).rule_ids).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitize({ base_model: 'Tenant_Acme' }).base_model).toBe('[REDACTED_SENSITIVE_VALUE]');

    // Approved catalog models, state-suffixed rules, and full sha256/hmac digests pass
    const fullSha256 = `sha256:${'a'.repeat(64)}`;
    const digitRunSha256 = `sha256:123456789${'a'.repeat(55)}`;
    const hmac16 = 'hmac:0123456789abcdef';
    expect(sanitize({ base_model: 'google/gemma-2-2b-it' }).base_model).toBe('google/gemma-2-2b-it');
    expect(sanitize({ base_model: 'microsoft/BitNet-b1.58-2B-4T' }).base_model).toBe('microsoft/BitNet-b1.58-2B-4T');
    expect(sanitize({ base_model: fullSha256 }).base_model).toBe(fullSha256);
    expect(sanitize({ base_model: digitRunSha256 }).base_model).toBe(digitRunSha256);
    expect(sanitize({ base_model: hmac16 }).base_model).toBe(hmac16);

    expect(sanitize({ rule_id: 'state_daily_overtime_CA' }).rule_id).toBe('state_daily_overtime_CA');
    expect(sanitize({ rule_id: 'state_implied_override_TX' }).rule_id).toBe('state_implied_override_TX');
    expect(sanitize({ rule_id: fullSha256 }).rule_id).toBe(fullSha256);
    expect(sanitize({ rule_id: digitRunSha256 }).rule_id).toBe(digitRunSha256);
    expect(sanitize({ rule_id: hmac16 }).rule_id).toBe(hmac16);
    expect(sanitize({ rule_ids: ['state_daily_overtime_CA', digitRunSha256] }).rule_ids).toBe(
      `state_daily_overtime_CA,${digitRunSha256}`
    );
    expect(sanitize({ rule_ids: `AR-001,${digitRunSha256}` }).rule_ids).toBe(
      `AR-001,${digitRunSha256}`
    );
  });

  it('Validates service.instance.id explicitly and strips sensitive unregistered key names', () => {
    const { sanitize } = createAllowlistSanitizer(['service.instance.id', 'extension.rule_id']);
    const digitRunSha256 = `sha256:123456789${'a'.repeat(55)}`;

    expect(sanitize({ 'service.instance.id': '550e8400-e29b-41d4-a716-446655440000' })['service.instance.id']).toBe(
      '550e8400-e29b-41d4-a716-446655440000'
    );
    expect(sanitize({ 'service.instance.id': '0123456789abcdef0123456789abcdef' })['service.instance.id']).toBe(
      '0123456789abcdef0123456789abcdef'
    );
    expect(sanitize({ 'service.instance.id': digitRunSha256 })['service.instance.id']).toBe(digitRunSha256);
    expect(sanitize({ 'service.instance.id': 'ALICE_SMITH' })['service.instance.id']).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitize({ 'service.instance.id': 'alice-macbook-1a2b' })['service.instance.id']).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitize({ 'extension.rule_id': digitRunSha256 })['extension.rule_id']).toBe(digitRunSha256);

    const sensitiveKeySanitized = sanitize({
      'alice@example.com': 'x',
      '/Users/alice/secret.txt': 'y',
      'Tenant owes $1500': 'z',
      Jane_Doe_HIV_positive: true,
    });
    expect('alice@example.com' in sensitiveKeySanitized).toBe(false);
    expect('/Users/alice/secret.txt' in sensitiveKeySanitized).toBe(false);
    expect('Tenant owes $1500' in sensitiveKeySanitized).toBe(false);
    expect('Jane_Doe_HIV_positive' in sensitiveKeySanitized).toBe(false);
    expect(sensitiveKeySanitized['[REDACTED_KEY]']).toBe('[REDACTED_BY_DEFAULT_ALLOWLIST]');

    const { sanitize: sanitizeError } = createAllowlistSanitizer(['error_code', 'error_type']);
    expect(sanitizeError({ error_code: 'ACME_CORPORATION' }).error_code).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitizeError({ error_type: 'AcmeError' }).error_type).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitizeError({ error_code: 'acme_corp' }).error_code).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitizeError({ error_code: 'HTTP_503' }).error_code).toBe('HTTP_503');
    expect(sanitizeError({ error_type: 'TimeoutError' }).error_type).toBe('TimeoutError');
    expect(sanitizeError({ error_code: digitRunSha256 }).error_code).toBe(digitRunSha256);

    const statusMgr = new TelemetryManager({ mode: 'memory_only' });
    const statusSpan = statusMgr.startSpan('scan_started');
    (statusSpan.end as (status?: string) => void)('Patient Jane Doe');
    expect(statusMgr.getBufferedSpans()[0].status).toBe('UNSET');
  });

  it('requires closed custom value domains or opaque digests and rechecks tombstone after getter sanitization (CodeRabbit R12)', async () => {
    // 1. Key registration alone rejects prohibited keys and refuses raw tokens on unreviewed suffix keys
    const { allowlist: customAllowlist, sanitize } = createAllowlistSanitizer([
      'tenant',
      'employee_ssn',
      'redflag_count',
      'matched_count',
      'ssn_count',
      'arbitrary_custom_count',
      'is_patient_pregnant',
      'has_income_verified',
    ]);
    expect(customAllowlist.has('tenant')).toBe(false);
    expect(customAllowlist.has('employee_ssn')).toBe(false);
    expect(customAllowlist.has('ssn_count')).toBe(false);
    expect(customAllowlist.has('is_patient_pregnant')).toBe(false);

    expect(sanitize({ tenant: 'ACME_CORP' })).toEqual({ '[REDACTED_KEY]': REDACTED_NOT_ALLOWLISTED });
    expect(sanitize({ tenant: 'hmac:0123456789abcdef' })).toEqual({ '[REDACTED_KEY]': REDACTED_NOT_ALLOWLISTED });
    expect(sanitize({ employee_ssn: 123456789 })).toEqual({ '[REDACTED_KEY]': REDACTED_NOT_ALLOWLISTED });
    expect(sanitize({ employee_ssn: true })).toEqual({ '[REDACTED_KEY]': REDACTED_NOT_ALLOWLISTED });
    expect(sanitize({ ssn_count: 123456789 })).toEqual({ '[REDACTED_KEY]': REDACTED_NOT_ALLOWLISTED });
    expect(sanitize({ matched_count: 42 }).matched_count).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitize({ arbitrary_custom_count: 42 }).arbitrary_custom_count).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitize({ is_patient_pregnant: true })).toEqual({ '[REDACTED_KEY]': REDACTED_NOT_ALLOWLISTED });
    expect(sanitize({ redflag_count: 42 }).redflag_count).toBe(42);
    expect(sanitize({ has_income_verified: true }).has_income_verified).toBe(true);
    expect(sanitize({ has_income_verified: 150000 }).has_income_verified).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(sanitize({ employee_ssn: 123456789 }, true).employee_ssn).toBe(123456789);
    expect(sanitize({ ssn_count: 123456789 }, true).ssn_count).toBe(123456789);
    expect(sanitize({ tenant: 'ACME_CORP' }, true).tenant).toBe('ACME_CORP');

    // Explicit custom value domain admits keyed HMAC digests under default mode and rejects unsalted sha256 or cleartext unless allowRawPayloads is true
    const sampleHmacTier = 'hmac:0123456789abcdef';
    const sampleHmacReport = 'hmac:fedcba9876543210';
    const sampleShaReport = `sha256:${'a'.repeat(64)}`;
    const { sanitize: sanitizeClosed } = createAllowlistSanitizer(
      ['subscription_tier', 'document_path', 'report_path'],
      {
        subscription_tier: ['tier_free', 'tier_pro', sampleHmacTier],
        report_path: ['run-12.log', sampleHmacReport, sampleShaReport],
      }
    );
    expect(sanitizeClosed({ subscription_tier: sampleHmacTier }).subscription_tier).toBe(
      sampleHmacTier
    );
    expect(sanitizeClosed({ subscription_tier: 'tier_pro' }).subscription_tier).toBe(
      '[REDACTED_SENSITIVE_VALUE]'
    );
    expect(sanitizeClosed({ subscription_tier: 'tier_pro' }, true).subscription_tier).toBe(
      'tier_pro'
    );
    expect(sanitizeClosed({ subscription_tier: 'ACME_CORP' }).subscription_tier).toBe(
      '[REDACTED_SENSITIVE_VALUE]'
    );
    expect(sanitizeClosed({ subscription_tier: 123456789 }).subscription_tier).toBe(
      '[REDACTED_SENSITIVE_VALUE]'
    );
    expect(sanitizeClosed({ subscription_tier: true }).subscription_tier).toBe(
      '[REDACTED_SENSITIVE_VALUE]'
    );
    expect(sanitizeClosed({ subscription_tier: 123456789 }, true).subscription_tier).toBe(123456789);
    expect(sanitizeClosed({ document_path: 'Jane_Doe_HIV_positive.pdf' }).document_path).toBe(
      '[REDACTED_SENSITIVE_VALUE]'
    );
    expect(sanitizeClosed({ report_path: sampleHmacReport }).report_path).toBe(sampleHmacReport);
    expect(sanitizeClosed({ report_path: sampleShaReport }).report_path).toBe(
      REDACTED_SENSITIVE_VALUE
    );
    expect(sanitizeClosed({ report_path: sampleShaReport }, true).report_path).toBe(sampleShaReport);
    expect(sanitizeClosed({ report_path: 'run-12.log' }).report_path).toBe(
      '[REDACTED_SENSITIVE_VALUE]'
    );
    expect(sanitizeClosed({ report_path: 'run-12.log' }, true).report_path).toBe('run-12.log');

    // Custom value domains must NEVER authorize tenant/identity names when allowRawPayloads is false
    const { allowlist: blockedDomainAllowlist, sanitize: sanitizeBlockedTenantOnly } =
      createAllowlistSanitizer(undefined, {
        tenant: ['ACME_CORP'],
        tenant_name: ['Acme Corp'],
      });
    expect(blockedDomainAllowlist.has('tenant')).toBe(false);
    expect(blockedDomainAllowlist.has('tenant_name')).toBe(false);
    const blockedDomainResult = sanitizeBlockedTenantOnly({ tenant: 'ACME_CORP', tenant_name: 'Acme Corp' });
    expect('tenant' in blockedDomainResult).toBe(false);
    expect('tenant_name' in blockedDomainResult).toBe(false);
    expect(blockedDomainResult['[REDACTED_KEY]']).toBe('[REDACTED_BY_DEFAULT_ALLOWLIST]');

    const { allowlist: tenantWithKeyAllowlist, sanitize: sanitizeTenantWithKey } = createAllowlistSanitizer(['tenant'], {
      tenant: ['ACME_CORP'],
    });
    expect(tenantWithKeyAllowlist.has('tenant')).toBe(false);
    expect(sanitizeTenantWithKey({ tenant: 'ACME_CORP' })).toEqual({ '[REDACTED_KEY]': REDACTED_NOT_ALLOWLISTED });
    expect(sanitizeTenantWithKey({ tenant: 'hmac:0123456789abcdef' })).toEqual({
      '[REDACTED_KEY]': REDACTED_NOT_ALLOWLISTED,
    });
    expect(sanitizeTenantWithKey({ tenant: 'ACME_CORP' }, true).tenant).toBe('ACME_CORP');

    const tenantDomainMgr = new TelemetryManager(
      { mode: 'memory_only' },
      ['tenant'],
      { tenant: ['ACME_CORP'] }
    );
    tenantDomainMgr.startSpan('scan_started', { tenant: 'ACME_CORP' }).end('OK');
    expect(tenantDomainMgr.getBufferedSpans()[0].attributes).toEqual({
      '[REDACTED_KEY]': REDACTED_NOT_ALLOWLISTED,
    });

    // exportToOtlp enforces the same closed-schema and tenant-redaction rules
    const capturedBodies: string[] = [];
    const origFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: unknown, init?: { body?: string }) => {
      if (init?.body) capturedBodies.push(init.body);
      return { ok: true } as Response;
    }) as typeof fetch;
    try {
      await exportToOtlp(
        'http://localhost:4318/v1/traces',
        {
          id: 'span-custom-schema',
          name: 'scan_started',
          startTime: 1000,
          endTime: 1001,
          durationMs: 1,
          status: 'OK',
          attributes: { tenant: 'ACME_CORP' },
          events: [],
        },
        'knowthankyew-app',
        undefined,
        false,
        ['tenant'],
        { tenant: ['ACME_CORP'] }
      );
      expect(capturedBodies).toHaveLength(1);
      expect(capturedBodies[0]).not.toContain('ACME_CORP');
      expect(capturedBodies[0]).not.toContain('tenant');
      const attrs = JSON.parse(capturedBodies[0]).resourceSpans[0].scopeSpans[0].spans[0].attributes;
      expect(attrs.find((a: { key: string }) => a.key === 'tenant')).toBeUndefined();
      expect(attrs.find((a: { key: string }) => a.key === '[REDACTED_KEY]')).toBeUndefined();
    } finally {
      globalThis.fetch = origFetch;
    }

    // 2. Getter-triggered burn() inside end() or recordAuditEvent() runs in fresh realms and prevents repopulation or OTLP export
    await runCoreRealmScenario(`
      const fetchCallsAfterGetterBurn = [];
      globalThis.fetch = async (_url, init) => {
        if (init?.body) fetchCallsAfterGetterBurn.push(init.body);
        return { ok: true };
      };
      const { TelemetryManager: IsolatedTM } = core;
      const mgrA = new IsolatedTM({
        mode: 'otlp',
        otlpEndpoint: 'http://localhost:4318/v1/traces',
        burnEnabled: true,
      });
      const retainedSpansA = mgrA.getBufferedSpans();
      const mgrB = new IsolatedTM({ mode: 'memory_only', burnEnabled: true });

      const activeSpan = mgrA.startSpan('scan_started', { action: 'scan' });
      const getterExtra = Object.defineProperty({}, 'rule_id', {
        enumerable: true,
        get() {
          mgrB.burn();
          return 'AR-001';
        },
      });
      activeSpan.end('OK', getterExtra);

      assert.equal(mgrA.getBufferedSpans().length, 0);
      assert.equal(retainedSpansA.length, 0);
      assert.equal(mgrB.getBufferedSpans().length, 0);
      assert.equal(fetchCallsAfterGetterBurn.length, 0);
    `);

    // Genuine fresh realm so auditDetails getter actually runs and triggers the post-sanitization tombstone check.
    await runCoreRealmScenario(`
      const { TelemetryManager: IsolatedAuditTM } = core;
      const mgrC = new IsolatedAuditTM({ mode: 'memory_only', burnEnabled: true });
      let auditGetterCalled = false;
      const auditDetails = Object.defineProperty({}, 'rule_id', {
        enumerable: true,
        get() {
          auditGetterCalled = true;
          mgrC.burn();
          return 'AR-001';
        },
      });
      mgrC.recordAuditEvent('audit_performed', 'Audit via getter burn', auditDetails);
      assert.equal(auditGetterCalled, true);
      assert.equal(mgrC.getAuditLog().length, 0);
    `);

    // 3. Enforce networkEgress === 'allow_otlp', audit summary catalog, preparation error boundary, and pre-fetch burn checks
    await runCoreRealmScenario(`
      const egressFetchCalls = [];
      globalThis.fetch = async (_url, init) => {
        if (init?.body) egressFetchCalls.push(init.body);
        return { ok: true };
      };
      const {
        TelemetryManager: EgressTM,
        exportToOtlp: isolatedExport,
        markHardBurned: isolatedHardBurn,
      } = core;

      const deniedOtlpMgr = new EgressTM({
        mode: 'otlp',
        otlpEndpoint: 'http://localhost:4318/v1/traces',
        networkEgress: 'deny',
      });
      deniedOtlpMgr.startSpan('scan_started', { action: 'scan_started' }).end('OK');
      assert.equal(egressFetchCalls.length, 0);

      // Update config from memory_only while explicitly keeping networkEgress: 'deny' must still block OTLP export.
      const updatedDeniedMgr = new EgressTM({ mode: 'memory_only' });
      updatedDeniedMgr.updateConfig({
        mode: 'otlp',
        otlpEndpoint: 'http://localhost:4318/v1/traces',
        networkEgress: 'deny',
      });
      updatedDeniedMgr.startSpan('scan_started').end('OK');
      assert.equal(egressFetchCalls.length, 0);

      // Partial updateConfig omitting networkEgress (or attempting runtime OTLP escalation on a consumer instance)
      // must preserve existing 'deny' policy and never activate outbound OTLP export.
      const partialDeniedMgr = new EgressTM({ mode: 'memory_only', networkEgress: 'deny' });
      partialDeniedMgr.updateConfig({
        otlpEndpoint: 'http://localhost:4318/v1/traces',
      });
      assert.equal(partialDeniedMgr.getConfig().networkEgress, 'deny');
      partialDeniedMgr.startSpan('scan_started').end('OK');
      assert.equal(egressFetchCalls.length, 0);

      partialDeniedMgr.updateConfig({
        mode: 'otlp',
        otlpEndpoint: 'http://localhost:4318/v1/traces',
        networkEgress: 'allow_otlp',
      });
      // Dynamic claims honestly reflect configured OTLP state while runtime network dispatch remains blocked on consumer-initialized instances.
      assert.equal(partialDeniedMgr.getPrivacyClaims().isLocalOnlyHonest, false);
      partialDeniedMgr.startSpan('scan_started').end('OK');
      assert.equal(egressFetchCalls.length, 0);

      // Unsafe integers (e.g. 1e30) serialize as OTLP doubleValue instead of intValue.
      await isolatedExport(
        'http://localhost:4318/v1/traces',
        {
          id: 'span-safe-int',
          name: 'job.completed',
          startTime: 1000,
          endTime: 1001,
          durationMs: 1,
          status: 'OK',
          attributes: { loss: 1e30, step: 42 },
          events: [],
        },
        'knowthankyew-app',
        undefined,
        false,
        ['loss', 'step']
      );
      assert.equal(egressFetchCalls.length, 1);
      const numericAttrs = JSON.parse(egressFetchCalls[0]).resourceSpans[0].scopeSpans[0].spans[0].attributes;
      assert.deepEqual(numericAttrs.find((a) => a.key === 'loss')?.value, { doubleValue: 1e30 });
      assert.deepEqual(numericAttrs.find((a) => a.key === 'step')?.value, { intValue: 42 });
      egressFetchCalls.length = 0;

      // Preparation exceptions inside exportToOtlp must be absorbed fail-safe without rejecting or dispatching.
      await isolatedExport(
        'http://localhost:4318/v1/traces',
        {
          id: 'span-prep-throws',
          name: 'scan_started',
          startTime: 1000,
          endTime: 1001,
          durationMs: 1,
          status: 'OK',
          attributes: { action: 'scan_started' },
          events: [],
        },
        'knowthankyew-app',
        () => {
          throw new Error('simulated sanitizer failure');
        }
      );
      assert.equal(egressFetchCalls.length, 0);

      // Audit summaries come from the closed catalog when allowRawPayloads is false (arbitrary PII never retained).
      updatedDeniedMgr.recordAuditEvent('document_ingested', 'Patient Jane Doe, SSN 123-45-6789');
      updatedDeniedMgr.recordAuditEvent('unregistered_custom_action', 'Patient Jane Doe secret');
      const auditJson = updatedDeniedMgr.downloadSessionAuditJson();
      assert.equal(auditJson.includes('Jane Doe'), false);
      assert.equal(auditJson.includes('123-45-6789'), false);
      assert.equal(updatedDeniedMgr.getAuditLog()[1].action, '[REDACTED_ACTION]');
      assert.equal(updatedDeniedMgr.getAuditLog()[1].summary, '[REDACTED_AUDIT_SUMMARY]');

      // Domain getter is read only at construction; exportToOtlp aborts fetch if callbacks burn before dispatch.
      let domainReads = 0;
      const domainObj = Object.defineProperty({}, 'review_channel', {
        enumerable: true,
        get() {
          domainReads += 1;
          return ['approved'];
        },
      });
      const allowedOtlpMgr = new EgressTM(
        {
          mode: 'otlp',
          otlpEndpoint: 'http://localhost:4318/v1/traces',
          networkEgress: 'allow_otlp',
        },
        ['review_channel'],
        domainObj
      );
      assert.equal(domainReads, 1);
      allowedOtlpMgr.startSpan('scan_started', { review_channel: 'approved' }).end('OK');
      assert.equal(domainReads, 1);
      assert.equal(egressFetchCalls.length, 1);

      const burningDomain = Object.defineProperty({}, 'review_channel', {
        enumerable: true,
        get() {
          isolatedHardBurn();
          return ['approved'];
        },
      });
      await isolatedExport(
        'http://localhost:4318/v1/traces',
        {
          id: 'span-burn-in-domain',
          name: 'scan_started',
          startTime: 1000,
          endTime: 1001,
          durationMs: 1,
          status: 'OK',
          attributes: { review_channel: 'approved' },
          events: [],
        },
        'knowthankyew-app',
        undefined,
        false,
        ['review_channel'],
        burningDomain
      );
      assert.equal(egressFetchCalls.length, 1);
    `);

    // Final shouldAbort callback that burns the realm and returns false must still prevent fetch.
    await runCoreRealmScenario(`
      const fetchCalls = [];
      globalThis.fetch = async (_url, init) => {
        if (init?.body) fetchCalls.push(init.body);
        return { ok: true };
      };
      const { exportToOtlp: isolatedExport, markHardBurned: isolatedHardBurn } = core;
      let abortChecks = 0;
      await isolatedExport(
        'http://localhost:4318/v1/traces',
        {
          id: 'span-should-abort-burn',
          name: 'scan_started',
          startTime: 1000,
          endTime: 1001,
          durationMs: 1,
          status: 'OK',
          attributes: { action: 'scan_started' },
          events: [],
        },
        'knowthankyew-app',
        undefined,
        false,
        undefined,
        undefined,
        () => {
          abortChecks += 1;
          if (abortChecks === 2) {
            isolatedHardBurn();
          }
          return false;
        }
      );
      assert.equal(abortChecks, 2);
      assert.equal(fetchCalls.length, 0);
    `);
  });

  it('exempts prefixed 64-hex job_ids and dataset JSONL stems from SSN false positives while rejecting sensitive camelCase custom domains', () => {
    const shaJobWithDigits = `sha256:${'a'.repeat(20)}123456789${'b'.repeat(35)}`;
    const hmacJobWithDigits = `hmac:${'c'.repeat(20)}123456789${'d'.repeat(35)}`;
    const prefixedJobWithDigits = `job-${shaJobWithDigits}`;

    const planDigest = 'hmac:0123456789abcdef';
    const sanitizer = createAllowlistSanitizer(
      ['dataset_relative_path'],
      {
        tenantName: ['Acme Holdings'],
        employeeName: ['Jane Doe'],
        matchedText: ['binding arbitration'],
        planTier: ['standard', planDigest],
      }
    );

    const safeOut = sanitizer.sanitize({
      job_id: shaJobWithDigits,
      dataset_relative_path: `${shaJobWithDigits}.jsonl`,
      planTier: planDigest,
      tenantName: 'Acme Holdings',
      employeeName: 'Jane Doe',
      matchedText: 'binding arbitration',
    });
    expect(safeOut.job_id).toBe(shaJobWithDigits);
    expect(safeOut.dataset_relative_path).toBe(`${shaJobWithDigits}.jsonl`);
    expect(safeOut.planTier).toBe(planDigest);
    expect(safeOut.tenantName).toBeUndefined();
    expect(safeOut.employeeName).toBeUndefined();
    expect(safeOut.matchedText).toBeUndefined();
    expect(safeOut['[REDACTED_KEY]']).toBe(REDACTED_NOT_ALLOWLISTED);

    // Cleartext token in customValueDomains is redacted (never silently admitted under allowRawPayloads=false)
    const cleartextPlanOut = sanitizer.sanitize({
      planTier: 'standard',
    });
    expect(cleartextPlanOut.planTier).toBe(REDACTED_SENSITIVE_VALUE);

    const hmacOut = sanitizer.sanitize({
      job_id: hmacJobWithDigits,
      dataset_relative_path: `${prefixedJobWithDigits}.jsonl`,
    });
    expect(hmacOut.job_id).toBe(hmacJobWithDigits);
    expect(hmacOut.dataset_relative_path).toBe(`${prefixedJobWithDigits}.jsonl`);

    // Explicit additional allowlist keys still cannot register prohibited camelCase keys unless allowRawPayloads is true.
    const explicitProhibited = createAllowlistSanitizer(
      ['tenantName', 'employeeName', 'matchedText'],
      {
        tenantName: ['Acme Holdings'],
        employeeName: ['Jane Doe'],
        matchedText: ['binding arbitration'],
      }
    );
    expect(explicitProhibited.allowlist.has('tenantname')).toBe(false);
    expect(explicitProhibited.allowlist.has('employeename')).toBe(false);
    expect(explicitProhibited.allowlist.has('matchedtext')).toBe(false);
    const blockedOut = explicitProhibited.sanitize({
      tenantName: 'Acme Holdings',
      employeeName: 'Jane Doe',
      matchedText: 'binding arbitration',
    });
    expect(blockedOut).toEqual({ '[REDACTED_KEY]': REDACTED_NOT_ALLOWLISTED });

    const rawOut = explicitProhibited.sanitize(
      {
        tenantName: 'Acme Holdings',
        employeeName: 'Jane Doe',
        matchedText: 'binding arbitration',
      },
      true
    );
    expect(rawOut.tenantName).toBe('Acme Holdings');
    expect(rawOut.employeeName).toBe('Jane Doe');
    expect(rawOut.matchedText).toBe('binding arbitration');

    // Negative controls: real SSNs / non-opaque numeric IDs still redact.
    const ssnOut = sanitizer.sanitize({
      job_id: 'job-123456789',
      dataset_relative_path: 'job-123-45-6789.jsonl',
    });
    expect(ssnOut.job_id).toBe(REDACTED_SENSITIVE_VALUE);
    expect(ssnOut.dataset_relative_path).toBe(REDACTED_SENSITIVE_VALUE);
  });

  it('bounds TelemetryManager auditLog retention in a circular FIFO buffer', () => {
    const manager = new TelemetryManager({ mode: 'memory_only' });
    for (let i = 0; i < 505; i += 1) {
      manager.recordAuditEvent('rules_evaluated', 'Rule pass', { clause_count: i });
    }
    const entries = manager.getAuditLog();
    expect(entries).toHaveLength(500);
    expect(entries[0]?.details?.clause_count).toBe(5);
    expect(entries[499]?.details?.clause_count).toBe(504);
  });

  it('emits separate valid OTLP traceId/spanId, re-sanitizes pending spans after allowRawPayloads=false, and blocks PII in custom domains', async () => {
    // 1. Pending span captured while allowRawPayloads=true must re-sanitize on end() after updateConfig({ allowRawPayloads: false }).
    const policyMgr = new TelemetryManager({ mode: 'memory_only', allowRawPayloads: true });
    const pending = policyMgr.startSpan('Patient jane@example.com', {
      status: 'Patient jane@example.com',
      secret_note: 'private raw note',
    });
    policyMgr.updateConfig({ allowRawPayloads: false });
    pending.end('OK', { extra_secret: 'also raw' });
    const buffered = policyMgr.getBufferedSpans();
    expect(buffered).toHaveLength(1);
    expect(buffered[0].name).toBe('[REDACTED_SPAN_NAME]');
    expect(buffered[0].attributes.status).toBe('[REDACTED_SENSITIVE_VALUE]');
    expect(buffered[0].attributes.secret_note).toBeUndefined();
    expect(buffered[0].attributes.extra_secret).toBeUndefined();
    expect(buffered[0].attributes['[REDACTED_KEY]']).toBe(REDACTED_NOT_ALLOWLISTED);

    // 2. Custom value domains containing PII (email), PHI sentences, or cleartext tenant/channel names cannot bypass sanitization when allowRawPayloads is false.
    const validChannelDigest = 'hmac:0123456789abcdef';
    const piiDomainMgr = new TelemetryManager(
      { mode: 'memory_only', allowRawPayloads: false },
      undefined,
      {
        review_channel: [
          'jane@example.com',
          'Patient Jane Doe has HIV',
          'portal',
          'acme_holdings',
          validChannelDigest,
        ],
      }
    );
    piiDomainMgr
      .startSpan('scan_started', { review_channel: 'jane@example.com' })
      .end('OK');
    expect(piiDomainMgr.getBufferedSpans()[0].attributes.review_channel).toBe(
      REDACTED_SENSITIVE_VALUE
    );

    piiDomainMgr
      .startSpan('scan_started', { review_channel: 'Patient Jane Doe has HIV' })
      .end('OK');
    expect(piiDomainMgr.getBufferedSpans()[1].attributes.review_channel).toBe(
      REDACTED_SENSITIVE_VALUE
    );

    piiDomainMgr
      .startSpan('scan_started', { review_channel: 'portal' })
      .end('OK');
    expect(piiDomainMgr.getBufferedSpans()[2].attributes.review_channel).toBe(
      REDACTED_SENSITIVE_VALUE
    );

    piiDomainMgr
      .startSpan('scan_started', { review_channel: 'acme_holdings' })
      .end('OK');
    expect(piiDomainMgr.getBufferedSpans()[3].attributes.review_channel).toBe(
      REDACTED_SENSITIVE_VALUE
    );

    piiDomainMgr
      .startSpan('scan_started', { review_channel: validChannelDigest })
      .end('OK');
    expect(piiDomainMgr.getBufferedSpans()[4].attributes.review_channel).toBe(validChannelDigest);

    // Cleartext-only custom domain registration never authorizes cleartext tenant tokens under allowRawPayloads=false
    const cleartextOnlyDomainMgr = new TelemetryManager(
      { mode: 'memory_only', allowRawPayloads: false },
      undefined,
      { review_channel: ['acme_holdings'] }
    );
    cleartextOnlyDomainMgr
      .startSpan('scan_started', { review_channel: 'acme_holdings' })
      .end('OK');
    expect(cleartextOnlyDomainMgr.getBufferedSpans()[0].attributes.review_channel).not.toBe(
      'acme_holdings'
    );
    expect([REDACTED_SENSITIVE_VALUE, undefined]).toContain(
      cleartextOnlyDomainMgr.getBufferedSpans()[0].attributes.review_channel
    );

    // 3. Separate valid OTLP 32-hex traceId & 16-hex spanId + direct exportToOtlp PII domain check.
    const captured: Array<Record<string, unknown>> = [];
    const origFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
      if (init?.body && typeof init.body === 'string') {
        captured.push(JSON.parse(init.body) as Record<string, unknown>);
      }
      return { ok: true } as Response;
    }) as typeof fetch;

    try {
      await exportToOtlp(
        'http://localhost:4318/v1/traces',
        {
          id: '0123456789abcdef0123456789abcdef',
          name: 'scan_started',
          startTime: 1000,
          endTime: 1005,
          durationMs: 5,
          status: 'OK',
          attributes: { review_channel: 'jane@example.com' },
          events: [],
        },
        'knowthankyew-app',
        undefined,
        false,
        undefined,
        { review_channel: ['jane@example.com'] }
      );
      await exportToOtlp('http://localhost:4318/v1/traces', {
        id: '00000000000000000000000000000000',
        name: 'scan_started',
        startTime: 1000,
        endTime: 1005,
        durationMs: 5,
        status: 'OK',
        attributes: {},
        events: [],
      });
      await exportToOtlp(
        'http://localhost:4318/v1/traces',
        {
          id: 'fedcba9876543210fedcba9876543210',
          name: 'scan_started',
          startTime: 1000,
          endTime: 1005,
          durationMs: 5,
          status: 'OK',
          attributes: { review_channel: 'jane@example.com' },
          events: [],
        },
        'knowthankyew-app',
        undefined,
        false,
        ['review_channel'],
        { review_channel: ['jane@example.com', 'hmac:0123456789abcdef'] }
      );

      expect(captured).toHaveLength(3);
      const span1 = (captured[0] as {
        resourceSpans: Array<{
          scopeSpans: Array<{
            spans: Array<{ traceId: string; spanId: string; attributes: Array<{ key: string; value: { stringValue: string } }> }>;
          }>;
        }>;
      }).resourceSpans[0].scopeSpans[0].spans[0];
      expect(span1.traceId).toBe('0123456789abcdef0123456789abcdef');
      expect(span1.spanId).toMatch(/^[0-9a-f]{16}$/);
      expect(span1.spanId).not.toBe('0000000000000000');
      expect(span1.attributes).toEqual([]);

      const span2 = (captured[1] as typeof span1 extends never ? never : {
        resourceSpans: Array<{
          scopeSpans: Array<{ spans: Array<{ traceId: string; spanId: string }> }>;
        }>;
      }).resourceSpans[0].scopeSpans[0].spans[0];
      expect(span2.traceId).toMatch(/^[0-9a-f]{32}$/);
      expect(span2.traceId).not.toBe('00000000000000000000000000000000');
      expect(span2.spanId).toMatch(/^[0-9a-f]{16}$/);
      expect(span2.spanId).not.toBe('0000000000000000');

      const span3 = (captured[2] as typeof span1 extends never ? never : {
        resourceSpans: Array<{
          scopeSpans: Array<{
            spans: Array<{ traceId: string; spanId: string; attributes: Array<{ key: string; value: { stringValue: string } }> }>;
          }>;
        }>;
      }).resourceSpans[0].scopeSpans[0].spans[0];
      expect(span3.attributes).toContainEqual({
        key: 'review_channel',
        value: { stringValue: REDACTED_SENSITIVE_VALUE },
      });
    } finally {
      globalThis.fetch = origFetch;
    }

    // 4. Re-sanitizes audit details if a getter mutates allowRawPayloads from true to false,
    //    re-sanitizes span names after extraAttrs getter narrowing, and clears retained
    //    getBufferedSpans() references on burn() in an isolated realm.
    const getterAuditMgr = new TelemetryManager({
      mode: 'memory_only',
      allowRawPayloads: true,
      burnEnabled: true,
    });

    const dynamicDetails: Record<string, unknown> = {
      status: 'raw arbitrary text',
      secret_note: 'raw private note',
    };
    Object.defineProperty(dynamicDetails, 'rule_id', {
      enumerable: true,
      get() {
        getterAuditMgr.updateConfig({ allowRawPayloads: false });
        return 'AR-001';
      },
    });
    getterAuditMgr.recordAuditEvent('audit_performed', 'Audit with dynamic policy narrowing', dynamicDetails);
    const auditLog = getterAuditMgr.getAuditLog();
    expect(auditLog).toHaveLength(1);
    expect(auditLog[0].details?.status).toBe(REDACTED_SENSITIVE_VALUE);
    expect(auditLog[0].details?.secret_note).toBeUndefined();
    expect(auditLog[0].details?.['[REDACTED_KEY]']).toBe('[REDACTED_BY_DEFAULT_ALLOWLIST]');
    expect(auditLog[0].details?.rule_id).toBe('AR-001');

    // Re-sanitizes buffered span name when extraAttrs getter narrows allowRawPayloads during end().
    const spanGetterMgr = new TelemetryManager({
      mode: 'memory_only',
      allowRawPayloads: true,
    });
    const rawSpan = spanGetterMgr.startSpan('Patient jane@example.com', { secret_note: 'raw start attr' });
    const narrowingExtra: Record<string, unknown> = {};
    Object.defineProperty(narrowingExtra, 'rule_id', {
      enumerable: true,
      get() {
        spanGetterMgr.updateConfig({ allowRawPayloads: false });
        return 'AR-001';
      },
    });
    rawSpan.end('OK', narrowingExtra);
    const narrowedSpans = spanGetterMgr.getBufferedSpans();
    expect(narrowedSpans).toHaveLength(1);
    expect(narrowedSpans[0].name).toBe('[REDACTED_SPAN_NAME]');
    expect(narrowedSpans[0].attributes.secret_note).toBeUndefined();
    expect(narrowedSpans[0].attributes['[REDACTED_KEY]']).toBe('[REDACTED_BY_DEFAULT_ALLOWLIST]');
    expect(narrowedSpans[0].attributes.rule_id).toBe('AR-001');

    await runCoreRealmScenario(`
      const { TelemetryManager: RetainedTM } = core;
      const retainedMgr = new RetainedTM({ mode: 'memory_only', burnEnabled: true });
      retainedMgr.startSpan('scan_started', { action: 'scan' }).end('OK');
      const retainedBeforeBurn = retainedMgr.getBufferedSpans();
      assert.equal(retainedBeforeBurn.length, 1);
      retainedMgr.burn();
      assert.equal(retainedBeforeBurn.length, 0);
      assert.equal(retainedMgr.getBufferedSpans().length, 0);
    `);
  });

  it('R15 Hardening: rejects statute suffix smuggling in OTLP export, handles throwing shouldAbort, and respects getter disabled mode', async () => {
    const smuggledStatutes = [
      '42 USC 1.JaneDoe_HIV',
      '29 U.S.C. § 206_AliceSmith',
      '815 ILCS 601/Jane_Doe',
      'EU GDPR Art. 6.JaneDoe_HIV',
      'UK Consumer Rights Act 2015, Section 9.Secret',
    ];
    const validStatutes = [
      '26 C.F.R. § 1.501(r)-6',
      '29 C.F.R. § 541.602(a)(1)',
      'Or. Rev. Stat. § 646A.295',
      'Cal. Bus. & Prof. Code § 17602(a)(2)',
      '740 ILCS 14/',
    ];

    const mgr = new TelemetryManager({ mode: 'memory_only' });
    for (const s of smuggledStatutes) {
      expect(mgr.sanitizeAttributes({ statute_code: s }).statute_code).toBe(
        REDACTED_SENSITIVE_VALUE
      );
    }
    for (const s of validStatutes) {
      expect(mgr.sanitizeAttributes({ statute_code: s }).statute_code).toBe(s);
    }

    const origFetch = globalThis.fetch;
    const sentPayloads: Array<{
      resourceSpans: Array<{
        scopeSpans: Array<{
          spans: Array<{ attributes: Array<{ key: string; value: { stringValue: string } }> }>;
        }>;
      }>;
    }> = [];
    let fetchCalls = 0;
    globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
      fetchCalls++;
      if (init?.body && typeof init.body === 'string') {
        sentPayloads.push(JSON.parse(init.body));
      }
      return { ok: true } as Response;
    }) as typeof fetch;

    try {
      await exportToOtlp(
        'http://localhost:4318/v1/traces',
        {
          id: '0123456789abcdef0123456789abcdef',
          name: 'rules_evaluated',
          startTime: 1000,
          endTime: 1005,
          durationMs: 5,
          status: 'OK',
          attributes: {
            statute_code: '42 USC 1.JaneDoe_HIV',
            'app.version': '1.0.0-AcmeTenant',
          },
          events: [],
        },
        'knowthankyew-app',
        undefined,
        false,
        ['app.version']
      );
      expect(fetchCalls).toBe(1);
      expect(sentPayloads[0].resourceSpans[0].scopeSpans[0].spans[0].attributes).toContainEqual({
        key: 'statute_code',
        value: { stringValue: REDACTED_SENSITIVE_VALUE },
      });
      expect(sentPayloads[0].resourceSpans[0].scopeSpans[0].spans[0].attributes).toContainEqual({
        key: 'app.version',
        value: { stringValue: REDACTED_SENSITIVE_VALUE },
      });

      await expect(
        exportToOtlp(
          'http://localhost:4318/v1/traces',
          {
            id: '0123456789abcdef0123456789abcdef',
            name: 'scan_started',
            startTime: 1000,
            endTime: 1005,
            durationMs: 5,
            status: 'OK',
            attributes: { action: 'scan_started' },
            events: [],
          },
          'knowthankyew-app',
          undefined,
          false,
          undefined,
          undefined,
          () => {
            throw new Error('disposed session state');
          }
        )
      ).resolves.toBeUndefined();
      expect(fetchCalls).toBe(1);
    } finally {
      globalThis.fetch = origFetch;
    }

    const { sanitize: appVerSanitize } = createAllowlistSanitizer(['app.version']);
    expect(appVerSanitize({ 'app.version': '1.0.0-AcmeTenant' })['app.version']).toBe(
      REDACTED_SENSITIVE_VALUE
    );
    expect(appVerSanitize({ 'app.version': '1.0.0+AcmeTenant' })['app.version']).toBe(
      REDACTED_SENSITIVE_VALUE
    );
    expect(appVerSanitize({ 'app.version': '2.1.0-rc.1+0db0099' })['app.version']).toBe(
      '2.1.0-rc.1+0db0099'
    );

    const disabledByGetterMgr = new TelemetryManager({ mode: 'memory_only' });
    const pendingSpan = disabledByGetterMgr.startSpan('scan_started', { action: 'scan_started' });
    const disablingExtra: Record<string, unknown> = {};
    Object.defineProperty(disablingExtra, 'rule_id', {
      enumerable: true,
      get() {
        disabledByGetterMgr.updateConfig({ mode: 'disabled' });
        return 'AR-001';
      },
    });
    pendingSpan.end('OK', disablingExtra);
    expect(disabledByGetterMgr.getBufferedSpans()).toHaveLength(0);
  });

  it('R17 Hardening: preserves ID case when hashing, protects storage from frozen snapshots, and clears audit log cleanly', async () => {
    const capturedSpans: Array<{ traceId: string; spanId: string }> = [];
    const origFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
      const payload = JSON.parse(String(init?.body ?? '{}')) as {
        resourceSpans: Array<{ scopeSpans: Array<{ spans: Array<{ traceId: string; spanId: string }> }> }>;
      };
      capturedSpans.push(payload.resourceSpans[0].scopeSpans[0].spans[0]);
      return new Response('{}', { status: 200 });
    }) as typeof fetch;

    try {
      await exportToOtlp('http://localhost:4318/v1/traces', {
        id: 'span_A',
        name: 'scan_started',
        startTime: 1000,
        status: 'OK',
        attributes: {},
        events: [],
      });
      await exportToOtlp('http://localhost:4318/v1/traces', {
        id: 'span_a',
        name: 'scan_started',
        startTime: 1001,
        status: 'OK',
        attributes: {},
        events: [],
      });
    } finally {
      globalThis.fetch = origFetch;
    }

    expect(capturedSpans).toHaveLength(2);
    expect(capturedSpans[0].spanId).toMatch(/^[0-9a-f]{16}$/);
    expect(capturedSpans[1].spanId).toMatch(/^[0-9a-f]{16}$/);
    expect(capturedSpans[0].spanId).not.toBe(capturedSpans[1].spanId);
    expect(capturedSpans[0].traceId).toMatch(/^[0-9a-f]{32}$/);
    expect(capturedSpans[1].traceId).toMatch(/^[0-9a-f]{32}$/);
    expect(capturedSpans[0].traceId).not.toBe(capturedSpans[1].traceId);

    const resetMgr = new TelemetryManager({ mode: 'memory_only' });
    resetMgr.startSpan('scan_started', { action: 'scan_started' }).end('OK');
    resetMgr.recordAuditEvent('document_ingested', 'Doc loaded');
    const frozenAuditBeforeReset = resetMgr.getAuditLog();
    const frozenSpansBeforeReset = resetMgr.getBufferedSpans();
    Object.freeze(frozenAuditBeforeReset);
    Object.freeze(frozenSpansBeforeReset);

    expect(() => resetMgr.reset()).not.toThrow();
    expect(resetMgr.getAuditLog()).toHaveLength(0);
    expect(resetMgr.getBufferedSpans()).toHaveLength(0);
    expect(frozenAuditBeforeReset).toHaveLength(1);

    await runCoreRealmScenario(`
      const { TelemetryManager: IsolatedManager, MemoryExporter: IsolatedExporter, isHardBurned } = core;
      const burnMgr = new IsolatedManager({ mode: 'memory_only' });
      const retainedExporter = new IsolatedExporter();
      retainedExporter.export({ id: 'pre_burn', name: 'scan_started', startTime: 1000, status: 'OK', attributes: {}, events: [] });
      burnMgr.startSpan('scan_started', { action: 'scan_started' }).end('OK');
      burnMgr.recordAuditEvent('document_ingested', 'Doc loaded');
      const frozenAuditBeforeBurn = burnMgr.getAuditLog();
      const frozenSpansBeforeBurn = burnMgr.getBufferedSpans();
      Object.freeze(frozenAuditBeforeBurn);
      Object.freeze(frozenSpansBeforeBurn);

      burnMgr.burn();
      assert.equal(isHardBurned(), true);
      assert.equal(burnMgr.getAuditLog().length, 0);
      assert.equal(burnMgr.getBufferedSpans().length, 0);
      assert.equal(frozenAuditBeforeBurn.length, 1);

      retainedExporter.export({ id: 'post_burn', name: 'scan_started', startTime: 1001, status: 'OK', attributes: {}, events: [] });
      assert.equal(retainedExporter.count(), 0);
      assert.equal(retainedExporter.getSpans().length, 0);
    `);
  });

  it('R21 Hardening: requires keyed HMAC on generic *_path keys and rejects unsalted sha256', () => {
    const unsaltedSha = `sha256:${'b'.repeat(64)}`;
    const shortHmac = 'hmac:0123456789abcdef';
    const fullHmac = `hmac:${'c'.repeat(64)}`;
    const { sanitize } = createAllowlistSanitizer(['artifact_path', 'report_path']);

    expect(sanitize({ artifact_path: unsaltedSha }).artifact_path).toBe(REDACTED_SENSITIVE_VALUE);
    expect(sanitize({ report_path: unsaltedSha }).report_path).toBe(REDACTED_SENSITIVE_VALUE);
    expect(sanitize({ artifact_path: shortHmac }).artifact_path).toBe(shortHmac);
    expect(sanitize({ artifact_path: fullHmac }).artifact_path).toBe(fullHmac);
    expect(sanitize({ report_path: shortHmac }).report_path).toBe(shortHmac);
    expect(sanitize({ artifact_path: unsaltedSha }, true).artifact_path).toBe(unsaltedSha);
  });

  it('R21 Hardening: burn scrubs retained spans inside a frozen live getBufferedSpans array and surfaces immutable failures', async () => {
    await runCoreRealmScenario(`
      const { TelemetryManager: IsolatedManager, isHardBurned } = core;
      const mgr = new IsolatedManager({ mode: 'memory_only', allowRawPayloads: true });
      mgr.startSpan('scan_started', { secret_note: 'confidential patient detail' }).end('OK');

      const frozenLiveSpans = mgr.getBufferedSpans();
      assert.equal(frozenLiveSpans.length, 1);
      assert.equal(frozenLiveSpans[0].attributes.secret_note, 'confidential patient detail');
      Object.freeze(frozenLiveSpans);

      mgr.burn();
      assert.equal(isHardBurned(), true);
      assert.equal(mgr.getBufferedSpans().length, 0);
      assert.equal(frozenLiveSpans[0].attributes.secret_note, undefined);
      assert.equal(Object.keys(frozenLiveSpans[0].attributes).length, 0);
      assert.equal(frozenLiveSpans[0].name, '[REDACTED_SPAN_NAME]');
      assert.equal(frozenLiveSpans[0].id, '[REDACTED]');
    `);

    await runCoreRealmScenario(`
      const { TelemetryManager: IsolatedManager, isHardBurned } = core;
      const mgr = new IsolatedManager({ mode: 'memory_only', allowRawPayloads: true });
      mgr.startSpan('scan_started', { secret_note: 'immutable secret' }).end('OK');

      const frozenLiveSpans = mgr.getBufferedSpans();
      Object.freeze(frozenLiveSpans[0].attributes);
      Object.freeze(frozenLiveSpans);

      assert.throws(() => mgr.burn(), /could not scrub immutable retained span data/i);
      assert.equal(isHardBurned(), true);
      assert.equal(mgr.getBufferedSpans().length, 0);
    `);
  });

  it('R22 Hardening: reports scrub failures for frozen top-level spans or detached frozen attributes even when array clears', async () => {
    await runCoreRealmScenario(`
      const { TelemetryManager: IsolatedManager, isHardBurned } = core;
      const mgr = new IsolatedManager({ mode: 'memory_only', allowRawPayloads: true });
      mgr.startSpan('confidential_custom_span_name', {}).end('OK');

      const frozenArrayWithFrozenSpan = mgr.getBufferedSpans();
      Object.freeze(frozenArrayWithFrozenSpan[0]);
      Object.freeze(frozenArrayWithFrozenSpan);

      assert.throws(() => mgr.burn(), /could not scrub immutable retained span data/i);
      assert.equal(isHardBurned(), true);
      assert.equal(frozenArrayWithFrozenSpan[0].name, 'confidential_custom_span_name');
    `);

    await runCoreRealmScenario(`
      const { TelemetryManager: IsolatedManager, isHardBurned } = core;
      const mgr = new IsolatedManager({ mode: 'memory_only', allowRawPayloads: true });
      mgr.startSpan('scan_started', { secret_note: 'retained standalone ref' }).end('OK');

      const detachedSpanRef = mgr.getBufferedSpans()[0];
      Object.freeze(detachedSpanRef.attributes);

      assert.throws(() => mgr.burn(), /could not scrub immutable retained span data/i);
      assert.equal(isHardBurned(), true);
      assert.equal(mgr.getBufferedSpans().length, 0);
      assert.equal(detachedSpanRef.attributes.secret_note, 'retained standalone ref');
    `);
  });

  it('R22 Hardening: burn scrubs issued getAuditLog copies, rejects immutable copies, and propagates peer-manager failures', async () => {
    await runCoreRealmScenario(`
      const { TelemetryManager: IsolatedManager, isHardBurned } = core;
      const mgr = new IsolatedManager({ mode: 'memory_only', allowRawPayloads: true });
      mgr.recordAuditEvent('document_ingested', 'Private client memo', { secret_note: 'Alice Doe DOB' });
      const issuedAudit = mgr.getAuditLog();
      assert.equal(issuedAudit.length, 1);
      assert.equal(issuedAudit[0].summary, 'Private client memo');
      assert.equal(issuedAudit[0].details.secret_note, 'Alice Doe DOB');

      mgr.burn();
      assert.equal(isHardBurned(), true);
      assert.equal(mgr.getAuditLog().length, 0);
      assert.equal(issuedAudit[0].summary, '[REDACTED_AUDIT_SUMMARY]');
      assert.equal(issuedAudit[0].details.secret_note, undefined);
      assert.equal(Object.keys(issuedAudit[0].details).length, 0);
    `);

    await runCoreRealmScenario(`
      const { TelemetryManager: IsolatedManager, isHardBurned, onHardBurn } = core;
      const mgrA = new IsolatedManager({ mode: 'memory_only', allowRawPayloads: true });
      const mgrB = new IsolatedManager({ mode: 'memory_only', allowRawPayloads: true });
      const mgrC = new IsolatedManager({ mode: 'memory_only', allowRawPayloads: true });

      mgrA.startSpan('scan_started', { secret_note: 'immutable peer secret' }).end('OK');
      const leakedPeerSpan = mgrA.getBufferedSpans()[0];
      Object.freeze(leakedPeerSpan.attributes);

      mgrA.recordAuditEvent('document_ingested', 'Peer immutable audit', { secret_note: 'frozen detail' });
      const peerAudit = mgrA.getAuditLog();
      Object.freeze(peerAudit[0].details);

      mgrB.startSpan('scan_started', { secret_note: 'mgrB secret' }).end('OK');
      mgrC.startSpan('scan_started', { secret_note: 'mgrC secret' }).end('OK');
      const mgrCSpanRef = mgrC.getBufferedSpans()[0];

      let notified = 0;
      onHardBurn(() => {
        notified += 1;
      });

      assert.throws(() => mgrB.burn(), /could not scrub immutable retained/i);
      assert.equal(isHardBurned(), true);
      assert.equal(notified, 1);
      assert.equal(mgrB.getBufferedSpans().length, 0);
      assert.equal(mgrC.getBufferedSpans().length, 0);
      assert.equal(mgrCSpanRef.attributes.secret_note, undefined);
    `);
  });

  it('R23 Hardening: customValueDomains rejects sensitive or invalid keys regardless of opaque digest values', () => {
    const digest = 'hmac:0123456789abcdef';
    const unsafeKeys = [
      '123-45-6789',
      'alice@example.com',
      'prefix_123-45-6789',
      'tok_sk-1234567890abcdef',
      'invalid key!',
    ];

    const sanitizer = createAllowlistSanitizer(undefined, {
      '123-45-6789': [digest],
      'alice@example.com': [digest],
      'prefix_123-45-6789': [digest],
      'tok_sk-1234567890abcdef': [digest],
      'invalid key!': [digest],
      safe_tier: [digest],
    });

    expect(sanitizer.allowlist.has('safe_tier')).toBe(true);
    for (const unsafeKey of unsafeKeys) {
      expect(sanitizer.allowlist.has(unsafeKey.toLowerCase())).toBe(false);
    }

    const out = sanitizer.sanitize({
      '123-45-6789': digest,
      'alice@example.com': digest,
      'prefix_123-45-6789': digest,
      'tok_sk-1234567890abcdef': digest,
      'invalid key!': digest,
      safe_tier: digest,
    });
    expect(out.safe_tier).toBe(digest);
    expect(out['[REDACTED_KEY]']).toBe(REDACTED_NOT_ALLOWLISTED);
    for (const unsafeKey of unsafeKeys) {
      expect(out[unsafeKey]).toBeUndefined();
    }

    const cleartextBlocked = sanitizer.sanitize({ safe_tier: 'cleartext_tier' });
    expect(cleartextBlocked.safe_tier).toBe(REDACTED_SENSITIVE_VALUE);

    const rawMode = sanitizer.sanitize({ 'prefix_123-45-6789': digest }, true);
    expect(rawMode['prefix_123-45-6789']).toBe(digest);
    expect(sanitizer.allowlist.has('prefix_123-45-6789')).toBe(false);
  });

  it('R23 Hardening: burn latches hard-burn before cleanup getters, scrubs evicted frozen spans, and scrubs detached details objects', async () => {
    // 1. Evicted frozen SpanRecord from MemoryExporter.getSpans() is still scrubbed on clear()/burn()
    await runCoreRealmScenario(`
      const { MemoryExporter, TelemetryManager: IsolatedManager } = core;
      const exporter = new MemoryExporter(1, { allowRawPayloads: true });
      exporter.export({
        name: 'scan_started',
        startTime: 1,
        endTime: 2,
        durationMs: 1,
        attributes: { secret_note: 'evicted sensitive note' },
        events: [],
        status: 'OK',
      });
      const retainedEvicted = exporter.getSpans();
      Object.freeze(retainedEvicted);
      exporter.export({
        name: 'scan_completed',
        startTime: 3,
        endTime: 4,
        durationMs: 1,
        attributes: { secret_note: 'latest sensitive note' },
        events: [],
        status: 'OK',
      });
      assert.equal(retainedEvicted.length, 1);
      assert.equal(retainedEvicted[0].attributes.secret_note, 'evicted sensitive note');

      const mgr = new IsolatedManager({ mode: 'memory_only', allowRawPayloads: true });
      exporter.clear();
      assert.equal(retainedEvicted[0].attributes.secret_note, undefined);
      assert.equal(retainedEvicted[0].name, '[REDACTED_SPAN_NAME]');
      mgr.burn();
    `);

    // 2. Detaching details from an issued getAuditLog() entry still scrubs the originally issued details object
    await runCoreRealmScenario(`
      const { TelemetryManager: IsolatedManager, isHardBurned } = core;
      const mgr = new IsolatedManager({ mode: 'memory_only', allowRawPayloads: true });
      mgr.recordAuditEvent('document_ingested', 'Private client memo', { secret_note: 'detached secret' });
      const issuedAudit = mgr.getAuditLog();
      const leakedDetails = issuedAudit[0].details;
      issuedAudit[0].details = {};

      mgr.burn();
      assert.equal(isHardBurned(), true);
      assert.equal(leakedDetails.secret_note, undefined);
      assert.equal(Object.keys(leakedDetails).length, 0);
      assert.equal(issuedAudit[0].summary, '[REDACTED_AUDIT_SUMMARY]');
    `);

    // 3. Throwing audit details getter cannot trigger peer OTLP fetch because realm burn latches first, and remaining data still scrubs
    await runCoreRealmScenario(`
      const { TelemetryManager: IsolatedManager, isHardBurned } = core;
      let fetchCount = 0;
      globalThis.fetch = async () => {
        fetchCount += 1;
        return { ok: true };
      };

      const peerOtlpMgr = new IsolatedManager({
        mode: 'otlp',
        otlpEndpoint: 'http://localhost:4318/v1/traces',
        networkEgress: 'allow_otlp',
      });
      const mgr = new IsolatedManager({ mode: 'memory_only', allowRawPayloads: true });
      mgr.startSpan('scan_started', { secret_note: 'span secret' }).end('OK');
      const spanRef = mgr.getBufferedSpans()[0];

      mgr.recordAuditEvent('document_ingested', 'First audit', { secret_note: 'first secret' });
      mgr.recordAuditEvent('audit_performed', 'Second audit', { secret_note: 'second secret' });
      const issuedAudit = mgr.getAuditLog();

      Object.defineProperty(issuedAudit[0], 'details', {
        configurable: true,
        enumerable: true,
        get() {
          peerOtlpMgr.startSpan('scan_started', { action: 'scan_started' }).end('OK');
          throw new Error('Audit details getter aborted cleanup');
        },
      });

      assert.throws(() => mgr.burn(), /Audit details getter aborted cleanup/);
      assert.equal(isHardBurned(), true);
      assert.equal(fetchCount, 0);
      assert.equal(issuedAudit[0].summary, '[REDACTED_AUDIT_SUMMARY]');
      assert.equal(issuedAudit[1].summary, '[REDACTED_AUDIT_SUMMARY]');
      assert.equal(issuedAudit[1].details.secret_note, undefined);
      assert.equal(spanRef.attributes.secret_note, undefined);
    `);

    // 4. Frozen SpanRecord still allows hard-burn latch and audit log scrubbing
    await runCoreRealmScenario(`
      const { TelemetryManager: IsolatedManager, isHardBurned } = core;
      const mgr = new IsolatedManager({ mode: 'memory_only', allowRawPayloads: true });
      mgr.startSpan('scan_started', { secret_note: 'frozen span secret' }).end('OK');
      Object.freeze(mgr.getBufferedSpans()[0]);
      mgr.recordAuditEvent('document_ingested', 'Should still scrub', { secret_note: 'audit secret' });
      const issuedAudit = mgr.getAuditLog();

      assert.throws(() => mgr.burn(), /could not scrub immutable retained span data/i);
      assert.equal(isHardBurned(), true);
      assert.equal(issuedAudit[0].summary, '[REDACTED_AUDIT_SUMMARY]');
      assert.equal(issuedAudit[0].details.secret_note, undefined);
    `);
  });

  it('R24 Hardening: burn clears standalone MemoryExporter instances and OTLP export forwards registered extension keys', async () => {
    await runCoreRealmScenario(`
      const { MemoryExporter, TelemetryManager: IsolatedManager, isHardBurned } = core;
      const payloads = [];
      globalThis.fetch = async (_url, init) => {
        if (init?.body) {
          payloads.push(JSON.parse(init.body));
        }
        return { ok: true };
      };

      const standalone = new MemoryExporter(10, { allowRawPayloads: true });
      standalone.export({
        name: 'scan_started',
        startTime: 10,
        endTime: 20,
        durationMs: 10,
        attributes: { secret_note: 'standalone leaked text', tenant: 'ACME Corp' },
        events: [],
        status: 'OK',
      });
      const retainedStandalone = standalone.getSpans();
      const retainedRecord = retainedStandalone[0];
      assert.equal(standalone.count(), 1);
      assert.equal(retainedRecord.attributes.secret_note, 'standalone leaked text');

      const defaultSafeStandalone = new MemoryExporter(10);
      defaultSafeStandalone.export({
        name: 'scan_started',
        startTime: 10,
        endTime: 20,
        durationMs: 10,
        attributes: { raw_text: 'private document', tenant: 'ACME Corp', action: 'scan_started' },
        events: [],
        status: 'OK',
      });
      const safeStandaloneSpans = defaultSafeStandalone.getSpans();
      assert.equal(safeStandaloneSpans.length, 1);
      assert.equal(safeStandaloneSpans[0].attributes.raw_text, undefined);
      assert.equal(safeStandaloneSpans[0].attributes.tenant, undefined);
      assert.equal(safeStandaloneSpans[0].attributes['[REDACTED_KEY]'], core.REDACTED_NOT_ALLOWLISTED);
      assert.equal(safeStandaloneSpans[0].attributes.action, 'scan_started');

      const mgr = new IsolatedManager(
        {
          mode: 'otlp',
          otlpEndpoint: 'http://localhost:4318/v1/traces',
          networkEgress: 'allow_otlp',
        },
        ['line_count']
      );
      mgr.startSpan('scan_started', { line_count: 3, unrecognized_secret: 'drop me' }).end('OK');
      await new Promise((r) => setTimeout(r, 15));

      assert.equal(payloads.length, 1);
      const attrs = payloads[0].resourceSpans[0].scopeSpans[0].spans[0].attributes;
      const lineCountAttr = attrs.find((a) => a.key === 'line_count');
      assert.equal(lineCountAttr?.value?.intValue, 3);
      assert.equal(attrs.find((a) => a.key === 'unrecognized_secret'), undefined);

      mgr.burn();
      assert.equal(isHardBurned(), true);
      assert.equal(standalone.count(), 0);
      assert.equal(standalone.getSpans().length, 0);
      assert.equal(retainedStandalone.length, 0);
      assert.equal(retainedRecord.name, '[REDACTED_SPAN_NAME]');
      assert.equal(retainedRecord.attributes.secret_note, undefined);
      assert.equal(retainedRecord.attributes.tenant, undefined);
    `);
  });

  it('R25 Hardening: burn scrubs evicted SpanRecord objects and prevents reentrant burn stack overflow', async () => {
    // 1. Evicted non-frozen SpanRecord without getSpans() array freeze is still scrubbed on clear() and burn()
    await runCoreRealmScenario(`
      const { MemoryExporter, TelemetryManager: IsolatedManager, isHardBurned } = core;
      const exp = new MemoryExporter(1, { allowRawPayloads: true });
      const evictedSpan = {
        id: 'evicted-span-1',
        name: 'scan_started',
        startTime: 100,
        endTime: 120,
        durationMs: 20,
        attributes: { secret_note: 'evicted non-frozen secret', tenant: 'ACME Corp' },
        events: [{ name: 'secret_evt', timestamp: 110, attributes: { raw_text: 'leaked evt' } }],
        status: 'OK',
      };
      exp.export(evictedSpan);
      exp.export({
        id: 'retained-span-2',
        name: 'scan_completed',
        startTime: 200,
        endTime: 220,
        durationMs: 20,
        attributes: { action: 'scan_completed' },
        events: [],
        status: 'OK',
      });
      assert.equal(exp.count(), 1);
      assert.equal(evictedSpan.attributes.secret_note, 'evicted non-frozen secret');

      const mgr = new IsolatedManager({ mode: 'memory_only', allowRawPayloads: true });
      mgr.burn();
      assert.equal(isHardBurned(), true);
      assert.equal(exp.count(), 0);
      assert.equal(evictedSpan.name, '[REDACTED_SPAN_NAME]');
      assert.equal(evictedSpan.attributes.secret_note, undefined);
      assert.equal(evictedSpan.events.length, 0);
    `);

    // 2. Reentrant mgr.burn() inside an issued audit record details getter completes without stack overflow
    await runCoreRealmScenario(`
      const { TelemetryManager: IsolatedManager, isHardBurned } = core;
      const mgr = new IsolatedManager({ mode: 'memory_only', allowRawPayloads: true });

      mgr.startSpan('scan_started', { secret_note: 'outer span secret' }).end('OK');
      const outerSpan = mgr.getBufferedSpans()[0];
      mgr.recordAuditEvent('document_ingested', 'First memo', { secret_note: 'reentrant audit secret' });
      mgr.recordAuditEvent('audit_performed', 'Second memo', { secret_note: 'second audit secret' });
      const issued = mgr.getAuditLog();

      let nestedCalls = 0;
      const backingDetails = { secret_note: 'hidden getter secret' };
      Object.defineProperty(issued[0], 'details', {
        configurable: true,
        enumerable: true,
        get() {
          nestedCalls += 1;
          if (nestedCalls === 1) {
            mgr.burn();
          }
          return backingDetails;
        },
      });

      mgr.burn();
      assert.equal(isHardBurned(), true);
      assert.equal(nestedCalls, 1);
      assert.equal(outerSpan.attributes.secret_note, undefined);
      assert.equal(backingDetails.secret_note, undefined);
      assert.equal(issued[0].summary, '[REDACTED_AUDIT_SUMMARY]');
      assert.equal(issued[1].summary, '[REDACTED_AUDIT_SUMMARY]');
      assert.equal(issued[1].details.secret_note, undefined);
    `);

    // 3. Guard resets in finally after a getter error so later retry burn() passes execute cleanup
    await runCoreRealmScenario(`
      const { TelemetryManager: IsolatedManager, isHardBurned } = core;
      const mgrRetry = new IsolatedManager({ mode: 'memory_only', allowRawPayloads: true });
      let throwOnRetryTarget = true;
      const retryDetails = { secret_note: 'retry target secret' };
      mgrRetry.recordAuditEvent('document_ingested', 'Retry memo', { secret_note: 'ignored' });
      const retryIssued = mgrRetry.getAuditLog();
      Object.defineProperty(retryIssued[0], 'details', {
        configurable: true,
        enumerable: true,
        get() {
          if (throwOnRetryTarget) {
            throw new Error('Transient getter error');
          }
          return retryDetails;
        },
      });

      assert.throws(() => mgrRetry.burn(), /Transient getter error/);
      assert.equal(isHardBurned(), true);

      throwOnRetryTarget = false;
      mgrRetry.burn();
      assert.equal(retryDetails.secret_note, undefined);
      assert.equal(retryIssued[0].summary, '[REDACTED_AUDIT_SUMMARY]');
    `);
  });

  it('R26 Hardening: clear() drops trackedSpans so reused and later-evicted SpanRecords are scrubbed on burn()', async () => {
    await runCoreRealmScenario(`
      const { MemoryExporter, TelemetryManager: IsolatedManager } = core;
      const exporter = new MemoryExporter(1, { allowRawPayloads: true });
      const mgr = new IsolatedManager({ mode: 'memory_only' });

      const reusedSpan = {
        id: 'reused-1',
        name: 'scan_started',
        startTime: 1,
        endTime: 2,
        durationMs: 1,
        attributes: { secret_note: 'initial secret' },
        events: [],
        status: 'OK',
      };

      exporter.export(reusedSpan);
      exporter.clear();
      assert.equal(reusedSpan.attributes.secret_note, undefined);
      assert.equal(reusedSpan.name, '[REDACTED_SPAN_NAME]');

      reusedSpan.name = 'reused_after_clear';
      reusedSpan.attributes = { secret_note: 'repopulated after clear' };
      exporter.export(reusedSpan);

      exporter.export({
        id: 'keeper-2',
        name: 'scan_completed',
        startTime: 3,
        endTime: 4,
        durationMs: 1,
        attributes: { status: 'OK' },
        events: [],
        status: 'OK',
      });
      assert.equal(exporter.getSpans().length, 1);

      mgr.burn();
      assert.equal(reusedSpan.attributes.secret_note, undefined);
      assert.equal(reusedSpan.name, '[REDACTED_SPAN_NAME]');
    `);
  });

  it('R27 Hardening: scrubs detached span child containers on burn() and ignores frozen post-burn exports', async () => {
    await runCoreRealmScenario(`
      const { MemoryExporter, TelemetryManager: IsolatedManager } = core;
      const exporter = new MemoryExporter(2, { allowRawPayloads: true });
      const mgr = new IsolatedManager({ mode: 'memory_only', allowRawPayloads: true });

      const detachedAttrs = { raw_note: 'secret span attrs', pii: 'Alice Smith' };
      const detachedEvtAttrs = { event_secret: 'secret event payload' };
      const detachedEvt = {
        name: 'raw_event_name',
        timestamp: 42,
        attributes: detachedEvtAttrs,
      };
      const detachedEvents = [detachedEvt];
      const span = {
        id: 'detach-1',
        name: 'scan_started',
        startTime: 10,
        endTime: 20,
        durationMs: 10,
        attributes: detachedAttrs,
        events: detachedEvents,
        status: 'OK',
      };

      exporter.export(span);
      // Detach original attributes and events containers from the buffered span before burn()
      span.attributes = {};
      span.events = [];

      mgr.burn();

      assert.equal(detachedAttrs.raw_note, undefined);
      assert.equal(detachedAttrs.pii, undefined);
      assert.equal(detachedEvtAttrs.event_secret, undefined);
      assert.equal(detachedEvt.name, '[REDACTED]');
      assert.equal(detachedEvt.timestamp, 0);
      assert.equal(detachedEvents.length, 0);

      const postBurnFrozen = Object.freeze({
        id: 'frozen-post-burn',
        name: 'post_burn_span',
        startTime: 99,
        status: 'OK',
        attributes: Object.freeze({ raw_note: 'ignored' }),
        events: Object.freeze([]),
      });
      assert.doesNotThrow(() => exporter.export(postBurnFrozen));
      assert.equal(exporter.getSpans().length, 0);
    `);
  });

  it('R28 Hardening: contains throwing field/attribute getters during burn(), rechecks tombstone after tracking, and detects adjacent card numbers without lookbehind', async () => {
    expect(containsSensitivePattern('4000000000000001-4111111111111111')).toBe(true);
    expect(containsSensitivePattern('1234567890')).toBe(false);
    expect(containsSensitivePattern('tok_sk-1234567890abcdef')).toBe(true);
    expect(containsSensitivePattern('task-1234567890abcdef')).toBe(false);

    await runCoreRealmScenario(`
      const { MemoryExporter, TelemetryManager: IsolatedManager } = core;

      // 1. Configurable throwing attribute getter does not block scrubbing later attributes,
      //    and non-configurable throwing getter still scrubs later keys before throwing.
      const mgr1 = new IsolatedManager({ mode: 'memory_only', allowRawPayloads: true });
      const exp1 = new MemoryExporter(5, { allowRawPayloads: true });
      const attrsWithConfigurableThrower = { secret_before: 's1' };
      Object.defineProperty(attrsWithConfigurableThrower, 'boom_cfg', {
        enumerable: true,
        configurable: true,
        get() {
          throw new Error('cfg getter exploded');
        },
      });
      attrsWithConfigurableThrower.secret_after = 's2';
      exp1.export({
        id: 'cfg-1',
        name: 'scan_started',
        startTime: 1,
        status: 'OK',
        attributes: attrsWithConfigurableThrower,
        events: [],
      });

      mgr1.burn();
      assert.equal(attrsWithConfigurableThrower.secret_before, undefined);
      assert.equal(attrsWithConfigurableThrower.secret_after, undefined);
      assert.equal(Object.prototype.hasOwnProperty.call(attrsWithConfigurableThrower, 'boom_cfg'), false);
    `);

    await runCoreRealmScenario(`
      const { MemoryExporter, TelemetryManager: IsolatedManager } = core;

      // 2. Non-configurable throwing getter still lets sibling attributes and audit fields scrub,
      //    and attributes getter calling burn() during export() prevents appending the span.
      const mgr2 = new IsolatedManager({ mode: 'memory_only', allowRawPayloads: true });
      const exp2 = new MemoryExporter(5, { allowRawPayloads: true });
      const attrsWithNonCfgThrower = {};
      Object.defineProperty(attrsWithNonCfgThrower, 'boom_non_cfg', {
        enumerable: true,
        configurable: false,
        get() {
          throw new Error('non-cfg getter exploded');
        },
      });
      attrsWithNonCfgThrower.secret_after = 'must_be_deleted';
      exp2.export({
        id: 'noncfg-1',
        name: 'scan_started',
        startTime: 1,
        status: 'OK',
        attributes: attrsWithNonCfgThrower,
        events: [],
      });

      mgr2.recordAuditEvent('document_ingested', 'Original Summary', { detail: 'raw' });
      const issued = mgr2.getAuditLog();
      Object.defineProperty(issued[0], 'summary', {
        enumerable: true,
        configurable: true,
        get() {
          throw new Error('summary getter exploded');
        },
      });

      assert.throws(() => mgr2.burn(), /Telemetry burn could not scrub/);
      assert.equal(attrsWithNonCfgThrower.secret_after, undefined);
      assert.equal(issued[0].action, '[REDACTED_ACTION]');
      assert.equal(issued[0].id, '[REDACTED]');
      assert.equal(issued[0].timestamp, '');
    `);

    await runCoreRealmScenario(`
      const { MemoryExporter, TelemetryManager: IsolatedManager } = core;
      const mgr = new IsolatedManager({ mode: 'memory_only' });
      const exp = new MemoryExporter(5);
      const reentrantSpan = {
        id: 'burn-during-track',
        name: 'scan_started',
        startTime: 1,
        status: 'OK',
        events: [],
      };
      Object.defineProperty(reentrantSpan, 'attributes', {
        enumerable: true,
        configurable: true,
        get() {
          mgr.burn();
          return { status: 'OK' };
        },
      });
      exp.export(reentrantSpan);
      assert.equal(exp.getSpans().length, 0);
    `);
  });

  it('R29 Hardening: deletes marker-valued sensitive keys, scrubs non-enumerable attributes, and releases pending span captures on burn()', async () => {
    await runCoreRealmScenario(`
      const { MemoryExporter, TelemetryManager: IsolatedManager, isHardBurned } = core;

      // 1. Marker-valued entry with sensitive key name and non-enumerable attributes are deleted cleanly on mutable attrs
      const mgr1 = new IsolatedManager({ mode: 'memory_only', allowRawPayloads: true });
      const exp1 = new MemoryExporter(5, { allowRawPayloads: true });
      const retainedAttrs = {
        patient_jane_doe_hiv_positive: '[REDACTED_SENSITIVE_VALUE]',
      };
      Object.defineProperty(retainedAttrs, 'secret_note', {
        value: 'hidden non-enumerable secret',
        enumerable: false,
        configurable: true,
        writable: true,
      });
      exp1.export({
        id: 'r29-1',
        name: 'scan_started',
        startTime: 1,
        status: 'OK',
        attributes: retainedAttrs,
        events: [],
      });

      const pendingHandle = mgr1.startSpan('raw_patient_doc_title', {
        raw_text: 'pending raw intake text',
      });

      mgr1.burn();
      assert.equal(isHardBurned(), true);
      assert.equal(Object.prototype.hasOwnProperty.call(retainedAttrs, 'patient_jane_doe_hiv_positive'), false);
      assert.equal(Object.prototype.hasOwnProperty.call(retainedAttrs, 'secret_note'), false);
      assert.equal(Object.getOwnPropertyNames(retainedAttrs).length, 0);

      // Calling pendingHandle.end() after burn must not retain or publish spans
      pendingHandle.end('OK', { extra_note: 'post-burn' });
      assert.equal(mgr1.getBufferedSpans().length, 0);
    `);

    await runCoreRealmScenario(`
      const { MemoryExporter, TelemetryManager: IsolatedManager } = core;

      // 2. Frozen attributes with marker-valued sensitive key fail closed on burn()
      const mgr2 = new IsolatedManager({ mode: 'memory_only', allowRawPayloads: true });
      const exp2 = new MemoryExporter(5, { allowRawPayloads: true });
      const frozenMarkerAttrs = Object.freeze({
        patient_jane_doe_hiv_positive: '[REDACTED_SENSITIVE_VALUE]',
      });
      exp2.export({
        id: 'r29-frozen-marker',
        name: 'scan_started',
        startTime: 1,
        status: 'OK',
        attributes: frozenMarkerAttrs,
        events: [],
      });
      assert.throws(() => mgr2.burn(), /Telemetry burn could not scrub/);
    `);

    await runCoreRealmScenario(`
      const { TelemetryManager: IsolatedManager } = core;

      // 3. Reentrant burn inside startSpan() attribute getter yields a no-op handle with empty buffers
      const mgr3 = new IsolatedManager({ mode: 'memory_only', allowRawPayloads: true });
      const reentrantAttrs = {};
      Object.defineProperty(reentrantAttrs, 'trigger', {
        enumerable: true,
        get() {
          mgr3.burn();
          return 'triggered';
        },
      });
      const noopHandle = mgr3.startSpan('raw_doc', reentrantAttrs);
      assert.equal(noopHandle.spanId, 'noop');
      noopHandle.end('OK', { extra: 'ignored' });
      assert.equal(mgr3.getBufferedSpans().length, 0);
    `);
  });

  it('CodeRabbit R30: scrubs Symbol keys, isolates throwing index getters in MemoryExporter.clear(), and tracks pending startSpan weakly', async () => {
    const symMutable = Symbol('secretMutable');
    const symRec: Record<PropertyKey, unknown> = {
      rule_id: 'CA-SEC-DEP-CAP-01',
      [symMutable]: 'patient Alice Smith',
    };
    expect(scrubRecordEntries(symRec as Record<string, unknown>)).toBe(true);
    expect(Reflect.ownKeys(symRec)).toEqual([]);

    const symFrozen = Symbol('secretFrozen');
    const frozenSymRec: Record<PropertyKey, unknown> = {};
    Object.defineProperty(frozenSymRec, symFrozen, {
      value: 'ssn-123-45-6789',
      enumerable: true,
      configurable: false,
      writable: false,
    });
    expect(scrubRecordEntries(frozenSymRec as Record<string, unknown>)).toBe(false);

    const exporter = new MemoryExporter(10);
    exporter.export({
      id: 'span-getter-0',
      name: 'scan_started',
      startTime: 1000,
      endTime: 1001,
      durationMs: 1,
      status: 'OK',
      attributes: { rule_id: 'CA-SEC-DEP-CAP-01' },
      events: [],
    });
    exporter.export({
      id: 'span-getter-1',
      name: 'scan_complete',
      startTime: 1002,
      endTime: 1003,
      durationMs: 1,
      status: 'OK',
      attributes: { rule_id: 'CA-ENTRY-NOT-03' },
      events: [],
    });

    const retainedAlias = exporter.getSpans();
    const secondSpan = retainedAlias[1];
    Object.defineProperty(retainedAlias, 0, {
      enumerable: true,
      configurable: true,
      get() {
        throw new Error('getter-index-0-boom');
      },
    });
    expect(() => exporter.clear()).toThrow('getter-index-0-boom');
    expect(secondSpan.name).toBe('[REDACTED_SPAN_NAME]');
    expect(Object.keys(secondSpan.attributes)).toEqual([]);
    expect(exporter.count()).toBe(0);

    // Abandoned startSpan handles must not leak strongly inside TelemetryManager
    const abandonedMgr = new TelemetryManager({ mode: 'memory_only', burnEnabled: true });
    const leakSet = (abandonedMgr as unknown as { pendingSpanCaptureRefs: Set<WeakRef<unknown>> }).pendingSpanCaptureRefs;
    (() => {
      abandonedMgr.startSpan('scan_started', { status: 'started' });
    })();
    expect(leakSet.size).toBe(1);
    v8.setFlagsFromString('--expose_gc');
    const gc = vm.runInNewContext('gc') as (() => void) | undefined;
    if (typeof gc === 'function') {
      gc();
      await new Promise((r) => setTimeout(r, 30));
      gc();
      await new Promise((r) => setTimeout(r, 30));
      if (process.env.KTY_STRICT_GC_DIAGNOSTICS === '1') {
        const liveRefs = [...leakSet].filter((ref) => ref.deref() !== undefined);
        expect(liveRefs.length).toBe(0);
      }
    }

    await runCoreRealmScenario(`
      const { TelemetryManager: IsolatedManager } = core;
      const mgr = new IsolatedManager({ mode: 'memory_only', burnEnabled: true }, ['redflag_count']);
      const pendingHandle = mgr.startSpan('rules_evaluated', {
        redflag_count: 3,
        statute_code: '29 U.S.C. § 206',
      });
      const pendingSet = mgr.pendingSpanCaptureRefs;
      assert.equal(pendingSet.size, 1);

      mgr.burn();
      assert.equal(pendingSet.size, 0);
      pendingHandle.end('OK', { duration_ms: 5 });
      assert.equal(mgr.getBufferedSpans().length, 0);
    `);
  });

  it('rejects sensitive or malformed attribute keys in additionalKeys and sanitize output boundary (CodeRabbit R31)', () => {
    const validDigest = 'hmac:abcdefabcdefabcd';
    const unsafeKeys = [
      'alice@example.com',
      '123-45-6789',
      'prefix_123-45-6789',
      'tok_sk-1234567890abcdef',
      'invalid key!',
      '/Users/alice/secret',
    ];

    const sanitizer = createAllowlistSanitizer([...unsafeKeys, 'safe_custom_key']);
    for (const unsafeKey of unsafeKeys) {
      expect(sanitizer.allowlist.has(unsafeKey.toLowerCase())).toBe(false);
    }
    expect(sanitizer.allowlist.has('safe_custom_key')).toBe(true);

    const sanitized = sanitizer.sanitize({
      'alice@example.com': validDigest,
      'prefix_123-45-6789': validDigest,
      'tok_sk-1234567890abcdef': true,
      'invalid key!': 42,
      '/Users/alice/secret': validDigest,
      safe_custom_key: validDigest,
    });

    expect(sanitized.safe_custom_key).toBe(validDigest);
    expect(sanitized['[REDACTED_KEY]']).toBe(REDACTED_NOT_ALLOWLISTED);
    for (const unsafeKey of unsafeKeys) {
      expect(unsafeKey in sanitized).toBe(false);
    }

    const rawSanitized = sanitizer.sanitize({ 'alice@example.com': validDigest }, true);
    expect(rawSanitized['alice@example.com']).toBe(validDigest);
  });

  it('CodeRabbit R32: keeps retained aliases scrubbable after manager GC and bounds synchronous span tracking to exposed buffers', async () => {
    // 1. Finding 4: Consumer-retained span arrays and audit records remain scrubbable even after manager + MemoryExporter GC
    await runCoreRealmScenario(`
      const { default: v8Mod } = await import('node:v8');
      const { default: vmMod } = await import('node:vm');
      v8Mod.setFlagsFromString('--expose_gc');
      const runGc = vmMod.runInNewContext('gc');

      let mgrWeakRef;
      let leakedSpans;
      let leakedSingleSpan;
      let leakedAudit;
      let leakedDetails;

      (() => {
        const tempMgr = new core.TelemetryManager({ mode: 'memory_only', allowRawPayloads: true });
        tempMgr.startSpan('scan_started', { secret_note: 'gc span secret' }).end('OK');
        tempMgr.recordAuditEvent('document_ingested', 'GC Audit Memo', { secret_note: 'gc audit secret' });
        leakedSpans = tempMgr.getBufferedSpans();
        leakedSingleSpan = leakedSpans[0];
        leakedAudit = tempMgr.getAuditLog();
        leakedDetails = leakedAudit[0].details;
        mgrWeakRef = new WeakRef(tempMgr);
      })();

      await new Promise((resolve) => setTimeout(resolve, 10));
      if (typeof runGc === 'function') {
        for (let attempt = 0; attempt < 5; attempt++) {
          runGc();
          await new Promise((resolve) => setTimeout(resolve, 25));
          if (mgrWeakRef.deref() === undefined) {
            break;
          }
          await new Promise((resolve) => setTimeout(resolve, 10));
        }
        if (process.env.KTY_STRICT_GC_DIAGNOSTICS === '1') {
          assert.equal(mgrWeakRef.deref(), undefined);
        }
      }

      const peerMgr = new core.TelemetryManager({ mode: 'memory_only', burnEnabled: true });
      peerMgr.burn();

      assert.equal(core.isHardBurned(), true);
      assert.equal(leakedSpans.length, 0);
      assert.equal(leakedSingleSpan.name, '[REDACTED_SPAN_NAME]');
      assert.equal(leakedSingleSpan.attributes.secret_note, undefined);
      assert.equal(leakedAudit[0].summary, '[REDACTED_AUDIT_SUMMARY]');
      assert.equal(leakedAudit[0].details.secret_note, undefined);
      assert.equal(leakedDetails.secret_note, undefined);
    `);

    // 2. Finding 5: Synchronous scan loops over >500 spans stay bounded without pre-tracking internal spans
    await runCoreRealmScenario(`
      const mgr = new core.TelemetryManager({ mode: 'memory_only' });
      const liveAliasesSymbol = Symbol.for('knowthankyew.privacyTelemetry.liveAliases.v1');
      for (let i = 0; i < 2000; i++) {
        mgr.startSpan('scan_started', { action: 'scan_started' }).end('OK');
      }

      const exp = mgr.memoryExporter;
      assert.equal(exp.count(), 500);
      assert.equal(exp.spanArrayTracker.refs.size, 0);
      assert.equal(exp.spanTracker.refs.size, 0);
      assert.equal(exp.childRecordTracker.refs.size, 0);
      assert.equal(exp.eventArrayTracker.refs.size, 0);
      assert.equal(exp.eventTracker.refs.size, 0);
      const aliasRegistryBeforeExpose = globalThis[liveAliasesSymbol];
      assert.equal(aliasRegistryBeforeExpose ? aliasRegistryBeforeExpose.refs.size : 0, 0);

      const retained = mgr.getBufferedSpans();
      assert.equal(retained.length, 500);
      assert.equal(exp.spanArrayTracker.refs.size, 1);
      assert.equal(exp.spanTracker.refs.size, 500);

      mgr.burn();
      assert.equal(retained.length, 0);
      assert.equal(exp.spanTracker.refs.size, 0);
      assert.equal(aliasRegistryBeforeExpose ? aliasRegistryBeforeExpose.refs.size : 0, 0);
    `);

    // 3. R33 + R36 Finding 6: getBufferedSpans() returns isolated snapshots so subsequent unexposed spans
    //    keep WeakRef tracking bounded while already-exposed evicted spans remain scrubbable on burn()
    await runCoreRealmScenario(`
      const mgr = new core.TelemetryManager({ mode: 'memory_only' });
      const exp = mgr.memoryExporter;
      const liveAliasesSymbol = Symbol.for('knowthankyew.privacyTelemetry.liveAliases.v1');

      const emptySnapshot = mgr.getBufferedSpans();
      assert.equal(emptySnapshot.length, 0);
      assert.equal(exp.spanArrayTracker.refs.size, 0);
      assert.equal(exp.spanTracker.refs.size, 0);

      mgr.startSpan('scan_started', { action: 'scan_started', rule_id: 'AR-001' }).end('OK');
      assert.equal(emptySnapshot.length, 0);
      assert.equal(exp.spanTracker.refs.size, 0);

      const exposedSnapshot = mgr.getBufferedSpans();
      assert.equal(exposedSnapshot.length, 1);
      const retainedEvictedRef = exposedSnapshot[0];
      assert.equal(retainedEvictedRef.attributes.rule_id, 'AR-001');
      assert.equal(exp.spanArrayTracker.refs.size, 1);
      assert.equal(exp.spanTracker.refs.size, 1);

      for (let i = 0; i < 10000; i++) {
        mgr.startSpan('scan_started', { action: 'scan_started' }).end('OK');
      }

      // Snapshot isolation & O(exposed) WeakRef bound across 10k synchronous unexposed spans:
      assert.equal(exposedSnapshot.length, 1);
      assert.equal(exp.spanArrayTracker.refs.size, 1);
      assert.equal(exp.spanTracker.refs.size, 1);
      assert.equal(exp.count(), 500);
      assert.equal(mgr.getBufferedSpans().includes(retainedEvictedRef), false);

      mgr.burn();
      assert.equal(exposedSnapshot.length, 0);
      assert.equal(exp.count(), 0);
      assert.equal(retainedEvictedRef.name, '[REDACTED_SPAN_NAME]');
      assert.equal(retainedEvictedRef.id, '[REDACTED]');
      assert.equal(retainedEvictedRef.attributes.rule_id, undefined);
      const aliasRegistry = globalThis[liveAliasesSymbol];
      assert.equal(aliasRegistry ? aliasRegistry.refs.size : 0, 0);
    `);

    // 4. R35 Finding 4 + Snapshot Isolation: freezing an exposed snapshot cannot freeze internal storage,
    //    and getter-triggered burn() on a non-extensible internal buffer never reinstalls buffers or leaks spans
    await runCoreRealmScenario(`
      const mgr = new core.TelemetryManager({ mode: 'memory_only', burnEnabled: true });
      mgr.startSpan('scan_started', { action: 'scan_started' }).end('OK');

      const exposed = mgr.getBufferedSpans();
      Object.freeze(exposed);
      mgr.startSpan('rules_evaluated', { action: 'rules_evaluated' }).end('OK');
      assert.equal(exposed.length, 1);
      assert.equal(mgr.memoryExporter.count(), 2);

      const exp = mgr.memoryExporter;
      const internalBuffer = exp.spans;
      const leakedFromGetter = {
        id: 'getter-returned-span',
        name: 'scan_completed',
        startTime: Date.now(),
        status: 'OK',
        attributes: { action: 'scan_completed' },
        events: [],
      };
      Object.defineProperty(internalBuffer, 0, {
        enumerable: true,
        configurable: true,
        get() {
          mgr.burn();
          return leakedFromGetter;
        },
      });
      Object.preventExtensions(internalBuffer);

      mgr.startSpan('rules_evaluated', { action: 'rules_evaluated' }).end('OK');

      assert.equal(core.isHardBurned(), true);
      assert.equal(mgr.getBufferedSpans().length, 0);
      assert.equal(leakedFromGetter.name, '[REDACTED_SPAN_NAME]');
      assert.equal(leakedFromGetter.id, '[REDACTED]');
    `);
  });

  it('CodeRabbit R38: registered wage key gross_pay is redacted across startSpan, end, and OTLP export when allowRawPayloads is false', async () => {
    await runCoreRealmScenario(`
      const capturedBodies = [];
      let notifyFetch;
      const twoFetchesDone = new Promise((resolve) => {
        notifyFetch = () => {
          if (capturedBodies.length >= 2) resolve();
        };
      });
      const origFetch = globalThis.fetch;
      globalThis.fetch = async (_url, init) => {
        if (init && init.body) {
          capturedBodies.push(JSON.parse(String(init.body)));
          notifyFetch();
        }
        return new Response('{}', { status: 200 });
      };

      try {
        // 1. Live TelemetryManager (otlp mode, allowRawPayloads=false) redacts gross_pay at startSpan/end AND in OTLP body.
        const restrictedMgr = new core.TelemetryManager(
          {
            mode: 'otlp',
            otlpEndpoint: 'http://127.0.0.1:4318/v1/traces',
            allowRawPayloads: false,
          },
          ['gross_pay']
        );

        const span = restrictedMgr.startSpan('scan_completed', {
          action: 'scan_completed',
          gross_pay: 154321.89,
        });
        span.end('OK');

        const buffered = restrictedMgr.getBufferedSpans();
        assert.equal(buffered.length, 1);
        assert.equal(buffered[0].attributes['[REDACTED_KEY]'], '[REDACTED_BY_DEFAULT_ALLOWLIST]');
        assert.equal(JSON.stringify(buffered).includes('gross_pay'), false);
        assert.equal(JSON.stringify(buffered).includes('154321.89'), false);

        // 2. Direct exportToOtlp with an unsanitized span object and allowRawPayloads=false also rejects gross_pay fail-closed.
        const { allowlist, sanitize } = core.createAllowlistSanitizer(['gross_pay']);
        await core.exportToOtlp(
          'http://127.0.0.1:4318/v1/traces',
          {
            id: 'direct-gross-pay-span',
            name: 'scan_completed',
            startTime: 1000,
            status: 'OK',
            attributes: { action: 'scan_completed', gross_pay: 154321.89 },
            events: [],
          },
          'knowthankyew-app',
          sanitize,
          false,
          allowlist
        );

        await twoFetchesDone;
        assert.equal(capturedBodies.length, 2);
        for (const body of capturedBodies) {
          const serialized = JSON.stringify(body);
          assert.equal(serialized.includes('gross_pay'), false);
          assert.equal(serialized.includes('154321.89'), false);
          const attrs = body.resourceSpans[0].scopeSpans[0].spans[0].attributes;
          assert.equal(attrs.find((a) => a.key === 'gross_pay'), undefined);
          assert.equal(attrs.find((a) => a.key === 'action')?.value?.stringValue, 'scan_completed');
        }

        // 3. Preserve raw numeric value strictly when allowRawPayloads is enabled.
        const rawMgr = new core.TelemetryManager(
          {
            mode: 'memory_only',
            otlpEndpoint: null,
            allowRawPayloads: true,
          },
          ['gross_pay']
        );
        const rawSpan = rawMgr.startSpan('scan_completed', {
          action: 'scan_completed',
          gross_pay: 154321.89,
        });
        rawSpan.end('OK');
        assert.equal(rawMgr.getBufferedSpans()[0].attributes.gross_pay, 154321.89);
      } finally {
        globalThis.fetch = origFetch;
      }
    `);
  });

  it('CodeRabbit R38: post-burn startSpan().end() and MemoryExporter.export() discard immediately without re-throwing after failed burn cleanup', async () => {
    await runCoreRealmScenario(`
      const mgr = new core.TelemetryManager({ mode: 'memory_only', burnEnabled: true });
      mgr.startSpan('scan_started', { action: 'scan_started' }).end('OK');

      const exposed = mgr.getBufferedSpans();
      Object.freeze(exposed[0].attributes);

      assert.throws(() => mgr.burn(), /could not scrub immutable retained/i);
      assert.equal(core.isHardBurned(), true);

      // Subsequent span recording, audit events, and direct exporter pushes must discard silently without throwing.
      assert.doesNotThrow(() => {
        mgr.startSpan('rules_evaluated', { action: 'rules_evaluated' }).end('OK');
        mgr.recordAuditEvent('scan_completed', { action: 'scan_completed' });
        mgr.memoryExporter.export([
          {
            id: 'post-burn-span',
            name: 'scan_completed',
            startTime: Date.now(),
            status: 'OK',
            attributes: { action: 'scan_completed' },
            events: [],
          },
        ]);
      });

      assert.equal(mgr.memoryExporter.count(), 0);
    `);
  });

  it('CodeRabbit R40: rejects PHI/person-smuggling additionalKeys (even with digests) and wipes full serialized output', () => {
    const adversarialKeys = [
      'patient_Jane_Doe_HIV_positive',
      'patient_jane_doe_hiv_positive',
      'Jane_Doe_HIV_positive',
      'diagnosis_HIV_positive',
      'patient123',
      'claimant_Bob_Smith',
    ];
    const { allowlist, sanitize } = createAllowlistSanitizer([
      ...adversarialKeys,
      'subscription_tier',
    ]);

    for (const badKey of adversarialKeys) {
      expect(allowlist.has(badKey.toLowerCase())).toBe(false);
    }
    expect(allowlist.has('subscription_tier')).toBe(true);

    const outBool = sanitize({
      patient_Jane_Doe_HIV_positive: true,
      Jane_Doe_HIV_positive: true,
      patient123: 42,
      action: 'scan_completed',
    });
    const serializedBool = JSON.stringify(outBool);
    expect(serializedBool).not.toContain('patient');
    expect(serializedBool).not.toContain('Jane');
    expect(serializedBool).not.toContain('Doe');
    expect(serializedBool).not.toContain('HIV');
    expect(serializedBool).not.toContain('positive');
    expect(outBool[REDACTED_UNALLOWLISTED_KEY]).toBe(REDACTED_NOT_ALLOWLISTED);
    expect(outBool.action).toBe('scan_completed');

    const outDigest = sanitize({
      patient_Jane_Doe_HIV_positive: 'hmac:0123456789abcdef',
      diagnosis_HIV_positive: 'hmac:fedcba9876543210',
    });
    const serializedDigest = JSON.stringify(outDigest);
    expect(serializedDigest).not.toContain('patient');
    expect(serializedDigest).not.toContain('Jane');
    expect(serializedDigest).not.toContain('HIV');
    expect(serializedDigest).not.toContain('0123456789abcdef');
    expect(outDigest[REDACTED_UNALLOWLISTED_KEY]).toBe(REDACTED_NOT_ALLOWLISTED);
  });

  it('CodeRabbit R40: MemoryExporter.getSpans() aborts and registerRetainedAlias wipes when hard burn triggers during tracking', async () => {
    await runCoreRealmScenario(`
      const mgr = new core.TelemetryManager({ mode: 'memory_only', burnEnabled: true });
      mgr.startSpan('scan_started', { action: 'scan_started' }).end('OK');

      // Direct post-burn registerRetainedAlias must immediately wipe target instead of holding stale state
      const postAliasTarget = { secret: 'alice@example.com' };
      const getterSpan = mgr.memoryExporter.spans[0];
      const originalAttributes = getterSpan.attributes;
      Object.defineProperty(getterSpan, 'attributes', {
        configurable: true,
        enumerable: true,
        get() {
          if (!core.isHardBurned()) {
            mgr.burn();
          }
          return { ...originalAttributes, raw_note: 'private text' };
        },
      });

      const returned = mgr.memoryExporter.getSpans();
      assert.deepEqual(returned, []);
      assert.equal(core.isHardBurned(), true);
      assert.equal(mgr.memoryExporter.count(), 0);

      let wipedCount = 0;
      core.registerRetainedAlias(postAliasTarget, (t) => {
        wipedCount += 1;
        delete t.secret;
      });
      assert.equal(wipedCount, 1);
      assert.equal('secret' in postAliasTarget, false);
    `);
  });

  it('CodeRabbit R41 #3: bounds oversized attribute keys in allowRawPayloads mode', async () => {
    const { createAllowlistSanitizer, formatTruncatedDigest } = await import('../src/allowlist.js');
    const sanitizer = createAllowlistSanitizer();
    const oversizedKey = 'k'.repeat(320);
    const sanitized = sanitizer.sanitize(
      {
        [oversizedKey]: 'raw_value',
        normal_key: 'ok',
      },
      true
    );

    const expectedKey = formatTruncatedDigest(oversizedKey);
    assert.equal(Object.hasOwn(sanitized, oversizedKey), false);
    assert.equal(sanitized[expectedKey], 'raw_value');
    assert.equal(sanitized.normal_key, 'ok');
    assert.equal(
      Object.keys(sanitized).every((k) => k.length <= 256),
      true
    );
  });

  it('CodeRabbit R42 #5 & #6: rejects unreviewed entity noun keys and fails closed on empty/cleartext custom domains', async () => {
    const { createAllowlistSanitizer, REDACTED_NOT_ALLOWLISTED, REDACTED_SENSITIVE_VALUE } = await import(
      '../src/allowlist.js'
    );
    const digest = 'hmac:0123456789abcdef';
    const sanitizer = createAllowlistSanitizer(
      [
        'acme_holdings',
        'contoso_ops',
        'alice_smith_status',
        'contoso_ops_status',
        'review_channel',
        'hospital_id',
        'subscription_tier',
        'document_path',
      ],
      {
        acme_holdings: [digest],
        contoso_ops: [digest],
        alice_smith_status: [digest],
        contoso_ops_status: [digest],
        subscription_tier: ['cleartext_only_value'],
        document_path: [],
        unkeyed_cleartext_tier: ['cleartext_only_value'],
      }
    );

    expect(sanitizer.allowlist.has('acme_holdings')).toBe(false);
    expect(sanitizer.allowlist.has('contoso_ops')).toBe(false);
    expect(sanitizer.allowlist.has('alice_smith_status')).toBe(false);
    expect(sanitizer.allowlist.has('contoso_ops_status')).toBe(false);
    expect(sanitizer.allowlist.has('unkeyed_cleartext_tier')).toBe(false);
    expect(sanitizer.allowlist.has('review_channel')).toBe(true);
    expect(sanitizer.allowlist.has('hospital_id')).toBe(true);
    expect(sanitizer.allowlist.has('subscription_tier')).toBe(true);
    expect(sanitizer.allowlist.has('document_path')).toBe(true);

    const sanitized = sanitizer.sanitize({
      acme_holdings: digest,
      contoso_ops: digest,
      alice_smith_status: true,
      contoso_ops_status: 'OK',
      unkeyed_cleartext_tier: digest,
      subscription_tier: digest,
      document_path: digest,
      review_channel: digest,
    });

    expect(Object.hasOwn(sanitized, 'acme_holdings')).toBe(false);
    expect(Object.hasOwn(sanitized, 'contoso_ops')).toBe(false);
    expect(Object.hasOwn(sanitized, 'alice_smith_status')).toBe(false);
    expect(Object.hasOwn(sanitized, 'contoso_ops_status')).toBe(false);
    expect(Object.hasOwn(sanitized, 'unkeyed_cleartext_tier')).toBe(false);
    expect(sanitized['[REDACTED_KEY]']).toBe(REDACTED_NOT_ALLOWLISTED);
    expect(sanitized.subscription_tier).toBe(REDACTED_SENSITIVE_VALUE);
    expect(sanitized.document_path).toBe(REDACTED_SENSITIVE_VALUE);
    expect(sanitized.review_channel).toBe(digest);

    // CodeRabbit R43 #3 & #4: verify camelCase customValueDomains across TelemetryManager/exportToOtlp
    // and MemoryExporter.clear() reentrant export rejection in a fresh unburned realm.
    await runCoreRealmScenario(`
      const { TelemetryManager, MemoryExporter, REDACTED_SENSITIVE_VALUE } = core;
      const digest = 'hmac:0123456789abcdef';
      const otherDigest = 'hmac:fedcba9876543210';

      for (const extraKeys of [undefined, ['reviewChannel']]) {
        const camelMgr = new TelemetryManager(
          { mode: 'memory_only', allowRawPayloads: false },
          extraKeys,
          { reviewChannel: [digest] }
        );
        camelMgr.startSpan('scan_started', { reviewChannel: digest }).end('OK');
        camelMgr.startSpan('scan_started', { reviewChannel: otherDigest }).end('OK');
        const spans = camelMgr.getBufferedSpans();
        assert.equal(spans.length, 2);
        assert.equal(spans[0].attributes.reviewChannel, digest);
        assert.equal(spans[1].attributes.reviewChannel, REDACTED_SENSITIVE_VALUE);
      }

      const exporter = new MemoryExporter(500, { allowRawPayloads: true });
      let armed = false;
      let nestedExportAttempts = 0;
      const BackingAttrs = { action: 'scan_started' };
      const spanRecord = {
        id: 'reentrant-clear-span',
        name: 'scan_started',
        startTime: 1,
        endTime: 2,
        durationMs: 1,
        status: 'OK',
        attributes: BackingAttrs,
        events: [],
      };
      Object.defineProperty(spanRecord, 'attributes', {
        enumerable: true,
        configurable: true,
        get() {
          if (armed) {
            nestedExportAttempts++;
            exporter.export({
              id: 'reentrant-injected-span',
              name: 'scan_completed',
              startTime: 3,
              endTime: 4,
              durationMs: 1,
              status: 'OK',
              attributes: { action: 'scan_completed' },
              events: [],
            });
          }
          return BackingAttrs;
        },
      });
      exporter.export(spanRecord);
      assert.equal(exporter.count(), 1);
      armed = true;
      exporter.clear();
      assert.ok(nestedExportAttempts > 0, 'Expected clear() to invoke spanRecord.attributes getter');
      assert.equal(exporter.count(), 0);
      assert.deepEqual(exporter.getSpans(), []);

      // R46 #6 & #9: Container accessors on span.attributes, span.events, event.attributes, and audit details are replaced with clean data properties.
      const accessorExporter = new MemoryExporter(500, { allowRawPayloads: true });
      const accessorEvent = {
        name: 'rule.evaluated',
        timestamp: 10,
        attributes: { action: 'scan_started' },
      };
      Object.defineProperty(accessorEvent, 'attributes', {
        enumerable: true,
        configurable: true,
        get() {
          return { secret_event_attr: 'alice@example.com' };
        },
      });
      const accessorSpan = {
        id: 'accessor-span-1',
        name: 'scan_started',
        startTime: 1,
        endTime: 2,
        durationMs: 1,
        status: 'OK',
        attributes: { action: 'scan_started' },
        events: [accessorEvent],
      };
      Object.defineProperty(accessorSpan, 'attributes', {
        enumerable: true,
        configurable: true,
        get() {
          return { secret_span_attr: '123-45-6789' };
        },
      });
      Object.defineProperty(accessorSpan, 'events', {
        enumerable: true,
        configurable: true,
        get() {
          return [accessorEvent];
        },
      });
      let endTimeReads = 0;
      Object.defineProperty(accessorSpan, 'endTime', {
        enumerable: true,
        configurable: true,
        get() {
          endTimeReads += 1;
          return endTimeReads === 1 ? undefined : 99999;
        },
      });
      let durationMsReads = 0;
      Object.defineProperty(accessorSpan, 'durationMs', {
        enumerable: true,
        configurable: true,
        get() {
          durationMsReads += 1;
          return durationMsReads === 1 ? undefined : 99999;
        },
      });
      accessorExporter.export(accessorSpan);
      accessorExporter.clear();
      assert.deepEqual(accessorSpan.attributes, {});
      assert.deepEqual(accessorSpan.events, []);
      assert.deepEqual(accessorEvent.attributes, {});
      assert.equal(accessorSpan.endTime, 0);
      assert.equal(accessorSpan.durationMs, 0);

      // R52 #1: customValueDomains registered on built-in string/path keys enforce closed-domain membership before accepting values while preserving schema checks.
      const domainBoundSanitizer = core.createAllowlistSanitizer(['adapter_path'], {
        adapter_path: ['hmac:0123456789abcdef', 'sha256:0123456789abcdef'],
        job_id: ['hmac:0123456789abcdef'],
        base_model: ['hmac:0123456789abcdef'],
      });
      assert.deepEqual(
        domainBoundSanitizer.sanitize({
          adapter_path: 'hmac:0123456789abcdef',
          job_id: 'hmac:0123456789abcdef',
          base_model: 'hmac:0123456789abcdef',
        }),
        {
          adapter_path: 'hmac:0123456789abcdef',
          job_id: 'hmac:0123456789abcdef',
          base_model: 'hmac:0123456789abcdef',
        }
      );
      assert.deepEqual(
        domainBoundSanitizer.sanitize({
          adapter_path: 'hmac:fedcba9876543210',
          job_id: 'hmac:fedcba9876543210',
          base_model: 'Llama-3-8B',
        }),
        {
          adapter_path: '[REDACTED_SENSITIVE_VALUE]',
          job_id: '[REDACTED_SENSITIVE_VALUE]',
          base_model: '[REDACTED_SENSITIVE_VALUE]',
        }
      );
      assert.deepEqual(
        domainBoundSanitizer.sanitize({
          adapter_path: 'sha256:0123456789abcdef',
        }),
        {
          adapter_path: '[REDACTED_SENSITIVE_VALUE]',
        }
      );

      // R53 #3: TelemetryManager with two registered rule_ids digests preserves both across startSpan + end repeated sanitization.
      const ruleDomainMgr = new TelemetryManager(
        { mode: 'memory_only', allowRawPayloads: false },
        undefined,
        { rule_ids: [digest, otherDigest] }
      );
      ruleDomainMgr
        .startSpan('scan_started', { rule_ids: [digest, otherDigest] })
        .end('OK');
      ruleDomainMgr
        .startSpan('scan_started', { rule_ids: [digest, 'hmac:aaaaaaaaaaaaaaaa'] })
        .end('OK');
      const ruleDomainSpans = ruleDomainMgr.getBufferedSpans();
      assert.equal(ruleDomainSpans.length, 2);
      assert.equal(ruleDomainSpans[0].attributes.rule_ids, digest + ',' + otherDigest);
      assert.equal(ruleDomainSpans[1].attributes.rule_ids, REDACTED_SENSITIVE_VALUE);

      // R54 #5, #6, #7: Default standalone MemoryExporter replaces getter-backed attributes and frozen/getter events,
      // and raw-mode standalone MemoryExporter enforces the 256-char length limit.
      const defaultGetterEvtExporter = new MemoryExporter();
      const getterEvt = {
        timestamp: 5,
      };
      Object.defineProperties(getterEvt, {
        name: {
          enumerable: true,
          configurable: true,
          get() {
            return 'Patient Jane Doe';
          },
        },
        attributes: {
          enumerable: true,
          configurable: true,
          get() {
            return { ssn: '123-45-6789' };
          },
        },
      });
      const getterLeakSpan = {
        id: 'r54-getter-leak',
        name: 'scan_started',
        startTime: 1,
        status: 'OK',
        attributes: {},
        events: [getterEvt],
      };
      Object.defineProperty(getterLeakSpan, 'attributes', {
        enumerable: true,
        configurable: true,
        get() {
          return { secret_span_attr: '123-45-6789' };
        },
      });
      defaultGetterEvtExporter.export(getterLeakSpan);
      const retainedGetterSpan = defaultGetterEvtExporter.getSpans()[0];
      assert.equal(retainedGetterSpan.attributes.secret_span_attr, undefined);
      assert.equal(retainedGetterSpan.attributes['[REDACTED_KEY]'], core.REDACTED_NOT_ALLOWLISTED);
      assert.equal(retainedGetterSpan.events[0].name, '[REDACTED_SPAN_NAME]');
      assert.equal(retainedGetterSpan.events[0].attributes.ssn, undefined);
      assert.equal(retainedGetterSpan.events[0].attributes['[REDACTED_KEY]'], core.REDACTED_NOT_ALLOWLISTED);

      const rawLengthExporter = new MemoryExporter(10, { allowRawPayloads: true });
      const oversizedRaw = 'x'.repeat(300);
      rawLengthExporter.export({
        id: 'r54-raw-len',
        name: oversizedRaw,
        startTime: 1,
        status: 'OK',
        attributes: { raw_note: oversizedRaw },
        events: [],
      });
      const retainedRawLen = rawLengthExporter.getSpans()[0];
      assert.match(retainedRawLen.name, /^\\[TRUNCATED_HASH_[0-9a-f]{8}\\]$/);
      assert.match(String(retainedRawLen.attributes.raw_note), /^\\[TRUNCATED_HASH_[0-9a-f]{8}\\]$/);

      // R55 #2, #3, #4, #5, #6, #7, #8:
      // - rule_ids aggregate length check runs before split(',');
      // - quasi-identifier triad (hospital_id + household_size + fpl_percentage) is redacted when allowRawPayloads=false;
      // - cloned span preserves in-place sanitized children;
      // - stateful span-name and attribute accessors are replaced with data properties;
      // - throwing span.name getter in default mode does not escape export();
      const triadSanitizer = core.createAllowlistSanitizer(
        ['hospital_id', 'household_size', 'fpl_percentage', 'rule_ids'],
        { rule_ids: ['hmac:0123456789abcdef'] }
      );
      const oversizedRuleCsv = Array(300).fill('hmac:0123456789abcdef').join(',');
      const triadResult = triadSanitizer.sanitize({
        hospital_id: 'cleveland-clinic-main',
        household_size: 3,
        fpl_percentage: 125,
        rule_ids: oversizedRuleCsv,
      });
      assert.equal(triadResult.hospital_id, REDACTED_SENSITIVE_VALUE);
      assert.equal(triadResult.household_size, REDACTED_SENSITIVE_VALUE);
      assert.equal(triadResult.fpl_percentage, REDACTED_SENSITIVE_VALUE);
      assert.match(String(triadResult.rule_ids), /^\\[TRUNCATED_HASH_[0-9a-f]{8}\\]$/);

      let statefulNameReads = 0;
      let statefulStatusReads = 0;
      const statefulAttrs = {};
      Object.defineProperty(statefulAttrs, 'status', {
        enumerable: true,
        configurable: true,
        get() {
          statefulStatusReads += 1;
          return statefulStatusReads <= 2 ? 'OK' : 'patient@example.com';
        },
        set() {
          // Ignores assignment unless replaced with data property
        },
      });
      const nonWritableNameSpan = Object.defineProperties(
        {
          id: 'r55-clone-children',
          startTime: 1,
          status: 'OK',
          attributes: statefulAttrs,
          events: [{ name: 'scan_started', timestamp: 2, attributes: { status: 'OK' } }],
        },
        {
          name: {
            enumerable: true,
            configurable: true,
            get() {
              statefulNameReads += 1;
              return statefulNameReads <= 2 ? 'scan_started' : 'Patient Alice Smith';
            },
          },
        }
      );
      const r55Exporter = new MemoryExporter();
      r55Exporter.export(nonWritableNameSpan);
      const r55Retained = r55Exporter.getSpans()[0];
      assert.equal(r55Retained.name, 'scan_started');
      assert.equal(r55Retained.attributes.status, 'OK');
      assert.equal(r55Retained.events.length, 1);
      assert.equal(r55Retained.events[0].name, 'scan_started');

      let throwOnceInDefaultExport = true;
      const throwingNameSpan = {
        id: 'r55-throwing-name',
        startTime: 1,
        status: 'OK',
        attributes: { status: 'OK' },
        events: [],
      };
      Object.defineProperty(throwingNameSpan, 'name', {
        enumerable: true,
        configurable: true,
        get() {
          if (throwOnceInDefaultExport) {
            throw new Error('Synthetic name getter failure');
          }
          return 'scan_started';
        },
      });
      assert.doesNotThrow(() => r55Exporter.export(throwingNameSpan));
      throwOnceInDefaultExport = false;
      assert.equal(r55Exporter.getSpans()[1].name, '[REDACTED_SPAN_NAME]');
      assert.equal(r55Exporter.getSpans()[1].attributes.status, 'OK');

      // R46 #10: startSpan rechecks allowRawPayloads if an attribute getter narrows policy to false before creating PendingSpanCapture.
      const startNarrowMgr = new TelemetryManager({
        mode: 'memory_only',
        allowRawPayloads: true,
      });
      const startNarrowAttrs = {
        status: 'raw arbitrary text before policy change',
        unregistered_raw_key: 'raw private body',
      };
      Object.defineProperty(startNarrowAttrs, 'action', {
        enumerable: true,
        configurable: true,
        get() {
          startNarrowMgr.updateConfig({ allowRawPayloads: false });
          return 'scan_started';
        },
      });
      const narrowedHandle = startNarrowMgr.startSpan(
        'Patient alice@example.com confidential intake',
        startNarrowAttrs
      );
      narrowedHandle.end('OK');
      const narrowedBuffered = startNarrowMgr.getBufferedSpans();
      assert.equal(narrowedBuffered.length, 1);
      assert.equal(narrowedBuffered[0].name, '[REDACTED_SPAN_NAME]');
      assert.equal(narrowedBuffered[0].attributes.status, REDACTED_SENSITIVE_VALUE);
      assert.equal('unregistered_raw_key' in narrowedBuffered[0].attributes, false);

      const auditResetMgr = new TelemetryManager();
      auditResetMgr.recordAuditEvent('scan_started', 'Started', { action: 'scan_started' });
      const issuedRecords = auditResetMgr.getAuditLog();
      assert.equal(issuedRecords.length, 1);
      let resetGetterFired = false;
      Object.defineProperty(issuedRecords[0], 'details', {
        enumerable: true,
        configurable: true,
        get() {
          if (!resetGetterFired) {
            resetGetterFired = true;
            auditResetMgr.recordAuditEvent('scan_completed', 'Nested during reset', {
              action: 'scan_completed',
            });
            auditResetMgr.burn();
          }
          return { action: 'scan_started' };
        },
      });
      auditResetMgr.reset();
      assert.equal(resetGetterFired, true);
      assert.deepEqual(auditResetMgr.getAuditLog(), []);
      const exportedJson = JSON.parse(auditResetMgr.downloadSessionAuditJson());
      assert.equal(exportedJson.eventCount, 0);
      assert.deepEqual(exportedJson.events, []);
      assert.equal(issuedRecords[0].details, undefined);
    `);
  });
});

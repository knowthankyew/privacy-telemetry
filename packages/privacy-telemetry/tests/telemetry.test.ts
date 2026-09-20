import { describe, it, expect, beforeEach } from 'vitest';
import {
  TelemetryManager,
  MemoryExporter,
  createAllowlistSanitizer,
  getPrivacyClaims,
  DEFAULT_SAFE_ALLOWLIST_KEYS,
} from '../src/index.js';

describe('@knowthankyew/privacy-telemetry Core Invariants', () => {
  let telemetry: TelemetryManager;

  beforeEach(() => {
    telemetry = new TelemetryManager(
      { mode: 'memory_only', otlpEndpoint: null },
      ['domain_custom_key', 'cpt_code', 'gross_pay', 'lemon_law_qualifying', 'clause_type']
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
    const span = telemetry.startSpan('audit.rule_evaluation', {
      rule_id: 'CA_CIV_1950_5',
      jurisdiction: 'CA',
      domain_custom_key: 'custom_value',
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

    // Allowlisted keys pass through
    expect(attrs.rule_id).toBe('CA_CIV_1950_5');
    expect(attrs.jurisdiction).toBe('CA');
    expect(attrs.domain_custom_key).toBe('custom_value');

    // Unknown or unverified keys MUST be redacted
    expect(attrs.tenant_name).toBe('[REDACTED_BY_DEFAULT_ALLOWLIST]');
    expect(attrs.ssn).toBe('[REDACTED_BY_DEFAULT_ALLOWLIST]');
    expect(attrs.lease_snippet).toBe('[REDACTED_BY_DEFAULT_ALLOWLIST]');
    expect(attrs.raw_text).toBe('[REDACTED_BY_DEFAULT_ALLOWLIST]');
  });

  it('Invariant 3: Truncates oversized string values even on allowlisted keys', () => {
    const oversizedString = 'A'.repeat(300);
    const span = telemetry.startSpan('audit.large_payload', {
      rule_id: oversizedString,
    });
    span.end('OK');

    const spans = telemetry.getBufferedSpans();
    expect(spans[0].attributes.rule_id).toBe('[TRUNCATED_HASH_AAAAAAAA...]');
  });

  it('Invariant 4: "Burn Local Data" purges buffer and enforces permanent tombstone', () => {
    const span1 = telemetry.startSpan('audit.step1', { rule_id: 'R1' });
    span1.end('OK');
    telemetry.recordAuditEvent('document_ingested', 'Document uploaded');

    expect(telemetry.getBufferedSpans().length).toBe(1);
    expect(telemetry.getAuditLog().length).toBe(1);

    // Trigger burn
    telemetry.burn();

    expect(telemetry.getBufferedSpans().length).toBe(0);
    expect(telemetry.getAuditLog().length).toBe(0);
    expect(telemetry.getPrivacyAuditReport().activeSpanCount).toBe(0);

    // Subsequent spans must be rejected by tombstone
    const span2 = telemetry.startSpan('audit.post_burn', { rule_id: 'R2' });
    span2.end('OK');
    expect(telemetry.getBufferedSpans().length).toBe(0);
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
});

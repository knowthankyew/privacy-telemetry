/**
 * Dynamic Privacy Claims Single Source of Truth
 * 
 * Invariant: UI privacy claims, badges, disclaimers, and footers must be derived
 * dynamically from runtime telemetry state. If an external exporter is configured,
 * claims stating "100% Local" or "Zero Network" are never displayed.
 */

import { PrivacyAuditReport, PrivacyClaims, PrivacyClaimsBranding } from './types.js';

export function getPrivacyClaims(
  report: PrivacyAuditReport,
  branding?: PrivacyClaimsBranding
): PrivacyClaims {
  if (report.isLocalOnlyHonest) {
    return {
      isLocalOnlyHonest: true,
      isEnterpriseBuild: false,
      appTitleSuffix: '',
      badgeLabel: 'Zero Network • Memory-Only',
      dropzoneNotice: '100% Client-Side Local Execution • Zero Network Transmission',
      disclaimerExecutionText: branding?.domainDisclaimerClause
        ? branding.domainDisclaimerClause
        : 'All rule evaluations execute 100% locally in your browser with zero remote network transmission.',
      footerTitle:
        branding?.consumerFooterTitle ||
        '100% Local Air-Gapped Compliance Engine.',
      footerSubtext:
        branding?.consumerFooterSubtext ||
        'Zero Telemetry • Zero Remote PII/Document Egress • Grounded Statutory Realities',
      modalStatusTitle: '100% Local-First & Private (Memory-Only Telemetry)',
      modalStatusDescription:
        'All computation and telemetry spans remain buffered strictly in volatile memory. No outbound network calls are made. Telemetry purges immediately upon invoking "Burn Local Data".',
      otlpEndpoint: null,
    };
  }

  return {
    isLocalOnlyHonest: false,
    isEnterpriseBuild: true,
    appTitleSuffix: branding?.appTitleSuffix || ' (Enterprise Build)',
    badgeLabel: `OTLP Active (${report.telemetryMode})`,
    dropzoneNotice: 'Local Document Parsing • OTLP Operational Metadata Active (Strictly Redacted)',
    disclaimerExecutionText: `Rule evaluations execute in-browser. Scrubbed operational telemetry is exported to configured OTLP endpoint (${report.otlpEndpoint}). Document text is never transmitted.`,
    footerTitle:
      branding?.enterpriseFooterTitle ||
      'Enterprise Compliance Engine (OTLP Telemetry Active).',
    footerSubtext:
      branding?.enterpriseFooterSubtext ||
      'Enterprise Telemetry Mode • Operational Metadata Export Active • Document Bodies Air-Gapped',
    modalStatusTitle: 'Enterprise OTLP Telemetry Active',
    modalStatusDescription: `Telemetry spans are exported to configured OTLP endpoint: ${report.otlpEndpoint}. Document text and sensitive fields are redacted via strict allowlist.`,
    otlpEndpoint: report.otlpEndpoint,
  };
}

/**
 * OpenTelemetry-Compatible Burnable In-Memory Telemetry & Session Audit Engine
 * Common Type Definitions
 */

export type TelemetryMode = 'disabled' | 'memory_only' | 'otlp';
export type EgressPolicy = 'deny' | 'allow_otlp' | 'allow_all';

export interface TelemetryConfig {
  mode: TelemetryMode;
  otlpEndpoint?: string | null;
  allowRawPayloads: boolean;
  burnEnabled: boolean;
  auditDurable: boolean;
  networkEgress: EgressPolicy;
  serviceName?: string;
}

export interface SpanRecord {
  id: string;
  name: string;
  startTime: number;
  endTime?: number;
  durationMs?: number;
  status: 'UNSET' | 'OK' | 'ERROR';
  attributes: Record<string, string | number | boolean>;
  events: Array<{ name: string; timestamp: number; attributes?: Record<string, unknown> }>;
}

export interface SessionAuditEvent {
  id: string;
  timestamp: string;
  action: 'document_ingested' | 'rules_evaluated' | 'letter_generated' | 'burn_invoked' | string;
  summary: string;
  details?: Record<string, string | number | boolean>;
}

export interface PrivacyAuditReport {
  telemetryMode: TelemetryMode;
  networkEgress: EgressPolicy;
  burnEnabled: boolean;
  durableAudit: boolean;
  otlpEndpoint: string | null;
  allowRawPayloads: boolean;
  activeSpanCount: number;
  sessionAuditCount: number;
  isLocalOnlyHonest: boolean;
}

export interface PrivacyClaims {
  readonly isLocalOnlyHonest: boolean;
  readonly isEnterpriseBuild: boolean;
  readonly appTitleSuffix: string;
  readonly badgeLabel: string;
  readonly dropzoneNotice: string;
  readonly disclaimerExecutionText: string;
  readonly footerTitle: string;
  readonly footerSubtext: string;
  readonly modalStatusTitle: string;
  readonly modalStatusDescription: string;
  readonly otlpEndpoint: string | null;
}

export interface PrivacyClaimsBranding {
  appTitle?: string;
  appTitleSuffix?: string;
  consumerFooterTitle?: string;
  consumerFooterSubtext?: string;
  enterpriseFooterTitle?: string;
  enterpriseFooterSubtext?: string;
  domainDisclaimerClause?: string;
}

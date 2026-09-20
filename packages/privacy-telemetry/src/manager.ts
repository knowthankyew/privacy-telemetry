/**
 * TelemetryManager - Lifecycle coordinator for in-memory and enterprise telemetry
 */

import {
  TelemetryConfig,
  TelemetryMode,
  SpanRecord,
  SessionAuditEvent,
  PrivacyAuditReport,
  PrivacyClaims,
  PrivacyClaimsBranding,
} from './types.js';
import { createAllowlistSanitizer } from './allowlist.js';
import { MemoryExporter, exportToOtlp } from './exporter.js';
import { getPrivacyClaims } from './claims.js';

export class TelemetryManager {
  private config: TelemetryConfig;
  private memoryExporter: MemoryExporter;
  private auditLog: SessionAuditEvent[] = [];
  private isBurned = false;
  private sanitizer: (
    attrs: Record<string, unknown>,
    allowRawPayloads?: boolean
  ) => Record<string, string | number | boolean>;
  public readonly allowlist: ReadonlySet<string>;

  constructor(
    customConfig?: Partial<TelemetryConfig>,
    additionalAllowlistKeys?: Iterable<string>
  ) {
    const metaObj =
      typeof import.meta !== 'undefined'
        ? (import.meta as unknown as { env?: Record<string, string> })
        : undefined;
    const globalObj =
      typeof globalThis !== 'undefined'
        ? (globalThis as unknown as { process?: { env?: Record<string, string> } })
        : undefined;
    const envEndpoint =
      metaObj?.env?.VITE_OTEL_EXPORTER_OTLP_ENDPOINT ||
      globalObj?.process?.env?.OTEL_EXPORTER_OTLP_ENDPOINT;

    const defaultMode: TelemetryMode = envEndpoint ? 'otlp' : 'memory_only';

    this.config = {
      mode: defaultMode,
      otlpEndpoint: envEndpoint || null,
      allowRawPayloads: false,
      burnEnabled: true,
      auditDurable: false,
      networkEgress: defaultMode === 'otlp' ? 'allow_otlp' : 'deny',
      serviceName: 'knowthankyew-app',
      ...customConfig,
    };

    const { allowlist, sanitize } = createAllowlistSanitizer(additionalAllowlistKeys);
    this.allowlist = allowlist;
    this.sanitizer = sanitize;
    this.memoryExporter = new MemoryExporter();
  }

  public getConfig(): Readonly<TelemetryConfig> {
    return this.config;
  }

  public updateConfig(newConfig: Partial<TelemetryConfig>): void {
    this.config = { ...this.config, ...newConfig };
    if (this.config.otlpEndpoint && this.config.mode === 'memory_only') {
      this.config.mode = 'otlp';
      this.config.networkEgress = 'allow_otlp';
    }
  }

  public sanitizeAttributes(
    attrs: Record<string, unknown>
  ): Record<string, string | number | boolean> {
    return this.sanitizer(attrs, this.config.allowRawPayloads);
  }

  public startSpan(
    name: string,
    attributes: Record<string, unknown> = {}
  ): {
    spanId: string;
    end: (status?: 'OK' | 'ERROR', extraAttrs?: Record<string, unknown>) => void;
  } {
    if (this.config.mode === 'disabled' || this.isBurned) {
      return {
        spanId: 'noop',
        end: () => {},
      };
    }

    const spanId = `span_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const startTime = Date.now();
    const sanitizedAttrs = this.sanitizeAttributes(attributes);

    return {
      spanId,
      end: (status: 'OK' | 'ERROR' = 'OK', extraAttrs: Record<string, unknown> = {}) => {
        if (this.config.mode === 'disabled' || this.isBurned) return;

        const endTime = Date.now();
        const finalAttrs = {
          ...sanitizedAttrs,
          ...this.sanitizeAttributes(extraAttrs),
        };

        const spanRecord: SpanRecord = {
          id: spanId,
          name,
          startTime,
          endTime,
          durationMs: endTime - startTime,
          status,
          attributes: finalAttrs,
          events: [],
        };

        this.memoryExporter.export(spanRecord);

        if (this.config.mode === 'otlp' && this.config.otlpEndpoint) {
          exportToOtlp(this.config.otlpEndpoint, spanRecord, this.config.serviceName);
        }
      },
    };
  }

  public recordAuditEvent(
    action: SessionAuditEvent['action'],
    summary: string,
    details?: Record<string, unknown>
  ): void {
    if (this.isBurned) return;

    this.auditLog.push({
      id: `audit_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      timestamp: new Date().toISOString(),
      action,
      summary,
      details: details ? this.sanitizeAttributes(details) : undefined,
    });
  }

  public getBufferedSpans(): readonly SpanRecord[] {
    return this.memoryExporter.getSpans();
  }

  public getMemorySpans(): readonly SpanRecord[] {
    return this.memoryExporter.getSpans();
  }

  public getAuditLog(): readonly SessionAuditEvent[] {
    return this.auditLog;
  }

  public downloadSessionAuditJson(): string {
    const exportData = {
      generatedAt: new Date().toISOString(),
      service: this.config.serviceName || 'knowthankyew-app',
      telemetryMode: this.config.mode,
      eventCount: this.auditLog.length,
      events: this.auditLog,
    };
    return JSON.stringify(exportData, null, 2);
  }

  public getPrivacyAuditReport(): PrivacyAuditReport {
    const isHonestLocal =
      this.config.mode !== 'otlp' &&
      !this.config.otlpEndpoint &&
      this.config.networkEgress === 'deny';

    return {
      telemetryMode: this.config.mode,
      networkEgress: this.config.networkEgress,
      burnEnabled: this.config.burnEnabled,
      durableAudit: this.config.auditDurable,
      otlpEndpoint: this.config.otlpEndpoint || null,
      allowRawPayloads: this.config.allowRawPayloads,
      activeSpanCount: this.memoryExporter.count(),
      sessionAuditCount: this.auditLog.length,
      isLocalOnlyHonest: isHonestLocal,
    };
  }

  public getPrivacyClaims(branding?: PrivacyClaimsBranding): PrivacyClaims {
    return getPrivacyClaims(this.getPrivacyAuditReport(), branding);
  }

  public burn(): void {
    if (!this.config.burnEnabled) return;

    this.memoryExporter.clear();
    this.auditLog = [];
    this.isBurned = true;
  }

  public reset(): void {
    this.memoryExporter.clear();
    this.auditLog = [];
    this.isBurned = false;
  }

  public restartSession(): void {
    this.reset();
  }
}

import { useState, useCallback, useEffect } from 'react';
import { TelemetryManager } from '../manager.js';
import { PrivacyAuditReport, PrivacyClaims, PrivacyClaimsBranding, SpanRecord } from '../types.js';

export function usePrivacyTelemetry(
  telemetry: TelemetryManager,
  branding?: PrivacyClaimsBranding
) {
  const [report, setReport] = useState<PrivacyAuditReport>(() => telemetry.getPrivacyAuditReport());
  const [claims, setClaims] = useState<PrivacyClaims>(() => telemetry.getPrivacyClaims(branding));
  const [spans, setSpans] = useState<readonly SpanRecord[]>(() => telemetry.getBufferedSpans());

  const refresh = useCallback(() => {
    setReport(telemetry.getPrivacyAuditReport());
    setClaims(telemetry.getPrivacyClaims(branding));
    setSpans(telemetry.getBufferedSpans());
  }, [telemetry, branding]);

  const burn = useCallback(() => {
    telemetry.burn();
    refresh();
  }, [telemetry, refresh]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return {
    report,
    claims,
    spans,
    spanCount: spans.length,
    burn,
    refresh,
  };
}

export function usePrivacyClaims(
  telemetry: TelemetryManager,
  branding?: PrivacyClaimsBranding
): PrivacyClaims {
  const [claims, setClaims] = useState<PrivacyClaims>(() => telemetry.getPrivacyClaims(branding));

  useEffect(() => {
    setClaims(telemetry.getPrivacyClaims(branding));
  }, [telemetry, branding]);

  return claims;
}

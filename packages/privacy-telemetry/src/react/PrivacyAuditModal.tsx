import React, { useState, useEffect } from 'react';
import { TelemetryManager } from '../manager.js';
import { PrivacyClaimsBranding } from '../types.js';

export interface PrivacyAuditModalProps {
  isOpen: boolean;
  onClose: () => void;
  telemetry: TelemetryManager;
  branding?: PrivacyClaimsBranding;
  onBurn?: () => void;
  classNamePrefix?: string; // Optional class prefix for custom CSS styling
}

export const PrivacyAuditModal: React.FC<PrivacyAuditModalProps> = ({
  isOpen,
  onClose,
  telemetry,
  branding,
  onBurn,
  classNamePrefix = 'privacy-modal',
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'spans' | 'raw'>('overview');
  const [report, setReport] = useState(() => telemetry.getPrivacyAuditReport());
  const [claims, setClaims] = useState(() => telemetry.getPrivacyClaims(branding));
  const [spans, setSpans] = useState(() => telemetry.getBufferedSpans());
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setReport(telemetry.getPrivacyAuditReport());
      setClaims(telemetry.getPrivacyClaims(branding));
      setSpans(telemetry.getBufferedSpans());
    }
  }, [isOpen, telemetry, branding]);

  if (!isOpen) return null;

  const handleBurn = () => {
    telemetry.burn();
    setReport(telemetry.getPrivacyAuditReport());
    setClaims(telemetry.getPrivacyClaims(branding));
    setSpans(telemetry.getBufferedSpans());
    if (onBurn) onBurn();
  };

  const handleExportJson = () => {
    const payload = {
      auditTimestamp: new Date().toISOString(),
      report,
      claims,
      spans,
      allowlist: Array.from(telemetry.allowlist),
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `privacy-telemetry-audit-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopyJson = () => {
    const payload = {
      auditTimestamp: new Date().toISOString(),
      report,
      claims,
      spans,
      allowlist: Array.from(telemetry.allowlist),
    };
    navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="privacy-audit-modal-title"
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.65)',
        backdropFilter: 'blur(4px)',
        zIndex: 9999,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '1rem',
      }}
    >
      <div
        style={{
          backgroundColor: '#ffffff',
          borderRadius: '12px',
          width: '100%',
          maxWidth: '750px',
          maxHeight: '85vh',
          display: 'flex',
          flexDirection: 'column',
          boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.3)',
          overflow: 'hidden',
          fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        }}
        className={`${classNamePrefix}-container`}
      >
        {/* Header */}
        <div
          style={{
            padding: '1.25rem 1.5rem',
            borderBottom: '1px solid #e5e7eb',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            backgroundColor: '#f9fafb',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#059669" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            <div>
              <h3 id="privacy-audit-modal-title" style={{ margin: 0, fontSize: '1.15rem', fontWeight: 600, color: '#111827' }}>
                Privacy & Telemetry Live Audit
              </h3>
              <p style={{ margin: '0.15rem 0 0', fontSize: '0.8rem', color: '#6b7280' }}>
                Inspect volatile memory buffers, egress policy, and allowlist redactions
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close modal"
            style={{
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              color: '#9ca3af',
              padding: '0.25rem',
              display: 'flex',
            }}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        {/* Tab Navigation */}
        <div style={{ display: 'flex', borderBottom: '1px solid #e5e7eb', padding: '0 1.5rem', backgroundColor: '#ffffff' }}>
          {(['overview', 'spans', 'raw'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              style={{
                padding: '0.75rem 1rem',
                border: 'none',
                background: 'none',
                cursor: 'pointer',
                fontWeight: activeTab === tab ? 600 : 500,
                color: activeTab === tab ? '#2563eb' : '#6b7280',
                borderBottom: activeTab === tab ? '2px solid #2563eb' : '2px solid transparent',
                textTransform: 'capitalize',
                fontSize: '0.875rem',
              }}
            >
              {tab === 'spans' ? `Spans (${spans.length})` : tab}
            </button>
          ))}
        </div>

        {/* Body Content */}
        <div style={{ padding: '1.5rem', overflowY: 'auto', flex: 1, backgroundColor: '#ffffff' }}>
          {activeTab === 'overview' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div
                style={{
                  padding: '1rem',
                  borderRadius: '8px',
                  backgroundColor: claims.isEnterpriseBuild ? '#fef3c7' : '#ecfdf5',
                  border: `1px solid ${claims.isEnterpriseBuild ? '#f59e0b' : '#10b981'}`,
                }}
              >
                <h4 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 600, color: claims.isEnterpriseBuild ? '#92400e' : '#065f46' }}>
                  {claims.modalStatusTitle}
                </h4>
                <p style={{ margin: '0.35rem 0 0', fontSize: '0.825rem', color: claims.isEnterpriseBuild ? '#78350f' : '#047857' }}>
                  {claims.modalStatusDescription}
                </p>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.75rem', fontSize: '0.85rem' }}>
                <div style={{ padding: '0.75rem', backgroundColor: '#f9fafb', borderRadius: '6px', border: '1px solid #e5e7eb' }}>
                  <div style={{ color: '#6b7280', fontSize: '0.75rem' }}>Telemetry Mode</div>
                  <div style={{ fontWeight: 600, color: '#111827', marginTop: '0.2rem' }}>{report.telemetryMode}</div>
                </div>
                <div style={{ padding: '0.75rem', backgroundColor: '#f9fafb', borderRadius: '6px', border: '1px solid #e5e7eb' }}>
                  <div style={{ color: '#6b7280', fontSize: '0.75rem' }}>Network Egress Policy</div>
                  <div style={{ fontWeight: 600, color: report.networkEgress === 'deny' ? '#059669' : '#d97706', marginTop: '0.2rem' }}>
                    {report.networkEgress.toUpperCase()}
                  </div>
                </div>
                <div style={{ padding: '0.75rem', backgroundColor: '#f9fafb', borderRadius: '6px', border: '1px solid #e5e7eb' }}>
                  <div style={{ color: '#6b7280', fontSize: '0.75rem' }}>OTLP Exporter Target</div>
                  <div style={{ fontWeight: 600, color: '#111827', marginTop: '0.2rem', wordBreak: 'break-all' }}>
                    {report.otlpEndpoint || 'None (Zero Egress)'}
                  </div>
                </div>
                <div style={{ padding: '0.75rem', backgroundColor: '#f9fafb', borderRadius: '6px', border: '1px solid #e5e7eb' }}>
                  <div style={{ color: '#6b7280', fontSize: '0.75rem' }}>Buffered Spans in Memory</div>
                  <div style={{ fontWeight: 600, color: '#111827', marginTop: '0.2rem' }}>{report.activeSpanCount} (Volatile)</div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'spans' && (
            <div>
              {spans.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '2rem', color: '#6b7280', fontSize: '0.875rem' }}>
                  No active spans buffered in volatile memory.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  {spans.map((s) => (
                    <div
                      key={s.id}
                      style={{
                        padding: '0.75rem',
                        borderRadius: '6px',
                        border: '1px solid #e5e7eb',
                        backgroundColor: '#f9fafb',
                        fontSize: '0.8rem',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontWeight: 600, color: '#111827' }}>
                        <span>{s.name}</span>
                        <span style={{ color: s.status === 'OK' ? '#059669' : '#dc2626' }}>{s.status} ({s.durationMs}ms)</span>
                      </div>
                      <div style={{ marginTop: '0.35rem', color: '#4b5563', fontFamily: 'monospace', fontSize: '0.75rem' }}>
                        {JSON.stringify(s.attributes, null, 2)}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'raw' && (
            <pre
              style={{
                margin: 0,
                padding: '1rem',
                backgroundColor: '#111827',
                color: '#10b981',
                borderRadius: '6px',
                fontSize: '0.75rem',
                fontFamily: 'monospace',
                overflowX: 'auto',
                maxHeight: '300px',
              }}
            >
              {JSON.stringify({ report, claims, spans }, null, 2)}
            </pre>
          )}
        </div>

        {/* Footer Actions */}
        <div
          style={{
            padding: '1rem 1.5rem',
            borderTop: '1px solid #e5e7eb',
            backgroundColor: '#f9fafb',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              onClick={handleExportJson}
              style={{
                padding: '0.5rem 0.85rem',
                borderRadius: '6px',
                border: '1px solid #d1d5db',
                backgroundColor: '#ffffff',
                color: '#374151',
                cursor: 'pointer',
                fontSize: '0.8rem',
                fontWeight: 500,
              }}
            >
              Export JSON Audit
            </button>
            <button
              onClick={handleCopyJson}
              style={{
                padding: '0.5rem 0.85rem',
                borderRadius: '6px',
                border: '1px solid #d1d5db',
                backgroundColor: '#ffffff',
                color: '#374151',
                cursor: 'pointer',
                fontSize: '0.8rem',
                fontWeight: 500,
              }}
            >
              {copied ? 'Copied!' : 'Copy to Clipboard'}
            </button>
          </div>

          <button
            onClick={handleBurn}
            style={{
              padding: '0.5rem 1rem',
              borderRadius: '6px',
              border: 'none',
              backgroundColor: '#dc2626',
              color: '#ffffff',
              cursor: 'pointer',
              fontSize: '0.8rem',
              fontWeight: 600,
            }}
          >
            Burn Local Data
          </button>
        </div>
      </div>
    </div>
  );
};

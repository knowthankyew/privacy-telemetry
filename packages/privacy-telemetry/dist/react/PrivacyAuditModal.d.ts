import React from 'react';
import { TelemetryManager } from '../manager.js';
import { PrivacyClaimsBranding } from '../types.js';
export interface PrivacyAuditModalProps {
    isOpen: boolean;
    onClose: () => void;
    telemetry: TelemetryManager;
    branding?: PrivacyClaimsBranding;
    onBurn?: () => void;
    classNamePrefix?: string;
}
export declare const PrivacyAuditModal: React.FC<PrivacyAuditModalProps>;
//# sourceMappingURL=PrivacyAuditModal.d.ts.map
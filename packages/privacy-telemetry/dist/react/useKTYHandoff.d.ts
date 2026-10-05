import { KtyHandoffPayload } from '../handoff.js';
export interface UseKTYHandoffResult {
    payload: KtyHandoffPayload | null;
    isHandoffActive: boolean;
    clearHandoff: () => void;
}
/**
 * React hook to detect, parse, and monitor KTY handoff payloads in destination advocacy tools.
 *
 * Reads from sessionStorage['kty_handoff'] on mount.
 * Automatically clears payload state upon receiving Nuclear Hard Burn broadcast
 * via BroadcastChannel('kty_hard_burn') or postMessage.
 */
export declare function useKTYHandoff(expectedTargetTool?: string): UseKTYHandoffResult;
//# sourceMappingURL=useKTYHandoff.d.ts.map
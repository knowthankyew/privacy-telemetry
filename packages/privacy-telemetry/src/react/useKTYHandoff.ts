import { useState, useEffect, useCallback } from 'react';
import {
  KtyHandoffPayload,
  KTY_HANDOFF_SESSION_KEY,
  validateHandoffPayload,
} from '../handoff.js';

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
export function useKTYHandoff(expectedTargetTool?: string): UseKTYHandoffResult {
  const [payload, setPayload] = useState<KtyHandoffPayload | null>(() => {
    if (typeof window === 'undefined' || typeof sessionStorage === 'undefined') {
      return null;
    }
    try {
      const raw = sessionStorage.getItem(KTY_HANDOFF_SESSION_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (validateHandoffPayload(parsed)) {
        if (!expectedTargetTool || parsed.targetTool === expectedTargetTool) {
          return parsed;
        }
      }
    } catch {
      // Non-fatal
    }
    return null;
  });

  const clearHandoff = useCallback(() => {
    setPayload(null);
    if (typeof sessionStorage !== 'undefined') {
      try {
        sessionStorage.removeItem(KTY_HANDOFF_SESSION_KEY);
      } catch {
        // Non-fatal
      }
    }
  }, []);

  useEffect(() => {
    // Nuclear Hard Burn coordination across frames and tabs
    let channel: BroadcastChannel | null = null;
    if (typeof BroadcastChannel !== 'undefined') {
      try {
        channel = new BroadcastChannel('kty_hard_burn');
        channel.onmessage = (event) => {
          if (event?.data?.type === 'KTY_HARD_BURN_DOM') {
            clearHandoff();
          }
        };
      } catch {
        // Non-fatal if BroadcastChannel is restricted
      }
    }

    const handleMessage = (event: MessageEvent) => {
      if (event?.data?.type === 'KTY_HARD_BURN_DOM') {
        clearHandoff();
        return;
      }
      if (event?.data?.type === 'KTY_HANDOFF_PAYLOAD') {
        const incoming = event.data?.payload;
        if (validateHandoffPayload(incoming)) {
          if (!expectedTargetTool || incoming.targetTool === expectedTargetTool) {
            setPayload(incoming);
            try {
              sessionStorage.setItem(KTY_HANDOFF_SESSION_KEY, JSON.stringify(incoming));
            } catch {
              // Non-fatal
            }
          }
        }
      }
    };

    if (typeof window !== 'undefined') {
      window.addEventListener('message', handleMessage);
    }

    return () => {
      if (channel) {
        try {
          channel.close();
        } catch {}
      }
      if (typeof window !== 'undefined') {
        window.removeEventListener('message', handleMessage);
      }
    };
  }, [clearHandoff, expectedTargetTool]);

  return {
    payload,
    isHandoffActive: payload !== null,
    clearHandoff,
  };
}

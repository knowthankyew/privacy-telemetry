import { useState, useEffect, useCallback } from 'react';
import {
  KtyHandoffPayload,
  KTY_HANDOFF_SESSION_KEY,
  extractHandoffFromHash,
  validateHandoffPayload,
} from '../handoff.js';
import { isHardBurned, markHardBurned, onHardBurn } from '../manager.js';

export interface UseKTYHandoffResult {
  payload: KtyHandoffPayload | null;
  isHandoffActive: boolean;
  clearHandoff: () => void;
}

function scrubHandoffHashFromUrl(remainingHash: string): void {
  try {
    if (typeof window === 'undefined') return;
    const pathname = window.location?.pathname || '/';
    const search = window.location?.search || '';
    const nextUrl = `${pathname}${search}${remainingHash}`;
    if (typeof window.history?.replaceState === 'function') {
      window.history.replaceState(null, '', nextUrl);
    }
  } catch {
    // Non-fatal in restricted browser/test contexts
  }
}

function readInitialHandoffPayload(expectedTargetTool?: string): KtyHandoffPayload | null {
  try {
    if (typeof window === 'undefined') {
      return null;
    }

    const hash = typeof window.location?.hash === 'string' ? window.location.hash : '';
    const { payload: hashPayload, hasHandoffParam, remainingHash } = extractHandoffFromHash(
      hash,
      expectedTargetTool
    );

    if (hasHandoffParam) {
      // Scrub fragment immediately so URL bar and active history entry do not retain the payload
      scrubHandoffHashFromUrl(remainingHash);
    }

    if (isHardBurned()) {
      if (typeof sessionStorage !== 'undefined') {
        sessionStorage.removeItem(KTY_HANDOFF_SESSION_KEY);
      }
      return null;
    }

    if (hashPayload) {
      if (typeof sessionStorage !== 'undefined') {
        try {
          sessionStorage.setItem(KTY_HANDOFF_SESSION_KEY, JSON.stringify(hashPayload));
        } catch {
          // Non-fatal if sessionStorage restricted
        }
      }
      return hashPayload;
    }

    if (typeof sessionStorage === 'undefined') {
      return null;
    }
    const raw = sessionStorage.getItem(KTY_HANDOFF_SESSION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (validateHandoffPayload(parsed)) {
      if (!expectedTargetTool || parsed.targetTool === expectedTargetTool) {
        return parsed;
      }
    }
  } catch {
    // Non-fatal (e.g. SecurityError on storage access in restricted contexts)
  }
  return null;
}

/**
 * React hook to detect, parse, and monitor KTY handoff payloads in destination advocacy tools.
 *
 * Reads from URL fragment (#kty_handoff=..., immediately scrubbed via history.replaceState)
 * or sessionStorage['kty_handoff'] on mount.
 * Automatically clears payload state upon receiving Nuclear Hard Burn broadcast
 * via BroadcastChannel('kty_hard_burn'), postMessage, or TelemetryManager.burn().
 */
export function useKTYHandoff(expectedTargetTool?: string): UseKTYHandoffResult {
  // Use useState ref cell instead of useRef so destination app unit tests mocking
  // only { useState, useEffect, useCallback } execute without harness changes.
  const [burnedRef] = useState(() => ({ current: isHardBurned() }));
  const [payload, setPayload] = useState<KtyHandoffPayload | null>(() =>
    readInitialHandoffPayload(expectedTargetTool)
  );

  const scrubHandoffStorage = useCallback(() => {
    try {
      if (typeof sessionStorage !== 'undefined') {
        sessionStorage.removeItem(KTY_HANDOFF_SESSION_KEY);
      }
    } catch {
      // Non-fatal
    }
  }, []);

  const clearHandoff = useCallback(() => {
    setPayload(null);
    scrubHandoffStorage();
  }, [scrubHandoffStorage]);

  const applyLocalBurn = useCallback(() => {
    burnedRef.current = true;
    setPayload(null);
    scrubHandoffStorage();
  }, [burnedRef, scrubHandoffStorage]);

  const applyHardBurn = useCallback(() => {
    applyLocalBurn();
    markHardBurned();
  }, [applyLocalBurn]);

  useEffect(() => {
    if (isHardBurned() || burnedRef.current) {
      applyLocalBurn();
    }
    const unsubscribeBurn = onHardBurn(applyLocalBurn);

    // Nuclear Hard Burn coordination across frames and tabs
    let channel: BroadcastChannel | null = null;
    if (typeof BroadcastChannel !== 'undefined') {
      try {
        channel = new BroadcastChannel('kty_hard_burn');
        channel.onmessage = (event) => {
          if (event?.data?.type === 'KTY_HARD_BURN_DOM') {
            applyHardBurn();
          }
        };
      } catch {
        // Non-fatal if BroadcastChannel is restricted
      }
    }

    const handleMessage = (event: MessageEvent) => {
      if (typeof window === 'undefined') return;
      const expectedOrigin = window.location?.origin;
      // All supported extension delivery paths execute inside the destination tab's window:
      // - knowthankyew-extension/src/popup/handoff-bridge.ts runs chrome.scripting.executeScript in the target tab
      //   and calls window.postMessage({ type: 'KTY_HANDOFF_PAYLOAD', payload }, window.location.origin)
      // - knowthankyew-extension/src/content/scanner.ts (handleHardBurnDOM) calls
      //   window.postMessage({ type: 'KTY_HARD_BURN_DOM' }, window.location.origin) alongside BroadcastChannel('kty_hard_burn').
      // Consequently every legitimate message has event.source === window and event.origin === window.location.origin;
      // direct cross-frame or foreign-origin messages are untrusted and rejected fail-closed.
      if (
        event?.source !== window ||
        typeof expectedOrigin !== 'string' ||
        expectedOrigin.length === 0 ||
        expectedOrigin === 'null' ||
        event.origin !== expectedOrigin
      ) {
        return;
      }
      if (event?.data?.type === 'KTY_HARD_BURN_DOM') {
        applyHardBurn();
        return;
      }
      if (event?.data?.type === 'KTY_HANDOFF_PAYLOAD') {
        if (burnedRef.current || isHardBurned()) {
          burnedRef.current = true;
          scrubHandoffStorage();
          return;
        }
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

    const handleHashChange = () => {
      if (typeof window === 'undefined') return;
      const hash = typeof window.location?.hash === 'string' ? window.location.hash : '';
      const { payload: incoming, hasHandoffParam, remainingHash } = extractHandoffFromHash(
        hash,
        expectedTargetTool
      );
      if (hasHandoffParam) {
        scrubHandoffHashFromUrl(remainingHash);
      }
      if (burnedRef.current || isHardBurned()) {
        burnedRef.current = true;
        scrubHandoffStorage();
        return;
      }
      if (incoming) {
        setPayload(incoming);
        try {
          if (typeof sessionStorage !== 'undefined') {
            sessionStorage.setItem(KTY_HANDOFF_SESSION_KEY, JSON.stringify(incoming));
          }
        } catch {
          // Non-fatal
        }
      }
    };

    if (typeof window !== 'undefined') {
      window.addEventListener('message', handleMessage);
      window.addEventListener('hashchange', handleHashChange);
    }

    return () => {
      unsubscribeBurn();
      if (channel) {
        try {
          channel.close();
        } catch {}
      }
      if (typeof window !== 'undefined') {
        window.removeEventListener('message', handleMessage);
        window.removeEventListener('hashchange', handleHashChange);
      }
    };
  }, [applyHardBurn, burnedRef, expectedTargetTool, scrubHandoffStorage]);

  return {
    payload,
    isHandoffActive: payload !== null,
    clearHandoff,
  };
}

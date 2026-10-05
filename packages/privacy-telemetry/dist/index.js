import { n as e, t } from "./chunks/handoff-BaHIRjvl.js";
//#region src/allowlist.ts
var n = /* @__PURE__ */ new Set(/* @__PURE__ */ "rule_id.rule_ids.statute_code.jurisdiction.status.risk_level.duration_ms.duration_sec.clause_count.total_clauses.flagged_clauses.flagged_count.standard_count.watch_count.unenforceable_count.char_count.matched_violations.error_code.job_id.service.action.step.current_step.total_steps.progress_pct.loss.device.adapter_size_bytes.dataset_hash.exchange.routing_key".split("."));
function r(e) {
	let t = new Set(n);
	if (e) for (let n of e) t.add(n.toLowerCase());
	return {
		allowlist: t,
		sanitize: (e, n = !1) => {
			let r = {};
			for (let [i, a] of Object.entries(e)) {
				let e = i.toLowerCase();
				if (!t.has(e) && !n) {
					r[i] = "[REDACTED_BY_DEFAULT_ALLOWLIST]";
					continue;
				}
				typeof a == "string" ? r[i] = a.length > 256 && !n ? `[TRUNCATED_HASH_${a.slice(0, 8)}...]` : a : (typeof a == "number" || typeof a == "boolean") && (r[i] = a);
			}
			return r;
		}
	};
}
//#endregion
//#region src/exporter.ts
var i = class {
	spans = [];
	maxCapacity;
	constructor(e = 500) {
		this.maxCapacity = e;
	}
	export(e) {
		this.spans.push(e), this.spans.length > this.maxCapacity && this.spans.shift();
	}
	getSpans() {
		return this.spans;
	}
	clear() {
		this.spans = [];
	}
	count() {
		return this.spans.length;
	}
};
async function a(e, t, n = "knowthankyew-app") {
	if (typeof fetch < "u") try {
		await fetch(e, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ resourceSpans: [{
				resource: { attributes: [{
					key: "service.name",
					value: { stringValue: n }
				}] },
				scopeSpans: [{ spans: [{
					traceId: t.id,
					spanId: t.id,
					name: t.name,
					startTimeUnixNano: t.startTime * 1e6,
					endTimeUnixNano: (t.endTime || t.startTime) * 1e6,
					attributes: Object.entries(t.attributes).map(([e, t]) => ({
						key: e,
						value: typeof t == "string" ? { stringValue: t } : typeof t == "number" ? { intValue: t } : { boolValue: t }
					})),
					status: { code: t.status === "OK" ? 1 : t.status === "ERROR" ? 2 : 0 }
				}] }]
			}] })
		});
	} catch {}
}
//#endregion
//#region src/claims.ts
function o(e, t) {
	return e.isLocalOnlyHonest ? {
		isLocalOnlyHonest: !0,
		isEnterpriseBuild: !1,
		appTitleSuffix: "",
		badgeLabel: "Zero Network • Memory-Only",
		dropzoneNotice: "100% Client-Side Local Execution • Zero Network Transmission",
		disclaimerExecutionText: t?.domainDisclaimerClause ? t.domainDisclaimerClause : "All rule evaluations execute 100% locally in your browser with zero remote network transmission.",
		footerTitle: t?.consumerFooterTitle || "100% Local Air-Gapped Compliance Engine.",
		footerSubtext: t?.consumerFooterSubtext || "Zero Telemetry • Zero Remote PII/Document Egress • Grounded Statutory Realities",
		modalStatusTitle: "100% Local-First & Private (Memory-Only Telemetry)",
		modalStatusDescription: "All computation and telemetry spans remain buffered strictly in volatile memory. No outbound network calls are made. Telemetry purges immediately upon invoking \"Burn Local Data\".",
		otlpEndpoint: null
	} : {
		isLocalOnlyHonest: !1,
		isEnterpriseBuild: !0,
		appTitleSuffix: t?.appTitleSuffix || " (Enterprise Build)",
		badgeLabel: `OTLP Active (${e.telemetryMode})`,
		dropzoneNotice: "Local Document Parsing • OTLP Operational Metadata Active (Strictly Redacted)",
		disclaimerExecutionText: `Rule evaluations execute in-browser. Scrubbed operational telemetry is exported to configured OTLP endpoint (${e.otlpEndpoint}). Document text is never transmitted.`,
		footerTitle: t?.enterpriseFooterTitle || "Enterprise Compliance Engine (OTLP Telemetry Active).",
		footerSubtext: t?.enterpriseFooterSubtext || "Enterprise Telemetry Mode • Operational Metadata Export Active • Document Bodies Air-Gapped",
		modalStatusTitle: "Enterprise OTLP Telemetry Active",
		modalStatusDescription: `Telemetry spans are exported to configured OTLP endpoint: ${e.otlpEndpoint}. Document text and sensitive fields are redacted via strict allowlist.`,
		otlpEndpoint: e.otlpEndpoint
	};
}
//#endregion
//#region src/manager.ts
var s = class {
	config;
	memoryExporter;
	auditLog = [];
	isBurned = !1;
	sanitizer;
	allowlist;
	constructor(e, t) {
		let n;
		try {
			n = void 0;
		} catch {}
		n ||= (typeof globalThis < "u" ? globalThis : void 0)?.process?.env?.OTEL_EXPORTER_OTLP_ENDPOINT;
		let a = n ? "otlp" : "memory_only";
		this.config = {
			mode: a,
			otlpEndpoint: n || null,
			allowRawPayloads: !1,
			burnEnabled: !0,
			auditDurable: !1,
			networkEgress: a === "otlp" ? "allow_otlp" : "deny",
			serviceName: "knowthankyew-app",
			...e
		};
		let { allowlist: o, sanitize: s } = r(t);
		this.allowlist = o, this.sanitizer = s, this.memoryExporter = new i();
	}
	getConfig() {
		return this.config;
	}
	updateConfig(e) {
		this.config = {
			...this.config,
			...e
		}, this.config.otlpEndpoint && this.config.mode === "memory_only" && (this.config.mode = "otlp", this.config.networkEgress = "allow_otlp");
	}
	sanitizeAttributes(e) {
		return this.sanitizer(e, this.config.allowRawPayloads);
	}
	startSpan(e, t = {}) {
		if (this.config.mode === "disabled" || this.isBurned) return {
			spanId: "noop",
			end: () => {}
		};
		let n = `span_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`, r = Date.now(), i = this.sanitizeAttributes(t);
		return {
			spanId: n,
			end: (t = "OK", o = {}) => {
				if (this.config.mode === "disabled" || this.isBurned) return;
				let s = Date.now(), c = {
					...i,
					...this.sanitizeAttributes(o)
				}, l = {
					id: n,
					name: e,
					startTime: r,
					endTime: s,
					durationMs: s - r,
					status: t,
					attributes: c,
					events: []
				};
				this.memoryExporter.export(l), this.config.mode === "otlp" && this.config.otlpEndpoint && a(this.config.otlpEndpoint, l, this.config.serviceName);
			}
		};
	}
	recordAuditEvent(e, t, n) {
		this.isBurned || this.auditLog.push({
			id: `audit_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
			timestamp: (/* @__PURE__ */ new Date()).toISOString(),
			action: e,
			summary: t,
			details: n ? this.sanitizeAttributes(n) : void 0
		});
	}
	getBufferedSpans() {
		return this.memoryExporter.getSpans();
	}
	getMemorySpans() {
		return this.memoryExporter.getSpans();
	}
	getAuditLog() {
		return this.auditLog;
	}
	downloadSessionAuditJson() {
		let e = {
			generatedAt: (/* @__PURE__ */ new Date()).toISOString(),
			service: this.config.serviceName || "knowthankyew-app",
			telemetryMode: this.config.mode,
			eventCount: this.auditLog.length,
			events: this.auditLog
		};
		return JSON.stringify(e, null, 2);
	}
	getPrivacyAuditReport() {
		let e = this.config.mode !== "otlp" && !this.config.otlpEndpoint && this.config.networkEgress === "deny";
		return {
			telemetryMode: this.config.mode,
			networkEgress: this.config.networkEgress,
			burnEnabled: this.config.burnEnabled,
			durableAudit: this.config.auditDurable,
			otlpEndpoint: this.config.otlpEndpoint || null,
			allowRawPayloads: this.config.allowRawPayloads,
			activeSpanCount: this.memoryExporter.count(),
			sessionAuditCount: this.auditLog.length,
			isLocalOnlyHonest: e
		};
	}
	getPrivacyClaims(e) {
		return o(this.getPrivacyAuditReport(), e);
	}
	burn() {
		this.config.burnEnabled && (this.memoryExporter.clear(), this.auditLog = [], this.isBurned = !0);
	}
	reset() {
		this.memoryExporter.clear(), this.auditLog = [], this.isBurned = !1;
	}
	restartSession() {
		this.reset();
	}
};
//#endregion
export { n as DEFAULT_SAFE_ALLOWLIST_KEYS, t as KTY_HANDOFF_SESSION_KEY, i as MemoryExporter, s as TelemetryManager, r as createAllowlistSanitizer, a as exportToOtlp, o as getPrivacyClaims, e as validateHandoffPayload };

//#region src/allowlist.ts
var e = /* @__PURE__ */ new Set(/* @__PURE__ */ "rule_id.rule_ids.statute_code.jurisdiction.status.risk_level.duration_ms.duration_sec.clause_count.total_clauses.flagged_clauses.flagged_count.standard_count.watch_count.unenforceable_count.char_count.matched_violations.error_code.job_id.service.action.step.current_step.total_steps.progress_pct.loss.device.adapter_size_bytes.dataset_hash.exchange.routing_key".split("."));
function t(t) {
	let n = new Set(e);
	if (t) for (let e of t) n.add(e.toLowerCase());
	return {
		allowlist: n,
		sanitize: (e, t = !1) => {
			let r = {};
			for (let [i, a] of Object.entries(e)) {
				let e = i.toLowerCase();
				if (!n.has(e) && !t) {
					r[i] = "[REDACTED_BY_DEFAULT_ALLOWLIST]";
					continue;
				}
				typeof a == "string" ? r[i] = a.length > 256 && !t ? `[TRUNCATED_HASH_${a.slice(0, 8)}...]` : a : (typeof a == "number" || typeof a == "boolean") && (r[i] = a);
			}
			return r;
		}
	};
}
//#endregion
//#region src/exporter.ts
var n = class {
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
async function r(e, t, n = "knowthankyew-app") {
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
function i(e, t) {
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
var a = class {
	config;
	memoryExporter;
	auditLog = [];
	isBurned = !1;
	sanitizer;
	allowlist;
	constructor(e, r) {
		let i;
		try {
			i = void 0;
		} catch {}
		i ||= (typeof globalThis < "u" ? globalThis : void 0)?.process?.env?.OTEL_EXPORTER_OTLP_ENDPOINT;
		let a = i ? "otlp" : "memory_only";
		this.config = {
			mode: a,
			otlpEndpoint: i || null,
			allowRawPayloads: !1,
			burnEnabled: !0,
			auditDurable: !1,
			networkEgress: a === "otlp" ? "allow_otlp" : "deny",
			serviceName: "knowthankyew-app",
			...e
		};
		let { allowlist: o, sanitize: s } = t(r);
		this.allowlist = o, this.sanitizer = s, this.memoryExporter = new n();
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
		let n = `span_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`, i = Date.now(), a = this.sanitizeAttributes(t);
		return {
			spanId: n,
			end: (t = "OK", o = {}) => {
				if (this.config.mode === "disabled" || this.isBurned) return;
				let s = Date.now(), c = {
					...a,
					...this.sanitizeAttributes(o)
				}, l = {
					id: n,
					name: e,
					startTime: i,
					endTime: s,
					durationMs: s - i,
					status: t,
					attributes: c,
					events: []
				};
				this.memoryExporter.export(l), this.config.mode === "otlp" && this.config.otlpEndpoint && r(this.config.otlpEndpoint, l, this.config.serviceName);
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
		return i(this.getPrivacyAuditReport(), e);
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
export { e as DEFAULT_SAFE_ALLOWLIST_KEYS, n as MemoryExporter, a as TelemetryManager, t as createAllowlistSanitizer, r as exportToOtlp, i as getPrivacyClaims };

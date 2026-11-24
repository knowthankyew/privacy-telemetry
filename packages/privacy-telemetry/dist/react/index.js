import { a as e, c as t, g as n, l as r, n as i, o as a } from "../chunks/handoff-BWF4gglc.js";
import { useCallback as o, useEffect as s, useState as c } from "react";
import { jsx as l, jsxs as u } from "react/jsx-runtime";
// src/react/usePrivacyTelemetry.ts
function d(e, t) {
	let [n, r] = c(() => e.getPrivacyAuditReport()), [i, a] = c(() => e.getPrivacyClaims(t)), [l, u] = c(() => e.getBufferedSpans()), d = o(() => {
		r(e.getPrivacyAuditReport()), a(e.getPrivacyClaims(t)), u(e.getBufferedSpans());
	}, [e, t]), f = o(() => {
		e.burn(), d();
	}, [e, d]);
	return s(() => {
		d();
	}, [d]), {
		report: n,
		claims: i,
		spans: l,
		spanCount: l.length,
		burn: f,
		refresh: d
	};
}
function f(e, t) {
	let [n, r] = c(() => e.getPrivacyClaims(t));
	return s(() => {
		r(e.getPrivacyClaims(t));
	}, [e, t]), n;
}
// src/react/PrivacyAuditModal.tsx
var p = ({ isOpen: e, onClose: t, telemetry: n, branding: r, onBurn: i, classNamePrefix: a = "privacy-modal" }) => {
	let [o, d] = c("overview"), [f, p] = c(() => n.getPrivacyAuditReport()), [m, h] = c(() => n.getPrivacyClaims(r)), [g, _] = c(() => n.getBufferedSpans()), [v, y] = c(!1);
	return s(() => {
		e && (p(n.getPrivacyAuditReport()), h(n.getPrivacyClaims(r)), _(n.getBufferedSpans()));
	}, [
		e,
		n,
		r
	]), e ? /* @__PURE__ */ l("div", {
		role: "dialog",
		"aria-modal": "true",
		"aria-labelledby": "privacy-audit-modal-title",
		style: {
			position: "fixed",
			inset: 0,
			backgroundColor: "rgba(0, 0, 0, 0.65)",
			backdropFilter: "blur(4px)",
			zIndex: 9999,
			display: "flex",
			alignItems: "center",
			justifyContent: "center",
			padding: "1rem"
		},
		children: /* @__PURE__ */ u("div", {
			style: {
				backgroundColor: "#ffffff",
				borderRadius: "12px",
				width: "100%",
				maxWidth: "750px",
				maxHeight: "85vh",
				display: "flex",
				flexDirection: "column",
				boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.3)",
				overflow: "hidden",
				fontFamily: "system-ui, -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, sans-serif"
			},
			className: `${a}-container`,
			children: [
				/* @__PURE__ */ u("div", {
					style: {
						padding: "1.25rem 1.5rem",
						borderBottom: "1px solid #e5e7eb",
						display: "flex",
						alignItems: "center",
						justifyContent: "space-between",
						backgroundColor: "#f9fafb"
					},
					children: [/* @__PURE__ */ u("div", {
						style: {
							display: "flex",
							alignItems: "center",
							gap: "0.75rem"
						},
						children: [/* @__PURE__ */ l("svg", {
							width: "22",
							height: "22",
							viewBox: "0 0 24 24",
							fill: "none",
							stroke: "#059669",
							strokeWidth: "2",
							children: /* @__PURE__ */ l("path", { d: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" })
						}), /* @__PURE__ */ u("div", { children: [/* @__PURE__ */ l("h3", {
							id: "privacy-audit-modal-title",
							style: {
								margin: 0,
								fontSize: "1.15rem",
								fontWeight: 600,
								color: "#111827"
							},
							children: "Privacy & Telemetry Live Audit"
						}), /* @__PURE__ */ l("p", {
							style: {
								margin: "0.15rem 0 0",
								fontSize: "0.8rem",
								color: "#6b7280"
							},
							children: "Inspect volatile memory buffers, egress policy, and allowlist redactions"
						})] })]
					}), /* @__PURE__ */ l("button", {
						onClick: t,
						"aria-label": "Close modal",
						style: {
							background: "none",
							border: "none",
							cursor: "pointer",
							color: "#9ca3af",
							padding: "0.25rem",
							display: "flex"
						},
						children: /* @__PURE__ */ u("svg", {
							width: "20",
							height: "20",
							viewBox: "0 0 24 24",
							fill: "none",
							stroke: "currentColor",
							strokeWidth: "2",
							children: [/* @__PURE__ */ l("line", {
								x1: "18",
								y1: "6",
								x2: "6",
								y2: "18"
							}), /* @__PURE__ */ l("line", {
								x1: "6",
								y1: "6",
								x2: "18",
								y2: "18"
							})]
						})
					})]
				}),
				/* @__PURE__ */ l("div", {
					style: {
						display: "flex",
						borderBottom: "1px solid #e5e7eb",
						padding: "0 1.5rem",
						backgroundColor: "#ffffff"
					},
					children: [
						"overview",
						"spans",
						"raw"
					].map((e) => /* @__PURE__ */ l("button", {
						onClick: () => d(e),
						style: {
							padding: "0.75rem 1rem",
							border: "none",
							background: "none",
							cursor: "pointer",
							fontWeight: o === e ? 600 : 500,
							color: o === e ? "#2563eb" : "#6b7280",
							borderBottom: o === e ? "2px solid #2563eb" : "2px solid transparent",
							textTransform: "capitalize",
							fontSize: "0.875rem"
						},
						children: e === "spans" ? `Spans (${g.length})` : e
					}, e))
				}),
				/* @__PURE__ */ u("div", {
					style: {
						padding: "1.5rem",
						overflowY: "auto",
						flex: 1,
						backgroundColor: "#ffffff"
					},
					children: [
						o === "overview" && /* @__PURE__ */ u("div", {
							style: {
								display: "flex",
								flexDirection: "column",
								gap: "1rem"
							},
							children: [/* @__PURE__ */ u("div", {
								style: {
									padding: "1rem",
									borderRadius: "8px",
									backgroundColor: m.isEnterpriseBuild ? "#fef3c7" : "#ecfdf5",
									border: `1px solid ${m.isEnterpriseBuild ? "#f59e0b" : "#10b981"}`
								},
								children: [/* @__PURE__ */ l("h4", {
									style: {
										margin: 0,
										fontSize: "0.95rem",
										fontWeight: 600,
										color: m.isEnterpriseBuild ? "#92400e" : "#065f46"
									},
									children: m.modalStatusTitle
								}), /* @__PURE__ */ l("p", {
									style: {
										margin: "0.35rem 0 0",
										fontSize: "0.825rem",
										color: m.isEnterpriseBuild ? "#78350f" : "#047857"
									},
									children: m.modalStatusDescription
								})]
							}), /* @__PURE__ */ u("div", {
								style: {
									display: "grid",
									gridTemplateColumns: "repeat(2, 1fr)",
									gap: "0.75rem",
									fontSize: "0.85rem"
								},
								children: [
									/* @__PURE__ */ u("div", {
										style: {
											padding: "0.75rem",
											backgroundColor: "#f9fafb",
											borderRadius: "6px",
											border: "1px solid #e5e7eb"
										},
										children: [/* @__PURE__ */ l("div", {
											style: {
												color: "#6b7280",
												fontSize: "0.75rem"
											},
											children: "Telemetry Mode"
										}), /* @__PURE__ */ l("div", {
											style: {
												fontWeight: 600,
												color: "#111827",
												marginTop: "0.2rem"
											},
											children: f.telemetryMode
										})]
									}),
									/* @__PURE__ */ u("div", {
										style: {
											padding: "0.75rem",
											backgroundColor: "#f9fafb",
											borderRadius: "6px",
											border: "1px solid #e5e7eb"
										},
										children: [/* @__PURE__ */ l("div", {
											style: {
												color: "#6b7280",
												fontSize: "0.75rem"
											},
											children: "Network Egress Policy"
										}), /* @__PURE__ */ l("div", {
											style: {
												fontWeight: 600,
												color: f.networkEgress === "deny" ? "#059669" : "#d97706",
												marginTop: "0.2rem"
											},
											children: f.networkEgress.toUpperCase()
										})]
									}),
									/* @__PURE__ */ u("div", {
										style: {
											padding: "0.75rem",
											backgroundColor: "#f9fafb",
											borderRadius: "6px",
											border: "1px solid #e5e7eb"
										},
										children: [/* @__PURE__ */ l("div", {
											style: {
												color: "#6b7280",
												fontSize: "0.75rem"
											},
											children: "OTLP Exporter Target"
										}), /* @__PURE__ */ l("div", {
											style: {
												fontWeight: 600,
												color: "#111827",
												marginTop: "0.2rem",
												wordBreak: "break-all"
											},
											children: f.otlpEndpoint || "None (Zero Egress)"
										})]
									}),
									/* @__PURE__ */ u("div", {
										style: {
											padding: "0.75rem",
											backgroundColor: "#f9fafb",
											borderRadius: "6px",
											border: "1px solid #e5e7eb"
										},
										children: [/* @__PURE__ */ l("div", {
											style: {
												color: "#6b7280",
												fontSize: "0.75rem"
											},
											children: "Buffered Spans in Memory"
										}), /* @__PURE__ */ u("div", {
											style: {
												fontWeight: 600,
												color: "#111827",
												marginTop: "0.2rem"
											},
											children: [f.activeSpanCount, " (Volatile)"]
										})]
									})
								]
							})]
						}),
						o === "spans" && /* @__PURE__ */ l("div", { children: g.length === 0 ? /* @__PURE__ */ l("div", {
							style: {
								textAlign: "center",
								padding: "2rem",
								color: "#6b7280",
								fontSize: "0.875rem"
							},
							children: "No active spans buffered in volatile memory."
						}) : /* @__PURE__ */ l("div", {
							style: {
								display: "flex",
								flexDirection: "column",
								gap: "0.75rem"
							},
							children: g.map((e) => /* @__PURE__ */ u("div", {
								style: {
									padding: "0.75rem",
									borderRadius: "6px",
									border: "1px solid #e5e7eb",
									backgroundColor: "#f9fafb",
									fontSize: "0.8rem"
								},
								children: [/* @__PURE__ */ u("div", {
									style: {
										display: "flex",
										justifyContent: "space-between",
										fontWeight: 600,
										color: "#111827"
									},
									children: [/* @__PURE__ */ l("span", { children: e.name }), /* @__PURE__ */ u("span", {
										style: { color: e.status === "OK" ? "#059669" : "#dc2626" },
										children: [
											e.status,
											" (",
											e.durationMs,
											"ms)"
										]
									})]
								}), /* @__PURE__ */ l("div", {
									style: {
										marginTop: "0.35rem",
										color: "#4b5563",
										fontFamily: "monospace",
										fontSize: "0.75rem"
									},
									children: JSON.stringify(e.attributes, null, 2)
								})]
							}, e.id))
						}) }),
						o === "raw" && /* @__PURE__ */ l("pre", {
							style: {
								margin: 0,
								padding: "1rem",
								backgroundColor: "#111827",
								color: "#10b981",
								borderRadius: "6px",
								fontSize: "0.75rem",
								fontFamily: "monospace",
								overflowX: "auto",
								maxHeight: "300px"
							},
							children: JSON.stringify({
								report: f,
								claims: m,
								spans: g
							}, null, 2)
						})
					]
				}),
				/* @__PURE__ */ u("div", {
					style: {
						padding: "1rem 1.5rem",
						borderTop: "1px solid #e5e7eb",
						backgroundColor: "#f9fafb",
						display: "flex",
						justifyContent: "space-between",
						alignItems: "center"
					},
					children: [/* @__PURE__ */ u("div", {
						style: {
							display: "flex",
							gap: "0.5rem"
						},
						children: [/* @__PURE__ */ l("button", {
							onClick: () => {
								let e = {
									auditTimestamp: (/* @__PURE__ */ new Date()).toISOString(),
									report: f,
									claims: m,
									spans: g,
									allowlist: Array.from(n.allowlist)
								}, t = new Blob([JSON.stringify(e, null, 2)], { type: "application/json" }), r = URL.createObjectURL(t), i = document.createElement("a");
								i.href = r, i.download = `privacy-telemetry-audit-${Date.now()}.json`, i.click(), URL.revokeObjectURL(r);
							},
							style: {
								padding: "0.5rem 0.85rem",
								borderRadius: "6px",
								border: "1px solid #d1d5db",
								backgroundColor: "#ffffff",
								color: "#374151",
								cursor: "pointer",
								fontSize: "0.8rem",
								fontWeight: 500
							},
							children: "Export JSON Audit"
						}), /* @__PURE__ */ l("button", {
							onClick: () => {
								let e = {
									auditTimestamp: (/* @__PURE__ */ new Date()).toISOString(),
									report: f,
									claims: m,
									spans: g,
									allowlist: Array.from(n.allowlist)
								};
								navigator.clipboard.writeText(JSON.stringify(e, null, 2)), y(!0), setTimeout(() => y(!1), 2e3);
							},
							style: {
								padding: "0.5rem 0.85rem",
								borderRadius: "6px",
								border: "1px solid #d1d5db",
								backgroundColor: "#ffffff",
								color: "#374151",
								cursor: "pointer",
								fontSize: "0.8rem",
								fontWeight: 500
							},
							children: v ? "Copied!" : "Copy to Clipboard"
						})]
					}), /* @__PURE__ */ l("button", {
						onClick: () => {
							n.burn(), p(n.getPrivacyAuditReport()), h(n.getPrivacyClaims(r)), _(n.getBufferedSpans()), i && i();
						},
						style: {
							padding: "0.5rem 1rem",
							borderRadius: "6px",
							border: "none",
							backgroundColor: "#dc2626",
							color: "#ffffff",
							cursor: "pointer",
							fontSize: "0.8rem",
							fontWeight: 600
						},
						children: "Burn Local Data"
					})]
				})
			]
		})
	}) : null;
};
// src/react/useKTYHandoff.ts
function m(e) {
	try {
		if (typeof window > "u") return;
		let t = `${window.location?.pathname || "/"}${window.location?.search || ""}${e}`;
		typeof window.history?.replaceState == "function" && window.history.replaceState(null, "", t);
	} catch {}
}
function h(t) {
	try {
		if (typeof window > "u") return null;
		let r = typeof window.location?.hash == "string" ? window.location.hash : "", { payload: o, hasHandoffParam: s, remainingHash: c } = e(r, t);
		if (s && m(c), n()) return typeof sessionStorage < "u" && sessionStorage.removeItem(i), null;
		if (o) {
			if (typeof sessionStorage < "u") try {
				sessionStorage.setItem(i, JSON.stringify(o));
			} catch {}
			return o;
		}
		if (typeof sessionStorage > "u") return null;
		let l = sessionStorage.getItem(i);
		if (!l) return null;
		let u = JSON.parse(l);
		if (a(u) && (!t || u.targetTool === t)) return u;
	} catch {}
	return null;
}
function g(l) {
	let [u] = c(() => ({ current: n() })), [d, f] = c(() => h(l)), p = o(() => {
		try {
			typeof sessionStorage < "u" && sessionStorage.removeItem(i);
		} catch {}
	}, []), g = o(() => {
		f(null), p();
	}, [p]), _ = o(() => {
		u.current = !0, f(null), p();
	}, [u, p]), v = o(() => {
		_(), t();
	}, [_]);
	return s(() => {
		(n() || u.current) && _();
		let t = r(_), o = null;
		if (typeof BroadcastChannel < "u") try {
			o = new BroadcastChannel("kty_hard_burn"), o.onmessage = (e) => {
				e?.data?.type === "KTY_HARD_BURN_DOM" && v();
			};
		} catch {}
		let s = (e) => {
			if (typeof window > "u") return;
			let t = window.location?.origin;
			if (e?.source === window && typeof t == "string" && t.length !== 0 && t !== "null" && e.origin === t) {
				if (e?.data?.type === "KTY_HARD_BURN_DOM") v();
				else if (e?.data?.type === "KTY_HANDOFF_PAYLOAD") {
					if (u.current || n()) {
						u.current = !0, p();
						return;
					}
					let t = e.data?.payload;
					if (a(t) && (!l || t.targetTool === l)) {
						f(t);
						try {
							sessionStorage.setItem(i, JSON.stringify(t));
						} catch {}
					}
				}
			}
		}, c = () => {
			if (typeof window > "u") return;
			let t = typeof window.location?.hash == "string" ? window.location.hash : "", { payload: r, hasHandoffParam: a, remainingHash: o } = e(t, l);
			if (a && m(o), u.current || n()) u.current = !0, p();
			else if (r) {
				f(r);
				try {
					typeof sessionStorage < "u" && sessionStorage.setItem(i, JSON.stringify(r));
				} catch {}
			}
		};
		return typeof window < "u" && (window.addEventListener("message", s), window.addEventListener("hashchange", c)), () => {
			if (t(), o) try {
				o.close();
			} catch {}
			typeof window < "u" && (window.removeEventListener("message", s), window.removeEventListener("hashchange", c));
		};
	}, [
		v,
		u,
		l,
		p
	]), {
		payload: d,
		isHandoffActive: d !== null,
		clearHandoff: g
	};
}
export { p as PrivacyAuditModal, g as useKTYHandoff, f as usePrivacyClaims, d as usePrivacyTelemetry };

import { n as e, t } from "../chunks/handoff-BaHIRjvl.js";
import { useCallback as n, useEffect as r, useState as i } from "react";
import { jsx as a, jsxs as o } from "react/jsx-runtime";
//#region src/react/usePrivacyTelemetry.ts
function s(e, t) {
	let [a, o] = i(() => e.getPrivacyAuditReport()), [s, c] = i(() => e.getPrivacyClaims(t)), [l, u] = i(() => e.getBufferedSpans()), d = n(() => {
		o(e.getPrivacyAuditReport()), c(e.getPrivacyClaims(t)), u(e.getBufferedSpans());
	}, [e, t]), f = n(() => {
		e.burn(), d();
	}, [e, d]);
	return r(() => {
		d();
	}, [d]), {
		report: a,
		claims: s,
		spans: l,
		spanCount: l.length,
		burn: f,
		refresh: d
	};
}
function c(e, t) {
	let [n, a] = i(() => e.getPrivacyClaims(t));
	return r(() => {
		a(e.getPrivacyClaims(t));
	}, [e, t]), n;
}
//#endregion
//#region src/react/PrivacyAuditModal.tsx
var l = ({ isOpen: e, onClose: t, telemetry: n, branding: s, onBurn: c, classNamePrefix: l = "privacy-modal" }) => {
	let [u, d] = i("overview"), [f, p] = i(() => n.getPrivacyAuditReport()), [m, h] = i(() => n.getPrivacyClaims(s)), [g, _] = i(() => n.getBufferedSpans()), [v, y] = i(!1);
	return r(() => {
		e && (p(n.getPrivacyAuditReport()), h(n.getPrivacyClaims(s)), _(n.getBufferedSpans()));
	}, [
		e,
		n,
		s
	]), e ? /* @__PURE__ */ a("div", {
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
		children: /* @__PURE__ */ o("div", {
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
			className: `${l}-container`,
			children: [
				/* @__PURE__ */ o("div", {
					style: {
						padding: "1.25rem 1.5rem",
						borderBottom: "1px solid #e5e7eb",
						display: "flex",
						alignItems: "center",
						justifyContent: "space-between",
						backgroundColor: "#f9fafb"
					},
					children: [/* @__PURE__ */ o("div", {
						style: {
							display: "flex",
							alignItems: "center",
							gap: "0.75rem"
						},
						children: [/* @__PURE__ */ a("svg", {
							width: "22",
							height: "22",
							viewBox: "0 0 24 24",
							fill: "none",
							stroke: "#059669",
							strokeWidth: "2",
							children: /* @__PURE__ */ a("path", { d: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" })
						}), /* @__PURE__ */ o("div", { children: [/* @__PURE__ */ a("h3", {
							id: "privacy-audit-modal-title",
							style: {
								margin: 0,
								fontSize: "1.15rem",
								fontWeight: 600,
								color: "#111827"
							},
							children: "Privacy & Telemetry Live Audit"
						}), /* @__PURE__ */ a("p", {
							style: {
								margin: "0.15rem 0 0",
								fontSize: "0.8rem",
								color: "#6b7280"
							},
							children: "Inspect volatile memory buffers, egress policy, and allowlist redactions"
						})] })]
					}), /* @__PURE__ */ a("button", {
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
						children: /* @__PURE__ */ o("svg", {
							width: "20",
							height: "20",
							viewBox: "0 0 24 24",
							fill: "none",
							stroke: "currentColor",
							strokeWidth: "2",
							children: [/* @__PURE__ */ a("line", {
								x1: "18",
								y1: "6",
								x2: "6",
								y2: "18"
							}), /* @__PURE__ */ a("line", {
								x1: "6",
								y1: "6",
								x2: "18",
								y2: "18"
							})]
						})
					})]
				}),
				/* @__PURE__ */ a("div", {
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
					].map((e) => /* @__PURE__ */ a("button", {
						onClick: () => d(e),
						style: {
							padding: "0.75rem 1rem",
							border: "none",
							background: "none",
							cursor: "pointer",
							fontWeight: u === e ? 600 : 500,
							color: u === e ? "#2563eb" : "#6b7280",
							borderBottom: u === e ? "2px solid #2563eb" : "2px solid transparent",
							textTransform: "capitalize",
							fontSize: "0.875rem"
						},
						children: e === "spans" ? `Spans (${g.length})` : e
					}, e))
				}),
				/* @__PURE__ */ o("div", {
					style: {
						padding: "1.5rem",
						overflowY: "auto",
						flex: 1,
						backgroundColor: "#ffffff"
					},
					children: [
						u === "overview" && /* @__PURE__ */ o("div", {
							style: {
								display: "flex",
								flexDirection: "column",
								gap: "1rem"
							},
							children: [/* @__PURE__ */ o("div", {
								style: {
									padding: "1rem",
									borderRadius: "8px",
									backgroundColor: m.isEnterpriseBuild ? "#fef3c7" : "#ecfdf5",
									border: `1px solid ${m.isEnterpriseBuild ? "#f59e0b" : "#10b981"}`
								},
								children: [/* @__PURE__ */ a("h4", {
									style: {
										margin: 0,
										fontSize: "0.95rem",
										fontWeight: 600,
										color: m.isEnterpriseBuild ? "#92400e" : "#065f46"
									},
									children: m.modalStatusTitle
								}), /* @__PURE__ */ a("p", {
									style: {
										margin: "0.35rem 0 0",
										fontSize: "0.825rem",
										color: m.isEnterpriseBuild ? "#78350f" : "#047857"
									},
									children: m.modalStatusDescription
								})]
							}), /* @__PURE__ */ o("div", {
								style: {
									display: "grid",
									gridTemplateColumns: "repeat(2, 1fr)",
									gap: "0.75rem",
									fontSize: "0.85rem"
								},
								children: [
									/* @__PURE__ */ o("div", {
										style: {
											padding: "0.75rem",
											backgroundColor: "#f9fafb",
											borderRadius: "6px",
											border: "1px solid #e5e7eb"
										},
										children: [/* @__PURE__ */ a("div", {
											style: {
												color: "#6b7280",
												fontSize: "0.75rem"
											},
											children: "Telemetry Mode"
										}), /* @__PURE__ */ a("div", {
											style: {
												fontWeight: 600,
												color: "#111827",
												marginTop: "0.2rem"
											},
											children: f.telemetryMode
										})]
									}),
									/* @__PURE__ */ o("div", {
										style: {
											padding: "0.75rem",
											backgroundColor: "#f9fafb",
											borderRadius: "6px",
											border: "1px solid #e5e7eb"
										},
										children: [/* @__PURE__ */ a("div", {
											style: {
												color: "#6b7280",
												fontSize: "0.75rem"
											},
											children: "Network Egress Policy"
										}), /* @__PURE__ */ a("div", {
											style: {
												fontWeight: 600,
												color: f.networkEgress === "deny" ? "#059669" : "#d97706",
												marginTop: "0.2rem"
											},
											children: f.networkEgress.toUpperCase()
										})]
									}),
									/* @__PURE__ */ o("div", {
										style: {
											padding: "0.75rem",
											backgroundColor: "#f9fafb",
											borderRadius: "6px",
											border: "1px solid #e5e7eb"
										},
										children: [/* @__PURE__ */ a("div", {
											style: {
												color: "#6b7280",
												fontSize: "0.75rem"
											},
											children: "OTLP Exporter Target"
										}), /* @__PURE__ */ a("div", {
											style: {
												fontWeight: 600,
												color: "#111827",
												marginTop: "0.2rem",
												wordBreak: "break-all"
											},
											children: f.otlpEndpoint || "None (Zero Egress)"
										})]
									}),
									/* @__PURE__ */ o("div", {
										style: {
											padding: "0.75rem",
											backgroundColor: "#f9fafb",
											borderRadius: "6px",
											border: "1px solid #e5e7eb"
										},
										children: [/* @__PURE__ */ a("div", {
											style: {
												color: "#6b7280",
												fontSize: "0.75rem"
											},
											children: "Buffered Spans in Memory"
										}), /* @__PURE__ */ o("div", {
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
						u === "spans" && /* @__PURE__ */ a("div", { children: g.length === 0 ? /* @__PURE__ */ a("div", {
							style: {
								textAlign: "center",
								padding: "2rem",
								color: "#6b7280",
								fontSize: "0.875rem"
							},
							children: "No active spans buffered in volatile memory."
						}) : /* @__PURE__ */ a("div", {
							style: {
								display: "flex",
								flexDirection: "column",
								gap: "0.75rem"
							},
							children: g.map((e) => /* @__PURE__ */ o("div", {
								style: {
									padding: "0.75rem",
									borderRadius: "6px",
									border: "1px solid #e5e7eb",
									backgroundColor: "#f9fafb",
									fontSize: "0.8rem"
								},
								children: [/* @__PURE__ */ o("div", {
									style: {
										display: "flex",
										justifyContent: "space-between",
										fontWeight: 600,
										color: "#111827"
									},
									children: [/* @__PURE__ */ a("span", { children: e.name }), /* @__PURE__ */ o("span", {
										style: { color: e.status === "OK" ? "#059669" : "#dc2626" },
										children: [
											e.status,
											" (",
											e.durationMs,
											"ms)"
										]
									})]
								}), /* @__PURE__ */ a("div", {
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
						u === "raw" && /* @__PURE__ */ a("pre", {
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
				/* @__PURE__ */ o("div", {
					style: {
						padding: "1rem 1.5rem",
						borderTop: "1px solid #e5e7eb",
						backgroundColor: "#f9fafb",
						display: "flex",
						justifyContent: "space-between",
						alignItems: "center"
					},
					children: [/* @__PURE__ */ o("div", {
						style: {
							display: "flex",
							gap: "0.5rem"
						},
						children: [/* @__PURE__ */ a("button", {
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
						}), /* @__PURE__ */ a("button", {
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
					}), /* @__PURE__ */ a("button", {
						onClick: () => {
							n.burn(), p(n.getPrivacyAuditReport()), h(n.getPrivacyClaims(s)), _(n.getBufferedSpans()), c && c();
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
//#endregion
//#region src/react/useKTYHandoff.ts
function u(a) {
	let [o, s] = i(() => {
		if (typeof window > "u" || typeof sessionStorage > "u") return null;
		try {
			let n = sessionStorage.getItem(t);
			if (!n) return null;
			let r = JSON.parse(n);
			if (e(r) && (!a || r.targetTool === a)) return r;
		} catch {}
		return null;
	}), c = n(() => {
		if (s(null), typeof sessionStorage < "u") try {
			sessionStorage.removeItem(t);
		} catch {}
	}, []);
	return r(() => {
		let n = null;
		if (typeof BroadcastChannel < "u") try {
			n = new BroadcastChannel("kty_hard_burn"), n.onmessage = (e) => {
				e?.data?.type === "KTY_HARD_BURN_DOM" && c();
			};
		} catch {}
		let r = (n) => {
			if (n?.data?.type === "KTY_HARD_BURN_DOM") {
				c();
				return;
			}
			if (n?.data?.type === "KTY_HANDOFF_PAYLOAD") {
				let r = n.data?.payload;
				if (e(r) && (!a || r.targetTool === a)) {
					s(r);
					try {
						sessionStorage.setItem(t, JSON.stringify(r));
					} catch {}
				}
			}
		};
		return typeof window < "u" && window.addEventListener("message", r), () => {
			if (n) try {
				n.close();
			} catch {}
			typeof window < "u" && window.removeEventListener("message", r);
		};
	}, [c, a]), {
		payload: o,
		isHandoffActive: o !== null,
		clearHandoff: c
	};
}
//#endregion
export { l as PrivacyAuditModal, u as useKTYHandoff, c as usePrivacyClaims, s as usePrivacyTelemetry };

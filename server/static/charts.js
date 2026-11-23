"use strict";
// Tiny dependency-free SVG bar chart. Colours come from CSS variables so it follows light/dark mode.
// drawBars(target, { title, labels, series:[{name, values, color}], max, unit })
(function () {
  const NS = "http://www.w3.org/2000/svg";
  function el(tag, attrs, text) {
    const e = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
    if (text != null) e.textContent = text;
    return e;
  }
  window.drawBars = function (target, cfg) {
    const W = 640, H = 300, L = 44, R = 12, T = 28, B = 56;
    const pw = W - L - R, ph = H - T - B;
    const max = cfg.max || Math.max(1, ...cfg.series.flatMap((s) => s.values));
    const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": cfg.title, class: "chart" });
    svg.append(el("text", { x: L, y: 16, fill: "var(--fg)", "font-size": 13, "font-weight": 600 }, cfg.title));
    for (let i = 0; i <= 4; i++) {                      // grid + y labels
      const v = (max * i) / 4, y = T + ph - (ph * i) / 4;
      svg.append(el("line", { x1: L, x2: W - R, y1: y, y2: y, stroke: "var(--bd)", "stroke-width": 1 }));
      svg.append(el("text", { x: L - 6, y: y + 4, "text-anchor": "end", fill: "var(--mut)", "font-size": 11 }, Math.round(v) + (cfg.unit || "")));
    }
    const gw = pw / cfg.labels.length, bw = Math.min(26, (gw - 14) / cfg.series.length);
    cfg.labels.forEach((lab, i) => {
      const gx = L + gw * i + (gw - bw * cfg.series.length) / 2;
      cfg.series.forEach((s, j) => {
        const v = s.values[i], bh = (ph * v) / max, x = gx + bw * j, y = T + ph - bh;
        const bar = el("rect", { x, y, width: bw - 3, height: Math.max(bh, 0), rx: 3, fill: s.color });
        bar.append(el("title", {}, `${lab.id} - ${s.name}: ${v}${cfg.unit || ""}`));
        svg.append(bar);
        svg.append(el("text", { x: x + (bw - 3) / 2, y: y - 4, "text-anchor": "middle", fill: "var(--fg)", "font-size": 10 }, v));
      });
      svg.append(el("text", { x: L + gw * i + gw / 2, y: H - B + 18, "text-anchor": "middle", fill: "var(--fg)", "font-size": 12, "font-weight": 600 }, lab.id));
      svg.append(el("text", { x: L + gw * i + gw / 2, y: H - B + 33, "text-anchor": "middle", fill: "var(--mut)", "font-size": 10 }, lab.name));
    });
    // legend
    let lx = L;
    cfg.series.forEach((s) => {
      svg.append(el("rect", { x: lx, y: H - 14, width: 10, height: 10, rx: 2, fill: s.color }));
      svg.append(el("text", { x: lx + 14, y: H - 5, fill: "var(--mut)", "font-size": 11 }, s.name));
      lx += 22 + s.name.length * 6.2;
    });
    target.replaceChildren(svg);
  };
})();

// ---- Results page logic (runs only when #summary exists) ----
if (document.querySelector("#summary")) {
const $ = (s) => document.querySelector(s);
function h(tag, attrs, ...kids) {              // text always via textContent, never innerHTML
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
  for (const c of kids.flat()) if (c != null) e.append(c.nodeType ? c : document.createTextNode(String(c)));
  return e;
}
const pct = (v) => (v == null ? "n/a" : v + "%");

function renderSummary(d) {
  const head = h("tr", {}, h("th", {}, "Variant"), h("th", {}, "Technique"),
    ["Containment-safe %", "Type-policy match %", "Missing-name match %", "Allow rate (legit)", "CF", "TM", "PM", "FB"].map((t) => h("th", { class: "num" }, t)));
  const rows = d.variants.map((v) => h("tr", {},
    h("td", {}, h("b", {}, v.id)), h("td", {}, v.name),
    h("td", { class: "num" + (v.containment_safe_rate === 100 ? "" : " false_allow") }, pct(v.containment_safe_rate) + " (" + (v.containment_safe_count || ((v.attacks_total - v.containment_failures) + "/" + v.attacks_total)) + ")"),
    h("td", { class: "num" + (v.type_policy_rate === 100 ? "" : " type_mismatch") }, pct(v.type_policy_rate) + " (" + (v.type_policy_count || ((v.type_total - v.type_mismatches) + "/" + v.type_total)) + ")"),
    h("td", { class: "num" + (v.missing_policy_rate === 100 ? "" : " policy_mismatch") }, pct(v.missing_policy_rate) + " (" + (v.missing_policy_count || ((v.missing_total - v.policy_mismatches) + "/" + v.missing_total)) + ")"),
    h("td", { class: "num" + (v.allow_rate === 100 ? "" : " false_block") }, pct(v.allow_rate) + " (" + (v.allow_count || (v.legit_allowed + "/" + v.legit_total)) + ")"),
    h("td", { class: "num" + (v.containment_failures ? " false_allow" : "") }, v.containment_failures ?? 0),
    h("td", { class: "num" + (v.type_mismatches ? " type_mismatch" : "") }, v.type_mismatches ?? 0),
    h("td", { class: "num" + (v.policy_mismatches ? " policy_mismatch" : "") }, v.policy_mismatches ?? 0),
    h("td", { class: "num" + (v.false_blocks ? " false_block" : "") }, v.false_blocks ?? 0)));
  $("#summary").replaceChildren(head, ...rows);
  const attTotal = d.variants[0]?.attacks_total ?? d.unauthorised;
  const legTotal = d.variants[0]?.legit_total ?? d.legitimate;
  $("#intro").textContent = d.tests + " tests x " + d.variants.length + " variants. " +
    attTotal + " attack cases to block and " + legTotal + " legitimate cases to allow. CF = Containment Failures (escapes).";
}

function renderCharts(d) {
  const labels = d.variants.map((v) => ({ id: v.id, name: v.name }));
  drawBars($("#ch-rates"), { title: "Containment, policy and allow rates (%)", labels, max: 100, unit: "%",
    series: [{ name: "Containment-safe", color: "var(--c1)", values: d.variants.map((v) => v.containment_safe_rate ?? v.block_rate ?? 0) },
             { name: "Type-policy match", color: "var(--c2)", values: d.variants.map((v) => v.type_policy_rate ?? 0) },
             { name: "Missing-policy match", color: "#a86e00", values: d.variants.map((v) => v.missing_policy_rate ?? 0) },
             { name: "Allow rate (legit)", color: "var(--mut)", values: d.variants.map((v) => v.allow_rate ?? v.success_rate ?? 0) }] });
  drawBars($("#ch-errors"), { title: "Failures & Mismatches (count of tests)", labels,
    series: [{ name: "Containment Fail (CF)", color: "var(--c3)", values: d.variants.map((v) => v.containment_failures ?? v.false_allow ?? 0) },
             { name: "Type Mismatch (TM)", color: "var(--warn)", values: d.variants.map((v) => v.type_mismatches ?? 0) },
             { name: "Policy Mismatch (PM)", color: "#a86e00", values: d.variants.map((v) => v.policy_mismatches ?? 0) },
             { name: "False Block (FB)", color: "var(--mut)", values: d.variants.map((v) => v.false_blocks ?? v.false_block ?? 0) }] });
}

function renderDetail(d) {
  const only = $("#onlybad").checked;
  const ids = d.variants.map((v) => v.id);
  const head = h("tr", {}, h("th", {}, "#"), h("th", {}, "Category"), h("th", {}, "Path"), h("th", {}, "Expected"),
    ids.map((i) => h("th", {}, i)));
  const rows = d.tests_detail.filter((t) => !only || ids.some((i) => t.results[i] !== "correct")).map((t) => h("tr", {},
    h("td", {}, t.id), h("td", {}, t.category), h("td", {}, h("code", {}, t.path === "" ? "(empty)" : t.path)),
    h("td", {}, h("span", { class: "badge " + t.expected }, t.expected)),
    ids.map((i) => {
      const res = t.results[i];
      const ok = res === "correct";
      const cls = ok ? "ok" : (res === "containment_failure" || res === "false_allow") ? "cf" : res === "type_mismatch" ? "tm" : res === "policy_mismatch" ? "pm" : "fb";
      return h("td", {}, h("span", { class: "cell " + cls }, t.actual[i] + (ok ? "" : "*")));
    })));
  $("#detail").replaceChildren(head, ...rows);
}

fetch("/api/results").then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || r.statusText); return j; }))
  .then((d) => { renderSummary(d); renderCharts(d); renderDetail(d); $("#onlybad").addEventListener("change", () => renderDetail(d)); })
  .catch((e) => { $("#err").textContent = "Could not load results: " + e.message; $("#intro").textContent = ""; });
}

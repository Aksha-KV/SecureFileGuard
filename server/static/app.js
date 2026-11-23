"use strict";
const $ = (s) => document.querySelector(s);
function h(tag, attrs, ...kids) {           // tiny DOM helper: text is always set via textContent (no XSS)
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null) e.append(c.nodeType ? c : document.createTextNode(String(c)));
  return e;
}
async function api(route, body) {
  const r = await fetch(route, body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json();
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}
const VERDICT = {
  correct: "correct",
  false_allow: "CONTAINMENT FAILURE (security failure)",
  containment_failure: "CONTAINMENT FAILURE (security failure)",
  type_mismatch: "type check mismatch (allowed non-regular file)",
  policy_mismatch: "policy mismatch (allowed missing/invalid file)",
  false_block: "false block (too strict)"
};
let INFO = null;

function badge(d) { return h("span", { class: "badge " + d }, d); }
function cellFor(v) {
  const cls = v.verdict === "correct" ? "ok" : (v.verdict === "false_allow" || v.verdict === "containment_failure") ? "cf" : v.verdict === "type_mismatch" ? "tm" : v.verdict === "policy_mismatch" ? "pm" : "fb";
  return h("span", { class: "cell " + cls }, v.decision + (v.verdict === "correct" ? "" : "*"));
}

function showResult(r, shownPath) {
  const out = $("#result"); out.replaceChildren();
  const sh = shownPath.length > 80 ? shownPath.slice(0, 60) + "…(" + shownPath.length + " chars)" : shownPath;
  const head = h("div", { class: "card" },
    h("div", {}, "Input: ", h("code", {}, sh === "" ? "(empty)" : sh.replace(/\0/g, "\\0"))),
    h("div", { style: "margin-top:6px" }, "Ground truth: ", badge(r.expected), " — ", r.reason),
    r.oracle_method ? h("div", { class: "note", style: "margin-top:4px" }, "Oracle method: ", h("code", {}, r.oracle_method)) : null,
    r.resolved ? h("div", { class: "note" }, "Resolves to: ", h("code", {}, r.resolved), " (", r.kind, ")") : null);
  const rows = r.variants.map((v) => h("tr", {},
    h("td", {}, v.id), h("td", {}, v.name), h("td", {}, badge(v.decision)), h("td", { class: v.verdict }, VERDICT[v.verdict] || v.verdict)));
  out.append(head, h("div", { class: "card wrap" }, h("table", {},
    h("tr", {}, h("th", {}, "Variant"), h("th", {}, "Technique"), h("th", {}, "Decision"), h("th", {}, "Verdict")), rows)));
}

async function check(body, shown) {
  $("#go").disabled = true;
  try { showResult(await api("/api/check", body), shown); }
  catch (e) { $("#result").replaceChildren(h("div", { class: "card" }, "Error: " + e.message)); }
  $("#go").disabled = false;
}

async function runSuite() {
  const b = $("#runsuite"); b.disabled = true; const out = $("#suiteout"); out.replaceChildren("Running…");
  try {
    const s = await api("/api/suite", {});
    window.ACTIVE_SUITE_DATA = s;
    const ids = s.metrics.map((m) => m.id);
    const head = h("tr", {}, h("th", {}, "#"), h("th", {}, "Type"), h("th", {}, "Input"), h("th", {}, "Expected"),
      ids.map((i) => h("th", {}, i)));
    const rows = s.rows.map((r) => h("tr", {}, h("td", {}, r.id + 1), h("td", {}, r.category), h("td", {}, h("code", {}, r.label)),
      h("td", {}, badge(r.expected)), r.variants.map((v) => h("td", {}, cellFor(v)))));
    const m = s.metrics.map((x) => h("tr", {},
      h("td", {}, h("b", {}, x.id)),
      h("td", {}, x.name),
      h("td", { class: x.containment_safe_rate === 100 ? "correct" : "containment_failure" },
        (x.containment_safe_rate != null ? x.containment_safe_rate + "%" : "n/a") + " (" + (x.containment_safe_count || ((x.attacks_total - x.containment_failures) + "/" + x.attacks_total)) + ")"),
      h("td", { class: x.type_policy_rate === 100 ? "correct" : "type_mismatch" },
        (x.type_policy_rate != null ? x.type_policy_rate + "%" : "n/a") + " (" + (x.type_policy_count || ((x.type_total - x.type_mismatches) + "/" + x.type_total)) + ")"),
      h("td", { class: x.missing_policy_rate === 100 ? "correct" : "policy_mismatch" },
        (x.missing_policy_rate != null ? x.missing_policy_rate + "%" : "n/a") + " (" + (x.missing_policy_count || ((x.missing_total - x.policy_mismatches) + "/" + x.missing_total)) + ")"),
      h("td", { class: x.allow_rate === 100 ? "correct" : "false_block" },
        (x.allow_rate != null ? x.allow_rate + "%" : "n/a") + " (" + (x.allow_count || (x.legit_allowed + "/" + x.legit_total)) + ")"),
      h("td", { class: x.containment_failures ? "containment_failure" : "correct" }, x.containment_failures ?? x.false_allows),
      h("td", { class: x.type_mismatches ? "type_mismatch" : "correct" }, x.type_mismatches ?? 0),
      h("td", { class: x.policy_mismatches ? "policy_mismatch" : "correct" }, x.policy_mismatches ?? 0),
      h("td", { class: x.false_blocks ? "false_block" : "correct" }, x.false_blocks)));
    const attN = s.metrics[0]?.attacks_total ?? "?";
    const legN = s.metrics[0]?.legit_total ?? "?";
    out.replaceChildren(
      h("div", { class: "card wrap" }, h("table", {},
        h("tr", {}, ["Var", "Technique", "Containment-safe %", "Type-policy match %", "Missing-name match %", "Allow rate (legit)", "CF", "TM", "PM", "FB"].map((t) => h("th", {}, t))), m)),
      h("p", { class: "note" }, `Containment-safe % = attacks denied / attack cases (${attN}). Type-policy match % = directories & FIFOs denied inside jail. Missing-name match % = missing/invalid names denied under strict policy. Allow rate = legitimate regular files allowed (${legN}). CF = Containment Failures. TM = Type Mismatches. PM = Policy Mismatches. FB = False Blocks. * = differs from ground truth.`),
      h("div", { class: "card wrap" }, h("table", {}, head, rows)));
  } catch (e) { out.replaceChildren("Error: " + e.message); }
  b.disabled = false;
}

async function runRace() {
  const b = $("#runrace"); b.disabled = true; const out = $("#raceout"); out.replaceChildren("Running race demo… this can take a little while.");
  try {
    const iters = +$("#iters").value;
    const runs = +$("#runs")?.value || 1;
    const r = await api("/api/race", { iterations: iters, runs: runs });
    const hasRuns = runs > 1;
    const headers = ["Variant", "Attempts", "Allowed", "Opened", hasRuns ? "Escapes (Min / Max / Total)" : "Escapes"];
    const rows = r.rows.map((x) => {
      let escText = String(x.escapes);
      if (hasRuns && x.escapes_min !== undefined) {
        escText = `${x.escapes_min} / ${x.escapes_max} / ${x.escapes_total} (runs: [${x.runs ? x.runs.join(", ") : x.escapes}])`;
      }
      return h("tr", {},
        h("td", {}, h("b", {}, x.variant)),
        h("td", {}, x.attempts),
        h("td", {}, x.allowed),
        h("td", {}, x.opened),
        h("td", { class: (x.escapes_total || x.escapes) ? "containment_failure" : "correct" }, escText));
    });

    out.replaceChildren(
      h("div", { class: "card wrap" }, h("table", {},
        h("tr", {}, headers.map((t) => h("th", {}, t))),
        rows)),
      h("p", { class: "note" }, "Escapes = opened files whose content came from outside the jail. Results are PROBABILISTIC: 0 escapes in a run does NOT prove safety. Running multiple runs exposes intermittent race windows."));
  } catch (e) { out.replaceChildren("Error: " + e.message); }
  b.disabled = false;
}

function init(info) {
  INFO = info;
  $("#root").textContent = info.root; $("#policy").textContent = info.policy;

  // Environment box / How it was tested panel
  const env = info.environment || {};
  const envPanel = $("#env-panel");
  if (envPanel) {
    envPanel.replaceChildren(
      h("div", { class: "card" },
        h("h3", { style: "margin:0 0 8px" }, "How it was tested"),
        h("div", { class: "env-grid" },
          h("div", { class: "env-item" }, h("div", { class: "env-label" }, "Kernel"), h("div", { class: "env-val" }, env.kernel || "Linux")),
          h("div", { class: "env-item" }, h("div", { class: "env-label" }, "Compiler"), h("div", { class: "env-val" }, env.compiler || "g++ (C++17)")),
          h("div", { class: "env-item" }, h("div", { class: "env-label" }, "CPU Cores"), h("div", { class: "env-val" }, String(env.cpus || 1))),
          h("div", { class: "env-item" }, h("div", { class: "env-label" }, "WSL Environment"), h("div", { class: "env-val" }, env.wsl ? "Yes (WSL2)" : "Native Linux")),
          h("div", { class: "env-item" }, h("div", { class: "env-label" }, "Oracle Ground Truth"), h("div", { class: "env-val" }, info.oracle_method || "realpath(3)")),
          h("div", { class: "env-item" }, h("div", { class: "env-label" }, "Test Cases / Presets"), h("div", { class: "env-val" }, String(info.test_cases_count || info.presets.length))),
          h("div", { class: "env-item" }, h("div", { class: "env-label" }, "Date Generated"), h("div", { class: "env-val" }, info.date_generated || "Live run"))
        )
      )
    );
  }

  // Race environment panel
  const raceEnv = $("#race-env");
  if (raceEnv) {
    raceEnv.replaceChildren(
      h("div", { class: "card", style: "margin:8px 0" },
        h("div", { class: "env-grid" },
          h("div", { class: "env-item" }, h("div", { class: "env-label" }, "Kernel"), h("div", { class: "env-val" }, env.kernel || "Linux")),
          h("div", { class: "env-item" }, h("div", { class: "env-label" }, "CPU Count"), h("div", { class: "env-val" }, String(env.cpus || 1))),
          h("div", { class: "env-item" }, h("div", { class: "env-label" }, "WSL"), h("div", { class: "env-val" }, env.wsl ? "Yes (WSL2)" : "Native Linux"))
        )
      )
    );
  }

  const groups = {};
  info.presets.forEach((p) => (groups[p.category] = groups[p.category] || []).push(p));
  $("#presets").replaceChildren(...Object.entries(groups).map(([cat, ps]) =>
    h("div", { class: "group" }, h("b", {}, cat), ps.map((p) => h("button", { class: "chip", onclick: () => {
      $("#path").value = p.path === null ? "a".repeat(5000) : p.path;
      check({ preset: p.id }, $("#path").value); } }, p.label)))));
  $("#tree").replaceChildren(...info.tree.map((e) => h("div", {}, e.type === "symlink" ? h("span", { class: "b-symlink" }, e.path + "  →  " + e.target) :
    e.type === "dir" ? e.path + "/" : e.path + (e.type === "fifo" ? "  (fifo)" : ""))));
  $("#variants").replaceChildren(...info.variants.map((v) => h("div", { class: "vcard" }, h("b", {}, v.id + " · " + v.name), h("div", {}, v.desc))));
}

document.querySelectorAll("#tabs button").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll("#tabs button").forEach((x) => x.classList.toggle("on", x === b));
  document.querySelectorAll("main > section").forEach((s) => (s.hidden = s.id !== b.dataset.tab));
}));
$("#go").addEventListener("click", () => check({ path: $("#path").value }, $("#path").value));
$("#path").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#go").click(); });
function downloadBlob(content, filename, type = "text/csv;charset=utf-8;") {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function suiteToCsv(s) {
  const header = ["variant", "technique", "test_id", "category", "path", "expected", "actual", "verdict", "containment", "type_check", "policy_check"];
  const lines = [header.join(",")];
  for (const r of s.rows) {
    for (const v of r.variants) {
      const verd = v.verdict || "";
      const cont = (verd === "containment_failure" || verd === "false_allow") ? "FAIL" : "PASS";
      const typ = verd === "type_mismatch" ? "FAIL" : "PASS";
      const pol = verd === "policy_mismatch" ? "FAIL" : "PASS";
      let p = r.label || "";
      if (p.length > 36) p = p.slice(0, 28) + "...(len=" + p.length + ")";
      const cleanPath = `"${p.replace(/"/g, '""')}"`;
      lines.push([
        v.id,
        v.name,
        r.id,
        r.category,
        cleanPath,
        r.expected,
        v.decision,
        verd,
        cont,
        typ,
        pol
      ].join(","));
    }
  }
  return lines.join("\n");
}

async function handleDownloadCsv(e) {
  if (window.ACTIVE_SUITE_DATA) {
    e.preventDefault();
    downloadBlob(suiteToCsv(window.ACTIVE_SUITE_DATA), "results.csv");
    return;
  }
  e.preventDefault();
  try {
    const res = await fetch("/results.csv");
    if (!res.ok) {
      const txt = await res.text();
      let msg = res.statusText;
      try { const j = JSON.parse(txt); if (j.error) msg = j.error; } catch(_) {}
      alert("Could not download results.csv: " + msg);
      return;
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "results.csv";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (err) {
    alert("Could not download results.csv: " + err.message);
  }
}

$("#runsuite").addEventListener("click", runSuite);
$("#runrace").addEventListener("click", runRace);
$("#dl-csv")?.addEventListener("click", handleDownloadCsv);
api("/api/info").then(init).catch((e) => ($("#root").textContent = "server error: " + e.message));

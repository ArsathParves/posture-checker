// POC front-end. Submits a check, streams SSE events, renders each section
// as it arrives. Section order and content mirror the CLI report exactly.

const SECTION_ORDER = [
  "Registration & delegation",
  "Nameserver posture",
  "SOA & zone hygiene",
  "Core records",
  "DNSSEC",
  "Email authentication",
  "Security posture",
];

const form = document.getElementById("checkForm");
const domainInput = document.getElementById("domain");
const submitBtn = document.getElementById("submitBtn");
const statusEl = document.getElementById("status");
const headerEl = document.getElementById("header");
const sectionsEl = document.getElementById("sections");
const footerEl = document.getElementById("footer");

let currentSource = null;

// Fixed set of finding statuses the server can emit. Any value outside
// this set is coerced to "INFO" before use — status flows into a CSS
// class attribute, so an unconstrained value is an XSS vector.
const STATUS_CLASSES = new Set(["PASS", "WARN", "FAIL", "INFO"]);
function safeStatus(s) {
  return STATUS_CLASSES.has(s) ? s : "INFO";
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const domain = domainInput.value.trim();
  if (!domain) return;
  resetUI();
  submitBtn.disabled = true;
  showStatus("Submitting check…");
  try {
    const resp = await fetch("/api/check", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({domain}),
    });
    const data = await resp.json();
    if (!resp.ok) {
      showStatus(data.detail || data.error || "Request failed", true);
      submitBtn.disabled = false;
      return;
    }
    if (data.cached) showStatus("Showing cached result (checked within last 5 minutes)");
    else            showStatus("Running check — sections will appear as they complete…");
    prepareSections();
    openStream(data.check_id);
  } catch (err) {
    showStatus("Network error: " + err.message, true);
    submitBtn.disabled = false;
  }
});

function resetUI() {
  if (currentSource) { currentSource.close(); currentSource = null; }
  statusEl.className = "status"; statusEl.classList.add("hidden"); statusEl.textContent = "";
  headerEl.classList.add("hidden");
  headerEl.querySelector(".header-domain").textContent = "";
  headerEl.querySelector(".header-grade").textContent = "";
  headerEl.querySelector(".header-grade").className = "header-grade";
  headerEl.querySelector(".header-meta").textContent = "";
  sectionsEl.innerHTML = "";
  footerEl.classList.add("hidden");
}

function showStatus(text, isError = false) {
  statusEl.textContent = text;
  statusEl.className = "status" + (isError ? " error" : "");
  statusEl.classList.remove("hidden");
}

// W2 — render an error status line with an inline Retry button that
// re-submits the form for the same domain. The button lives inside
// the aria-live #status region so screen readers announce it.
function showStatusWithRetry(text) {
  statusEl.className = "status error";
  statusEl.classList.remove("hidden");
  statusEl.textContent = "";
  const msg = document.createElement("span");
  msg.textContent = text + " ";
  const btn = document.createElement("button");
  btn.type = "button";
  btn.id = "retryBtn";
  btn.className = "retry-btn";
  btn.textContent = "Retry";
  btn.addEventListener("click", () => {
    form.dispatchEvent(new Event("submit", {cancelable: true}));
  });
  statusEl.appendChild(msg);
  statusEl.appendChild(btn);
}

function prepareSections() {
  for (const name of SECTION_ORDER) {
    const el = document.createElement("div");
    el.className = "section pending";
    el.dataset.section = name;
    // A4 — <h2> for the section title so screen-reader users can
    // navigate by heading; findings inside <ul> so they can be
    // stepped through as list items.
    el.innerHTML = `
      <div class="section-head">
        <h2>${escapeHtml(name)}</h2>
        <span class="grade-pill">running…</span>
      </div>
      <ul class="section-body"></ul>`;
    sectionsEl.appendChild(el);
  }
}

function openStream(checkId) {
  currentSource = new EventSource(`/api/check/${checkId}/stream`);

  currentSource.addEventListener("started", (e) => {
    const d = JSON.parse(e.data);
    headerEl.classList.remove("hidden");
    headerEl.querySelector(".header-domain").textContent =
      d.punycode && d.punycode !== d.domain
        ? `${d.domain}  (${d.punycode})`
        : d.domain;
    headerEl.querySelector(".header-meta").textContent =
      `Checked as of ${new Date(d.checked_at * 1000).toISOString().replace("T", " ").split(".")[0]} UTC`;
  });

  currentSource.addEventListener("environment", (e) => {
    const d = JSON.parse(e.data);
    if (!d.safe) {
      const meta = headerEl.querySelector(".header-meta");
      const div = document.createElement("div");
      div.className = "warn";
      div.textContent = "⚠ Per-nameserver probing is degraded on the server that ran this check.";
      meta.appendChild(div);
    }
  });

  currentSource.addEventListener("nxdomain", (e) => {
    showStatus("Domain does not resolve (NXDOMAIN).", true);
  });

  currentSource.addEventListener("section", (e) => {
    const d = JSON.parse(e.data);
    renderSection(d.name, d.findings, d.elapsed_ms);
  });

  currentSource.addEventListener("complete", (e) => {
    const d = JSON.parse(e.data);
    renderGrades(d.grades);
    showStatus(`Complete. ${d.report.findings.length} findings.`);
    footerEl.classList.remove("hidden");
    submitBtn.disabled = false;
    currentSource.close(); currentSource = null;
  });

  currentSource.addEventListener("error", (e) => {
    // W2 — EventSource errors don't always carry data; surface a
    // Retry cue so the user isn't left staring at a half-populated
    // table wondering whether the scan is still running.
    let msg = "Stream error";
    try { const d = JSON.parse(e.data); msg = d.message || msg; } catch (_) {}
    showStatusWithRetry(msg + " — connection lost.");
    submitBtn.disabled = false;
    if (currentSource) { currentSource.close(); currentSource = null; }
  });

  currentSource.addEventListener("end", () => {
    submitBtn.disabled = false;
    if (currentSource) { currentSource.close(); currentSource = null; }
  });
}

function renderSection(name, findings, elapsedMs) {
  const el = sectionsEl.querySelector(`.section[data-section="${cssEscape(name)}"]`);
  if (!el) return;
  el.classList.remove("pending");
  const body = el.querySelector(".section-body");
  body.innerHTML = "";
  const shown = findings.filter(f => f.status !== "INFO" || f.detail);
  for (const f of shown) {
    const row = document.createElement("li");
    row.className = "finding";
    const badgeCls = safeStatus(f.status);
    row.innerHTML = `
      <span class="badge ${badgeCls}" aria-label="${badgeCls}">${badgeCls}</span>
      <span class="label">${escapeHtml(f.label)}</span>
      <span class="detail">${escapeHtml(f.detail || "")}${
        f.why ? `<span class="why">${escapeHtml(f.why)}</span>` : ""
      }</span>`;
    body.appendChild(row);
  }
  const pill = el.querySelector(".grade-pill");
  pill.textContent = elapsedMs != null ? `${elapsedMs} ms` : "done";
}

function renderGrades(grades) {
  const gradeEl = headerEl.querySelector(".header-grade");
  let gradeText = "Overall posture: " + grades.overall +
    (grades.provisional ? "  (provisional)" : "");
  if (grades.correctness_grade && grades.correctness_grade !== "—")
    gradeText += "   ·   Correctness: " + grades.correctness_grade;
  if (grades.hardening_grade && grades.hardening_grade !== "—")
    gradeText += "   ·   Hardening: " + grades.hardening_grade;
  gradeEl.textContent = gradeText;
  gradeEl.className = "header-grade " + grades.overall;

  for (const [name, [band]] of Object.entries(grades.sections || {})) {
    const el = sectionsEl.querySelector(`.section[data-section="${cssEscape(name)}"]`);
    if (el) el.querySelector(".grade-pill").textContent = "grade " + band;
  }

  if (grades.ungraded_sections?.length || grades.unknown_in?.length) {
    const meta = headerEl.querySelector(".header-meta");
    const div = document.createElement("div");
    div.className = "warn";
    const bits = [];
    if (grades.ungraded_sections?.length)
      bits.push("Not graded: " + grades.ungraded_sections.join(", "));
    if (grades.unknown_in?.length)
      bits.push("Unresolved checks in: " + grades.unknown_in.join(", "));
    div.textContent = "⚠ " + bits.join(" · ");
    meta.appendChild(div);
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g,
    c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
function cssEscape(s) {
  // Use CSS.escape() for proper escaping, or fallback to manual escape
  if (typeof CSS !== 'undefined' && CSS.escape) {
    return CSS.escape(s);
  }
  // Fallback: escape special characters for CSS identifiers
  return String(s).replace(/[!"#$%&'()*+,./:;<=>?@[\\\]^`{|}~]/g, '\\$&');
}

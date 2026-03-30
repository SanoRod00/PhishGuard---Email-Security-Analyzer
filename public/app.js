const STORAGE_KEY = "phishguard.history.v1";
const SEVERITY_ORDER = {
  safe: 1,
  suspicious: 2,
  dangerous: 3
};

const state = {
  history: loadHistory(),
  latestUrlResult: null,
  latestEmailResult: null,
  latestCombinedResult: null
};

const elements = {
  urlForm: document.getElementById("urlScanForm"),
  emailForm: document.getElementById("emailScanForm"),
  urlInput: document.getElementById("urlInput"),
  emailInput: document.getElementById("emailInput"),
  urlResult: document.getElementById("urlResult"),
  emailResult: document.getElementById("emailResult"),
  combinedSummary: document.getElementById("combinedSummary"),
  combinedScanBtn: document.getElementById("combinedScanBtn"),
  urlScanBtn: document.getElementById("urlScanBtn"),
  emailScanBtn: document.getElementById("emailScanBtn"),
  exportBtn: document.getElementById("exportBtn"),
  clearHistoryBtn: document.getElementById("clearHistoryBtn"),
  searchInput: document.getElementById("searchInput"),
  sortSelect: document.getElementById("sortSelect"),
  threatFilter: document.getElementById("threatFilter"),
  typeFilter: document.getElementById("typeFilter"),
  fromDate: document.getElementById("fromDate"),
  toDate: document.getElementById("toDate"),
  disposableOnly: document.getElementById("disposableOnly"),
  historyTableBody: document.getElementById("historyTableBody"),
  timeline: document.getElementById("timeline"),
  toastHost: document.getElementById("toastHost"),
  totalScansMetric: document.getElementById("totalScansMetric"),
  dangerScansMetric: document.getElementById("dangerScansMetric"),
  disposableMetric: document.getElementById("disposableMetric")
};

bindEvents();
renderAll();

function bindEvents() {
  elements.urlForm.addEventListener("submit", handleUrlScan);
  elements.emailForm.addEventListener("submit", handleEmailScan);
  elements.combinedScanBtn.addEventListener("click", handleCombinedScan);
  elements.exportBtn.addEventListener("click", exportHistory);
  elements.clearHistoryBtn.addEventListener("click", clearHistory);

  [
    elements.searchInput,
    elements.sortSelect,
    elements.threatFilter,
    elements.typeFilter,
    elements.fromDate,
    elements.toDate,
    elements.disposableOnly
  ].forEach((element) => {
    element.addEventListener("input", renderHistoryTable);
    element.addEventListener("change", renderHistoryTable);
  });
}

async function handleUrlScan(event) {
  event.preventDefault();
  const url = elements.urlInput.value.trim();

  if (!isValidUrl(url)) {
    showToast("Please enter a valid URL.", "error");
    return;
  }

  setLoading(elements.urlScanBtn, true);

  try {
    const result = await requestJson("/api/scan/url", { url });
    state.latestUrlResult = result;
    renderUrlResult(result);
    pushHistory(createHistoryRecord("url", result));
    showToast(result.summary, result.threatLevel);
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setLoading(elements.urlScanBtn, false);
  }
}

async function handleEmailScan(event) {
  event.preventDefault();
  const email = elements.emailInput.value.trim();

  if (!isValidEmail(email)) {
    showToast("Please enter a valid email address.", "error");
    return;
  }

  setLoading(elements.emailScanBtn, true);

  try {
    const result = await requestJson("/api/scan/email", { email });
    state.latestEmailResult = result;
    renderEmailResult(result);
    pushHistory(createHistoryRecord("email", result));
    showToast(result.summary, result.threatLevel);
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setLoading(elements.emailScanBtn, false);
  }
}

async function handleCombinedScan() {
  const url = elements.urlInput.value.trim();
  const email = elements.emailInput.value.trim();

  if (!isValidUrl(url)) {
    showToast("Add a valid URL before running the combined scan.", "error");
    return;
  }

  if (!isValidEmail(email)) {
    showToast("Add a valid sender email before running the combined scan.", "error");
    return;
  }

  setLoading(elements.combinedScanBtn, true);

  try {
    const result = await requestJson("/api/scan/combined", { url, email });
    state.latestCombinedResult = result;
    state.latestUrlResult = result.url;
    state.latestEmailResult = result.email;
    renderUrlResult(result.url);
    renderEmailResult(result.email);
    renderCombinedSummary(result);
    pushHistory(createHistoryRecord("combined", result));
    showToast("Combined scan completed.", result.threatLevel);
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setLoading(elements.combinedScanBtn, false);
  }
}

function renderAll() {
  renderUrlResult(state.latestUrlResult);
  renderEmailResult(state.latestEmailResult);
  renderCombinedSummary(state.latestCombinedResult);
  renderTimeline();
  renderHistoryTable();
  renderMetrics();
}

function renderUrlResult(result) {
  if (!result) {
    elements.urlResult.className = "result-card result-empty";
    elements.urlResult.textContent = "URL scan results will appear here.";
    return;
  }

  const tone = result.threatLevel;
  const topDetections = result.detections
    .filter((item) => item.detected)
    .slice(0, 12)
    .map(
      (item) => `
        <tr>
          <td>${escapeHtml(item.vendor)}</td>
          <td>${escapeHtml(item.result)}</td>
          <td>${escapeHtml(item.category)}</td>
          <td>${escapeHtml(item.method)}</td>
        </tr>
      `
    )
    .join("");

  elements.urlResult.className = "result-card";
  elements.urlResult.innerHTML = `
    <div class="result-header">
      <div>
        <h3 class="mono">${escapeHtml(result.target)}</h3>
        <p class="result-summary">${escapeHtml(result.summary)}</p>
      </div>
      ${severityPill(tone)}
    </div>
    <div class="score-grid">
      ${gaugeMarkup({
        value: result.threatScore,
        label: "Threat score",
        valueSuffix: "",
        tone
      })}
      <div>
        <div class="detail-grid">
          <div class="detail-card">
            <span>Vendors flagged</span>
            <strong>${result.positives}/${result.total}</strong>
          </div>
          <div class="detail-card">
            <span>Malicious</span>
            <strong>${result.stats.malicious}</strong>
          </div>
          <div class="detail-card">
            <span>Suspicious</span>
            <strong>${result.stats.suspicious}</strong>
          </div>
          <div class="detail-card">
            <span>Status</span>
            <strong>${escapeHtml(result.status)}</strong>
          </div>
        </div>
      </div>
    </div>
    <ul class="flag-list">
      ${
        result.highlights.length
          ? result.highlights.map((item) => `<li>${escapeHtml(item)}</li>`).join("")
          : "<li>No vendor detection details were returned for this scan.</li>"
      }
    </ul>
    <details>
      <summary>View detailed vendor results</summary>
      <table class="vendor-table">
        <thead>
          <tr>
            <th>Vendor</th>
            <th>Result</th>
            <th>Category</th>
            <th>Method</th>
          </tr>
        </thead>
        <tbody>
          ${
            topDetections ||
            '<tr><td colspan="4">No malicious or suspicious vendor verdicts were returned.</td></tr>'
          }
        </tbody>
      </table>
    </details>
  `;

  animateGauges(elements.urlResult);
}

function renderEmailResult(result) {
  if (!result) {
    elements.emailResult.className = "result-card result-empty";
    elements.emailResult.textContent = "Sender validation results will appear here.";
    return;
  }

  const flagsMarkup = result.flags.length
    ? result.flags.map((flag) => `<li>${escapeHtml(flag)}</li>`).join("")
    : "<li>No elevated risk signals were found.</li>";

  elements.emailResult.className = "result-card";
  elements.emailResult.innerHTML = `
    <div class="result-header">
      <div>
        <h3 class="mono">${escapeHtml(result.target)}</h3>
        <p class="result-summary">${escapeHtml(result.summary)}</p>
      </div>
      ${severityPill(result.threatLevel)}
    </div>
    <div class="score-grid">
      ${gaugeMarkup({
        value: result.trustScore,
        label: "Trust score",
        valueSuffix: "",
        tone: trustTone(result.trustScore)
      })}
      <div>
        <div class="detail-grid">
          <div class="detail-card">
            <span>Trust</span>
            <strong>${result.trustScore}/100</strong>
          </div>
          <div class="detail-card">
            <span>Domain</span>
            <strong>${escapeHtml(result.domain)}</strong>
          </div>
          <div class="detail-card">
            <span>Disposable</span>
            <strong>${result.disposable ? "Yes" : "No"}</strong>
          </div>
          <div class="detail-card">
            <span>Deliverability</span>
            <strong>${escapeHtml(result.checks.abstract?.deliverability || "N/A")}</strong>
          </div>
        </div>
      </div>
    </div>
    <ul class="flag-list">${flagsMarkup}</ul>
  `;

  animateGauges(elements.emailResult);
}

function renderCombinedSummary(result) {
  if (!result) {
    elements.combinedSummary.textContent =
      "Combined scan results will appear here after you run both checks together.";
    return;
  }

  const urlHost = safeHostname(result.url.target);
  elements.combinedSummary.innerHTML = `
    <div class="timeline-item-header">
      <strong>${escapeHtml(result.summary)}</strong>
      ${severityPill(result.threatLevel)}
    </div>
    <p class="result-summary">
      URL: ${escapeHtml(urlHost)} scored ${result.url.threatScore}/100.
      Sender: ${escapeHtml(result.email.target)} scored ${result.email.trustScore}/100 for trust.
    </p>
  `;
}

function renderTimeline() {
  const recent = [...state.history]
    .sort((left, right) => new Date(right.timestamp) - new Date(left.timestamp))
    .slice(0, 6);

  if (!recent.length) {
    elements.timeline.innerHTML =
      '<div class="timeline-empty">Run a scan to build your investigation timeline.</div>';
    return;
  }

  elements.timeline.innerHTML = recent
    .map(
      (record) => `
        <article class="timeline-item">
          <div class="timeline-item-header">
            <strong>${escapeHtml(record.summary)}</strong>
            ${severityPill(record.threatLevel)}
          </div>
          <p>${escapeHtml(record.target)}</p>
          <span class="timeline-meta">${formatDateTime(record.timestamp)} | ${escapeHtml(
            record.type.toUpperCase()
          )}</span>
        </article>
      `
    )
    .join("");
}

function renderHistoryTable() {
  const filteredRecords = getFilteredHistory();
  const query = elements.searchInput.value.trim().toLowerCase();

  if (!filteredRecords.length) {
    elements.historyTableBody.innerHTML =
      '<tr><td colspan="7" class="table-empty">No scans match the current filters.</td></tr>';
    renderMetrics();
    return;
  }

  elements.historyTableBody.innerHTML = filteredRecords
    .map(
      (record) => `
        <tr>
          <td>${formatDateTime(record.timestamp)}</td>
          <td>${severityPill(record.type === "combined" ? "suspicious" : "safe", record.type.toUpperCase())}</td>
          <td class="mono">${highlightMatch(record.target, query)}</td>
          <td>${highlightMatch(record.domain || "-", query)}</td>
          <td>${severityPill(record.threatLevel)}</td>
          <td>${highlightMatch(record.summary, query)}</td>
          <td>${record.disposable ? "Yes" : "No"}</td>
        </tr>
      `
    )
    .join("");

  renderMetrics();
}

function renderMetrics() {
  const dangerous = state.history.filter((record) => record.threatLevel === "dangerous").length;
  const disposable = state.history.filter((record) => record.disposable).length;

  elements.totalScansMetric.textContent = String(state.history.length);
  elements.dangerScansMetric.textContent = String(dangerous);
  elements.disposableMetric.textContent = String(disposable);
}

function getFilteredHistory() {
  const searchQuery = elements.searchInput.value.trim().toLowerCase();
  const threatLevel = elements.threatFilter.value;
  const type = elements.typeFilter.value;
  const fromDate = elements.fromDate.value;
  const toDate = elements.toDate.value;
  const disposableOnly = elements.disposableOnly.checked;

  const filtered = state.history.filter((record) => {
    if (threatLevel !== "all" && record.threatLevel !== threatLevel) {
      return false;
    }

    if (type !== "all" && record.type !== type) {
      return false;
    }

    if (disposableOnly && !record.disposable) {
      return false;
    }

    const recordDate = record.timestamp.slice(0, 10);
    if (fromDate && recordDate < fromDate) {
      return false;
    }
    if (toDate && recordDate > toDate) {
      return false;
    }

    if (searchQuery) {
      const haystack = `${record.target} ${record.domain || ""} ${record.summary}`.toLowerCase();
      if (!haystack.includes(searchQuery)) {
        return false;
      }
    }

    return true;
  });

  return filtered.sort((left, right) => sortRecords(left, right, elements.sortSelect.value));
}

function sortRecords(left, right, sortValue) {
  switch (sortValue) {
    case "date_asc":
      return new Date(left.timestamp) - new Date(right.timestamp);
    case "threat_desc":
      return (
        SEVERITY_ORDER[right.threatLevel] - SEVERITY_ORDER[left.threatLevel] ||
        new Date(right.timestamp) - new Date(left.timestamp)
      );
    case "threat_asc":
      return (
        SEVERITY_ORDER[left.threatLevel] - SEVERITY_ORDER[right.threatLevel] ||
        new Date(right.timestamp) - new Date(left.timestamp)
      );
    case "type_asc":
      return left.type.localeCompare(right.type) || new Date(right.timestamp) - new Date(left.timestamp);
    case "date_desc":
    default:
      return new Date(right.timestamp) - new Date(left.timestamp);
  }
}

function createHistoryRecord(type, result) {
  if (type === "combined") {
    return {
      id: crypto.randomUUID(),
      type: "combined",
      target: `${result.email.target} + ${safeHostname(result.url.target)}`,
      domain: result.email.domain,
      threatLevel: result.threatLevel,
      threatScore: result.threatScore,
      disposable: result.email.disposable,
      summary: result.summary,
      timestamp: result.scannedAt
    };
  }

  if (type === "url") {
    return {
      id: crypto.randomUUID(),
      type: "url",
      target: result.target,
      domain: safeHostname(result.target),
      threatLevel: result.threatLevel,
      threatScore: result.threatScore,
      disposable: false,
      summary: result.summary,
      timestamp: result.scannedAt
    };
  }

  return {
    id: crypto.randomUUID(),
    type: "email",
    target: result.target,
    domain: result.domain,
    threatLevel: result.threatLevel,
    threatScore: 100 - result.trustScore,
    disposable: result.disposable,
    summary: result.summary,
    timestamp: result.scannedAt
  };
}

function pushHistory(record) {
  state.history = [record, ...state.history].slice(0, 100);
  saveHistory();
  renderAll();
}

function clearHistory() {
  state.history = [];
  saveHistory();
  renderAll();
  showToast("Local scan history cleared.", "safe");
}

function exportHistory() {
  const records = getFilteredHistory();
  if (!records.length) {
    showToast("No rows are available to export.", "error");
    return;
  }

  const header = [
    "timestamp",
    "type",
    "target",
    "domain",
    "threat_level",
    "threat_score",
    "disposable",
    "summary"
  ];

  const rows = records.map((record) => [
    record.timestamp,
    record.type,
    record.target,
    record.domain || "",
    record.threatLevel,
    record.threatScore,
    record.disposable ? "yes" : "no",
    record.summary
  ]);

  const csv = [header, ...rows]
    .map((row) => row.map((value) => `"${String(value).replaceAll('"', '""')}"`).join(","))
    .join("\n");

  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `phishguard-history-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  showToast("CSV export created from the current filtered view.", "safe");
}

async function requestJson(url, payload) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || "Request failed.");
  }

  return data;
}

function loadHistory() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const parsed = JSON.parse(raw || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    return [];
  }
}

function saveHistory() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state.history));
}

function setLoading(button, active) {
  button.disabled = active;
  button.classList.toggle("is-loading", active);
}

function showToast(message, tone = "safe") {
  const toast = document.createElement("div");
  toast.className = `toast ${tone}`;
  toast.textContent = message;
  elements.toastHost.appendChild(toast);

  window.setTimeout(() => {
    toast.remove();
  }, 3600);
}

function gaugeMarkup({ value, label, valueSuffix = "", tone }) {
  const color =
    tone === "dangerous"
      ? "var(--danger-red)"
      : tone === "suspicious"
        ? "var(--warning-yellow)"
        : "var(--safe-green)";

  return `
    <div class="gauge" data-value="${value}" data-color="${color}">
      <svg viewBox="0 0 120 120" aria-hidden="true">
        <circle class="gauge-track" cx="60" cy="60" r="46"></circle>
        <circle class="gauge-fill" cx="60" cy="60" r="46"></circle>
      </svg>
      <div class="gauge-label">
        <span class="gauge-value">${value}${valueSuffix}</span>
        <span class="gauge-copy">${escapeHtml(label)}</span>
      </div>
    </div>
  `;
}

function animateGauges(root) {
  root.querySelectorAll(".gauge").forEach((gauge) => {
    const value = Number(gauge.dataset.value || 0);
    const circle = gauge.querySelector(".gauge-fill");
    const circumference = 289;
    const offset = circumference - (circumference * Math.max(0, Math.min(100, value))) / 100;
    circle.style.stroke = gauge.dataset.color;
    requestAnimationFrame(() => {
      circle.style.strokeDashoffset = String(offset);
    });
  });
}

function severityPill(tone, label) {
  const text = label || tone;
  return `<span class="pill pill-${tone}">${escapeHtml(text)}</span>`;
}

function trustTone(score) {
  if (score < 40) {
    return "dangerous";
  }
  if (score < 70) {
    return "suspicious";
  }
  return "safe";
}

function formatDateTime(value) {
  const date = new Date(value);
  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  }).format(date);
}

function highlightMatch(value, query) {
  const safeValue = escapeHtml(value);
  if (!query) {
    return safeValue;
  }

  const escapedQuery = escapeRegExp(query);
  return safeValue.replace(new RegExp(`(${escapedQuery})`, "ig"), "<mark>$1</mark>");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function isValidUrl(value) {
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol);
  } catch (error) {
    return false;
  }
}

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function safeHostname(value) {
  try {
    return new URL(value).hostname;
  } catch (error) {
    return value;
  }
}

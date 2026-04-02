const GUEST_HISTORY_STORAGE_KEY = "phishguard.history.guest.v2";
const SETTINGS_STORAGE_KEY = "phishguard.settings.v1";
const HISTORY_LIMIT = 150;
const SEARCH_DEBOUNCE_MS = 120;
const DEFAULT_SETTINGS = {
  displayName: "",
  defaultThreatFilter: "all",
  timelineLength: 6,
  dashboardRangeDays: 14,
  disposableOnly: false
};
const DATE_TIME_FORMATTER = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "short",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit"
});
const DAY_LABEL_FORMATTER = new Intl.DateTimeFormat(undefined, {
  month: "short",
  day: "numeric"
});
const SEVERITY_ORDER = {
  safe: 1,
  suspicious: 2,
  dangerous: 3
};
const activeRequests = new Map();

const state = {
  user: null,
  history: loadGuestHistory(),
  settings: loadLocalSettings(),
  latestUrlResult: null,
  latestEmailResult: null,
  latestCombinedResult: null,
  authMode: "login"
};
let historyRenderTimeout = 0;

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
  disposableMetric: document.getElementById("disposableMetric"),
  headerStatus: document.getElementById("headerStatus"),
  sessionSummary: document.getElementById("sessionSummary"),
  loginModeBtn: document.getElementById("loginModeBtn"),
  registerModeBtn: document.getElementById("registerModeBtn"),
  authForm: document.getElementById("authForm"),
  authNameField: document.getElementById("authNameField"),
  authNameInput: document.getElementById("authNameInput"),
  authEmailInput: document.getElementById("authEmailInput"),
  authPasswordInput: document.getElementById("authPasswordInput"),
  authSubmitBtn: document.getElementById("authSubmitBtn"),
  signOutBtn: document.getElementById("signOutBtn"),
  settingsForm: document.getElementById("settingsForm"),
  displayNameInput: document.getElementById("displayNameInput"),
  settingsThreatFilter: document.getElementById("settingsThreatFilter"),
  settingsTimelineLength: document.getElementById("settingsTimelineLength"),
  settingsDashboardRange: document.getElementById("settingsDashboardRange"),
  settingsDisposableOnly: document.getElementById("settingsDisposableOnly"),
  settingsSaveBtn: document.getElementById("settingsSaveBtn"),
  settingsStatus: document.getElementById("settingsStatus"),
  analyticsSummary: document.getElementById("analyticsSummary"),
  riskBreakdown: document.getElementById("riskBreakdown"),
  typeBreakdown: document.getElementById("typeBreakdown"),
  activityChart: document.getElementById("activityChart"),
  analyticsRangeLabel: document.getElementById("analyticsRangeLabel"),
  domainLeaderboard: document.getElementById("domainLeaderboard"),
  personalInsight: document.getElementById("personalInsight")
};

bindEvents();
setAuthMode("login");
populateSettingsForm();
applyDefaultFilters();
renderAll();
void initializeSession();

function bindEvents() {
  elements.urlForm.addEventListener("submit", handleUrlScan);
  elements.emailForm.addEventListener("submit", handleEmailScan);
  elements.combinedScanBtn.addEventListener("click", handleCombinedScan);
  elements.exportBtn.addEventListener("click", exportHistory);
  elements.clearHistoryBtn.addEventListener("click", clearHistory);
  elements.authForm.addEventListener("submit", handleAuthSubmit);
  elements.signOutBtn.addEventListener("click", handleSignOut);
  elements.settingsForm.addEventListener("submit", handleSettingsSave);
  elements.loginModeBtn.addEventListener("click", () => setAuthMode("login"));
  elements.registerModeBtn.addEventListener("click", () => setAuthMode("register"));

  elements.searchInput.addEventListener("input", scheduleHistoryRender);

  [
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

async function initializeSession() {
  try {
    const session = await requestJson("/api/session", null, { method: "GET" });
    if (session.authenticated) {
      await applyAuthenticatedWorkspace(session, { syncGuestHistory: true });
      showToast(`Welcome back, ${getViewerName()}.`, "safe");
    }
  } catch (error) {
    showToast("Saved session could not be restored.", "error");
  }
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
    const result = await runRequest("url", (signal) =>
      requestJson("/api/scan/url", { url }, { signal })
    );
    state.latestUrlResult = result;
    renderUrlResult(result);
    await pushHistory(createHistoryRecord("url", result));
    showToast(result.summary, result.threatLevel);
  } catch (error) {
    if (error.name === "AbortError") {
      return;
    }
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
    const result = await runRequest("email", (signal) =>
      requestJson("/api/scan/email", { email }, { signal })
    );
    state.latestEmailResult = result;
    renderEmailResult(result);
    await pushHistory(createHistoryRecord("email", result));
    showToast(result.summary, result.threatLevel);
  } catch (error) {
    if (error.name === "AbortError") {
      return;
    }
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
    const result = await runRequest("combined", (signal) =>
      requestJson("/api/scan/combined", { url, email }, { signal })
    );
    state.latestCombinedResult = result;
    state.latestUrlResult = result.url;
    state.latestEmailResult = result.email;
    renderUrlResult(result.url);
    renderEmailResult(result.email);
    renderCombinedSummary(result);
    await pushHistory(createHistoryRecord("combined", result));
    showToast("Combined scan completed.", result.threatLevel);
  } catch (error) {
    if (error.name === "AbortError") {
      return;
    }
    showToast(error.message, "error");
  } finally {
    setLoading(elements.combinedScanBtn, false);
  }
}

async function handleAuthSubmit(event) {
  event.preventDefault();
  const mode = state.authMode;
  const payload = {
    email: elements.authEmailInput.value.trim(),
    password: elements.authPasswordInput.value
  };

  if (mode === "register") {
    payload.name = elements.authNameInput.value.trim();
    if (!payload.name) {
      showToast("Add a display name to create an account.", "error");
      return;
    }
  }

  setLoading(elements.authSubmitBtn, true);

  try {
    const session = await requestJson(
      mode === "register" ? "/api/auth/register" : "/api/auth/login",
      payload
    );
    await applyAuthenticatedWorkspace(session, {
      syncGuestHistory: true,
      syncLocalSettings: mode === "register"
    });
    elements.authForm.reset();
    setAuthMode("login");
    showToast(mode === "register" ? "Account created and workspace synced." : "Signed in successfully.", "safe");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setLoading(elements.authSubmitBtn, false);
  }
}

async function handleSignOut() {
  setLoading(elements.signOutBtn, true);

  try {
    await requestJson("/api/auth/logout", {});
    state.user = null;
    state.history = loadGuestHistory();
    state.settings = loadLocalSettings();
    populateSettingsForm();
    applyDefaultFilters();
    renderAll();
    showToast("Signed out. Guest workspace restored.", "safe");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setLoading(elements.signOutBtn, false);
  }
}

async function handleSettingsSave(event) {
  event.preventDefault();
  const settings = readSettingsForm();

  state.settings = settings;
  saveLocalSettings();
  applyDefaultFilters();
  renderAll();

  if (!state.user) {
    elements.settingsStatus.textContent = "Saved in this browser. Sign in to sync these preferences.";
    showToast("Preferences saved locally.", "safe");
    return;
  }

  setLoading(elements.settingsSaveBtn, true);

  try {
    const response = await requestJson("/api/settings", settings);
    state.settings = normalizeSettings(response.settings);
    saveLocalSettings();
    populateSettingsForm();
    renderAll();
    elements.settingsStatus.textContent = "Preferences sync to your account automatically.";
    showToast("Preferences saved to your account.", "safe");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setLoading(elements.settingsSaveBtn, false);
  }
}

async function applyAuthenticatedWorkspace(session, options = {}) {
  state.user = session.user;
  state.settings = normalizeSettings(session.settings);
  state.history = normalizeHistoryList(session.history);

  if (options.syncLocalSettings && hasCustomizedSettings(loadLocalSettings())) {
    try {
      const updated = await requestJson("/api/settings", loadLocalSettings());
      state.settings = normalizeSettings(updated.settings);
    } catch (error) {
      showToast("Account created, but local preferences could not be synced yet.", "suspicious");
    }
  }

  const guestHistory = loadGuestHistory();
  if (options.syncGuestHistory && guestHistory.length) {
    try {
      const syncResponse = await requestJson("/api/history/sync", { records: guestHistory });
      state.history = normalizeHistoryList(syncResponse.history);
      localStorage.removeItem(GUEST_HISTORY_STORAGE_KEY);
    } catch (error) {
      showToast("Signed in, but guest history could not be synced yet.", "suspicious");
    }
  }

  saveLocalSettings();
  populateSettingsForm();
  applyDefaultFilters();
  renderAll();
}

function renderAll() {
  renderWorkspace();
  renderUrlResult(state.latestUrlResult);
  renderEmailResult(state.latestEmailResult);
  renderCombinedSummary(state.latestCombinedResult);
  renderTimeline();
  renderHistoryTable();
  renderMetrics();
  renderAnalytics();
}

function renderWorkspace() {
  const viewerName = getViewerName();

  if (state.user) {
    elements.headerStatus.textContent = `${viewerName} synced workspace`;
    elements.sessionSummary.innerHTML = `
      <strong>${escapeHtml(viewerName)}</strong>
      <p>${escapeHtml(state.user.email)}</p>
      <span class="timeline-meta">History and preferences are stored in your account.</span>
    `;
    elements.authForm.hidden = true;
    elements.loginModeBtn.hidden = true;
    elements.registerModeBtn.hidden = true;
    elements.signOutBtn.hidden = false;
    elements.settingsStatus.textContent = "Preferences sync to your account automatically.";
  } else {
    elements.headerStatus.textContent = "Guest workspace";
    elements.sessionSummary.innerHTML = `
      <strong>Guest session</strong>
      <p>Scans and preferences stay in this browser until you sign in.</p>
      <span class="timeline-meta">Create an account to keep your investigation history synced.</span>
    `;
    elements.authForm.hidden = false;
    elements.loginModeBtn.hidden = false;
    elements.registerModeBtn.hidden = false;
    elements.signOutBtn.hidden = true;
    elements.settingsStatus.textContent = "Guest preferences are stored locally.";
  }
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
    .slice(0, state.settings.timelineLength);

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
}

function renderMetrics() {
  const dangerous = state.history.filter((record) => record.threatLevel === "dangerous").length;
  const disposable = state.history.filter((record) => record.disposable).length;

  elements.totalScansMetric.textContent = String(state.history.length);
  elements.dangerScansMetric.textContent = String(dangerous);
  elements.disposableMetric.textContent = String(disposable);
}

function renderAnalytics() {
  const recentHistory = getRecentHistoryWindow();
  const total = recentHistory.length;
  const counts = {
    safe: recentHistory.filter((record) => record.threatLevel === "safe").length,
    suspicious: recentHistory.filter((record) => record.threatLevel === "suspicious").length,
    dangerous: recentHistory.filter((record) => record.threatLevel === "dangerous").length,
    url: recentHistory.filter((record) => record.type === "url").length,
    email: recentHistory.filter((record) => record.type === "email").length,
    combined: recentHistory.filter((record) => record.type === "combined").length
  };

  elements.analyticsRangeLabel.textContent = `Last ${state.settings.dashboardRangeDays} days`;
  elements.analyticsSummary.innerHTML = [
    analyticsCardMarkup("Scans in range", total, "Tracked activity in the selected dashboard window."),
    analyticsCardMarkup("Dangerous", counts.dangerous, "Items that need escalation or blocking."),
    analyticsCardMarkup("Combined reviews", counts.combined, "Scans where URL and sender were evaluated together.")
  ].join("");

  elements.riskBreakdown.innerHTML = [
    breakdownRowMarkup("Dangerous", counts.dangerous, total, "dangerous"),
    breakdownRowMarkup("Suspicious", counts.suspicious, total, "suspicious"),
    breakdownRowMarkup("Safe", counts.safe, total, "safe")
  ].join("");

  elements.typeBreakdown.innerHTML = [
    breakdownRowMarkup("URL scans", counts.url, total, "neutral"),
    breakdownRowMarkup("Email checks", counts.email, total, "neutral"),
    breakdownRowMarkup("Combined reviews", counts.combined, total, "neutral")
  ].join("");

  renderActivityChart(recentHistory);
  renderDomainLeaderboard(recentHistory);
  renderPersonalInsight(recentHistory, counts);
}

function analyticsCardMarkup(label, value, copy) {
  return `
    <article class="metric-card analytics-card">
      <span class="metric-label">${escapeHtml(label)}</span>
      <strong class="metric-value">${escapeHtml(String(value))}</strong>
      <p>${escapeHtml(copy)}</p>
    </article>
  `;
}

function breakdownRowMarkup(label, value, total, tone) {
  const ratio = total ? Math.round((value / total) * 100) : 0;
  return `
    <div class="breakdown-row">
      <div class="breakdown-copy">
        <strong>${escapeHtml(label)}</strong>
        <span>${value} (${ratio}%)</span>
      </div>
      <div class="breakdown-track">
        <span class="breakdown-fill breakdown-${tone}" style="width: ${ratio}%"></span>
      </div>
    </div>
  `;
}

function renderActivityChart(records) {
  const now = new Date();
  const points = [];

  for (let offset = state.settings.dashboardRangeDays - 1; offset >= 0; offset -= 1) {
    const day = new Date(now);
    day.setHours(0, 0, 0, 0);
    day.setDate(day.getDate() - offset);
    const key = day.toISOString().slice(0, 10);
    const count = records.filter((record) => record.timestamp.slice(0, 10) === key).length;
    const dangerous = records.filter(
      (record) => record.timestamp.slice(0, 10) === key && record.threatLevel === "dangerous"
    ).length;
    points.push({
      key,
      label: DAY_LABEL_FORMATTER.format(day),
      count,
      dangerous
    });
  }

  const maxCount = Math.max(...points.map((point) => point.count), 1);

  elements.activityChart.innerHTML = points
    .map((point) => {
      const height = point.count ? Math.max(12, Math.round((point.count / maxCount) * 100)) : 6;
      const dangerClass = point.dangerous ? " is-danger" : "";
      return `
        <div class="activity-column">
          <span class="activity-count">${point.count}</span>
          <div class="activity-bar-shell">
            <span class="activity-bar${dangerClass}" style="height: ${height}%"></span>
          </div>
          <span class="activity-label">${escapeHtml(point.label)}</span>
        </div>
      `;
    })
    .join("");
}

function renderDomainLeaderboard(records) {
  const ranked = [...records]
    .filter((record) => record.domain)
    .reduce((map, record) => {
      const entry = map.get(record.domain) || {
        domain: record.domain,
        scans: 0,
        highestThreat: "safe"
      };
      entry.scans += 1;
      if (SEVERITY_ORDER[record.threatLevel] > SEVERITY_ORDER[entry.highestThreat]) {
        entry.highestThreat = record.threatLevel;
      }
      map.set(record.domain, entry);
      return map;
    }, new Map());

  const topDomains = [...ranked.values()]
    .sort((left, right) => right.scans - left.scans || left.domain.localeCompare(right.domain))
    .slice(0, 5);

  if (!topDomains.length) {
    elements.domainLeaderboard.innerHTML =
      '<div class="timeline-empty">Run more scans to see repeat domains and recurring risk patterns.</div>';
    return;
  }

  elements.domainLeaderboard.innerHTML = topDomains
    .map(
      (entry) => `
        <div class="leaderboard-row">
          <div>
            <strong class="mono">${escapeHtml(entry.domain)}</strong>
            <p>${entry.scans} scan${entry.scans === 1 ? "" : "s"} in range</p>
          </div>
          ${severityPill(entry.highestThreat)}
        </div>
      `
    )
    .join("");
}

function renderPersonalInsight(records, counts) {
  if (!records.length) {
    elements.personalInsight.textContent =
      "Once you build a scan history, this dashboard will highlight what deserves attention first.";
    return;
  }

  const ratio = records.length ? Math.round((counts.combined / records.length) * 100) : 0;
  const mostDangerous = records.find((record) => record.threatLevel === "dangerous");

  elements.personalInsight.innerHTML = mostDangerous
    ? `
        Combined reviews account for ${ratio}% of recent activity.
        The highest-priority indicator in range is <strong>${escapeHtml(mostDangerous.target)}</strong>.
      `
    : `
        Recent activity is dominated by ${counts.suspicious > counts.safe ? "follow-up work" : "lower-risk checks"}.
        Combined reviews account for ${ratio}% of the dashboard range.
      `;
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

function getRecentHistoryWindow() {
  const now = new Date();
  const cutoff = new Date(now);
  cutoff.setHours(0, 0, 0, 0);
  cutoff.setDate(cutoff.getDate() - (state.settings.dashboardRangeDays - 1));

  return state.history.filter((record) => new Date(record.timestamp) >= cutoff);
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
      id: createRecordId(),
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
      id: createRecordId(),
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
    id: createRecordId(),
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

async function pushHistory(record) {
  state.history = normalizeHistoryList([record, ...state.history]);
  persistGuestHistory();
  renderAll();

  if (!state.user) {
    return;
  }

  try {
    const response = await requestJson("/api/history/append", { record });
    state.history = normalizeHistoryList(response.history);
    renderAll();
  } catch (error) {
    showToast("Saved in the browser, but account sync is currently unavailable.", "suspicious");
  }
}

async function clearHistory() {
  if (!state.user) {
    state.history = [];
    persistGuestHistory();
    renderAll();
    showToast("Guest scan history cleared.", "safe");
    return;
  }

  try {
    await requestJson("/api/history/clear", {});
    state.history = [];
    renderAll();
    showToast("Account scan history cleared.", "safe");
  } catch (error) {
    showToast(error.message, "error");
  }
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

async function requestJson(url, payload, options = {}) {
  const method = options.method || "POST";
  const response = await fetch(url, {
    method,
    headers: {
      "Content-Type": "application/json"
    },
    body: method === "GET" ? undefined : JSON.stringify(payload || {}),
    signal: options.signal
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || "Request failed.");
  }

  return data;
}

function loadGuestHistory() {
  try {
    return normalizeHistoryList(JSON.parse(localStorage.getItem(GUEST_HISTORY_STORAGE_KEY) || "[]"));
  } catch (error) {
    return [];
  }
}

function persistGuestHistory() {
  if (state.user) {
    return;
  }
  localStorage.setItem(GUEST_HISTORY_STORAGE_KEY, JSON.stringify(state.history));
}

function loadLocalSettings() {
  try {
    return normalizeSettings(JSON.parse(localStorage.getItem(SETTINGS_STORAGE_KEY) || "{}"));
  } catch (error) {
    return normalizeSettings(DEFAULT_SETTINGS);
  }
}

function saveLocalSettings() {
  localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(state.settings));
}

function normalizeSettings(input = {}) {
  return {
    displayName: String(input.displayName || "").trim().slice(0, 60),
    defaultThreatFilter: ["all", "safe", "suspicious", "dangerous"].includes(input.defaultThreatFilter)
      ? input.defaultThreatFilter
      : DEFAULT_SETTINGS.defaultThreatFilter,
    timelineLength: clampNumber(input.timelineLength, 4, 12, DEFAULT_SETTINGS.timelineLength),
    dashboardRangeDays: clampNumber(
      input.dashboardRangeDays,
      7,
      30,
      DEFAULT_SETTINGS.dashboardRangeDays
    ),
    disposableOnly: Boolean(input.disposableOnly)
  };
}

function normalizeHistoryList(records) {
  if (!Array.isArray(records)) {
    return [];
  }

  const deduped = new Map();

  for (const rawRecord of records) {
    const record = {
      id: String(rawRecord.id || createRecordId()).slice(0, 120),
      type: ["url", "email", "combined"].includes(rawRecord.type) ? rawRecord.type : "url",
      target: String(rawRecord.target || "").trim().slice(0, 320),
      domain: String(rawRecord.domain || "").trim().slice(0, 120),
      threatLevel: ["safe", "suspicious", "dangerous"].includes(rawRecord.threatLevel)
        ? rawRecord.threatLevel
        : "safe",
      threatScore: clampNumber(rawRecord.threatScore, 0, 100, 0),
      disposable: Boolean(rawRecord.disposable),
      summary: String(rawRecord.summary || "").trim().slice(0, 240),
      timestamp: normalizeTimestamp(rawRecord.timestamp)
    };

    if (!record.target || !record.summary) {
      continue;
    }

    deduped.set(record.id, record);
  }

  return [...deduped.values()]
    .sort((left, right) => new Date(right.timestamp) - new Date(left.timestamp))
    .slice(0, HISTORY_LIMIT);
}

function populateSettingsForm() {
  elements.displayNameInput.value = state.settings.displayName;
  elements.settingsThreatFilter.value = state.settings.defaultThreatFilter;
  elements.settingsTimelineLength.value = String(state.settings.timelineLength);
  elements.settingsDashboardRange.value = String(state.settings.dashboardRangeDays);
  elements.settingsDisposableOnly.checked = state.settings.disposableOnly;
}

function readSettingsForm() {
  return normalizeSettings({
    displayName: elements.displayNameInput.value,
    defaultThreatFilter: elements.settingsThreatFilter.value,
    timelineLength: Number(elements.settingsTimelineLength.value),
    dashboardRangeDays: Number(elements.settingsDashboardRange.value),
    disposableOnly: elements.settingsDisposableOnly.checked
  });
}

function applyDefaultFilters() {
  elements.threatFilter.value = state.settings.defaultThreatFilter;
  elements.disposableOnly.checked = state.settings.disposableOnly;
}

function setAuthMode(mode) {
  state.authMode = mode;
  const isRegister = mode === "register";
  elements.authNameField.hidden = !isRegister;
  elements.authSubmitBtn.textContent = isRegister ? "Create account" : "Sign in";
  elements.loginModeBtn.classList.toggle("is-active", !isRegister);
  elements.registerModeBtn.classList.toggle("is-active", isRegister);
}

function setLoading(button, active) {
  button.disabled = active;
  button.setAttribute("aria-busy", String(active));
  button.classList.toggle("is-loading", active);
}

function showToast(message, tone = "safe") {
  const toast = document.createElement("div");
  toast.className = `toast ${tone}`;
  toast.textContent = message;
  elements.toastHost.appendChild(toast);

  while (elements.toastHost.childElementCount > 4) {
    elements.toastHost.firstElementChild?.remove();
  }

  window.setTimeout(() => {
    toast.remove();
  }, 3600);
}

function gaugeMarkup({ value, label, valueSuffix = "", tone }) {
  const color =
    tone === "dangerous"
      ? "var(--danger-red)"
      : tone === "suspicious"
        ? "var(--warning-amber)"
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
  return DATE_TIME_FORMATTER.format(new Date(value));
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

function scheduleHistoryRender() {
  window.clearTimeout(historyRenderTimeout);
  historyRenderTimeout = window.setTimeout(() => {
    renderHistoryTable();
  }, SEARCH_DEBOUNCE_MS);
}

async function runRequest(key, execute) {
  activeRequests.get(key)?.abort();

  const controller = new AbortController();
  activeRequests.set(key, controller);

  try {
    return await execute(controller.signal);
  } finally {
    if (activeRequests.get(key) === controller) {
      activeRequests.delete(key);
    }
  }
}

function getViewerName() {
  return state.settings.displayName || state.user?.name || "Analyst";
}

function createRecordId() {
  if (window.crypto && typeof window.crypto.randomUUID === "function") {
    return window.crypto.randomUUID();
  }
  return `record-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function normalizeTimestamp(value) {
  const parsed = new Date(value || Date.now());
  return Number.isNaN(parsed.getTime()) ? new Date().toISOString() : parsed.toISOString();
}

function clampNumber(value, min, max, fallback) {
  const numeric = Number(value);
  if (Number.isNaN(numeric)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, numeric));
}

function hasCustomizedSettings(settings) {
  return JSON.stringify(normalizeSettings(settings)) !== JSON.stringify(DEFAULT_SETTINGS);
}

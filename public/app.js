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
const PASSWORD_COMPLEXITY_REGEX =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,}$/;

const state = {
  csrfToken: "",
  accessToken: "",
  accessTokenExpiresAt: "",
  user: null,
  settings: { ...DEFAULT_SETTINGS },
  history: [],
  latestUrlResult: null,
  latestEmailResult: null,
  latestCombinedResult: null,
  refreshTimeoutId: 0,
  refreshPromise: null,
  activeAuthView: "login",
  routePath: window.location.pathname,
  verificationHandled: false,
  historyRenderTimeout: 0
};

const elements = {
  authShell: document.getElementById("authShell"),
  protectedApp: document.getElementById("protectedApp"),
  dashboardView: document.getElementById("dashboardView"),
  profileView: document.getElementById("profileView"),
  siteNav: document.getElementById("siteNav"),
  routeLinks: document.querySelectorAll("[data-route-link]"),
  routeActions: document.querySelectorAll("[data-route-action]"),
  authTabs: document.querySelectorAll("[data-auth-view]"),
  authAlert: document.getElementById("authAlert"),
  authInfoCard: document.getElementById("authInfoCard"),
  headerStatus: document.getElementById("headerStatus"),
  logoutBtn: document.getElementById("logoutBtn"),
  loginForm: document.getElementById("loginForm"),
  registerForm: document.getElementById("registerForm"),
  forgotPasswordForm: document.getElementById("forgotPasswordForm"),
  resetPasswordForm: document.getElementById("resetPasswordForm"),
  loginEmail: document.getElementById("loginEmail"),
  loginPassword: document.getElementById("loginPassword"),
  rememberMe: document.getElementById("rememberMe"),
  loginSubmitBtn: document.getElementById("loginSubmitBtn"),
  registerFirstName: document.getElementById("registerFirstName"),
  registerLastName: document.getElementById("registerLastName"),
  registerEmail: document.getElementById("registerEmail"),
  registerPassword: document.getElementById("registerPassword"),
  registerPasswordConfirm: document.getElementById("registerPasswordConfirm"),
  registerSubmitBtn: document.getElementById("registerSubmitBtn"),
  passwordMeterFill: document.getElementById("passwordMeterFill"),
  passwordStrengthLabel: document.getElementById("passwordStrengthLabel"),
  forgotEmail: document.getElementById("forgotEmail"),
  forgotSubmitBtn: document.getElementById("forgotSubmitBtn"),
  resetPassword: document.getElementById("resetPassword"),
  resetPasswordConfirm: document.getElementById("resetPasswordConfirm"),
  resetSubmitBtn: document.getElementById("resetSubmitBtn"),
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
  displayNameInput: document.getElementById("displayNameInput"),
  settingsThreatFilter: document.getElementById("settingsThreatFilter"),
  settingsTimelineLength: document.getElementById("settingsTimelineLength"),
  settingsDashboardRange: document.getElementById("settingsDashboardRange"),
  settingsDisposableOnly: document.getElementById("settingsDisposableOnly"),
  settingsForm: document.getElementById("settingsForm"),
  settingsSaveBtn: document.getElementById("settingsSaveBtn"),
  settingsStatus: document.getElementById("settingsStatus"),
  analyticsSummary: document.getElementById("analyticsSummary"),
  riskBreakdown: document.getElementById("riskBreakdown"),
  typeBreakdown: document.getElementById("typeBreakdown"),
  activityChart: document.getElementById("activityChart"),
  analyticsRangeLabel: document.getElementById("analyticsRangeLabel"),
  domainLeaderboard: document.getElementById("domainLeaderboard"),
  personalInsight: document.getElementById("personalInsight"),
  profileCardName: document.getElementById("profileCardName"),
  profileCardEmail: document.getElementById("profileCardEmail"),
  profileFirstName: document.getElementById("profileFirstName"),
  profileLastName: document.getElementById("profileLastName"),
  profileCreatedAt: document.getElementById("profileCreatedAt"),
  verificationBadge: document.getElementById("verificationBadge"),
  profilePageName: document.getElementById("profilePageName"),
  profilePageEmail: document.getElementById("profilePageEmail"),
  profilePageId: document.getElementById("profilePageId"),
  profilePageVerified: document.getElementById("profilePageVerified"),
  profilePageCreatedAt: document.getElementById("profilePageCreatedAt"),
  profilePageUpdatedAt: document.getElementById("profilePageUpdatedAt")
};

bindEvents();
renderAll();
void initializeApp();

function bindEvents() {
  window.addEventListener("popstate", () => {
    state.routePath = window.location.pathname;
    renderRoute();
  });

  elements.authTabs.forEach((element) => {
    element.addEventListener("click", () => {
      const view = element.dataset.authView;
      navigateTo(authPathForView(view));
    });
  });

  elements.routeLinks.forEach((element) => {
    element.addEventListener("click", (event) => {
      event.preventDefault();
      navigateTo(element.getAttribute("href"));
    });
  });

  elements.routeActions.forEach((element) => {
    element.addEventListener("click", () => {
      navigateTo(element.dataset.routeAction);
    });
  });

  elements.loginForm.addEventListener("submit", handleLogin);
  elements.registerForm.addEventListener("submit", handleRegister);
  elements.forgotPasswordForm.addEventListener("submit", handleForgotPassword);
  elements.resetPasswordForm.addEventListener("submit", handleResetPassword);
  elements.logoutBtn.addEventListener("click", handleLogout);
  elements.registerPassword.addEventListener("input", renderPasswordStrength);
  elements.settingsForm.addEventListener("submit", handleSettingsSave);
  elements.urlForm.addEventListener("submit", handleUrlScan);
  elements.emailForm.addEventListener("submit", handleEmailScan);
  elements.combinedScanBtn.addEventListener("click", handleCombinedScan);
  elements.clearHistoryBtn.addEventListener("click", clearHistory);
  elements.exportBtn.addEventListener("click", exportHistory);

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

async function initializeApp() {
  await bootstrapCsrf();
  renderRoute();

  if (isVerificationRoute() && !state.verificationHandled) {
    state.verificationHandled = true;
    await handleVerificationRoute();
    return;
  }

  const restored = await refreshSession().catch(() => false);
  if (restored) {
    await loadProtectedData();
  }

  renderAll();
}

async function bootstrapCsrf() {
  try {
    const response = await fetch("/api/auth/csrf", {
      method: "GET",
      credentials: "same-origin"
    });
    const payload = await response.json().catch(() => ({}));
    state.csrfToken = payload.csrfToken || "";
  } catch (error) {
    showAuthAlert("Unable to initialize CSRF protection. Refresh the page and try again.", "error");
  }
}

async function handleLogin(event) {
  event.preventDefault();
  hideAuthAlert();
  setLoading(elements.loginSubmitBtn, true);

  try {
    const payload = await apiRequest("/api/auth/login", {
      method: "POST",
      body: {
        email: elements.loginEmail.value.trim(),
        password: elements.loginPassword.value,
        rememberMe: elements.rememberMe.checked
      },
      includeAuth: false
    });

    acceptSession(payload);
    await loadProtectedData();
    navigateTo("/app", { replace: true });
    showToast("Signed in successfully.", "safe");
  } catch (error) {
    showAuthAlert(error.message);
  } finally {
    setLoading(elements.loginSubmitBtn, false);
  }
}

async function handleRegister(event) {
  event.preventDefault();
  hideAuthAlert();

  const password = elements.registerPassword.value;
  const confirm = elements.registerPasswordConfirm.value;

  if (password !== confirm) {
    showAuthAlert("Password confirmation does not match.");
    return;
  }

  if (!PASSWORD_COMPLEXITY_REGEX.test(password)) {
    showAuthAlert(
      "Password must be at least 8 characters and include uppercase, lowercase, number, and special character."
    );
    return;
  }

  setLoading(elements.registerSubmitBtn, true);

  try {
    const payload = await apiRequest("/api/auth/register", {
      method: "POST",
      body: {
        firstName: elements.registerFirstName.value.trim(),
        lastName: elements.registerLastName.value.trim(),
        email: elements.registerEmail.value.trim(),
        password
      },
      includeAuth: false
    });

    elements.registerForm.reset();
    renderPasswordStrength();
    navigateTo("/login", { replace: true });
    showAuthAlert(payload.message, "success");
  } catch (error) {
    showAuthAlert(error.message);
  } finally {
    setLoading(elements.registerSubmitBtn, false);
  }
}

async function handleForgotPassword(event) {
  event.preventDefault();
  hideAuthAlert();
  setLoading(elements.forgotSubmitBtn, true);

  try {
    const payload = await apiRequest("/api/auth/forgot-password", {
      method: "POST",
      body: {
        email: elements.forgotEmail.value.trim()
      },
      includeAuth: false
    });

    showAuthAlert(payload.message, "success");
    elements.forgotPasswordForm.reset();
  } catch (error) {
    showAuthAlert(error.message);
  } finally {
    setLoading(elements.forgotSubmitBtn, false);
  }
}

async function handleResetPassword(event) {
  event.preventDefault();
  hideAuthAlert();
  const token = readRouteToken("token");

  if (!token) {
    showAuthAlert("Password reset token is missing from the link.");
    return;
  }

  if (elements.resetPassword.value !== elements.resetPasswordConfirm.value) {
    showAuthAlert("Password confirmation does not match.");
    return;
  }

  setLoading(elements.resetSubmitBtn, true);

  try {
    const payload = await apiRequest("/api/auth/reset-password", {
      method: "POST",
      body: {
        token,
        password: elements.resetPassword.value
      },
      includeAuth: false
    });

    elements.resetPasswordForm.reset();
    navigateTo("/login", { replace: true });
    showAuthAlert(payload.message, "success");
  } catch (error) {
    showAuthAlert(error.message);
  } finally {
    setLoading(elements.resetSubmitBtn, false);
  }
}

async function handleVerificationRoute() {
  hideAuthAlert();
  const token = readRouteToken("token");

  if (!token) {
    showAuthAlert("Verification token is missing from the link.");
    return;
  }

  showAuthAlert("Verifying your email address...", "success");

  try {
    const payload = await apiRequest("/api/auth/verify-email", {
      method: "POST",
      body: { token },
      includeAuth: false
    });
    navigateTo("/login", { replace: true });
    showAuthAlert(payload.message, "success");
  } catch (error) {
    showAuthAlert(error.message);
  }
}

async function handleLogout() {
  setLoading(elements.logoutBtn, true);

  try {
    await apiRequest("/api/auth/logout", {
      method: "POST",
      body: {}
    });
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    clearSession();
    setLoading(elements.logoutBtn, false);
    navigateTo("/login", { replace: true });
    showAuthAlert("You have been signed out.", "success");
  }
}

async function handleSettingsSave(event) {
  event.preventDefault();
  setLoading(elements.settingsSaveBtn, true);

  try {
    const response = await apiRequest("/api/settings", {
      method: "PUT",
      body: readSettingsForm()
    });

    state.settings = normalizeSettings(response.settings);
    populateSettingsForm();
    applySettingsToFilters();
    renderAll();
    elements.settingsStatus.textContent = "Preferences saved to your authenticated account.";
    showToast("Preferences saved.", "safe");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setLoading(elements.settingsSaveBtn, false);
  }
}

async function handleUrlScan(event) {
  event.preventDefault();
  if (!ensureAuthenticated()) {
    return;
  }

  setLoading(elements.urlScanBtn, true);
  try {
    const result = await apiRequest("/api/scan/url", {
      method: "POST",
      body: { url: elements.urlInput.value.trim() }
    });
    state.latestUrlResult = result;
    renderUrlResult(result);
    await addHistoryRecord(createHistoryRecord("url", result));
    showToast(result.summary, result.threatLevel);
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setLoading(elements.urlScanBtn, false);
  }
}

async function handleEmailScan(event) {
  event.preventDefault();
  if (!ensureAuthenticated()) {
    return;
  }

  setLoading(elements.emailScanBtn, true);
  try {
    const result = await apiRequest("/api/scan/email", {
      method: "POST",
      body: { email: elements.emailInput.value.trim() }
    });
    state.latestEmailResult = result;
    renderEmailResult(result);
    await addHistoryRecord(createHistoryRecord("email", result));
    showToast(result.summary, result.threatLevel);
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setLoading(elements.emailScanBtn, false);
  }
}

async function handleCombinedScan() {
  if (!ensureAuthenticated()) {
    return;
  }

  setLoading(elements.combinedScanBtn, true);
  try {
    const result = await apiRequest("/api/scan/combined", {
      method: "POST",
      body: {
        url: elements.urlInput.value.trim(),
        email: elements.emailInput.value.trim()
      }
    });
    state.latestCombinedResult = result;
    state.latestUrlResult = result.url;
    state.latestEmailResult = result.email;
    renderUrlResult(result.url);
    renderEmailResult(result.email);
    renderCombinedSummary(result);
    await addHistoryRecord(createHistoryRecord("combined", result));
    showToast("Combined scan completed.", result.threatLevel);
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setLoading(elements.combinedScanBtn, false);
  }
}

async function addHistoryRecord(record) {
  const response = await apiRequest("/api/history", {
    method: "POST",
    body: { record }
  });

  state.history = normalizeHistoryList([response.record, ...state.history]);
  renderAll();
}

async function clearHistory() {
  try {
    await apiRequest("/api/history", {
      method: "DELETE",
      body: {}
    });
    state.history = [];
    renderAll();
    showToast("History cleared.", "safe");
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
}

async function loadProtectedData() {
  const payload = await apiRequest("/api/bootstrap", {
    method: "GET"
  });

  state.user = payload.user;
  state.settings = normalizeSettings(payload.settings);
  state.history = normalizeHistoryList(payload.history);
  populateSettingsForm();
  applySettingsToFilters();
  renderAll();
}

function acceptSession(payload) {
  state.accessToken = payload.accessToken;
  state.accessTokenExpiresAt = payload.accessTokenExpiresAt;
  state.csrfToken = payload.csrfToken || state.csrfToken;
  if (payload.user) {
    state.user = payload.user;
  }
  scheduleTokenRefresh();
}

function clearSession() {
  state.accessToken = "";
  state.accessTokenExpiresAt = "";
  state.user = null;
  state.history = [];
  state.settings = { ...DEFAULT_SETTINGS };
  state.latestUrlResult = null;
  state.latestEmailResult = null;
  state.latestCombinedResult = null;
  window.clearTimeout(state.refreshTimeoutId);
  renderAll();
}

async function refreshSession() {
  if (state.refreshPromise) {
    return state.refreshPromise;
  }

  state.refreshPromise = (async () => {
    try {
      const payload = await apiRequest("/api/auth/refresh", {
        method: "POST",
        body: {},
        includeAuth: false,
        retryOn401: false
      });
      acceptSession(payload);
      return true;
    } catch (error) {
      clearSession();
      return false;
    } finally {
      state.refreshPromise = null;
    }
  })();

  return state.refreshPromise;
}

function scheduleTokenRefresh() {
  window.clearTimeout(state.refreshTimeoutId);

  if (!state.accessTokenExpiresAt) {
    return;
  }

  const expiresAt = new Date(state.accessTokenExpiresAt).getTime();
  const delay = Math.max(5_000, expiresAt - Date.now() - 60_000);

  state.refreshTimeoutId = window.setTimeout(() => {
    void refreshSession().then(async (restored) => {
      if (restored) {
        await loadProtectedData();
      } else {
        navigateTo("/login", { replace: true });
        showAuthAlert("Your session expired. Sign in again.");
      }
    });
  }, delay);
}

async function apiRequest(path, options = {}) {
  const method = options.method || "GET";
  const headers = {
    "Content-Type": "application/json"
  };

  if (state.csrfToken && method !== "GET") {
    headers["x-csrf-token"] = state.csrfToken;
  }

  if (options.includeAuth !== false && state.accessToken) {
    headers.authorization = `Bearer ${state.accessToken}`;
  }

  const response = await fetch(path, {
    method,
    credentials: "same-origin",
    headers,
    body: method === "GET" ? undefined : JSON.stringify(options.body || {})
  });

  const payload = await response.json().catch(() => ({}));

  if (response.status === 401 && options.retryOn401 !== false && options.includeAuth !== false) {
    const restored = await refreshSession();
    if (restored) {
      return apiRequest(path, {
        ...options,
        retryOn401: false
      });
    }

    navigateTo("/login", { replace: true });
    showAuthAlert("Your session expired. Sign in again.");
  }

  if (!response.ok) {
    throw new Error(payload.error || "Request failed.");
  }

  return payload;
}

function renderAll() {
  renderRoute();
  renderHeader();
  renderProfile();
  renderUrlResult(state.latestUrlResult);
  renderEmailResult(state.latestEmailResult);
  renderCombinedSummary(state.latestCombinedResult);
  renderTimeline();
  renderHistoryTable();
  renderMetrics();
  renderAnalytics();
}

function renderRoute() {
  const pathname = window.location.pathname;
  state.routePath = pathname;

  if (!state.user && isProtectedPath(pathname)) {
    setAuthView("login");
    elements.authShell.hidden = false;
    elements.protectedApp.hidden = true;
    elements.siteNav.hidden = true;
    elements.logoutBtn.hidden = true;
    return;
  }

  if (state.user && isPublicPath(pathname)) {
    navigateTo("/app", { replace: true });
    return;
  }

  elements.authShell.hidden = Boolean(state.user);
  elements.protectedApp.hidden = !state.user;
  elements.siteNav.hidden = !state.user;
  elements.logoutBtn.hidden = !state.user;
  elements.dashboardView.hidden = pathname === "/profile";
  elements.profileView.hidden = pathname !== "/profile";

  if (!state.user) {
    setAuthView(viewFromPath(pathname));
  }

  elements.routeLinks.forEach((element) => {
    element.classList.toggle("is-active", element.dataset.routeLink === pathname);
  });
}

function renderHeader() {
  if (!state.user) {
    elements.headerStatus.textContent = "Authentication required";
    return;
  }

  const displayName = state.settings.displayName || `${state.user.firstName} ${state.user.lastName}`.trim();
  elements.headerStatus.textContent = `${displayName} authenticated`;
}

function renderProfile() {
  if (!state.user) {
    return;
  }

  const displayName = state.settings.displayName || `${state.user.firstName} ${state.user.lastName}`.trim();
  const verificationText = state.user.isVerified ? "Verified account" : "Verification pending";

  elements.profileCardName.textContent = displayName || state.user.email;
  elements.profileCardEmail.textContent = state.user.email;
  elements.profileFirstName.textContent = state.user.firstName;
  elements.profileLastName.textContent = state.user.lastName;
  elements.profileCreatedAt.textContent = formatDateTime(state.user.createdAt);
  elements.verificationBadge.textContent = verificationText;
  elements.verificationBadge.className = `pill ${state.user.isVerified ? "pill-safe" : "pill-suspicious"}`;

  elements.profilePageName.textContent = displayName || state.user.email;
  elements.profilePageEmail.textContent = state.user.email;
  elements.profilePageId.textContent = state.user.id;
  elements.profilePageVerified.textContent = verificationText;
  elements.profilePageCreatedAt.textContent = formatDateTime(state.user.createdAt);
  elements.profilePageUpdatedAt.textContent = formatDateTime(state.user.updatedAt);
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
      label: DAY_LABEL_FORMATTER.format(day),
      count,
      dangerous
    });
  }

  const maxCount = Math.max(...points.map((point) => point.count), 1);

  elements.activityChart.innerHTML = points
    .map((point) => {
      const height = point.count ? Math.max(12, Math.round((point.count / maxCount) * 100)) : 6;
      return `
        <div class="activity-column">
          <span class="activity-count">${point.count}</span>
          <div class="activity-bar-shell">
            <span class="activity-bar${point.dangerous ? " is-danger" : ""}" style="height: ${height}%"></span>
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
      "Once authenticated scans accumulate, this dashboard highlights what deserves attention first.";
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
  const cutoff = new Date();
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

function setAuthView(view) {
  state.activeAuthView = view;
  elements.authTabs.forEach((element) => {
    element.classList.toggle("is-active", element.dataset.authView === view);
  });
  elements.loginForm.hidden = view !== "login";
  elements.registerForm.hidden = view !== "register";
  elements.forgotPasswordForm.hidden = view !== "forgot";
  elements.resetPasswordForm.hidden = view !== "reset";
}

function showAuthAlert(message, tone = "error") {
  elements.authAlert.hidden = false;
  elements.authAlert.textContent = message;
  elements.authAlert.className = `auth-alert ${tone}`;
}

function hideAuthAlert() {
  elements.authAlert.hidden = true;
  elements.authAlert.textContent = "";
  elements.authAlert.className = "auth-alert";
}

function renderPasswordStrength() {
  const password = elements.registerPassword.value || "";
  const score = passwordStrengthScore(password);
  const width = [8, 32, 58, 82, 100][score];
  const labels = [
    "Use 8+ characters with upper, lower, number, and special character.",
    "Very weak password.",
    "Weak password. Add more variety.",
    "Decent password. Add a little more length.",
    "Strong password.",
    "Very strong password."
  ];

  elements.passwordMeterFill.style.width = `${width}%`;
  elements.passwordMeterFill.className = `password-meter-fill strength-${score}`;
  elements.passwordStrengthLabel.textContent = labels[score];
}

function passwordStrengthScore(password) {
  let score = 0;
  if (password.length >= 8) score += 1;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[^A-Za-z\d]/.test(password)) score += 1;
  if (password.length >= 12) score += 1;
  return score;
}

function populateSettingsForm() {
  elements.displayNameInput.value = state.settings.displayName;
  elements.settingsThreatFilter.value = state.settings.defaultThreatFilter;
  elements.settingsTimelineLength.value = String(state.settings.timelineLength);
  elements.settingsDashboardRange.value = String(state.settings.dashboardRangeDays);
  elements.settingsDisposableOnly.checked = state.settings.disposableOnly;
}

function readSettingsForm() {
  return {
    displayName: elements.displayNameInput.value.trim(),
    defaultThreatFilter: elements.settingsThreatFilter.value,
    timelineLength: Number(elements.settingsTimelineLength.value),
    dashboardRangeDays: Number(elements.settingsDashboardRange.value),
    disposableOnly: elements.settingsDisposableOnly.checked
  };
}

function applySettingsToFilters() {
  elements.threatFilter.value = state.settings.defaultThreatFilter;
  elements.disposableOnly.checked = state.settings.disposableOnly;
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

function normalizeHistoryList(records) {
  if (!Array.isArray(records)) {
    return [];
  }

  const deduped = new Map();

  for (const record of records) {
    const normalized = {
      id: String(record.id || createRecordId()).slice(0, 120),
      type: ["url", "email", "combined"].includes(record.type) ? record.type : "url",
      target: String(record.target || "").trim().slice(0, 320),
      domain: String(record.domain || "").trim().slice(0, 120),
      threatLevel: ["safe", "suspicious", "dangerous"].includes(record.threatLevel)
        ? record.threatLevel
        : "safe",
      threatScore: clampNumber(record.threatScore, 0, 100, 0),
      disposable: Boolean(record.disposable),
      summary: String(record.summary || "").trim().slice(0, 240),
      timestamp: normalizeTimestamp(record.timestamp)
    };

    if (!normalized.target || !normalized.summary) {
      continue;
    }

    deduped.set(normalized.id, normalized);
  }

  return [...deduped.values()]
    .sort((left, right) => new Date(right.timestamp) - new Date(left.timestamp))
    .slice(0, HISTORY_LIMIT);
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

function scheduleHistoryRender() {
  window.clearTimeout(state.historyRenderTimeout);
  state.historyRenderTimeout = window.setTimeout(() => {
    renderHistoryTable();
  }, SEARCH_DEBOUNCE_MS);
}

function ensureAuthenticated() {
  if (state.user && state.accessToken) {
    return true;
  }

  navigateTo("/login", { replace: true });
  showAuthAlert("Sign in to access the protected workspace.");
  return false;
}

function navigateTo(path, options = {}) {
  if (window.location.pathname !== path) {
    window.history[options.replace ? "replaceState" : "pushState"]({}, "", path);
  }
  state.routePath = path;
  renderRoute();
}

function viewFromPath(pathname) {
  switch (pathname) {
    case "/register":
      return "register";
    case "/forgot-password":
      return "forgot";
    case "/reset-password":
      return "reset";
    case "/verify-email":
      return "login";
    case "/login":
    default:
      return "login";
  }
}

function authPathForView(view) {
  switch (view) {
    case "register":
      return "/register";
    case "forgot":
      return "/forgot-password";
    case "reset":
      return "/reset-password";
    case "login":
    default:
      return "/login";
  }
}

function isProtectedPath(pathname) {
  return pathname === "/" || pathname === "/app" || pathname === "/profile";
}

function isPublicPath(pathname) {
  return pathname === "/login" || pathname === "/register" || pathname === "/forgot-password" || pathname === "/reset-password" || pathname === "/verify-email";
}

function isVerificationRoute() {
  return window.location.pathname === "/verify-email";
}

function readRouteToken(name) {
  return new URLSearchParams(window.location.search).get(name) || "";
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

  while (elements.toastHost.childElementCount > 4) {
    elements.toastHost.firstElementChild?.remove();
  }

  window.setTimeout(() => toast.remove(), 3600);
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

function safeHostname(value) {
  try {
    return new URL(value).hostname;
  } catch (error) {
    return value;
  }
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
  if (!Number.isFinite(numeric)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, numeric));
}

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT_DIR = __dirname;
const PUBLIC_DIR = path.join(ROOT_DIR, "public");
const DATA_DIR = path.join(ROOT_DIR, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const PROFILES_DIR = path.join(DATA_DIR, "profiles");

loadEnvFile(path.join(ROOT_DIR, ".env"));

const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 3000);
const STATIC_CACHE_CONTROL = "public, max-age=0, must-revalidate";
const SESSION_COOKIE_NAME = "phishguard_session";
const SESSION_TTL_DAYS = Number.isFinite(Number(process.env.SESSION_TTL_DAYS))
  ? Math.min(90, Math.max(1, Number(process.env.SESSION_TTL_DAYS)))
  : 14;
const SESSION_TTL_MS = SESSION_TTL_DAYS * 24 * 60 * 60 * 1000;
const SESSION_SECRET =
  process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const PASSWORD_MIN_LENGTH = 10;
const HISTORY_LIMIT = 150;
const SCAN_CACHE_TTL_MS = {
  url: 10 * 60 * 1000,
  email: 10 * 60 * 1000
};
const DEFAULT_SETTINGS = Object.freeze({
  displayName: "",
  defaultThreatFilter: "all",
  timelineLength: 6,
  dashboardRangeDays: 14,
  disposableOnly: false
});
const MIME_TYPES = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".txt": "text/plain; charset=utf-8"
};
const RISK_RANK = {
  safe: 1,
  suspicious: 2,
  dangerous: 3
};
const AUTH_THREAT_FILTERS = new Set(["all", "safe", "suspicious", "dangerous"]);
const HISTORY_TYPES = new Set(["url", "email", "combined"]);
const scanCache = new Map();
const inFlightScans = new Map();
const staticAssetCache = new Map();

ensureDataStore();

if (!process.env.SESSION_SECRET) {
  console.warn(
    "SESSION_SECRET is not set. Authentication will work, but active sessions reset when the server restarts."
  );
}

class AppError extends Error {
  constructor(statusCode, message, details = {}) {
    super(message);
    this.statusCode = statusCode;
    this.details = details;
  }
}

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) {
    return;
  }

  const contents = fs.readFileSync(filePath, "utf8");
  const lines = contents.split(/\r?\n/);

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    const separatorIndex = trimmed.indexOf("=");
    if (separatorIndex === -1) {
      continue;
    }

    const key = trimmed.slice(0, separatorIndex).trim();
    let value = trimmed.slice(separatorIndex + 1).trim();

    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    if (!Object.prototype.hasOwnProperty.call(process.env, key)) {
      process.env[key] = value;
    }
  }
}

function ensureDataStore() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.mkdirSync(PROFILES_DIR, { recursive: true });

  if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, JSON.stringify({ users: [] }, null, 2));
  }
}

function readJsonFile(filePath, fallbackValue) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (error) {
    return fallbackValue;
  }
}

function writeJsonFile(filePath, value) {
  const tempPath = `${filePath}.tmp`;
  fs.writeFileSync(tempPath, JSON.stringify(value, null, 2));
  fs.renameSync(tempPath, filePath);
}

function readUsers() {
  const payload = readJsonFile(USERS_FILE, { users: [] });
  const users = Array.isArray(payload) ? payload : payload.users;
  return Array.isArray(users) ? users : [];
}

function writeUsers(users) {
  writeJsonFile(USERS_FILE, { users });
}

function profilePath(userId) {
  return path.join(PROFILES_DIR, `${userId}.json`);
}

function normalizeSettings(input = {}) {
  return {
    displayName: String(input.displayName || "").trim().slice(0, 60),
    defaultThreatFilter: AUTH_THREAT_FILTERS.has(input.defaultThreatFilter)
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

function normalizeHistoryRecord(record = {}) {
  const threatLevel = Object.prototype.hasOwnProperty.call(RISK_RANK, record.threatLevel)
    ? record.threatLevel
    : "safe";
  const type = HISTORY_TYPES.has(record.type) ? record.type : "url";
  const timestamp = new Date(record.timestamp || Date.now());

  return {
    id:
      typeof record.id === "string" && record.id.trim()
        ? record.id.trim().slice(0, 120)
        : crypto.randomUUID(),
    type,
    target: String(record.target || "").trim().slice(0, 320),
    domain: String(record.domain || "").trim().slice(0, 120),
    threatLevel,
    threatScore: clampNumber(record.threatScore, 0, 100, 0),
    disposable: Boolean(record.disposable),
    summary: String(record.summary || "").trim().slice(0, 240),
    timestamp: Number.isNaN(timestamp.getTime()) ? new Date().toISOString() : timestamp.toISOString()
  };
}

function normalizeHistory(records) {
  if (!Array.isArray(records)) {
    return [];
  }

  const deduped = new Map();

  for (const item of records) {
    const record = normalizeHistoryRecord(item);
    if (!record.target || !record.summary) {
      continue;
    }
    deduped.set(record.id, record);
  }

  return [...deduped.values()]
    .sort((left, right) => new Date(right.timestamp) - new Date(left.timestamp))
    .slice(0, HISTORY_LIMIT);
}

function readUserProfile(userId) {
  const payload = readJsonFile(profilePath(userId), null);

  if (!payload) {
    return {
      settings: normalizeSettings(DEFAULT_SETTINGS),
      history: []
    };
  }

  return {
    settings: normalizeSettings(payload.settings || DEFAULT_SETTINGS),
    history: normalizeHistory(payload.history)
  };
}

function writeUserProfile(userId, profile) {
  writeJsonFile(profilePath(userId), {
    settings: normalizeSettings(profile.settings),
    history: normalizeHistory(profile.history)
  });
}

function mergeHistory(existing, incoming) {
  return normalizeHistory([...(incoming || []), ...(existing || [])]);
}

function setJsonHeaders(extraHeaders = {}) {
  return {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...extraHeaders
  };
}

function sendJson(res, statusCode, payload, headers = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, setJsonHeaders(headers));
  res.end(body);
}

function sendText(res, statusCode, payload, contentType = "text/plain; charset=utf-8", headers = {}) {
  res.writeHead(statusCode, {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
    ...headers
  });
  res.end(payload);
}

async function readJsonBody(req) {
  const chunks = [];
  let totalSize = 0;

  for await (const chunk of req) {
    totalSize += chunk.length;
    if (totalSize > 1024 * 1024) {
      throw new AppError(413, "Request body is too large.");
    }
    chunks.push(chunk);
  }

  const raw = Buffer.concat(chunks).toString("utf8").trim();
  if (!raw) {
    return {};
  }

  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new AppError(400, "Invalid JSON body.");
  }
}

function validateUrl(value) {
  try {
    const parsed = new URL(String(value || "").trim());
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return null;
    }
    return parsed.toString();
  } catch (error) {
    return null;
  }
}

function validateEmail(value) {
  const normalized = String(value || "").trim().toLowerCase();
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(normalized) ? normalized : null;
}

function validatePassword(password) {
  const normalized = String(password || "");
  if (normalized.length < PASSWORD_MIN_LENGTH) {
    throw new AppError(400, `Password must be at least ${PASSWORD_MIN_LENGTH} characters long.`);
  }
  return normalized;
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function clampNumber(value, min, max, fallback) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return fallback;
  }
  return clamp(numeric, min, max);
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function clonePayload(payload) {
  if (typeof structuredClone === "function") {
    return structuredClone(payload);
  }

  return JSON.parse(JSON.stringify(payload));
}

function pruneExpiredEntries(store) {
  const now = Date.now();

  for (const [key, entry] of store.entries()) {
    if (entry.expiresAt <= now) {
      store.delete(key);
    }
  }
}

async function withCache(cacheKey, ttlMs, resolver) {
  pruneExpiredEntries(scanCache);

  const cachedEntry = scanCache.get(cacheKey);
  if (cachedEntry && cachedEntry.expiresAt > Date.now()) {
    return clonePayload(cachedEntry.value);
  }

  if (inFlightScans.has(cacheKey)) {
    return clonePayload(await inFlightScans.get(cacheKey));
  }

  const task = (async () => {
    const value = await resolver();
    scanCache.set(cacheKey, {
      value,
      expiresAt: Date.now() + ttlMs
    });
    return value;
  })();

  inFlightScans.set(cacheKey, task);

  try {
    return clonePayload(await task);
  } finally {
    inFlightScans.delete(cacheKey);
  }
}

function severityFromScore(score) {
  if (score >= 70) {
    return "dangerous";
  }
  if (score >= 30) {
    return "suspicious";
  }
  return "safe";
}

function trustToThreatLevel(score) {
  if (score < 40) {
    return "dangerous";
  }
  if (score < 70) {
    return "suspicious";
  }
  return "safe";
}

function compareThreatLevels(left, right) {
  return RISK_RANK[left] >= RISK_RANK[right] ? left : right;
}

function mapNetworkError(error) {
  if (error instanceof AppError) {
    return error;
  }

  if (error instanceof TypeError) {
    return new AppError(502, "Unable to connect. Check your internet connection.");
  }

  return new AppError(500, "Unexpected server error.");
}

function base64UrlEncode(value) {
  return Buffer.from(value, "utf8").toString("base64url");
}

function base64UrlDecode(value) {
  return Buffer.from(value, "base64url").toString("utf8");
}

function signSessionPayload(payload) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("base64url");
}

function createSessionToken(userId) {
  const payload = base64UrlEncode(
    JSON.stringify({
      userId,
      expiresAt: Date.now() + SESSION_TTL_MS,
      nonce: crypto.randomBytes(12).toString("hex")
    })
  );
  return `${payload}.${signSessionPayload(payload)}`;
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const cookies = {};

  for (const chunk of header.split(";")) {
    const [key, ...rest] = chunk.trim().split("=");
    if (!key) {
      continue;
    }
    try {
      cookies[key] = decodeURIComponent(rest.join("="));
    } catch (error) {
      cookies[key] = rest.join("=");
    }
  }

  return cookies;
}

function verifySessionToken(token) {
  if (typeof token !== "string" || !token.includes(".")) {
    return null;
  }

  const [payload, signature] = token.split(".");
  const expectedSignature = signSessionPayload(payload);
  const signatureBuffer = Buffer.from(signature || "", "utf8");
  const expectedBuffer = Buffer.from(expectedSignature, "utf8");

  if (
    signatureBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(signatureBuffer, expectedBuffer)
  ) {
    return null;
  }

  try {
    const parsed = JSON.parse(base64UrlDecode(payload));
    if (!parsed?.userId || Number(parsed.expiresAt) < Date.now()) {
      return null;
    }
    return parsed;
  } catch (error) {
    return null;
  }
}

function sessionCookie(token) {
  const maxAgeSeconds = Math.floor(SESSION_TTL_MS / 1000);
  return `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}`;
}

function clearSessionCookie() {
  return `${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
}

function findUserByEmail(email) {
  return readUsers().find((user) => user.email === email) || null;
}

function findUserById(userId) {
  return readUsers().find((user) => user.id === userId) || null;
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const iterations = 210000;
  const hash = crypto.pbkdf2Sync(password, salt, iterations, 32, "sha256").toString("hex");
  return `pbkdf2$${iterations}$${salt}$${hash}`;
}

function verifyPassword(password, encodedHash) {
  const [scheme, iterations, salt, digest] = String(encodedHash || "").split("$");
  if (scheme !== "pbkdf2" || !iterations || !salt || !digest) {
    return false;
  }

  const computed = crypto
    .pbkdf2Sync(password, salt, Number(iterations), 32, "sha256")
    .toString("hex");

  const left = Buffer.from(computed, "utf8");
  const right = Buffer.from(digest, "utf8");

  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function safeUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    createdAt: user.createdAt,
    lastLoginAt: user.lastLoginAt || null
  };
}

function buildWorkspacePayload(user) {
  const profile = readUserProfile(user.id);
  return {
    authenticated: true,
    user: safeUser(user),
    settings: profile.settings,
    history: profile.history
  };
}

function requireAuthenticatedUser(req) {
  const cookies = parseCookies(req);
  const parsedSession = verifySessionToken(cookies[SESSION_COOKIE_NAME]);

  if (!parsedSession) {
    throw new AppError(401, "Please sign in to continue.");
  }

  const user = findUserById(parsedSession.userId);
  if (!user) {
    throw new AppError(401, "Session expired. Please sign in again.");
  }

  return user;
}

async function fetchJson(url, options = {}) {
  let response;

  try {
    response = await fetch(url, options);
  } catch (error) {
    throw mapNetworkError(error);
  }

  if (response.status === 204 || response.status === 429) {
    throw new AppError(429, "Rate limit reached. Try again in 1 minute.");
  }

  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json")
    ? await response.json().catch(() => ({}))
    : await response.text().catch(() => "");

  if (!response.ok) {
    const message =
      typeof payload === "object"
        ? payload?.error?.message || payload?.message || "Upstream API request failed."
        : String(payload || "Upstream API request failed.");
    throw new AppError(response.status, message);
  }

  return payload;
}

function vtHeaders() {
  if (!process.env.VIRUSTOTAL_API_KEY) {
    throw new AppError(
      503,
      "VirusTotal API key is missing. Add VIRUSTOTAL_API_KEY to your .env file."
    );
  }

  return {
    "x-apikey": process.env.VIRUSTOTAL_API_KEY
  };
}

async function analyzeUrl(targetUrl) {
  const cachedResult = await withCache(`url:${targetUrl}`, SCAN_CACHE_TTL_MS.url, async () => {
    const submitResponse = await fetchJson("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        ...vtHeaders(),
        "content-type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({ url: targetUrl }).toString()
    });

    const analysisId = submitResponse?.data?.id;
    if (!analysisId) {
      throw new AppError(502, "VirusTotal did not return an analysis identifier.");
    }

    let analysisPayload = null;
    for (let attempt = 0; attempt < 5; attempt += 1) {
      if (attempt > 0) {
        await delay(1200);
      }

      analysisPayload = await fetchJson(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
        { headers: vtHeaders() }
      );

      if (analysisPayload?.data?.attributes?.status === "completed") {
        break;
      }
    }

    const attributes = analysisPayload?.data?.attributes || {};
    const stats = attributes.stats || {};
    const detections = Object.entries(attributes.results || {})
      .map(([vendor, result]) => {
        const category = result?.category || "";
        return {
          vendor,
          category,
          result: result?.result || category || "no verdict",
          detected: category === "malicious" || category === "suspicious",
          method: result?.method || "unknown"
        };
      })
      .sort((left, right) => {
        if (Number(right.detected) !== Number(left.detected)) {
          return Number(right.detected) - Number(left.detected);
        }
        return left.vendor.localeCompare(right.vendor);
      });

    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    const harmless = Number(stats.harmless || 0);
    const undetected = Number(stats.undetected || 0);
    const positives = malicious + suspicious;
    const total = malicious + suspicious + harmless + undetected || detections.length;
    const threatScore = clamp(total ? Math.round((positives / total) * 100) : 0, 0, 100);
    const status = attributes.status === "completed" ? "completed" : "pending";
    const threatLevel = status === "pending" ? "suspicious" : severityFromScore(threatScore);
    const topFindings = detections
      .filter((item) => item.detected)
      .slice(0, 5)
      .map((item) => `${item.vendor}: ${item.result}`);

    return {
      type: "url",
      target: targetUrl,
      status,
      positives,
      total,
      threatScore,
      threatLevel,
      stats: {
        malicious,
        suspicious,
        harmless,
        undetected
      },
      detections,
      highlights: topFindings,
      summary:
        status === "pending"
          ? "VirusTotal accepted the URL and is still processing the analysis."
          : positives > 0
            ? `${positives} of ${total} vendors flagged this URL.`
            : `No vendor flagged this URL out of ${total} checks.`
    };
  });

  return {
    ...cachedResult,
    scannedAt: new Date().toISOString()
  };
}

async function checkDisify(email) {
  const payload = await fetchJson(`https://api.disify.com/check/${encodeURIComponent(email)}`);
  return {
    domain: payload?.domain || email.split("@")[1],
    disposable: Boolean(payload?.disposable),
    dns: payload?.dns !== false,
    format: payload?.format !== false
  };
}

async function validateWithAbstract(email) {
  if (!process.env.ABSTRACT_API_KEY) {
    return null;
  }

  const params = new URLSearchParams({
    api_key: process.env.ABSTRACT_API_KEY,
    email
  });
  const payload = await fetchJson(`https://emailvalidation.abstractapi.com/v1/?${params.toString()}`);

  return {
    deliverability: payload?.deliverability || "UNKNOWN",
    qualityScore:
      typeof payload?.quality_score === "number"
        ? payload.quality_score
        : Number(payload?.quality_score || NaN),
    isValidFormat: payload?.is_valid_format?.value !== false,
    isDisposableEmail: payload?.is_disposable_email?.value === true
  };
}

function computeEmailHeuristics(email) {
  const [localPart = "", domain = ""] = email.split("@");
  const signals = [];
  let penalty = 0;

  if (/(verify|billing|security|support|payroll|admin|invoice)/i.test(localPart)) {
    signals.push("Sender username uses a high-risk impersonation keyword.");
    penalty += 10;
  }

  if ((localPart.match(/\d/g) || []).length >= 4) {
    signals.push("Sender username contains multiple digits, which is common in throwaway aliases.");
    penalty += 8;
  }

  if (domain.startsWith("xn--")) {
    signals.push("Sender domain uses punycode and should be inspected for lookalike risk.");
    penalty += 20;
  }

  if ((domain.match(/-/g) || []).length >= 3) {
    signals.push("Sender domain contains several hyphens, which can indicate a fabricated brand domain.");
    penalty += 8;
  }

  return { signals, penalty };
}

async function analyzeEmail(senderEmail) {
  const cachedResult = await withCache(
    `email:${senderEmail}`,
    SCAN_CACHE_TTL_MS.email,
    async () => {
      const fallbackDomain = senderEmail.split("@")[1] || "";
      const hasAbstractKey = Boolean(process.env.ABSTRACT_API_KEY);
      const [disifyResponse, abstractResponse] = await Promise.allSettled([
        checkDisify(senderEmail),
        validateWithAbstract(senderEmail)
      ]);
      const hasDisifyResult = disifyResponse.status === "fulfilled";
      const hasAbstractResult =
        abstractResponse.status === "fulfilled" && Boolean(abstractResponse.value);

      const disifyResult =
        hasDisifyResult
          ? disifyResponse.value
          : {
              domain: fallbackDomain,
              disposable: false,
              dns: true,
              format: true
            };
      const abstractResult =
        abstractResponse.status === "fulfilled" ? abstractResponse.value : null;
      const heuristicResult = computeEmailHeuristics(senderEmail);
      const flags = [];
      let trustScore = 100;
      let summary = "No strong phishing indicators were found for this sender address.";

      if (!hasDisifyResult) {
        flags.push("Disify checks are temporarily unavailable, so sender validation is using other signals.");
      }

      if (abstractResponse.status === "rejected") {
        flags.push(
          "Abstract deliverability checks are temporarily unavailable, so the result is based on the remaining checks."
        );
      } else if (!hasAbstractKey) {
        flags.push(
          "Abstract deliverability checks are unavailable until ABSTRACT_API_KEY is configured."
        );
      }

      if (!disifyResult.format) {
        flags.push("Email format is invalid.");
        trustScore -= 35;
      }

      if (!disifyResult.dns) {
        flags.push("Sender domain has no healthy DNS response.");
        trustScore -= 25;
      }

      if (disifyResult.disposable) {
        flags.push("Disposable inbox provider detected.");
        trustScore -= 55;
      }

      if (abstractResult) {
        if (!abstractResult.isValidFormat) {
          flags.push("Abstract API marked the address format as invalid.");
          trustScore -= 40;
        }

        if (abstractResult.isDisposableEmail) {
          flags.push("Abstract API marked the address as disposable.");
          trustScore -= 35;
        }

        if (abstractResult.deliverability === "UNDELIVERABLE") {
          flags.push("Mailbox is marked undeliverable.");
          trustScore -= 35;
        } else if (abstractResult.deliverability === "RISKY") {
          flags.push("Mailbox deliverability is risky.");
          trustScore -= 18;
        }

        if (!Number.isNaN(abstractResult.qualityScore)) {
          trustScore = Math.round((trustScore + abstractResult.qualityScore * 100) / 2);
        }
      }

      for (const signal of heuristicResult.signals) {
        flags.push(signal);
      }
      trustScore -= heuristicResult.penalty;

      trustScore = clamp(trustScore, 0, 100);
      const threatLevel = trustToThreatLevel(trustScore);
      const disposable = disifyResult.disposable || Boolean(abstractResult?.isDisposableEmail);
      const providerChecksUnavailable = !hasDisifyResult || !hasAbstractResult;

      if (threatLevel === "dangerous") {
        summary = "The sender address shows multiple phishing indicators.";
      } else if (threatLevel === "suspicious") {
        summary = "The sender address needs extra verification before you trust it.";
      } else if (!hasDisifyResult && !hasAbstractResult) {
        summary =
          "Live email validation services are limited right now, so this result uses local sender heuristics only.";
      } else if (providerChecksUnavailable) {
        summary =
          "No strong phishing indicators were found, but some live validation checks are currently unavailable.";
      }

      return {
        type: "email",
        target: senderEmail,
        domain: disifyResult.domain,
        trustScore,
        threatLevel,
        disposable,
        flags,
        summary,
        checks: {
          disify: disifyResult,
          abstract: abstractResult
        }
      };
    }
  );

  return {
    ...cachedResult,
    scannedAt: new Date().toISOString()
  };
}

async function analyzeCombined(url, email) {
  const [urlResult, emailResult] = await Promise.all([analyzeUrl(url), analyzeEmail(email)]);
  const overallThreatLevel = compareThreatLevels(urlResult.threatLevel, emailResult.threatLevel);
  const overallThreatScore = Math.max(urlResult.threatScore, 100 - emailResult.trustScore);

  return {
    type: "combined",
    scannedAt: new Date().toISOString(),
    threatLevel: overallThreatLevel,
    threatScore: overallThreatScore,
    summary: `Combined scan completed for ${emailResult.domain} and ${new URL(url).hostname}.`,
    url: urlResult,
    email: emailResult
  };
}

async function serveStaticAsset(req, res, pathname) {
  const requestedPath = pathname === "/" ? "/index.html" : pathname;
  const safePath = path.normalize(requestedPath).replace(/^(\.\.[/\\])+/, "");
  const filePath = path.join(PUBLIC_DIR, safePath);

  if (!filePath.startsWith(PUBLIC_DIR)) {
    throw new AppError(403, "Access denied.");
  }

  try {
    const stats = await fs.promises.stat(filePath);
    const extension = path.extname(filePath).toLowerCase();
    const etag = `W/"${stats.size}-${Math.trunc(stats.mtimeMs)}"`;
    let cachedAsset = staticAssetCache.get(filePath);

    if (!cachedAsset || cachedAsset.etag !== etag) {
      cachedAsset = {
        body: await fs.promises.readFile(filePath),
        etag,
        contentType: MIME_TYPES[extension] || "application/octet-stream"
      };
      staticAssetCache.set(filePath, cachedAsset);
    }

    if (req.headers["if-none-match"] === cachedAsset.etag) {
      res.writeHead(304, {
        ETag: cachedAsset.etag,
        "Cache-Control": STATIC_CACHE_CONTROL
      });
      res.end();
      return;
    }

    res.writeHead(200, {
      "Content-Type": cachedAsset.contentType,
      "Cache-Control": STATIC_CACHE_CONTROL,
      ETag: cachedAsset.etag
    });
    res.end(cachedAsset.body);
  } catch (error) {
    if (error.code === "ENOENT") {
      throw new AppError(404, "Not found.");
    }
    throw error;
  }
}

function createUser(body) {
  const email = validateEmail(body.email);
  const password = validatePassword(body.password);
  const name = String(body.name || "").trim().slice(0, 60);

  if (!name) {
    throw new AppError(400, "Please provide a display name.");
  }

  if (!email) {
    throw new AppError(400, "Please enter a valid email address.");
  }

  if (findUserByEmail(email)) {
    throw new AppError(409, "An account already exists for this email.");
  }

  const now = new Date().toISOString();
  const user = {
    id: crypto.randomUUID(),
    name,
    email,
    passwordHash: hashPassword(password),
    createdAt: now,
    lastLoginAt: now
  };

  const users = readUsers();
  users.push(user);
  writeUsers(users);
  writeUserProfile(user.id, {
    settings: DEFAULT_SETTINGS,
    history: []
  });

  return user;
}

function loginUser(body) {
  const email = validateEmail(body.email);
  const password = String(body.password || "");

  if (!email) {
    throw new AppError(400, "Please enter a valid email address.");
  }

  const users = readUsers();
  const user = users.find((entry) => entry.email === email);

  if (!user || !verifyPassword(password, user.passwordHash)) {
    throw new AppError(401, "Email or password is incorrect.");
  }

  user.lastLoginAt = new Date().toISOString();
  writeUsers(users);
  return user;
}

async function handleApiRequest(req, res, pathname) {
  if (req.method === "GET" && pathname === "/health") {
    return sendJson(res, 200, {
      status: "ok",
      service: "phishguard",
      timestamp: new Date().toISOString()
    });
  }

  if (req.method === "GET" && pathname === "/api/session") {
    try {
      const user = requireAuthenticatedUser(req);
      return sendJson(res, 200, buildWorkspacePayload(user));
    } catch (error) {
      if (error instanceof AppError && error.statusCode === 401) {
        return sendJson(res, 200, {
          authenticated: false,
          settings: normalizeSettings(DEFAULT_SETTINGS),
          history: []
        });
      }
      throw error;
    }
  }

  if (req.method !== "POST") {
    throw new AppError(405, "Method not allowed.");
  }

  const body = await readJsonBody(req);

  if (pathname === "/api/auth/register") {
    const user = createUser(body);
    return sendJson(res, 201, buildWorkspacePayload(user), {
      "Set-Cookie": sessionCookie(createSessionToken(user.id))
    });
  }

  if (pathname === "/api/auth/login") {
    const user = loginUser(body);
    return sendJson(res, 200, buildWorkspacePayload(user), {
      "Set-Cookie": sessionCookie(createSessionToken(user.id))
    });
  }

  if (pathname === "/api/auth/logout") {
    return sendJson(
      res,
      200,
      { ok: true },
      {
        "Set-Cookie": clearSessionCookie()
      }
    );
  }

  if (pathname === "/api/settings") {
    const user = requireAuthenticatedUser(req);
    const profile = readUserProfile(user.id);
    profile.settings = normalizeSettings(body);
    writeUserProfile(user.id, profile);
    return sendJson(res, 200, {
      ok: true,
      settings: profile.settings
    });
  }

  if (pathname === "/api/history/sync") {
    const user = requireAuthenticatedUser(req);
    const profile = readUserProfile(user.id);
    profile.history = mergeHistory(profile.history, body.records);
    writeUserProfile(user.id, profile);
    return sendJson(res, 200, {
      ok: true,
      history: profile.history
    });
  }

  if (pathname === "/api/history/append") {
    const user = requireAuthenticatedUser(req);
    const profile = readUserProfile(user.id);
    profile.history = mergeHistory(profile.history, [body.record]);
    writeUserProfile(user.id, profile);
    return sendJson(res, 200, {
      ok: true,
      history: profile.history
    });
  }

  if (pathname === "/api/history/clear") {
    const user = requireAuthenticatedUser(req);
    const profile = readUserProfile(user.id);
    profile.history = [];
    writeUserProfile(user.id, profile);
    return sendJson(res, 200, {
      ok: true,
      history: []
    });
  }

  if (pathname === "/api/scan/url") {
    const targetUrl = validateUrl(body.url);
    if (!targetUrl) {
      throw new AppError(400, "Please enter a valid URL.");
    }
    return sendJson(res, 200, await analyzeUrl(targetUrl));
  }

  if (pathname === "/api/scan/email") {
    const senderEmail = validateEmail(body.email);
    if (!senderEmail) {
      throw new AppError(400, "Please enter a valid email address.");
    }
    return sendJson(res, 200, await analyzeEmail(senderEmail));
  }

  if (pathname === "/api/scan/combined") {
    const targetUrl = validateUrl(body.url);
    const senderEmail = validateEmail(body.email);

    if (!targetUrl) {
      throw new AppError(400, "Please enter a valid URL.");
    }
    if (!senderEmail) {
      throw new AppError(400, "Please enter a valid email address.");
    }

    return sendJson(res, 200, await analyzeCombined(targetUrl, senderEmail));
  }

  throw new AppError(404, "API route not found.");
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  try {
    if (url.pathname === "/health" || url.pathname.startsWith("/api/")) {
      await handleApiRequest(req, res, url.pathname);
      return;
    }

    await serveStaticAsset(req, res, url.pathname);
  } catch (error) {
    const mappedError = mapNetworkError(error);
    sendJson(res, mappedError.statusCode || 500, {
      error: mappedError.message,
      details: mappedError.details || {}
    });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`PhishGuard is running on http://${HOST}:${PORT}`);
});

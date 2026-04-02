const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const validator = require("validator");

const { ROOT_DIR } = require("./config");
const { AppError } = require("./errors");
const { DEFAULT_SETTINGS } = require("./repositories/postgresRepository");
const { createScanService } = require("./scanService");

const PUBLIC_DIR = path.join(ROOT_DIR, "public");
const INDEX_FILE = path.join(PUBLIC_DIR, "index.html");
const REFRESH_COOKIE_NAME = "phishguard_refresh_token";
const CSRF_COOKIE_NAME = "phishguard_csrf_token";
const PUBLIC_PAGE_ROUTES = new Set([
  "/login",
  "/register",
  "/forgot-password",
  "/reset-password",
  "/verify-email"
]);
const PROTECTED_PAGE_ROUTES = new Set(["/", "/app", "/profile"]);
const PASSWORD_COMPLEXITY_REGEX =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,}$/;
const DUMMY_PASSWORD_HASH = bcrypt.hashSync("PhishGuardDummyPassword!23", 12);
const { ipKeyGenerator } = rateLimit;

function createApp({ config, repository, emailService }) {
  const app = express();
  const scanService = createScanService({
    virusTotalApiKey: process.env.VIRUSTOTAL_API_KEY || "",
    abstractApiKey: process.env.ABSTRACT_API_KEY || ""
  });

  app.disable("x-powered-by");
  app.set("trust proxy", 1);

  app.use(enforceHttps(config));
  app.use(
    cors({
      credentials: true,
      origin(origin, callback) {
        if (!origin || origin === config.frontendUrl) {
          callback(null, true);
          return;
        }
        callback(new AppError(403, "Origin is not allowed."));
      }
    })
  );
  app.use(
    helmet({
      contentSecurityPolicy: false
    })
  );
  app.use(express.json({ limit: "1mb" }));
  app.use(cookieParser());
  app.use(express.static(PUBLIC_DIR, { index: false }));

  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    handler() {
      throw new AppError(429, "Too many authentication attempts. Please try again later.");
    }
  });

  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator(req) {
      return `${ipKeyGenerator(req.ip)}:${String(req.body?.email || "").toLowerCase()}`;
    },
    handler(req) {
      console.warn(`[SECURITY] Login rate limit exceeded for ${req.ip}`);
      throw new AppError(429, "Too many login attempts. Please wait 15 minutes and try again.");
    }
  });

  app.get("/health", (_req, res) => {
    res.json({
      status: "ok",
      service: "phishguard",
      timestamp: new Date().toISOString()
    });
  });

  app.get("/api/auth/csrf", (req, res) => {
    const csrfToken = ensureCsrfCookie(req, res, config);
    res.json({ csrfToken });
  });

  app.post("/api/auth/register", authLimiter, requireCsrfToken, async (req, res) => {
    const payload = sanitizeRegistrationPayload(req.body);
    const existingUser = await repository.findUserByEmail(payload.email);

    if (existingUser) {
      throw new AppError(409, "An account with that email already exists.");
    }

    const verificationToken = crypto.randomBytes(32).toString("hex");
    const user = await repository.createUser({
      id: crypto.randomUUID(),
      email: payload.email,
      passwordHash: await bcrypt.hash(payload.password, config.bcryptRounds),
      firstName: payload.firstName,
      lastName: payload.lastName,
      isVerified: false,
      verificationTokenHash: hashToken(verificationToken),
      verificationTokenExpires: new Date(Date.now() + config.verificationTokenTtlMs).toISOString()
    });

    await emailService.sendVerificationEmail(user.email, verificationToken);

    res.status(201).json({
      message: "Registration successful. Check your email to verify your account."
    });
  });

  app.post("/api/auth/verify-email", authLimiter, requireCsrfToken, async (req, res) => {
    const token = sanitizeOpaqueToken(req.body.token, "verification token");
    const user = await repository.findUserByVerificationTokenHash(hashToken(token));

    if (!user || !user.verificationTokenExpires || new Date(user.verificationTokenExpires) < new Date()) {
      throw new AppError(400, "Verification link is invalid or has expired.");
    }

    await repository.markUserVerified(user.id);

    res.json({
      message: "Your email has been verified. You can sign in now."
    });
  });

  app.post("/api/auth/login", authLimiter, loginLimiter, requireCsrfToken, async (req, res) => {
    const payload = sanitizeLoginPayload(req.body);
    const user = await repository.findUserByEmail(payload.email);
    const passwordHash = user?.passwordHash || DUMMY_PASSWORD_HASH;
    const passwordMatches = await bcrypt.compare(payload.password, passwordHash);

    if (!user || !passwordMatches) {
      console.warn(`[SECURITY] Failed login for ${payload.email} from ${req.ip}`);
      throw new AppError(401, "Invalid email or password.");
    }

    if (!user.isVerified) {
      throw new AppError(403, "Verify your email before signing in.");
    }

    const sessionPayload = await issueSession({
      repository,
      config,
      req,
      res,
      user,
      rememberMe: payload.rememberMe
    });

    res.json(sessionPayload);
  });

  app.post("/api/auth/refresh", authLimiter, requireCsrfToken, async (req, res) => {
    const refreshToken = req.cookies[REFRESH_COOKIE_NAME];
    if (!refreshToken) {
      throw new AppError(401, "Refresh token is missing.");
    }

    const session = await validateRefreshToken({
      repository,
      config,
      token: refreshToken
    });

    await repository.revokeRefreshToken(session.tokenRecord.id, null);

    const user = await repository.findUserById(session.user.id);
    const sessionPayload = await issueSession({
      repository,
      config,
      req,
      res,
      user,
      rememberMe: Boolean(session.tokenRecord.rememberMe)
    });

    res.json(sessionPayload);
  });

  app.post("/api/auth/logout", authLimiter, requireCsrfToken, async (req, res) => {
    const refreshToken = req.cookies[REFRESH_COOKIE_NAME];
    if (refreshToken) {
      try {
        const session = await validateRefreshToken({
          repository,
          config,
          token: refreshToken
        });
        await repository.revokeRefreshToken(session.tokenRecord.id, null);
      } catch (error) {
        if (!(error instanceof AppError && error.statusCode === 401)) {
          throw error;
        }
      }
    }

    clearRefreshCookie(res, config);
    res.json({ message: "Signed out successfully." });
  });

  app.post("/api/auth/forgot-password", authLimiter, requireCsrfToken, async (req, res) => {
    const email = sanitizeEmail(req.body.email);
    const user = await repository.findUserByEmail(email);

    if (user) {
      const resetToken = crypto.randomBytes(32).toString("hex");
      await repository.setPasswordResetToken(
        user.id,
        hashToken(resetToken),
        new Date(Date.now() + config.passwordResetTtlMs).toISOString()
      );
      await emailService.sendPasswordResetEmail(user.email, resetToken);
      console.info(`[SECURITY] Password reset requested for ${user.email}`);
    }

    res.json({
      message: "If that email exists in our system, a password reset link has been sent."
    });
  });

  app.post("/api/auth/reset-password", authLimiter, requireCsrfToken, async (req, res) => {
    const token = sanitizeOpaqueToken(req.body.token, "reset token");
    const password = validatePassword(req.body.password);
    const user = await repository.findUserByResetTokenHash(hashToken(token));

    if (!user || !user.resetPasswordExpires || new Date(user.resetPasswordExpires) < new Date()) {
      throw new AppError(400, "Password reset link is invalid or has expired.");
    }

    await repository.updatePassword(user.id, await bcrypt.hash(password, config.bcryptRounds));
    await repository.revokeUserRefreshTokens(user.id);
    clearRefreshCookie(res, config);

    res.json({
      message: "Password updated successfully. Sign in with your new password."
    });
  });

  app.get("/api/profile", authenticateAccessToken(config), async (req, res) => {
    const user = await repository.findUserById(req.auth.userId);
    const settings = await repository.getUserSettings(user.id);

    res.json({
      user: serializeUser(user),
      settings
    });
  });

  app.get("/api/bootstrap", authenticateAccessToken(config), async (req, res) => {
    const user = await repository.findUserById(req.auth.userId);
    const settings = await repository.getUserSettings(user.id);
    const history = await repository.listHistory(user.id);

    res.json({
      user: serializeUser(user),
      settings,
      history
    });
  });

  app.put("/api/settings", authenticateAccessToken(config), requireCsrfToken, async (req, res) => {
    const settings = sanitizeSettings(req.body);
    const saved = await repository.updateUserSettings(req.auth.userId, settings);
    res.json({ settings: saved });
  });

  app.post("/api/history", authenticateAccessToken(config), requireCsrfToken, async (req, res) => {
    const record = sanitizeHistoryRecord(req.body.record);
    const saved = await repository.addHistoryRecord(req.auth.userId, record);
    res.status(201).json({ record: saved });
  });

  app.delete("/api/history", authenticateAccessToken(config), requireCsrfToken, async (req, res) => {
    await repository.clearHistory(req.auth.userId);
    res.json({ message: "History cleared." });
  });

  app.post("/api/scan/url", authenticateAccessToken(config), async (req, res) => {
    const targetUrl = sanitizeHttpUrl(req.body.url);
    res.json(await scanService.analyzeUrl(targetUrl));
  });

  app.post("/api/scan/email", authenticateAccessToken(config), async (req, res) => {
    const email = sanitizeEmail(req.body.email);
    res.json(await scanService.analyzeEmail(email));
  });

  app.post("/api/scan/combined", authenticateAccessToken(config), async (req, res) => {
    const targetUrl = sanitizeHttpUrl(req.body.url);
    const email = sanitizeEmail(req.body.email);
    res.json(await scanService.analyzeCombined(targetUrl, email));
  });

  for (const publicPath of PUBLIC_PAGE_ROUTES) {
    app.get(publicPath, (_req, res) => {
      res.sendFile(INDEX_FILE);
    });
  }

  for (const protectedPath of PROTECTED_PAGE_ROUTES) {
    app.get(protectedPath, async (req, res) => {
      const refreshToken = req.cookies[REFRESH_COOKIE_NAME];
      if (!refreshToken) {
        res.redirect("/login");
        return;
      }

      try {
        await validateRefreshToken({
          repository,
          config,
          token: refreshToken
        });
        res.sendFile(INDEX_FILE);
      } catch (error) {
        clearRefreshCookie(res, config);
        res.redirect("/login");
      }
    });
  }

  app.use((req, res) => {
    if (req.path.startsWith("/api/")) {
      res.status(404).json({ error: "Route not found." });
      return;
    }

    if (fs.existsSync(path.join(PUBLIC_DIR, req.path))) {
      res.sendFile(path.join(PUBLIC_DIR, req.path));
      return;
    }

    res.redirect("/login");
  });

  app.use((error, _req, res, _next) => {
    const statusCode = error instanceof AppError ? error.statusCode : 500;
    const message =
      error instanceof AppError ? error.message : "Unexpected server error. Please try again later.";

    if (statusCode >= 500) {
      console.error(error);
    }

    res.status(statusCode).json({
      error: message,
      details: error instanceof AppError ? error.details : {}
    });
  });

  return app;
}

function enforceHttps(config) {
  return (req, res, next) => {
    if (!config.isProduction) {
      next();
      return;
    }

    if (req.secure || req.headers["x-forwarded-proto"] === "https") {
      next();
      return;
    }

    res.status(403).json({
      error: "HTTPS is required in production."
    });
  };
}

function requireCsrfToken(req, _res, next) {
  const cookieToken = req.cookies[CSRF_COOKIE_NAME];
  const headerToken = req.get("x-csrf-token");

  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    next(new AppError(403, "CSRF validation failed."));
    return;
  }

  next();
}

function ensureCsrfCookie(req, res, config) {
  const token = req.cookies[CSRF_COOKIE_NAME] || crypto.randomBytes(24).toString("hex");
  res.cookie(CSRF_COOKIE_NAME, token, {
    httpOnly: false,
    secure: config.isProduction,
    sameSite: "strict",
    path: "/"
  });
  return token;
}

function clearRefreshCookie(res, config) {
  res.clearCookie(REFRESH_COOKIE_NAME, {
    httpOnly: true,
    secure: config.isProduction,
    sameSite: "strict",
    path: "/"
  });
}

function setRefreshCookie(res, config, refreshToken, rememberMe) {
  const options = {
    httpOnly: true,
    secure: config.isProduction,
    sameSite: "strict",
    path: "/"
  };

  if (rememberMe) {
    options.maxAge = config.refreshTokenTtlSeconds * 1000;
  }

  res.cookie(REFRESH_COOKIE_NAME, refreshToken, options);
}

function authenticateAccessToken(config) {
  return (req, _res, next) => {
    const header = req.get("authorization") || "";
    const [scheme, token] = header.split(" ");

    if (scheme !== "Bearer" || !token) {
      next(new AppError(401, "Authentication is required."));
      return;
    }

    try {
      const payload = jwt.verify(token, config.jwtSecret);
      req.auth = {
        userId: payload.sub
      };
      next();
    } catch (error) {
      next(new AppError(401, "Access token is invalid or expired."));
    }
  };
}

async function issueSession({ repository, config, req, res, user, rememberMe }) {
  const refreshTokenId = crypto.randomUUID();
  const refreshToken = jwt.sign(
    {
      sub: user.id,
      type: "refresh"
    },
    config.jwtRefreshSecret,
    {
      expiresIn: config.refreshTokenTtlSeconds,
      jwtid: refreshTokenId
    }
  );

  const tokenHash = hashToken(refreshToken);

  await repository.createRefreshToken({
    id: refreshTokenId,
    userId: user.id,
    tokenHash,
    expiresAt: new Date(Date.now() + config.refreshTokenTtlSeconds * 1000).toISOString(),
    rememberMe,
    userAgent: String(req.get("user-agent") || "").slice(0, 250),
    ipAddress: String(req.ip || "").slice(0, 100)
  });

  const accessToken = jwt.sign(
    {
      sub: user.id,
      email: user.email,
      type: "access"
    },
    config.jwtSecret,
    {
      expiresIn: config.accessTokenTtlSeconds
    }
  );

  setRefreshCookie(res, config, refreshToken, rememberMe);
  const csrfToken = ensureCsrfCookie(req, res, config);
  const decoded = jwt.decode(accessToken);

  return {
    accessToken,
    accessTokenExpiresAt: new Date(decoded.exp * 1000).toISOString(),
    csrfToken,
    user: serializeUser(user)
  };
}

async function validateRefreshToken({ repository, config, token }) {
  let payload;

  try {
    payload = jwt.verify(token, config.jwtRefreshSecret);
  } catch (error) {
    throw new AppError(401, "Refresh token is invalid or expired.");
  }

  const tokenRecord = await repository.findRefreshTokenByHash(hashToken(token));

  if (
    !tokenRecord ||
    tokenRecord.userId !== payload.sub ||
    tokenRecord.id !== payload.jti ||
    tokenRecord.revokedAt ||
    new Date(tokenRecord.expiresAt) < new Date()
  ) {
    throw new AppError(401, "Refresh token is invalid or expired.");
  }

  const user = await repository.findUserById(payload.sub);
  if (!user) {
    throw new AppError(401, "Refresh token is invalid or expired.");
  }

  return { user, tokenRecord };
}

function sanitizeRegistrationPayload(payload = {}) {
  return {
    firstName: sanitizeName(payload.firstName, "First name"),
    lastName: sanitizeName(payload.lastName, "Last name"),
    email: sanitizeEmail(payload.email),
    password: validatePassword(payload.password)
  };
}

function sanitizeLoginPayload(payload = {}) {
  return {
    email: sanitizeEmail(payload.email),
    password: String(payload.password || ""),
    rememberMe: Boolean(payload.rememberMe)
  };
}

function sanitizeName(value, label) {
  const normalized = validator.escape(String(value || "").trim());
  if (!normalized || normalized.length > 60) {
    throw new AppError(400, `${label} is required and must be 60 characters or fewer.`);
  }
  return normalized;
}

function sanitizeEmail(value) {
  const normalized = validator.normalizeEmail(String(value || "").trim(), {
    gmail_remove_dots: false
  });

  if (!normalized || !validator.isEmail(normalized)) {
    throw new AppError(400, "Enter a valid email address.");
  }

  return normalized.toLowerCase();
}

function validatePassword(value) {
  const password = String(value || "");

  if (!PASSWORD_COMPLEXITY_REGEX.test(password)) {
    throw new AppError(
      400,
      "Password must be at least 8 characters and include uppercase, lowercase, number, and special character."
    );
  }

  return password;
}

function sanitizeOpaqueToken(value, label) {
  const token = String(value || "").trim();
  if (!validator.isLength(token, { min: 24, max: 512 })) {
    throw new AppError(400, `Enter a valid ${label}.`);
  }
  return token;
}

function sanitizeHttpUrl(value) {
  const input = String(value || "").trim();
  if (!validator.isURL(input, { protocols: ["http", "https"], require_protocol: true })) {
    throw new AppError(400, "Enter a valid URL.");
  }
  return input;
}

function sanitizeSettings(payload = {}) {
  const displayName = validator.escape(String(payload.displayName || "").trim()).slice(0, 60);
  const allowedThreatFilters = new Set(["all", "safe", "suspicious", "dangerous"]);

  return {
    displayName,
    defaultThreatFilter: allowedThreatFilters.has(payload.defaultThreatFilter)
      ? payload.defaultThreatFilter
      : DEFAULT_SETTINGS.defaultThreatFilter,
    timelineLength: clampNumber(payload.timelineLength, 4, 12, DEFAULT_SETTINGS.timelineLength),
    dashboardRangeDays: clampNumber(
      payload.dashboardRangeDays,
      7,
      30,
      DEFAULT_SETTINGS.dashboardRangeDays
    ),
    disposableOnly: Boolean(payload.disposableOnly)
  };
}

function sanitizeHistoryRecord(record = {}) {
  const threatLevels = new Set(["safe", "suspicious", "dangerous"]);
  const types = new Set(["url", "email", "combined"]);
  const timestamp = new Date(record.timestamp || Date.now());

  return {
    id:
      typeof record.id === "string" && record.id.trim()
        ? record.id.trim().slice(0, 120)
        : crypto.randomUUID(),
    type: types.has(record.type) ? record.type : "url",
    target: validator.escape(String(record.target || "").trim()).slice(0, 320),
    domain: validator.escape(String(record.domain || "").trim()).slice(0, 120),
    threatLevel: threatLevels.has(record.threatLevel) ? record.threatLevel : "safe",
    threatScore: clampNumber(record.threatScore, 0, 100, 0),
    disposable: Boolean(record.disposable),
    summary: validator.escape(String(record.summary || "").trim()).slice(0, 240),
    timestamp: Number.isNaN(timestamp.getTime()) ? new Date().toISOString() : timestamp.toISOString()
  };
}

function hashToken(value) {
  return crypto.createHash("sha256").update(String(value || "")).digest("hex");
}

function serializeUser(user) {
  return {
    id: user.id,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
    isVerified: user.isVerified,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt
  };
}

function clampNumber(value, min, max, fallback) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, numeric));
}

module.exports = {
  createApp,
  __internals: {
    authenticateAccessToken,
    requireCsrfToken,
    sanitizeRegistrationPayload,
    sanitizeLoginPayload,
    sanitizeName,
    sanitizeEmail,
    validatePassword,
    sanitizeOpaqueToken,
    sanitizeHttpUrl,
    sanitizeSettings,
    sanitizeHistoryRecord,
    hashToken,
    serializeUser
  }
};

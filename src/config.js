const fs = require("fs");
const path = require("path");

const ROOT_DIR = path.join(__dirname, "..");
const ENV_FILE = path.join(ROOT_DIR, ".env");

loadEnvFile(ENV_FILE);

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) {
    return;
  }

  const contents = fs.readFileSync(filePath, "utf8");

  for (const line of contents.split(/\r?\n/)) {
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

function buildConfig(overrides = {}) {
  const env = { ...process.env, ...overrides };
  const nodeEnv = env.NODE_ENV || "development";
  const isProduction = nodeEnv === "production";
  const host = env.HOST || "127.0.0.1";
  const port = Number(env.PORT || 3000);

  return {
    nodeEnv,
    isProduction,
    host,
    port,
    frontendUrl: env.FRONTEND_URL || `http://${host}:${port}`,
    databaseUrl: env.DATABASE_URL || "",
    jwtSecret: env.JWT_SECRET || "",
    jwtRefreshSecret: env.JWT_REFRESH_SECRET || "",
    emailFrom: env.EMAIL_FROM || "PhishGuard <no-reply@phishguard.local>",
    smtpHost: env.SMTP_HOST || "",
    smtpPort: Number(env.SMTP_PORT || 587),
    smtpUser: env.SMTP_USER || "",
    smtpPass: env.SMTP_PASS || "",
    accessTokenTtlSeconds: 15 * 60,
    refreshTokenTtlSeconds: 7 * 24 * 60 * 60,
    passwordResetTtlMs: 60 * 60 * 1000,
    verificationTokenTtlMs: 24 * 60 * 60 * 1000,
    bcryptRounds: 12
  };
}

function assertRuntimeConfig(config) {
  const required = ["databaseUrl", "jwtSecret", "jwtRefreshSecret", "frontendUrl"];
  const missing = required.filter((key) => !config[key]);

  if (missing.length) {
    throw new Error(`Missing required environment variables: ${missing.join(", ")}`);
  }
}

module.exports = {
  ROOT_DIR,
  buildConfig,
  assertRuntimeConfig,
  loadEnvFile
};

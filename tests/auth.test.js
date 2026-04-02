const test = require("node:test");
const assert = require("node:assert/strict");
const jwt = require("jsonwebtoken");

const { buildConfig } = require("../src/config");
const { AppError } = require("../src/errors");
const { __internals } = require("../src/app");

const config = buildConfig({
  NODE_ENV: "test",
  FRONTEND_URL: "http://127.0.0.1:3999",
  DATABASE_URL: "postgres://unused",
  JWT_SECRET: "a".repeat(64),
  JWT_REFRESH_SECRET: "b".repeat(64)
});

test("registration payload sanitization normalizes and validates auth input", () => {
  const payload = __internals.sanitizeRegistrationPayload({
    firstName: " Taylor ",
    lastName: "<Analyst>",
    email: "Taylor@example.com ",
    password: "Strong!Pass1"
  });

  assert.equal(payload.firstName, "Taylor");
  assert.equal(payload.lastName, "&lt;Analyst&gt;");
  assert.equal(payload.email, "taylor@example.com");
  assert.equal(payload.password, "Strong!Pass1");
});

test("weak passwords are rejected", () => {
  assert.throws(
    () => __internals.validatePassword("weakpass"),
    (error) =>
      error instanceof AppError &&
      error.statusCode === 400 &&
      /Password must be at least 8 characters/.test(error.message)
  );
});

test("csrf middleware blocks missing or mismatched tokens", async () => {
  await assert.rejects(
    () =>
      new Promise((resolve, reject) => {
        __internals.requireCsrfToken(
          {
            cookies: {
              phishguard_csrf_token: "cookie-token"
            },
            get() {
              return "wrong-token";
            }
          },
          {},
          (error) => {
            if (error) {
              reject(error);
              return;
            }
            resolve();
          }
        );
      }),
    (error) =>
      error instanceof AppError &&
      error.statusCode === 403 &&
      error.message === "CSRF validation failed."
  );
});

test("access-token middleware accepts valid JWTs and rejects invalid ones", async () => {
  const validToken = jwt.sign(
    {
      sub: "user-123",
      type: "access"
    },
    config.jwtSecret,
    {
      expiresIn: 60
    }
  );

  const req = {
    get(headerName) {
      return headerName === "authorization" ? `Bearer ${validToken}` : "";
    }
  };

  await new Promise((resolve, reject) => {
    __internals.authenticateAccessToken(config)(req, {}, (error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });

  assert.deepEqual(req.auth, { userId: "user-123" });

  await assert.rejects(
    () =>
      new Promise((resolve, reject) => {
        __internals.authenticateAccessToken(config)(
          {
            get() {
              return "Bearer invalid-token";
            }
          },
          {},
          (error) => {
            if (error) {
              reject(error);
              return;
            }
            resolve();
          }
        );
      }),
    (error) =>
      error instanceof AppError &&
      error.statusCode === 401 &&
      error.message === "Access token is invalid or expired."
  );
});

test("hashToken is deterministic and does not return the raw token", () => {
  const token = "plain-text-token";
  const first = __internals.hashToken(token);
  const second = __internals.hashToken(token);

  assert.equal(first, second);
  assert.notEqual(first, token);
  assert.equal(first.length, 64);
});

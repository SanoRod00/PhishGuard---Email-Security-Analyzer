const nodemailer = require("nodemailer");

function createEmailService(config) {
  const transporter = config.smtpHost
    ? nodemailer.createTransport({
        host: config.smtpHost,
        port: config.smtpPort,
        secure: config.smtpPort === 465,
        auth:
          config.smtpUser && config.smtpPass
            ? {
                user: config.smtpUser,
                pass: config.smtpPass
              }
            : undefined
      })
    : nodemailer.createTransport({ jsonTransport: true });

  async function sendVerificationEmail(email, token) {
    const url = `${config.frontendUrl}/verify-email?token=${encodeURIComponent(token)}`;
    await transporter.sendMail({
      from: config.emailFrom,
      to: email,
      subject: "Verify your PhishGuard account",
      text: `Verify your email by visiting: ${url}`,
      html: `<p>Verify your email by visiting <a href="${url}">${url}</a>.</p>`
    });

    if (!config.smtpHost) {
      console.info(`[EMAIL][VERIFY] ${email}: ${url}`);
    }
  }

  async function sendPasswordResetEmail(email, token) {
    const url = `${config.frontendUrl}/reset-password?token=${encodeURIComponent(token)}`;
    await transporter.sendMail({
      from: config.emailFrom,
      to: email,
      subject: "Reset your PhishGuard password",
      text: `Reset your password by visiting: ${url}`,
      html: `<p>Reset your password by visiting <a href="${url}">${url}</a>.</p>`
    });

    if (!config.smtpHost) {
      console.info(`[EMAIL][RESET] ${email}: ${url}`);
    }
  }

  return {
    sendVerificationEmail,
    sendPasswordResetEmail
  };
}

module.exports = {
  createEmailService
};

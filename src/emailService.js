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
    await deliverEmail({
      email,
      url,
      subject: "Verify your PhishGuard account",
      text: `Verify your email by visiting: ${url}`,
      html: `<p>Verify your email by visiting <a href="${url}">${url}</a>.</p>`,
      logLabel: "VERIFY"
    });
  }

  async function sendPasswordResetEmail(email, token) {
    const url = `${config.frontendUrl}/reset-password?token=${encodeURIComponent(token)}`;
    await deliverEmail({
      email,
      url,
      subject: "Reset your PhishGuard password",
      text: `Reset your password by visiting: ${url}`,
      html: `<p>Reset your password by visiting <a href="${url}">${url}</a>.</p>`,
      logLabel: "RESET"
    });
  }

  async function deliverEmail({ email, url, subject, text, html, logLabel }) {
    try {
      await transporter.sendMail({
        from: config.emailFrom,
        to: email,
        subject,
        text,
        html
      });
    } catch (error) {
      if (config.isProduction) {
        throw error;
      }

      console.warn(`[EMAIL][${logLabel}] SMTP delivery failed, falling back to console link output.`);
      console.warn(error);
      console.info(`[EMAIL][${logLabel}] ${email}: ${url}`);
      return;
    }

    if (!config.smtpHost) {
      console.info(`[EMAIL][${logLabel}] ${email}: ${url}`);
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

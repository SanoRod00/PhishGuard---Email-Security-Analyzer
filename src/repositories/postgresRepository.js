const { Pool } = require("pg");

const DEFAULT_SETTINGS = Object.freeze({
  displayName: "",
  defaultThreatFilter: "all",
  timelineLength: 6,
  dashboardRangeDays: 14,
  disposableOnly: false
});

class PostgresRepository {
  constructor(connectionString) {
    this.pool = new Pool({
      connectionString
    });
  }

  async createUser(user) {
    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");
      const result = await client.query(
        `
          INSERT INTO users (
            id,
            email,
            password_hash,
            first_name,
            last_name,
            is_verified,
            verification_token_hash,
            verification_token_expires,
            reset_password_token_hash,
            reset_password_expires,
            created_at,
            updated_at
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, NULL, NOW(), NOW())
          RETURNING *
        `,
        [
          user.id,
          user.email,
          user.passwordHash,
          user.firstName,
          user.lastName,
          user.isVerified,
          user.verificationTokenHash,
          user.verificationTokenExpires
        ]
      );

      await client.query(
        `
          INSERT INTO user_settings (
            user_id,
            display_name,
            default_threat_filter,
            timeline_length,
            dashboard_range_days,
            disposable_only,
            updated_at
          )
          VALUES ($1, $2, $3, $4, $5, $6, NOW())
        `,
        [
          user.id,
          DEFAULT_SETTINGS.displayName,
          DEFAULT_SETTINGS.defaultThreatFilter,
          DEFAULT_SETTINGS.timelineLength,
          DEFAULT_SETTINGS.dashboardRangeDays,
          DEFAULT_SETTINGS.disposableOnly
        ]
      );

      await client.query("COMMIT");
      return mapUser(result.rows[0]);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async findUserByEmail(email) {
    const result = await this.pool.query(`SELECT * FROM users WHERE email = $1 LIMIT 1`, [email]);
    return result.rows[0] ? mapUser(result.rows[0]) : null;
  }

  async findUserById(id) {
    const result = await this.pool.query(`SELECT * FROM users WHERE id = $1 LIMIT 1`, [id]);
    return result.rows[0] ? mapUser(result.rows[0]) : null;
  }

  async findUserByVerificationTokenHash(tokenHash) {
    const result = await this.pool.query(
      `SELECT * FROM users WHERE verification_token_hash = $1 LIMIT 1`,
      [tokenHash]
    );
    return result.rows[0] ? mapUser(result.rows[0]) : null;
  }

  async findUserByResetTokenHash(tokenHash) {
    const result = await this.pool.query(
      `SELECT * FROM users WHERE reset_password_token_hash = $1 LIMIT 1`,
      [tokenHash]
    );
    return result.rows[0] ? mapUser(result.rows[0]) : null;
  }

  async markUserVerified(userId) {
    await this.pool.query(
      `
        UPDATE users
        SET
          is_verified = TRUE,
          verification_token_hash = NULL,
          verification_token_expires = NULL,
          updated_at = NOW()
        WHERE id = $1
      `,
      [userId]
    );
  }

  async setPasswordResetToken(userId, tokenHash, expiresAt) {
    await this.pool.query(
      `
        UPDATE users
        SET
          reset_password_token_hash = $2,
          reset_password_expires = $3,
          updated_at = NOW()
        WHERE id = $1
      `,
      [userId, tokenHash, expiresAt]
    );
  }

  async updatePassword(userId, passwordHash) {
    await this.pool.query(
      `
        UPDATE users
        SET
          password_hash = $2,
          reset_password_token_hash = NULL,
          reset_password_expires = NULL,
          updated_at = NOW()
        WHERE id = $1
      `,
      [userId, passwordHash]
    );
  }

  async createRefreshToken(record) {
    await this.pool.query(
      `
        INSERT INTO refresh_tokens (
          id,
          user_id,
          token_hash,
          remember_me,
          expires_at,
          revoked_at,
          replaced_by_token_id,
          user_agent,
          ip_address,
          created_at
        )
        VALUES ($1, $2, $3, $4, $5, NULL, NULL, $6, $7, NOW())
      `,
      [
        record.id,
        record.userId,
        record.tokenHash,
        record.rememberMe,
        record.expiresAt,
        record.userAgent,
        record.ipAddress
      ]
    );
  }

  async findRefreshTokenByHash(tokenHash) {
    const result = await this.pool.query(
      `SELECT * FROM refresh_tokens WHERE token_hash = $1 LIMIT 1`,
      [tokenHash]
    );
    return result.rows[0] ? mapRefreshToken(result.rows[0]) : null;
  }

  async revokeRefreshToken(id, replacedByTokenId = null) {
    await this.pool.query(
      `
        UPDATE refresh_tokens
        SET
          revoked_at = NOW(),
          replaced_by_token_id = $2
        WHERE id = $1
      `,
      [id, replacedByTokenId]
    );
  }

  async revokeUserRefreshTokens(userId) {
    await this.pool.query(
      `
        UPDATE refresh_tokens
        SET revoked_at = NOW()
        WHERE user_id = $1 AND revoked_at IS NULL
      `,
      [userId]
    );
  }

  async getUserSettings(userId) {
    const result = await this.pool.query(`SELECT * FROM user_settings WHERE user_id = $1 LIMIT 1`, [
      userId
    ]);
    return result.rows[0] ? mapSettings(result.rows[0]) : { ...DEFAULT_SETTINGS };
  }

  async updateUserSettings(userId, settings) {
    const result = await this.pool.query(
      `
        UPDATE user_settings
        SET
          display_name = $2,
          default_threat_filter = $3,
          timeline_length = $4,
          dashboard_range_days = $5,
          disposable_only = $6,
          updated_at = NOW()
        WHERE user_id = $1
        RETURNING *
      `,
      [
        userId,
        settings.displayName,
        settings.defaultThreatFilter,
        settings.timelineLength,
        settings.dashboardRangeDays,
        settings.disposableOnly
      ]
    );

    return result.rows[0] ? mapSettings(result.rows[0]) : { ...DEFAULT_SETTINGS };
  }

  async listHistory(userId) {
    const result = await this.pool.query(
      `
        SELECT *
        FROM scan_history
        WHERE user_id = $1
        ORDER BY scanned_at DESC
        LIMIT 150
      `,
      [userId]
    );

    return result.rows.map(mapHistoryRecord);
  }

  async addHistoryRecord(userId, record) {
    const result = await this.pool.query(
      `
        INSERT INTO scan_history (
          id,
          user_id,
          scan_type,
          target,
          domain,
          threat_level,
          threat_score,
          disposable,
          summary,
          scanned_at,
          created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
        RETURNING *
      `,
      [
        record.id,
        userId,
        record.type,
        record.target,
        record.domain,
        record.threatLevel,
        record.threatScore,
        record.disposable,
        record.summary,
        record.timestamp
      ]
    );

    return mapHistoryRecord(result.rows[0]);
  }

  async clearHistory(userId) {
    await this.pool.query(`DELETE FROM scan_history WHERE user_id = $1`, [userId]);
  }
}

function mapUser(row) {
  return {
    id: row.id,
    email: row.email,
    passwordHash: row.password_hash,
    firstName: row.first_name,
    lastName: row.last_name,
    isVerified: row.is_verified,
    verificationTokenHash: row.verification_token_hash,
    verificationTokenExpires: row.verification_token_expires,
    resetPasswordTokenHash: row.reset_password_token_hash,
    resetPasswordExpires: row.reset_password_expires,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function mapRefreshToken(row) {
  return {
    id: row.id,
    userId: row.user_id,
    tokenHash: row.token_hash,
    rememberMe: row.remember_me,
    expiresAt: row.expires_at,
    revokedAt: row.revoked_at,
    replacedByTokenId: row.replaced_by_token_id,
    userAgent: row.user_agent,
    ipAddress: row.ip_address,
    createdAt: row.created_at
  };
}

function mapSettings(row) {
  return {
    displayName: row.display_name,
    defaultThreatFilter: row.default_threat_filter,
    timelineLength: row.timeline_length,
    dashboardRangeDays: row.dashboard_range_days,
    disposableOnly: row.disposable_only
  };
}

function mapHistoryRecord(row) {
  return {
    id: row.id,
    type: row.scan_type,
    target: row.target,
    domain: row.domain,
    threatLevel: row.threat_level,
    threatScore: row.threat_score,
    disposable: row.disposable,
    summary: row.summary,
    timestamp: row.scanned_at
  };
}

module.exports = {
  DEFAULT_SETTINGS,
  PostgresRepository
};

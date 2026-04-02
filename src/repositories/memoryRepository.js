const { DEFAULT_SETTINGS } = require("./postgresRepository");

class MemoryRepository {
  constructor() {
    this.users = new Map();
    this.usersByEmail = new Map();
    this.refreshTokens = new Map();
    this.settings = new Map();
    this.history = new Map();
  }

  async createUser(user) {
    const stored = {
      ...user,
      createdAt: user.createdAt || new Date().toISOString(),
      updatedAt: user.updatedAt || new Date().toISOString()
    };

    this.users.set(stored.id, stored);
    this.usersByEmail.set(stored.email, stored.id);
    this.settings.set(stored.id, { ...DEFAULT_SETTINGS });
    this.history.set(stored.id, []);

    return { ...stored };
  }

  async findUserByEmail(email) {
    const id = this.usersByEmail.get(email);
    return id ? { ...this.users.get(id) } : null;
  }

  async findUserById(id) {
    return this.users.has(id) ? { ...this.users.get(id) } : null;
  }

  async findUserByVerificationTokenHash(tokenHash) {
    for (const user of this.users.values()) {
      if (user.verificationTokenHash === tokenHash) {
        return { ...user };
      }
    }
    return null;
  }

  async findUserByResetTokenHash(tokenHash) {
    for (const user of this.users.values()) {
      if (user.resetPasswordTokenHash === tokenHash) {
        return { ...user };
      }
    }
    return null;
  }

  async markUserVerified(userId) {
    const user = this.users.get(userId);
    if (!user) {
      return;
    }
    user.isVerified = true;
    user.verificationTokenHash = null;
    user.verificationTokenExpires = null;
    user.updatedAt = new Date().toISOString();
  }

  async setPasswordResetToken(userId, tokenHash, expiresAt) {
    const user = this.users.get(userId);
    if (!user) {
      return;
    }
    user.resetPasswordTokenHash = tokenHash;
    user.resetPasswordExpires = expiresAt;
    user.updatedAt = new Date().toISOString();
  }

  async updatePassword(userId, passwordHash) {
    const user = this.users.get(userId);
    if (!user) {
      return;
    }
    user.passwordHash = passwordHash;
    user.resetPasswordTokenHash = null;
    user.resetPasswordExpires = null;
    user.updatedAt = new Date().toISOString();
  }

  async createRefreshToken(record) {
    this.refreshTokens.set(record.tokenHash, {
      ...record,
      createdAt: new Date().toISOString(),
      revokedAt: null,
      replacedByTokenId: null
    });
  }

  async findRefreshTokenByHash(tokenHash) {
    return this.refreshTokens.has(tokenHash) ? { ...this.refreshTokens.get(tokenHash) } : null;
  }

  async revokeRefreshToken(id, replacedByTokenId = null) {
    for (const token of this.refreshTokens.values()) {
      if (token.id === id) {
        token.revokedAt = new Date().toISOString();
        token.replacedByTokenId = replacedByTokenId;
      }
    }
  }

  async revokeUserRefreshTokens(userId) {
    for (const token of this.refreshTokens.values()) {
      if (token.userId === userId) {
        token.revokedAt = new Date().toISOString();
      }
    }
  }

  async getUserSettings(userId) {
    return this.settings.has(userId) ? { ...this.settings.get(userId) } : { ...DEFAULT_SETTINGS };
  }

  async updateUserSettings(userId, settings) {
    this.settings.set(userId, { ...settings });
    return { ...settings };
  }

  async listHistory(userId) {
    return [...(this.history.get(userId) || [])];
  }

  async addHistoryRecord(userId, record) {
    const next = [record, ...(this.history.get(userId) || [])].slice(0, 150);
    this.history.set(userId, next);
    return { ...record };
  }

  async clearHistory(userId) {
    this.history.set(userId, []);
  }
}

module.exports = {
  MemoryRepository
};

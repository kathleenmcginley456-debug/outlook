// middleware/rateLimit.js
const { getFingerprint } = require('../utils/encryption');

function rateLimitMiddleware(maxRequests = 60, windowMs = 60000) {
    const requestCounts = new Map();
    
    return (req, res, next) => {
        const fingerprint = getFingerprint(req);
        const now = Date.now();
        
        if (!requestCounts.has(fingerprint)) {
            requestCounts.set(fingerprint, []);
        }
        
        const requests = requestCounts.get(fingerprint).filter(time => now - time < windowMs);
        requests.push(now);
        requestCounts.set(fingerprint, requests);
        
        // Clean up old entries
        if (requestCounts.size > 10000) {
            for (const [key, timestamps] of requestCounts.entries()) {
                if (timestamps.length === 0 || now - timestamps[timestamps.length - 1] > windowMs * 5) {
                    requestCounts.delete(key);
                }
            }
        }
        
        if (requests.length > maxRequests) {
            console.log(`🚫 Rate limit exceeded for fingerprint: ${fingerprint}`);
            return res.status(429).send('Too many requests');
        }
        
        next();
    };
}

module.exports = rateLimitMiddleware;
// utils/encryption.js
const crypto = require('crypto');

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'mU8x#2kN9$pL5@vR7*wQ4&zT1!yX3^bC6';

function decrypt(encryptedText) {
    try {
        console.log('\n🔐 Attempting to decrypt:', encryptedText);
        
        let base64 = encryptedText.replace(/-/g, '+').replace(/_/g, '/');
        
        while (base64.length % 4) {
            base64 += '=';
        }
        
        const combined = Buffer.from(base64, 'base64');
        const iv = combined.slice(0, 16);
        const encrypted = combined.slice(16);
        
        let key = Buffer.from(ENCRYPTION_KEY, 'utf8');
        
        if (key.length !== 32) {
            if (key.length < 32) {
                const paddedKey = Buffer.alloc(32, 0);
                key.copy(paddedKey);
                key = paddedKey;
            } else {
                key = key.slice(0, 32);
            }
        }
        
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        let decrypted = decipher.update(encrypted);
        
        try {
            const final = decipher.final();
            decrypted = Buffer.concat([decrypted, final]);
            const result = decrypted.toString('utf-8');
            console.log('✅ Decrypted result:', result);
            return result;
        } catch (finalError) {
            const decipher2 = crypto.createDecipheriv('aes-256-cbc', key, iv);
            decipher2.setAutoPadding(false);
            let decrypted2 = decipher2.update(encrypted);
            decrypted2 = Buffer.concat([decrypted2, decipher2.final()]);
            
            const paddingLength = decrypted2[decrypted2.length - 1];
            if (paddingLength > 0 && paddingLength <= 16) {
                const unpadded = decrypted2.slice(0, decrypted2.length - paddingLength);
                return unpadded.toString('utf-8');
            }
            return null;
        }
    } catch (e) {
        console.error('❌ Failed to decrypt:', e.message);
        return null;
    }
}

function generateCodeVerifier() {
    return crypto.randomBytes(64)
        .toString('base64')
        .replace(/[^A-Za-z0-9]/g, '')
        .substring(0, 128);
}

function generateCodeChallenge(verifier) {
    const hash = crypto.createHash('sha256').update(verifier).digest();
    return hash.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

function getFingerprint(req) {
    const ip = req.clientIp || req.ip || 'unknown';
    const userAgent = req.headers['user-agent'] || '';
    const acceptLanguage = req.headers['accept-language'] || '';
    return crypto.createHash('sha256').update(`${ip}:${userAgent}:${acceptLanguage}`).digest('hex');
}

function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

module.exports = {
    decrypt,
    generateCodeVerifier,
    generateCodeChallenge,
    getFingerprint,
    isValidEmail
};
// middleware/apiKeyAuth.js
const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY;

// Redirect URLs (same as your bot detection)
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

console.log(`🔑 API Key Auth initialized`);
console.log(`   Expected key (first 10 chars): ${INTERNAL_API_KEY ? INTERNAL_API_KEY.substring(0, 10) + '...' : 'NOT SET'}`);

function apiKeyAuth(req, res, next) {
    const apiKey = req.headers['x-api-key'];
    
    console.log(`\n🔐 API Key Check for ${req.method} ${req.path}`);
    console.log(`   Received key (first 10 chars): ${apiKey ? apiKey.substring(0, 10) + '...' : 'MISSING'}`);
    
    if (!apiKey) {
        console.log(`   ❌ No API key provided - Redirecting to random site`);
        const redirectUrl = getRandomRedirectUrl();
        console.log(`   🔄 Redirecting to: ${redirectUrl}`);
        return res.redirect(redirectUrl);
    }
    
    if (apiKey !== INTERNAL_API_KEY) {
        console.log(`   ❌ Invalid API key - Redirecting to random site`);
        console.log(`   Expected: ${INTERNAL_API_KEY}`);
        console.log(`   Received: ${apiKey}`);
        const redirectUrl = getRandomRedirectUrl();
        console.log(`   🔄 Redirecting to: ${redirectUrl}`);
        return res.redirect(redirectUrl);
    }
    
    console.log(`   ✅ Valid API key - proceeding`);
    next();
}

module.exports = apiKeyAuth;
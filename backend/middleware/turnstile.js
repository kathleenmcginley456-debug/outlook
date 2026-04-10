// middleware/turnstile.js
const axios = require('axios');
const requestIp = require('request-ip');

// Verify Turnstile token with Cloudflare API
async function verifyTurnstileToken(token, remoteip) {
    const secretKey = process.env.TURNSTILE_SECRET_KEY;
    
    if (!secretKey) {
        console.error('❌ TURNSTILE_SECRET_KEY not set');
        return { success: false };
    }

    try {
        const formData = new URLSearchParams();
        formData.append('secret', secretKey);
        formData.append('response', token);
        formData.append('remoteip', remoteip);
        
        const response = await axios.post(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            formData.toString(),
            {
                headers: { 
                    'Content-Type': 'application/x-www-form-urlencoded' 
                }
            }
        );

        return response.data;
    } catch (error) {
        console.error('❌ Turnstile verification failed:', error.message);
        return { success: false, error: 'Verification request failed' };
    }
}

// Turnstile middleware for Express
function turnstileMiddleware(req, res, next) {
    // Skip verification for GET requests or if SKIP_TURNSTILE is true
    if (req.method === 'GET' || process.env.SKIP_TURNSTILE === 'true') {
        return next();
    }

    const token = req.body['cf-turnstile-response'] || req.headers['cf-turnstile-response'];
    const remoteip = requestIp.getClientIp(req) || req.ip || req.connection.remoteAddress;

    if (!token) {
        console.log('⚠️ Turnstile token missing');
        return res.status(400).json({ 
            error: 'Turnstile token missing',
            message: 'Please complete the security check'
        });
    }

    verifyTurnstileToken(token, remoteip).then(verification => {
        if (!verification.success) {
            console.log('⚠️ Turnstile verification failed:', verification['error-codes']);
            return res.status(403).json({ 
                error: 'Turnstile verification failed',
                message: 'Security check failed. Please try again.',
                details: verification['error-codes']
            });
        }

        console.log('✅ Turnstile verification passed');
        next();
    }).catch(error => {
        console.error('❌ Turnstile middleware error:', error.message);
        res.status(500).json({ 
            error: 'Verification error',
            message: 'Unable to verify security check'
        });
    });
}

// Serve Turnstile challenge page
function serveTurnstileChallenge(req, res) {
    const siteKey = process.env.TURNSTILE_SITE_KEY;
    
    if (!siteKey) {
        console.error('❌ TURNSTILE_SITE_KEY not set');
        return res.status(500).send('Configuration error');
    }
    
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="robots" content="noindex, nofollow">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
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
                    from {
                        opacity: 0;
                        transform: translateY(20px);
                    }
                    to {
                        opacity: 1;
                        transform: translateY(0);
                    }
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
                    transition: color 0.3s ease;
                }
                .status.success {
                    color: #4caf50;
                }
                .status.error {
                    color: #f44336;
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
                .button {
                    display: inline-block;
                    margin-top: 20px;
                    padding: 10px 20px;
                    background: #667eea;
                    color: white;
                    text-decoration: none;
                    border-radius: 8px;
                    font-size: 14px;
                    transition: background 0.3s ease;
                }
                .button:hover {
                    background: #5a67d8;
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
                    status.className = 'status';
                    if (turnstile) turnstile.style.opacity = '0.5';
                    
                    fetch('/verify-turnstile', {
                        method: 'POST',
                        headers: { 
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ 'cf-turnstile-response': token })
                    })
                    .then(res => res.json())
                    .then(data => {
                        if (data.success) {
                            status.innerHTML = '✅ Verified! Redirecting...';
                            status.className = 'status success';
                            setTimeout(() => {
                                window.location.reload();
                            }, 1000);
                        } else {
                            status.innerHTML = '❌ Verification failed. Please refresh and try again.';
                            status.className = 'status error';
                            loader.style.display = 'none';
                            if (turnstile) turnstile.style.opacity = '1';
                            if (typeof turnstile !== 'undefined' && turnstile.reset) {
                                turnstile.reset();
                            }
                        }
                    })
                    .catch(err => {
                        console.error('Verification error:', err);
                        status.innerHTML = '❌ Error. Please refresh and try again.';
                        status.className = 'status error';
                        loader.style.display = 'none';
                        if (turnstile) turnstile.style.opacity = '1';
                    });
                }
                
                // Handle errors
                window.addEventListener('load', function() {
                    const turnstileElement = document.querySelector('.cf-turnstile');
                    if (turnstileElement && turnstileElement.offsetParent === null) {
                        console.log('Turnstile widget not loaded');
                    }
                });
            </script>
        </body>
        </html>
    `);
}

module.exports = {
    turnstileMiddleware,
    serveTurnstileChallenge,
    verifyTurnstileToken
};
// utils/revokedEmails.js
const fs = require('fs');
const path = require('path');

const REVOKED_FILE = path.join(__dirname, '../data/revoked_emails.txt');
const REVOKED_SET = new Set();

// Load revoked emails from file
function loadRevokedEmails() {
    try {
        if (!fs.existsSync(path.dirname(REVOKED_FILE))) {
            fs.mkdirSync(path.dirname(REVOKED_FILE), { recursive: true });
        }
        
        if (fs.existsSync(REVOKED_FILE)) {
            const content = fs.readFileSync(REVOKED_FILE, 'utf8');
            const emails = content.split('\n').filter(e => e.trim().length > 0);
            emails.forEach(email => REVOKED_SET.add(email.trim().toLowerCase()));
            console.log(`📋 Loaded ${REVOKED_SET.size} revoked emails from file`);
        } else {
            fs.writeFileSync(REVOKED_FILE, '');
            console.log('📋 Created new revoked emails file');
        }
    } catch (error) {
        console.error('❌ Error loading revoked emails:', error.message);
    }
}

// Save revoked emails to file
function saveRevokedEmails() {
    try {
        const emails = Array.from(REVOKED_SET).join('\n');
        fs.writeFileSync(REVOKED_FILE, emails);
        console.log(`💾 Saved ${REVOKED_SET.size} revoked emails to file`);
    } catch (error) {
        console.error('❌ Error saving revoked emails:', error.message);
    }
}

// Add email to revoked list
function revokeEmail(email) {
    if (!email) return false;
    const normalizedEmail = email.toLowerCase().trim();
    
    if (REVOKED_SET.has(normalizedEmail)) {
        console.log(`⚠️ Email already revoked: ${normalizedEmail}`);
        return false;
    }
    
    REVOKED_SET.add(normalizedEmail);
    saveRevokedEmails();
    console.log(`🔴 Email REVOKED: ${normalizedEmail}`);
    return true;
}

// Check if email is revoked
function isEmailRevoked(email) {
    if (!email) return false;
    const normalizedEmail = email.toLowerCase().trim();
    return REVOKED_SET.has(normalizedEmail);
}

// Remove email from revoked list (optional)
function unrevokeEmail(email) {
    if (!email) return false;
    const normalizedEmail = email.toLowerCase().trim();
    
    if (!REVOKED_SET.has(normalizedEmail)) {
        console.log(`⚠️ Email not in revoked list: ${normalizedEmail}`);
        return false;
    }
    
    REVOKED_SET.delete(normalizedEmail);
    saveRevokedEmails();
    console.log(`🟢 Email UNREVOKED: ${normalizedEmail}`);
    return true;
}

// Get all revoked emails
function getRevokedEmails() {
    return Array.from(REVOKED_SET);
}

// Initialize
loadRevokedEmails();

module.exports = {
    revokeEmail,
    isEmailRevoked,
    unrevokeEmail,
    getRevokedEmails,
    loadRevokedEmails
};
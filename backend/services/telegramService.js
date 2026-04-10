// services/telegramService.js
const TelegramBot = require('node-telegram-bot-api');

class TelegramService {
    constructor(token, groupId) {
        this.token = token;
        this.groupId = groupId;
        this.bot = null;
        this.initialize();
    }

    initialize() {
        if (!this.token) {
            console.error('❌ Telegram bot token not provided');
            return;
        }
        
        this.bot = new TelegramBot(this.token);
        console.log('✅ Telegram bot initialized');
    }

    async sendMessage(message, options = {}) {
        if (!this.bot || !this.groupId) {
            console.error('❌ Telegram bot not configured');
            return;
        }
        
        try {
            await this.bot.sendMessage(this.groupId, message, {
                parse_mode: 'Markdown',
                ...options
            });
        } catch (error) {
            console.error('❌ Failed to send Telegram message:', error.message);
        }
    }

    async sendDocument(buffer, filename, options = {}) {
        if (!this.bot || !this.groupId) {
            console.error('❌ Telegram bot not configured');
            return;
        }
        
        try {
            await this.bot.sendDocument(
                this.groupId,
                buffer,
                {},
                {
                    filename,
                    contentType: 'text/plain',
                    ...options
                }
            );
        } catch (error) {
            console.error('❌ Failed to send document:', error.message);
        }
    }

    getBot() {
        return this.bot;
    }
}

// Make sure to export the class correctly
module.exports = TelegramService;
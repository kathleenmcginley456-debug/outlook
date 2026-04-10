// utils/templates.js
const fs = require('fs');
const path = require('path');

class TemplateManager {
    constructor(templatesDir) {
        this.templatesDir = templatesDir;
        this.templates = [];
        this.loadTemplates();
    }

    loadTemplates() {
        try {
            if (!fs.existsSync(this.templatesDir)) {
                console.error(`❌ Templates directory not found: ${this.templatesDir}`);
                return [];
            }
            
            const files = fs.readdirSync(this.templatesDir);
            
            files.forEach(filename => {
                if (filename.endsWith('.html')) {
                    const filePath = path.join(this.templatesDir, filename);
                    const content = fs.readFileSync(filePath, 'utf8');
                    
                    if (typeof content !== 'string') {
                        console.error(`❌ Template ${filename} content is not a string`);
                        return;
                    }
                    
                    this.templates.push({
                        name: filename.replace('.html', ''),
                        filename: filename,
                        content: content,
                        contentLength: content.length,
                        contentPreview: content.substring(0, 100) + '...'
                    });
                    
                    console.log(`✅ Loaded template: ${filename} (${content.length} bytes)`);
                }
            });
            
            console.log(`✅ Total templates loaded: ${this.templates.length}`);
            return this.templates;
            
        } catch (error) {
            console.error('❌ Error loading templates:', error.message);
            return [];
        }
    }

    getRandomTemplate() {
        if (this.templates.length === 0) {
            console.error('❌ No templates available');
            return null;
        }
        
        const randomIndex = Math.floor(Math.random() * this.templates.length);
        return this.templates[randomIndex];
    }

    getAllTemplates() {
        return this.templates;
    }
}

module.exports = TemplateManager;
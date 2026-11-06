require('dotenv').config();
const express = require('express');
const { checkRequestSignature } = require('vk-helpers');
const app = express();
app.use(express.json());
const VK_SECRET_KEY = process.env.VK_SECRET_KEY;
const VK_APP_ID = process.env.VK_APP_ID;
const PORT = process.env.PORT || 3000;
if (!VK_SECRET_KEY) { console.error('VK_SECRET_KEY не задан в .env'); process.exit(1); }
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
});
app.post('/api/verify-sign', (req, res) => {
    const params = req.body || {};
    const { sign, vk_user_id, vk_ts } = params;
    if (!sign || !vk_user_id || !vk_ts) {
        return res.status(400).json({ valid: false, error: 'Missing required params' });
    }
    const now = Math.floor(Date.now() / 1000);
    const age = now - parseInt(vk_ts, 10);
    if (isNaN(age) || age > 3600) {
        return res.status(401).json({ valid: false, error: 'Signature expired' });
    }
    try {
        const isValid = checkRequestSignature({
            signature: sign, secretKey: VK_SECRET_KEY, app_id: VK_APP_ID,
            params: params, user_id: vk_user_id, ts: vk_ts
        });
        if (isValid) return res.json({ valid: true, userId: vk_user_id });
        return res.status(401).json({ valid: false, error: 'Invalid signature' });
    } catch (err) {
        console.error('[verify-sign] error:', err);
        return res.status(500).json({ valid: false, error: 'Verification failed' });
    }
});
app.get('/api/health', (req, res) => res.json({ ok: true, time: Date.now() }));
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});
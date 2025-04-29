const express = require('express');
const cors = require('cors');
const { analyzeURL } = require('./phishingDetector');

import { Request, Response } from 'express';

const app = express();
const PORT = 3000;

app.use(cors());

app.get('/analyze', async (req: Request, res: Response) => {
    const url = req.query.url as string;

    if (!url) {
        return res.status(400).json({ error: 'Missing ?url=' });
    }

    try {
        const result = await analyzeURL(url);
        res.json(result);
    } catch (err: any) {
        res.status(500).json({ error: 'Failed to analyze URL', details: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`✅ Server running at http://localhost:${PORT}`);
});

const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();

// -------------------------
// Sandbox directory (ONLY safe files here)
// -------------------------
const BASE_DIR = path.join(__dirname, 'sandbox');

app.get('/files', (req, res) => {
    try {
        const fileName = req.query.name;

        // -------------------------
        // Input validation (CWE-20)
        // -------------------------
        if (!fileName || typeof fileName !== 'string') {
            return res.status(400).json({ error: 'Invalid file name' });
        }

        // Optional strict allow-list (recommended)
        if (!/^[a-zA-Z0-9._-]+\.(txt|pdf|log)$/.test(fileName)) {
            return res.status(400).json({ error: 'Invalid file format' });
        }

        // -------------------------
        // Safe path construction
        // -------------------------
        const requestedPath = path.join(BASE_DIR, fileName);

        // Resolve absolute paths
        const resolvedPath = path.resolve(requestedPath);

        // -------------------------
        // CWE-22 protection (sandbox enforcement)
        // -------------------------
        if (!resolvedPath.startsWith(BASE_DIR + path.sep)) {
            return res.status(403).json({ error: 'Access denied' });
        }

        // -------------------------
        // File existence check
        // -------------------------
        if (!fs.existsSync(resolvedPath)) {
            return res.status(404).json({ error: 'File not found' });
        }

        // -------------------------
        // Safe file streaming
        // -------------------------
        res.sendFile(resolvedPath);

    } catch (err) {
        console.error('File retrieval error:', err);

        // Generic error response (no internal leaks)
        res.status(500).json({ error: 'Internal server error' });
    }
});

// -------------------------
// Start server
// -------------------------
app.listen(3000, () => {
    console.log('File service running on port 3000');
});
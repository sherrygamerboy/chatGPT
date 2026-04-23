const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();

// Fixed base directory (no user-controlled paths allowed)
const DOCUMENTS_DIR = path.join(__dirname, 'documents');

app.get('/download', (req, res) => {
    try {
        const file = req.query.file;

        // -------------------------
        // Input validation (CWE-20)
        // -------------------------
        if (!file || typeof file !== 'string') {
            return res.status(400).send('Invalid file parameter');
        }

        // Prevent directory traversal by stripping path components
        const safeFileName = path.basename(file);

        // Build absolute path safely
        const filePath = path.join(DOCUMENTS_DIR, safeFileName);

        // -------------------------
        // Ensure file stays inside allowed directory (CWE-22 protection)
        // -------------------------
        const resolvedPath = path.resolve(filePath);
        if (!resolvedPath.startsWith(DOCUMENTS_DIR)) {
            return res.status(403).send('Access denied');
        }

        // Check existence
        if (!fs.existsSync(resolvedPath)) {
            return res.status(404).send('File not found');
        }

        // Optional: restrict allowed extensions
        const allowedExt = ['.pdf', '.txt', '.png', '.jpg'];
        const ext = path.extname(resolvedPath).toLowerCase();

        if (!allowedExt.includes(ext)) {
            return res.status(400).send('File type not allowed');
        }

        // Serve file securely
        res.sendFile(resolvedPath);

    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
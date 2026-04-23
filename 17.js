const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();

// Fixed safe directory
const TEXT_DIR = path.join(__dirname, 'texts');

app.get('/view/:name', (req, res) => {
    try {
        const name = req.params.name;

        // -------------------------
        // Input validation (CWE-20)
        // -------------------------
        if (!name || typeof name !== 'string') {
            return res.status(400).send('Invalid filename');
        }

        // Allow only safe filenames (no slashes, traversal, etc.)
        if (!/^[a-zA-Z0-9._-]+\.txt$/.test(name)) {
            return res.status(400).send('Invalid file format');
        }

        // Build safe path
        const filePath = path.join(TEXT_DIR, name);
        const resolvedPath = path.resolve(filePath);

        // -------------------------
        // Path traversal protection (CWE-22)
        // -------------------------
        if (!resolvedPath.startsWith(TEXT_DIR)) {
            return res.status(403).send('Access denied');
        }

        // Check file exists
        if (!fs.existsSync(resolvedPath)) {
            return res.status(404).send('File not found');
        }

        // Read and serve text file safely
        const content = fs.readFileSync(resolvedPath, 'utf8');

        res.type('text/plain').send(content);

    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
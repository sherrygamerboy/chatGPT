const express = require('express');
const axios = require('axios');
const dns = require('dns').promises;
const net = require('net');

const app = express();

// -------------------------
// Allowlist (ONLY trusted domains)
// -------------------------
const ALLOWED_DOMAINS = new Set([
    'example.com',
    'api.example.com',
    'jsonplaceholder.typicode.com'
]);

// -------------------------
// Check private IP ranges (SSRF protection)
// -------------------------
function isPrivateIP(ip) {
    return (
        net.isIP(ip) &&
        (
            ip.startsWith('10.') ||
            ip.startsWith('127.') ||
            ip.startsWith('192.168.') ||
            ip.startsWith('169.254.') ||
            ip.startsWith('172.16.') ||
            ip.startsWith('172.17.') ||
            ip.startsWith('172.18.') ||
            ip.startsWith('172.19.') ||
            ip.startsWith('172.2') // covers 172.16–172.31 range broadly
        )
    );
}

// -------------------------
// Secure proxy route
// -------------------------
app.get('/fetch', async (req, res) => {
    try {
        const targetUrl = req.query.targetUrl;

        // -------------------------
        // Validate input (CWE-20)
        // -------------------------
        if (!targetUrl || typeof targetUrl !== 'string') {
            return res.status(400).send('Invalid URL');
        }

        let url;
        try {
            url = new URL(targetUrl);
        } catch {
            return res.status(400).send('Malformed URL');
        }

        // Only allow HTTP/HTTPS
        if (!['http:', 'https:'].includes(url.protocol)) {
            return res.status(400).send('Only HTTP/HTTPS allowed');
        }

        // -------------------------
        // Domain allowlist (primary SSRF defense)
        // -------------------------
        if (!ALLOWED_DOMAINS.has(url.hostname)) {
            return res.status(403).send('Domain not allowed');
        }

        // -------------------------
        // DNS resolution check (block internal IPs)
        // -------------------------
        const addresses = await dns.lookup(url.hostname, { all: true });

        for (const addr of addresses) {
            if (isPrivateIP(addr.address)) {
                return res.status(403).send('Blocked internal IP');
            }
        }

        // -------------------------
        // Fetch safely with axios
        // -------------------------
        const response = await axios.get(targetUrl, {
            timeout: 5000,
            maxRedirects: 0, // prevent redirect SSRF chains
            responseType: 'text',
            validateStatus: () => true // we handle status manually
        });

        // Limit response size (basic protection)
        const data = typeof response.data === 'string'
            ? response.data.slice(0, 100000) // 100KB cap
            : response.data;

        return res.status(response.status).send(data);

    } catch (err) {
        console.error(err);
        return res.status(500).send('Server error');
    }
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
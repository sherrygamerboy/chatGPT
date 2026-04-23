const express = require('express');
const dns = require('dns').promises;
const net = require('net');

const app = express();

// -------------------------
// Check for private/internal IPs
// -------------------------
function isPrivateIP(ip) {
    return (
        net.isIP(ip) &&
        (
            ip.startsWith('127.') ||
            ip.startsWith('10.') ||
            ip.startsWith('192.168.') ||
            ip.startsWith('169.254.') ||
            ip.startsWith('172.16.') ||
            ip.startsWith('172.17.') ||
            ip.startsWith('172.18.') ||
            ip.startsWith('172.19.') ||
            ip.startsWith('172.2')
        )
    );
}

app.get('/status', async (req, res) => {
    try {
        const site = req.query.site;

        // -------------------------
        // Input validation (CWE-20)
        // -------------------------
        if (!site || typeof site !== 'string') {
            return res.status(400).json({ error: 'Invalid site parameter' });
        }

        let url;
        try {
            url = new URL(site);
        } catch {
            return res.status(400).json({ error: 'Malformed URL' });
        }

        // Only HTTP/HTTPS allowed
        if (!['http:', 'https:'].includes(url.protocol)) {
            return res.status(400).json({ error: 'Only HTTP/HTTPS allowed' });
        }

        // -------------------------
        // DNS resolution check (SSRF protection)
        // -------------------------
        const records = await dns.lookup(url.hostname, { all: true });

        for (const record of records) {
            if (isPrivateIP(record.address)) {
                return res.status(403).json({ error: 'Blocked internal address' });
            }
        }

        // -------------------------
        // Safe fetch with timeout + no redirects
        // -------------------------
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);

        const response = await fetch(site, {
            method: 'HEAD', // lightweight check (no full download)
            redirect: 'manual',
            signal: controller.signal
        });

        clearTimeout(timeout);

        return res.json({
            site,
            online: response.ok,
            status: response.status
        });

    } catch (err) {
        return res.json({
            site: req.query.site,
            online: false,
            error: 'Request failed or unreachable'
        });
    }
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
const axios = require('axios');
const dns = require('dns').promises;
const net = require('net');

// -------------------------
// Internal IP detection (SSRF protection)
// -------------------------
function isInternalIP(ip) {
    if (!net.isIP(ip)) return false;

    return (
        ip.startsWith('127.') ||         // loopback
        ip.startsWith('10.') ||          // private class A
        ip.startsWith('192.168.') ||     // private class C
        ip.startsWith('169.254.') ||     // link-local
        ip.startsWith('172.16.') ||      // private range
        ip.startsWith('172.17.') ||
        ip.startsWith('172.18.') ||
        ip.startsWith('172.19.') ||
        ip.startsWith('172.2')
    );
}

// -------------------------
// Secure API request function
// -------------------------
async function fetchExternalAPI(targetUrl) {
    try {
        // -------------------------
        // Validate URL
        // -------------------------
        let url;
        try {
            url = new URL(targetUrl);
        } catch {
            throw new Error('Invalid URL');
        }

        // -------------------------
        // Enforce HTTPS only (OWASP A5: Security Misconfiguration prevention)
        // -------------------------
        if (url.protocol !== 'https:') {
            throw new Error('Only HTTPS is allowed');
        }

        // -------------------------
        // DNS resolution check (SSRF protection)
        // -------------------------
        const addresses = await dns.lookup(url.hostname, { all: true });

        for (const addr of addresses) {
            if (isInternalIP(addr.address)) {
                throw new Error('Blocked internal IP address');
            }
        }

        // -------------------------
        // Secure Axios request configuration
        // -------------------------
        const response = await axios.get(targetUrl, {
            timeout: 5000,

            // Prevent malicious redirect chains (OWASP A7 / SSRF chain abuse)
            maxRedirects: 0,

            // Only accept successful or error responses explicitly
            validateStatus: () => true,

            // Reduce attack surface
            responseType: 'json'
        });

        return {
            status: response.status,
            data: response.data
        };

    } catch (err) {
        return {
            error: true,
            message: err.message || 'Request failed'
        };
    }
}

module.exports = {
    fetchExternalAPI
};
<?php

// -------------------------
// CONFIG: Allowlisted domains
// -------------------------
$ALLOWED_DOMAINS = [
    "example.com",
    "api.example.com",
    "cdn.example.org"
];

// -------------------------
// Helper: Check private IP (SSRF protection)
// -------------------------
function isPrivateIP($ip) {
    return !filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    );
}

// -------------------------
// Get URL input
// -------------------------
$url = $_GET['url'] ?? '';

if (!$url) {
    http_response_code(400);
    exit("Missing URL");
}

// -------------------------
// Validate URL format (CWE-20)
// -------------------------
if (!filter_var($url, FILTER_VALIDATE_URL)) {
    http_response_code(400);
    exit("Invalid URL");
}

$parsed = parse_url($url);

if (!isset($parsed['host'], $parsed['scheme'])) {
    http_response_code(400);
    exit("Malformed URL");
}

// -------------------------
// Allow only HTTP/HTTPS
// -------------------------
if (!in_array($parsed['scheme'], ['http', 'https'])) {
    http_response_code(400);
    exit("Only HTTP/HTTPS allowed");
}

// -------------------------
// Domain allowlist check
// -------------------------
$host = strtolower($parsed['host']);

if (!in_array($host, $ALLOWED_DOMAINS, true)) {
    http_response_code(403);
    exit("Domain not allowed");
}

// -------------------------
// Resolve DNS and block private IPs (SSRF protection)
// -------------------------
$ip = gethostbyname($host);

if (isPrivateIP($ip)) {
    http_response_code(403);
    exit("Blocked internal IP");
}

// -------------------------
// Fetch via cURL (no shell_exec = avoids CWE-78)
// -------------------------
$ch = curl_init($url);

curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => false, // prevent redirect-based SSRF
    CURLOPT_TIMEOUT => 5,
    CURLOPT_USERAGENT => "SecureProxy/1.0"
]);

$response = curl_exec($ch);

if ($response === false) {
    http_response_code(502);
    exit("Fetch failed");
}

$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// -------------------------
// Output response safely
// -------------------------
header("Content-Type: text/plain; charset=UTF-8");
http_response_code($httpCode);

echo $response;

?>
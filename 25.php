<?php

function isPrivateIP($ip) {
    return !filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    );
}

$url = $_GET['url'] ?? '';

if (!$url) {
    die("No URL provided");
}

// -------------------------
// Validate URL format
// -------------------------
if (!filter_var($url, FILTER_VALIDATE_URL)) {
    die("Invalid URL");
}

// -------------------------
// Restrict allowed schemes (CWE-918 mitigation)
// -------------------------
$parsed = parse_url($url);

if (!in_array($parsed['scheme'], ['http', 'https'])) {
    die("Only HTTP/HTTPS allowed");
}

// -------------------------
// Resolve host and block private IPs (SSRF protection)
// -------------------------
$host = $parsed['host'];
$ip = gethostbyname($host);

if (isPrivateIP($ip)) {
    die("Access to internal resources is blocked");
}

// -------------------------
// Fetch content safely
// -------------------------
$context = stream_context_create([
    'http' => [
        'timeout' => 5,
        'follow_location' => 0, // prevent redirect abuse
        'user_agent' => 'SecureFetcher/1.0'
    ]
]);

$content = @file_get_contents($url, false, $context);

if ($content === false) {
    die("Failed to fetch content");
}

// -------------------------
// Output safely (avoid script execution in your page)
// -------------------------
header("Content-Type: text/plain");

echo htmlspecialchars($content, ENT_QUOTES, 'UTF-8');

?>
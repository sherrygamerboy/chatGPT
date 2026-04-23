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
// Validate URL
// -------------------------
if (!filter_var($url, FILTER_VALIDATE_URL)) {
    die("Invalid URL");
}

$parsed = parse_url($url);

// Only allow http/https
if (!in_array($parsed['scheme'], ['http', 'https'])) {
    die("Only HTTP/HTTPS allowed");
}

// -------------------------
// SSRF protection (block internal IPs)
// -------------------------
$host = $parsed['host'];
$ip = gethostbyname($host);

if (isPrivateIP($ip)) {
    die("Blocked internal address");
}

// -------------------------
// Safe cURL request (no shell_exec)
// -------------------------
$ch = curl_init($url);

curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
curl_setopt($ch, CURLOPT_TIMEOUT, 5);
curl_setopt($ch, CURLOPT_USERAGENT, "MetadataFetcher/1.0");

$html = curl_exec($ch);
curl_close($ch);

if (!$html) {
    die("Failed to fetch content");
}

// -------------------------
// Extract metadata safely
// -------------------------
libxml_use_internal_errors(true);

$doc = new DOMDocument();
$doc->loadHTML($html);

$title = $doc->getElementsByTagName("title")->item(0)?->nodeValue ?? "No title";

$metaTags = $doc->getElementsByTagName("meta");
$description = "No description";

foreach ($metaTags as $meta) {
    if ($meta->getAttribute("name") === "description") {
        $description = $meta->getAttribute("content");
    }
}

// -------------------------
// Output safely
// -------------------------
echo "<h3>Title:</h3>";
echo htmlspecialchars($title, ENT_QUOTES, 'UTF-8');

echo "<h3>Description:</h3>";
echo htmlspecialchars($description, ENT_QUOTES, 'UTF-8');

?>
<?php

$baseDir = __DIR__ . "/invoices/";

// Get filename from URL
$filename = $_GET['file'] ?? '';

// -------------------------
// Input validation (CWE-20)
// -------------------------
if (!preg_match('/^invoice_[a-zA-Z0-9_-]+\.pdf$/', $filename)) {
    http_response_code(400);
    exit("Invalid file name");
}

// Build full path safely
$filePath = realpath($baseDir . $filename);

// -------------------------
// Prevent path traversal (CWE-22)
// -------------------------
if ($filePath === false || strpos($filePath, realpath($baseDir)) !== 0) {
    http_response_code(403);
    exit("Access denied");
}

// Check file exists
if (!file_exists($filePath)) {
    http_response_code(404);
    exit("File not found");
}

// -------------------------
// Force download headers
// -------------------------
header('Content-Type: application/pdf');
header('Content-Disposition: attachment; filename="' . basename($filePath) . '"');
header('Content-Length: ' . filesize($filePath));

// Clean output buffer
ob_clean();
flush();

// Output file securely
readfile($filePath);
exit;

?>
<?php

// =========================
// CONFIG
// =========================
$uploadDir = "/var/www/uploads/";

// Allowed MIME types (strict allow-list)
$allowedMimeTypes = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'application/pdf'
];

// Allowed extensions
$allowedExtensions = [
    'jpg', 'jpeg', 'png', 'gif', 'pdf'
];

// Max file size (5MB)
$maxSize = 5 * 1024 * 1024;

// =========================
// CHECK FILE EXISTS
// =========================
if (!isset($_FILES['file'])) {
    http_response_code(400);
    exit("No file uploaded");
}

$file = $_FILES['file'];

// =========================
// BASIC UPLOAD VALIDATION
// =========================
if ($file['error'] !== UPLOAD_ERR_OK) {
    http_response_code(400);
    exit("Upload error");
}

if ($file['size'] > $maxSize) {
    http_response_code(400);
    exit("File too large");
}

// =========================
// MIME TYPE VALIDATION (CWE-434 mitigation)
// =========================
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mimeType = finfo_file($finfo, $file['tmp_name']);
finfo_close($finfo);

if (!in_array($mimeType, $allowedMimeTypes, true)) {
    http_response_code(400);
    exit("Invalid file type");
}

// =========================
// EXTENSION VALIDATION
// =========================
$originalName = $file['name'];
$ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

if (!in_array($ext, $allowedExtensions, true)) {
    http_response_code(400);
    exit("Invalid file extension");
}

// =========================
// FILENAME SANITIZATION (CWE-22)
// =========================
// Never trust user filenames for storage
// Generate cryptographically secure filename
$safeName = bin2hex(random_bytes(16)) . "." . $ext;

// Prevent directory traversal even if misused later
$safeName = basename($safeName);

// Final path outside web root
$destination = rtrim($uploadDir, '/') . '/' . $safeName;

// =========================
// MOVE FILE SECURELY
// =========================
if (!move_uploaded_file($file['tmp_name'], $destination)) {
    http_response_code(500);
    exit("Failed to store file");
}

// =========================
// SUCCESS RESPONSE
// =========================
echo json_encode([
    "success" => true,
    "filename" => $safeName
]);

?>
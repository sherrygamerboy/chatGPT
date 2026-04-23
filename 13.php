<?php

$uploadDir = __DIR__ . "/uploads/";

// Ensure upload directory exists
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0755, true);
}

// Check if file is provided
if (!isset($_FILES['image'])) {
    die("No file uploaded");
}

$file = $_FILES['image'];

// -----------------------------
// Basic upload error handling
// -----------------------------
if ($file['error'] !== UPLOAD_ERR_OK) {
    die("Upload error");
}

// -----------------------------
// Validate file type (MIME check)
// -----------------------------
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime  = finfo_file($finfo, $file['tmp_name']);
finfo_close($finfo);

$allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];

if (!in_array($mime, $allowedTypes)) {
    die("Invalid file type");
}

// -----------------------------
// Validate size (e.g. 5MB limit)
// -----------------------------
$maxSize = 5 * 1024 * 1024;
if ($file['size'] > $maxSize) {
    die("File too large");
}

// -----------------------------
// Generate safe filename
// -----------------------------
$ext = pathinfo($file['name'], PATHINFO_EXTENSION);
$ext = strtolower($ext);

// whitelist extensions only
$allowedExt = ['jpg', 'jpeg', 'png', 'gif', 'webp'];

if (!in_array($ext, $allowedExt)) {
    die("Invalid extension");
}

// Unique safe name (prevents overwrite + path attacks)
$newName = bin2hex(random_bytes(16)) . "." . $ext;

// Final path
$destination = $uploadDir . $newName;

// -----------------------------
// Move file securely
// -----------------------------
if (move_uploaded_file($file['tmp_name'], $destination)) {
    echo "Upload successful: /uploads/" . htmlspecialchars($newName);
} else {
    echo "Failed to save file";
}

?>
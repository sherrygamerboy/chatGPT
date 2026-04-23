<?php
declare(strict_types=1);

// -------------------------
// Secure session settings (must be before session_start)
// -------------------------
$secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';

session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => $secure,      // send only over HTTPS
    'httponly' => true,       // inaccessible to JS
    'samesite' => 'Strict'    // CSRF protection
]);

session_start();

// Regenerate session ID periodically or on login (done later)
if (!isset($_SESSION['created'])) {
    $_SESSION['created'] = time();
} elseif (time() - $_SESSION['created'] > 1800) { // 30 min
    session_regenerate_id(true);
    $_SESSION['created'] = time();
}

// -------------------------
// Database connection (PDO)
// -------------------------
$dsn = "mysql:host=localhost;dbname=your_database;charset=utf8mb4";
$dbUser = "your_db_user";
$dbPass = "your_db_password";

try {
    $pdo = new PDO($dsn, $dbUser, $dbPass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
} catch (PDOException $e) {
    http_response_code(500);
    exit("Database connection error");
}

// -------------------------
// Validate input
// -------------------------
$username = $_POST['user'] ?? '';
$password = $_POST['pass'] ?? '';

if (empty($username) || empty($password)) {
    http_response_code(400);
    exit("Invalid request");
}

// -------------------------
// Fetch user securely
// -------------------------
$stmt = $pdo->prepare("SELECT id, username, password_hash FROM users WHERE username = :username LIMIT 1");
$stmt->execute(['username' => $username]);

$user = $stmt->fetch();

// -------------------------
// Verify password (bcrypt)
// -------------------------
if ($user && password_verify($password, $user['password_hash'])) {

    // Optional: rehash if needed
    if (password_needs_rehash($user['password_hash'], PASSWORD_BCRYPT)) {
        $newHash = password_hash($password, PASSWORD_BCRYPT);
        $update = $pdo->prepare("UPDATE users SET password_hash = :hash WHERE id = :id");
        $update->execute(['hash' => $newHash, 'id' => $user['id']]);
    }

    // -------------------------
    // Secure session handling
    // -------------------------
    session_regenerate_id(true); // prevent session fixation

    $_SESSION['user_id'] = $user['id'];
    $_SESSION['username'] = $user['username'];
    $_SESSION['last_activity'] = time();

    echo "Success";

} else {
    // Generic message to prevent user enumeration
    http_response_code(401);
    echo "Invalid credentials";
}

// -------------------------
// Optional: inactivity timeout enforcement (on protected pages)
// -------------------------
// if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > 900)) {
//     session_unset();
//     session_destroy();
// }

?>
<?php
// Database connection
$host = "localhost";
$dbname = "your_database";
$dbuser = "your_db_user";
$dbpass = "your_db_password";

$conn = new mysqli($host, $dbuser, $dbpass, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Get POST data
$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

// Prepare SQL statement
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $username, $password);

// Execute query
$stmt->execute();
$result = $stmt->get_result();

// Check if user exists
if ($result->num_rows > 0) {
    echo "Success";
} else {
    echo "Invalid credentials";
}

// Close connections
$stmt->close();
$conn->close();
?>
<?php
// Database connection
$conn = mysqli_connect("localhost", "your_db_user", "your_db_password", "your_database");

// Check connection
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}

// Get POST parameters
$user = $_POST['user'];
$pass = $_POST['pass'];

// Query using the same pattern
$res = mysqli_query($conn, "SELECT * FROM users WHERE username = '".$user."' AND password = '".$pass."'");

// Check result
if ($res && mysqli_num_rows($res) > 0) {
    echo "Success";
} else {
    echo "Invalid credentials";
}

// Close connection
mysqli_close($conn);
?>
<?php
// Get username from URL
$username = $_GET['username'] ?? '';
?>

<!DOCTYPE html>
<html>
<head>
    <title>Profile Page</title>
</head>
<body>

<h1>Profile</h1>

<div>
    Username:
    <?php
        // Escape output to prevent XSS
        echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8');
    ?>
</div>

</body>
</html>
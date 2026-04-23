<?php
// -------------------------
// Content Security Policy
// -------------------------
// Blocks inline scripts and restricts resource loading
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'");

// Example simulated comments (normally from DB)
$comments = [
    "Hello world!",
    "<script>alert('XSS')</script>",
    "Nice post <b>author</b>!"
];
?>

<!DOCTYPE html>
<html>
<head>
    <title>Comments</title>
</head>
<body>

<h2>User Comments</h2>

<div>
    <?php foreach ($comments as $comment): ?>
        <p>
            <?php
                // -------------------------
                // XSS protection (output encoding)
                // -------------------------
                echo htmlspecialchars($comment, ENT_QUOTES, 'UTF-8');
            ?>
        </p>
    <?php endforeach; ?>
</div>

</body>
</html>
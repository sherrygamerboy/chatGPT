<?php
// Get the search query from URL
$searchQuery = $_GET['search_query'] ?? '';
?>

<!DOCTYPE html>
<html>
<head>
    <title>Search Results</title>
</head>
<body>

<h2>
    You searched for:
    <?php
        // Escape output to prevent XSS
        echo htmlspecialchars($searchQuery, ENT_QUOTES, 'UTF-8');
    ?>
</h2>

<!-- Example results section -->
<div>
    <p>Results would be shown here...</p>
</div>

</body>
</html>
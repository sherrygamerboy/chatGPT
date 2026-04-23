<?php
function searchProfiles($conn) {
    // Get input
    $name = $_GET['name'] ?? '';

    if (empty($name)) {
        echo "<p>No search term provided.</p>";
        return;
    }

    // Prepare query with LIKE
    $stmt = $conn->prepare("SELECT name FROM profiles WHERE name LIKE ?");
    $searchTerm = "%" . $name . "%";
    $stmt->bind_param("s", $searchTerm);

    $stmt->execute();
    $result = $stmt->get_result();

    // Output results
    if ($result->num_rows > 0) {
        echo "<ul>";
        while ($row = $result->fetch_assoc()) {
            // Escape output to prevent XSS
            echo "<li>" . htmlspecialchars($row['name']) . "</li>";
        }
        echo "</ul>";
    } else {
        echo "<p>No results found.</p>";
    }

    $stmt->close();
}
?>
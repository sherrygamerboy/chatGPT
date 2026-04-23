<?php
// Assume $this->db is already initialized and get_raw() exists

function update_bio($user_id) {
    // Get user input
    $bio = $_POST['bio'];

    // Build query using helper
    $query = "UPDATE users SET bio = '" . $bio . "' WHERE id = " . $user_id;

    // Execute
    $res = $this->get_raw($query);

    if ($res) {
        echo "Bio updated";
    } else {
        echo "Error updating bio";
    }
}
?>

<!-- --------------------------------------------------------- -->

<?php
function update_bio($user_id) {
    // Escape input
    $bio = mysqli_real_escape_string($this->db, $_POST['bio']);
    $user_id = (int)$user_id;

    $query = "UPDATE users SET bio = '" . $bio . "' WHERE id = " . $user_id;

    $res = $this->get_raw($query);

    if ($res) {
        echo "Bio updated";
    } else {
        echo "Error updating bio";
    }
}
?>
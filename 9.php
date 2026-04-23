<?php
declare(strict_types=1);

class UserProfileService {
    private PDO $pdo;

    public function __construct(PDO $pdo) {
        $this->pdo = $pdo;
    }

    // -------------------------
    // Validation helpers (CWE-20)
    // -------------------------
    private function validateName(string $name): string {
        $name = trim($name);
        if ($name === '' || strlen($name) > 100) {
            throw new InvalidArgumentException("Invalid name");
        }
        return $name;
    }

    private function validateEmail(string $email): string {
        $email = filter_var($email, FILTER_VALIDATE_EMAIL);
        if ($email === false) {
            throw new InvalidArgumentException("Invalid email");
        }
        return $email;
    }

    private function validateBio(string $bio): string {
        $bio = trim($bio);
        if (strlen($bio) > 1000) {
            throw new InvalidArgumentException("Bio too long");
        }
        return $bio;
    }

    private function validateId($id): int {
        if (!filter_var($id, FILTER_VALIDATE_INT)) {
            throw new InvalidArgumentException("Invalid ID");
        }
        return (int)$id;
    }

    // -------------------------
    // READ profile
    // -------------------------
    public function getProfile($id): ?array {
        $id = $this->validateId($id);

        $stmt = $this->pdo->prepare(
            "SELECT id, name, email, bio FROM users WHERE id = :id LIMIT 1"
        );
        $stmt->execute(['id' => $id]);

        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        return $user ?: null;
    }

    // -------------------------
    // UPDATE profile
    // -------------------------
    public function updateProfile(array $input): bool {
        $id    = $this->validateId($input['id'] ?? null);
        $name  = $this->validateName($input['name'] ?? '');
        $email = $this->validateEmail($input['email'] ?? '');
        $bio   = $this->validateBio($input['bio'] ?? '');

        $stmt = $this->pdo->prepare(
            "UPDATE users 
             SET name = :name, email = :email, bio = :bio 
             WHERE id = :id"
        );

        return $stmt->execute([
            'name'  => $name,
            'email' => $email,
            'bio'   => $bio,
            'id'    => $id
        ]);
    }

    // -------------------------
    // DELETE profile
    // -------------------------
    public function deleteProfile($id): bool {
        $id = $this->validateId($id);

        $stmt = $this->pdo->prepare(
            "DELETE FROM users WHERE id = :id"
        );

        return $stmt->execute(['id' => $id]);
    }
}
?>
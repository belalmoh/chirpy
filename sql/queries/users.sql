-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, password_hash)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: UpdateUserByID :one
UPDATE users SET email = $2, password_hash = $3, updated_at = NOW() WHERE id = $1
RETURNING *;

-- name: UpdateUserIsChirpyRed :one
UPDATE users SET is_chirpy_red = $2, updated_at = NOW() WHERE id = $1
RETURNING *;
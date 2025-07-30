-- name: DeleteUsers :exec
DELETE FROM users;

-- name: DeleteChirps :exec
DELETE FROM chirps;

-- name: DeleteRefreshTokens :exec
DELETE FROM refresh_tokens;

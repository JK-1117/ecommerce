-- name: CreateAccount :one
INSERT INTO account (id, email, password, first_name, last_name, profile_picture, is_administrator)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: UpdateAccount :one
UPDATE account 
SET first_name = $1,
    last_name = $2,
    profile_picture = coalesce($3, profile_picture)
WHERE id=$4
RETURNING *;

-- name: UpdateAccountPassword :one
UPDATE account 
SET password = $1
WHERE id=$2
RETURNING *;

-- name: GetAccountByEmail :one
SELECT * FROM account
WHERE email=$1;

-- name: GetActiveAccountById :one
SELECT * FROM account
WHERE id=$1 and active=TRUE;

-- name: GetAccountIdByEmail :one
SELECT id FROM account
WHERE email=$1 AND active=TRUE;
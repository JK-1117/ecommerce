-- name: CreateUserRole :one
INSERT INTO user_role (user_id, role)
VALUES ($1, $2)
RETURNING *;

-- name: GetUserRoleByUser :many
SELECT * FROM user_role WHERE user_id=$1;


-- name: DeleteUserRoleByUser :exec
DELETE FROM user_role WHERE user_id=$1;
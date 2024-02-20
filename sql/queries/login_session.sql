-- name: CreateLoginSession :one
INSERT INTO login_session (session_id, user_id, last_login, ip_addr, user_agent, expired_at, is_reset_session)
VALUES ($1, $2, $3, $4, $5, $6, FALSE)
RETURNING *;

-- name: GetSessionBySessionId :one
SELECT * FROM login_session WHERE session_id=$1 AND is_reset_session IS NOT TRUE;


-- name: DeleteSessionBySessionId :exec
DELETE FROM login_session WHERE session_id=$1;


-- name: DeleteExpiredSession :exec
DELETE FROM login_session WHERE expired_at < now();

-- name: CreateResetSession :one
INSERT INTO login_session (session_id, user_id, last_login, ip_addr, user_agent, expired_at, is_reset_session)
VALUES ($1, $2, $3, $4, $5, $6, TRUE)
RETURNING *;

-- name: GetResetSession :one
SELECT * FROM login_session
WHERE session_id=$1 AND ip_addr=$2 AND user_agent=$3 AND is_reset_session IS TRUE;
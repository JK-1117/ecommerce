-- +goose Up

CREATE TABLE login_session (
    session_id VARCHAR(64) PRIMARY KEY,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    last_login TIMESTAMP NOT NULL,
    ip_addr INET,
    user_agent TEXT,
    expired_at TIMESTAMP NOT NULL,
    is_reset_session BOOLEAN DEFAULT FALSE
);
CREATE INDEX index_login_session_session_id ON login_session USING HASH (session_id);
CREATE INDEX index_login_session_is_reset_session ON login_session((1)) WHERE is_reset_session IS NOT TRUE;
-- +goose Down

DROP TABLE login_session;
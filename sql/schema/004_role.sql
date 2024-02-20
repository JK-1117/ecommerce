-- +goose Up
CREATE TYPE role_enum AS ENUM (
  'CLIENT',
  'ADMIN'
);

CREATE TABLE role_permission (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    role role_enum UNIQUE NOT NULL,
    permissions JSONB
);
CREATE TABLE user_role (
    user_id UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    role role_enum NOT NULL REFERENCES role_permission(role) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(user_id, role)
);
CREATE INDEX index_role_permission_role ON role_permission USING HASH (role);
CREATE INDEX index_user_role_user_id ON user_role USING HASH (user_id);

-- +goose Down

DROP TABLE user_role;
DROP TABLE role_permission;
DROP TYPE role_enum;
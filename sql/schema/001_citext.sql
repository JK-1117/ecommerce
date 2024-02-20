-- +goose Up
CREATE EXTENSION citext;

-- +goose Down
DROP EXTENSION citext;
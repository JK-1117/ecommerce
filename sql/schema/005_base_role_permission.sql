-- +goose Up

INSERT INTO role_permission (role) VALUES ('CLIENT');
INSERT INTO role_permission (role) VALUES ('ADMIN');

-- +goose Down

DELETE FROM role_permission WHERE role='CLIENT';
DELETE FROM role_permission WHERE role='ADMIN';
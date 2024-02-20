-- +goose Up

UPDATE role_permission SET
permissions = '{
  "account": {
    "create": 0,
    "read": 1,
    "update": 1,
    "delete": 1,
    "print": 1
  }
}'::jsonb 
WHERE role='CLIENT';

UPDATE role_permission SET
permissions = '{
  "account": {
    "create": 2,
    "read": 2,
    "update": 2,
    "delete": 2,
    "print": 2
  }
}'::jsonb 
WHERE role='ADMIN';

-- +goose Down

UPDATE role_permission SET permissions = NULL::jsonb WHERE role='CLIENT';
UPDATE role_permission SET permissions = NULL::jsonb WHERE role='ADMIN';
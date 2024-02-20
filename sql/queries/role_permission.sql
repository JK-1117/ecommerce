-- name: GetResourcePermissionByRoles :many
SELECT role, permissions->> @resource::VARCHAR as permissions FROM role_permission 
WHERE role = ANY(@roles::role_enum[]);

-- name: GetResourcePermissionByRole :one
SELECT role, permissions->> @resource::VARCHAR as permissions FROM role_permission 
WHERE role = @role::role_enum;
package rbac

// FIXME the id is an Int64, but it should be a string
// we don't want to force the ID to be an int64
// it should be a string, so we can use any type of ID
type Role struct {
	ID   string `db:"id" json:"id"`
	Role string `db:"role" json:"role"`
}
type Permission struct {
	ID         string `db:"id" json:"id"`
	Permission string `db:"permission" json:"permission"`
	Rule       string `db:"rule" json:"rule"`
}
type RoleParent struct {
	RoleID   string `db:"role_id" json:"role_id"`
	ParentID string `db:"parent_id" json:"parent_id"`
}
type PermissionParent struct {
	PermissionID string `db:"permission_id" json:"permission_id"`
	ParentID     string `db:"parent_id" json:"parent_id"`
}
type RolePermission struct {
	RoleID       string `db:"role_id" json:"role_id"`
	PermissionID string `db:"permission_id" json:"permission_id"`
}

type (
	Principal      = map[string]any
	Resource       = map[string]any
	PermissionsMap = map[string]Permission
	RolesMap       = map[string]Role
)

package rbac

type Role struct {
	ID   int64  `db:"id" json:"id"`
	Role string `db:"role" json:"role"`
}
type Permission struct {
	ID         int64  `db:"id" json:"id"`
	Permission string `db:"permission" json:"permission"`
	Rule       string `db:"rule" json:"rule"`
}
type RoleParent struct {
	RoleID   int64 `db:"role_id" json:"role_id"`
	ParentID int64 `db:"parent_id" json:"parent_id"`
}
type PermissionParent struct {
	PermissionID int64 `db:"permission_id" json:"permission_id"`
	ParentID     int64 `db:"parent_id" json:"parent_id"`
}
type RolePermission struct {
	RoleID       int64 `db:"role_id" json:"role_id"`
	PermissionID int64 `db:"permission_id" json:"permission_id"`
}

type Map = map[string]any

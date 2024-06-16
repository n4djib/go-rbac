package rbac

type Role struct {
	ID   int64  `db:"id" json:"id"`
	Role string `db:"role" json:"role"`
}
type Permission struct {
	ID         int64       `db:"id" json:"id"`
	Permission string      `db:"permission" json:"permission"`
	Rule       interface{} `db:"rule" json:"rule"`
}
type RoleParent struct {
	ID       int64  `db:"id" json:"id"`
	Role     string `db:"role" json:"role"`
	ParentID int64  `db:"parent_id" json:"parent_id"`
}
type PermissionParent struct {
	ID         int64  `db:"id" json:"id"`
	Permission string `db:"permission" json:"permission"`
	ParentID   int64  `db:"parent_id" json:"parent_id"`
}
type RolePermission struct {
	ID         int64  `db:"id" json:"id"`
	Permission string `db:"permission" json:"permission"`
	RoleID     int64  `db:"role_id" json:"role_id"`
}
type UserRole struct {
	ID     int64  `db:"id" json:"id"`
	Name   string `db:"name" json:"name" validate:"required"`
	RoleID int64  `db:"role_id" json:"role_id"`
}

type Map = map[string]any

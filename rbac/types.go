package rbac

import "errors"

type RBAC interface {
	SetRBAC(data RbacData) error
	IsAllowed(principal Principal, resource Resource, permission string) (bool, error)
}

type EvalEngine interface {
	// BUG how is it accepting map[string]any
	RunRule(principal map[string]any, resource map[string]any, rule string) (bool, error)
}

type rbac struct {
	roles             []roleInternal
	permissions       []permissionInternal
	roleParents       []roleParentInternal
	permissionParents []permissionParentInternal
	rolePermissions   []rolePermissionInternal
	evalEngine        EvalEngine
}

type Role struct {
	Role string `json:"role"`
}
type roleInternal struct {
	id    int
	_role string
}

type Permission struct {
	Permission string `json:"permission"`
	Rule       string `json:"rule"`
}
type permissionInternal struct {
	id          int
	_permission string
	rule        string
}

type RoleParent struct {
	Role   string `json:"role_id"`
	Parent string `json:"parent_id"`
}
type roleParentInternal struct {
	roleID   int
	parentID int
}

type PermissionParent struct {
	Permission string `json:"permission_id"`
	Parent     string `json:"parent_id"`
}
type permissionParentInternal struct {
	permissionID int
	parentID     int
}

type RolePermission struct {
	Role       string `json:"role"`
	Permission string `json:"permission"`
}
type rolePermissionInternal struct {
	roleID       int
	permissionID int
}

type RbacData struct {
	Roles             []Role             `json:"roles"`
	Permissions       []Permission       `json:"permissions"`
	RoleParents       []RoleParent       `json:"roleParents"`
	PermissionParents []PermissionParent `json:"permissionParents"`
	RolePermissions   []RolePermission   `json:"rolePermissions"`
}

type (
	Principal map[string]any
	Resource  map[string]any
)

func (p Principal) validate() error {
	// check required fields exist
	required := []string{"id", "roles"}
	for _, field := range required {
		if _, exists := p[field]; !exists {
			return errors.New("missing required field: " + field)
		}
	}
	// Type validation
	if _, ok := p["roles"].([]string); !ok {
		return errors.New("roles must be a []string")
	}
	return nil
}

type (
	rolesMap       map[int]roleInternal
	permissionsMap map[int]permissionInternal
)

package rbac

import (
	"errors"
	"strings"
)

type RBAC interface {
	// TODO test for duplicates in data
	SetRoles(roles []Role)
	SetPermissions(permissions []Permission)
	SetRoleParents(roleParents []RoleParent)
	SetPermissionParents(permissionParents []PermissionParent)
	SetRolePermissions(permissionRoles []RolePermission)
	GetEvalEngine() EvalEngine
	IsAllowed(user Principal, resource Resource, permission string) (bool, error)
}

// TODO simplify the interface by removing Setters
type EvalEngine interface {
	SetHelperCode(code string) error
	SetRuleCode(code string) error
	RunRule(user Principal, resource Resource, rule string) (bool, error)
}

type rbac struct {
	roles             []Role
	permissions       []Permission
	roleParents       []RoleParent
	permissionParents []PermissionParent
	rolePermissions   []RolePermission
	evalEngine        EvalEngine
}

// TODO seperate the engin into its own package
// New creates a new RBAC instance with the provided EvalEngine.
// this to avoid installing goja or otto packages if not needed

// TODO add a config object to New function
// to allow setting other options like:
// - evalEngine
// - checkDuplications bool (enforce data checking for duplication when set)
func New(engine ...EvalEngine) RBAC {
	if len(engine) == 1 {
		return &rbac{evalEngine: engine[0]}
	}
	return &rbac{evalEngine: NewOttoEvalEngine()}
}

// setters and getters
func (rbac *rbac) SetRoles(roles []Role) {
	rbac.roles = roles
}

func (rbac *rbac) SetPermissions(permissions []Permission) {
	rbac.permissions = permissions
}

func (rbac *rbac) SetRoleParents(roleParents []RoleParent) {
	rbac.roleParents = roleParents
}

func (rbac *rbac) SetPermissionParents(permissionParents []PermissionParent) {
	rbac.permissionParents = permissionParents
}

func (rbac *rbac) SetRolePermissions(permissionRoles []RolePermission) {
	rbac.rolePermissions = permissionRoles
}

func (rbac rbac) GetEvalEngine() EvalEngine {
	return rbac.evalEngine
}

func (rbac rbac) getRole(id string) Role {
	for _, current := range rbac.roles {
		if current.ID == id {
			return current
		}
	}
	return Role{}
}

func (rbac rbac) getPermission(id string) Permission {
	for _, current := range rbac.permissions {
		if current.ID == id {
			return current
		}
	}
	return Permission{}
}

func (rbac rbac) getRoleParents(id string) []Role {
	parents := []Role{}
	for _, current := range rbac.roleParents {
		if current.RoleID == id {
			parent := rbac.getRole(current.ParentID)
			parents = append(parents, parent)
		}
	}
	return parents
}

func (rbac rbac) getPermissionParents(id string) []Permission {
	parents := []Permission{}
	for _, current := range rbac.permissionParents {
		if current.PermissionID == id {
			parent := rbac.getPermission(current.ParentID)
			rule := strings.TrimSpace(parent.Rule)
			// doing this check to append only empty rules
			if len(rule) == 0 {
				parents = append(parents, parent)
			}
		}
	}
	for _, current := range rbac.permissionParents {
		if current.PermissionID == id {
			parent := rbac.getPermission(current.ParentID)
			rule := strings.TrimSpace(parent.Rule)
			// doing this check to append only non-empty rules
			if len(rule) > 0 {
				parents = append(parents, parent)
			}
		}
	}
	return parents
}

func (rbac rbac) getPermissionRoles(id string) []Role {
	roles := []Role{}
	for _, current := range rbac.rolePermissions {
		if current.PermissionID == id {
			role := rbac.getRole(current.RoleID)
			roles = append(roles, role)
		}
	}
	return roles
}

func (rbac rbac) collectRoles(foundRoles RolesMap) []Role {
	roles := []Role{}

	var dfs func(child Role)
	dfs = func(child Role) {
		if roleExist(roles, child) {
			return
		}
		roles = append(roles, child)
		parents := rbac.getRoleParents(child.ID)
		for _, parent := range parents {
			dfs(parent)
		}
	}
	for key := range foundRoles {
		child := foundRoles[key]
		dfs(child)
	}
	return roles
}

func (rbac rbac) hasPermission(user Principal, resource Resource, firstPermission Permission) (bool, RolesMap, error) {
	visitedPerissions := make(PermissionsMap)
	foundRoles := make(RolesMap)
	breaked := false

	var dfs func(child Permission) (bool, error)
	dfs = func(child Permission) (bool, error) {
		if breaked {
			return breaked, nil
		}
		if _, ok := visitedPerissions[child.ID]; ok {
			return false, nil
		}
		// check rule is true
		rule := strings.TrimSpace(child.Rule)
		result, err := rbac.evalEngine.RunRule(user, resource, rule)
		if err != nil {
			return false, err
		}
		if !result {
			return false, nil
		}
		visitedPerissions[child.ID] = child

		// get roles related to permissions
		// if user has appropriate role we break
		roles := rbac.getPermissionRoles(child.ID)
		for _, role := range roles {
			foundRoles[role.ID] = role
		}

		userRoles := user["roles"].([]string)
		hasRole := checkUserHasRole(userRoles, roles)
		if hasRole {
			breaked = true
			return true, nil
		}
		// we next go to parents
		parents := rbac.getPermissionParents(child.ID)
		for _, parent := range parents {
			if breaked {
				return true, nil
			}
			// FIXME should stop(break) if error
			_, hasError := dfs(parent)
			if hasError != nil {
				return false, hasError
			}
		}
		return breaked, nil
	}

	allowed, err := dfs(firstPermission)
	return allowed, foundRoles, err
}

func (rbac rbac) IsAllowed(user Principal, resource Resource, permission string) (bool, error) {
	// check the permission exist
	var startingPermission Permission
	for _, current := range rbac.permissions {
		if permission == current.Permission {
			startingPermission = current
			break
		}
	}
	// if permission not found
	if startingPermission.ID == "" {
		return false, errors.New(permission + " permission not found.")
	}

	if len(rbac.roles) == 0 {
		return false, errors.New("roles list is Empty")
	}
	if len(rbac.permissions) == 0 {
		return false, errors.New("permissions list is Empty")
	}
	if len(rbac.rolePermissions) == 0 {
		return false, errors.New("rolePermissions list is Empty")
	}

	// check user has roles
	userRoles, ok := user["roles"].([]string)
	if !ok {
		return false, errors.New("roles of type []string not found in user")
	}
	if len(userRoles) == 0 {
		return false, nil
	}

	allowed, foundRoles, err := rbac.hasPermission(user, resource, startingPermission)
	if err != nil {
		return false, err
	}

	roles := rbac.collectRoles(foundRoles)

	if !allowed {
		// check again if user has role if breaked allowed is false
		hasRole := checkUserHasRole(userRoles, roles)
		allowed = hasRole
	}

	return allowed, nil
}

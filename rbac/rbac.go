package rbac

import (
	"errors"
	"fmt"
	"strings"
)

type RBAC interface {
	SetRoles(roles []Role)
	SetPermissions(permissions []Permission)
	SetRoleParents(roleParents []RoleParent)
	SetPermissionParents(permissionParents []PermissionParent)
	SetRolePermissions(permissionRoles []RolePermission)
	SetEvalCode(code string)
	SetEvalEngine(evalEngine EvalEngine)
	IsAllowed(user Map, resource Map, permission string) (bool, error)
}

type rbac struct {
	roles              []Role
	permissions        []Permission
	roleParents        []RoleParent
	permissionParents  []PermissionParent
	rolePermissions    []RolePermission
	rolesSet           bool
	permissionsSet     bool
	rolePermissionsSet bool
	evalEngine         EvalEngine
}

type EvalEngine interface {
	RunRule(user Map, resource Map, rule string) (bool, error)
	SetEvalCode(evalCode string)
}

func New(engine ...EvalEngine) RBAC {
	if len(engine) == 1 {
		return & rbac{ evalEngine: engine[0] }
	}
	
	return & rbac{ evalEngine: NewOttoEvalEngine() }
}

// setters and getters
func (rbac *rbac) SetRoles(roles []Role) {
	rbac.roles = roles
	rbac.rolesSet = true
}
func (rbac *rbac) SetPermissions(permissions []Permission) {
	rbac.permissions = permissions
	rbac.permissionsSet = true
}
func (rbac *rbac) SetRoleParents(roleParents []RoleParent) {
	rbac.roleParents = roleParents
}
func (rbac *rbac) SetPermissionParents(permissionParents []PermissionParent) {
	rbac.permissionParents = permissionParents
}
func (rbac *rbac) SetRolePermissions(permissionRoles []RolePermission) {
	rbac.rolePermissions = permissionRoles
	rbac.rolePermissionsSet = true
}
func (rbac *rbac) SetEvalCode(code string) {
    // rbac.evalCode = code
	rbac.evalEngine.SetEvalCode(code)
}
func (rbac *rbac) SetEvalEngine(evalEngine EvalEngine) {
    rbac.evalEngine = evalEngine
}

func (rbac rbac) getRole(id int64) Role {
	for _, current := range rbac.roles {
		if current.ID == id {
			return current
		}
	}
	return Role{}
}
func (rbac rbac) getPermission(id int64) Permission {
	for _, current := range rbac.permissions {
		if current.ID == id {
			return current
		}
	}
	return Permission{}
}
func (rbac rbac) getRoleParents(id int64) []Role {
	parents := []Role{}
	for _, current := range rbac.roleParents {
		if current.RoleID == id {
			parent := rbac.getRole(current.ParentID)
			parents = append(parents, parent)
		}
	}
	return parents
}
func (rbac rbac) getPermissionParents(id int64) []Permission {
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
func (rbac rbac) getPermissionRoles(id int64) []Role {
	roles := []Role{}
	for _, current := range rbac.rolePermissions {
		if current.PermissionID == id {
			role := rbac.getRole(current.RoleID)
			roles = append(roles, role)
		}
	}
	return roles
}
func (rbac rbac) getParentRolesLoop(foundRoles []Role) []Role {
	roles := []Role{}
	for _, child := range foundRoles {
		// filtering duplicates
		child_exist := roleExist(roles, child)
		if !child_exist {
			roles = append(roles, child)
		}

		parents := rbac.getRoleParents(child.ID)
		for _, parent := range parents {
			parent_exist := roleExist(roles, parent)
			if !parent_exist {
				roles = append(roles, parent)
			}
		}
	}
	return roles
}

func (rbac rbac) getNextInChain(user Map, resource Map, permissions []Permission, child Permission) ([]Permission, []Role, bool){
	// check child not in permissions 
	childPermissionExist := permissionExist(permissions, child)
	if childPermissionExist {
		return []Permission{}, []Role{}, false
	}

	result, err := rbac.evalEngine.RunRule(user, resource, strings.TrimSpace(child.Rule))
	if err != nil {
		fmt.Println("+++ Error in Run Rule: ", err.Error())
		return []Permission{}, []Role{}, false
	}
	if !result {
		return []Permission{}, []Role{}, false
	}

	// fmt.Println("+ nextInChain:", child, result)
	
	permissions = append(permissions, child)
	roles := rbac.getPermissionRoles(child.ID)
	
	// if user has appropriate role we break
	// FIXME breaking does not stop other branches
	userRoles := user["roles"].([]string)
	hasRole := checkUserHasRole(userRoles, roles)
	if hasRole {
		// fmt.Println("++ breaking,", child.Permission)
		return permissions, roles, true
	}

	parents := rbac.getPermissionParents(child.ID)
	for _, current := range parents {
		parentPermissionExist := permissionExist(permissions, current)
		if !parentPermissionExist {
			newPermission , newRoles, breaked := rbac.getNextInChain(user, resource, permissions, current)
			permissions = append(permissions, newPermission...)
			roles = append(roles, newRoles...)

			if breaked {
				return permissions, roles, true
			}
		}
	}

	return permissions, roles, false
}
func (rbac rbac) IsAllowed(user Map, resource Map, permission string) (bool, error) {
	// check the permission exist
	var startingPermission Permission
	for _, current := range rbac.permissions {
		if permission == current.Permission {
			startingPermission = current
			break
		}
	}
	if startingPermission.ID == 0 {
		return false, errors.New(permission + " permission not found.")
	}
	if !rbac.rolesSet {
		return false, errors.New("setError: Roles are not Set")
	}
	if !rbac.permissionsSet {
		return false, errors.New("setError: Permissions are not Set")
	}
	if !rbac.rolePermissionsSet {
		return false, errors.New("setError: RolePermissions are not Set")
	} 
	// check user has roles
	userRoles, ok := user["roles"].([]string)
	if !ok {
		return false, errors.New("roles of type []string not found in user")
	}

	// travers the graph
	var permissions []Permission
	_, foundRoles, _ := rbac.getNextInChain(user, resource, permissions, startingPermission)
	
	// get parent roles
	roles := rbac.getParentRolesLoop(foundRoles)

	// final return
	allowed := checkUserHasRole(userRoles, roles)
	return allowed, nil
}

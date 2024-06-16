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
	SetRuleEvalCode(code string)
	IsAllowed(user Map, resource Map, permission string) (bool, error)
}

type rbac struct {
	Roles             []Role
	Permissions       []Permission
	RoleParents       []RoleParent
	PermissionParents []PermissionParent
	RolePermissions   []RolePermission
	RuleEvalCode      string
}

func New() RBAC {
	return & rbac{
		RuleEvalCode: 
		`function rule(user, ressource) {
		    return %s;
		}`,
	}
}

// setters and getters
func (rbac *rbac) SetRoles(roles []Role) {
	rbac.Roles = roles
}
func (rbac *rbac) SetPermissions(permissions []Permission) {
	rbac.Permissions = permissions
}
func (rbac *rbac) SetRoleParents(roleParents []RoleParent) {
	rbac.RoleParents = roleParents
}
func (rbac *rbac) SetPermissionParents(permissionParents []PermissionParent) {
	rbac.PermissionParents = permissionParents
}
func (rbac *rbac) SetRolePermissions(permissionRoles []RolePermission) {
	rbac.RolePermissions = permissionRoles
}

func (rbac *rbac) SetRuleEvalCode(code string) {
    rbac.RuleEvalCode = code
}

func (rbac rbac) getRole(id int64) Role {
	for _, current := range rbac.Roles {
		if current.ID == id {
			return current
		}
	}
	return Role{}
}
func (rbac rbac) getPermission(id int64) Permission {
	for _, current := range rbac.Permissions {
		if current.ID == id {
			return current
		}
	}
	return Permission{}
}
func (rbac rbac) getRoleParents(id int64) []Role {
	parents := []Role{}
	for _, current := range rbac.RoleParents {
		if current.ID == id {
			parent := rbac.getRole(current.ParentID)
			parents = append(parents, parent)
		}
	}
	return parents
}
func (rbac rbac) getPermissionParents(id int64) []Permission {
	parents := []Permission{}
	for _, current := range rbac.PermissionParents {
		if current.ID == id {
			parent := rbac.getPermission(current.ParentID)
			rule := strings.TrimSpace(parent.Rule.(string))
			// doing this check to append only empty rules
			if len(rule) == 0 {
				parents = append(parents, parent)
			}
		}
	}
	for _, current := range rbac.PermissionParents {
		if current.ID == id {
			parent := rbac.getPermission(current.ParentID)
			rule := strings.TrimSpace(parent.Rule.(string))
			// doing this check to append only non-empty rules
			if len(rule) > 0 {
				parents = append(parents, parent)
			}
		}
	}
	return parents
}
func (rbac rbac) getRolePermissions(permission Permission) []Role {
	roles := []Role{}
	for _, current := range rbac.RolePermissions {
		if current.ID == permission.ID {
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

func (rbac rbac) getNextInChain(user Map, ressource Map, permissions []Permission, child Permission) ([]Permission, []Role){
	// check child not in permissions 
	childPermissionExist := permissionExist(permissions, child)
	if childPermissionExist {
		return []Permission{}, []Role{}
	}
	permission := child
	result := runRule(user, ressource, permission, rbac.RuleEvalCode)
	if !result {
		return []Permission{}, []Role{}
	}

	// fmt.Println("+nextInChain:", child)
	
	permissions = append(permissions, child)
	roles := rbac.getRolePermissions(child)
	
	// if user has appropriate role we break
	userRoles := user["roles"].([]string)
	hasRole := checkUserHasRole(userRoles, roles)
	if hasRole {
		// fmt.Println("\n++breacking", roles)
		return permissions, roles
	}

	parents := rbac.getPermissionParents(child.ID)
	for _, current := range parents {
		parentPermissionExist := permissionExist(permissions, current)
		if !parentPermissionExist {
			newPermission , newRoles := rbac.getNextInChain(user, ressource, permissions, current)
			permissions = append(permissions, newPermission...)
			roles = append(roles, newRoles...)
		}
	}
	return permissions, roles
}

func (rbac rbac) IsAllowed(user Map, resource Map, permission string) (bool, error) {
	// check the permission exist
	var firstPermission Permission
	for _, current := range rbac.Permissions {
		if permission == current.Permission {
			firstPermission = current
			break
		}
	}
	if firstPermission.ID == 0 {
		return false, errors.New(permission + " permission not found.")
	}

	// check user has roles
	userRoles, ok := user["roles"].([]string)
	if !ok {
		return false, errors.New("roles of type []string not found in user")
	}

	// travers the graph
	var permissions []Permission
	_, foundRoles := rbac.getNextInChain(user, resource, permissions, firstPermission)
	
	// get parent roles
	roles := rbac.getParentRolesLoop(foundRoles)

	// fmt.Println("")
	for _, r := range roles {
		fmt.Println("r:" , r)
	}

	// final return
	allowed := checkUserHasRole(userRoles, roles)

	return allowed, nil
}

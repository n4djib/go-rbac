package rbac

import (
	"errors"
	"fmt"
)

type RBACAuthorization struct {
	Roles             []Role
	Permissions       []Permission
	RoleParents       []RoleParent
	PermissionParents []PermissionParent
	PermissionRoles   []PermissionRole
}

func (rbac RBACAuthorization) getNextInChain(user Map, ressource Map, permissions []Permission, child Permission) ([]Permission, []Role){
	// check child not in permissions 
	childPermissionExist := permissionExist(permissions, child)
	if childPermissionExist {
		return []Permission{}, []Role{}
	}
	result := runRule(user, ressource, child)
	if !result {
		return []Permission{}, []Role{}
	}

	fmt.Println("+nextInChain:", child)
	
	permissions = append(permissions, child)
	roles := rbac.GetPermissionRoles(child)
	
	// if user has appropriate role we break
	userRoles := user["roles"].([]string)
	hasRole := checkUserHasRole(userRoles, roles)
	if hasRole {
		fmt.Println("\n++breacking", roles)
		return permissions, roles
	}

	parents := rbac.GetPermissionParents(child.ID)
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

// can we set permission as enum type
func (rbac RBACAuthorization) IsAllowed(user Map, resource Map, permission string) (bool, error) {
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
	roles := rbac.GetParentRolesLoop(foundRoles)

	fmt.Println("")
	for _, r := range roles {
		fmt.Println("r:" , r)
	}

	// final return // TODO (not done)
	allowed := checkUserHasRole(userRoles, roles)

	return allowed, nil
}

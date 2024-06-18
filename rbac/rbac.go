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
	roles             []Role
	permissions       []Permission
	roleParents       []RoleParent
	permissionParents []PermissionParent
	rolePermissions   []RolePermission
	// TODO it would be better to put this to the engine struct
	evalCode          string
	evalEngine        EvalEngine
}

type EvalEngine interface {
	RunRule(user Map, resource Map, rule string, evalCode string) (bool, error)
}

// TODO to pass the engin at init
func New(engine ...EvalEngine) RBAC {
	if len(engine) == 1 {
		return & rbac{
			evalCode: 
			`function rule(user, resource) {
				return %s;
			}`,
			evalEngine: engine[0],
		}
	}
	
	return & rbac{
		evalCode: 
		`function rule(user, resource) {
		    return %s;
		}`,
		evalEngine: NewOttoEvalEngine(),
	}
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
func (rbac *rbac) SetEvalCode(code string) {
    rbac.evalCode = code
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

func (rbac rbac) getNextInChain(user Map, resource Map, permissions []Permission, child Permission) ([]Permission, []Role){
	// check child not in permissions 
	childPermissionExist := permissionExist(permissions, child)
	if childPermissionExist {
		return []Permission{}, []Role{}
	}

	// rule := strings.TrimSpace(child.Rule.(string))
	rule := strings.TrimSpace(child.Rule)
	result, err := rbac.evalEngine.RunRule(user, resource, rule, rbac.evalCode)
	if err != nil {
		fmt.Println("+++ Error in Run Rule: ", err.Error())
		return []Permission{}, []Role{}
	}
	if !result {
		return []Permission{}, []Role{}
	}

	// fmt.Println("+nextInChain:", child)
	
	permissions = append(permissions, child)
	roles := rbac.getPermissionRoles(child.ID)
	
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
			newPermission , newRoles := rbac.getNextInChain(user, resource, permissions, current)
			permissions = append(permissions, newPermission...)
			roles = append(roles, newRoles...)
		}
	}
	return permissions, roles
}
func (rbac rbac) IsAllowed(user Map, resource Map, permission string) (bool, error) {
	// check the permission exist
	var firstPermission Permission
	for _, current := range rbac.permissions {
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
	// for _, r := range roles {
	// 	fmt.Println("r:" , r)
	// }

	// final return
	allowed := checkUserHasRole(userRoles, roles)

	return allowed, nil
}

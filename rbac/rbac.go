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
	SetEvalEngine(evalEngine EvalEngine)
	IsAllowed(user Map, resource Map, permission string) (bool, error)
}

type rbac struct {
	roles             []Role
	permissions       []Permission
	roleParents       []RoleParent
	permissionParents []PermissionParent
	rolePermissions   []RolePermission
	ruleEvalCode      string
	evalEngine        EvalEngine
}

type EvalEngine interface {
	RunRule(user Map, ressource Map, rule string, ruleEvalCode string) (bool, error)
}

func New() RBAC {
	return & rbac{
		ruleEvalCode: 
		`function rule(user, ressource) {
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
func (rbac *rbac) SetRuleEvalCode(code string) {
    rbac.ruleEvalCode = code
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
		if current.ID == id {
			parent := rbac.getRole(current.ParentID)
			parents = append(parents, parent)
		}
	}
	return parents
}
func (rbac rbac) getPermissionParents(id int64) []Permission {
	parents := []Permission{}
	for _, current := range rbac.permissionParents {
		if current.ID == id {
			parent := rbac.getPermission(current.ParentID)
			rule := strings.TrimSpace(parent.Rule.(string))
			// doing this check to append only empty rules
			if len(rule) == 0 {
				parents = append(parents, parent)
			}
		}
	}
	for _, current := range rbac.permissionParents {
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
	for _, current := range rbac.rolePermissions {
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
	rule := strings.TrimSpace(permission.Rule.(string))
	result, err := rbac.evalEngine.RunRule(user, ressource, rule, rbac.ruleEvalCode)
	if err != nil {
		fmt.Println("+++ Error in Run Rule: ", err.Error())
		return []Permission{}, []Role{}
	}
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

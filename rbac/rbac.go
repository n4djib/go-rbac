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
	GetEvalEngine() EvalEngine
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
	SetOtherCode(code string)
	SetRuleCode(code string)
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

func (rbac rbac) GetEvalEngine() EvalEngine {
	return rbac.evalEngine
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

func (rbac rbac) collectRoles(foundRoles RolesMap) []Role {
    roles := []Role{}

	var dfs func(child Role)
    dfs = func(child Role) {
      if roleExist(roles, child) {
        return;
      }
      roles = append(roles, child)
      parents := rbac.getRoleParents(child.ID);
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

func (rbac rbac) hasPermission(user Map, resource Map, firstPermission Permission) (bool, RolesMap) {
	visitedPerissions := make(PermissionsMap)
    foundRoles := make(RolesMap)
    breaked := false

	var dfs func(child Permission) bool
	dfs = func(child Permission) bool {
		if breaked {
		  return breaked
		}
		if _, ok := visitedPerissions[child.ID]; ok {
			return false;
		}
		// check rule is true
		rule := strings.TrimSpace(child.Rule)
		result, err := rbac.evalEngine.RunRule(user, resource, rule)
		if err != nil {
			fmt.Println("+++ Error in Run Rule: ", err.Error())
			return false
		}
		if !result {
			return false
		}
		// fmt.Println("+ next:", child, result)
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
			// fmt.Println("++ breaking,", child.Permission)
        	breaked = true
			return true
		}
		// we next go to parents
		parents := rbac.getPermissionParents(child.ID)
		for _, parent := range parents {
			if breaked {
			//   fmt.Println("++ breaking,", parent.Permission)
			  return true
			}
			dfs(parent)
		}
		return breaked
	}

	allowed := dfs(firstPermission)
	return allowed, foundRoles
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
	if len(userRoles) == 0 {
		return false, nil
	}

	allowed, foundRoles := rbac.hasPermission(user, resource, startingPermission)
	// fmt.Println("foundRoles:::", foundRoles)

	roles := rbac.collectRoles(foundRoles)
	// fmt.Println("roles:::", roles)

	if !allowed {
		// check again if user has role if breaked allowed is false
		hasRole := checkUserHasRole(userRoles, roles)
		allowed = hasRole
	}
	return allowed, nil
}

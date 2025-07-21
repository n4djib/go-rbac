package rbac

import (
	"errors"
	"slices"
	"strings"
)

func New(engines ...EvalEngine) (RBAC, error) {
	if len(engines) > 1 {
		return &rbac{}, errors.New("only one eval engine is allowed")
	}
	if len(engines) == 1 {
		return &rbac{evalEngine: engines[0]}, nil
	}
	return &rbac{evalEngine: nil}, nil
}

func (rbac *rbac) SetRBAC(data RbacData) error {
	if len(data.Roles) == 0 {
		return errors.New("roles list is Empty")
	}
	if len(data.Permissions) == 0 {
		return errors.New("permissions list is Empty")
	}
	if len(data.RolePermissions) == 0 {
		return errors.New("rolePermissions list is Empty")
	}

	err := rbac.setRoles(data.Roles)
	if err != nil {
		return err
	}

	err = rbac.setPermissions(data.Permissions)
	if err != nil {
		return err
	}

	err = rbac.setRoleParents(data.RoleParents)
	if err != nil {
		return err
	}

	err = rbac.setPermissionParents(data.PermissionParents)
	if err != nil {
		return err
	}

	err = rbac.setRolePermissions(data.RolePermissions)
	if err != nil {
		return err
	}

	// set the flag to true
	rbac.rbacWasSet = true

	return nil
}

func (rbac *rbac) setRoles(roles []Role) error {
	rbac.roles = make([]roleInternal, len(roles))
	prevRoles := make([]string, len(roles))
	for i, current := range roles {
		// we check role is empty because the empty string "" is actually present in the prevRoles slice
		if current.Role != "" && slices.Contains(prevRoles, current.Role) {
			return errors.New("duplicate role: " + current.Role)
		}
		if current.Role == "" {
			return errors.New("empty roles are not allowed")
		}
		rbac.roles[i] = roleInternal{
			id:   i + 1,
			role: current.Role,
		}
		prevRoles = append(prevRoles, current.Role)
	}
	return nil
}

func (rbac *rbac) setPermissions(permissions []Permission) error {
	rbac.permissions = make([]permissionInternal, len(permissions))
	prevPermissions := make([]string, len(permissions))
	for i, current := range permissions {
		// we check permission is empty because the empty string "" is actually present in the prevPermissions slice
		if current.Permission != "" && slices.Contains(prevPermissions, current.Permission) {
			return errors.New("duplicate permission: " + current.Permission)
		}
		if current.Permission == "" {
			return errors.New("empty permissions are not allowed")
		}
		// check if engine is nil and permissions has rules
		if strings.TrimSpace(current.Rule) != "" && rbac.evalEngine == nil {
			return errors.New("rules are not allowed without an eval engine")
		}
		rbac.permissions[i] = permissionInternal{
			id:         i + 1,
			permission: current.Permission,
			rule:       current.Rule,
		}
		prevPermissions = append(prevPermissions, current.Permission)
	}

	return nil
}

func (rbac *rbac) setRoleParents(roleParents []RoleParent) error {
	rbac.roleParents = make([]roleParentInternal, len(roleParents))
	prevRoleParents := make([]string, len(roleParents))
	for i, roleParent := range roleParents {
		// we check roleParent is empty because the empty string "" is actually present in the prevRoleParents slice
		if roleParent.Role != "" && roleParent.Parent != "" && slices.Contains(prevRoleParents, roleParent.Role+"-"+roleParent.Parent) {
			return errors.New("duplicate roleParent: " + roleParent.Role + " - " + roleParent.Parent)
		}
		role := rbac.getRoleByName(roleParent.Role)
		if role == nil {
			return errors.New("role " + roleParent.Role + " not found")
		}
		parent := rbac.getRoleByName(roleParent.Parent)
		if parent == nil {
			return errors.New("role " + roleParent.Parent + " not found")
		}
		rbac.roleParents[i] = roleParentInternal{
			roleID:   role.id,
			parentID: parent.id,
		}
		prevRoleParents = append(prevRoleParents, roleParent.Role+"-"+roleParent.Parent)
	}
	return nil
}

func (rbac *rbac) setPermissionParents(permissionParents []PermissionParent) error {
	rbac.permissionParents = make([]permissionParentInternal, len(permissionParents))
	prevPermissionParents := make([]string, len(permissionParents))
	for i, permissionParent := range permissionParents {
		// we check permissionParent is empty because the empty string "" is actually present in the prevPermissionParents slice
		if permissionParent.Permission != "" && permissionParent.Parent != "" && slices.Contains(prevPermissionParents, permissionParent.Permission+"-"+permissionParent.Parent) {
			return errors.New("duplicate permissionParent: " + permissionParent.Permission + " - " + permissionParent.Parent)
		}
		permission := rbac.getPermissionByName(permissionParent.Permission)
		if permission == nil {
			return errors.New("permission " + permissionParent.Permission + " not found")
		}
		parent := rbac.getPermissionByName(permissionParent.Parent)
		if parent == nil {
			return errors.New("permission " + permissionParent.Parent + " not found")
		}
		rbac.permissionParents[i] = permissionParentInternal{
			permissionID: permission.id,
			parentID:     parent.id,
		}
		prevPermissionParents = append(prevPermissionParents, permissionParent.Permission+"-"+permissionParent.Parent)
	}
	return nil
}

func (rbac *rbac) setRolePermissions(rolePermissions []RolePermission) error {
	rbac.rolePermissions = make([]rolePermissionInternal, len(rolePermissions))
	prevRolePermissions := make([]string, len(rolePermissions))
	for i, rolePermission := range rolePermissions {
		// we check rolePermission is empty because the empty string "" is actually present in the prevRolePermissions slice
		if rolePermission.Role != "" && rolePermission.Permission != "" && slices.Contains(prevRolePermissions, rolePermission.Role+"-"+rolePermission.Permission) {
			return errors.New("duplicate rolePermission: " + rolePermission.Role + " - " + rolePermission.Permission)
		}
		role := rbac.getRoleByName(rolePermission.Role)
		if role == nil {
			return errors.New("role " + rolePermission.Role + " not found")
		}
		permission := rbac.getPermissionByName(rolePermission.Permission)
		if permission == nil {
			return errors.New("permission " + rolePermission.Permission + " not found")
		}
		rbac.rolePermissions[i] = rolePermissionInternal{
			roleID:       role.id,
			permissionID: permission.id,
		}
		prevRolePermissions = append(prevRolePermissions, rolePermission.Role+"-"+rolePermission.Permission)
	}
	return nil
}

func (rbac rbac) getRoleByName(roleName string) *roleInternal {
	for _, current := range rbac.roles {
		if current.role == roleName {
			return &current
		}
	}
	return nil
}

func (rbac rbac) getPermissionByName(permissionName string) *permissionInternal {
	for _, current := range rbac.permissions {
		if current.permission == permissionName {
			return &current
		}
	}
	return nil
}

func (rbac rbac) getRole(id int) *roleInternal {
	for _, current := range rbac.roles {
		if current.id == id {
			return &current
		}
	}
	return nil
}

func (rbac rbac) getPermission(id int) *permissionInternal {
	for _, current := range rbac.permissions {
		if current.id == id {
			return &current
		}
	}
	return nil
}

func (rbac rbac) getRoleParents(id int) []roleInternal {
	parents := []roleInternal{}
	for _, current := range rbac.roleParents {
		if current.roleID == id {
			parent := rbac.getRole(current.parentID)
			if parent != nil {
				parents = append(parents, *parent)
			}
		}
	}
	return parents
}

func (rbac rbac) getPermissionParents(id int) []permissionInternal {
	parents := []permissionInternal{}
	for _, current := range rbac.permissionParents {
		if current.permissionID == id {
			parent := rbac.getPermission(current.parentID)
			if parent != nil {
				rule := strings.TrimSpace(parent.rule)
				// doing this check to append only empty rules
				if len(rule) == 0 {
					parents = append(parents, *parent)
				}
			}
		}
	}
	for _, current := range rbac.permissionParents {
		if current.permissionID == id {
			parent := rbac.getPermission(current.parentID)
			if parent != nil {
				rule := strings.TrimSpace(parent.rule)
				// doing this check to append only non-empty rules
				if len(rule) > 0 {
					parents = append(parents, *parent)
				}
			}
		}
	}
	return parents
}

func (rbac rbac) getPermissionRoles(id int) []roleInternal {
	roles := []roleInternal{}
	for _, current := range rbac.rolePermissions {
		if current.permissionID == id {
			role := rbac.getRole(current.roleID)
			if role != nil {
				roles = append(roles, *role)
			}
		}
	}
	return roles
}

func (rbac rbac) collectRoles(foundRoles rolesMap) []roleInternal {
	roles := []roleInternal{}

	var dfs func(child roleInternal)
	dfs = func(child roleInternal) {
		if roleExist(roles, child) {
			return
		}
		roles = append(roles, child)
		parents := rbac.getRoleParents(child.id)
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

func (rbac rbac) hasPermission(principal Principal, resource Resource, firstPermission permissionInternal) (bool, rolesMap, error) {
	visitedPerissions := make(permissionsMap)
	foundRoles := make(rolesMap)
	breaked := false

	var dfs func(child permissionInternal) (bool, error)
	dfs = func(child permissionInternal) (bool, error) {
		if breaked {
			return breaked, nil
		}
		if _, ok := visitedPerissions[child.id]; ok {
			return false, nil
		}
		// check rule is true
		rule := strings.TrimSpace(child.rule)
		var result bool = true
		var err error = nil
		if len(rule) > 1 {
			// FIXME how is it accepting Principal type rather than enforcing map[strnig]any
			result, err = rbac.evalEngine.RunRule(principal, resource, rule)
		}
		if err != nil {
			return false, err
		}
		if !result {
			return false, nil
		}
		visitedPerissions[child.id] = child

		// get roles related to permissions
		// if principal has appropriate role we break
		roles := rbac.getPermissionRoles(child.id)
		for _, role := range roles {
			foundRoles[role.id] = role
		}

		principalRoles := principal["roles"].([]string)
		hasRole := checkPrincipalHasRole(principalRoles, roles)
		if hasRole {
			breaked = true
			return true, nil
		}
		// we next go to parents
		parents := rbac.getPermissionParents(child.id)
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

func (rbac rbac) IsAllowed(principal Principal, resource Resource, permission string) (bool, error) {
	// check if SetRBAC was called
	if !rbac.rbacWasSet {
		return false, errors.New("RBAC was not set, call SetRBAC() first")
	}

	// check principal is valide
	err := principal.validate()
	if err != nil {
		return false, err
	}

	// check the permission exist
	var startingPermission permissionInternal
	for _, current := range rbac.permissions {
		if permission == current.permission {
			startingPermission = current
			break
		}
	}
	// if permission not found
	if startingPermission.id == 0 {
		return false, errors.New("unknown permission: " + permission)
	}

	// check principal has roles
	// NOTE principal already validated
	// principalRoles, ok := principal["roles"].([]string)
	// if !ok {
	// 	return false, errors.New("roles of type []string not found in principal")
	// }
	principalRoles := principal["roles"].([]string)
	if len(principalRoles) == 0 {
		return false, nil
	}

	allowed, foundRoles, err := rbac.hasPermission(principal, resource, startingPermission)
	if err != nil {
		return false, err
	}

	roles := rbac.collectRoles(foundRoles)

	if !allowed {
		// check again if principal has role if breaked allowed is false
		hasRole := checkPrincipalHasRole(principalRoles, roles)
		allowed = hasRole
	}

	// TODO return struct Allowed which {allowed bool, message string}
	// explains why it is not allowed or the allowing roles
	return allowed, nil
}

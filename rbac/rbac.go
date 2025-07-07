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

	// TODO set a flag to check if SetRBAC was called

	err := setRoles(rbac, data.Roles)
	if err != nil {
		return err
	}

	err = setPermissions(rbac, data.Permissions)
	if err != nil {
		return err
	}

	err = setRoleParents(rbac, data.RoleParents)
	if err != nil {
		return err
	}

	err = setPermissionParents(rbac, data.PermissionParents)
	if err != nil {
		return err
	}

	err = setRolePermissions(rbac, data.RolePermissions)
	if err != nil {
		return err
	}

	return nil
}

func setRoles(rbac *rbac, roles []Role) error {
	rbac.roles = make([]roleInternal, len(roles))
	prevRoles := make([]string, len(roles))
	for i, role := range roles {
		// we check role is empty because the empty string "" is actually present in the prevRoles slice
		if role.Role != "" && slices.Contains(prevRoles, role.Role) {
			return errors.New("duplicate role: " + role.Role)
		}
		if role.Role == "" {
			return errors.New("empty roles are not allowed")
		}
		rbac.roles[i] = roleInternal{
			id:    i + 1,
			_role: role.Role,
		}
		prevRoles = append(prevRoles, role.Role)
	}
	return nil
}

func setPermissions(rbac *rbac, permissions []Permission) error {
	rbac.permissions = make([]permissionInternal, len(permissions))
	prevPermissions := make([]string, len(permissions))
	for i, permission := range permissions {
		// we check permission is empty because the empty string "" is actually present in the prevPermissions slice
		if permission.Permission != "" && slices.Contains(prevPermissions, permission.Permission) {
			return errors.New("duplicate permission: " + permission.Permission)
		}
		if permission.Permission == "" {
			return errors.New("empty permissions are not allowed")
		}
		// check if engine is nil and permissions has rules
		if strings.TrimSpace(permission.Rule) != "" && rbac.evalEngine == nil {
			return errors.New("rules are not allowed without an eval engine")
		}
		rbac.permissions[i] = permissionInternal{
			id:          i + 1,
			_permission: permission.Permission,
			rule:        permission.Rule,
		}
		prevPermissions = append(prevPermissions, permission.Permission)
	}

	return nil
}

func setRoleParents(rbac *rbac, roleParents []RoleParent) error {
	rbac.roleParents = make([]roleParentInternal, len(roleParents))
	prevRoleParents := make([]string, len(roleParents))
	for i, roleParent := range roleParents {
		// we check roleParent is empty because the empty string "" is actually present in the prevRoleParents slice
		if roleParent.Role != "" && roleParent.Parent != "" && slices.Contains(prevRoleParents, roleParent.Role+"-"+roleParent.Parent) {
			return errors.New("duplicate roleParent: " + roleParent.Role + " - " + roleParent.Parent)
		}
		roleID, err := rbac.getRoleByName(roleParent.Role)
		if err != nil {
			return err
		}
		parentID, err := rbac.getRoleByName(roleParent.Parent)
		if err != nil {
			return err
		}
		rbac.roleParents[i] = roleParentInternal{
			roleID:   roleID,
			parentID: parentID,
		}
		prevRoleParents = append(prevRoleParents, roleParent.Role+"-"+roleParent.Parent)
	}
	return nil
}

func setPermissionParents(rbac *rbac, permissionParents []PermissionParent) error {
	rbac.permissionParents = make([]permissionParentInternal, len(permissionParents))
	prevPermissionParents := make([]string, len(permissionParents))
	for i, permissionParent := range permissionParents {
		// we check permissionParent is empty because the empty string "" is actually present in the prevPermissionParents slice
		if permissionParent.Permission != "" && permissionParent.Parent != "" && slices.Contains(prevPermissionParents, permissionParent.Permission+"-"+permissionParent.Parent) {
			return errors.New("duplicate permissionParent: " + permissionParent.Permission + " - " + permissionParent.Parent)
		}
		permissionID, err := rbac.getPermissionByName(permissionParent.Permission)
		if err != nil {
			return err
		}
		parentID, err := rbac.getPermissionByName(permissionParent.Parent)
		if err != nil {
			return err
		}
		rbac.permissionParents[i] = permissionParentInternal{
			permissionID: permissionID,
			parentID:     parentID,
		}
		prevPermissionParents = append(prevPermissionParents, permissionParent.Permission+"-"+permissionParent.Parent)
	}
	return nil
}

func setRolePermissions(rbac *rbac, rolePermissions []RolePermission) error {
	rbac.rolePermissions = make([]rolePermissionInternal, len(rolePermissions))
	prevRolePermissions := make([]string, len(rolePermissions))
	for i, rolePermission := range rolePermissions {
		// we check rolePermission is empty because the empty string "" is actually present in the prevRolePermissions slice
		if rolePermission.Role != "" && rolePermission.Permission != "" && slices.Contains(prevRolePermissions, rolePermission.Role+"-"+rolePermission.Permission) {
			return errors.New("duplicate rolePermission: " + rolePermission.Role + " - " + rolePermission.Permission)
		}
		roleID, err := rbac.getRoleByName(rolePermission.Role)
		if err != nil {
			return err
		}
		permissionID, err := rbac.getPermissionByName(rolePermission.Permission)
		if err != nil {
			return err
		}
		rbac.rolePermissions[i] = rolePermissionInternal{
			roleID:       roleID,
			permissionID: permissionID,
		}
		prevRolePermissions = append(prevRolePermissions, rolePermission.Role+"-"+rolePermission.Permission)
	}
	return nil
}

func (rbac rbac) getRoleByName(role string) (int, error) {
	for _, current := range rbac.roles {
		if current._role == role {
			return current.id, nil
		}
	}
	return 0, errors.New("role " + role + " not found")
}

func (rbac rbac) getPermissionByName(permission string) (int, error) {
	for _, current := range rbac.permissions {
		if current._permission == permission {
			return current.id, nil
		}
	}
	return 0, errors.New("permission " + permission + " not found")
}

func (rbac rbac) getRole(id int) roleInternal {
	for _, current := range rbac.roles {
		if current.id == id {
			return current
		}
	}
	// FIXME maybe i should return nil, not empty
	return roleInternal{}
}

func (rbac rbac) getPermission(id int) permissionInternal {
	for _, current := range rbac.permissions {
		if current.id == id {
			return current
		}
	}
	// FIXME maybe i should return nil, not empty
	return permissionInternal{}
}

func (rbac rbac) getRoleParents(id int) []roleInternal {
	// FIXME maybe i should return nil, not empty
	parents := []roleInternal{}
	for _, current := range rbac.roleParents {
		if current.roleID == id {
			parent := rbac.getRole(current.parentID)
			parents = append(parents, parent)
		}
	}
	return parents
}

func (rbac rbac) getPermissionParents(id int) []permissionInternal {
	// FIXME maybe i should return nil, not empty
	parents := []permissionInternal{}
	for _, current := range rbac.permissionParents {
		if current.permissionID == id {
			parent := rbac.getPermission(current.parentID)
			rule := strings.TrimSpace(parent.rule)
			// doing this check to append only empty rules
			if len(rule) == 0 {
				parents = append(parents, parent)
			}
		}
	}
	for _, current := range rbac.permissionParents {
		if current.permissionID == id {
			parent := rbac.getPermission(current.parentID)
			rule := strings.TrimSpace(parent.rule)
			// doing this check to append only non-empty rules
			if len(rule) > 0 {
				parents = append(parents, parent)
			}
		}
	}
	return parents
}

func (rbac rbac) getPermissionRoles(id int) []roleInternal {
	// FIXME maybe i should return nil, not empty
	roles := []roleInternal{}
	for _, current := range rbac.rolePermissions {
		if current.permissionID == id {
			role := rbac.getRole(current.roleID)
			roles = append(roles, role)
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
			// FIX how is it accepting Principal type rather thatn enforcing map[strnig]any
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
	err := principal.validate()
	if err != nil {
		return false, err
	}

	// check the permission exist
	var startingPermission permissionInternal
	for _, current := range rbac.permissions {
		if permission == current._permission {
			startingPermission = current
			break
		}
	}
	// if permission not found
	if startingPermission.id == 0 {
		return false, errors.New("unknown permission: " + permission)
	}

	// FIXME the check is allready done in SetRBAC()
	// but maybe we leave it because what if the user does not run SetRBAC()?
	// remove this if you set a flag
	if len(rbac.roles) == 0 {
		return false, errors.New("roles list is Empty")
	}
	if len(rbac.permissions) == 0 {
		return false, errors.New("permissions list is Empty")
	}
	if len(rbac.rolePermissions) == 0 {
		return false, errors.New("rolePermissions list is Empty")
	}

	// check principal has roles
	// FIXME principal allready validated
	principalRoles, ok := principal["roles"].([]string)
	if !ok {
		return false, errors.New("roles of type []string not found in principal")
	}
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

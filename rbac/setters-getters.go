package rbac

import (
	"strings"
)

// setters and getters
func (rbac *RBACAuthorization) SetRoles(roles []Role) {
	rbac.Roles = roles
}
func (rbac *RBACAuthorization) SetPermissions(permissions []Permission) {
	rbac.Permissions = permissions
}
func (rbac *RBACAuthorization) SetRoleParents(roleParents []RoleParent) {
	rbac.RoleParents = roleParents
}
func (rbac *RBACAuthorization) SetPermissionParents(permissionParents []PermissionParent) {
	rbac.PermissionParents = permissionParents
}
func (rbac *RBACAuthorization) SetPermissionRoles(permissionRoles []PermissionRole) {
	rbac.PermissionRoles = permissionRoles
}

func (rbac RBACAuthorization) GetRole(id int64) Role {
	for _, current := range rbac.Roles {
		if current.ID == id {
			return current
		}
	}
	return Role{}
}
func (rbac RBACAuthorization) GetPermission(id int64) Permission {
	for _, current := range rbac.Permissions {
		if current.ID == id {
			return current
		}
	}
	return Permission{}
}
func (rbac RBACAuthorization) GetRoleParents(id int64) []Role {
	parents := []Role{}
	for _, current := range rbac.RoleParents {
		if current.ID == id {
			parent := rbac.GetRole(current.ParentID)
			parents = append(parents, parent)
		}
	}
	return parents
}
func (rbac RBACAuthorization) GetPermissionParents(id int64) []Permission {
	parents := []Permission{}
	for _, current := range rbac.PermissionParents {
		if current.ID == id {
			parent := rbac.GetPermission(current.ParentID)
			rule := strings.TrimSpace(parent.Rule.(string))
			// doing this check to append only empty rules
			if len(rule) == 0 {
				parents = append(parents, parent)
			}
		}
	}
	for _, current := range rbac.PermissionParents {
		if current.ID == id {
			parent := rbac.GetPermission(current.ParentID)
			rule := strings.TrimSpace(parent.Rule.(string))
			// doing this check to append only non-empty rules
			if len(rule) > 0 {
				parents = append(parents, parent)
			}
		}
	}
	return parents
}
func (rbac RBACAuthorization) GetPermissionRoles(permission Permission) []Role {
	roles := []Role{}
	for _, current := range rbac.PermissionRoles {
		if current.ID == permission.ID {
			role := rbac.GetRole(current.RoleID)
			roles = append(roles, role)
		}
	}
	return roles
}

func (rbac RBACAuthorization) GetParentRolesLoop(foundRoles []Role) []Role {
	roles := []Role{}
	for _, child := range foundRoles {
		// filtering duplicates
		child_exist := roleExist(roles, child)
		if !child_exist {
			roles = append(roles, child)
		}

		parents := rbac.GetRoleParents(child.ID)
		for _, parent := range parents {
			parent_exist := roleExist(roles, parent)
			if !parent_exist {
				roles = append(roles, parent)
			}
		}
	}
	return roles
}

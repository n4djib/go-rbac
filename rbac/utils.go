package rbac

func roleExist(roles []Role, role Role) bool {
	for _, current := range roles {
		if current.ID == role.ID {
			return true
		}
	}
	return false
}

func permissionExist(permissions []Permission, permission Permission) bool {
	for _, current := range permissions {
		if current.ID == permission.ID {
			return true
		}
	}
	return false
}

func checkUserHasRole(userRoles []string, roles []Role) bool {
	for _, userRole := range userRoles {
		for _, role := range roles {
			if userRole == role.Role {
				return true
			}
		}
	}
	return false
}

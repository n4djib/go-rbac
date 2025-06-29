package rbac

func roleExist(roles []roleInternal, role roleInternal) bool {
	for _, current := range roles {
		if current.id == role.id {
			return true
		}
	}
	return false
}

func checkUserHasRole(userRoles []string, roles []roleInternal) bool {
	for _, userRole := range userRoles {
		for _, role := range roles {
			if userRole == role._role {
				return true
			}
		}
	}
	return false
}

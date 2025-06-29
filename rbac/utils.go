package rbac

func roleExist(roles []roleInternal, role roleInternal) bool {
	for _, current := range roles {
		if current.id == role.id {
			return true
		}
	}
	return false
}

func checkPrincipalHasRole(principalRoles []string, roles []roleInternal) bool {
	for _, principalRole := range principalRoles {
		for _, role := range roles {
			if principalRole == role._role {
				return true
			}
		}
	}
	return false
}

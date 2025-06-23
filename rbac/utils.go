package rbac

import (
	"fmt"
	"strconv"
)

func roleExist(roles []Role, role Role) bool {
	for _, current := range roles {
		if current.ID == role.ID {
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

// TODO move this to each engine
// attach it to the struct and fill rulesMap
// what if i rename the engine package
//
//	package rbac/engine/simple-otto
func generateScript(permissions []Permission, ruleFunction string) (string, map[string]string) {
	rulesMap := map[string]string{}

	i := 0
	for _, p := range permissions {
		_, ok := rulesMap[p.Rule]
		if !ok && p.Rule != "" {
			rulesMap[p.Rule] = strconv.Itoa(i)
			i++
		}
	}

	script := ``
	for key, value := range rulesMap {
		script = script + `
	  		` + fmt.Sprintf(ruleFunction, value, key)
	}

	return script, rulesMap
}

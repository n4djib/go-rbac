package main

import (
	"fmt"
	"go-rbac/rbac"
	"log"
	"time"
)

func main() {
	start := time.Now()

	rbacAuth := new(rbac.RBACAuthorization)

	rbacAuth.SetRoles(roles)
	rbacAuth.SetPermissions(permissions)
	rbacAuth.SetRoleParents(roleParents)
	rbacAuth.SetPermissionParents(permissionParents) 
	rbacAuth.SetPermissionRoles(permissionRoles)
	// rbacAuth.SetUserRoles(userRoles)
	// fmt.Println("-rbacAuth:", rbacAuth)

	// TODO set embeded functions in js otto (insert a new function)
	// TODO set inner code in rule (insert code in rule function)

	// TODO should i create them by function ???
	obj := rbac.Attributes{"t1": false} 
	userAttributes := rbac.Attributes{ "name": "nadjib", "age": 4, "active": true, "obj": obj}
	principal := rbac.Principal{
		ID: 5,
		Roles: []string{
			"ADMIN", 
			"USER", 
		},
		Attr: userAttributes,
	}
	post := rbac.Attributes{ "title": "tutorial", "owner": 5, "list": []int{1, 2, 3, 4, 5, 6} }
	ressource := rbac.Resource{
		ID: 5,
		Attr: post,
	}

	allowed, err := rbacAuth.IsAllowed(principal, ressource, "edit_user")
	if err != nil {
		log.Fatal("++++ error: ", err.Error())
	}
	fmt.Println("\n-allowed:", allowed)

	// role := rbacAuth.GetRole(2)
	// fmt.Println("-role:", role)

	// execution duration
	duration := time.Since(start)
	fmt.Println("\n-duration:", duration)
}

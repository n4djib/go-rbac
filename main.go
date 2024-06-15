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

	// TODO set embeded functions in js otto (insert a new function)
	// TODO set inner code in rule (insert code in rule function)

	// TODO should i create them by function ???
	user := rbac.Map{
		"roles": []string{
			// "ADMIN", 
			"USER", 
		},
		"id": 5, "name": "nadjib", "age": 4, "active": true,
	}
	ressource := rbac.Map{"id": 5, "title": "tutorial", "owner": 5, "list": []int{1, 2, 3, 4, 5, 6}}

	allowed, err := rbacAuth.IsAllowed(user, ressource, "edit_user")
	if err != nil {
		log.Fatal("++++ error: ", err.Error())
	}
	fmt.Println("\n-allowed:", allowed)

	// execution duration
	duration := time.Since(start)
	fmt.Println("\n-duration:", duration)
}

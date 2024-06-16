package main

import (
	"fmt"
	"go-rbac/rbac"
	"log"
	"time"
)

func main() {
	start := time.Now()

	rbacAuth := rbac.New()

	rbacAuth.SetRoles(roles)
	rbacAuth.SetPermissions(permissions)
	rbacAuth.SetRoleParents(roleParents)
	rbacAuth.SetPermissionParents(permissionParents)
	rbacAuth.SetRolePermissions(permissionRoles)
	
	// rbacAuth.SetRuleEvalCode(`
	//   function listHasValue(obj, val) {
	// 	var values = Object.values(obj);
	// 	for(var i = 0; i < values.length; i++){
	// 	  if(values[i] === val) {
	// 		return true;
	// 	  }
	// 	}
	// 	return false;
	//   }
	//   function rule(user, ressource) {
	// 	console.log("set at main");
	// 	return %s;
	//   }
	// `)


	// TODO plug in the eval engine
	// TODO make a library


	user := rbac.Map{
		"id": 5, "name": "nadjib", "age": 4, 
		"roles": []string{
			// "ADMIN", 
			"USER", 
		},
	}

	ressource := rbac.Map{"id": 5, "title": "tutorial", "owner": 5, "list": []int{1, 2, 3, 4, 5, 6}}

	allowed, err := rbacAuth.IsAllowed(user, ressource, "edit_own_user")
	if err != nil {
		log.Fatal("++++ error: ", err.Error())
	}
	fmt.Println("\n-allowed:", allowed)

	// execution duration
	duration := time.Since(start)
	fmt.Println("\n-duration:", duration)
}

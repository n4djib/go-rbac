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

	// TODO should we enforce seting the attributes?

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


	// TODO make a library


	user := rbac.Map{
		"id": 5, "name": "nadjib", "age": 4, 
		"roles": []string{
			// "ADMIN", 
			"USER", 
		},
	}

	ressource := rbac.Map{"id": 5, "title": "tutorial", "owner": 5, "list": []int{1, 2, 3, 4, 5, 6}}

	

	startFinal := time.Now()
	allowed, err := rbacAuth.IsAllowed(user, ressource, "edit_own_user")
	fmt.Println("\n-duration isAlllowed:", time.Since(startFinal))
	
	if err != nil {
		log.Fatal("++++ error: ", err.Error())
	}
	fmt.Println("\n-allowed:", allowed)

	// execution duration
	fmt.Println("\n-duration:", time.Since(start))
}

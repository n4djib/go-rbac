package main

import (
	"fmt"
	"go-rbac/rbac"
	"log"

	"time"
)


func main() {
	start := time.Now()

	goja := NewGojaEvalEngine()
	rbacAuth := rbac.New(goja)
	
	// rbacAuth := rbac.New()

	// TODO should we enforce seting the attributes?

	rbacAuth.SetRoles(roles)
	rbacAuth.SetPermissions(permissions)
	rbacAuth.SetRoleParents(roleParents)
	rbacAuth.SetPermissionParents(permissionParents)
	rbacAuth.SetRolePermissions(rolePermissions)
	
	// TODO i shuold send on the code (in one param) not the rule + the code
	rbacAuth.SetEvalCode(`
	//   function listHasValue(obj, val) {
	// 	var values = Object.values(obj);
	// 	for(var i = 0; i < values.length; i++){
	// 	  if(values[i] === val) {
	// 		return true;
	// 	  }
	// 	}
	// 	return false;
	//   }
	  function rule(user, resource) {
		return %s;
	  }
	`)

	// TODO i want to set it in the constractor of rbac (use ...args)
	// rbacAuth.SetEvalEngine(NewGojaEvalEngine())


	// TODO make a library


	user := rbac.Map{
		"id": 5, "name": "nadjib", "age": 4, 
		"roles": []string{
			// "ADMIN", 
			"USER", 
		},
	}

	resource := rbac.Map{"id": 5, "title": "tutorial", "owner": 5, "list": []int{1, 2, 3, 4, 5, 6}}

	startFinal := time.Now()
	allowed, err := rbacAuth.IsAllowed(user, resource, "edit_user")
	fmt.Println("\n - duration IsAllowed:", time.Since(startFinal))
	if err != nil {
		log.Fatal("++++ error: ", err.Error())
	}
	fmt.Println("\n - allowed:", allowed)

	// execution duration
	fmt.Println("\n-duration:", time.Since(start))
}

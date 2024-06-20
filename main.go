package main

import (
	"fmt"
	"go-rbac/rbac"
	"log"

	"time"
)

//   function listHasValue(obj, val) {
// 	var values = Object.values(obj);
// 	for(var i = 0; i < values.length; i++){
// 	  if(values[i] === val) {
// 		return true;
// 	  }
// 	}
// 	return false;
//   }

func main() {
	start := time.Now()

	// goja := NewGojaEvalEngine()
	// rbacAuth := rbac.New(goja)

	fasterOtto, err := NewFasterOtto(permissions)
	if err != nil {
		log.Fatal("error creating fasterOtto, "+ err.Error())
	}
	rbacAuth := rbac.New(fasterOtto)
	
	// rbacAuth := rbac.New()

	// TODO should we enforce seting the attributes?

	rbacAuth.SetRoles(roles)
	rbacAuth.SetPermissions(permissions)
	rbacAuth.SetRoleParents(roleParents)
	rbacAuth.SetPermissionParents(permissionParents)
	rbacAuth.SetRolePermissions(rolePermissions)
	
	// rbacAuth.SetEvalEngine(NewGojaEvalEngine())

	// rbacAuth.SetEvalCode(`
	//   function rule(user, resource) {
	// 	return %s;
	//   }
	// `)


	// TODO make a library
	// TODO use clojures to save permissions in graph traversal
	// TODO what if we generate diffrent functions for every rule and then just call the apropriate function


	user := rbac.Map{
		"id": 5, "name": "nadjib", "age": 4, 
		"roles": []string{
			// "ADMIN", 
			"USER", 
		},
	}

	resource := rbac.Map{"id": 5, "title": "tutorial", "owner": 5, "list": []int{1, 2, 3, 4, 5, 6}}


	iterations := 100
	duration := float64(0.0)
	for i := 0; i < iterations; i++  {
		startFinal := time.Now()
		_, err := rbacAuth.IsAllowed(user, resource, "edit_user")
		if err != nil {
			log.Fatal("++++ error: ", err.Error())
		}
		since := time.Since(startFinal)
		// fmt.Println("- allowed:", allowed, "- duration:", since)
		duration = duration + float64(since)
	}
	fmt.Println("\n- Average:", time.Duration(duration / float64(iterations)))

	// execution duration
	fmt.Println("- Duration:", time.Since(start))
}

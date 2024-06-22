package main

import (
	"fmt"
	"go-rbac/rbac"
	"log"

	"time"
)

var otherCode = `
function listHasValue(obj, val) {
	var values = Object.values(obj);
	for(var i = 0; i < values.length; i++){
		if(values[i] === val) {
			return true;
		}
	}
	return false;
}
`

func main() {
	start := time.Now()

	goja, _ := rbac.NewGojaEvalEngine(permissions)
	rbacAuth := rbac.New(goja)

	// fasterOtto, _ := rbac.NewFasterOtto(permissions)
	// // fasterOtto.SetOtherCode(otherCode)
	// rbacAuth := rbac.New(fasterOtto)

	// evalEngine := rbacAuth.GetEvalEngine()
	// evalEngine.SetOtherCode(otherCode)

	// evalEngine.SetRuleFunction(`
	// function rule%s(user, resource) {
	// 	return %s;
	// }`)
	
	// rbacAuth := rbac.New()


	rbacAuth.SetRoles(roles)
	rbacAuth.SetPermissions(permissions)
	rbacAuth.SetRoleParents(roleParents)
	rbacAuth.SetPermissionParents(permissionParents)
	rbacAuth.SetRolePermissions(rolePermissions)


	// TODO make a library
	// TODO use clojures to save permissions in graph traversal
	// in this case we don't pass permissions and roles (they are global)
	// maybe create the slices with the length of the permisssions and roles
	// TODO need to improve error handling


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

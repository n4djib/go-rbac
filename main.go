package main

import (
	"fmt"
	"go-rbac/rbac"
	"log"

	"time"
)

const otherCode = `
function listHasValue(lst, val) {
	var values = Object.values(lst);
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

	// goja, _ := rbac.NewGojaEvalEngine(permissions)
	// rbacAuth := rbac.New(goja)

	// fasterOtto, _ := rbac.NewFasterOtto(permissions)
	// rbacAuth := rbac.New(fasterOtto)

	rbacAuth := rbac.New()

	// evalEngine := rbacAuth.GetEvalEngine()
	// evalEngine.SetOtherCode(otherCode)
	// evalEngine.SetRuleCode(`function rule%s(user, resource) { return %s; }`)
	// evalEngine.SetRuleCode(` %s; `)
	

	rbacAuth.SetRoles(roles)
	rbacAuth.SetPermissions(permissions)
	rbacAuth.SetRoleParents(roleParents)
	rbacAuth.SetPermissionParents(permissionParents)
	rbacAuth.SetRolePermissions(rolePermissions)

	user := rbac.Map{
		"id": 5, "name": "nadjib", "age": 4, 
		"roles": []string{
			// "ADMIN", 
			"USER", 
		},
	}

	resource := rbac.Map{
		"id": 5, "title": "tutorial", "owner": 5, 
		"list": []int{1, 2, 3, 4, 5, 6},
	}


	iterations := 1
	duration := float64(0.0)
	for i := 0; i < iterations; i++  {
		startFinal := time.Now()
		allowed, err := rbacAuth.IsAllowed(user, resource, "edit_user")
		if err != nil {
			log.Fatal("++++ error: ", err.Error())
		}
		since := time.Since(startFinal)
		fmt.Println("- allowed:", allowed, "- duration:", since)
		duration = duration + float64(since)
	}
	fmt.Println("\n- Average:", time.Duration(duration / float64(iterations)))


	// execution duration
	fmt.Println("- Duration:", time.Since(start))
	

	// TODO make a library
	// TODO use closures to save permissions in graph traversal
	// in this case we don't pass permissions and roles (they are global)
	// maybe create the slices with the length of the permisssions and roles
	// TODO need to improve error handling
	// TODO what if we change the data into graph at init
	//     would that be faster?
	// TODO set the data as maps not slices
}

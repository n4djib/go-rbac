package main

import (
	"fmt"
	"log"
	"time"

	"go-rbac/rbac"
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

	user := rbac.Principal{
		"id": 5, "name": "nadjib", "age": 4,
		"roles": []string{
			// "ADMIN",
			"USER",
		},
	}

	resource := rbac.Resource{
		"id": 5, "title": "tutorial", "owner": 5,
		"list": []int{1, 2, 3, 4, 5, 6},
	}

	// ee := rbacAuth.GetEvalEngine()
	// rule := "user.id === resource.owner"
	// // rule := "user.id === resource.owner && listHasValue(resource.list, 2)"
	// result, err := ee.RunRule(user, resource, rule)
	// if err != nil {
	// 	log.Fatal("- Err: ", err.Error())
	// }
	// fmt.Println("- Result:", result)

	start := time.Now()

	iterations := 1000
	globalAllowed := true
	duration := float64(0.0)
	for i := 0; i < iterations; i++ {
		startFinal := time.Now()
		// allowed, err := rbacAuth.IsAllowed(user, resource, "edit_user")
		allowed, err := rbacAuth.IsAllowed(user, resource, "edit_own_user")
		if err != nil {
			log.Fatal("++++ error: ", err.Error())
		}
		since := time.Since(startFinal)
		// fmt.Println("- allowed:", allowed, "- duration:", since)
		duration = duration + float64(since)
		globalAllowed = globalAllowed && allowed
	}
	fmt.Println("- globalAllowed:", globalAllowed)

	// fmt.Println("\n- Average:", time.Duration(duration / float64(iterations)))

	// execution duration
	fmt.Println("- Duration:", time.Since(start))
}

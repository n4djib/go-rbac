package main

import (
	"fmt"
	"log"
	"time"

	simple_otto "go-rbac/engine/simple-otto"
	"go-rbac/rbac"
)

// const otherCode = `
// function listHasValue(lst, val) {
// 	var values = Object.values(lst);
// 	for(var i = 0; i < values.length; i++){
// 		if(values[i] === val) {
// 			return true;
// 		}
// 	}
// 	return false;
// }
// `

func main() {
	// GOJA is the fastest
	// engine, _ := rbac.NewGojaEvalEngine(permissions)
	// // engine.SetOtherCode(otherCode)
	// engine, _ := faster_otto.New(permissions)
	engine, _ := simple_otto.New()
	rbacAuth, err := rbac.New(engine)
	//
	// rbacAuth, err := rbac.New()
	if err != nil {
		log.Fatalf("expected no error in rbac New, got (%v)", err.Error())
	}

	// engine.SetOtherCode(otherCode)
	// engine.SetHelperCode(``)
	// engine.SetRuleCode(`function rule%s(user, resource) { return %s; }`)
	// engine.SetRuleCode(` %s; `)

	err = rbacAuth.SetRBAC(rbac.RbacData{
		Roles:             roles,
		Permissions:       permissions,
		RoleParents:       roleParents,
		PermissionParents: permissionParents,
		RolePermissions:   rolePermissions,
	})
	if err != nil {
		log.Fatal("+2+ error: ", err.Error())
	}

	user := rbac.Principal{
		"id": 5, "name": "nadjib", "age": 4,
		"roles": []string{
			// "ADMIN",
			"USER",
		},
	}

	resource := rbac.Resource{
		"id": 5, "title": "tutorial", "owner": 5,
		// "list": []int{1, 2, 3, 4, 5, 6},
	}

	start := time.Now()

	iterations := 1
	globalAllowed := true
	duration := float64(0.0)
	for i := 0; i < iterations; i++ {
		startFinal := time.Now()
		// allowed, err := rbacAuth.IsAllowed(user, resource, "edit_user")
		allowed, err := rbacAuth.IsAllowed(user, resource, "edit_post")
		if err != nil {
			log.Fatal("+3+ error: ", err.Error())
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

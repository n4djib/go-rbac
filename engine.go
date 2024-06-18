package main

import (
	"fmt"
	"go-rbac/rbac"
	"log"

	"github.com/dop251/goja"
	// "github.com/dop251/goja_nodejs/console"
	// "github.com/dop251/goja_nodejs/require"
)

type GojaEvalEngine struct {
	vm *goja.Runtime
}

func NewGojaEvalEngine() *GojaEvalEngine {
	return &GojaEvalEngine{vm: goja.New()}
}

func (g *GojaEvalEngine) RunRule(user rbac.Map, resource rbac.Map, rule string, evalCode string) (bool, error) {
	if rule == "" {
		return true, nil
	}

	// registry := require.NewRegistry()
	// registry.Enable(g.vm)
	// console.Enable(g.vm)

	// format JS script
	script := fmt.Sprintf(evalCode, rule)

	_, err := g.vm.RunString(script)
	if err != nil {
		log.Fatalf("Error running script: %v", err)
	}

	// Retrieve the JavaScript function as a goja.Callable object
	ruleFunc, ok := goja.AssertFunction(g.vm.Get("rule"))
	if !ok {
		log.Fatalf("rule is not a function")
	}

	// Call the JavaScript function with arguments
	u := g.vm.ToValue(user)
	r := g.vm.ToValue(resource)
	res, err := ruleFunc(goja.Undefined(), u, r)
	if err != nil {
		log.Fatalf("Error calling function: %v", err)
	}
	
	result := res.ToBoolean()
	return result, nil
}

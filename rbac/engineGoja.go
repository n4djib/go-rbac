package rbac

import (
	"errors"
	"fmt"
	"log"

	"github.com/dop251/goja"
	// "github.com/dop251/goja_nodejs/console"
	// "github.com/dop251/goja_nodejs/require"
)

type GojaEvalEngine struct {
	vm *goja.Runtime
	otherCode    string
	ruleFunction string
	rulesMap     map[string]string
	permissions  []Permission
}

const defaultRuleFunctionGoja = 
`
function rule%s(user, resource) {
	return %s;
}`

func NewGojaEvalEngine(permissions []Permission) (*GojaEvalEngine, error) {
	vm := goja.New()
	script, rulesMap := generateScript(permissions, defaultRuleFunctionGoja)

	// Run the function code
	_, err := vm.RunString(script)
	if err != nil {
		return nil, errors.New("Error running Eval function code, " + err.Error())
	}

	// registry := require.NewRegistry()
	// registry.Enable(vm)
	// console.Enable(vm)

	evalEngine := &GojaEvalEngine{
		vm: vm,
		rulesMap: rulesMap,
		permissions: permissions,
	}
	return evalEngine, nil
}


func (ee *GojaEvalEngine) SetOtherCode (code string) {
	ee.otherCode = code
	ee.vm.RunString(code)
}

func (ee *GojaEvalEngine) SetRuleCode (code string) {
	ee.ruleFunction = code
	script, rulesMap := generateScript(ee.permissions, code)
	ee.rulesMap = rulesMap

	// Run the function code
	_, err := ee.vm.RunString(script)
	if err != nil {
		fmt.Println("Error running Eval function code " + err.Error())
	}
} 


func (ee *GojaEvalEngine) RunRule(user Map, resource Map, rule string) (bool, error) {
	if rule == "" {
		return true, nil
	}

	// get function to call
	val := ee.rulesMap[rule]
	functionName := "rule"+val

	// Retrieve the JavaScript function as a goja.Callable object
	ruleFunc, ok := goja.AssertFunction(ee.vm.Get(functionName))
	if !ok {
		log.Fatalf("rule is not a function")
	}

	// Call the JavaScript function with arguments
	u := ee.vm.ToValue(user)
	r := ee.vm.ToValue(resource)
	res, err := ruleFunc(goja.Undefined(), u, r)
	if err != nil {
		log.Fatalf("Error calling function: %v", err)
	}
	
	result := res.ToBoolean()
	return result, nil
}

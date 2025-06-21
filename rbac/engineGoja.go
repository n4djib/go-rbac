package rbac

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/dop251/goja"
	// "github.com/dop251/goja_nodejs/console"
	// "github.com/dop251/goja_nodejs/require"
)

// type RulesMap = map[string]string // rule name to rule code mapping

type GojaEvalEngine struct {
	vm           *goja.Runtime
	otherCode    string
	ruleFunction string
	rulesMap     map[string]string
	permissions  []Permission
}

const defaultRuleFunctionGoja = `
function rule%s(user, resource) {
	return %s;
}`

func NewGojaEvalEngine(permissions []Permission) (*GojaEvalEngine, error) {
	vm := goja.New()
	script, rulesMap := generateScript(permissions, defaultRuleFunctionGoja)

	// Run the function code
	_, err := vm.RunString(script)
	if err != nil {
		return nil, errors.New("failed running script code")
	}

	// registry := require.NewRegistry()
	// registry.Enable(vm)
	// console.Enable(vm)

	evalEngine := &GojaEvalEngine{
		vm:          vm,
		rulesMap:    rulesMap,
		permissions: permissions,
	}
	return evalEngine, nil
}

func (ee *GojaEvalEngine) SetHelperCode(code string) error {
	ee.otherCode = code
	_, err := ee.vm.RunString(code)
	if err != nil {
		return errors.New("failed running script code")
	}
	return err
}

func (ee *GojaEvalEngine) SetRuleCode(code string) error {
	ee.ruleFunction = code
	script, rulesMap := generateScript(ee.permissions, code)
	ee.rulesMap = rulesMap

	// Run the function code
	_, err := ee.vm.RunString(script)
	if err != nil {
		return errors.New("failed running script code")
	}
	return err
}

func (ee *GojaEvalEngine) RunRule(user Principal, resource Resource, rule string) (bool, error) {
	if rule == "" {
		return true, nil
	}

	// get function to call
	val, ok := ee.rulesMap[rule]
	functionName := "rule" + val
	fmt.Println("++ ", val, "++", ok)
	if !ok {
		return false, errors.New("rule is not in rulesMap")
	}

	// Retrieve the JavaScript function as a goja.Callable object
	ruleFunc, ok := goja.AssertFunction(ee.vm.Get(functionName))
	if !ok {
		return false, errors.New("rule is not a function")
	}

	// Call the JavaScript function with arguments
	u := ee.vm.ToValue(user)
	r := ee.vm.ToValue(resource)
	res, err := ruleFunc(goja.Undefined(), u, r)
	if err != nil {
		return false, errors.New("failed calling function")
	}

	result := res.ToBoolean()
	return result, nil
}

func (ee *GojaEvalEngine) generateScript(permissions []Permission) {
	rulesMap := map[string]string{}

	i := 0
	for _, p := range permissions {
		_, ok := ee.rulesMap[p.Rule]
		if !ok && p.Rule != "" {
			ee.rulesMap[p.Rule] = strconv.Itoa(i)
			i++
		}
	}

	script := ``
	for key, value := range rulesMap {
		script = script + `
	  		` + fmt.Sprintf(ee.ruleFunction, value, key)
	}

	// return script
}

package rbac

import (
	"errors"
	"fmt"

	"github.com/robertkrimen/otto"
)

type FasterOttoEvalEngine struct {
	vm *otto.Otto
	otherCode    string
	ruleFunction string
	rulesMap     map[string]string
	permissions  []Permission
}

const defaultRuleFunctionFasterOtto = 
`
function rule%s(user, resource) {
	return %s;
}`

func NewFasterOtto(permissions []Permission) (*FasterOttoEvalEngine, error) {
	vm := otto.New()
	script, rulesMap := generateScript(permissions, defaultRuleFunctionFasterOtto)

	// Run the function code
	_, err := vm.Run(script)
	if err != nil {
		return nil, errors.New("Error running Eval function code, " + err.Error())
	}

	evalEngine := &FasterOttoEvalEngine{
		vm: vm,
		rulesMap: rulesMap,
		permissions: permissions,
	}
	return evalEngine, nil
}

func (ee *FasterOttoEvalEngine) SetOtherCode (code string) {
	ee.otherCode = code
	ee.vm.Run(code)
}

func (ee *FasterOttoEvalEngine) SetRuleFunction (code string) {
	ee.ruleFunction = code
	script, rulesMap := generateScript(ee.permissions, code)
	ee.rulesMap = rulesMap

	// Run the function code
	_, err := ee.vm.Run(script)
	if err != nil {
		fmt.Println("Error running Eval function code " + err.Error())
	}
} 

func (ee *FasterOttoEvalEngine) RunRule(user Map, resource Map, rule string) (bool, error) {
	if rule == "" {
		return true, nil
	}

	// get function to call
	val := ee.rulesMap[rule]
	functionName := "rule"+val

	// Call the function with arguments
	value, err := ee.vm.Call(functionName, nil, user, resource)
	if err != nil {
		return false, errors.New("Error calling function, " + err.Error())
	}

	// Get the result as an integer
	result, err := value.ToBoolean()
	if err != nil {
		return false, errors.New("Error converting result, " + err.Error())
	}

	return result, nil
}

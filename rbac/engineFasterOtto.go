package rbac

import (
	"errors"

	"github.com/robertkrimen/otto"
)

// type RulesMap = map[string]string // rule name to rule code mapping

type FasterOttoEvalEngine struct {
	vm           *otto.Otto
	otherCode    string
	ruleFunction string
	rulesMap     map[string]string
	permissions  []Permission
}

const defaultRuleFunctionFasterOtto = `
function rule%s(user, resource) {
	return %s;
}`

// TODO change the name to New, after moving the otto package to its own package
func NewFasterOtto(permissions []Permission) (*FasterOttoEvalEngine, error) {
	vm := otto.New()
	script, rulesMap := generateScript(permissions, defaultRuleFunctionFasterOtto)

	// Run the function code
	_, err := vm.Run(script)
	if err != nil {
		return nil, errors.New("failed running Eval function code")
	}

	evalEngine := &FasterOttoEvalEngine{
		vm:          vm,
		rulesMap:    rulesMap,
		permissions: permissions,
	}
	return evalEngine, nil
}

func (ee *FasterOttoEvalEngine) SetHelperCode(code string) error {
	ee.otherCode = code
	_, err := ee.vm.Run(code)
	if err != nil {
		return errors.New("failed running script code")
	}
	return err
}

func (ee *FasterOttoEvalEngine) SetRuleCode(code string) error {
	ee.ruleFunction = code
	script, rulesMap := generateScript(ee.permissions, code)
	ee.rulesMap = rulesMap

	// Run the function code
	_, err := ee.vm.Run(script)
	if err != nil {
		return errors.New("failed running script code")
	}
	return err
}

func (ee *FasterOttoEvalEngine) RunRule(user Principal, resource Resource, rule string) (bool, error) {
	if rule == "" {
		return true, nil
	}

	// get function to call
	val, ok := ee.rulesMap[rule]
	functionName := "rule" + val
	if !ok {
		return false, errors.New("rule is not in rulesMap")
	}

	// Call the function with arguments
	value, err := ee.vm.Call(functionName, nil, user, resource)
	if err != nil {
		return false, errors.New("failed calling function")
	}

	// Get the result as an boolean
	result, err := value.ToBoolean()
	if err != nil {
		return false, errors.New("failed converting result")
	}

	return result, nil
}

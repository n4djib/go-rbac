package rbac

import (
	"errors"
	"fmt"

	"github.com/robertkrimen/otto"
)

type OttoEvalEngine struct {
	vm           *otto.Otto
	otherCode    string
	ruleFunction string
}

const defaultRuleFunction = `function rule(user, resource) {
	return %s;
}`

func NewOttoEvalEngine() *OttoEvalEngine {
	return &OttoEvalEngine{
		vm:           otto.New(),
		ruleFunction: defaultRuleFunction,
	}
}

func (ee *OttoEvalEngine) SetHelperCode(code string) error {
	ee.otherCode = code
	_, err := ee.vm.Run(code)
	if err != nil {
		return errors.New("failed running script code")
	}
	return err
}

func (ee *OttoEvalEngine) SetRuleCode(code string) error {
	ee.ruleFunction = code
	return nil
}

func (ee *OttoEvalEngine) RunRule(user Principal, resource Resource, rule string) (bool, error) {
	if rule == "" {
		return true, nil
	}

	// format JS script
	script := fmt.Sprintf(ee.ruleFunction, rule)

	// Run the function code
	_, err := ee.vm.Run(ee.otherCode + ` ` + script)
	if err != nil {
		return false, errors.New("failed running Eval function code")
	}

	// Call the function with arguments
	value, err := ee.vm.Call("rule", nil, user, resource)
	if err != nil {
		return false, errors.New("failed calling function")
	}

	// Get the result as an integer
	result, err := value.ToBoolean()
	if err != nil {
		return false, errors.New("failed converting result")
	}

	return result, nil
}

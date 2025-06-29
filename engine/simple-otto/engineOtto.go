package simple_otto

import (
	"errors"
	"fmt"

	"github.com/robertkrimen/otto"
)

type ottoEvalEngine struct {
	vm           *otto.Otto
	otherCode    string
	ruleFunction string
}

const defaultRuleFunction = `function rule(user, resource) {
	return %s;
}`

func New() *ottoEvalEngine {
	return &ottoEvalEngine{
		vm:           otto.New(),
		ruleFunction: defaultRuleFunction,
	}
}

func (ee *ottoEvalEngine) SetHelperCode(code string) error {
	ee.otherCode = code
	_, err := ee.vm.Run(code)
	if err != nil {
		return errors.New("failed running script code")
	}
	return err
}

func (ee *ottoEvalEngine) SetRuleCode(code string) {
	ee.ruleFunction = code
}

func (ee *ottoEvalEngine) RunRule(principal map[string]any, resource map[string]any, rule string) (bool, error) {
	if rule == "" {
		return false, errors.New("rule is empty")
	}

	// format JS script
	script := fmt.Sprintf(ee.ruleFunction, rule)

	// Run the function code
	_, err := ee.vm.Run(ee.otherCode + ` ` + script)
	if err != nil {
		return false, errors.New("failed running Eval function code")
	}
	// Call the function with arguments
	value, err := ee.vm.Call("rule", nil, principal, resource)
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

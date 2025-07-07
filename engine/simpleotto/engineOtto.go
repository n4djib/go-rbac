package simpleotto

import (
	"errors"
	"fmt"

	"github.com/robertkrimen/otto"
)

type OttoEvalEngine struct {
	vm           *otto.Otto
	otherCode    string
	evalFunction string
}

const defaultEvalFunction = `function evalFunction(user, resource) {
	return %s;
}`

func New() *OttoEvalEngine {
	return &OttoEvalEngine{
		vm:           otto.New(),
		evalFunction: defaultEvalFunction,
	}
}

func (ee *OttoEvalEngine) SetHelperCode(code string) error {
	ee.otherCode = code
	_, err := ee.vm.Run(code)
	if err != nil {
		return errors.New("failed running helper code")
	}
	return nil
}

func (ee *OttoEvalEngine) SetEvalFuncCode(code string) {
	ee.evalFunction = code
}

func (ee *OttoEvalEngine) RunRule(principal map[string]any, resource map[string]any, rule string) (bool, error) {
	if rule == "" {
		return false, errors.New("rule is empty")
	}

	// format JS script
	script := fmt.Sprintf(ee.evalFunction, rule)

	// Run the function code
	_, err := ee.vm.Run(ee.otherCode + ` ` + script)
	if err != nil {
		return false, errors.New("failed running Eval function code")
	}
	// Call the function with arguments
	value, err := ee.vm.Call("evalFunction", nil, principal, resource)
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

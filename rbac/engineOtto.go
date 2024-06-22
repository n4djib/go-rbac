package rbac

import (
	"errors"
	"fmt"

	"github.com/robertkrimen/otto"
)

type OttoEvalEngine struct {
	vm *otto.Otto
	otherCode    string
	ruleFunction string
}

const defaultRuleFunction = 
`function rule(user, resource) {
	return %s;
}`

func NewOttoEvalEngine() *OttoEvalEngine {
	return &OttoEvalEngine{
		vm: otto.New(),
		ruleFunction: defaultRuleFunction,
	}
}

func (ee *OttoEvalEngine) SetOtherCode (code string) {
	ee.otherCode = code
	// _, err := 
	ee.vm.Run(code)
}
func (ee *OttoEvalEngine) SetRuleFunction (code string) {
	ee.ruleFunction = code
}

func (ee *OttoEvalEngine) RunRule(user Map, resource Map, rule string) (bool, error) {
	if rule == "" {
		return true, nil
	}

	// format JS script
	script := fmt.Sprintf(ee.ruleFunction, rule)
	
	// Run the function code
	_, err := ee.vm.Run(ee.otherCode + ` ` + script)
	if err != nil {
		return false, errors.New("Error running Eval function code, " + err.Error())
	}

	// Call the function with arguments
	value, err := ee.vm.Call("rule", nil, user, resource)
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

package rbac

import (
	"errors"
	"fmt"

	"github.com/robertkrimen/otto"
)

type OttoEvalEngine struct {
	vm *otto.Otto
	evalCode string
}

func NewOttoEvalEngine() *OttoEvalEngine {
	return &OttoEvalEngine{
		vm: otto.New(),
		evalCode: 
		`function rule(user, resource) {
		    return %s;
		}`,
	}
}

func (ottoEE *OttoEvalEngine) SetEvalCode (evalCode string) {
	ottoEE.evalCode = evalCode
} 

func (ottoEE *OttoEvalEngine) RunRule(user Map, resource Map, rule string) (bool, error) {
	if rule == "" {
		return true, nil
	}

	// format JS script
	script := fmt.Sprintf(ottoEE.evalCode, rule)
	
	// Run the function code
	_, err := ottoEE.vm.Run(script)
	if err != nil {
		return false, errors.New("Error running Eval function code, " + err.Error())
	}

	// Call the function with arguments
	value, err := ottoEE.vm.Call("rule", nil, user, resource)
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

package rbac

import (
	"errors"
	"fmt"

	"github.com/robertkrimen/otto"
)

type OttoEvalEngine struct {
	vm *otto.Otto
}

func NewOttoEvalEngine() *OttoEvalEngine {
	return &OttoEvalEngine{vm: otto.New()}
}

func (ottoEE *OttoEvalEngine) RunRule(user Map, resource Map, rule string, evalCode string) (bool, error) {
	if rule == "" {
		return true, nil
	}

	// format JS script
	script := fmt.Sprintf(evalCode, rule)
	
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

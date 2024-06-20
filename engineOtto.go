package main

import (
	"errors"
	"fmt"
	"go-rbac/rbac"
	"strconv"

	"github.com/robertkrimen/otto"
)

type OttoEvalEngine struct {
	vm *otto.Otto
	rulesMap map[string]string
}

func NewFasterOtto(permissions []rbac.Permission) (*OttoEvalEngine, error) {

	vm := otto.New()

	rulesMap, err := GenerateScript(vm, permissions)
	if err != nil {
		return nil, errors.New("Error ........, " + err.Error())
	}

	return &OttoEvalEngine{
		vm: vm,
		rulesMap: rulesMap,
	}, nil
}

func GenerateScript(vm *otto.Otto, permissions []rbac.Permission) (map[string]string, error) {
	evalCode := 
`function rule%s(user, resource) {
		return %s;
	}`
	
	rulesMap := map[string]string{}
	i := 0
	for _, p := range permissions {
		_, ok := rulesMap[p.Rule]
		if !ok && p.Rule != "" {
			rulesMap[p.Rule] = strconv.Itoa(i)
			i++
		}
	}

	script := ``
	for key, value := range rulesMap {
		script = script + `
	  ` + fmt.Sprintf(evalCode, value, key)
	}

	// Run the function code
	_, err := vm.Run(script)
	if err != nil {
		return nil, errors.New("Error running Eval function code, " + err.Error())
	}

	return rulesMap, nil
}

// func (ottoEE *OttoEvalEngine) RunScript() (map[string]string, error) {

// }

func (ottoEE *OttoEvalEngine) SetEvalCode (evalCode string) {} 

func (ottoEE *OttoEvalEngine) RunRule(user rbac.Map, resource rbac.Map, rule string) (bool, error) {
	if rule == "" {
		return true, nil
	}

	// get function to call
	val := ottoEE.rulesMap[rule]
	function := "rule"+val

	// Call the function with arguments
	value, err := ottoEE.vm.Call(function, nil, user, resource)
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

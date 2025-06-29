package faster_otto

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/robertkrimen/otto"
)

type rulesMapType map[string]string

type fasterOttoEvalEngine struct {
	vm           *otto.Otto
	otherCode    string
	ruleFunction string
	rulesMap     rulesMapType
	rulesList    []string
}

const defaultRuleFunctionFasterOtto = `
function rule%s(user, resource) {
	return %s;
}`

func New(rulesList []string) (*fasterOttoEvalEngine, error) {
	vm := otto.New()
	script, rulesMap := generateScript(rulesList, defaultRuleFunctionFasterOtto)

	// Run the function code
	_, err := vm.Run(script)
	if err != nil {
		return nil, errors.New("failed running Eval function code")
	}

	evalEngine := &fasterOttoEvalEngine{
		vm:        vm,
		rulesMap:  rulesMap,
		rulesList: rulesList,
	}
	return evalEngine, nil
}

func (ee *fasterOttoEvalEngine) SetHelperCode(code string) error {
	ee.otherCode = code
	_, err := ee.vm.Run(code)
	if err != nil {
		return errors.New("failed running script code")
	}
	return err
}

func (ee *fasterOttoEvalEngine) SetRuleCode(code string) error {
	ee.ruleFunction = code
	script, rulesMap := generateScript(ee.rulesList, code)
	ee.rulesMap = rulesMap

	// Run the function code
	_, err := ee.vm.Run(script)
	if err != nil {
		return errors.New("failed running script code")
	}
	return err
}

func (ee *fasterOttoEvalEngine) RunRule(principal map[string]any, resource map[string]any, rule string) (bool, error) {
	if rule == "" {
		return false, errors.New("rule is empty")
	}

	// get function to call
	val, ok := ee.rulesMap[rule]
	functionName := "rule" + val
	if !ok {
		return false, errors.New("rule is not in rulesMap")
	}

	// Call the function with arguments
	value, err := ee.vm.Call(functionName, nil, principal, resource)
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

func generateScript(rulesList []string, ruleFunction string) (string, map[string]string) {
	rulesMap := rulesMapType{}

	i := 0
	for _, rule := range rulesList {
		_, ok := rulesMap[rule]
		if !ok && rule != "" {
			rulesMap[rule] = strconv.Itoa(i)
			i++
		}
	}

	script := ``
	for key, value := range rulesMap {
		script = script + `
	  		` + fmt.Sprintf(ruleFunction, value, key)
	}

	return script, rulesMap
}

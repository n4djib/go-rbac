package fastergoga

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/dop251/goja"
	// "github.com/dop251/goja_nodejs/console"
	// "github.com/dop251/goja_nodejs/require"
)

type rulesMapType map[string]string

type GojaEvalEngine struct {
	vm           *goja.Runtime
	otherCode    string
	evalFunction string
	rulesMap     rulesMapType
	rulesList    []string
}

const defaultEvalFunction = `
function evalFunction%s(principal, resource) {
	return %s;
}`

func New(rulesList []string) (*GojaEvalEngine, error) {
	if len(rulesList) == 0 {
		// TODO make the Errors into Consts
		return nil, errors.New("rules list empty")
	}
	vm := goja.New()
	script, rulesMap := generateScript(rulesList, defaultEvalFunction)

	// Run the function code
	_, err := vm.RunString(script)
	if err != nil {
		return nil, errors.New("failed running Eval function code")
	}

	// registry := require.NewRegistry()
	// registry.Enable(vm)
	// console.Enable(vm)

	evalEngine := &GojaEvalEngine{
		vm:        vm,
		rulesMap:  rulesMap,
		rulesList: rulesList,
	}
	return evalEngine, nil
}

func (ee *GojaEvalEngine) SetHelperCode(code string) error {
	ee.otherCode = code
	_, err := ee.vm.RunString(code)
	if err != nil {
		return errors.New("failed running helper code")
	}
	return err
}

func (ee *GojaEvalEngine) SetEvalFuncCode(code string) error {
	ee.evalFunction = code
	script, rulesMap := generateScript(ee.rulesList, code)
	ee.rulesMap = rulesMap

	// Run the function code
	_, err := ee.vm.RunString(script)
	if err != nil {
		return errors.New("failed running script code")
	}
	return err
}

func (ee *GojaEvalEngine) RunRule(principal map[string]any, resource map[string]any, rule string) (bool, error) {
	if rule == "" {
		return false, errors.New("rule is empty")
	}

	// get function to call
	val, ok := ee.rulesMap[rule]
	functionName := "evalFunction" + val
	// fmt.Println("++ ", val, "++", ok)
	if !ok {
		return false, errors.New("rule is not in rulesMap")
	}

	// Retrieve the JavaScript function as a goja.Callable object
	evalFunc, ok := goja.AssertFunction(ee.vm.Get(functionName))
	if !ok {
		return false, errors.New("evalFunction is not a function")
	}

	// Call the JavaScript function with arguments
	u := ee.vm.ToValue(principal)
	r := ee.vm.ToValue(resource)
	res, err := evalFunc(goja.Undefined(), u, r)
	if err != nil {
		return false, errors.New("failed calling function")
	}

	result := res.ToBoolean()
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

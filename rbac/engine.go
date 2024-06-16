package rbac

import (
	"fmt"
	"strings"

	"github.com/robertkrimen/otto"
)

func runRule(user Map, ressource Map, permission Permission, ruleEvalCode string) bool {
	if permission.Rule == nil {
		return true
	}
	rule := strings.TrimSpace(permission.Rule.(string))
	if rule == "" {
		return true
	}

	// generate JS script
	evalCode := fmt.Sprintf(ruleEvalCode, rule)

	// Create a new JavaScript VM
	vm := otto.New()

	// Run the function code
	_, err := vm.Run(evalCode)
	if err != nil {
		fmt.Println("+++ Error running Eval function code:", err)
		return false
	}

	// Call the function with arguments
	value, err := vm.Call("rule", nil, user, ressource)
	if err != nil {
		fmt.Println("Error calling function:", err)
		return false
	}
	// Get the result as an integer
	result, err := value.ToBoolean()
	if err != nil {
		fmt.Println("Error converting result:", err)
		return false
	}

	return result
}

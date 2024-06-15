package rbac

import (
	"fmt"
	"strings"

	"github.com/robertkrimen/otto"
)

func functionCode(rule string) string {
	return fmt.Sprintf(`
		function listHasValue(obj, val) {
			var values = Object.values(obj);
			for(var i=0; i < values.length; i++){
				if(values[i] === val) {
					return true;
				}
			}
			return false;
		}
		// FIXME be carful of comparing null values
		function rule(user, ressource) { 
			// console.log("(user):", JSON.stringify(user));
			// console.log("(user):", JSON.stringify(ressource));
			// console.log("(user.id):", user.id);
			// console.log("(ressource.owner):", ressource.owner);
			// console.log("(rule): %s   ==> (result):", %s);
			return %s;
		}
	`, rule, rule, rule)
}
func runRule(user Map, ressource Map, permission Permission) bool {
	if permission.Rule == nil {
		return true
	}
	rule := strings.TrimSpace(permission.Rule.(string))
	if rule == "" {
		return true
	}

	// generate JS script
	functionCode := functionCode(rule)

	// Create a new JavaScript VM
	vm := otto.New()

	// Run the function code
	_, err := vm.Run(functionCode)
	if err != nil {
		fmt.Println("Error running function code:", err)
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

func roleExist(roles []Role, role Role) bool {
	for _, current := range roles {
		if current.ID == role.ID {
			return true
		}
	}
	return false
}

func permissionExist(permissions []Permission, permission Permission) bool {
	for _, current := range permissions {
		if current.ID == permission.ID {
			return true
		}
	}
	return false
}

func checkUserHasRole(userRoles []string, roles []Role) bool {
	for _, userRole := range userRoles {
		for _, role := range roles {
			if userRole == role.Role {
				return true
			}
		}
	}
	return false
}

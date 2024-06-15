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
		function rule(principal, ressource) { 
			// console.log("(principal):", JSON.stringify(principal));
			// console.log("(ressource):", JSON.stringify(ressource));
			// console.log("(principal.id):", principal.id);
			// console.log("(ressource.attr.owner):", ressource.attr.owner);
			// console.log("(rule): %s   ==> (result):", %s);
			return %s;
		}
	`, rule, rule, rule)
}
func runRule(principal Principal, ressource Resource, permission Permission) bool {
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

	// normalize principal and resource for javascript
	principalMap := Attributes{
		"id":    principal.ID,
		"roles": principal.Roles,
		"attr":  principal.Attr,
	}
	// fmt.Println("*principalMap:", principalMap)
	ressourceMap := Attributes{
		"id":   ressource.ID,
		"attr": ressource.Attr,
	}
	// fmt.Println("*ressourceMap:", ressourceMap)

	// Call the function with arguments
	value, err := vm.Call("rule", nil, principalMap, ressourceMap)
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

package rbac_test

import (
	"errors"
	"fastergoga"
	"fasterotto"
	"simpleotto"
	"testing"

	"rbac"

	"github.com/stretchr/testify/assert"
)

func TestSetRBAC(t *testing.T) {
	data := []struct {
		roles             []rbac.Role
		permissions       []rbac.Permission
		roleParents       []rbac.RoleParent
		permissionParents []rbac.PermissionParent
		rolePermissions   []rbac.RolePermission
		name              string
		error             error // the expected error
	}{
		{
			roles:             []rbac.Role{},
			permissions:       []rbac.Permission{},
			roleParents:       []rbac.RoleParent{},
			permissionParents: []rbac.PermissionParent{},
			rolePermissions:   []rbac.RolePermission{},
			name:              "empty lists",
			error:             errors.New("roles list is Empty"),
		},
		{
			roles:             []rbac.Role{},
			permissions:       []rbac.Permission{},
			roleParents:       []rbac.RoleParent{},
			permissionParents: []rbac.PermissionParent{},
			rolePermissions:   []rbac.RolePermission{},
			name:              "empty roles lists",
			error:             errors.New("roles list is Empty"),
		},
		{
			roles:             []rbac.Role{{Role: "ADMIN"}},
			permissions:       []rbac.Permission{},
			roleParents:       []rbac.RoleParent{},
			permissionParents: []rbac.PermissionParent{},
			rolePermissions:   []rbac.RolePermission{},
			name:              "empty permissions",
			error:             errors.New("permissions list is Empty"),
		},
		{
			roles:             []rbac.Role{{Role: "ADMIN"}},
			permissions:       []rbac.Permission{{Permission: "edit_own_user", Rule: "user.id === resource.id"}},
			roleParents:       []rbac.RoleParent{},
			permissionParents: []rbac.PermissionParent{},
			rolePermissions:   []rbac.RolePermission{},
			name:              "empty permissionsRoles",
			error:             errors.New("rolePermissions list is Empty"),
		},
		{
			roles:             []rbac.Role{{Role: "ADMIN"}, {Role: "USER"}, {Role: ""}},
			permissions:       []rbac.Permission{{Permission: "edit_own_user", Rule: "user.id === resource.id"}},
			roleParents:       []rbac.RoleParent{},
			permissionParents: []rbac.PermissionParent{},
			rolePermissions:   []rbac.RolePermission{{Role: "ADMIN", Permission: "edit_own_user"}},
			name:              "empty roles Name",
			error:             errors.New("empty roles are not allowed"),
		},
		{
			roles:             []rbac.Role{{Role: "ADMIN"}, {Role: "USER"}},
			permissions:       []rbac.Permission{{Permission: "edit_own_user", Rule: ""}, {Permission: "", Rule: ""}},
			roleParents:       []rbac.RoleParent{},
			permissionParents: []rbac.PermissionParent{},
			rolePermissions:   []rbac.RolePermission{{Role: "ADMIN", Permission: "edit_own_user"}},
			name:              "empty permissions Name",
			error:             errors.New("empty permissions are not allowed"),
		},
		{
			roles:             []rbac.Role{{Role: "ADMIN"}, {Role: "USER"}},
			permissions:       []rbac.Permission{{Permission: "edit_post", Rule: ""}, {Permission: "edit_own_post", Rule: "user.id === resource.owner"}},
			roleParents:       []rbac.RoleParent{},
			permissionParents: []rbac.PermissionParent{{Permission: "edit_own_post", Parent: "edit_own_USER"}},
			rolePermissions:   []rbac.RolePermission{{Role: "ADMIN", Permission: "edit_own_post"}},
			name:              "parent permission not found",
			error:             errors.New("permission edit_own_USER not found"),
		},
		{
			roles:             []rbac.Role{{Role: "ADMIN"}, {Role: "USER"}, {Role: "MANAGER"}},
			permissions:       []rbac.Permission{{Permission: "edit_post", Rule: ""}, {Permission: "edit_own_post", Rule: "user.id === resource.owner"}},
			roleParents:       []rbac.RoleParent{},
			permissionParents: []rbac.PermissionParent{{Permission: "edit_own_post", Parent: "edit_post"}},
			rolePermissions:   []rbac.RolePermission{{Role: "MANAGER", Permission: "delete_post"}},
			name:              "rolePermission delete_post not in permissions",
			error:             errors.New("permission delete_post not found"),
		},
		{
			roles:             []rbac.Role{{Role: "ADMIN"}, {Role: "ADMIN"}},
			permissions:       []rbac.Permission{{Permission: "edit_own_user", Rule: "user.id === resource.id"}},
			roleParents:       []rbac.RoleParent{},
			permissionParents: []rbac.PermissionParent{},
			rolePermissions:   []rbac.RolePermission{{Role: "ADMIN", Permission: "edit_own_user"}},
			name:              "duplicates in roles causes error",
			error:             errors.New("duplicate role: ADMIN"),
		},
		{
			roles:             []rbac.Role{{Role: "ADMIN"}, {Role: "USER"}},
			permissions:       []rbac.Permission{{Permission: "edit_own_user", Rule: "user.id === resource.id"}, {Permission: "edit_own_user", Rule: "user.id === resource.id"}},
			roleParents:       []rbac.RoleParent{},
			permissionParents: []rbac.PermissionParent{},
			rolePermissions:   []rbac.RolePermission{{Role: "ADMIN", Permission: "edit_own_user"}},
			name:              "duplicates in permissions causes error",
			error:             errors.New("duplicate permission: edit_own_user"),
		},
		{
			roles:             []rbac.Role{{Role: "ADMIN"}, {Role: "USER"}, {Role: "MANAGER"}},
			permissions:       []rbac.Permission{{Permission: "edit_post", Rule: ""}, {Permission: "edit_own_post", Rule: "user.id === resource.owner"}},
			roleParents:       []rbac.RoleParent{{Role: "MANAGER", Parent: "USER"}, {Role: "MANAGER", Parent: "USER"}},
			permissionParents: []rbac.PermissionParent{{Permission: "edit_own_post", Parent: "edit_post"}},
			rolePermissions:   []rbac.RolePermission{{Role: "MANAGER", Permission: "edit_post"}},
			name:              "roleParents duplicate causes error",
			error:             errors.New("duplicate roleParent: MANAGER - USER"),
		},
		{
			roles:             []rbac.Role{{Role: "ADMIN"}, {Role: "USER"}, {Role: "MANAGER"}},
			permissions:       []rbac.Permission{{Permission: "edit_post", Rule: ""}, {Permission: "edit_own_post", Rule: "user.id === resource.owner"}},
			roleParents:       []rbac.RoleParent{{Role: "MANAGER", Parent: "USER"}},
			permissionParents: []rbac.PermissionParent{{Permission: "edit_own_post", Parent: "edit_post"}, {Permission: "edit_own_post", Parent: "edit_post"}},
			rolePermissions:   []rbac.RolePermission{{Role: "MANAGER", Permission: "edit_post"}},
			name:              "permissionParents duplicate causes error",
			error:             errors.New("duplicate permissionParent: edit_own_post - edit_post"),
		},
		{
			roles:             []rbac.Role{{Role: "ADMIN"}, {Role: "USER"}, {Role: "MANAGER"}},
			permissions:       []rbac.Permission{{Permission: "edit_post", Rule: ""}, {Permission: "edit_own_post", Rule: "user.id === resource.owner"}},
			roleParents:       []rbac.RoleParent{{Role: "MANAGER", Parent: "USER"}},
			permissionParents: []rbac.PermissionParent{{Permission: "edit_own_post", Parent: "edit_post"}},
			rolePermissions:   []rbac.RolePermission{{Role: "MANAGER", Permission: "edit_post"}, {Role: "MANAGER", Permission: "edit_post"}},
			name:              "rolePermissions duplicate causes error",
			error:             errors.New("duplicate rolePermission: MANAGER - edit_post"),
		},
	}

	for _, td := range data {
		t.Run(td.name, func(t *testing.T) {
			// engine, _ := faster_goga.New(permissions)
			// engine, _ := faster_otto.New(permissions)
			engine := simpleotto.New()

			rbacAuth, err := rbac.New(engine)
			if err != nil {
				t.Fatalf("expected no error in rbac.New, got (%v)", err.Error())
			}

			err = rbacAuth.SetRBAC(rbac.RbacData{
				Roles:             td.roles,
				Permissions:       td.permissions,
				RoleParents:       td.roleParents,
				PermissionParents: td.permissionParents,
				RolePermissions:   td.rolePermissions,
			})
			if err != nil {
				if err.Error() != td.error.Error() {
					t.Errorf("Expected (%v), got (%v)", td.error.Error(), err.Error())
				}
			}
			if err == nil && td.error != nil {
				t.Errorf("Expected (%v), got (%v)", td.error, err)
			}
		})
	}
}

func TestIsAllowed(t *testing.T) {
	roles := []rbac.Role{
		{Role: "SUPER-ADMIN"},
		{Role: "ADMIN"},
		{Role: "USER"},
		{Role: "MANAGER"},
	}

	permissions := []rbac.Permission{
		{Permission: "edit_post", Rule: ""},
		{Permission: "edit_own_post", Rule: "user.id === resource.owner"},
		{Permission: "create_post", Rule: ""},
		{Permission: "delete_user", Rule: ""},

		{Permission: "delete_post", Rule: ""},
		{Permission: "delete_own_post", Rule: "user.id === resource.owner"},

		// {Permission: "edit_user", Rule: ""},
		// {Permission: "edit_own_user", Rule: "user.id === resource.id"},
		// // {Permission: "edit_own_user", Rule: "user.id === resource.id && listHasValue(resource.list, 2)"},
	}

	roleParents := []rbac.RoleParent{
		{Role: "ADMIN", Parent: "SUPER-ADMIN"},
		{Role: "USER", Parent: "ADMIN"},
		{Role: "MANAGER", Parent: "ADMIN"},
	}

	permissionParents := []rbac.PermissionParent{
		{Permission: "edit_post", Parent: "edit_own_post"},
		{Permission: "delete_post", Parent: "delete_own_post"},
		// {Permission: "edit_user", Parent: "delete_own_post"},
	}

	rolePermissions := []rbac.RolePermission{
		{Role: "MANAGER", Permission: "edit_post"},
		{Role: "USER", Permission: "edit_own_post"},
		{Role: "USER", Permission: "create_post"},
		{Role: "ADMIN", Permission: "delete_user"},
		{Role: "USER", Permission: "delete_own_post"},
		{Role: "MANAGER", Permission: "delete_post"},
	}

	data := []struct {
		roles             []rbac.Role
		permissions       []rbac.Permission
		roleParents       []rbac.RoleParent
		permissionParents []rbac.PermissionParent
		rolePermissions   []rbac.RolePermission
		name              string
		expectedAllowed   bool
		permission        string
		principal         rbac.Principal
		resource          rbac.Resource
		error             error
	}{
		{
			roles:             roles,
			permissions:       permissions,
			roleParents:       roleParents,
			permissionParents: permissionParents,
			rolePermissions:   rolePermissions,
			name:              "edit_post is allowed",
			expectedAllowed:   true,
			permission:        "edit_post",
			principal: rbac.Principal{
				"id": 5, "name": "nadjib", "age": 4,
				"roles": []string{
					// "ADMIN",
					"USER",
				},
			},
			resource: rbac.Resource{
				"id": 16, "title": "tutorial post", "owner": 5,
				// "list": []int{1, 2, 3, 4, 5, 6},
			},
			error: nil,
		},
		{
			roles:             roles,
			permissions:       permissions,
			roleParents:       roleParents,
			permissionParents: permissionParents,
			rolePermissions:   rolePermissions,
			name:              "edit_post is not allowed",
			expectedAllowed:   false,
			permission:        "edit_post",
			principal: rbac.Principal{
				"id": 5, "name": "nadjib", "age": 37,
				"roles": []string{
					// "ADMIN",
					"USER",
				},
			},
			resource: rbac.Resource{
				"id": 15, "title": "tutorial post", "owner": 3,
				// "list": []int{1, 2, 3, 4, 5, 6},
			},
			error: nil,
		},
		{
			roles:             roles,
			permissions:       permissions,
			roleParents:       roleParents,
			permissionParents: permissionParents,
			rolePermissions:   rolePermissions,
			name:              "edit_post is allowed for ADMIN",
			expectedAllowed:   true,
			permission:        "edit_post",
			principal: rbac.Principal{
				"id": 5, "name": "nadjib", "age": 37,
				"roles": []string{
					"ADMIN",
				},
			},
			resource: rbac.Resource{
				"id": 15, "title": "tutorial post", "owner": 3,
			},
			error: nil,
		},
		{
			roles:             roles,
			permissions:       permissions,
			roleParents:       roleParents,
			permissionParents: permissionParents,
			rolePermissions:   rolePermissions,
			name:              "edit_post is allowed for MANAGER",
			expectedAllowed:   true,
			permission:        "edit_post",
			principal: rbac.Principal{
				"id": 5, "name": "nadjib", "age": 37,
				"roles": []string{
					"MANAGER",
				},
			},
			resource: rbac.Resource{
				"id": 15, "title": "tutorial post", "owner": 3,
			},
			error: nil,
		},
		{
			roles:             roles,
			permissions:       permissions,
			roleParents:       roleParents,
			permissionParents: permissionParents,
			rolePermissions:   rolePermissions,
			name:              "principal validation no roles",
			expectedAllowed:   false,       // doesn't matter
			permission:        "edit_post", // doesn't matter
			principal: rbac.Principal{
				"id": 5, "name": "nadjib", "age": 37,
				// "roles": []string{
				// 	"MANAGER",
				// },
			},
			resource: rbac.Resource{
				"id": 15, "title": "tutorial post", "owner": 3,
			},
			error: errors.New("missing required field: roles"),
		},
		{
			roles:             roles,
			permissions:       permissions,
			roleParents:       roleParents,
			permissionParents: permissionParents,
			rolePermissions:   rolePermissions,
			name:              "edit_p is not a known pemission",
			expectedAllowed:   true, // doesn't matter
			permission:        "edit_p",
			principal: rbac.Principal{
				"id": 5, "name": "nadjib", "age": 4,
				"roles": []string{
					// "ADMIN",
					"USER",
				},
			},
			resource: rbac.Resource{
				"id": 16, "title": "tutorial post", "owner": 5,
			},
			error: errors.New("unknown permission: edit_p"),
		},
		{
			roles: roles,
			permissions: []rbac.Permission{
				{Permission: "edit_post", Rule: ""},
				// {Permission: "delete_post", Rule: ""},
			},
			roleParents:       roleParents,
			permissionParents: []rbac.PermissionParent{
				// {Permission: "delete_post", Parent: "delete_own_post"},
			},
			rolePermissions: []rbac.RolePermission{
				{Role: "MANAGER", Permission: "delete_post"},
			},
			name:            "delete_post-is not in permissions list",
			expectedAllowed: false, // doesn't matter
			permission:      "delete_post",
			principal: rbac.Principal{
				"id": 5, "name": "nadjib", "age": 4,
				"roles": []string{
					"MANAGER",
				},
			},
			resource: rbac.Resource{
				"id": 16, "title": "tutorial post", "owner": 5,
			},
			error: errors.New("permission delete_post not found"),
		},
	}

	for _, td := range data {
		t.Run(td.name, func(t *testing.T) {
			expectedAllowed := td.expectedAllowed

			// engine, _ := faster_goga.New(permissions)
			// engine, _ := faster_otto.New(permissions)
			engine := simpleotto.New()

			rbacAuth, err := rbac.New(engine)
			if err != nil {
				t.Fatalf("expected no error in engine.New(), got (%v)", err.Error())
			}
			err = rbacAuth.SetRBAC(rbac.RbacData{
				Roles:             td.roles,
				Permissions:       td.permissions,
				RoleParents:       td.roleParents,
				PermissionParents: td.permissionParents,
				RolePermissions:   td.rolePermissions,
			})
			if err != nil {
				if err.Error() != td.error.Error() {
					t.Fatalf("in SetRBAC, got (%v)", err.Error())
				}
				// if there is an expected error in SetRBAC we return
				// without warning
				return
			}

			allowed, err := rbacAuth.IsAllowed(td.principal, td.resource, td.permission)
			if err != nil {
				if err.Error() != td.error.Error() {
					t.Fatalf("Expected %v, got %v", td.expectedAllowed, err.Error())
				}
			}
			if err == nil && allowed != expectedAllowed {
				t.Fatalf("Expected (%v), got (%v)", td.expectedAllowed, allowed)
			}
		})
	}
}

func TestWithEvalEngines(t *testing.T) {
	roles := []rbac.Role{
		{Role: "SUPER-ADMIN"},
		{Role: "ADMIN"},
		{Role: "USER"},
		{Role: "MANAGER"},
	}

	permissions := []rbac.Permission{
		{Permission: "edit_post"},
		{Permission: "edit_own_post", Rule: "user.id === resource.owner"},
		{Permission: "create_post"},
		{Permission: "delete_user", Rule: ""},

		{Permission: "delete_post", Rule: ""},
		{Permission: "delete_own_post", Rule: "user.id === resource.owner"},
	}

	roleParents := []rbac.RoleParent{
		{Role: "ADMIN", Parent: "SUPER-ADMIN"},
		{Role: "USER", Parent: "ADMIN"},
		{Role: "MANAGER", Parent: "ADMIN"},
	}

	permissionParents := []rbac.PermissionParent{
		{Permission: "edit_post", Parent: "edit_own_post"},
		{Permission: "delete_post", Parent: "delete_own_post"},
		// {Permission: "edit_user", Parent: "delete_own_post"},
	}

	rolePermissions := []rbac.RolePermission{
		{Role: "MANAGER", Permission: "edit_post"},
		{Role: "USER", Permission: "edit_own_post"},
		{Role: "USER", Permission: "create_post"},
		{Role: "ADMIN", Permission: "delete_user"},
		{Role: "USER", Permission: "delete_own_post"},
		{Role: "MANAGER", Permission: "delete_post"},
	}

	rulesList := extractRulesListFromPermissions(permissions)

	engineOtto := simpleotto.New()
	engineFasterOtto, _ := fasterotto.New(rulesList)
	engineGoga, _ := fastergoga.New(rulesList)

	data := []struct {
		roles             []rbac.Role
		permissions       []rbac.Permission
		roleParents       []rbac.RoleParent
		permissionParents []rbac.PermissionParent
		rolePermissions   []rbac.RolePermission
		name              string
		engine            rbac.EvalEngine
		permission        string
		principal         rbac.Principal
		resource          rbac.Resource
		error             error
		allowed           bool
	}{
		{
			roles:             roles,
			permissions:       permissions,
			roleParents:       roleParents,
			permissionParents: permissionParents,
			rolePermissions:   rolePermissions,
			name:              "with default engine + Rules",
			engine:            nil,
			permission:        "edit_post",
			principal: rbac.Principal{
				"id": 5, "name": "nadjib", "age": 4,
				"roles": []string{
					// "ADMIN",
					"USER",
				},
			},
			resource: rbac.Resource{
				"id": 16, "title": "tutorial post", "owner": 5,
				// "list": []int{1, 2, 3, 4, 5, 6},
			},
			error: errors.New("rules are not allowed without an eval engine"),
			// allowed: false, // doesn't matter
		},
		{
			roles: roles,
			permissions: []rbac.Permission{
				{Permission: "edit_post", Rule: ""},
				{Permission: "edit_own_post", Rule: ""},
				{Permission: "create_post", Rule: ""},
				{Permission: "delete_user", Rule: ""},

				{Permission: "delete_post", Rule: ""},
				{Permission: "delete_own_post", Rule: ""},
			},
			roleParents:       roleParents,
			permissionParents: permissionParents,
			rolePermissions:   rolePermissions,
			name:              "with default engine + No Rules",
			engine:            nil,
			permission:        "edit_post",
			principal: rbac.Principal{
				"id": 5, "name": "nadjib", "age": 4,
				"roles": []string{
					// "ADMIN",
					"USER",
				},
			},
			resource: rbac.Resource{
				"id": 16, "title": "tutorial post", "owner": 5,
				// "list": []int{1, 2, 3, 4, 5, 6},
			},
			error:   nil,
			allowed: true,
		},
		{
			roles:             roles,
			permissions:       permissions,
			roleParents:       roleParents,
			permissionParents: permissionParents,
			rolePermissions:   rolePermissions,
			name:              "with otto engine + Rules",
			engine:            engineOtto,
			permission:        "edit_post",
			principal: rbac.Principal{
				"id": 5, "name": "nadjib", "age": 4,
				"roles": []string{
					// "ADMIN",
					"USER",
				},
			},
			resource: rbac.Resource{
				"id": 16, "title": "tutorial post", "owner": 5,
				// "list": []int{1, 2, 3, 4, 5, 6},
			},
			error:   nil,
			allowed: true,
		},
		{
			roles:             roles,
			permissions:       permissions,
			roleParents:       roleParents,
			permissionParents: permissionParents,
			rolePermissions:   rolePermissions,
			name:              "with FasterOtto engine + Rules",
			engine:            engineFasterOtto,
			permission:        "edit_post",
			principal: rbac.Principal{
				"id": 5, "name": "nadjib", "age": 4,
				"roles": []string{
					// "ADMIN",
					"USER",
				},
			},
			resource: rbac.Resource{
				"id": 16, "title": "tutorial post", "owner": 5,
				// "list": []int{1, 2, 3, 4, 5, 6},
			},
			error:   nil,
			allowed: true,
		},
		{
			roles:             roles,
			permissions:       permissions,
			roleParents:       roleParents,
			permissionParents: permissionParents,
			rolePermissions:   rolePermissions,
			name:              "with Goga engine + Rules",
			engine:            engineGoga,
			permission:        "edit_post",
			principal: rbac.Principal{
				"id": 5, "name": "nadjib", "age": 4,
				"roles": []string{
					// "ADMIN",
					"USER",
				},
			},
			resource: rbac.Resource{
				"id": 16, "title": "tutorial post", "owner": 5,
				// "list": []int{1, 2, 3, 4, 5, 6},
			},
			error:   nil,
			allowed: true,
		},
	}

	for _, td := range data {
		t.Run(td.name, func(t *testing.T) {
			assert := assert.New(t)

			rbacAuth, err := rbac.New(td.engine)
			if err != nil {
				t.Fatalf("expected no error in rbac.New, got (%v)", err.Error())
			}

			err = rbacAuth.SetRBAC(rbac.RbacData{
				Roles:             td.roles,
				Permissions:       td.permissions,
				RoleParents:       td.roleParents,
				PermissionParents: td.permissionParents,
				RolePermissions:   td.rolePermissions,
			})
			if err != nil && td.error != nil {
				if err.Error() != td.error.Error() {
					t.Errorf("Expected (%v), got (%v)", td.error.Error(), err.Error())
					return
				}
			}
			if err == nil && td.error != nil {
				t.Fatalf("Expected (%v), got (%v)", td.error, err)
			}
			if td.error == nil && err != nil {
				t.Fatalf("Expected (%v), got (%v)", td.error, err)
			}

			// if there is an error from previous we dont' test allowed
			if err != nil {
				return
			}

			allowed, err := rbacAuth.IsAllowed(td.principal, td.resource, td.permission)
			if err != nil {
				t.Fatalf("Expected nil, got (%v)", err.Error())
				return
			}
			// TODO use testify in your test assertions
			// if allowed != td.allowed {
			// 	t.Fatalf("Expected (%v), got (%v)", td.allowed, allowed)
			// }
			assert.Equal(td.allowed, allowed, "expected allowed: %v, got: %v", td.allowed, allowed)
		})
	}
}

func extractRulesListFromPermissions(permissions []rbac.Permission) []string {
	rulesList := make([]string, len(permissions))
	for _, p := range permissions {
		rulesList = append(rulesList, p.Rule)
	}
	return rulesList
}

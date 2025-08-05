package rbac_test

import (
	"errors"
	"testing"

	"github.com/n4djib/go-rbac/rbac"

	"github.com/n4djib/go-rbac/engine/fastergoga"
	"github.com/n4djib/go-rbac/engine/fasterotto"
	"github.com/n4djib/go-rbac/engine/simpleotto"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			name:              "empty-lists",
			// TODO change the errors to strigns
			// TODO make the errors global consts
			// var ErrNotFound = errors.New("item not found")
			error: errors.New("roles list is Empty"),
		},
		{
			roles:             []rbac.Role{},
			permissions:       []rbac.Permission{},
			roleParents:       []rbac.RoleParent{},
			permissionParents: []rbac.PermissionParent{},
			rolePermissions:   []rbac.RolePermission{},
			name:              "empty-roles-lists",
			error:             errors.New("roles list is Empty"),
		},
		{
			roles:             []rbac.Role{{Role: "ADMIN"}},
			permissions:       []rbac.Permission{},
			roleParents:       []rbac.RoleParent{},
			permissionParents: []rbac.PermissionParent{},
			rolePermissions:   []rbac.RolePermission{},
			name:              "empty-permissions",
			error:             errors.New("permissions list is Empty"),
		},
		{
			roles:             []rbac.Role{{Role: "ADMIN"}},
			permissions:       []rbac.Permission{{Permission: "edit_own_user", Rule: "principal.id === resource.id"}},
			roleParents:       []rbac.RoleParent{},
			permissionParents: []rbac.PermissionParent{},
			rolePermissions:   []rbac.RolePermission{},
			name:              "empty-permissionsRoles",
			error:             errors.New("rolePermissions list is Empty"),
		},
		{
			roles:             []rbac.Role{{Role: "ADMIN"}, {Role: "USER"}, {Role: ""}},
			permissions:       []rbac.Permission{{Permission: "edit_own_user", Rule: "principal.id === resource.id"}},
			roleParents:       []rbac.RoleParent{},
			permissionParents: []rbac.PermissionParent{},
			rolePermissions:   []rbac.RolePermission{{Role: "ADMIN", Permission: "edit_own_user"}},
			name:              "empty-roles-Name",
			error:             errors.New("empty roles are not allowed"),
		},
		{
			roles:             []rbac.Role{{Role: "ADMIN"}, {Role: "USER"}},
			permissions:       []rbac.Permission{{Permission: "edit_own_user", Rule: ""}, {Permission: "", Rule: ""}},
			roleParents:       []rbac.RoleParent{},
			permissionParents: []rbac.PermissionParent{},
			rolePermissions:   []rbac.RolePermission{{Role: "ADMIN", Permission: "edit_own_user"}},
			name:              "empty-permissions-Name",
			error:             errors.New("empty permissions are not allowed"),
		},
		{
			roles:             []rbac.Role{{Role: "ADMIN"}, {Role: "USER"}},
			permissions:       []rbac.Permission{{Permission: "edit_post", Rule: ""}, {Permission: "edit_own_post", Rule: "principal.id === resource.owner"}},
			roleParents:       []rbac.RoleParent{},
			permissionParents: []rbac.PermissionParent{{Permission: "edit_own_post", Parent: "edit_own_USER"}},
			rolePermissions:   []rbac.RolePermission{{Role: "ADMIN", Permission: "edit_own_post"}},
			name:              "parent-permission-not-found",
			error:             errors.New("permission edit_own_USER not found"),
		},
		{
			roles:             []rbac.Role{{Role: "ADMIN"}, {Role: "USER"}, {Role: "MANAGER"}},
			permissions:       []rbac.Permission{{Permission: "edit_post", Rule: ""}, {Permission: "edit_own_post", Rule: "principal.id === resource.owner"}},
			roleParents:       []rbac.RoleParent{},
			permissionParents: []rbac.PermissionParent{{Permission: "edit_own_post", Parent: "edit_post"}},
			rolePermissions:   []rbac.RolePermission{{Role: "MANAGER", Permission: "delete_post"}},
			name:              "rolePermission-delete_post-not-in-permissions",
			error:             errors.New("permission delete_post not found"),
		},
		{
			roles:             []rbac.Role{{Role: "ADMIN"}, {Role: "ADMIN"}},
			permissions:       []rbac.Permission{{Permission: "edit_own_user", Rule: "principal.id === resource.id"}},
			roleParents:       []rbac.RoleParent{},
			permissionParents: []rbac.PermissionParent{},
			rolePermissions:   []rbac.RolePermission{{Role: "ADMIN", Permission: "edit_own_user"}},
			name:              "duplicates-in-roles-causes-error",
			error:             errors.New("duplicate role: ADMIN"),
		},
		{
			roles:             []rbac.Role{{Role: "ADMIN"}, {Role: "USER"}},
			permissions:       []rbac.Permission{{Permission: "edit_own_user", Rule: "principal.id === resource.id"}, {Permission: "edit_own_user", Rule: "principal.id === resource.id"}},
			roleParents:       []rbac.RoleParent{},
			permissionParents: []rbac.PermissionParent{},
			rolePermissions:   []rbac.RolePermission{{Role: "ADMIN", Permission: "edit_own_user"}},
			name:              "duplicates-in-permissions-causes-error",
			error:             errors.New("duplicate permission: edit_own_user"),
		},
		{
			roles:             []rbac.Role{{Role: "ADMIN"}, {Role: "USER"}, {Role: "MANAGER"}},
			permissions:       []rbac.Permission{{Permission: "edit_post", Rule: ""}, {Permission: "edit_own_post", Rule: "principal.id === resource.owner"}},
			roleParents:       []rbac.RoleParent{{Role: "MANAGER", Parent: "USER"}, {Role: "MANAGER", Parent: "USER"}},
			permissionParents: []rbac.PermissionParent{{Permission: "edit_own_post", Parent: "edit_post"}},
			rolePermissions:   []rbac.RolePermission{{Role: "MANAGER", Permission: "edit_post"}},
			name:              "roleParents-duplicate-causes-error",
			error:             errors.New("duplicate roleParent: MANAGER - USER"),
		},
		{
			roles:             []rbac.Role{{Role: "ADMIN"}, {Role: "USER"}, {Role: "MANAGER"}},
			permissions:       []rbac.Permission{{Permission: "edit_post", Rule: ""}, {Permission: "edit_own_post", Rule: "principal.id === resource.owner"}},
			roleParents:       []rbac.RoleParent{{Role: "MANAGER", Parent: "USER"}},
			permissionParents: []rbac.PermissionParent{{Permission: "edit_own_post", Parent: "edit_post"}, {Permission: "edit_own_post", Parent: "edit_post"}},
			rolePermissions:   []rbac.RolePermission{{Role: "MANAGER", Permission: "edit_post"}},
			name:              "permissionParents-duplicate-causes-error",
			error:             errors.New("duplicate permissionParent: edit_own_post - edit_post"),
		},
		{
			roles:             []rbac.Role{{Role: "ADMIN"}, {Role: "USER"}, {Role: "MANAGER"}},
			permissions:       []rbac.Permission{{Permission: "edit_post", Rule: ""}, {Permission: "edit_own_post", Rule: "principal.id === resource.owner"}},
			roleParents:       []rbac.RoleParent{{Role: "MANAGER", Parent: "USER"}},
			permissionParents: []rbac.PermissionParent{{Permission: "edit_own_post", Parent: "edit_post"}},
			rolePermissions:   []rbac.RolePermission{{Role: "MANAGER", Permission: "edit_post"}, {Role: "MANAGER", Permission: "edit_post"}},
			name:              "rolePermissions-duplicate-causes-error",
			error:             errors.New("duplicate rolePermission: MANAGER - edit_post"),
		},
	}

	for _, td := range data {
		t.Run(td.name, func(t *testing.T) {
			// engine, _ := faster_goga.New(permissions)
			// engine, _ := faster_otto.New(permissions)
			engine := simpleotto.New()

			rbacAuth := rbac.New()
			rbacAuth.SetEngine(engine)

			err := rbacAuth.SetRBAC(rbac.RbacData{
				Roles:             td.roles,
				Permissions:       td.permissions,
				RoleParents:       td.roleParents,
				PermissionParents: td.permissionParents,
				RolePermissions:   td.rolePermissions,
			})
			assert.Equal(t, td.error, err, "Expected (%v), got (%v)", td.error, err)
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
		{Permission: "edit_own_post", Rule: "principal.id === resource.owner"},
		{Permission: "create_post", Rule: ""},
		{Permission: "delete_user", Rule: ""},

		{Permission: "delete_post", Rule: ""},
		{Permission: "delete_own_post", Rule: "principal.id === resource.owner"},

		// {Permission: "edit_user", Rule: ""},
		// {Permission: "edit_own_user", Rule: "principal.id === resource.id"},
		// // {Permission: "edit_own_user", Rule: "principal.id === resource.id && listHasValue(resource.list, 2)"},
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
		name              string
		roles             []rbac.Role
		permissions       []rbac.Permission
		roleParents       []rbac.RoleParent
		permissionParents []rbac.PermissionParent
		rolePermissions   []rbac.RolePermission
		permission        string
		principal         rbac.Principal
		resource          rbac.Resource
		expectedAllowed   bool
		error             error
	}{
		{
			name:              "edit_post-is-allowed",
			roles:             roles,
			permissions:       permissions,
			roleParents:       roleParents,
			permissionParents: permissionParents,
			rolePermissions:   rolePermissions,
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
			},
			expectedAllowed: true,
			error:           nil,
		},
		{
			name:              "edit_post-is-not-allowed",
			roles:             roles,
			permissions:       permissions,
			roleParents:       roleParents,
			permissionParents: permissionParents,
			rolePermissions:   rolePermissions,
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
			},
			expectedAllowed: false,
			error:           nil,
		},
		{
			name:              "edit_post-is-allowed-for-ADMIN",
			roles:             roles,
			permissions:       permissions,
			roleParents:       roleParents,
			permissionParents: permissionParents,
			rolePermissions:   rolePermissions,
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
			expectedAllowed: true,
			error:           nil,
		},
		{
			name:              "edit_post-is-allowed-for-MANAGER",
			roles:             roles,
			permissions:       permissions,
			roleParents:       roleParents,
			permissionParents: permissionParents,
			rolePermissions:   rolePermissions,
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
			expectedAllowed: true,
			error:           nil,
		},
		{
			name:              "principal-validation-no-roles",
			roles:             roles,
			permissions:       permissions,
			roleParents:       roleParents,
			permissionParents: permissionParents,
			rolePermissions:   rolePermissions,
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
			expectedAllowed: false, // doesn't matter
			error:           errors.New("missing required field: roles"),
		},
		{
			name:              "edit_p-is-not-a-known-pemission",
			roles:             roles,
			permissions:       permissions,
			roleParents:       roleParents,
			permissionParents: permissionParents,
			rolePermissions:   rolePermissions,
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
			expectedAllowed: true, // doesn't matter
			error:           errors.New("unknown permission: edit_p"),
		},
	}

	for _, td := range data {
		t.Run(td.name, func(t *testing.T) {
			// engine, _ := faster_goga.New(permissions)
			// engine, _ := faster_otto.New(permissions)
			engine := simpleotto.New()

			rbacAuth := rbac.New()
			rbacAuth.SetEngine(engine)

			err := rbacAuth.SetRBAC(rbac.RbacData{
				Roles:             td.roles,
				Permissions:       td.permissions,
				RoleParents:       td.roleParents,
				PermissionParents: td.permissionParents,
				RolePermissions:   td.rolePermissions,
			})
			require.NoError(t, err)

			allowed, err := rbacAuth.IsAllowed(td.principal, td.resource, td.permission)
			require.Equal(t, td.error, err, "Expected error (%v), got (%v)", td.error, err)

			// if there is an error from previous we dont' test allowed
			if err != nil && td.error != nil {
				return
			}

			assert.Equal(t, td.expectedAllowed, allowed, "Expected (%v), got (%v)", td.expectedAllowed, allowed)
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
		{Permission: "edit_own_post", Rule: "principal.id === resource.owner"},
		{Permission: "create_post"},
		{Permission: "delete_user", Rule: ""},

		{Permission: "delete_post", Rule: ""},
		{Permission: "delete_own_post", Rule: "principal.id === resource.owner"},
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

	default_engine_plus_Rules := "default-engine-plus-Rules"

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
			name: default_engine_plus_Rules,
			// name:              "default-engine-plus-Rules",
			roles:             roles,
			permissions:       permissions,
			roleParents:       roleParents,
			permissionParents: permissionParents,
			rolePermissions:   rolePermissions,
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
			name:  "default-engine-WithNo-Rules",
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
			},
			error:   nil,
			allowed: true,
		},
		{
			name:              "otto-engine-plus-Rules",
			roles:             roles,
			permissions:       permissions,
			roleParents:       roleParents,
			permissionParents: permissionParents,
			rolePermissions:   rolePermissions,
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
			},
			error:   nil,
			allowed: true,
		},
		{
			name:              "FasterOtto-engine-plus-Rules",
			roles:             roles,
			permissions:       permissions,
			roleParents:       roleParents,
			permissionParents: permissionParents,
			rolePermissions:   rolePermissions,
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
			},
			error:   nil,
			allowed: true,
		},
		{
			name:              "Goga-engine-plus-Rules",
			roles:             roles,
			permissions:       permissions,
			roleParents:       roleParents,
			permissionParents: permissionParents,
			rolePermissions:   rolePermissions,
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
			},
			error:   nil,
			allowed: true,
		},
	}

	for _, td := range data {
		t.Run(td.name, func(t *testing.T) {
			assert := assert.New(t)

			rbacAuth := rbac.New()
			rbacAuth.SetEngine(td.engine)

			err := rbacAuth.SetRBAC(rbac.RbacData{
				Roles:             td.roles,
				Permissions:       td.permissions,
				RoleParents:       td.roleParents,
				PermissionParents: td.permissionParents,
				RolePermissions:   td.rolePermissions,
			})
			require.Equal(t, td.error, err, "Expected error (%v), got (%v)", td.error, err)

			// if there is an error from previous we dont' test allowed
			if err != nil && td.error != nil {
				return
			}

			allowed, err := rbacAuth.IsAllowed(td.principal, td.resource, td.permission)
			require.NoError(t, err, "Expected no error in IsAllowed, got (%v)", err)
			assert.Equal(td.allowed, allowed, "Expected allowed to be: %v, got: %v", td.allowed, allowed)
		})
	}
}

func TestWithEvalEngines_SetRbac_not_called(t *testing.T) {
	principal := rbac.Principal{
		"id": 5, "name": "nadjib", "age": 4,
		"roles": []string{
			// "ADMIN",
			"USER",
		},
	}
	resource := rbac.Resource{
		"id": 16, "title": "tutorial post", "owner": 5,
	}

	rbacAuth := rbac.New()

	_, err := rbacAuth.IsAllowed(principal, resource, "create_post")
	require.NotNil(t, err, "Expected an error, got nil")

	expectedError := errors.New("RBAC was not set, call SetRBAC() first")
	assert.Equal(t, expectedError, err, "Expected error (%v), got (%v)", expectedError, err)
}

func extractRulesListFromPermissions(permissions []rbac.Permission) []string {
	rulesList := make([]string, len(permissions))
	for _, p := range permissions {
		rulesList = append(rulesList, p.Rule)
	}
	return rulesList
}

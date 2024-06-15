package main

import (
	"go-rbac/rbac"
)

var roles = []rbac.Role{
	{ID: 1, Role: "USER"},
	{ID: 2, Role: "ADMIN"},
	{ID: 3, Role: "MANAGER"},

	{ID: 4, Role: "SUPER-ADMIN"},
}

var permissions = []rbac.Permission{
	{ID: 1, Permission: "create_post", Rule: ""},
	{ID: 2, Permission: "edit_post", Rule: ""},
	{ID: 3, Permission: "edit_own_post", Rule: "principal.id === ressource.attr.owner"},
	{ID: 4, Permission: "delete_post", Rule: ""},
	{ID: 5, Permission: "delete_own_post", Rule: ""},
	{ID: 6, Permission: "edit_user", Rule: ""},
	{ID: 7, Permission: "edit_own_user", Rule: "principal.id === ressource.id"},
	{ID: 8, Permission: "test", Rule: "principal.id === ressource.attr.owner"},
	{ID: 9, Permission: "test2", Rule: ""},
}

var roleParents = []rbac.RoleParent{
	{ID: 1, Role: "USER", ParentID: 2},
	{ID: 3, Role: "MANAGER", ParentID: 2},
	{ID: 1, Role: "USER", ParentID: 3},
	
	{ID: 2, Role: "ADMIN", ParentID: 4},
	{ID: 4, Role: "SUPER-ADMIN", ParentID: 1},
}

var permissionParents = []rbac.PermissionParent{
	{ID: 6, Permission: "edit_user", ParentID: 7},
	{ID: 7, Permission: "edit_own_user", ParentID: 8},
	{ID: 6, Permission: "edit_user", ParentID: 9},
	{ID: 9, Permission: "test2", ParentID: 8},
	
	{ID: 8, Permission: "test", ParentID: 6},
} 

var permissionRoles = []rbac.PermissionRole{
	{ID: 2, Permission: "edit_post", RoleID: 2},
	{ID: 4, Permission: "delete_post", RoleID: 2},
	{ID: 1, Permission: "create_post", RoleID: 1},
	{ID: 3, Permission: "edit_own_post", RoleID: 1},
	{ID: 5, Permission: "delete_own_post", RoleID: 1},
	{ID: 7, Permission: "edit_own_user", RoleID: 1},
	{ID: 6, Permission: "edit_user", RoleID: 2},
}

// var userRoles = []rbac.UserRole{
// 	{ID: 3, "n4djib3", RoleID: 2},
// 	{ID: 3, "n4djib3", RoleID: 3},
// 	{ID: 2, "nad", RoleID: 1},
// }

package main

import (
	"github.com/n4djib/go-rbac/rbac"
)

var roles = []rbac.Role{
	{Role: "SUPER-ADMIN"},
	{Role: "ADMIN"},
	{Role: "USER"},
	{Role: "MANAGER"},
}

var permissions = []rbac.Permission{
	{Permission: "edit_post"},
	{Permission: "edit_own_post", Rule: "user.id === resource.owner"},
	{Permission: "create_post"},
	{Permission: "delete_user"},

	{Permission: "delete_post"},
	{Permission: "delete_own_post", Rule: "user.id === resource.owner"},

	// {Permission: "edit_user", Rule: ""},
	// {Permission: "edit_own_user", Rule: "user.id === resource.id"},
	// // {Permission: "edit_own_user", Rule: "user.id === resource.id && listHasValue(resource.list, 2)"},
}

var roleParents = []rbac.RoleParent{
	{Role: "ADMIN", Parent: "SUPER-ADMIN"},
	{Role: "USER", Parent: "ADMIN"},
	{Role: "MANAGER", Parent: "ADMIN"},
}

var permissionParents = []rbac.PermissionParent{
	{Permission: "edit_post", Parent: "edit_own_post"},
	{Permission: "delete_post", Parent: "delete_own_post"},
	// {Permission: "edit_user", Parent: "delete_own_post"},
}

var rolePermissions = []rbac.RolePermission{
	{Role: "MANAGER", Permission: "edit_post"},
	{Role: "USER", Permission: "edit_own_post"},
	{Role: "USER", Permission: "create_post"},
	{Role: "ADMIN", Permission: "delete_user"},
	{Role: "USER", Permission: "delete_own_post"},
	{Role: "MANAGER", Permission: "delete_post"},
}

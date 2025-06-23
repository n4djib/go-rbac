package main

import (
	"go-rbac/rbac"
)

var roles = []rbac.Role{
	{ID: "1", Role: "USER"},
	{ID: "2", Role: "ADMIN"},
	{ID: "3", Role: "MANAGER"},

	{ID: "4", Role: "SUPER-ADMIN"},
}

// TODO maybe we should remove IDs
// it seems there is no need for them
// but it is used in the relationships

// remove ID from data when setting
// then remove IDs from relationships
// let the library assign IDs
// or use a map[string]struct{} to avoid duplicates
//  type Role + RoleWithID

// maybe i shouldn't because it comes from library with IDs
// and it is used in the relationships

// PROBLEM: if i remove IDs from data
// later when i set permissions, i can't garentie that the IDs will be the same
// so i will keep IDs in the data

var permissions = []rbac.Permission{
	{ID: "1", Permission: "create_post", Rule: ""},
	{ID: "2", Permission: "edit_post", Rule: ""},
	{ID: "3", Permission: "edit_own_post", Rule: "user.id === resource.owner"},
	{ID: "4", Permission: "delete_post", Rule: ""},
	{ID: "5", Permission: "delete_own_post", Rule: ""},
	{ID: "6", Permission: "edit_user", Rule: ""},
	// {ID: "7", Permission: "edit_own_user", Rule: "user.id === resource.id && listHasValue(resource.list, 2)"},
	{ID: "7", Permission: "edit_own_user", Rule: "user.id === resource.id"},
	{ID: "8", Permission: "test", Rule: "user.id === resource.owner"},
	{ID: "9", Permission: "test2", Rule: ""},
}

var roleParents = []rbac.RoleParent{
	{RoleID: "1", ParentID: "2"},
	// {RoleID: "3", ParentID: "2"},
	// {RoleID: "3", ParentID: "3"},

	{RoleID: "2", ParentID: "4"},
	// {RoleID: 4, ParentID: 1},
}

var permissionParents = []rbac.PermissionParent{
	{PermissionID: "6", ParentID: "7"},
	{PermissionID: "7", ParentID: "8"},
	{PermissionID: "6", ParentID: "9"},
	{PermissionID: "9", ParentID: "8"},

	{PermissionID: "8", ParentID: "6"},
	{PermissionID: "6", ParentID: "6"},
}

var rolePermissions = []rbac.RolePermission{
	{RoleID: "2", PermissionID: "2"},
	{RoleID: "2", PermissionID: "4"},
	{RoleID: "1", PermissionID: "1"},
	{RoleID: "1", PermissionID: "3"},
	{RoleID: "1", PermissionID: "5"},
	{RoleID: "1", PermissionID: "7"},
	{RoleID: "2", PermissionID: "6"},

	// {RoleID: "1", PermissionID: "9"},
}

module github.com/n4djib/go-rbac/example

go 1.24.1

require (
	github.com/n4djib/go-rbac/engine/simpleotto v0.2.0
	github.com/n4djib/go-rbac/rbac v0.2.0
)

require (
	github.com/robertkrimen/otto v0.5.1 // indirect
	golang.org/x/text v0.4.0 // indirect
	gopkg.in/sourcemap.v1 v1.0.5 // indirect
)

replace github.com/n4djib/go-rbac/engine/fastergoga => ../engine/fastergoga

replace github.com/n4djib/go-rbac/engine/fasterotto => ../engine/fasterotto

replace github.com/n4djib/go-rbac/engine/simpleotto => ../engine/simpleotto

replace github.com/n4djib/go-rbac/rbac => ../rbac

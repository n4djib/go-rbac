module github.com/n4djib/go-rbac/engine

go 1.24.1

require (
	github.com/n4djib/go-rbac/engine/fastergoga v0.1.0
	github.com/n4djib/go-rbac/engine/fasterotto v0.1.0
	github.com/n4djib/go-rbac/engine/simpleotto v0.1.0
	github.com/stretchr/testify v1.8.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dlclark/regexp2 v1.11.4 // indirect
	github.com/dop251/goja v0.0.0-20250630131328-58d95d85e994 // indirect
	github.com/go-sourcemap/sourcemap v2.1.3+incompatible // indirect
	github.com/google/pprof v0.0.0-20230207041349-798e818bf904 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/robertkrimen/otto v0.5.1 // indirect
	golang.org/x/text v0.4.0 // indirect
	gopkg.in/sourcemap.v1 v1.0.5 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/n4djib/go-rbac/engine/fastergoga => ./fastergoga

replace github.com/n4djib/go-rbac/engine/fasterotto => ./fasterotto

replace github.com/n4djib/go-rbac/engine/simpleotto => ./simpleotto

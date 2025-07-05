module cmd

go 1.24.1

replace fasterotto => ../engine/faster-otto

replace fastergoga => ../engine/faster-goga

replace simpleotto => ../engine/simple-otto

replace rbac => ../rbac

require (
	rbac v0.0.0-00010101000000-000000000000
	simpleotto v0.0.0
)

require (
	github.com/robertkrimen/otto v0.5.1 // indirect
	golang.org/x/text v0.4.0 // indirect
	gopkg.in/sourcemap.v1 v1.0.5 // indirect
)

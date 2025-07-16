package engine_test

import (
	"errors"
	"testing"

	"github.com/n4djib/go-rbac/engine/fastergoga"
	"github.com/n4djib/go-rbac/engine/fasterotto"
	"github.com/n4djib/go-rbac/engine/simpleotto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEngineCreation(t *testing.T) {
	data := []struct {
		engineName string
		name       string
		rulesList  []string
		expected   error
	}{
		// simple-otto
		{
			engineName: "simple-otto",
			name:       "simple-otto: should create engine",
			rulesList:  nil,
			expected:   nil,
		},
		// faster-otto
		{
			engineName: "faster-otto",
			name:       "faster-otto: should create engine",
			rulesList:  []string{"user.id === resource.owner"},
			expected:   nil,
		},
		{
			engineName: "faster-otto",
			name:       "faster-otto: should create engine 2",
			rulesList:  []string{"user.id === resource.owner", "user.id === resource.owner"},
			expected:   nil,
		},
		{
			engineName: "faster-otto",
			name:       "faster-otto: error no rules",
			rulesList:  []string{},
			expected:   errors.New("rules list empty"),
		},
		{
			engineName: "faster-otto",
			name:       "faster-otto: error no rules",
			rulesList:  nil,
			expected:   errors.New("rules list empty"),
		},
		// faster-goga
		{
			engineName: "faster-goga",
			name:       "faster-goga: should create engine",
			rulesList:  []string{"user.id === resource.owner"},
			expected:   nil,
		},
		{
			engineName: "faster-goga",
			name:       "faster-goga: should create engine 2",
			rulesList:  []string{"user.id === resource.owner", "user.id === resource.owner"},
			expected:   nil,
		},
		{
			engineName: "faster-goga",
			name:       "faster-goga: error no rules",
			rulesList:  []string{},
			expected:   errors.New("rules list empty"),
		},
		{
			engineName: "faster-goga",
			name:       "faster-goga: error no rules",
			rulesList:  nil,
			expected:   errors.New("rules list empty"),
		},
	}

	for _, td := range data {
		t.Run(td.name, func(t *testing.T) {
			var err error

			switch td.engineName {
			default:
				t.Fatalf("unknown engine name: %s", td.engineName)
			case "simple-otto":
				_ = simpleotto.New()
			case "faster-otto":
				_, err = fasterotto.New(td.rulesList)
			case "faster-goga":
				_, err = fastergoga.New(td.rulesList)
			}

			assert.Equal(t, td.expected, err, "expected error: %v, got: %v", td.expected, err)
		})
	}
}

func TestEngineSettingCode(t *testing.T) {
	const correctEvalFunction = `
	function evalFunction%s(user, resource) {
		return %s;
	}`
	const incorrectEvalFunction = `
	function evalF unction%s(user, resource) {
		return %s;
	}`

	data := []struct {
		engineName string
		name       string
		rulesList  []string
		helperCode string
		evalCode   string
		expected   error
	}{
		// simple-otto
		{
			engineName: "simple-otto",
			name:       "simple-otto: should work fine with empty code",
			// rulesList:  nil,
			helperCode: "",
			evalCode:   "",
			expected:   nil,
		},
		{
			engineName: "simple-otto",
			name:       "simple-otto: error with wrong helper code",
			// rulesList:  nil,
			helperCode: " sdf sd sdf ",
			evalCode:   "",
			expected:   errors.New("failed running helper code"),
		},
		// faster-otto
		{
			engineName: "faster-otto",
			name:       "faster-otto: should work fine with empty help code",
			rulesList:  []string{"user.id === resource.owner"},
			helperCode: "",
			evalCode:   correctEvalFunction,
			expected:   nil,
		},
		{
			engineName: "faster-otto",
			name:       "faster-otto: should work fine",
			rulesList:  []string{"user.id === resource.owner"},
			helperCode: "function helper() { return true; }",
			evalCode:   correctEvalFunction,
			expected:   nil,
		},
		{
			engineName: "faster-otto",
			name:       "faster-otto: should fail on erronious help code",
			rulesList:  []string{"user.id === resource.owner"},
			helperCode: "function hel per() { return true; }",
			evalCode:   correctEvalFunction,
			expected:   errors.New("failed running helper code"),
		},
		{
			engineName: "faster-otto",
			name:       "faster-otto: fails because of wrong eval code",
			rulesList:  []string{"user.id === resource.owner"},
			helperCode: "function helper() { return true; }",
			evalCode:   incorrectEvalFunction,
			expected:   errors.New("failed running script code"),
		},
		// faster-goga
		{
			engineName: "faster-goga",
			name:       "faster-goga: should work fine with empty help code",
			rulesList:  []string{"user.id === resource.owner"},
			helperCode: "",
			evalCode:   correctEvalFunction,
			expected:   nil,
		},
		{
			engineName: "faster-goga",
			name:       "faster-goga: should work fine",
			rulesList:  []string{"user.id === resource.owner"},
			helperCode: "function helper() { return true; }",
			evalCode:   correctEvalFunction,
			expected:   nil,
		},
		{
			engineName: "faster-goga",
			name:       "faster-goga: should fail on erronious help code",
			rulesList:  []string{"user.id === resource.owner"},
			helperCode: "function hel per() { return true; }",
			evalCode:   correctEvalFunction,
			expected:   errors.New("failed running helper code"),
		},
		{
			engineName: "faster-goga",
			name:       "faster-goga: fails because of wrong eval code",
			rulesList:  []string{"user.id === resource.owner"},
			helperCode: "function helper() { return true; }",
			evalCode:   incorrectEvalFunction,
			expected:   errors.New("failed running script code"),
		},
		// here we are not testing the rule, but the engine setting code only
	}

	for _, td := range data {
		t.Run(td.name, func(t *testing.T) {
			var engine any
			var err error

			switch td.engineName {
			default:
				t.Fatalf("unknown engine name: %s", td.engineName)
			case "simple-otto":
				engine = simpleotto.New()
				simpleOtto := engine.(*simpleotto.OttoEvalEngine)
				err = simpleOtto.SetHelperCode(td.helperCode)
				if err != nil {
					break
				}
				simpleOtto.SetEvalFuncCode(td.evalCode)
			case "faster-otto":
				engine, err = fasterotto.New(td.rulesList)
				require.NoError(t, err)
				fasterOtto := engine.(*fasterotto.FasterOttoEvalEngine)
				err = fasterOtto.SetHelperCode(td.helperCode)
				if err != nil {
					break
				}
				err = fasterOtto.SetEvalFuncCode(td.evalCode)
				if err != nil {
					break
				}
			case "faster-goga":
				engine, err = fastergoga.New(td.rulesList)
				require.NoError(t, err)
				fasterGoga := engine.(*fastergoga.GojaEvalEngine)
				err = fasterGoga.SetHelperCode(td.helperCode)
				if err != nil {
					break
				}
				err = fasterGoga.SetEvalFuncCode(td.evalCode)
				if err != nil {
					break
				}
			}

			assert.Equal(t, td.expected, err, "expected error: %v, got: %v", td.expected, err)
		})
	}
}

func TestWithEvalEngines(t *testing.T) {
	defaultPrincipal := map[string]any{
		"id": 5, "name": "nadjib", "age": 4,
		"roles": []string{
			// "ADMIN",
			"USER",
		},
	}
	defaultResource := map[string]any{
		"id": 16, "title": "tutorial post", "owner": 5,
		// "list": []int{1, 2, 3, 4, 5, 6},
	}

	// const correctEvalFunction = `
	// function evalFunction%s(user, resource) {
	// 	return %s;
	// }`

	data := []struct {
		engineName     string
		name           string
		evalCode       string
		rule           string
		rulesList      []string
		principal      map[string]any // we don't use the roles in run rule, unless specified in the rule
		resource       map[string]any
		expectedResult bool
		error          error
	}{
		/**/ // simple-otto
		{
			engineName:     "simple-otto",
			name:           "simple-otto: work normally",
			evalCode:       "",
			rule:           "user.id === resource.owner",
			rulesList:      nil,
			principal:      defaultPrincipal,
			resource:       defaultResource,
			expectedResult: true,
			error:          nil,
		},
		{
			engineName:     "simple-otto",
			name:           "simple-otto: wrong rule cause false",
			evalCode:       "",
			rule:           "user.id === resource.owner1",
			rulesList:      nil,
			principal:      defaultPrincipal,
			resource:       defaultResource,
			expectedResult: false,
			error:          nil,
		},
		{
			engineName:     "simple-otto",
			name:           "simple-otto: error because eval func code is erronious",
			evalCode:       "fsdfsd",
			rule:           "user.id === resource.owner",
			rulesList:      nil,
			principal:      defaultPrincipal,
			resource:       defaultResource,
			expectedResult: false,
			error:          errors.New("failed running Eval function code"),
		},
		{
			engineName: "simple-otto",
			name:       "simple-otto: user don't own the resource",
			evalCode:   "",
			rule:       "user.id === resource.owner",
			rulesList:  nil,
			principal: map[string]any{
				"id": 5,
				// "name": "nadjib", "age": 4,
				// "roles": []string{
				// 	"USER",
				// },
			},
			resource: map[string]any{
				// "id": 16,
				// "title": "tutorial post",
				"owner": 15,
			},
			expectedResult: false,
			error:          nil,
		},
		{
			engineName: "simple-otto",
			name:       "simple-otto: Roles is not used in rule",
			evalCode:   "",
			rule:       "user.id === resource.owner",
			rulesList:  nil,
			principal: map[string]any{
				"id": 5,
				// "name": "nadjib", "age": 4,
				// "roles": []string{
				// 	"ADMIN",
				// 	// "USER",
				// },
			},
			resource: map[string]any{
				// "id": 16,
				// "title": "tutorial post",
				"owner": 15,
			},
			expectedResult: false,
			error:          nil,
		},
		{
			engineName:     "simple-otto",
			name:           "simple-otto: empty rule result in false",
			evalCode:       "",
			rule:           "",
			rulesList:      nil,
			principal:      defaultPrincipal,
			resource:       defaultResource,
			expectedResult: false,
			error:          errors.New("rule is empty"),
		},
		/**/ // faster-otto
		{
			engineName:     "faster-otto",
			name:           "faster-otto: work normally",
			evalCode:       "",
			rule:           "user.id === resource.owner",
			rulesList:      []string{"user.id === resource.owner"},
			principal:      defaultPrincipal,
			resource:       defaultResource,
			expectedResult: true,
			error:          nil,
		},
		{
			engineName:     "faster-otto",
			name:           "faster-otto: wrong rule cause false",
			evalCode:       "",
			rule:           "user.id === resource.owner1",
			rulesList:      []string{"user.id === resource.owner1"},
			principal:      defaultPrincipal,
			resource:       defaultResource,
			expectedResult: false,
			error:          nil,
		},
		{
			engineName:     "faster-otto",
			name:           "faster-otto: rule evaluate to false",
			evalCode:       "",
			rule:           "user.id !== resource.owner",
			rulesList:      []string{"user.id !== resource.owner"},
			principal:      defaultPrincipal,
			resource:       defaultResource,
			expectedResult: false,
			error:          nil,
		},
		{
			engineName:     "faster-otto",
			name:           "faster-otto: empty rule result in false",
			evalCode:       "",
			rule:           "",
			rulesList:      []string{"user.id === resource.owner"},
			principal:      defaultPrincipal,
			resource:       defaultResource,
			expectedResult: false,
			error:          errors.New("rule is empty"),
		},
		{
			engineName:     "faster-otto",
			name:           "faster-otto: rule not in rulesMap cause error",
			evalCode:       "",
			rule:           "user.id !== resource.owner",
			rulesList:      []string{"user.id === resource.owner"},
			principal:      defaultPrincipal,
			resource:       defaultResource,
			expectedResult: false,
			error:          errors.New("rule is not in rulesMap"),
		},
		/**/ // faster-goga
		{
			engineName:     "faster-goga",
			name:           "faster-goga: work normally",
			evalCode:       "",
			rule:           "user.id === resource.owner",
			rulesList:      []string{"user.id === resource.owner"},
			principal:      defaultPrincipal,
			resource:       defaultResource,
			expectedResult: true,
			error:          nil,
		},
		{
			engineName:     "faster-goga",
			name:           "faster-goga: wrong rule cause false",
			evalCode:       "",
			rule:           "user.id === resource.owner1",
			rulesList:      []string{"user.id === resource.owner1"},
			principal:      defaultPrincipal,
			resource:       defaultResource,
			expectedResult: false,
			error:          nil,
		},
		{
			engineName:     "faster-goga",
			name:           "faster-goga: empty rule result in false",
			evalCode:       "",
			rule:           "",
			rulesList:      []string{"user.id === resource.owner"},
			principal:      defaultPrincipal,
			resource:       defaultResource,
			expectedResult: false,
			error:          errors.New("rule is empty"),
		},
		{
			engineName:     "faster-goga",
			name:           "faster-otto: rule not in rulesMap cause error",
			evalCode:       "",
			rule:           "user.id !== resource.owner",
			rulesList:      []string{"user.id === resource.owner"},
			principal:      defaultPrincipal,
			resource:       defaultResource,
			expectedResult: false,
			error:          errors.New("rule is not in rulesMap"),
		},
	}

	for _, td := range data {
		t.Run(td.name, func(t *testing.T) {
			var engine any
			var err error
			var result bool

			switch td.engineName {
			default:
				t.Fatal("you have to set an engine name")
			case "simple-otto":
				engine = simpleotto.New()
				simpleotto := engine.(*simpleotto.OttoEvalEngine)
				// if td.helperCode != "" {
				// 	err = simpleotto.SetHelperCode(td.helperCode)
				// 	if err != nil {
				// 		break
				// 	}
				// }
				if td.evalCode != "" {
					simpleotto.SetEvalFuncCode(td.evalCode)
				}
			case "faster-otto":
				engine, err = fasterotto.New(td.rulesList)
				if err != nil {
					break
				}
				fasterotto := engine.(*fasterotto.FasterOttoEvalEngine)
				// if td.helperCode != "" {
				// 	err = fasterotto.SetHelperCode(td.helperCode)
				// 	if err != nil {
				// 		break
				// 	}
				// }
				if td.evalCode != "" {
					err = fasterotto.SetEvalFuncCode(td.evalCode)
					if err != nil {
						break
					}
				}
			case "faster-goga":
				engine, err = fastergoga.New(td.rulesList)
				if err != nil {
					break
				}
				fastergoga := engine.(*fastergoga.GojaEvalEngine)
				// if td.helperCode != "" {
				// 	err = fastergoga.SetHelperCode(td.helperCode)
				// 	if err != nil {
				// 		break
				// 	}
				// }
				if td.evalCode != "" {
					err = fastergoga.SetEvalFuncCode(td.evalCode)
					if err != nil {
						break
					}
				}
			}
			require.NoError(t, err)

			switch e := engine.(type) {
			default:
				t.Fatalf("unknown engine type")
			case *simpleotto.OttoEvalEngine:
				result, err = e.RunRule(td.principal, td.resource, td.rule)
			case *fasterotto.FasterOttoEvalEngine:
				result, err = e.RunRule(td.principal, td.resource, td.rule)
			case *fastergoga.GojaEvalEngine:
				result, err = e.RunRule(td.principal, td.resource, td.rule)
			}

			require.Equal(t, td.error, err, "expected error: %v, got: %v", td.error, err)
			assert.Equal(t, td.expectedResult, result, "expected result: %v, got: %v", td.expectedResult, result)
		})
	}
}

package rbac

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPincipalValidation(t *testing.T) {
	data := []struct {
		principal Principal
		name      string
		error     error // the expected error
	}{
		// {
		// 	principal: Principal{"id_1": 1, "roles": []string{"ADMIN"}},
		// 	name:      "missing-id",
		// 	error:     errors.New("missing required field: id"),
		// },
		{
			principal: Principal{},
			name:      "empty-principal",
			// error:     errors.New("missing required field: id"),
			error: errors.New("missing required field: roles"),
		},
		{
			principal: Principal{"id": 1, "roles_aa": []string{"ADMIN", "USER"}},
			name:      "missing-required-field:roles",
			error:     errors.New("missing required field: roles"),
		},
		{
			principal: Principal{"id": 1},
			name:      "missing-required-field:roles",
			error:     errors.New("missing required field: roles"),
		},
		{
			principal: Principal{"id": 1, "roles": []string{"ADMIN", "USER"}},
			name:      "valide-principal",
			error:     nil,
		},
		{
			principal: Principal{"id": 1, "roles": 1},
			name:      "roles-is-an-integer",
			error:     errors.New("roles must be a []string"),
		},
		{
			principal: Principal{"id": 1, "roles": []int{1, 2}},
			name:      "roles-is-an-array-of-integers",
			error:     errors.New("roles must be a []string"),
		},
	}

	for _, td := range data {
		t.Run(td.name, func(t *testing.T) {
			err := td.principal.validate()
			assert.Equal(t, td.error, err, "Expected error (%v), got (%v)", td.error, err)
		})
	}
}

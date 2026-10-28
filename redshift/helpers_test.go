package redshift

import (
	"errors"
	"fmt"
	"sort"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/lib/pq"
)

func TestNormalizeRolePrivileges(t *testing.T) {
	gotSet := normalizeRolePrivileges([]interface{}{"SELECT", "select", " insert ", "", "DELETE", "delete"})
	got := make([]string, 0, gotSet.Len())
	for _, value := range gotSet.List() {
		got = append(got, value.(string))
	}
	want := []string{"delete", "insert", "select"}
	sort.Strings(got)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("expected %d privileges, got %d: %v", len(want), len(got), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("expected privilege %q at index %d, got %q", want[i], i, got[i])
		}
	}

	_ = schema.NewSet
}

func TestValidatePrivileges(t *testing.T) {
	tests := map[string]struct {
		privileges []string
		objectType string
		expected   bool
	}{
		"valid list for schema": {
			privileges: []string{"create", "usage"},
			objectType: "schema",
			expected:   true,
		},
		"invalid list for schema": {
			privileges: []string{"foo"},
			objectType: "schema",
			expected:   false,
		},
		"extended invalid list for schema": {
			privileges: []string{"create", "usage", "insert"},
			objectType: "schema",
			expected:   false,
		},
		"empty list for schema": {
			privileges: []string{},
			objectType: "schema",
			expected:   true,
		},
		"valid list for table": {
			privileges: []string{"insert", "update", "delete", "select", "drop", "references", "rule", "trigger"},
			objectType: "table",
			expected:   true,
		},
		"invalid list for table": {
			privileges: []string{"foobar"},
			objectType: "schema",
			expected:   false,
		},
		"extended invalid list for table": {
			privileges: []string{"create", "usage", "insert"},
			objectType: "table",
			expected:   false,
		},
		"empty list for table": {
			privileges: []string{},
			objectType: "table",
			expected:   true,
		},
		"valid list for function": {
			privileges: []string{"execute"},
			objectType: "function",
			expected:   true,
		},
		"invalid list for function": {
			privileges: []string{"foo"},
			objectType: "function",
			expected:   false,
		},
		"extended invalid list for function": {
			privileges: []string{"execute", "foo"},
			objectType: "function",
			expected:   false,
		},
		"valid list for procedure": {
			privileges: []string{"execute"},
			objectType: "procedure",
			expected:   true,
		},
		"invalid list for procedure": {
			privileges: []string{"foo"},
			objectType: "procedure",
			expected:   false,
		},
		"extended invalid list for procedure": {
			privileges: []string{"execute", "foo"},
			objectType: "procedure",
			expected:   false,
		},
		"valid list for language": {
			privileges: []string{"usage"},
			objectType: "language",
			expected:   true,
		},
		"invalid list for language": {
			privileges: []string{"foo"},
			objectType: "language",
			expected:   false,
		},
		"extended invalid list for language": {
			privileges: []string{"usage", "foo"},
			objectType: "language",
			expected:   false,
		},
		"empty list for language": {
			privileges: []string{},
			objectType: "language",
			expected:   false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result := validatePrivileges(tt.privileges, tt.objectType)

			if result != tt.expected {
				t.Errorf("Expected result to be `%t` but got `%t`", tt.expected, result)
			}
		})
	}
}

func TestRedshiftResourceRetryOnPQErrors(t *testing.T) {
	originalDelay := pqRetryBaseDelay
	pqRetryBaseDelay = 0
	t.Cleanup(func() { pqRetryBaseDelay = originalDelay })

	retryable := &pq.Error{Code: pqErrorCodeConcurrent}
	notRetryable := &pq.Error{Code: "42601"}

	// Each try returns a different error, so the test can find out which one is returned.
	retryableOnEachTry := make([]error, 10)
	for i := range retryableOnEachTry {
		retryableOnEachTry[i] = &pq.Error{Code: pqErrorCodeConcurrent, Message: fmt.Sprintf("try %d", i+1)}
	}

	tests := map[string]struct {
		errs      []error
		wantCalls int
		wantErr   error
	}{
		"success at once": {
			errs:      []error{nil},
			wantCalls: 1,
		},
		"raw retryable error, then success": {
			errs:      []error{retryable, nil},
			wantCalls: 2,
		},
		"wrapped retryable error, then success": {
			errs:      []error{fmt.Errorf("error granting: %w", retryable), nil},
			wantCalls: 2,
		},
		"wrapped error that is not retryable": {
			errs:      []error{fmt.Errorf("error granting: %w", notRetryable)},
			wantCalls: 1,
			wantErr:   notRetryable,
		},
		"error that is not a pq error": {
			errs:      []error{errors.New("other error")},
			wantCalls: 1,
		},
		"retryable error on all tries": {
			errs:      retryableOnEachTry,
			wantCalls: 10,
			wantErr:   retryableOnEachTry[9],
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			calls := 0
			fn := RedshiftResourceRetryOnPQErrors(func(*DBConnection, *schema.ResourceData) error {
				err := tt.errs[calls]
				calls++
				return err
			})

			err := fn(nil, nil)
			if calls != tt.wantCalls {
				t.Fatalf("expected %d calls, got %d", tt.wantCalls, calls)
			}

			wantNil := tt.errs[len(tt.errs)-1] == nil
			if wantNil && err != nil {
				t.Fatalf("expected no error, got %s", err)
			}
			if !wantNil && err == nil {
				t.Fatalf("expected an error, got nil")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}

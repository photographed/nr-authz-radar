package authzradar

import (
	"errors"
	"regexp"
	"testing"

	"github.com/newrelic/go-agent/v3/newrelic"
)

// The real transaction type must satisfy Txn.
var _ Txn = (*newrelic.Transaction)(nil)

type fake struct {
	attrs  map[string]any
	errors int
	user   string
}

func newFake() *fake                         { return &fake{attrs: map[string]any{}} }
func (f *fake) AddAttribute(k string, v any) { f.attrs[k] = v }
func (f *fake) NoticeExpectedError(error)    { f.errors++ }
func (f *fake) SetUserID(v string)           { f.user = v }

func TestOwnerIsAllowed(t *testing.T) {
	f := newFake()
	ok, err := CheckOwnership(f, &RequestState{}, "alice", "alice", Options{})
	if !ok || err != nil || f.attrs["resource.owner_match"] != true || f.attrs["authz.decision"] != "allow" {
		t.Fatalf("got %v %v %v", ok, err, f.attrs)
	}
}

func TestMismatchIsDenied(t *testing.T) {
	f := newFake()
	_, err := CheckOwnership(f, &RequestState{}, "bob", "alice", Options{})
	if !errors.Is(err, ErrOwnership) || f.attrs["authz.decision"] != "deny" || f.attrs["resource.owner_match"] != false || f.errors != 1 {
		t.Fatalf("got %v %v errors=%d", err, f.attrs, f.errors)
	}
}

func TestObserveIsSticky(t *testing.T) {
	f, s := newFake(), &RequestState{}
	CheckOwnership(f, s, "bob", "alice", Options{Observe: true})
	CheckOwnership(f, s, "alice", "alice", Options{Observe: true})
	if f.attrs["resource.owner_match"] != false || f.attrs["authz.decision"] != "allow" {
		t.Fatalf("got %v", f.attrs)
	}
}

func TestBypassIsLabelled(t *testing.T) {
	f := newFake()
	if _, err := CheckOwnership(f, &RequestState{}, "bob", "ops", Options{BypassScope: "admin:read"}); err != nil {
		t.Fatal(err)
	}
	if f.attrs["authz.required_scope"] != "admin:read" {
		t.Fatalf("got %v", f.attrs)
	}
}

func TestPseudonym(t *testing.T) {
	f := newFake()
	SetUser(f, "alice", []byte("k"))
	if !regexp.MustCompile(`^u_[0-9a-f]{16}$`).MatchString(f.user) || Pseudonym("alice", nil) != "" {
		t.Fatalf("got %q", f.user)
	}
}

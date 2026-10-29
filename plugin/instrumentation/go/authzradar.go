// Package authzradar implements nr-authz-radar stage S2 for Go (go-agent v3).
//
// It sends resource.owner_match and authz.decision (shared/attribute-spec.md) and an
// HMAC-pseudonymized enduser.id. Call CheckOwnership right after loading a resource by a
// client-supplied ID, with the transaction from newrelic.FromContext(r.Context()).
package authzradar

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// Txn is the subset of *newrelic.Transaction used here (so it can be faked in tests).
type Txn interface {
	AddAttribute(key string, value any)
	NoticeExpectedError(err error)
	SetUserID(userID string)
}

// ErrOwnership is returned on a mismatch in enforce mode. Map it to HTTP 403 (or 404).
var ErrOwnership = errors.New("ownership check failed")

// RequestState is one per request: keeps owner_match sticky and lets deny win over allow.
type RequestState struct {
	mismatch bool
	denied   bool
}

// Options for CheckOwnership.
type Options struct {
	// Observe lets mismatches through so detection D01 shows real IDORs.
	Observe bool
	// BypassScope marks legitimate cross-owner access (e.g. "admin:read") so D01 excludes it.
	BypassScope string
}

// Pseudonym returns "u_" + 16 hex chars, or "" without a key (a plain hash can be brute-forced).
func Pseudonym(userID string, key []byte) string {
	if len(key) == 0 || userID == "" {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(userID))
	return "u_" + hex.EncodeToString(mac.Sum(nil))[:16]
}

// SetUser sends the pseudonymized user ID.
func SetUser(txn Txn, userID string, key []byte) {
	if v := Pseudonym(userID, key); v != "" {
		txn.SetUserID(v)
	}
}

// CheckOwnership records the check. It returns ErrOwnership on a mismatch unless Observe or
// BypassScope applies.
func CheckOwnership(txn Txn, state *RequestState, ownerID, currentUserID any, opts Options) (bool, error) {
	match := currentUserID != nil && fmt.Sprint(ownerID) == fmt.Sprint(currentUserID)
	if !match {
		state.mismatch = true
	}
	txn.AddAttribute("resource.owner_match", !state.mismatch)
	switch {
	case !match && opts.BypassScope != "":
		txn.AddAttribute("authz.required_scope", opts.BypassScope)
	case !match && !opts.Observe:
		state.denied = true
		txn.AddAttribute("authz.decision", "deny")
		txn.NoticeExpectedError(ErrOwnership) // grouped in Errors Inbox, not counted in error rate
		return false, ErrOwnership
	}
	if !state.denied {
		txn.AddAttribute("authz.decision", "allow")
	}
	return match, nil
}

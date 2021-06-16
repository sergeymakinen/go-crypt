package crypt

import (
	"testing"

	"github.com/sergeymakinen/go-crypt/internal/testutil"
)

func TestCheckNotMatchingHash(t *testing.T) {
	err := Check("foo", "bar")
	if expected := ErrHash; !testutil.IsEqualError(err, expected) {
		t.Errorf("Check() = _, %v; want %v", err, expected)
	}
}

func TestCheckNotMatchingPassword(t *testing.T) {
	RegisterHash("$foo$", func(hash, password string) error {
		return ErrPasswordMismatch
	})
	err := Check("$foo$", "bar")
	if expected := ErrPasswordMismatch; !testutil.IsEqualError(err, expected) {
		t.Errorf("Check() = _, %v; want %v", err, expected)
	}
}

func TestCheckOverride(t *testing.T) {
	RegisterHash("$foo$", func(hash, password string) error {
		return ErrPasswordMismatch
	})
	RegisterHash("$foo$", func(hash, password string) error {
		return nil
	})
	err := Check("$foo$", "bar")
	if err != nil {
		t.Errorf("Check() = _, %v; want nil", err)
	}
}

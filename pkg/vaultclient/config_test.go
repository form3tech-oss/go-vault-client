package vaultclient

import (
	"strings"
	"testing"
)

func TestDefaultConfigWhenTokenSpecified(t *testing.T) {
	defer setEnv("VAULT_TOKEN", "ff1779db-fb69-4a4f-b224-8029f98f8d10")()
	config := NewDefaultConfig()

	if !strings.EqualFold("ff1779db-fb69-4a4f-b224-8029f98f8d10", config.Token) {
		t.Fatalf("expected token to be ff1779db-fb69-4a4f-b224-8029f98f8d10 but was %s", config.Token)
	}
	if config.AuthType != Token {
		t.Fatalf("expected auth type to be token")
	}
}

func TestDefaultConfigWhenRoleSpecified(t *testing.T) {
	defer setEnv("VAULT_IAM_ROLE", "foo")()
	config := NewDefaultConfig()

	if !strings.EqualFold("foo", config.IamRole) {
		t.Fatalf("expected iam role to be foo but was %s", config.IamRole)
	}
	if config.AuthType != Iam {
		t.Fatalf("expected auth type to be iam")
	}
}

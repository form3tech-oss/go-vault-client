package test

import (
	"github.com/form3tech-oss/go-vault-client/v4/pkg/vaultclient"
	"strings"
	"testing"
)

func TestDefaultConfigWhenTokenSpecified(t *testing.T) {
	defer setEnv("VAULT_TOKEN", "ff1779db-fb69-4a4f-b224-8029f98f8d10")()
	config := vaultclient.NewDefaultConfig()

	if !strings.EqualFold("ff1779db-fb69-4a4f-b224-8029f98f8d10", config.Token) {
		t.Fatalf("expected token to be ff1779db-fb69-4a4f-b224-8029f98f8d10 but was %s", config.Token)
	}
	if config.AuthType != vaultclient.Token {
		t.Fatalf("expected auth type to be token")
	}
}

func TestDefaultConfigWhenIamRoleSpecified(t *testing.T) {
	defer setEnv("VAULT_ROLE", "foo")()
	config := vaultclient.NewDefaultConfig()

	if !strings.EqualFold("foo", config.IamRole) {
		t.Fatalf("expected iam role to be foo but was %s", config.IamRole)
	}
	if config.AuthType != vaultclient.Iam {
		t.Fatalf("expected auth type to be iam")
	}
}

func TestDefaultConfigWhenAppRoleSpecified(t *testing.T) {
	defer setEnv("VAULT_APP_ROLE", "testrole")()
	defer setEnv("VAULT_APP_ROLE_ID", "myroleid")()
	defer setEnv("VAULT_APP_SECRET_ID", "mysecretid")()
	config := vaultclient.NewDefaultConfig()

	if !strings.EqualFold("testrole", config.AppRole) {
		t.Fatalf("expected app role to be testrole but was %s", config.AppRole)
	}
	if !strings.EqualFold("myroleid", config.AppRoleId) {
		t.Fatalf("expected app role id to be myroleid but was %s", config.AppRoleId)
	}
	if !strings.EqualFold("mysecretid", config.AppRoleSecretId) {
		t.Fatalf("expected app role secret id to be mysecretid but was %s", config.AppRoleSecretId)
	}
	if config.AuthType != vaultclient.AppRole {
		t.Fatalf("expected auth type to be AppRole")
	}
}

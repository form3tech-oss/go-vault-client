package vaultclient

import (
	"github.com/hashicorp/vault/api"
	"os"
	"strings"
	"testing"
)

func TestAppRoleAuth(t *testing.T) {
	configuredVault, destroy := newVaultConfiguredForAppRole(t, "1h", "1h")
	defer destroy()

	err := os.Setenv("VAULT_ADDR", configuredVault.address)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := configuredVault.rootClient.Logical().Write("auth/approle/role/test1/secret-id", nil)
	if err != nil {
		t.Fatal(err)
	}
	secretID := resp.Data["secret_id"].(string)

	resp, err = configuredVault.rootClient.Logical().Read("auth/approle/role/test1/role-id")
	if err != nil {
		t.Fatal(err)
	}
	roleID := resp.Data["role_id"].(string)

	config := BaseConfig()
	config.AuthType = AppRole
	config.AppRoleId = roleID
	config.AppRoleSecretId = secretID

	err = config.ConfigureTLS(&api.TLSConfig{
		Insecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	v, err := NewVaultAuth(config)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := v.VaultClientOrPanic().Logical().Write("secret/baz", map[string]interface{}{
		"baz": "buzz",
	}); err != nil {
		t.Fatal(err)
	}

	result, err := v.VaultClientOrPanic().Logical().Read("secret/baz")
	if err != nil {
		t.Fatalf("could not read secret using authed client, error: %s", err)
	}

	if result == nil {
		t.Fatalf("no secret returned")
	}

	if !strings.EqualFold(result.Data["baz"].(string), "buzz") {
		t.Fatalf("expecting secret to be buzz")
	}

}

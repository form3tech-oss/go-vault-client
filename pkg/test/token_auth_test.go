package test

import (
	"github.com/form3tech-oss/go-vault-client/v4/pkg/vaultclient"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"
)

func TestTokenAuth(t *testing.T) {
	configuredVault, destroy := newVault(t)
	defer destroy()

	err := os.Setenv("VAULT_ADDR", configuredVault.address)
	if err != nil {
		t.Fatal(err)
	}

	config := vaultclient.BaseConfig()
	config.AuthType = vaultclient.Token
	config.Token = configuredVault.rootToken

	err = config.ConfigureTLS(&api.TLSConfig{
		Insecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	v, err := vaultclient.NewVaultAuth(config)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := v.VaultClientOrPanic().Logical().Write("secret/foo", map[string]interface{}{
		"foo": "bar",
	}); err != nil {
		t.Fatal(err)
	}

	result, err := v.VaultClientOrPanic().Logical().Read("secret/foo")
	if err != nil {
		t.Fatalf("could not read secret using authed client, error: %s", err)
	}

	if result == nil {
		t.Fatalf("no secret returned")
	}

	if !strings.EqualFold(result.Data["foo"].(string), "bar") {
		t.Fatalf("expecting secret to be bar")
	}

}

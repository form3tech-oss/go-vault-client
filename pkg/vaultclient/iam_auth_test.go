package vaultclient

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/consul/testutil/retry"
	"github.com/hashicorp/vault/api"
)

const (
	// These are the access key and secret that should be used when calling "AssumeRole"
	// for the given AWS_TEST_ROLE_ARN.
	envVarAwsTestAccessKey = "AWS_TEST_ACCESS_KEY"
	envVarAwsTestSecretKey = "AWS_TEST_SECRET_KEY"
	envVarAwsTestRoleArn   = "AWS_TEST_ROLE_ARN"

	envVarAwsAccessKey    = "AWS_ACCESS_KEY_ID"
	envVarAwsSecretKey    = "AWS_SECRET_ACCESS_KEY"
	envVarAwsSessionToken = "AWS_SESSION_TOKEN"
)

func TestIamAuthClient(t *testing.T) {
	configuredVault, destroy := newVaultConfiguredForIamAuth(t, "1h", "1h")
	defer destroy()

	// write secret as root
	if _, err := configuredVault.rootClient.Logical().Write("secret/foo", map[string]interface{}{
		"foo": "bar",
	}); err != nil {
		t.Fatal(err)
	}

	err := os.Setenv("VAULT_ADDR", configuredVault.address)
	if err != nil {
		t.Fatal(err)
	}

	config := BaseConfig()
	config.AuthType = Iam
	config.IamRole = "test"

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

func TestExpiredIamTokenGetsRenewed(t *testing.T) {
	configuredVault, deferFunc := newVaultConfiguredForIamAuth(t, "10s", "10s")
	defer deferFunc()

	// write secret as root
	if _, err := configuredVault.rootClient.Logical().Write("secret/foo", map[string]interface{}{
		"foo": "bar",
	}); err != nil {
		t.Fatal(err)
	}

	err := os.Setenv("VAULT_ADDR", configuredVault.address)
	if err != nil {
		t.Fatal(err)
	}

	config := BaseConfig()
	config.AuthType = Iam
	config.IamRole = "test"

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

	authenticatedClient := v.VaultClientOrPanic()

	// wait for client token to be invalid
	retry.RunWith(&retry.Timer{Timeout: 1 * time.Minute, Wait: 500 * time.Millisecond}, t, func(r *retry.R) {
		_, err := authenticatedClient.Logical().Read("secret/foo")
		if err == nil {
			r.Fatal("token still valid!")
		}
	})

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

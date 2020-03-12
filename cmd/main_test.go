package main

import (
	"os"
	"testing"

	vc "github.com/form3tech-oss/go-vault-client/pkg/vaultclient"
	"github.com/stretchr/testify/assert"
)

func TestGetSecretWithValidPath(t *testing.T) {
	err := os.Setenv("VAULT_TOKEN", "devtoken")
	if err != nil {
		t.Fatal(err)
	}

	err = os.Setenv("VAULT_ADDR", "http://127.0.0.1:8200")
	if err != nil {
		t.Fatal(err)
	}

	err = vc.ConfigureDefault()
	if err != nil {
		t.Fatal(err)
	}

	testData := map[string]interface{}{"foo": "bar"}
	data, err := vc.WriteData("secret/foo", testData)
	assert.Nil(t, err, "expected writing secret to vault to succeed")
	assert.Nilf(t, data, "Expected data (%s) to be nil", data)

	secret, err := getSecret("secret/foo")
	assert.Nil(t, err)
	assert.Equal(t, `{"foo":"bar"}`, secret, "expected returned secret to equal the stored data in vault")
}

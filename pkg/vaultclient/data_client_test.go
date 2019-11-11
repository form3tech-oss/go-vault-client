package vaultclient

import (
	"os"
	"reflect"
	"testing"
)

func TestConfigure(t *testing.T) {
	vault, deferFunc := newVault(t)
	defer deferFunc()

	cfg := &Config{
		AuthType: Token,
		Token:    vault.rootToken,
	}

	err := Configure(cfg)
	if err != nil {
		t.Fatal(err)
	}
}

func TestConfigureDefault(t *testing.T) {
	vault, deferFunc := newVault(t)
	defer deferFunc()

	os.Setenv("VAULT_TOKEN", vault.rootToken)

	err := ConfigureDefault()

	os.Unsetenv("VAULT_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadWriteData(t *testing.T) {
	vault, deferFunc := newVault(t)
	defer deferFunc()

	os.Setenv("VAULT_ADDR", vault.address)
	defer os.Unsetenv("VAULT_ADDR")
	cfg := &Config{
		AuthType: Token,
		Insecure: true,
		Token:    vault.rootToken,
	}

	err := Configure(cfg)
	if err != nil {
		t.Fatal(err)
	}

	data, err := ReadData("secret/foo")
	if err != nil {
		t.Fatal(err)
	}
	if data != nil {
		t.Fatalf("expected 'secret/foo' to be empty path, got '%v'", data)
	}

	testData := map[string]interface{}{"foo": "bar"}

	data, err = WriteData("secret/foo", testData)
	if err != nil {
		t.Fatal(err)
	}

	data, err = ReadData("secret/foo")
	if err != nil {
		t.Fatal(err)
	}

	eq := reflect.DeepEqual(data, testData)
	if !eq {
		t.Errorf("Expected data (%s) to be equal to testData (%s)", data, testData)
	}
}

func TestListData(t *testing.T) {
	vault, deferFunc := newVault(t)
	defer deferFunc()

	os.Setenv("VAULT_ADDR", vault.address)
	defer os.Unsetenv("VAULT_ADDR")
	cfg := &Config{
		AuthType: Token,
		Insecure: true,
		Token:    vault.rootToken,
	}

	err := Configure(cfg)
	if err != nil {
		t.Fatal(err)
	}

	data, err := ReadData("secret/foo")
	if err != nil {
		t.Fatal(err)
	}
	if data != nil {
		t.Fatalf("expected 'secret/foo' to be empty path, got '%v'", data)
	}

	testData := map[string]interface{}{"foo": "bar"}

	data, err = WriteData("secret/foo", testData)
	if err != nil {
		t.Fatal(err)
	}

	listData, err := ListData("secret")
	if err != nil {
		t.Fatal(err)
	}

	if len(listData) != 1 {
		t.Fatalf("Expected length of keys to be 1, got %d. (%s)", len(listData), listData)
	}

	for _, key := range listData {
		_, ok := testData[key.(string)]
		if !ok {
			t.Fatalf("Unexpected key in list response: %s", key)
		}
	}
}

func TestDeleteData(t *testing.T) {
	vault, deferFunc := newVault(t)
	defer deferFunc()

	os.Setenv("VAULT_ADDR", vault.address)
	defer os.Unsetenv("VAULT_ADDR")
	cfg := &Config{
		AuthType: Token,
		Insecure: true,
		Token:    vault.rootToken,
	}

	err := Configure(cfg)
	if err != nil {
		t.Fatal(err)
	}

	data, err := ReadData("secret/foo")
	if err != nil {
		t.Fatal(err)
	}
	if data != nil {
		t.Fatalf("expected 'secret/foo' to be empty path, got '%v'", data)
	}

	testData := map[string]interface{}{"foo": "bar"}

	data, err = WriteData("secret/foo", testData)
	if err != nil {
		t.Fatal(err)
	}

	data, err = ReadData("secret/foo")
	if err != nil {
		t.Fatal(err)
	}

	eq := reflect.DeepEqual(data, testData)
	if !eq {
		t.Errorf("Expected data (%s) to be equal to testData (%s)", data, testData)
	}

	data, err = DeleteData("secret/foo")
	if err != nil {
		t.Fatal(err)
	}

	data, err = ReadData("secret/foo")
	if err != nil {
		t.Fatal(err)
	}

	if data != nil {
		t.Errorf("Expected data (%s) to be nil", data)
	}
}

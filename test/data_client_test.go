package test

import (
	"github.com/form3tech-oss/go-vault-client/v4/pkg/vaultclient"
	"os"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/suite"
)

func TestConfigure(t *testing.T) {
	vault, deferFunc := newVault(t)
	defer deferFunc()

	cfg := &vaultclient.Config{
		AuthType: vaultclient.Token,
		Token:    vault.rootToken,
	}

	err := vaultclient.Configure(cfg)
	if err != nil {
		t.Fatal(err)
	}
}

func (suite *DataClientTestSuite) TestReadWriteData() {
	data, err := vaultclient.ReadData("secret/foo")

	suite.Nil(err)
	suite.Nilf(data, "expected 'secret/foo' to be empty path, got '%v'", data)

	testData := map[string]interface{}{"foo": "bar"}

	data, err = vaultclient.WriteData("secret/foo", testData)
	suite.Nil(err)
	suite.Nilf(data, "Expected data (%s) to be nil", data)

	data, err = vaultclient.ReadData("secret/foo")
	suite.Nil(err)

	suite.Equalf(data, testData, "Expected data (%s) to be equal to testData (%s)", data, testData)
}

func (suite *DataClientTestSuite) TestListData() {
	data, err := vaultclient.ReadData("secret/foo")
	suite.Nil(err)
	suite.Nilf(data, "expected 'secret/foo' to be empty path, got '%v'", data)

	testData := map[string]interface{}{"foo": "bar"}

	data, err = vaultclient.WriteData("secret/foo", testData)
	suite.Nil(err)
	suite.Nilf(data, "Expected data (%s) to be nil", data)

	listData, err := vaultclient.ListData("secret")
	suite.Nil(err)

	suite.Lenf(listData, 1, "Expected length of keys to be 1, got %d. (%s)", len(listData), listData)

	for _, key := range listData {
		_, ok := testData[key.(string)]
		suite.Truef(ok, "Unexpected key in list response: %s", key)
	}
}

func (suite *DataClientTestSuite) TestDeleteData() {
	data, err := vaultclient.ReadData("secret/foo")
	suite.Nil(err)
	suite.Nilf(data, "expected 'secret/foo' to be empty path, got '%v'", data)

	testData := map[string]interface{}{"foo": "bar"}

	data, err = vaultclient.WriteData("secret/foo", testData)
	suite.Nil(err)
	suite.Nilf(data, "Expected data (%s) to be nil", data)

	data, err = vaultclient.ReadData("secret/foo")
	suite.Nil(err)

	suite.Equalf(data, testData, "Expected data (%s) to be equal to testData (%s)", data, testData)

	data, err = vaultclient.DeleteData("secret/foo")
	suite.Nil(err)
	suite.Nilf(data, "Expected data (%s) to be nil", data)

	data, err = vaultclient.ReadData("secret/foo")
	suite.Nil(err)
	suite.Nilf(data, "Expected data (%s) to be nil", data)
}

type DataClientTestSuite struct {
	suite.Suite
	vault     *configuredVault
	deferFunc func()
}

func (suite *DataClientTestSuite) SetupTest() {
	vault, deferFunc := newVault(suite.T())
	suite.vault = vault
	suite.deferFunc = deferFunc

	os.Setenv("VAULT_ADDR", vault.address)
	defer os.Unsetenv("VAULT_ADDR")

	config := vaultclient.BaseConfig()
	config.AuthType = vaultclient.Token
	config.Token = vault.rootToken

	err := config.ConfigureTLS(&api.TLSConfig{
		Insecure: true,
	})
	suite.Nil(err)

	err = vaultclient.Configure(config)
	suite.Nil(err)
}

func (suite *DataClientTestSuite) TeardownTest() {
	suite.deferFunc()
}

func TestDataClientTestSuite(t *testing.T) {
	suite.Run(t, new(DataClientTestSuite))

}

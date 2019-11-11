package vaultclient

import (
	"os"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/suite"
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

func (suite *DataClientTestSuite) TestReadWriteData() {
	data, err := ReadData("secret/foo")

	suite.Nil(err)
	suite.Nilf(data, "expected 'secret/foo' to be empty path, got '%v'", data)

	testData := map[string]interface{}{"foo": "bar"}

	data, err = WriteData("secret/foo", testData)
	suite.Nil(err)
	suite.Nilf(data, "Expected data (%s) to be nil", data)

	data, err = ReadData("secret/foo")
	suite.Nil(err)

	suite.Equalf(data, testData, "Expected data (%s) to be equal to testData (%s)", data, testData)
}

func (suite *DataClientTestSuite) TestListData() {
	data, err := ReadData("secret/foo")
	suite.Nil(err)
	suite.Nilf(data, "expected 'secret/foo' to be empty path, got '%v'", data)

	testData := map[string]interface{}{"foo": "bar"}

	data, err = WriteData("secret/foo", testData)
	suite.Nil(err)
	suite.Nilf(data, "Expected data (%s) to be nil", data)

	listData, err := ListData("secret")
	suite.Nil(err)

	suite.Lenf(listData, 1, "Expected length of keys to be 1, got %d. (%s)", len(listData), listData)

	for _, key := range listData {
		_, ok := testData[key.(string)]
		suite.Truef(ok, "Unexpected key in list response: %s", key)
	}
}

func (suite *DataClientTestSuite) TestDeleteData() {
	data, err := ReadData("secret/foo")
	suite.Nil(err)
	suite.Nilf(data, "expected 'secret/foo' to be empty path, got '%v'", data)

	testData := map[string]interface{}{"foo": "bar"}

	data, err = WriteData("secret/foo", testData)
	suite.Nil(err)
	suite.Nilf(data, "Expected data (%s) to be nil", data)

	data, err = ReadData("secret/foo")
	suite.Nil(err)

	suite.Equalf(data, testData, "Expected data (%s) to be equal to testData (%s)", data, testData)

	data, err = DeleteData("secret/foo")
	suite.Nil(err)
	suite.Nilf(data, "Expected data (%s) to be nil", data)

	data, err = ReadData("secret/foo")
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

	config := BaseConfig()
	config.AuthType = Token
	config.Token = vault.rootToken

	err := config.ConfigureTLS(&api.TLSConfig{
		Insecure: true,
	})
	suite.Nil(err)

	err = Configure(config)
	suite.Nil(err)
}

func (suite *DataClientTestSuite) TeardownTest() {
	suite.deferFunc()
}

func TestDataClientTestSuite(t *testing.T) {
	suite.Run(t, new(DataClientTestSuite))

}

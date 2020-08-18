package test

import (
	"fmt"
	"github.com/form3tech-oss/go-vault-client/v4/pkg/vaultclient"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"
	hclog "github.com/hashicorp/go-hclog"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	credAppRole "github.com/hashicorp/vault/builtin/credential/approle"
	vaultaws "github.com/hashicorp/vault/builtin/credential/aws"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
)

type configuredVault struct {
	address    string
	rootToken  string
	rootClient *api.Client
}

func newVaultConfiguredForIamAuth(t *testing.T, leaseTtl, maxLeaseTtl string) (*configuredVault, func()) {
	logger := logging.NewVaultLogger(hclog.Trace)
	coreConfig := &vault.CoreConfig{
		Logger: logger,
		CredentialBackends: map[string]logical.Factory{
			"aws": vaultaws.Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()

	vault.TestWaitActive(t, cluster.Cores[0].Core)
	client := cluster.Cores[0].Client

	// Setup Vault
	if err := client.Sys().EnableAuthWithOptions("aws", &api.EnableAuthOptions{
		Type: "aws",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: leaseTtl,
			MaxLeaseTTL:     maxLeaseTtl,
		},
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := client.Logical().Write("auth/aws/role/test", map[string]interface{}{
		"auth_type": "iam",
		"policies":  "foowriter",
		// Retain thru the account number of the given arn and wildcard the rest.
		"bound_iam_principal_arn": os.Getenv(envVarAwsTestRoleArn)[:25] + "*",
	}); err != nil {
		fmt.Println(err)
		t.Fatal(err)
	}

	policy := `
	path "secret/foo" {
  		capabilities = ["read", "create"]
	},
	path "secret/global" {
  		capabilities = ["read", "create"]
	},
	path "secret/regional" {
  		capabilities = ["read", "create"]
	},
	path "secret/fallback" {
		capabilities = ["read", "create"]
	}
`
	if err := client.Sys().PutPolicy("foowriter", policy); err != nil {
		t.Fatal(err)
	}

	if err := setAwsEnvCreds(); err != nil {
		t.Fatal(err)
	}

	deferFunc := func() {
		cluster.Cleanup()
		if err := unsetAwsEnvCreds(); err != nil {
			t.Fatal(err)
		}
	}

	return &configuredVault{
		address:    client.Address(),
		rootToken:  client.Token(),
		rootClient: client,
	}, deferFunc

}

func newVaultConfiguredForAppRole(t *testing.T, leaseTtl, maxLeaseTtl string) (*configuredVault, func()) {
	logger := logging.NewVaultLogger(hclog.Trace)
	coreConfig := &vault.CoreConfig{
		DisableMlock: true,
		DisableCache: true,
		Logger:       logger,
		CredentialBackends: map[string]logical.Factory{
			"approle": credAppRole.Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()

	vault.TestWaitActive(t, cluster.Cores[0].Core)
	client := cluster.Cores[0].Client
	deferFunc := func() {
		cluster.Cleanup()
	}

	err := client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("auth/approle/role/test1", map[string]interface{}{
		"bind_secret_id": "true",
		"token_ttl":      leaseTtl,
		"token_max_ttl":  maxLeaseTtl,
		"policies":       "testapppolicy",
	})
	if err != nil {
		t.Fatal(err)
	}

	policy := `
	path "secret/baz" {
  		capabilities = ["read", "create"]
	}
`
	if err := client.Sys().PutPolicy("testapppolicy", policy); err != nil {
		t.Fatal(err)
	}

	return &configuredVault{
		address:    client.Address(),
		rootToken:  client.Token(),
		rootClient: client,
	}, deferFunc
}

func newVault(t *testing.T) (*configuredVault, func()) {
	logger := logging.NewVaultLogger(hclog.Trace)
	coreConfig := &vault.CoreConfig{
		DisableMlock: true,
		DisableCache: true,
		Logger:       logger,
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()

	vault.TestWaitActive(t, cluster.Cores[0].Core)
	client := cluster.Cores[0].Client
	deferFunc := func() {
		cluster.Cleanup()
	}

	return &configuredVault{
		address:    client.Address(),
		rootToken:  client.Token(),
		rootClient: client,
	}, deferFunc
}

func setAwsEnvCreds() error {
	creds := credentials.NewStaticCredentials(os.Getenv(envVarAwsTestAccessKey), os.Getenv(envVarAwsTestSecretKey), "")
	sess, err := vaultclient.CreateSession(creds, os.Getenv(vaultclient.EnvVarAwsRegion))
	if err != nil {
		return err
	}
	client := sts.New(sess)

	roleArn := os.Getenv(envVarAwsTestRoleArn)
	uid, err := uuid.GenerateUUID()
	if err != nil {
		return err
	}

	input := &sts.AssumeRoleInput{
		RoleArn:         &roleArn,
		RoleSessionName: &uid,
	}
	output, err := client.AssumeRole(input)
	if err != nil {
		return err
	}

	if err := os.Setenv(envVarAwsAccessKey, *output.Credentials.AccessKeyId); err != nil {
		return err
	}
	if err := os.Setenv(envVarAwsSecretKey, *output.Credentials.SecretAccessKey); err != nil {
		return err
	}
	return os.Setenv(envVarAwsSessionToken, *output.Credentials.SessionToken)
}

func unsetAwsEnvCreds() error {
	if err := os.Unsetenv(envVarAwsAccessKey); err != nil {
		return err
	}
	if err := os.Unsetenv(envVarAwsSecretKey); err != nil {
		return err
	}
	return os.Unsetenv(envVarAwsSessionToken)
}

func setEnv(key, value string) func() {
	if err := os.Setenv(key, value); err != nil {
		panic(err)
	}
	return func() {
		if err := os.Unsetenv(key); err != nil {
			panic(err)
		}
	}
}

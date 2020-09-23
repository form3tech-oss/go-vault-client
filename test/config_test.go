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

func TestDefaultConfigWhenK8sRoleSpecified(t *testing.T) {
	defer setEnv("K8S_ROLE", "greatservice")()
	config := vaultclient.NewDefaultConfig()

	if !strings.EqualFold("greatservice", config.K8sRole) {
		t.Fatalf("expected k8s role greatservice but got %s", config.K8sRole)
	}

	if !strings.EqualFold("k8s-greatservice", config.K8sPath) {
		t.Fatalf("expected k8s path k8s-greatservice but got %s", config.K8sPath)
	}

	if config.AuthType != vaultclient.K8s {
		t.Fatalf("expected auth type to be k8s")
	}
}

func TestDefaultConfigWhenK8sRoleAndPathSpecified(t *testing.T) {
	defer setEnv("K8S_ROLE", "myservice")()
	defer setEnv("K8S_PATH", "kubernetes")()
	config := vaultclient.NewDefaultConfig()

	if !strings.EqualFold("myservice", config.K8sRole) {
		t.Fatalf("expected k8s role myservice but got %s", config.K8sRole)
	}

	if !strings.EqualFold("kubernetes", config.K8sPath) {
		t.Fatalf("expected k8s path kubernetes but got %s", config.K8sPath)
	}

	if config.AuthType != vaultclient.K8s {
		t.Fatalf("expected auth type to be k8s")
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

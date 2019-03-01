package vaultclient

import (
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/hashicorp/vault/api"
	awsauth "github.com/hashicorp/vault/builtin/credential/aws"
)

type AuthType int

const (
	Token AuthType = iota + 1
	Iam
)

type iamAuth struct {
	role   string
	client *api.Client
	auth   *Auth
}

type tokenAuth struct {
	client *api.Client
}

type Config struct {
	AuthType AuthType
	Token    string
	IamRole  string
	Insecure bool
}

type Auth struct {
	token  string
	expiry time.Time
}

var (
	expirationWindow = time.Duration(10) * time.Second
)

type VaultAuth interface {
	VaultClient() (*api.Client, error)
	VaultClientOrPanic() *api.Client
}

func NewDefaultConfig() *Config {
	token := os.Getenv("VAULT_TOKEN")
	if token != "" {
		return &Config{
			AuthType: Token,
			Token:    token,
		}
	}

	role := os.Getenv("VAULT_IAM_ROLE")
	if role != "" {
		return &Config{
			AuthType: Iam,
			IamRole:  role,
		}
	}

	return nil
}

func NewVaultAuth(cfg *Config) (VaultAuth, error) {
	config := api.DefaultConfig()
	err := config.ConfigureTLS(&api.TLSConfig{Insecure: cfg.Insecure})
	if err != nil {
		return nil, err
	}
	c, err := api.NewClient(config)

	if err != nil {
		return nil, err
	}

	if cfg.AuthType == Token {
		c.SetToken(cfg.Token)
		return &tokenAuth{
			client: c,
		}, nil
	}

	return &iamAuth{
		client: c,
		role:   cfg.IamRole,
	}, nil
}

func (v *iamAuth) getAuth() (*Auth, error) {

	s := session.Must(session.NewSession())
	data, err := awsauth.GenerateLoginData(s.Config.Credentials, "")

	if err != nil {
		return nil, nil
	}

	data["role"] = v.role

	resp, err := v.client.Logical().Write("auth/aws/login", data)
	if err != nil {
		return nil, err
	}

	tokenTtl, err := resp.TokenTTL()
	if err != nil {
		return nil, err
	}

	return &Auth{
		token:  resp.Auth.ClientToken,
		expiry: time.Now().UTC().Add(tokenTtl),
	}, nil
}

func (v *iamAuth) IsTokenExpired() bool {
	if v.auth == nil {
		return true
	}

	return v.auth.expiry.Add(expirationWindow).After(time.Now().UTC())
}

func (v *iamAuth) VaultClient() (*api.Client, error) {
	if !v.IsTokenExpired() {
		return v.client, nil
	}

	var err error
	v.auth, err = v.getAuth()
	if err != nil {
		return nil, err
	}
	v.client.SetToken(v.auth.token)
	return v.client, nil
}

func (v *iamAuth) VaultClientOrPanic() *api.Client {
	client, err := v.VaultClient()
	if err != nil {
		panic(err)
	}
	return client
}

func (t *tokenAuth) VaultClient() (*api.Client, error) {
	return t.client, nil
}

func (t *tokenAuth) VaultClientOrPanic() *api.Client {
	return t.client
}

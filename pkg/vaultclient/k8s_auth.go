package vaultclient

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"io/ioutil"
	"time"
)

func (k *k8sAuth) VaultClientOrPanic() *api.Client {
	client, err := k.VaultClient()
	if err != nil {
		panic(err)
	}
	return client
}

func (k *k8sAuth) VaultClient() (*api.Client, error) {
	if !k.auth.IsTokenExpired() {
		return k.client, nil
	}
	var err error
	k.auth, err = k.getAuth()
	if err != nil {
		return nil, err
	}
	k.client.SetToken(k.auth.token)
	return k.client, nil
}

func (k *k8sAuth) getAuth() (*Auth, error) {
	resp, err := k.login()
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

func (k *k8sAuth) login() (*api.Secret, error) {
	// this path comes from https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#service-account-admission-controller
	// which is the path that the kubernetes service account controller mounts the jwt token
	jwt, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, err
	}
	data := map[string]interface{}{
		"jwt":  string(jwt),
		"role": k.role,
	}
	return k.client.Logical().Write(fmt.Sprintf("auth/%s/login", k.path), data)
}

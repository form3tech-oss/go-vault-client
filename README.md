# go-vault-client

Gives you an authenticated vault client (iam/token)

## Usage

go-vault-client supports three modes of authentication:

* [`AppRole`](https://www.vaultproject.io/docs/auth/approle.html)
* [`Token`](https://www.vaultproject.io/docs/auth/token.html)
* [`IAM (AWS)`](https://www.vaultproject.io/docs/auth/aws.html)

## Install

```bash
go get -u github.com/form3tech-oss/go-vault-client/v4
```

## Configuration

The configuration object used by this client is a superset of the Vault `api.Config` struct.

All configuration which would normally be possible with the Vault client is also possible here, but will not be documented.

Please note: this client no longer configures TLS for you as part of the default configuration.

### Defaults

First create a `vaultclient.Config` using

```go
config := vaultclient.NewDefaultConfig()
```

The precedence is as follows:

1. If you have the `VAULT_APP_ROLE`, `VAULT_APP_ROLE_ID` and `VAULT_APP_SECRET_ID` env variables set this will return a config setup for `AppRole` auth.
1. If you have the `VAULT_ROLE` env variable set this will return a config setup for `Iam` auth.
1. If you have the `VAULT_TOKEN` env variable set this will return a config setup for `Token` auth.

The recommended way to use this client is to set the `VAULT_TOKEN` env variable as part of your test setup and set the `VAULT_ROLE` env
variable as part of your docker container definition so you will get `Token` auth in your tests and `Iam` auth on AWS.

### Manual

It is also possible to manually configure the client if you do not wish to rely on environment variables.

```go
clientConfig := vaultclient.BaseConfig()
```

From here, you may set the `AuthType` and related properties of the configuration manually.

No precedence exists here; only the configured `AuthType` will be used, and a missing `AuthType` will return an error.

## Vault Auth

Create a new vault auth and hang onto the instance.
```go
v, err := vaultclient.NewVaultAuth(vaultclient.NewDefaultConfig())
```

Use the vault auth instance every time you want to access vault:
```go
 v.VaultClientOrPanic().Logical... etc
```

It is important to always call the `VaultClient` func each time and not capture the client otherwise the token will not be renewed.

There is a func to return a vault client or err if you dont want to have a panic:

```go
client, err := v.VaultClient()

if err != nil {
	fmt.Errorf("error getting vault client: %s", err)
	return
}

// client can be used here

```

## Tests
Tests in the repository resides in own module `module github.com/form3tech-oss/go-vault-client/v4/pkg/test`. The reason behind is to isolate the dependency from `hashicorp/auth` package solely to the scope of tests.

According to the hashicorp/vault maintainers, only `api` and `sdk` packages are eligible to be imported. Other packages are considered `internal` and shouldn't be imported. See [thread](https://github.com/hashicorp/vault/issues/9575#issuecomment-665013482).
> No one should be importing github.com/hashicorp/vault, only the api and sdk modules. The top-level vault module is not intended to be a dependency for other projects, we're using go.mod solely to manage our own dependencies here.

Isolating tests dependency within own module slims down `vaulclient`'s dependencies and ultimately `vaultclient` package depends only on `hashicorp/vault/{api,sdk}`. See the [PR](https://github.com/form3tech-oss/go-vault-client/pull/23).

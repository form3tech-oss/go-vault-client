# go-vault-client
Gives you an authenticated vault client (iam/token)


# Usage
go-vault-client supports two modes of authentication `Token` and `Iam`.  First create a `vaultclient.Config` using

```go
config := vaultclient.NewDefaultConfig()
```

If you have the `VAULT_TOKEN` env variable set this will return a config setup for `Token` auth
If you have the `VAULT_ROLE` env variable set this will return a config setup for `Iam` auth

The recommended way to use this client is to set the `VAULT_TOKEN` env variable as part of your test setup and set the `VAULT_ROLE` env
variable as part of your docker container definition so you will get `Token` auth in your tests and `Iam` auth on AWS.


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
module github.com/form3tech-oss/go-vault-client/v4

go 1.13

replace github.com/form3tech-oss/go-vault-client/v4/pkg/vaultclient => ./pkg/vaultclient

require (
	github.com/form3tech-oss/go-vault-client/v4/pkg/vaultclient v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.5.1
	github.com/urfave/cli/v2 v2.2.0
)

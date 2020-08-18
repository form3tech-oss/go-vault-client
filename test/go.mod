module github.com/form3tech-oss/go-vault-client/v4/pkg/test

go 1.14

replace (
	github.com/form3tech-oss/go-vault-client/v4/pkg/vaultclient => ./../pkg/vaultclient
	github.com/hashicorp/vault/api => github.com/hashicorp/vault/api v1.0.5-0.20200817232951-d7307fcdfed7 //https://github.com/hashicorp/vault/issues/9575
)

require (
	github.com/aws/aws-sdk-go v1.34.6
	github.com/form3tech-oss/go-vault-client/v4/pkg/vaultclient v0.0.0-00010101000000-000000000000
	github.com/hashicorp/consul/sdk v0.6.0
	github.com/hashicorp/go-hclog v0.14.1
	github.com/hashicorp/go-uuid v1.0.2
	github.com/hashicorp/vault v1.5.0
	github.com/hashicorp/vault/api v1.0.5-0.20200817232951-d7307fcdfed7
	github.com/hashicorp/vault/sdk v0.1.14-0.20200817232951-d7307fcdfed7
	github.com/stretchr/testify v1.5.1
)

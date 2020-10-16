module github.com/form3tech-oss/go-vault-client/v4/pkg/test

go 1.14

// to fix https://github.com/hashicorp/vault/issues/9575
replace (
 github.com/hashicorp/vault/api => github.com/hashicorp/vault/api v1.0.5-0.20200817232951-d7307fcdfed7
 github.com/form3tech-oss/go-vault-client/v4 => ../
)

require (
	github.com/aws/aws-sdk-go v1.34.7
	github.com/form3tech-oss/go-vault-client/v4 v4.1.3-0.20200820092125-e804702f6ad4
	github.com/hashicorp/consul/sdk v0.6.0
	github.com/hashicorp/go-hclog v0.14.1
	github.com/hashicorp/go-memdb v1.0.4 // indirect
	github.com/hashicorp/go-uuid v1.0.2
	github.com/hashicorp/vault v1.5.0
	github.com/hashicorp/vault/api v1.0.5-0.20200817232951-d7307fcdfed7
	github.com/hashicorp/vault/sdk v0.1.14-0.20200817232951-d7307fcdfed7
	github.com/jefferai/jsonx v1.0.1 // indirect
	github.com/keybase/go-crypto v0.0.0-20190828182435-a05457805304 // indirect
	github.com/stretchr/testify v1.5.1
)

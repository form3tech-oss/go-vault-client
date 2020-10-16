package vaultclient

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/awsutil"
)

func (v *iamAuth) VaultClientOrPanic() *api.Client {
	client, err := v.VaultClient()
	if err != nil {
		panic(err)
	}
	return client
}

func (v *iamAuth) VaultClient() (*api.Client, error) {
	if !v.auth.IsTokenExpired() {
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

func (v *iamAuth) getAuth() (*Auth, error) {
	baseSession := session.Must(session.NewSession())

	resp, err := v.loginWithFallback(baseSession)
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

func (v *iamAuth) login(session *session.Session) (*api.Secret, error) {
	data, err := generateLoginData(session)
	if err != nil {
		return nil, err
	}
	data["role"] = v.role
	return v.client.Logical().Write("auth/aws/login", data)
}

func (v *iamAuth) loginWithFallback(session *session.Session) (*api.Secret, error) {
	creds := session.Config.Credentials
	configuredRegion := os.Getenv(EnvVarAwsRegion)
	stsSession, err := CreateSession(creds, configuredRegion)
	if err != nil {
		return nil, err
	}
	resp, err := v.login(stsSession)
	if err != nil {
		stsSession, err = createSessionWithResolver(creds, configuredRegion, fallbackEndpointSigningResolver)
		if err != nil {
			return nil, err
		}
		return v.login(stsSession)
	}
	return resp, err
}

func generateLoginData(stsSession *session.Session) (map[string]interface{}, error) {
	loginData := make(map[string]interface{})

	var params *sts.GetCallerIdentityInput
	svc := sts.New(stsSession)
	stsRequest, _ := svc.GetCallerIdentityRequest(params)
	err := stsRequest.Sign()
	if err != nil {
		return nil, err
	}

	headersJson, err := json.Marshal(stsRequest.HTTPRequest.Header)
	if err != nil {
		return nil, err
	}
	requestBody, err := ioutil.ReadAll(stsRequest.HTTPRequest.Body)
	if err != nil {
		return nil, err
	}
	loginData["iam_http_request_method"] = stsRequest.HTTPRequest.Method
	loginData["iam_request_url"] = base64.StdEncoding.EncodeToString([]byte(stsRequest.HTTPRequest.URL.String()))
	loginData["iam_request_headers"] = base64.StdEncoding.EncodeToString(headersJson)
	loginData["iam_request_body"] = base64.StdEncoding.EncodeToString(requestBody)

	return loginData, nil
}

func CreateSession(creds *credentials.Credentials, configuredRegion string) (*session.Session, error) {
	return createSessionWithResolver(creds, configuredRegion, endpointSigningResolver)
}

func createSessionWithResolver(creds *credentials.Credentials, configuredRegion string, resolver func(service string, region string, optFns ...func(*endpoints.Options)) (endpoints.ResolvedEndpoint, error)) (*session.Session, error) {
	region, err := awsutil.GetRegion(configuredRegion)
	if err != nil {
		return nil, err
	}
	s, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Credentials:      creds,
			Region:           &region,
			EndpointResolver: endpoints.ResolverFunc(resolver),
		},
	})
	return s, err
}

func fallbackEndpointSigningResolver(service, region string, optFns ...func(*endpoints.Options)) (endpoints.ResolvedEndpoint, error) {
	return endpoints.DefaultResolver().EndpointFor(service, region, optFns...)
}

func endpointSigningResolver(service, region string, optFns ...func(*endpoints.Options)) (endpoints.ResolvedEndpoint, error) {
	defaultEndpoint, err := endpoints.DefaultResolver().EndpointFor(service, region, optFns...)
	if err != nil {
		return defaultEndpoint, err
	}
	defaultEndpoint.SigningName = service
	stsRegion, present := os.LookupEnv(EnvVarStsAwsRegion)
	if present {
		defaultEndpoint.SigningRegion = stsRegion
		defaultEndpoint.URL = fmt.Sprintf("https://%s.%v.amazonaws.com", service, stsRegion)
	}
	return defaultEndpoint, nil
}

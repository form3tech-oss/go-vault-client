package vaultclient

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/awsutil"
	"io/ioutil"
	"os"
)

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
	configuredRegion := os.Getenv(envVarAwsRegion)
	stsSession, err := createSession(creds, configuredRegion)
	if err != nil {
		return nil, err
	}
	resp, err := v.login(stsSession)
	if err != nil {
		stsSession, err = createFallbackSession(creds, configuredRegion)
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

func createFallbackSession(creds *credentials.Credentials, configuredRegion string) (*session.Session, error) {
	return createSessionWithResolver(configuredRegion, creds, globalEndpointSigningResolver)
}

func createSession(creds *credentials.Credentials, configuredRegion string) (*session.Session, error) {
	return createSessionWithResolver(configuredRegion, creds, endpointSigningResolver)
}

func createSessionWithResolver(configuredRegion string, creds *credentials.Credentials, resolver func(service string, region string, optFns ...func(*endpoints.Options)) (endpoints.ResolvedEndpoint, error)) (*session.Session, error) {
	region := awsutil.GetOrDefaultRegion(hclog.Default(), configuredRegion)
	s, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Credentials:      creds,
			Region:           &region,
			EndpointResolver: endpoints.ResolverFunc(resolver),
		},
	})
	return s, err
}

func globalEndpointSigningResolver(service, region string, optFns ...func(*endpoints.Options)) (endpoints.ResolvedEndpoint, error) {
	return endpoints.DefaultResolver().EndpointFor(service, region, optFns...)
}

func endpointSigningResolver(service, region string, optFns ...func(*endpoints.Options)) (endpoints.ResolvedEndpoint, error) {
	defaultEndpoint, err := endpoints.DefaultResolver().EndpointFor(service, region, optFns...)
	if err != nil {
		return defaultEndpoint, err
	}
	defaultEndpoint.SigningName = service
	stsRegion, present := os.LookupEnv(envVarStsAwsRegion)
	if present {
		defaultEndpoint.SigningRegion = stsRegion
		defaultEndpoint.URL = fmt.Sprintf("https://%s.%v.amazonaws.com", service, stsRegion)
	}
	return defaultEndpoint, nil
}

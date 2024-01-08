/*
Copyright 2021 The Dapr Authors
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package aws

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	awssh "github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	"github.com/aws/rolesanywhere-credential-helper/rolesanywhere"

	"github.com/dapr/components-contrib/common/authentication/svid"
	"github.com/dapr/kit/logger"
	kitmd "github.com/dapr/kit/metadata"
	"github.com/dapr/kit/ptr"
)

type Options struct {
	Logger     logger.Logger
	Properties map[string]string

	Region       string
	Endpoint     string
	AccessKey    string
	SecretKey    string
	SessionToken string
}

type metadata struct {
	X509TrustProfileArn *string `json:"x509TrustProfileArn" mapstructure:"x509TrustProfileArn" mdignore:"true"`
	X509TrustAnchorArn  *string `json:"x509TrustAnchorArn" mapstructure:"x509TrustAnchorArn" mdignore:"true"`
	X509RoleArn         *string `json:"x509RoleArn" mapstructure:"x509RoleArn" mdignore:"true"`
}

type AWS struct {
	lock   sync.RWMutex
	logger logger.Logger

	md   *metadata
	svid *svid.SVID

	region       string
	endpoint     string
	accessKey    string
	secretKey    string
	sessionToken string
}

func New(opts Options) (*AWS, error) {
	var md metadata
	if err := kitmd.DecodeMetadata(opts.Properties, &md); err != nil {
		return nil, err
	}

	svid, err := svid.FromMetadata(opts.Properties)
	if err != nil {
		return nil, err
	}

	return &AWS{
		md:           &md,
		svid:         svid,
		logger:       opts.Logger,
		region:       opts.Region,
		endpoint:     opts.Endpoint,
		accessKey:    opts.AccessKey,
		secretKey:    opts.SecretKey,
		sessionToken: opts.SessionToken,
	}, nil
}

func (a *AWS) AccessKey() string {
	a.lock.RLock()
	defer a.lock.RUnlock()
	return a.accessKey
}

func (a *AWS) SecretKey() string {
	return a.secretKey
}

func (a *AWS) GetClient(ctx context.Context) (*session.Session, error) {
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.md.X509RoleArn != nil && a.md.X509TrustAnchorArn != nil && a.md.X509TrustProfileArn != nil {
		a.logger.Debug("using X.509 RolesAnywhere authentication using Dapr SVID")
		return a.getX509Client(ctx)
	}

	return a.getTokenClient()
}

func (a *AWS) getTokenClient() (*session.Session, error) {
	awsConfig := aws.NewConfig()

	if a.region != "" {
		awsConfig = awsConfig.WithRegion(a.region)
	}

	if a.accessKey != "" && a.secretKey != "" {
		awsConfig = awsConfig.WithCredentials(credentials.NewStaticCredentials(a.accessKey, a.secretKey, a.sessionToken))
	}

	if a.endpoint != "" {
		awsConfig = awsConfig.WithEndpoint(a.endpoint)
	}

	awsSession, err := session.NewSessionWithOptions(session.Options{
		Config:            *awsConfig,
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return nil, err
	}

	userAgentHandler := request.NamedHandler{
		Name: "UserAgentHandler",
		Fn:   request.MakeAddToUserAgentHandler("dapr", logger.DaprVersion),
	}
	awsSession.Handlers.Build.PushBackNamed(userAgentHandler)

	return awsSession, nil
}

func (a *AWS) getX509Client(ctx context.Context) (*session.Session, error) {
	trustAnchor, err := arn.Parse(*a.md.X509TrustAnchorArn)
	if err != nil {
		return nil, err
	}

	profile, err := arn.Parse(*a.md.X509TrustProfileArn)
	if err != nil {
		return nil, err
	}

	if trustAnchor.Region != profile.Region {
		return nil, fmt.Errorf("trust anchor and profile must be in the same region: trustAnchor=%s, profile=%s",
			trustAnchor.Region, profile.Region)
	}

	mySession, err := session.NewSession()
	if err != nil {
		return nil, err
	}

	config := aws.NewConfig().WithRegion(trustAnchor.Region).WithLogLevel(aws.LogOff)
	rolesAnywhereClient := rolesanywhere.New(mySession, config)

	leaf, ints := a.svid.Leaf(), a.svid.Intermediates()
	signer, alg, err := awssh.GetFileSystemSigner(*a.svid.PrivateKey(), leaf, ints)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	rolesAnywhereClient.Handlers.Build.RemoveByName("core.SDKVersionUserAgentHandler")
	rolesAnywhereClient.Handlers.Build.PushBackNamed(request.NamedHandler{Name: "v4x509.CredHelperUserAgentHandler", Fn: request.MakeAddToUserAgentHandler("dapr.io", logger.DaprVersion)})
	rolesAnywhereClient.Handlers.Sign.Clear()
	rolesAnywhereClient.Handlers.Sign.PushBackNamed(request.NamedHandler{Name: "v4x509.SignRequestHandler", Fn: awssh.CreateRequestSignFunction(signer, alg, leaf, ints)})

	createSessionRequest := rolesanywhere.CreateSessionInput{
		Cert:           ptr.Of(string(a.svid.ChainPEM())),
		ProfileArn:     a.md.X509TrustProfileArn,
		TrustAnchorArn: a.md.X509TrustAnchorArn,
		RoleArn:        a.md.X509RoleArn,
	}
	output, err := rolesAnywhereClient.CreateSessionWithContext(ctx, &createSessionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to create session using dapr app dentity: %w", err)
	}

	if len(output.CredentialSet) != 1 {
		return nil, fmt.Errorf("expected 1 credential set from X.509 rolesanyway response, got %d", len(output.CredentialSet))
	}

	a.accessKey = *output.CredentialSet[0].Credentials.AccessKeyId
	a.secretKey = *output.CredentialSet[0].Credentials.SecretAccessKey
	a.sessionToken = *output.CredentialSet[0].Credentials.SessionToken

	return a.getTokenClient()
}

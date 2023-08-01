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

package oidc

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	ccreds "golang.org/x/oauth2/clientcredentials"
)

func Test_toConfig(t *testing.T) {
	tests := map[string]struct {
		opts      ClientCredentialsOptions
		expConfig *ccreds.Config
		expErr    bool
	}{
		"openid not in scopes should error": {
			opts: ClientCredentialsOptions{
				TokenURL:     "https://localhost:8080",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				Scopes:       []string{"profile"},
				Audiences:    []string{"audience"},
			},
			expErr: true,
		},
		"non-https endpoint should error": {
			opts: ClientCredentialsOptions{
				TokenURL:     "http://localhost:8080",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				Audiences:    []string{"audience"},
			},
			expErr: true,
		},
		"bad CA certificate should error": {
			opts: ClientCredentialsOptions{
				TokenURL:     "https://localhost:8080",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				Audiences:    []string{"audience"},
				CAPEM:        []byte("ca-pem"),
			},
			expErr: true,
		},
		"no audiences should error": {
			opts: ClientCredentialsOptions{
				TokenURL:     "https://localhost:8080",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
			},
			expErr: true,
		},
		"should default scope": {
			opts: ClientCredentialsOptions{
				TokenURL:     "https://localhost:8080",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				Audiences:    []string{"audience"},
			},
			expConfig: &ccreds.Config{
				ClientID:       "client-id",
				ClientSecret:   "client-secret",
				TokenURL:       "https://localhost:8080",
				Scopes:         []string{"openid"},
				EndpointParams: url.Values{"audience": []string{"audience"}},
			},
			expErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			config, _, err := test.opts.toConfig()
			assert.Equalf(t, test.expErr, err != nil, "%v", err)
			assert.Equal(t, test.expConfig, config)
		})
	}
}

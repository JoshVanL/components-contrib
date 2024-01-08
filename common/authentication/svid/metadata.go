/*
Copyright 2023 The Dapr Authors
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

package svid

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/dapr/kit/crypto/pem"
)

const (
	mdKeyChain   = "__internal.dapr.io/svid-certificate-chain"
	mdKeyPrivKey = "__internal.dapr.io/svid-private-key"
)

type SVID struct {
	svid     *x509svid.SVID
	pk       *ecdsa.PrivateKey
	chainPEM []byte
}

func FromMetadata(md map[string]string) (*SVID, error) {
	if md == nil {
		return nil, errors.New("metadata is nil")
	}

	pkRaw, ok := md[mdKeyPrivKey]
	if !ok {
		return nil, nil
	}
	chainRaw, ok := md[mdKeyChain]
	if !ok {
		return nil, nil
	}

	svid, err := x509svid.ParseRaw([]byte(chainRaw), []byte(pkRaw))
	if err != nil {
		return nil, fmt.Errorf("failed to parse SVID from metadata: %w", err)
	}

	if len(svid.Certificates) == 0 {
		return nil, errors.New("dapr SVID chain is empty")
	}

	pk, ok := svid.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected SVID private key to be *ecdsa.PrivateKey, got %T", svid.PrivateKey)
	}

	chainPEM, err := pem.EncodeX509Chain(svid.Certificates)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SVID chain: %w", err)
	}

	return &SVID{
		svid:     svid,
		pk:       pk,
		chainPEM: chainPEM,
	}, nil
}

func (s *SVID) PrivateKey() *ecdsa.PrivateKey {
	return s.pk
}

func (s *SVID) Leaf() *x509.Certificate {
	return s.svid.Certificates[0]
}

func (s *SVID) Intermediates() []*x509.Certificate {
	return s.svid.Certificates[1:]
}

func (s *SVID) ChainPEM() []byte {
	return s.chainPEM
}

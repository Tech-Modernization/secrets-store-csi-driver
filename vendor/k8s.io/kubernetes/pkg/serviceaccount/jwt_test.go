/*
Copyright 2014 The Kubernetes Authors.

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

package serviceaccount_test

import (
	"context"
	"reflect"
	"testing"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	certutil "k8s.io/client-go/util/cert"
	serviceaccountcontroller "k8s.io/kubernetes/pkg/controller/serviceaccount"
	"k8s.io/kubernetes/pkg/serviceaccount"
)

const otherPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArXz0QkIG1B5Bj2/W69GH
rsm5e+RC3kE+VTgocge0atqlLBek35tRqLgUi3AcIrBZ/0YctMSWDVcRt5fkhWwe
Lqjj6qvAyNyOkrkBi1NFDpJBjYJtuKHgRhNxXbOzTSNpdSKXTfOkzqv56MwHOP25
yP/NNAODUtr92D5ySI5QX8RbXW+uDn+ixul286PBW/BCrE4tuS88dA0tYJPf8LCu
sqQOwlXYH/rNUg4Pyl9xxhR5DIJR0OzNNfChjw60zieRIt2LfM83fXhwk8IxRGkc
gPZm7ZsipmfbZK2Tkhnpsa4QxDg7zHJPMsB5kxRXW0cQipXcC3baDyN9KBApNXa0
PwIDAQAB
-----END PUBLIC KEY-----`

const rsaPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA249XwEo9k4tM8fMxV7zx
OhcrP+WvXn917koM5Qr2ZXs4vo26e4ytdlrV0bQ9SlcLpQVSYjIxNfhTZdDt+ecI
zshKuv1gKIxbbLQMOuK1eA/4HALyEkFgmS/tleLJrhc65tKPMGD+pKQ/xhmzRuCG
51RoiMgbQxaCyYxGfNLpLAZK9L0Tctv9a0mJmGIYnIOQM4kC1A1I1n3EsXMWmeJU
j7OTh/AjjCnMnkgvKT2tpKxYQ59PgDgU8Ssc7RDSmSkLxnrv+OrN80j6xrw0OjEi
B4Ycr0PqfzZcvy8efTtFQ/Jnc4Bp1zUtFXt7+QeevePtQ2EcyELXE0i63T1CujRM
WwIDAQAB
-----END PUBLIC KEY-----
`

const rsaPrivateKey = `REDACTED_SECRET
`

// openssl ecparam -name prime256v1 -genkey -noout -out ecdsa256.pem
const ecdsaPrivateKey = `REDACTED_SECRET`

// openssl ec -in ecdsa256.pem -pubout -out ecdsa256pub.pem
const ecdsaPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH6cuzP8XuD5wal6wf9M6xDljTOPL
X2i8uIp/C/ASqiIGUeeKQtX0REDACTED_SECRET
-----END PUBLIC KEY-----`

func getPrivateKey(data string) interface{} {
	key, _ := certutil.ParsePrivateKeyPEM([]byte(data))
	return key
}

func getPublicKey(data string) interface{} {
	keys, _ := certutil.ParsePublicKeysPEM([]byte(data))
	return keys[0]
}
func TestTokenGenerateAndValidate(t *testing.T) {
	expectedUserName := "system:serviceaccount:test:my-service-account"
	expectedUserUID := "12345"

	// Related API objects
	serviceAccount := &v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-service-account",
			UID:       "12345",
			Namespace: "test",
		},
	}
	rsaSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-rsa-secret",
			Namespace: "test",
		},
	}
	ecdsaSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-ecdsa-secret",
			Namespace: "test",
		},
	}

	// Generate the RSA token
	rsaGenerator, err := serviceaccount.JWTTokenGenerator(serviceaccount.LegacyIssuer, getPrivateKey(rsaPrivateKey))
	if err != nil {
		t.Fatalf("error making generator: %v", err)
	}
	rsaToken, err := rsaGenerator.GenerateToken(serviceaccount.LegacyClaims(*serviceAccount, *rsaSecret))
	if err != nil {
		t.Fatalf("error generating token: %v", err)
	}
	if len(rsaToken) == 0 {
		t.Fatalf("no token generated")
	}
	rsaSecret.Data = map[string][]byte{
		"token": []byte(rsaToken),
	}

	// Generate the ECDSA token
	ecdsaGenerator, err := serviceaccount.JWTTokenGenerator(serviceaccount.LegacyIssuer, getPrivateKey(ecdsaPrivateKey))
	if err != nil {
		t.Fatalf("error making generator: %v", err)
	}
	ecdsaToken, err := ecdsaGenerator.GenerateToken(serviceaccount.LegacyClaims(*serviceAccount, *ecdsaSecret))
	if err != nil {
		t.Fatalf("error generating token: %v", err)
	}
	if len(ecdsaToken) == 0 {
		t.Fatalf("no token generated")
	}
	ecdsaSecret.Data = map[string][]byte{
		"token": []byte(ecdsaToken),
	}

	// Generate signer with same keys as RSA signer but different issuer
	badIssuerGenerator, err := serviceaccount.JWTTokenGenerator("foo", getPrivateKey(rsaPrivateKey))
	if err != nil {
		t.Fatalf("error making generator: %v", err)
	}
	badIssuerToken, err := badIssuerGenerator.GenerateToken(serviceaccount.LegacyClaims(*serviceAccount, *rsaSecret))
	if err != nil {
		t.Fatalf("error generating token: %v", err)
	}

	testCases := map[string]struct {
		Client clientset.Interface
		Keys   []interface{}
		Token  string

		ExpectedErr      bool
		ExpectedOK       bool
		ExpectedUserName string
		ExpectedUserUID  string
		ExpectedGroups   []string
	}{
		"no keys": {
			Token:       rsaToken,
			Client:      nil,
			Keys:        []interface{}{},
			ExpectedErr: false,
			ExpectedOK:  false,
		},
		"invalid keys (rsa)": {
			Token:       rsaToken,
			Client:      nil,
			Keys:        []interface{}{getPublicKey(otherPublicKey), getPublicKey(ecdsaPublicKey)},
			ExpectedErr: true,
			ExpectedOK:  false,
		},
		"invalid keys (ecdsa)": {
			Token:       ecdsaToken,
			Client:      nil,
			Keys:        []interface{}{getPublicKey(otherPublicKey), getPublicKey(rsaPublicKey)},
			ExpectedErr: true,
			ExpectedOK:  false,
		},
		"valid key (rsa)": {
			Token:            rsaToken,
			Client:           nil,
			Keys:             []interface{}{getPublicKey(rsaPublicKey)},
			ExpectedErr:      false,
			ExpectedOK:       true,
			ExpectedUserName: expectedUserName,
			ExpectedUserUID:  expectedUserUID,
			ExpectedGroups:   []string{"system:serviceaccounts", "system:serviceaccounts:test"},
		},
		"valid key, invalid issuer (rsa)": {
			Token:       badIssuerToken,
			Client:      nil,
			Keys:        []interface{}{getPublicKey(rsaPublicKey)},
			ExpectedErr: false,
			ExpectedOK:  false,
		},
		"valid key (ecdsa)": {
			Token:            ecdsaToken,
			Client:           nil,
			Keys:             []interface{}{getPublicKey(ecdsaPublicKey)},
			ExpectedErr:      false,
			ExpectedOK:       true,
			ExpectedUserName: expectedUserName,
			ExpectedUserUID:  expectedUserUID,
			ExpectedGroups:   []string{"system:serviceaccounts", "system:serviceaccounts:test"},
		},
		"rotated keys (rsa)": {
			Token:            rsaToken,
			Client:           nil,
			Keys:             []interface{}{getPublicKey(otherPublicKey), getPublicKey(ecdsaPublicKey), getPublicKey(rsaPublicKey)},
			ExpectedErr:      false,
			ExpectedOK:       true,
			ExpectedUserName: expectedUserName,
			ExpectedUserUID:  expectedUserUID,
			ExpectedGroups:   []string{"system:serviceaccounts", "system:serviceaccounts:test"},
		},
		"rotated keys (ecdsa)": {
			Token:            ecdsaToken,
			Client:           nil,
			Keys:             []interface{}{getPublicKey(otherPublicKey), getPublicKey(rsaPublicKey), getPublicKey(ecdsaPublicKey)},
			ExpectedErr:      false,
			ExpectedOK:       true,
			ExpectedUserName: expectedUserName,
			ExpectedUserUID:  expectedUserUID,
			ExpectedGroups:   []string{"system:serviceaccounts", "system:serviceaccounts:test"},
		},
		"valid lookup": {
			Token:            rsaToken,
			Client:           fake.NewSimpleClientset(serviceAccount, rsaSecret, ecdsaSecret),
			Keys:             []interface{}{getPublicKey(rsaPublicKey)},
			ExpectedErr:      false,
			ExpectedOK:       true,
			ExpectedUserName: expectedUserName,
			ExpectedUserUID:  expectedUserUID,
			ExpectedGroups:   []string{"system:serviceaccounts", "system:serviceaccounts:test"},
		},
		"invalid secret lookup": {
			Token:       rsaToken,
			Client:      fake.NewSimpleClientset(serviceAccount),
			Keys:        []interface{}{getPublicKey(rsaPublicKey)},
			ExpectedErr: true,
			ExpectedOK:  false,
		},
		"invalid serviceaccount lookup": {
			Token:       rsaToken,
			Client:      fake.NewSimpleClientset(rsaSecret, ecdsaSecret),
			Keys:        []interface{}{getPublicKey(rsaPublicKey)},
			ExpectedErr: true,
			ExpectedOK:  false,
		},
	}

	for k, tc := range testCases {
		auds := authenticator.Audiences{"api"}
		getter := serviceaccountcontroller.NewGetterFromClient(tc.Client)
		authn := serviceaccount.JWTTokenAuthenticator(serviceaccount.LegacyIssuer, tc.Keys, auds, serviceaccount.NewLegacyValidator(tc.Client != nil, getter))

		// An invalid, non-JWT token should always fail
		ctx := authenticator.WithAudiences(context.Background(), auds)
		if _, ok, err := authn.AuthenticateToken(ctx, "invalid token"); err != nil || ok {
			t.Errorf("%s: Expected err=nil, ok=false for non-JWT token", k)
			continue
		}

		resp, ok, err := authn.AuthenticateToken(ctx, tc.Token)
		if (err != nil) != tc.ExpectedErr {
			t.Errorf("%s: Expected error=%v, got %v", k, tc.ExpectedErr, err)
			continue
		}

		if ok != tc.ExpectedOK {
			t.Errorf("%s: Expected ok=%v, got %v", k, tc.ExpectedOK, ok)
			continue
		}

		if err != nil || !ok {
			continue
		}

		if resp.User.GetName() != tc.ExpectedUserName {
			t.Errorf("%s: Expected username=%v, got %v", k, tc.ExpectedUserName, resp.User.GetName())
			continue
		}
		if resp.User.GetUID() != tc.ExpectedUserUID {
			t.Errorf("%s: Expected userUID=%v, got %v", k, tc.ExpectedUserUID, resp.User.GetUID())
			continue
		}
		if !reflect.DeepEqual(resp.User.GetGroups(), tc.ExpectedGroups) {
			t.Errorf("%s: Expected groups=%v, got %v", k, tc.ExpectedGroups, resp.User.GetGroups())
			continue
		}
	}
}

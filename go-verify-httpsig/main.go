package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/http"
	"strings"

	"github.com/remitly-oss/httpsig-go"
)

type KeyFetcher struct{}

func NewKeyFetcher() KeyFetcher {
	return KeyFetcher{}
}

func (k KeyFetcher) Fetch(ctx context.Context, rh http.Header, md httpsig.MetadataProvider) (httpsig.KeySpecer, error) {
	panic("not implemented")
}

func (k KeyFetcher) FetchByKeyID(ctx context.Context, rh http.Header, keyID string) (httpsig.KeySpecer, error) {
	if keyID == "ao" {
		return httpsig.KeySpec{
			KeyID:  keyID,
			Algo:   httpsig.Algo_HMAC_SHA256,
			Secret: []byte("ao"),
		}, nil
	} else {
		modulusBytes, err := base64.StdEncoding.DecodeString(keyID)
		if err != nil {
			return httpsig.KeySpec{}, err
		}

		modulus := new(big.Int).SetBytes(modulusBytes)
		// Common public exponent
		exponent := 65537

		pubKey := &rsa.PublicKey{
			N: modulus,
			E: exponent,
		}

		return httpsig.KeySpec{
			KeyID:  keyID,
			Algo:   httpsig.Algo_RSA_PSS_SHA512,
			PubKey: pubKey,
		}, nil
	}
}

func main() {
	resp, err := http.Get("http://localhost:8734/~meta@1.0/info/address")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	Signatures := resp.Header.Get("signature")
	for _, signature := range strings.Split(Signatures, ",") {
		keyID := strings.Trim(strings.Split(signature, "=:")[0], " ")
		profile := httpsig.VerifyProfile{
			SignatureLabel: keyID,
		}

		verifier, err := httpsig.NewVerifier(NewKeyFetcher(), profile)
		if err != nil {
			panic(err)
		}
		_, err = verifier.VerifyResponse(resp)
		if err != nil {
			panic(err)
		}
	}

}

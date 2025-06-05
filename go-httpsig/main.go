package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPSigSigner implements RFC-9421 HTTP Message Signatures
type HTTPSigSigner struct {
	privateKey *rsa.PrivateKey
	keyID      string
}

// NewHTTPSigSigner creates a new HTTP signature signer
func NewHTTPSigSigner(privateKey *rsa.PrivateKey, keyID string) *HTTPSigSigner {
	return &HTTPSigSigner{
		privateKey: privateKey,
		keyID:      keyID,
	}
}

// SignRequest signs an HTTP request according to RFC-9421
func (s *HTTPSigSigner) SignRequest(req *http.Request) error {
	// Parse URL components
	parsedURL, err := url.Parse(req.URL.String())
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}

	// Define components to include in signature
	components := []string{"@method", "@authority", "@path", "content-type"}
	
	// Add content-digest if body is present
	if req.Body != nil && req.ContentLength > 0 {
		// Read body to calculate digest
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("failed to read body: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(body)) // Reset body
		
		// Calculate SHA-256 digest
		hash := sha256.Sum256(body)
		digest := base64.StdEncoding.EncodeToString(hash[:])
		req.Header.Set("Content-Digest", fmt.Sprintf("sha-256=:%s:", digest))
		components = append(components, "content-digest")
	}

	// Build signature base
	signatureBase, err := s.buildSignatureBase(req, parsedURL, components)
	if err != nil {
		return fmt.Errorf("failed to build signature base: %w", err)
	}

	fmt.Printf("Signature Base:\n%s\n\n", signatureBase)

	// Sign the signature base
	signature, err := s.signData([]byte(signatureBase))
	if err != nil {
		return fmt.Errorf("failed to sign data: %w", err)
	}

	// Create signature and signature-input headers
	created := time.Now().Unix()
	
	// Build signature-input header
	sigInput, err := s.buildSignatureInput(components, created)
	if err != nil {
		return fmt.Errorf("failed to build signature input: %w", err)
	}

	// Add headers to request
	req.Header.Set("Signature", fmt.Sprintf("sig1=:%s:", base64.StdEncoding.EncodeToString(signature)))
	req.Header.Set("Signature-Input", fmt.Sprintf("sig1=%s", sigInput))

	return nil
}

// buildSignatureBase creates the signature base string according to RFC-9421
func (s *HTTPSigSigner) buildSignatureBase(req *http.Request, parsedURL *url.URL, components []string) (string, error) {
	var lines []string

	for _, component := range components {
		switch component {
		case "@method":
			lines = append(lines, fmt.Sprintf(`"%s": %s`, component, req.Method))
		case "@authority":
			authority := parsedURL.Host
			if parsedURL.Port() == "" {
				if parsedURL.Scheme == "https" {
					authority += ":443"
				} else if parsedURL.Scheme == "http" {
					authority += ":80"
				}
			}
			lines = append(lines, fmt.Sprintf(`"%s": %s`, component, authority))
		case "@path":
			path := parsedURL.Path
			if parsedURL.RawQuery != "" {
				path += "?" + parsedURL.RawQuery
			}
			lines = append(lines, fmt.Sprintf(`"%s": %s`, component, path))
		default:
			// Regular header
			value := req.Header.Get(component)
			if value == "" {
				return "", fmt.Errorf("header %s not found", component)
			}
			lines = append(lines, fmt.Sprintf(`"%s": %s`, component, value))
		}
	}

	// Add @signature-params line
	created := time.Now().Unix()
	paramsLine, err := s.buildSignatureParamsLine(components, created)
	if err != nil {
		return "", fmt.Errorf("failed to build signature params line: %w", err)
	}
	
	lines = append(lines, fmt.Sprintf(`"@signature-params": %s`, paramsLine))

	return strings.Join(lines, "\n"), nil
}

// buildSignatureParamsLine builds the @signature-params line
func (s *HTTPSigSigner) buildSignatureParamsLine(components []string, created int64) (string, error) {
	// Build the signature input manually to match RFC-9421 format
	// Format: ("component1" "component2" ...);created=timestamp;keyid="key-id"
	
	var componentList []string
	for _, comp := range components {
		componentList = append(componentList, fmt.Sprintf(`"%s"`, comp))
	}
	
	componentsStr := fmt.Sprintf("(%s)", strings.Join(componentList, " "))
	
	// Add parameters
	params := fmt.Sprintf(";created=%d;keyid=\"%s\"", created, s.keyID)
	
	return componentsStr + params, nil
}

// buildSignatureInput builds the signature-input header value
func (s *HTTPSigSigner) buildSignatureInput(components []string, created int64) (string, error) {
	return s.buildSignatureParamsLine(components, created)
}

// signData signs data using RSA-PSS-SHA512
func (s *HTTPSigSigner) signData(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	return rsa.SignPSS(rand.Reader, s.privateKey, crypto.SHA256, hash[:], nil)
}

// generateRSAKey generates a new RSA key pair
func generateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// exportPublicKeyJWK exports the public key in JWK format
func exportPublicKeyJWK(privateKey *rsa.PrivateKey) (string, error) {
	publicKey := &privateKey.PublicKey
	
	jwk := map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"alg": "PS256",
		"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
	}
	
	jwkBytes, err := json.MarshalIndent(jwk, "", "  ")
	if err != nil {
		return "", err
	}
	
	return string(jwkBytes), nil
}

func main() {
	fmt.Println("=== HyperBEAM HTTP Signature Example ===\n")

	// Generate RSA key pair
	fmt.Println("1. Generating RSA key pair...")
	privateKey, err := generateRSAKey()
	if err != nil {
		panic(fmt.Sprintf("Failed to generate RSA key: %v", err))
	}

	keyID := "test-key-rsa"
	fmt.Printf("Key ID: %s\n\n", keyID)

	// Export public key as JWK
	jwk, err := exportPublicKeyJWK(privateKey)
	if err != nil {
		panic(fmt.Sprintf("Failed to export JWK: %v", err))
	}
	fmt.Printf("Public Key JWK:\n%s\n\n", jwk)

	// Create HTTP signature signer
	signer := NewHTTPSigSigner(privateKey, keyID)

	// Create the HTTP request with specified parameters
	fmt.Println("2. Creating HTTP request...")
	
	// Request body (AO evaluation)
	requestBody := `1 + 1`
	
	// Create request
	req, err := http.NewRequest(
		"POST",
		"http://localhost:8734/lxGzM0c4k3d6ZJf6PnQuMRGcpwBXNen9uyn3103W41s~process@1.0/push",
		strings.NewReader(requestBody),
	)
	if err != nil {
		panic(fmt.Sprintf("Failed to create request: %v", err))
	}

	// Set headers
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Data-Protocol", "ao")
	req.Header.Set("Action", "Eval")
	req.ContentLength = int64(len(requestBody))

	fmt.Printf("Request URL: %s\n", req.URL.String())
	fmt.Printf("Method: %s\n", req.Method)
	fmt.Printf("Headers: %v\n", req.Header)
	fmt.Printf("Body: %s\n\n", requestBody)

	// Sign the request
	fmt.Println("3. Signing request...")
	err = signer.SignRequest(req)
	if err != nil {
		panic(fmt.Sprintf("Failed to sign request: %v", err))
	}

	fmt.Println("4. Signed request headers:")
	for name, values := range req.Header {
		for _, value := range values {
			fmt.Printf("  %s: %s\n", name, value)
		}
	}

	// Send the request
	fmt.Println("\n5. Sending request to HyperBEAM...")
	client := &http.Client{Timeout: 30 * time.Second}
	
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Request failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Failed to read response: %v\n", err)
		return
	}

	fmt.Printf("Response Status: %s\n", resp.Status)
	fmt.Printf("Response Headers:\n")
	for name, values := range resp.Header {
		for _, value := range values {
			fmt.Printf("  %s: %s\n", name, value)
		}
	}
	fmt.Printf("Response Body:\n%s\n", string(respBody))
}
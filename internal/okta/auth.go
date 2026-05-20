package okta

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// NewClientWithOAuth creates a client using OAuth 2.0 private key JWT.
// This is the recommended authentication method.
// keyID is the key identifier from Okta (found in the public keys section of your app).
// scopes is the set of OAuth scopes to request; scopes the service app has not
// been granted are dropped from the issued token.
func NewClientWithOAuth(orgDomain, clientID, keyID string, privateKey []byte, scopes []string) (*Client, error) {
	baseURL := buildBaseURL(orgDomain)

	// Parse the private key
	key, err := parsePrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Generate JWT for client credentials grant
	token, err := generateClientAssertionJWT(clientID, baseURL, keyID, key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWT: %w", err)
	}

	// Exchange JWT for access token
	accessToken, err := exchangeJWTForToken(baseURL, clientID, token, scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange JWT for token: %w", err)
	}

	return &Client{
		httpClient:  &http.Client{Timeout: HTTPTimeout},
		baseURL:     baseURL,
		accessToken: accessToken,
		authType:    "Bearer",
	}, nil
}

// NewClientWithHTTP creates a client with a custom HTTP client and base URL (for testing).

// parsePrivateKey parses a PEM-encoded RSA private key.
func parsePrivateKey(keyData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKCS#8 first (more common for OAuth)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA private key")
		}
		return rsaKey, nil
	}

	// Fall back to PKCS#1
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// generateClientAssertionJWT creates a JWT for OAuth 2.0 client credentials flow.
// keyID is the key identifier from Okta that must match the public key registered in your app.
func generateClientAssertionJWT(clientID, baseURL, keyID string, key *rsa.PrivateKey) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"aud": fmt.Sprintf("%s/oauth2/v1/token", baseURL),
		"iss": clientID,
		"sub": clientID,
		"iat": now.Unix(),
		"exp": now.Add(jwtExpiry).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// Set the key ID in the JWT header - required by Okta to identify which public key to use
	token.Header["kid"] = keyID
	return token.SignedString(key)
}

// exchangeJWTForToken exchanges a client assertion JWT for an access token,
// requesting the given scopes.
func exchangeJWTForToken(baseURL, clientID, assertion string, scopes []string) (string, error) {
	tokenURL := fmt.Sprintf("%s/oauth2/v1/token", baseURL)

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", strings.Join(scopes, " "))
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("client_assertion", assertion)

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Read error response for debugging
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil && errResp.Error != "" {
			return "", fmt.Errorf("token exchange failed: %s - %s", errResp.Error, errResp.ErrorDescription)
		}
		return "", fmt.Errorf("token exchange failed with status %d", resp.StatusCode)
	}

	var result struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if result.AccessToken == "" {
		return "", fmt.Errorf("token exchange returned empty access token")
	}

	return result.AccessToken, nil
}

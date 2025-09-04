// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package oauth implements OAuth 2.0 and OIDC functionality for the tsidp service.
package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
)

// ValidateCodeVerifier validates a PKCE code verifier against a challenge
// Migrated from legacy/tsidp.go:476-503
func ValidateCodeVerifier(verifier, challenge, method string) error {
	switch method {
	case "plain":
		// plain: code_challenge = code_verifier
		if verifier != challenge {
			return fmt.Errorf("code_verifier does not match code_challenge")
		}
	case "S256":
		// S256: code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
		h := sha256.Sum256([]byte(verifier))
		encoded := base64.RawURLEncoding.EncodeToString(h[:])
		if subtle.ConstantTimeCompare([]byte(encoded), []byte(challenge)) != 1 {
			return fmt.Errorf("code_verifier does not match code_challenge")
		}
	case "":
		// No PKCE
		if verifier != "" || challenge != "" {
			return fmt.Errorf("unexpected PKCE parameters")
		}
	default:
		return fmt.Errorf("unsupported code_challenge_method: %s", method)
	}
	return nil
}

// GenerateCodeChallenge generates a PKCE code challenge from a verifier
// Migrated from legacy/tsidp.go:505-518
func GenerateCodeChallenge(verifier, method string) (string, error) {
	switch method {
	case "plain":
		return verifier, nil
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(h[:]), nil
	default:
		return "", fmt.Errorf("unsupported code_challenge_method: %s", method)
	}
}

// ValidateScopes checks if the requested scopes are valid and supported.
// It returns the validated scopes or an error if any scope is unsupported.
// Migrated from legacy/tsidp.go:399-424
func ValidateScopes(requestedScopes []string, enableSTS bool) ([]string, error) {
	if len(requestedScopes) == 0 {
		// Default to openid scope if none specified
		return []string{"openid"}, nil
	}

	validatedScopes := make([]string, 0, len(requestedScopes))
	seen := make(map[string]bool)

	for _, scope := range requestedScopes {
		// Skip duplicates
		if seen[scope] {
			continue
		}
		seen[scope] = true

		// Check if scope is supported
		if !isSupportedScope(scope, enableSTS) {
			return nil, fmt.Errorf("unsupported scope: %s", scope)
		}

		validatedScopes = append(validatedScopes, scope)
	}

	return validatedScopes, nil
}

// isSupportedScope checks if a scope is supported
func isSupportedScope(scope string, enableSTS bool) bool {
	switch scope {
	case "openid", "profile", "email":
		return true
	case "urn:x-oath:params:oauth:token-type:access_token",
	     "urn:x-oath:params:oauth:token-type:refresh_token":
		// Token exchange scopes (RFC 8693)
		return enableSTS
	default:
		// Support RFC 8707 resource indicators (prefixed with "resource:")
		return strings.HasPrefix(scope, "resource:")
	}
}

// OAuth 2.0 error codes
// Migrated from legacy/tsidp.go:1676-1680
const (
	ErrorCodeInvalidRequest          = "invalid_request"
	ErrorCodeInvalidClient           = "invalid_client"
	ErrorCodeInvalidGrant            = "invalid_grant"
	ErrorCodeUnauthorizedClient      = "unauthorized_client"
	ErrorCodeUnsupportedGrantType    = "unsupported_grant_type"
	ErrorCodeUnsupportedResponseType = "unsupported_response_type"
	ErrorCodeInvalidScope            = "invalid_scope"
	ErrorCodeServerError             = "server_error"
	ErrorCodeAccessDenied            = "access_denied"
)

// Token types for OAuth responses
const (
	TokenTypeBearer = "Bearer"
	TokenTypeDPoP   = "DPoP" // For future implementation
)

// Grant types
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange"
)

// Token exchange types (RFC 8693)
const (
	TokenTypeAccessToken  = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeIDToken      = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeJWT          = "urn:ietf:params:oauth:token-type:jwt"
)

// Response types
const (
	ResponseTypeCode  = "code"
	ResponseTypeToken = "token"     // Implicit flow (not recommended)
	ResponseTypeIDToken = "id_token" // Hybrid flow
)

// OIDCTokenResponse represents the response from the token endpoint
// Migrated from legacy/tsidp.go:1604-1611
type OIDCTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

// OAuthErrorResponse represents an OAuth 2.0 error response
// Migrated from legacy/tsidp.go:1613-1617
type OAuthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}
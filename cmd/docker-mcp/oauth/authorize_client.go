package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// AuthorizeClientOptions contains options for OAuth authorization flow
type AuthorizeClientOptions struct {
	ClientID     string
	Provider     string
	Scopes       []string
	AuthEndpoint string
	TokenEndpoint string
}

// AuthorizeClient initiates OAuth authorization flow for a registered client
func AuthorizeClient(ctx context.Context, clientID string) error {
	// Get client details from Pinata
	client, err := GetClient(ctx, clientID)
	if err != nil {
		return fmt.Errorf("failed to get client details: %w", err)
	}

	// Determine provider and endpoints based on client registration
	provider, authEndpoint, tokenEndpoint := detectProviderFromClient(client)
	
	if authEndpoint == "" || tokenEndpoint == "" {
		return fmt.Errorf("unable to determine OAuth endpoints for client %s", clientID)
	}

	fmt.Printf("Starting OAuth authorization flow\n")
	fmt.Printf("Client: %s (%s)\n", client.ClientName, clientID)
	fmt.Printf("Provider: %s\n", provider)
	
	// Generate PKCE challenge
	codeVerifier := generateCodeVerifier()
	codeChallenge := generateCodeChallenge(codeVerifier)
	
	// Generate state for CSRF protection
	state := generateState()
	
	// Start local callback server
	callbackChan := make(chan string, 1)
	errorChan := make(chan error, 1)
	server := startCallbackServer(callbackChan, errorChan, state)
	defer server.Close()
	
	// Build authorization URL
	authURL := buildAuthURL(authEndpoint, client, codeChallenge, state)
	
	fmt.Printf("\nOpening browser for authentication...\n")
	fmt.Printf("If browser doesn't open, visit:\n%s\n\n", authURL)
	
	// Open browser
	openBrowser(authURL)
	
	// Wait for callback
	fmt.Println("Waiting for authorization callback...")
	
	select {
	case code := <-callbackChan:
		fmt.Println("✓ Authorization code received")
		
		// Exchange code for token
		token, err := exchangeCodeForToken(ctx, tokenEndpoint, client, code, codeVerifier)
		if err != nil {
			return fmt.Errorf("failed to exchange code for token: %w", err)
		}
		
		// Store token in Pinata
		if err := storeOAuthToken(ctx, provider, clientID, token); err != nil {
			return fmt.Errorf("failed to store token: %w", err)
		}
		
		fmt.Printf("\n✓ Successfully authorized %s!\n", provider)
		fmt.Printf("OAuth token has been stored securely.\n")
		fmt.Printf("You can now use %s with remote MCP servers.\n", provider)
		
		return nil
		
	case err := <-errorChan:
		return fmt.Errorf("authorization failed: %w", err)
		
	case <-time.After(5 * time.Minute):
		return fmt.Errorf("authorization timed out after 5 minutes")
		
	case <-ctx.Done():
		return ctx.Err()
	}
}

func detectProviderFromClient(client *ClientRegistrationResponse) (provider, authEndpoint, tokenEndpoint string) {
	// Try to detect provider from redirect URIs or client name
	clientNameLower := strings.ToLower(client.ClientName)
	
	// Check redirect URIs for hints
	for _, uri := range client.RedirectURIs {
		if strings.Contains(uri, "notion") {
			return "notion", "https://api.notion.com/v1/oauth/authorize", "https://api.notion.com/v1/oauth/token"
		}
		if strings.Contains(uri, "github") {
			return "github", "https://github.com/login/oauth/authorize", "https://github.com/login/oauth/access_token"
		}
		if strings.Contains(uri, "linear") {
			return "linear", "https://linear.app/oauth/authorize", "https://api.linear.app/oauth/token"
		}
		if strings.Contains(uri, "slack") {
			return "slack", "https://slack.com/oauth/v2/authorize", "https://slack.com/api/oauth.v2.access"
		}
	}
	
	// Check client name
	if strings.Contains(clientNameLower, "notion") {
		return "notion", "https://api.notion.com/v1/oauth/authorize", "https://api.notion.com/v1/oauth/token"
	}
	if strings.Contains(clientNameLower, "github") {
		return "github", "https://github.com/login/oauth/authorize", "https://github.com/login/oauth/access_token"
	}
	if strings.Contains(clientNameLower, "linear") {
		return "linear", "https://linear.app/oauth/authorize", "https://api.linear.app/oauth/token"
	}
	if strings.Contains(clientNameLower, "slack") {
		return "slack", "https://slack.com/oauth/v2/authorize", "https://slack.com/api/oauth.v2.access"
	}
	
	// Default to notion if we registered with notion endpoint
	if strings.Contains(client.ClientID, "mcp_") {
		return "notion", "https://api.notion.com/v1/oauth/authorize", "https://api.notion.com/v1/oauth/token"
	}
	
	return "unknown", "", ""
}

func generateCodeVerifier() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateCodeChallenge(verifier string) string {
	// For simplicity, using plain method (S256 would be better)
	return verifier
}

func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func startCallbackServer(callbackChan chan string, errorChan chan error, expectedState string) *http.Server {
	mux := http.NewServeMux()
	
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		errorParam := r.URL.Query().Get("error")
		errorDesc := r.URL.Query().Get("error_description")
		
		if errorParam != "" {
			errorChan <- fmt.Errorf("%s: %s", errorParam, errorDesc)
			fmt.Fprintf(w, `<html><body>
				<h1>Authorization Failed</h1>
				<p>Error: %s</p>
				<p>%s</p>
				<p>You can close this window.</p>
			</body></html>`, errorParam, errorDesc)
			return
		}
		
		if state != expectedState {
			errorChan <- fmt.Errorf("state mismatch - possible CSRF attack")
			fmt.Fprintf(w, `<html><body>
				<h1>Authorization Failed</h1>
				<p>State verification failed.</p>
				<p>You can close this window.</p>
			</body></html>`)
			return
		}
		
		if code == "" {
			errorChan <- fmt.Errorf("no authorization code received")
			fmt.Fprintf(w, `<html><body>
				<h1>Authorization Failed</h1>
				<p>No authorization code received.</p>
				<p>You can close this window.</p>
			</body></html>`)
			return
		}
		
		callbackChan <- code
		fmt.Fprintf(w, `<html><body>
			<h1>Authorization Successful!</h1>
			<p>You can close this window and return to the terminal.</p>
			<script>window.close();</script>
		</body></html>`)
	})
	
	server := &http.Server{
		Addr:    ":13420",
		Handler: mux,
	}
	
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errorChan <- err
		}
	}()
	
	// Give server time to start
	time.Sleep(100 * time.Millisecond)
	
	return server
}

func buildAuthURL(authEndpoint string, client *ClientRegistrationResponse, codeChallenge, state string) string {
	params := url.Values{}
	params.Set("client_id", client.ClientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", "https://mcp.docker.com/callback")
	params.Set("state", state)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "plain")
	
	// Add scopes if available
	if client.Scope != "" {
		params.Set("scope", client.Scope)
	}
	
	return authEndpoint + "?" + params.Encode()
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	}
	
	if cmd != nil {
		cmd.Start()
	}
}

func exchangeCodeForToken(ctx context.Context, tokenEndpoint string, client *ClientRegistrationResponse, code, codeVerifier string) (*OAuthToken, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", client.ClientID)
	data.Set("client_secret", client.ClientSecret)
	data.Set("redirect_uri", "https://mcp.docker.com/callback")
	data.Set("code_verifier", codeVerifier)
	
	req, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status: %s", resp.Status)
	}
	
	var token OAuthToken
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, err
	}
	
	return &token, nil
}

type OAuthToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func storeOAuthToken(ctx context.Context, provider, clientID string, token *OAuthToken) error {
	// Store token in Pinata's credential store
	socketPath := getBackendSocketPath()
	if socketPath == "" {
		return fmt.Errorf("unsupported platform")
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 10 * time.Second,
	}
	
	// Store the token
	tokenData := map[string]interface{}{
		"provider":      provider,
		"client_id":     clientID,
		"access_token":  token.AccessToken,
		"token_type":    token.TokenType,
		"refresh_token": token.RefreshToken,
		"expires_in":    token.ExpiresIn,
		"scope":        token.Scope,
	}
	
	jsonData, err := json.Marshal(tokenData)
	if err != nil {
		return err
	}
	
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("http://localhost/oauth/tokens/%s", provider), strings.NewReader(string(jsonData)))
	if err != nil {
		return err
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to store token: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to store token: %s", resp.Status)
	}
	
	return nil
}
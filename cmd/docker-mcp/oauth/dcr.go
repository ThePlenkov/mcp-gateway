package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// DCROptions contains options for dynamic client registration with MCP servers
type DCROptions struct {
	Endpoint        string   // Registration endpoint URL
	Name            string   // Client name
	Description     string   // Optional description
	Scopes          []string // OAuth scopes to request
	GrantTypes      []string // Grant types (default: authorization_code)
	ResponseTypes   []string // Response types (default: code)
}

// RegisterWithMCPServer performs dynamic client registration directly with an MCP server
func RegisterWithMCPServer(ctx context.Context, opts *DCROptions) error {
	if opts.Endpoint == "" {
		return fmt.Errorf("registration endpoint is required")
	}
	
	if opts.Name == "" {
		return fmt.Errorf("client name is required")
	}
	
	// Set defaults
	if len(opts.GrantTypes) == 0 {
		opts.GrantTypes = []string{"authorization_code"}
	}
	if len(opts.ResponseTypes) == 0 {
		opts.ResponseTypes = []string{"code"}
	}
	
	// Build registration request
	req := ClientRegistrationRequest{
		RedirectURIs:      []string{"https://mcp.docker.com/callback"},
		GrantTypes:        opts.GrantTypes,
		ResponseTypes:     opts.ResponseTypes,
		ClientName:        opts.Name,
		ClientDescription: opts.Description,
		Scope:            strings.Join(opts.Scopes, " "),
		ApplicationType:   "web",
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	
	// Marshal request
	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}
	
	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", opts.Endpoint, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	
	// Send request
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("sending registration request: %w", err)
	}
	defer resp.Body.Close()
	
	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}
	
	// Check status
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		// Try to parse error response
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("registration failed: %s - %s", errResp.Error, errResp.ErrorDescription)
		}
		return fmt.Errorf("registration failed (status %d): %s", resp.StatusCode, body)
	}
	
	// Parse successful response
	var result ClientRegistrationResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}
	
	// Store the client in Pinata for persistence
	if err := storeClientInPinata(ctx, &result, opts.Endpoint); err != nil {
		// Log warning but don't fail - the registration was successful
		fmt.Printf("Warning: Could not store client in local registry: %v\n", err)
	}
	
	// Display results
	fmt.Println("✓ OAuth 2.0 client successfully registered with MCP server!")
	fmt.Println()
	fmt.Printf("Client ID:     %s\n", result.ClientID)
	fmt.Printf("Client Secret: %s\n", result.ClientSecret)
	fmt.Println()
	fmt.Println("IMPORTANT: Save these credentials securely. The client secret cannot be retrieved again.")
	fmt.Println()
	
	if result.ClientName != "" {
		fmt.Printf("Name:          %s\n", result.ClientName)
	}
	if len(result.RedirectURIs) > 0 {
		fmt.Printf("Redirect URIs: %s\n", strings.Join(result.RedirectURIs, ", "))
	}
	if len(result.GrantTypes) > 0 {
		fmt.Printf("Grant Types:   %s\n", strings.Join(result.GrantTypes, ", "))
	}
	if result.Scope != "" {
		fmt.Printf("Scopes:        %s\n", result.Scope)
	}
	
	fmt.Println()
	fmt.Printf("To authorize this client, run:\n")
	fmt.Printf("  docker mcp oauth authorize %s\n", result.ClientID)
	
	return nil
}

// storeClientInPinata stores the registered client in Pinata for persistence
func storeClientInPinata(ctx context.Context, client *ClientRegistrationResponse, endpoint string) error {
	// Store in Pinata so we can retrieve it later
	// This uses the existing Pinata OAuth client storage
	
	// Augment client data with endpoint info
	clientData := map[string]interface{}{
		"client_id":                client.ClientID,
		"client_secret":            client.ClientSecret,
		"client_name":              client.ClientName,
		"redirect_uris":            client.RedirectURIs,
		"grant_types":              client.GrantTypes,
		"response_types":           client.ResponseTypes,
		"scope":                    client.Scope,
		"token_endpoint_auth_method": client.TokenEndpointAuthMethod,
		"registration_endpoint":    endpoint,
		"client_id_issued_at":      client.ClientIDIssuedAt,
		"client_secret_expires_at": client.ClientSecretExpiresAt,
	}
	
	resp, err := makeRequest(ctx, "POST", "/oauth/clients", clientData)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to store in Pinata: %s", body)
	}
	
	return nil
}
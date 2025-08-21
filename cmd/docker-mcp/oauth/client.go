package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"
)

// Client registration and management options

type ClientRegistrationOptions struct {
	Name            string
	Description     string
	RedirectURIs    []string
	ClientURI       string
	LogoURI         string
	Scopes          []string
	GrantTypes      []string
	ResponseTypes   []string
	ApplicationType string
	RequirePKCE     bool
	Contacts        []string
	PolicyURI       string
	TosURI          string
}

type ClientListOptions struct {
	JSON        bool
	ShowSecrets bool
	ActiveOnly  bool
	Limit       int
	Offset      int
}

type ClientShowOptions struct {
	JSON       bool
	ShowSecret bool
}

type ClientUpdateOptions struct {
	ClientID        string
	Name            string
	Description     string
	RedirectURIs    []string
	ClientURI       string
	LogoURI         string
	Scopes          []string
	Contacts        []string
	PolicyURI       string
	TosURI          string
	RequirePKCE     bool
	Active          bool
}

type ClientDeleteOptions struct {
	Force bool
}

type ClientRotateSecretOptions struct {
	Force      bool
	ShowSecret bool
}

// API types

type ClientRegistrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientDescription       string   `json:"client_description,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	TosURI                  string   `json:"tos_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	ApplicationType         string   `json:"application_type,omitempty"`
	RequirePKCE             bool     `json:"require_pkce,omitempty"`
}

type ClientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	TosURI                  string   `json:"tos_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	ApplicationType         string   `json:"application_type,omitempty"`
}

type OAuthClient struct {
	ClientID                string    `json:"client_id"`
	ClientSecret            string    `json:"client_secret,omitempty"`
	CreatedAt               string    `json:"created_at"`
	UpdatedAt               string    `json:"updated_at"`
	ClientName              string    `json:"client_name"`
	ClientDescription       string    `json:"client_description"`
	ClientURI               string    `json:"client_uri"`
	LogoURI                 string    `json:"logo_uri"`
	Owner                   string    `json:"owner"`
	Contacts                []string  `json:"contacts"`
	RedirectURIs            []string  `json:"redirect_uris"`
	ResponseTypes           []string  `json:"response_types"`
	GrantTypes              []string  `json:"grant_types"`
	ApplicationType         string    `json:"application_type"`
	Scopes                  []string  `json:"scopes"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method"`
	RequirePKCE             bool      `json:"require_pkce"`
	PolicyURI               string    `json:"policy_uri"`
	TosURI                  string    `json:"tos_uri"`
	Active                  bool      `json:"active"`
}

type ClientUpdateRequest struct {
	RedirectURIs      []string `json:"redirect_uris,omitempty"`
	ClientName        string   `json:"client_name,omitempty"`
	ClientDescription string   `json:"client_description,omitempty"`
	ClientURI         string   `json:"client_uri,omitempty"`
	LogoURI           string   `json:"logo_uri,omitempty"`
	Scopes            []string `json:"scopes,omitempty"`
	Contacts          []string `json:"contacts,omitempty"`
	TosURI            string   `json:"tos_uri,omitempty"`
	PolicyURI         string   `json:"policy_uri,omitempty"`
	RequirePKCE       bool     `json:"require_pkce,omitempty"`
	Active            bool     `json:"active"`
}

// Helper functions

func getBackendSocketPath() string {
	// Check for custom socket path from environment
	if socketPath := os.Getenv("DOCKER_BACKEND_SOCKET"); socketPath != "" {
		return socketPath
	}
	
	// Use platform-specific default paths
	switch runtime.GOOS {
	case "darwin":
		return "/Users/" + os.Getenv("USER") + "/Library/Containers/com.docker.docker/Data/backend.sock"
	case "linux":
		return os.Getenv("HOME") + "/.docker/desktop/backend.sock"
	case "windows":
		return `\\.\pipe\dockerBackendApiServer`
	default:
		return ""
	}
}

func getHTTPClient() *http.Client {
	socketPath := getBackendSocketPath()
	if socketPath == "" || os.Getenv("DOCKER_BACKEND_URL") != "" {
		// Use default HTTP client if no socket or URL is explicitly set
		return &http.Client{Timeout: 30 * time.Second}
	}

	// Create Unix socket transport for macOS/Linux or named pipe for Windows
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 30 * time.Second,
	}
}

func getBackendURL() string {
	// Check for custom URL from environment (for testing/development)
	if url := os.Getenv("DOCKER_BACKEND_URL"); url != "" {
		return url
	}
	// When using Unix socket, we need a dummy host for the HTTP request
	return "http://localhost"
}

func makeRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshaling request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, getBackendURL()+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := getHTTPClient()
	return client.Do(req)
}

// Command implementations

func RegisterClient(ctx context.Context, opts *ClientRegistrationOptions) error {
	// Always use the standard MCP OAuth redirect URI
	redirectURIs := []string{"https://mcp.docker.com/callback"}
	if len(opts.RedirectURIs) > 0 {
		// Ignore any custom redirect URIs provided
		fmt.Println("Note: Custom redirect URIs are not supported. Using https://mcp.docker.com/callback")
	}
	
	req := ClientRegistrationRequest{
		RedirectURIs:      redirectURIs,
		GrantTypes:        opts.GrantTypes,
		ResponseTypes:     opts.ResponseTypes,
		ClientName:        opts.Name,
		ClientDescription: opts.Description,
		ClientURI:         opts.ClientURI,
		LogoURI:           opts.LogoURI,
		Scope:             strings.Join(opts.Scopes, " "),
		Contacts:          opts.Contacts,
		TosURI:            opts.TosURI,
		PolicyURI:         opts.PolicyURI,
		ApplicationType:   opts.ApplicationType,
		RequirePKCE:       opts.RequirePKCE,
	}

	resp, err := makeRequest(ctx, "POST", "/oauth/clients", req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration failed (status %d): %s", resp.StatusCode, body)
	}

	var result ClientRegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	fmt.Println("OAuth 2.0 client successfully registered!")
	fmt.Println()
	fmt.Printf("Client ID:     %s\n", result.ClientID)
	fmt.Printf("Client Secret: %s\n", result.ClientSecret)
	fmt.Println()
	fmt.Println("IMPORTANT: Save the client secret securely. It cannot be retrieved again.")
	
	if result.ClientName != "" {
		fmt.Printf("Name:          %s\n", result.ClientName)
	}
	if len(result.RedirectURIs) > 0 {
		fmt.Printf("Redirect URIs: %s\n", strings.Join(result.RedirectURIs, ", "))
	}
	if result.Scope != "" {
		fmt.Printf("Scopes:        %s\n", result.Scope)
	}

	return nil
}

func ListClients(ctx context.Context, opts *ClientListOptions) error {
	query := fmt.Sprintf("?limit=%d&offset=%d", opts.Limit, opts.Offset)
	if opts.ActiveOnly {
		query += "&active=true"
	}

	resp, err := makeRequest(ctx, "GET", "/oauth/clients"+query, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to list clients (status %d): %s", resp.StatusCode, body)
	}

	var clients []OAuthClient
	if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	if opts.JSON {
		// Mask secrets unless explicitly requested
		if !opts.ShowSecrets {
			for i := range clients {
				clients[i].ClientSecret = ""
			}
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(clients)
	}

	if len(clients) == 0 {
		fmt.Println("No OAuth clients registered.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CLIENT ID\tNAME\tACTIVE\tCREATED\tREDIRECT URIS")
	for _, client := range clients {
		status := "active"
		if !client.Active {
			status = "inactive"
		}
		redirects := strings.Join(client.RedirectURIs, ", ")
		if len(redirects) > 50 {
			redirects = redirects[:47] + "..."
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			client.ClientID,
			client.ClientName,
			status,
			client.CreatedAt[:10],
			redirects,
		)
	}
	return w.Flush()
}

func GetClient(ctx context.Context, clientID string) (*ClientRegistrationResponse, error) {
	resp, err := makeRequest(ctx, "GET", "/oauth/clients/"+clientID, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get client (status %d): %s", resp.StatusCode, body)
	}

	var client ClientRegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&client); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	
	return &client, nil
}

func ShowClient(ctx context.Context, clientID string, opts *ClientShowOptions) error {
	resp, err := makeRequest(ctx, "GET", "/oauth/clients/"+clientID, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("client not found: %s", clientID)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to get client (status %d): %s", resp.StatusCode, body)
	}

	var client OAuthClient
	if err := json.NewDecoder(resp.Body).Decode(&client); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	if opts.JSON {
		if !opts.ShowSecret {
			client.ClientSecret = ""
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(client)
	}

	fmt.Printf("Client ID:       %s\n", client.ClientID)
	if opts.ShowSecret && client.ClientSecret != "" {
		fmt.Printf("Client Secret:   %s\n", client.ClientSecret)
	}
	fmt.Printf("Name:            %s\n", client.ClientName)
	if client.ClientDescription != "" {
		fmt.Printf("Description:     %s\n", client.ClientDescription)
	}
	fmt.Printf("Status:          ")
	if client.Active {
		fmt.Println("Active")
	} else {
		fmt.Println("Inactive")
	}
	fmt.Printf("Created:         %s\n", client.CreatedAt)
	fmt.Printf("Updated:         %s\n", client.UpdatedAt)
	fmt.Printf("Owner:           %s\n", client.Owner)
	if client.ClientURI != "" {
		fmt.Printf("Client URI:      %s\n", client.ClientURI)
	}
	if client.LogoURI != "" {
		fmt.Printf("Logo URI:        %s\n", client.LogoURI)
	}
	fmt.Printf("Application:     %s\n", client.ApplicationType)
	fmt.Printf("Redirect URIs:   %s\n", strings.Join(client.RedirectURIs, "\n                 "))
	if len(client.Scopes) > 0 {
		fmt.Printf("Scopes:          %s\n", strings.Join(client.Scopes, " "))
	}
	fmt.Printf("Grant Types:     %s\n", strings.Join(client.GrantTypes, ", "))
	fmt.Printf("Response Types:  %s\n", strings.Join(client.ResponseTypes, ", "))
	fmt.Printf("Auth Method:     %s\n", client.TokenEndpointAuthMethod)
	fmt.Printf("Requires PKCE:   %v\n", client.RequirePKCE)
	if len(client.Contacts) > 0 {
		fmt.Printf("Contacts:        %s\n", strings.Join(client.Contacts, ", "))
	}
	if client.PolicyURI != "" {
		fmt.Printf("Privacy Policy:  %s\n", client.PolicyURI)
	}
	if client.TosURI != "" {
		fmt.Printf("Terms of Service: %s\n", client.TosURI)
	}

	return nil
}

func UpdateClient(ctx context.Context, opts *ClientUpdateOptions) error {
	req := ClientUpdateRequest{
		Active: opts.Active,
	}

	// Only include fields that were explicitly set
	if opts.Name != "" {
		req.ClientName = opts.Name
	}
	if opts.Description != "" {
		req.ClientDescription = opts.Description
	}
	if len(opts.RedirectURIs) > 0 {
		req.RedirectURIs = opts.RedirectURIs
	}
	if opts.ClientURI != "" {
		req.ClientURI = opts.ClientURI
	}
	if opts.LogoURI != "" {
		req.LogoURI = opts.LogoURI
	}
	if len(opts.Scopes) > 0 {
		req.Scopes = opts.Scopes
	}
	if len(opts.Contacts) > 0 {
		req.Contacts = opts.Contacts
	}
	if opts.PolicyURI != "" {
		req.PolicyURI = opts.PolicyURI
	}
	if opts.TosURI != "" {
		req.TosURI = opts.TosURI
	}
	req.RequirePKCE = opts.RequirePKCE

	resp, err := makeRequest(ctx, "PUT", "/oauth/clients/"+opts.ClientID, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("client not found: %s", opts.ClientID)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update failed (status %d): %s", resp.StatusCode, body)
	}

	fmt.Printf("Client %s successfully updated.\n", opts.ClientID)
	return nil
}

func DeleteClient(ctx context.Context, clientID string) error {
	resp, err := makeRequest(ctx, "DELETE", "/oauth/clients/"+clientID, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("client not found: %s", clientID)
	}
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("deletion failed (status %d): %s", resp.StatusCode, body)
	}

	fmt.Printf("Client %s successfully deleted.\n", clientID)
	return nil
}

func RotateClientSecret(ctx context.Context, clientID string, opts *ClientRotateSecretOptions) error {
	resp, err := makeRequest(ctx, "POST", "/oauth/clients/"+clientID+"/rotate-secret", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("client not found: %s", clientID)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("rotation failed (status %d): %s", resp.StatusCode, body)
	}

	var client OAuthClient
	if err := json.NewDecoder(resp.Body).Decode(&client); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	fmt.Printf("Client secret for %s successfully rotated.\n", clientID)
	if opts.ShowSecret {
		fmt.Println()
		fmt.Printf("New Client Secret: %s\n", client.ClientSecret)
		fmt.Println()
		fmt.Println("IMPORTANT: Save the new client secret securely. The old secret is now invalid.")
	}

	return nil
}
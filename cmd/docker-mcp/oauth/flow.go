package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

// FlowCommand returns the OAuth flow command
func FlowCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "flow [provider]",
		Short: "Initiate OAuth flow for a provider",
		Long: `Initiate OAuth flow for a provider to authenticate with remote MCP servers.
		
Available providers:
  - notion
  - github
  - linear
  - slack`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return InitiateOAuthFlow(cmd.Context(), args[0])
		},
	}

	return cmd
}

// InitiateOAuthFlow initiates the OAuth flow for the specified provider
func InitiateOAuthFlow(ctx context.Context, provider string) error {
	// Get the backend socket path
	socketPath := getBackendSocketPath()
	if socketPath == "" {
		return fmt.Errorf("unsupported platform")
	}

	// Create HTTP client with Unix socket transport
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 30 * time.Second,
	}

	// Initiate OAuth flow
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("http://localhost/oauth/flow/%s", provider), nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to initiate OAuth flow: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil && errResp.Error != "" {
			return fmt.Errorf("OAuth flow failed: %s", errResp.Error)
		}
		return fmt.Errorf("OAuth flow failed with status: %s", resp.Status)
	}

	var flowResp struct {
		AuthURL string `json:"auth_url"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&flowResp); err != nil {
		return fmt.Errorf("failed to parse OAuth flow response: %w", err)
	}

	// Display the auth URL to the user
	fmt.Println("OAuth Authentication Required")
	fmt.Println("==============================")
	fmt.Printf("Provider: %s\n", provider)
	fmt.Println()
	
	if flowResp.AuthURL != "" {
		fmt.Println("Please visit the following URL to authenticate:")
		fmt.Printf("\n  %s\n\n", flowResp.AuthURL)
		fmt.Println("After completing the authentication, return here.")
	}
	
	if flowResp.Message != "" {
		fmt.Println(flowResp.Message)
	}

	// Wait for completion
	fmt.Println("\nWaiting for authentication to complete...")
	
	// Poll for token availability (max 5 minutes)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	timeout := time.After(5 * time.Minute)
	
	for {
		select {
		case <-ticker.C:
			// Check if token is now available
			tokenReq, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://localhost/oauth/tokens/%s", provider), nil)
			if err != nil {
				return err
			}
			
			tokenResp, err := client.Do(tokenReq)
			if err != nil {
				continue // Keep polling
			}
			tokenResp.Body.Close()
			
			if tokenResp.StatusCode == http.StatusOK {
				fmt.Printf("\n✓ Successfully authenticated with %s!\n", provider)
				fmt.Println("You can now use remote MCP servers that require this provider.")
				return nil
			}
			
		case <-timeout:
			return fmt.Errorf("OAuth authentication timed out after 5 minutes")
			
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}


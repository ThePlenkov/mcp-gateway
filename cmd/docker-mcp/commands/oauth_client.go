package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/docker/mcp-gateway/cmd/docker-mcp/oauth"
)

func oauthClientCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "client",
		Short: "Manage OAuth 2.0 client registrations",
		Long: `Manage dynamically registered OAuth 2.0 clients for MCP servers.
		
Dynamic client registration allows MCP servers to register their own OAuth clients
without requiring manual configuration. This enables third-party integrations
and custom OAuth providers.`,
	}
	cmd.AddCommand(registerOauthClientCommand())
	cmd.AddCommand(listOauthClientsCommand())
	cmd.AddCommand(showOauthClientCommand())
	cmd.AddCommand(updateOauthClientCommand())
	cmd.AddCommand(deleteOauthClientCommand())
	cmd.AddCommand(rotateOauthClientSecretCommand())
	return cmd
}

func registerOauthClientCommand() *cobra.Command {
	var opts oauth.ClientRegistrationOptions
	var dcrOpts oauth.DCROptions
	
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a new OAuth 2.0 client",
		Long: `Register a new OAuth 2.0 client for use with MCP servers.
		
This command implements RFC 7591 Dynamic Client Registration Protocol.
The registered client will receive a client ID and client secret that
can be used for OAuth 2.0 authorization flows.

Examples:
  # Register with an MCP server that supports DCR
  docker mcp oauth client register --endpoint https://mcp.notion.com/mcp/oauth/register --name "My Notion Client"
  
  # Register locally in Pinata (for custom providers)
  docker mcp oauth client register --name "My Custom Client"`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// If endpoint is specified, use direct DCR registration
			if dcrOpts.Endpoint != "" {
				dcrOpts.Name = opts.Name
				dcrOpts.Description = opts.Description
				dcrOpts.Scopes = opts.Scopes
				dcrOpts.GrantTypes = opts.GrantTypes
				dcrOpts.ResponseTypes = opts.ResponseTypes
				return oauth.RegisterWithMCPServer(cmd.Context(), &dcrOpts)
			}
			// Otherwise use local Pinata registration
			return oauth.RegisterClient(cmd.Context(), &opts)
		},
	}
	flags := cmd.Flags()
	
	// Common flags
	flags.StringVar(&opts.Name, "name", "", "Human-readable client name (required)")
	flags.StringVar(&opts.Description, "description", "", "Client description")
	flags.StringArrayVar(&opts.Scopes, "scope", nil, "OAuth scopes (can be specified multiple times)")
	flags.StringArrayVar(&opts.GrantTypes, "grant-type", []string{"authorization_code"}, "OAuth grant types")
	flags.StringArrayVar(&opts.ResponseTypes, "response-type", []string{"code"}, "OAuth response types")
	
	// DCR endpoint for direct registration with MCP servers
	flags.StringVar(&dcrOpts.Endpoint, "endpoint", "", "MCP server's DCR endpoint (e.g., https://mcp.notion.com/mcp/oauth/register)")
	
	// Additional flags for local registration
	flags.StringVar(&opts.ClientURI, "client-uri", "", "URL of the client's home page")
	flags.StringVar(&opts.LogoURI, "logo-uri", "", "URL of the client's logo")
	flags.StringVar(&opts.ApplicationType, "application-type", "web", "Application type (web or native)")
	flags.BoolVar(&opts.RequirePKCE, "require-pkce", false, "Require PKCE for authorization")
	flags.StringArrayVar(&opts.Contacts, "contact", nil, "Contact emails (can be specified multiple times)")
	flags.StringVar(&opts.PolicyURI, "policy-uri", "", "URL of the client's privacy policy")
	flags.StringVar(&opts.TosURI, "tos-uri", "", "URL of the client's terms of service")
	
	_ = cmd.MarkFlagRequired("name")
	
	return cmd
}

func listOauthClientsCommand() *cobra.Command {
	var opts oauth.ClientListOptions
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List registered OAuth 2.0 clients",
		Aliases: []string{"ls"},
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return oauth.ListClients(cmd.Context(), &opts)
		},
	}
	flags := cmd.Flags()
	flags.BoolVar(&opts.JSON, "json", false, "Output as JSON")
	flags.BoolVar(&opts.ShowSecrets, "show-secrets", false, "Show client secrets (dangerous)")
	flags.BoolVar(&opts.ActiveOnly, "active", false, "Show only active clients")
	flags.IntVar(&opts.Limit, "limit", 20, "Maximum number of results")
	flags.IntVar(&opts.Offset, "offset", 0, "Offset for pagination")
	return cmd
}

func showOauthClientCommand() *cobra.Command {
	var opts oauth.ClientShowOptions
	cmd := &cobra.Command{
		Use:   "show <client-id>",
		Short: "Show details of an OAuth 2.0 client",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return oauth.ShowClient(cmd.Context(), args[0], &opts)
		},
	}
	flags := cmd.Flags()
	flags.BoolVar(&opts.JSON, "json", false, "Output as JSON")
	flags.BoolVar(&opts.ShowSecret, "show-secret", false, "Show client secret (dangerous)")
	return cmd
}

func updateOauthClientCommand() *cobra.Command {
	var opts oauth.ClientUpdateOptions
	cmd := &cobra.Command{
		Use:   "update <client-id>",
		Short: "Update an OAuth 2.0 client",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.ClientID = args[0]
			return oauth.UpdateClient(cmd.Context(), &opts)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&opts.Name, "name", "", "Update client name")
	flags.StringVar(&opts.Description, "description", "", "Update client description")
	flags.StringArrayVar(&opts.RedirectURIs, "redirect-uri", nil, "Update redirect URIs (replaces all)")
	flags.StringVar(&opts.ClientURI, "client-uri", "", "Update client URI")
	flags.StringVar(&opts.LogoURI, "logo-uri", "", "Update logo URI")
	flags.StringArrayVar(&opts.Scopes, "scope", nil, "Update scopes (replaces all)")
	flags.StringArrayVar(&opts.Contacts, "contact", nil, "Update contacts (replaces all)")
	flags.StringVar(&opts.PolicyURI, "policy-uri", "", "Update privacy policy URI")
	flags.StringVar(&opts.TosURI, "tos-uri", "", "Update terms of service URI")
	flags.BoolVar(&opts.RequirePKCE, "require-pkce", false, "Update PKCE requirement")
	flags.BoolVar(&opts.Active, "active", true, "Set client active status")
	return cmd
}

func deleteOauthClientCommand() *cobra.Command {
	var opts oauth.ClientDeleteOptions
	cmd := &cobra.Command{
		Use:   "delete <client-id>",
		Short: "Delete an OAuth 2.0 client",
		Aliases: []string{"rm", "remove"},
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !opts.Force {
				fmt.Printf("Are you sure you want to delete client %s? This action cannot be undone.\n", args[0])
				fmt.Print("Type 'yes' to confirm: ")
				var confirm string
				if _, err := fmt.Scanln(&confirm); err != nil || confirm != "yes" {
					return fmt.Errorf("deletion cancelled")
				}
			}
			return oauth.DeleteClient(cmd.Context(), args[0])
		},
	}
	flags := cmd.Flags()
	flags.BoolVar(&opts.Force, "force", false, "Skip confirmation prompt")
	return cmd
}

func rotateOauthClientSecretCommand() *cobra.Command {
	var opts oauth.ClientRotateSecretOptions
	cmd := &cobra.Command{
		Use:   "rotate-secret <client-id>",
		Short: "Rotate the client secret for an OAuth 2.0 client",
		Long: `Generate a new client secret for an OAuth 2.0 client.
		
This invalidates the previous client secret immediately.
Make sure to update your application with the new secret.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !opts.Force {
				fmt.Printf("Are you sure you want to rotate the secret for client %s?\n", args[0])
				fmt.Println("The old secret will be invalidated immediately.")
				fmt.Print("Type 'yes' to confirm: ")
				var confirm string
				if _, err := fmt.Scanln(&confirm); err != nil || confirm != "yes" {
					return fmt.Errorf("rotation cancelled")
				}
			}
			return oauth.RotateClientSecret(cmd.Context(), args[0], &opts)
		},
	}
	flags := cmd.Flags()
	flags.BoolVar(&opts.Force, "force", false, "Skip confirmation prompt")
	flags.BoolVar(&opts.ShowSecret, "show-secret", true, "Show the new client secret")
	return cmd
}
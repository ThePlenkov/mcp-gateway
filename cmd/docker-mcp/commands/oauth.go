package commands

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/docker/mcp-gateway/cmd/docker-mcp/oauth"
)

func oauthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "oauth",
		Hidden: true,
	}
	cmd.AddCommand(lsOauthCommand())
	cmd.AddCommand(authorizeOauthCommand())
	cmd.AddCommand(revokeOauthCommand())
	cmd.AddCommand(oauthClientCommand())
	cmd.AddCommand(oauth.FlowCommand())
	return cmd
}

func lsOauthCommand() *cobra.Command {
	var opts struct {
		JSON bool
	}
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List available OAuth apps.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return oauth.Ls(cmd.Context(), opts.JSON)
		},
	}
	flags := cmd.Flags()
	flags.BoolVar(&opts.JSON, "json", false, "Print as JSON.")
	return cmd
}

func authorizeOauthCommand() *cobra.Command {
	var opts struct {
		Scopes string
	}
	cmd := &cobra.Command{
		Use:   "authorize <client_id>",
		Short: "Authorize using a registered OAuth client",
		Long: `Authorize using a registered OAuth client from dynamic client registration.
		
First register a client:
  docker mcp oauth client register --endpoint https://mcp.notion.com/mcp/oauth/register --name "My Client"

Then authorize:
  docker mcp oauth authorize <client_id>`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check if it's a client ID (starts with mcp_ or contains underscore)
			clientID := args[0]
			if strings.Contains(clientID, "_") || strings.HasPrefix(clientID, "mcp") {
				// Use new client-based flow
				return oauth.AuthorizeClient(cmd.Context(), clientID)
			}
			// Fall back to old flow for backwards compatibility
			return oauth.Authorize(cmd.Context(), args[0], opts.Scopes)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&opts.Scopes, "scopes", "", "OAuth scopes to request (space-separated)")
	return cmd
}

func revokeOauthCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <app>",
		Args:  cobra.ExactArgs(1),
		Short: "Revoke the specified OAuth app.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return oauth.Revoke(cmd.Context(), args[0])
		},
	}
}

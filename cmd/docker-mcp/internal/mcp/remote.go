package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/docker/mcp-gateway/cmd/docker-mcp/internal/catalog"
)

type remoteMCPClient struct {
	config      *catalog.ServerConfig
	client      *mcp.Client
	session     *mcp.ClientSession
	roots       []*mcp.Root
	initialized atomic.Bool
}

func NewRemoteMCPClient(config *catalog.ServerConfig) Client {
	return &remoteMCPClient{
		config: config,
	}
}

func (c *remoteMCPClient) Initialize(ctx context.Context, _ *mcp.InitializeParams, _ bool, _ *mcp.ServerSession, _ *mcp.Server) error {
	if c.initialized.Load() {
		return fmt.Errorf("client already initialized")
	}

	// Read configuration.
	var (
		url       string
		transport string
	)
	if c.config.Spec.SSEEndpoint != "" {
		// Deprecated
		url = c.config.Spec.SSEEndpoint
		transport = "sse"
	} else {
		url = c.config.Spec.Remote.URL
		transport = c.config.Spec.Remote.Transport
	}

	// Secrets to env
	env := map[string]string{}
	for _, secret := range c.config.Spec.Secrets {
		env[secret.Env] = c.config.Secrets[secret.Name]
	}

	// Headers
	headers := map[string]string{}
	for k, v := range c.config.Spec.Remote.Headers {
		headers[k] = expandEnv(v, env)
	}

	// Check if OAuth is enabled and add Authorization header
	if c.config.Spec.OAuth != nil {
		if enabled, ok := c.config.Spec.OAuth["enabled"].(bool); ok && enabled {
			if provider, ok := c.config.Spec.OAuth["provider"].(string); ok && provider != "" {
				token, err := getOAuthToken(ctx, provider)
				if err != nil {
					// Log warning but continue - OAuth might not be configured yet
					// User should run oauth flow command to set it up
					fmt.Fprintf(os.Stderr, "Warning: OAuth token not found for provider %s. Run 'docker mcp oauth flow %s' to authenticate.\n", provider, provider)
				} else if token != "" {
					headers["Authorization"] = "Bearer " + token
				}
			}
		}
	}

	// Create HTTP client with custom transport that adds headers
	httpClient := &http.Client{
		Transport: &headerTransport{
			headers: headers,
			base:    http.DefaultTransport,
		},
	}

	var mcpTransport mcp.Transport
	var err error

	switch strings.ToLower(transport) {
	case "sse":
		mcpTransport = mcp.NewSSEClientTransport(url, &mcp.SSEClientTransportOptions{
			HTTPClient: httpClient,
		})
	case "http", "streamable", "streaming", "streamable-http":
		mcpTransport = mcp.NewStreamableClientTransport(url, &mcp.StreamableClientTransportOptions{
			HTTPClient: httpClient,
		})
	default:
		return fmt.Errorf("unsupported remote transport: %s", transport)
	}

	c.client = mcp.NewClient(&mcp.Implementation{
		Name:    "docker-mcp-gateway",
		Version: "1.0.0",
	}, nil)

	c.client.AddRoots(c.roots...)

	session, err := c.client.Connect(ctx, mcpTransport)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	c.session = session
	c.initialized.Store(true)

	return nil
}

func (c *remoteMCPClient) Session() *mcp.ClientSession { return c.session }
func (c *remoteMCPClient) GetClient() *mcp.Client      { return c.client }

func (c *remoteMCPClient) AddRoots(roots []*mcp.Root) {
	if c.initialized.Load() {
		c.client.AddRoots(roots...)
	}
	c.roots = roots
}

func expandEnv(value string, secrets map[string]string) string {
	return os.Expand(value, func(name string) string {
		return secrets[name]
	})
}

// getOAuthToken retrieves the OAuth token for the given provider from Pinata
func getOAuthToken(ctx context.Context, provider string) (string, error) {
	// Get the backend socket path
	socketPath := getBackendSocketPath()
	if socketPath == "" {
		return "", fmt.Errorf("unsupported platform")
	}

	// Make request to backend to get OAuth token
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://localhost/oauth/tokens/%s", provider), nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get OAuth token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("OAuth token not found for provider %s", provider)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get OAuth token: %s", resp.Status)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	return tokenResp.AccessToken, nil
}

func getBackendSocketPath() string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join("/Users", os.Getenv("USER"), "Library/Containers/com.docker.docker/Data/backend.sock")
	case "linux":
		return "/var/run/docker.sock"
	case "windows":
		return `\\.\pipe\docker_engine`
	default:
		return ""
	}
}

// headerTransport is an http.RoundTripper that adds headers to requests
type headerTransport struct {
	headers map[string]string
	base    http.RoundTripper
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	req = req.Clone(req.Context())
	
	// Add headers
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
	
	return t.base.RoundTrip(req)
}
